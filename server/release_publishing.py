"""Authenticated signed-pack staging and atomic, persistent release activation."""

import base64
import asyncio
import binascii
import hashlib
import inspect
import logging
import os
import re
import secrets
import shutil
import sqlite3
import time
import tempfile
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Callable, Generator, Literal, ParamSpec, TypeAlias, TypeVar
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, FastAPI, Path as ApiPath, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Receive, Scope, Send

if __package__:
    from .auth_helpers import fail
else:
    from auth_helpers import fail

PREFIX = "/api/v1/releases/deployments"
MAX_MANIFEST = 8 * 1024 * 1024
MAX_JSON_BODY = 12 * 1024 * 1024
CHUNK_BYTES = 8 * 1024 * 1024
MAX_FILES = 20000
ID_PATTERN = r"^[a-f0-9]{64}$"
DeploymentId: TypeAlias = Annotated[str, ApiPath(pattern=ID_PATTERN)]
logger = logging.getLogger("mars-release-publishing")
P = ParamSpec("P")
T = TypeVar("T")


def redirected(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def checked_root(path: Path) -> Path:
    if not path.is_absolute() or any(redirected(part) for part in (path, *path.parents)):
        raise ValueError("Release storage must be an absolute path without links or junctions")
    return path.resolve()


def relative_parts(value: str) -> list[str]:
    parts = value.split("/")
    reserved = {"con", "prn", "aux", "nul", *(f"com{number}" for number in range(1, 10)),
                *(f"lpt{number}" for number in range(1, 10))}
    if (
        not value or len(value) > 512 or "\\" in value or ":" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(character in value for character in '<>"|?*')
        or any(part in {"", ".", ".."} or part.endswith((".", " ")) for part in parts)
        or any(part.split(".", 1)[0].casefold() in reserved for part in parts)
    ):
        raise fail(422, "unsafe_path", "Manifest contains an unsafe relative file path")
    return parts


def confined(root: Path, relative: str) -> Path:
    if any(redirected(parent) for parent in (root, *root.parents)):
        raise fail(409, "redirected_path", "Release roots cannot contain links or junctions")
    path = root
    for part in relative_parts(relative):
        path /= part
        if redirected(path):
            raise fail(409, "redirected_path", "Release paths cannot contain links or junctions")
    return path


def sync_directory(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write_synced(path: Path, content: bytes) -> None:
    with path.open("wb") as destination:
        destination.write(content)
        destination.flush()
        os.fsync(destination.fileno())


@dataclass(frozen=True)
class PublishSettings:
    legacy_root: Path
    directory: Path
    token: str
    public_key: str
    managed_dirs: tuple[str, ...]
    minecraft_version: str
    loader: str
    loader_version: str
    max_file_bytes: int = 512 * 1024 * 1024
    max_pack_bytes: int = 4 * 1024 * 1024 * 1024
    max_staging: int = 3
    expiry_seconds: int = 3600

    def __post_init__(self):
        legacy = checked_root(self.legacy_root)
        directory = checked_root(self.directory)
        if legacy == directory or legacy in directory.parents or directory in legacy.parents:
            raise ValueError("Publishing storage must be separate from the legacy release directory")
        repository = Path(__file__).resolve().parent.parent
        for name in ("static", "public", "output", "dist"):
            public = (repository / name).resolve()
            if public == directory or public in directory.parents or directory in public.parents:
                raise ValueError("Publishing storage overlaps a public application directory")
        object.__setattr__(self, "legacy_root", legacy)
        object.__setattr__(self, "directory", directory)
        if self.token and not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.token):
            raise ValueError("MARS_RELEASE_DEPLOY_TOKEN must contain 32..128 URL-safe characters")
        if self.token or (directory / "state.sqlite3").exists():
            if not re.fullmatch(r"[a-fA-F0-9]{64}", self.public_key) or self.public_key == "0" * 64:
                raise ValueError("MARS_RELEASE_PUBLIC_KEY must contain the trusted Ed25519 public key")
        for value in (self.max_file_bytes, self.max_pack_bytes, self.max_staging, self.expiry_seconds):
            if type(value) is not int or value <= 0:
                raise ValueError("Publishing limits must be positive integers")
        if self.max_file_bytes > self.max_pack_bytes or self.max_staging > 20 or self.expiry_seconds > 86400:
            raise ValueError("Invalid publishing size, staging or expiry limit")
        if not self.managed_dirs or any(len(relative_parts(part)) != 1 or part.startswith(".") for part in self.managed_dirs):
            raise ValueError("Publishing accepts only explicitly managed top-level directories")

    @classmethod
    def from_env(
        cls, root: Path, managed: tuple[str, ...], minecraft: str, loader: str, loader_version: str
    ) -> "PublishSettings":
        token = os.environ.get("MARS_RELEASE_DEPLOY_TOKEN", "")
        if token and token in {
            os.environ.get("MARS_API_JWT_SECRET"), os.environ.get("MARS_AUTH_JWT_SECRET"),
            os.environ.get("MARS_MINECRAFT_SERVER_TOKEN"), os.environ.get("GITHUB_CLIENT_SECRET"),
        }:
            raise ValueError("The release deployment credential must be separate from all account/package credentials")
        return cls(
            legacy_root=root,
            directory=Path(os.environ.get("MARS_RELEASE_PUBLISH_DIR", str(root.parent / f".{root.name}-publisher"))),
            token=token,
            public_key=os.environ.get("MARS_RELEASE_PUBLIC_KEY", ""),
            managed_dirs=managed,
            minecraft_version=minecraft,
            loader=loader,
            loader_version=loader_version,
            max_file_bytes=int(os.environ.get("MARS_RELEASE_MAX_FILE_BYTES", str(512 * 1024 * 1024))),
            max_pack_bytes=int(os.environ.get("MARS_RELEASE_MAX_PACK_BYTES", str(4 * 1024 * 1024 * 1024))),
            max_staging=int(os.environ.get("MARS_RELEASE_MAX_STAGING", "3")),
            expiry_seconds=int(os.environ.get("MARS_RELEASE_EXPIRY_SECONDS", "3600")),
        )


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Reserve(Input):
    manifestBase64: str = Field(min_length=1, max_length=4 * ((MAX_MANIFEST + 2) // 3))
    signature: str = Field(pattern=r"^[a-fA-F0-9]{128}$")


class Empty(Input):
    pass


class SignedFile(Input):
    path: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(ge=0)
    required: bool = True
    mutable: bool = False
    side: Literal["client", "both"] = "client"
    downloadUrl: str | None = Field(default=None, max_length=4096)
    manualDownload: bool = False
    sourcePage: str | None = Field(default=None, max_length=4096)


class SignedManifest(Input):
    schemaVersion: int = Field(ge=1, le=1)
    packVersion: str = Field(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
    minecraftVersion: str
    loader: str
    loaderVersion: str
    generatedAt: str = Field(min_length=1, max_length=128)
    managedDirs: list[str] = Field(min_length=1, max_length=32)
    files: list[SignedFile] = Field(min_length=1, max_length=MAX_FILES)
    modsDir: Literal["mods"] = "mods"
    curseforgeMods: list[dict] = Field(default_factory=list, max_length=0)


class UploadFile(BaseModel):
    index: int
    path: str
    sha256: str
    size: int
    uploadedBytes: int
    complete: bool
    reusable: bool


class DeploymentStatus(BaseModel):
    deploymentId: str
    packVersion: str
    manifestSha256: str
    status: Literal["staging", "published"]
    active: bool
    expiresAt: int | None
    chunkBytes: int
    files: list[UploadFile]


class UploadStatus(BaseModel):
    uploadedBytes: int
    complete: bool


class Published(BaseModel):
    deploymentId: str
    packVersion: str
    manifestSha256: str
    fileCount: int
    status: Literal["published"] = "published"


def file_matches(path: Path, entry: SignedFile) -> bool:
    if not path.is_file() or path.stat().st_size != entry.size:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest() == entry.sha256


class Publisher:
    def __init__(self, settings: PublishSettings, validate_snapshot: Callable[[Path], object]):
        self.settings = settings
        self.validate_snapshot = validate_snapshot
        self.database = settings.directory / "state.sqlite3"
        settings.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in ("staging", "published"):
            (settings.directory / directory).mkdir(mode=0o700, exist_ok=True)
        with closing(self._connect()) as db:
            mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if mode.lower() != "wal":
                raise RuntimeError("Release publishing requires SQLite WAL mode")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS deployments (
                    id TEXT PRIMARY KEY, manifest BLOB NOT NULL, signature TEXT NOT NULL,
                    base_id TEXT, status TEXT NOT NULL CHECK(status IN ('staging','published')),
                    expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS active_release (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    deployment_id TEXT NOT NULL REFERENCES deployments(id)
                );
            """)
        if os.name != "nt":
            self.database.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        if any(redirected(part) for part in (self.settings.directory, self.database)):
            raise fail(503, "storage_unavailable", "Publishing storage is redirected")
        db = sqlite3.connect(self.database, timeout=60)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=60000")
        return db

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    def _active(self, db: sqlite3.Connection) -> str | None:
        row = db.execute("SELECT deployment_id FROM active_release WHERE singleton=1").fetchone()
        return row[0] if row else None

    def active_root(self) -> tuple[str | None, Path]:
        with closing(self._connect()) as db:
            active = self._active(db)
        return active, self.root(active) if active else self.settings.legacy_root

    def root(self, identifier: str, published: bool = True) -> Path:
        if not re.fullmatch(ID_PATTERN, identifier):
            raise fail(503, "invalid_release_state", "Stored release identifier is invalid")
        prefix = "published" if published else "staging"
        return confined(self.settings.directory, f"{prefix}/{identifier}/release")

    def _manifest(self, raw: bytes, signature: str) -> SignedManifest:
        if len(raw) > MAX_MANIFEST:
            raise fail(413, "manifest_too_large", "Manifest exceeds 8 MiB")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.settings.public_key)).verify(
                bytes.fromhex(signature), raw
            )
        except InvalidSignature:
            raise fail(422, "invalid_signature", "Manifest signature does not match the trusted release key")
        try:
            manifest = SignedManifest.model_validate_json(raw)
        except ValidationError:
            raise fail(422, "invalid_manifest", "Signed manifest fields are invalid or unsupported")
        if (manifest.minecraftVersion, manifest.loader, manifest.loaderVersion) != (
            self.settings.minecraft_version, self.settings.loader, self.settings.loader_version
        ):
            raise fail(422, "incompatible_pack", "Pack Minecraft/loader versions differ from the configured server")
        managed = set(manifest.managedDirs)
        if len(managed) != len(manifest.managedDirs) or not managed <= set(self.settings.managed_dirs) or "mods" not in managed:
            raise fail(422, "invalid_managed_dirs", "Manifest directories differ from the permitted managed directories")
        paths: set[str] = set()
        total = 0
        for entry in manifest.files:
            parts = relative_parts(entry.path)
            if len(parts) < 2 or parts[0] not in managed:
                raise fail(422, "unmanaged_path", "Every uploaded file must belong to a declared managed directory")
            normalized = entry.path.casefold()
            if normalized in paths:
                raise fail(422, "duplicate_path", "Manifest file paths must be unique, including case")
            paths.add(normalized)
            if entry.size > self.settings.max_file_bytes:
                raise fail(413, "file_too_large", "A declared file exceeds the server upload limit")
            total += entry.size
            if entry.downloadUrl:
                url = urlsplit(entry.downloadUrl)
                if url.scheme != "https" or not url.netloc or url.username or url.password or url.fragment:
                    raise fail(422, "invalid_download_url", "Manifest download URLs must use credential-free HTTPS")
        if not any(entry.path.startswith("mods/") and entry.path.endswith(".jar") for entry in manifest.files):
            raise fail(422, "empty_modpack", "A pack must contain at least one declared mod JAR")
        if total > self.settings.max_pack_bytes:
            raise fail(413, "pack_too_large", "Pack exceeds the configured total size limit")
        return manifest

    def _row(self, db: sqlite3.Connection, identifier: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM deployments WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise fail(404, "deployment_not_found", "Deployment does not exist")
        if row["status"] == "staging" and row["expires"] <= int(time.time()):
            raise fail(410, "deployment_expired", "Deployment expired; reserve the signed release again")
        return row

    def _cleanup(self, db: sqlite3.Connection) -> None:
        expired = db.execute(
            "SELECT id FROM deployments WHERE status='staging' AND expires<=?", (int(time.time()),)
        ).fetchall()
        for row in expired:
            identifier = row["id"]
            folder = confined(self.settings.directory, f"staging/{identifier}")
            if folder.exists():
                shutil.rmtree(folder)
            # A prepared generation can survive a crash before the activation transaction.
            prepared = confined(self.settings.directory, f"published/{identifier}")
            if prepared.exists():
                shutil.rmtree(prepared)
            db.execute("DELETE FROM deployments WHERE id=?", (identifier,))

    def reserve(self, body: Reserve) -> str:
        try:
            raw = base64.b64decode(body.manifestBase64, validate=True)
        except binascii.Error:
            raise fail(422, "invalid_manifest_encoding", "Manifest must be exact base64-encoded UTF-8 bytes")
        self._manifest(raw, body.signature)
        identifier = hashlib.sha256(raw).hexdigest()
        with self.transaction() as db:
            self._cleanup(db)
            existing = db.execute("SELECT * FROM deployments WHERE id=?", (identifier,)).fetchone()
            if existing:
                if existing["signature"] != body.signature.lower():
                    raise fail(409, "deployment_conflict", "Manifest already has a different stored signature")
                return identifier
            if db.execute("SELECT count(*) FROM deployments WHERE status='staging'").fetchone()[0] >= self.settings.max_staging:
                raise fail(429, "staging_capacity", "Too many active pack deployments; finish or wait for expiry")
            root = self.root(identifier, published=False)
            root.mkdir(parents=True, mode=0o700, exist_ok=True)
            write_synced(root / "manifest.json", raw)
            write_synced(root / "manifest.json.sig", body.signature.lower().encode("ascii"))
            sync_directory(root)
            db.execute("INSERT INTO deployments VALUES (?, ?, ?, ?, 'staging', ?)", (
                identifier, raw, body.signature.lower(), self._active(db),
                int(time.time()) + self.settings.expiry_seconds,
            ))
        logger.info("Reserved signed pack deployment %s", identifier)
        return identifier

    def status(self, identifier: str) -> DeploymentStatus:
        with closing(self._connect()) as db:
            row = self._row(db, identifier)
            active = self._active(db)
        manifest = self._manifest(row["manifest"], row["signature"])
        published = row["status"] == "published"
        root = self.root(identifier, published=published)
        prepared = self.root(identifier)
        if not published and prepared.exists():
            root = prepared
        base = self.root(row["base_id"]) if row["base_id"] else self.settings.legacy_root
        entries = []
        for index, entry in enumerate(manifest.files):
            path = confined(root, entry.path)
            complete = file_matches(path, entry)
            part = confined(self.settings.directory, f"staging/{identifier}/parts/{index}")
            uploaded = entry.size if complete else (part.stat().st_size if part.is_file() else 0)
            if uploaded > entry.size:
                raise fail(503, "invalid_staging_state", "Staged payload exceeds its signed size")
            reusable = not complete and file_matches(confined(base, entry.path), entry)
            entries.append(UploadFile(
                index=index, path=entry.path, sha256=entry.sha256, size=entry.size,
                uploadedBytes=uploaded, complete=complete, reusable=reusable,
            ))
        return DeploymentStatus(
            deploymentId=identifier, manifestSha256=identifier, packVersion=manifest.packVersion,
            status=row["status"], active=active == identifier,
            expiresAt=None if published else row["expires"], chunkBytes=CHUNK_BYTES, files=entries,
        )

    def upload(self, identifier: str, index: int, offset: int, chunk: bytes) -> UploadStatus:
        if len(chunk) > CHUNK_BYTES:
            raise fail(413, "chunk_too_large", "Upload chunk exceeds 8 MiB")
        with self.transaction() as db:
            row = self._row(db, identifier)
            if row["status"] != "staging":
                raise fail(409, "release_immutable", "Published releases cannot be modified")
            if self.root(identifier).exists():
                raise fail(409, "generation_prepared", "Release is already prepared; retry commit instead of uploading")
            manifest = self._manifest(row["manifest"], row["signature"])
            if index < 0 or index >= len(manifest.files):
                raise fail(404, "file_not_declared", "File index is not declared by this signed manifest")
            entry = manifest.files[index]
            if offset < 0 or offset + len(chunk) > entry.size:
                raise fail(422, "invalid_offset", "Upload range exceeds the declared file size")
            target = confined(self.root(identifier, published=False), entry.path)
            if target.exists():
                if not file_matches(target, entry):
                    raise fail(409, "staged_file_changed", "Completed staged file was modified")
                return UploadStatus(uploadedBytes=entry.size, complete=True)
            part = confined(self.settings.directory, f"staging/{identifier}/parts/{index}")
            part.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            size = part.stat().st_size if part.exists() else 0
            if offset > size:
                raise fail(409, "offset_mismatch", "Resume from the uploaded byte count in deployment status")
            overlap = min(len(chunk), size - offset)
            if overlap:
                with part.open("rb") as source:
                    source.seek(offset)
                    if source.read(overlap) != chunk[:overlap]:
                        raise fail(409, "chunk_conflict", "Retried upload differs from already received bytes")
            with part.open("ab") as destination:
                destination.write(chunk[overlap:])
                destination.flush()
                os.fsync(destination.fileno())
            size = part.stat().st_size
            if size == entry.size:
                if not file_matches(part, entry):
                    part.unlink()
                    raise fail(422, "payload_hash_mismatch", "Uploaded file failed its signed SHA-256; restart this file")
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                os.replace(part, target)
                sync_directory(target.parent)
                return UploadStatus(uploadedBytes=size, complete=True)
            return UploadStatus(uploadedBytes=size, complete=False)

    def _copy_verified(self, source: Path, target: Path, entry: SignedFile, identifier: str) -> None:
        if not source.is_file():
            raise fail(409, "payload_missing", f"Upload required: {entry.path}")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        work = confined(self.settings.directory, f"staging/{identifier}/copies")
        work.mkdir(parents=True, mode=0o700, exist_ok=True)
        descriptor, filename = tempfile.mkstemp(prefix="copy-", dir=work)
        temporary = Path(filename)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as destination, source.open("rb") as origin:
                for chunk in iter(lambda: origin.read(64 * 1024), b""):
                    size += len(chunk)
                    if size > entry.size:
                        raise fail(409, "payload_changed", f"Existing payload changed; upload required: {entry.path}")
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if size != entry.size or digest.hexdigest() != entry.sha256:
                raise fail(409, "payload_changed", f"Existing payload differs; upload required: {entry.path}")
            os.replace(temporary, target)
            sync_directory(target.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def commit(self, identifier: str) -> Published:
        with self.transaction() as db:
            row = self._row(db, identifier)
            manifest = self._manifest(row["manifest"], row["signature"])
            active = self._active(db)
            if row["status"] == "published":
                if active != identifier:
                    raise fail(409, "release_superseded", "This deployment was superseded by a later release")
                return Published(deploymentId=identifier, manifestSha256=identifier,
                                 packVersion=manifest.packVersion, fileCount=len(manifest.files))
            if active != row["base_id"]:
                raise fail(409, "stale_deployment", "Another release was activated after this deployment was reserved")
            if active:
                active_row = self._row(db, active)
                # The active row was authenticated on activation; it may use a previously rotated public key.
                current = SignedManifest.model_validate_json(active_row["manifest"])
                if tuple(map(int, manifest.packVersion.split("."))) <= tuple(map(int, current.packVersion.split("."))):
                    raise fail(409, "non_increasing_version", "New deployments must use a higher pack version")
            root = self.root(identifier, published=False)
            prepared = self.root(identifier)
            already_prepared = prepared.exists()
            if already_prepared:
                root = prepared
            source_root = self.root(active) if active else self.settings.legacy_root
            for entry in manifest.files:
                target = confined(root, entry.path)
                if target.exists():
                    if not file_matches(target, entry):
                        raise fail(409, "staged_file_changed", "A staged file differs from the signed manifest")
                elif already_prepared:
                    raise fail(409, "incomplete_generation", "A prepared release is incomplete")
                else:
                    self._copy_verified(confined(source_root, entry.path), target, entry, identifier)
            if (root / "manifest.json").read_bytes() != row["manifest"] or (
                root / "manifest.json.sig"
            ).read_text(encoding="ascii").strip() != row["signature"]:
                raise fail(409, "staged_manifest_changed", "Staged manifest pair differs from its reserved signature")
            try:
                self.validate_snapshot(root)
            except (RuntimeError, ValueError):
                logger.error("Pack %s could not build a valid serving inventory", identifier)
                raise fail(422, "invalid_inventory", "The staged pack cannot produce a valid serving inventory")
            if not already_prepared:
                for directory, _, _ in os.walk(root, topdown=False):
                    sync_directory(Path(directory))
                prepared.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(root, prepared)
                sync_directory(prepared.parent)
            db.execute("UPDATE deployments SET status='published' WHERE id=?", (identifier,))
            db.execute(
                "INSERT INTO active_release VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET deployment_id=excluded.deployment_id",
                (identifier,),
            )
        logger.info("Activated pack %s (%s verified files)", manifest.packVersion, len(manifest.files))
        return Published(deploymentId=identifier, manifestSha256=identifier,
                         packVersion=manifest.packVersion, fileCount=len(manifest.files))


class PublishGuard:
    """Authenticate before reading any upload, and bound request bodies."""

    def __init__(self, app: ASGIApp, settings: PublishSettings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(PREFIX):
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        authorization = headers.get(b"authorization", b"")
        problem = None
        if not self.settings.token:
            problem = fail(503, "publishing_disabled", "Signed pack publishing is not configured")
        elif not secrets.compare_digest(authorization, f"Bearer {self.settings.token}".encode("ascii")):
            problem = fail(401, "deployment_auth_required", "A dedicated release deployment credential is required")
        elif b"origin" in headers or b"sec-fetch-mode" in headers:
            problem = fail(403, "server_only", "Release publishing accepts server-to-server requests only")
        limit = CHUNK_BYTES if scope["method"] == "PUT" else MAX_JSON_BODY
        length = headers.get(b"content-length")
        if problem is None and length is not None:
            if not length.isdigit():
                problem = fail(422, "invalid_length", "Content-Length is invalid")
            elif len(length) > 20:
                problem = fail(413, "body_too_large", "Release upload exceeds its request size limit")
            elif int(length) > limit:
                problem = fail(413, "body_too_large", "Release upload exceeds its request size limit")
        if problem:
            await JSONResponse({"detail": problem.detail}, status_code=problem.status_code,
                               headers={"Cache-Control": "no-store"})(scope, receive, send)
            return

        chunks = []
        size = 0
        try:
            async with asyncio.timeout(60):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    size += len(message.get("body", b""))
                    if size > limit:
                        await JSONResponse(
                            {"detail": {"code": "body_too_large", "message": "Release upload exceeds its request size limit"}},
                            status_code=413, headers={"Cache-Control": "no-store"},
                        )(scope, receive, send)
                        return
                    chunks.append(message)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await JSONResponse({"detail": {"code": "upload_timeout", "message": "Release upload timed out"}},
                               status_code=408, headers={"Cache-Control": "no-store"})(scope, receive, send)
            return
        if length is not None and size != int(length):
            await JSONResponse({"detail": {"code": "length_mismatch", "message": "Upload length differs"}},
                               status_code=422)(scope, receive, send)
            return

        async def replay():
            return chunks.pop(0) if chunks else await receive()

        async def private_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = [
                    pair for pair in message["headers"]
                    if pair[0].lower() not in {b"cache-control", b"x-content-type-options"}
                ] + [
                    (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                ]
            await send(message)

        await self.app(scope, replay, private_send)


def install_publishing(
    app: FastAPI, settings: PublishSettings, validate_snapshot: Callable[[Path], object]
) -> Publisher | None:
    publisher = Publisher(settings, validate_snapshot) if settings.token or (settings.directory / "state.sqlite3").exists() else None
    app.add_middleware(PublishGuard, settings=settings)
    router = APIRouter(prefix=PREFIX, tags=["Signed pack publishing"])
    deploy_bearer = HTTPBearer(auto_error=False, scheme_name="ReleaseDeploymentToken")
    previous_validation = app.exception_handlers.get(RequestValidationError, request_validation_exception_handler)

    async def validation_error(request: Request, exception: Exception):
        if request.url.path.startswith(PREFIX):
            return JSONResponse({"detail": {"code": "invalid_input", "message": "Deployment request fields are invalid"}},
                                status_code=422, headers={"Cache-Control": "no-store"})
        response = previous_validation(request, exception)
        return await response if inspect.isawaitable(response) else response

    app.add_exception_handler(RequestValidationError, validation_error)

    def ready(_credential: Annotated[HTTPAuthorizationCredentials | None, Depends(deploy_bearer)]) -> Publisher:
        if publisher is None:
            raise fail(503, "publishing_disabled", "Signed pack publishing is not configured")
        return publisher

    async def storage(method: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return await run_in_threadpool(method, *args, **kwargs)
        except (sqlite3.Error, OSError):
            logger.error("Release publishing storage operation failed")
            raise fail(503, "storage_unavailable", "Release storage is unavailable; the active release is preserved")

    @router.post("", response_model=DeploymentStatus)
    async def reserve(body: Reserve, workflow: Annotated[Publisher, Depends(ready)]):
        identifier = await storage(workflow.reserve, body)
        return await storage(workflow.status, identifier)

    @router.get("/{deployment_id}", response_model=DeploymentStatus)
    async def status(deployment_id: DeploymentId, workflow: Annotated[Publisher, Depends(ready)]):
        return await storage(workflow.status, deployment_id)

    @router.put("/{deployment_id}/files/{index}", response_model=UploadStatus)
    async def upload(
        deployment_id: DeploymentId, index: Annotated[int, ApiPath(ge=0)], request: Request,
        offset: Annotated[int, Query(ge=0)], workflow: Annotated[Publisher, Depends(ready)],
    ):
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/octet-stream":
            raise fail(415, "unsupported_media_type", "Send a raw payload chunk")
        return await storage(workflow.upload, deployment_id, index, offset, await request.body())

    @router.post("/{deployment_id}/commit", response_model=Published)
    async def commit(deployment_id: DeploymentId, body: Empty, workflow: Annotated[Publisher, Depends(ready)]):
        return await storage(workflow.commit, deployment_id)

    app.include_router(router)
    return publisher
