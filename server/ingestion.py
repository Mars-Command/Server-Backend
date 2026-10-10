"""Private capsule workflow. Nothing in this module authorizes artifact delivery."""

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
from functools import cache
import time
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import AsyncIterable, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

if __package__:
    from .capsules import CapsuleBlocked, CommunityStore, initialize_capsules
else:
    from capsules import CapsuleBlocked, CommunityStore, initialize_capsules

ROOT = Path(__file__).resolve().parent.parent
POLICY_VERSION = "capsule-v1"
logger = logging.getLogger("mars-capsules")
State = Literal[
    "reserved", "uploading", "quarantined", "scan_pending", "scan_blocked",
    "rejected", "publishable", "expired", "withdrawn",
]
ACTIVE = ("reserved", "uploading", "quarantined", "scan_pending", "scan_blocked", "publishable")
TRANSITIONS = {
    "reserved": {"uploading", "expired", "withdrawn"},
    "uploading": {"reserved", "quarantined", "expired", "withdrawn"},
    "quarantined": {"scan_pending", "expired", "withdrawn"},
    "scan_pending": {"scan_blocked", "rejected", "publishable", "expired", "withdrawn"},
    "scan_blocked": {"scan_pending", "expired", "withdrawn"},
    "rejected": {"expired", "withdrawn"},
    "publishable": {"scan_blocked", "expired", "withdrawn"},
    "expired": set(),
    "withdrawn": set(),
}


def timestamp(value: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat()


@dataclass(frozen=True)
class IngestionSettings:
    quarantine: Path
    retained: Path
    evidence: Path
    max_bytes: int = 64 * 1024 * 1024
    max_active: int = 10
    expiry_seconds: int = 7 * 86400
    lease_seconds: int = 300
    max_attempts: int = 3
    retry_seconds: int = 30
    evidence_seconds: int = 86400
    upload_seconds: int = 300
    policy_version: str = POLICY_VERSION
    scanner: str = "disabled"

    def __post_init__(self):
        for name in (
            "max_bytes", "max_active", "expiry_seconds", "lease_seconds",
            "max_attempts", "retry_seconds", "evidence_seconds", "upload_seconds",
        ):
            if type(getattr(self, name)) is not int or not 0 < getattr(self, name) <= 2**31:
                raise ValueError(f"Invalid capsule {name}")
        if self.scanner != "disabled":
            raise ValueError("No permitted production scanner adapter is installed")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", self.policy_version):
            raise ValueError("Invalid capsule policy version")
        roots = []
        public = [ROOT / name for name in ("static", "public", "output", "releases", "dist")]
        if os.environ.get("MARS_RELEASE_DIR"):
            public.append(Path(os.environ["MARS_RELEASE_DIR"]).resolve())
        for name in ("quarantine", "retained", "evidence"):
            path = Path(getattr(self, name))
            if not path.is_absolute():
                raise ValueError("Private bucket paths must be absolute")
            # Reject links/junctions in any existing ancestor, not merely the leaf.
            if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
                raise ValueError("Private bucket paths cannot contain links or junctions")
            path = path.resolve()
            if any(path == p or path in p.parents or p in path.parents for p in public):
                raise ValueError("Private buckets overlap a public/package directory")
            if any(path == p or path in p.parents or p in path.parents for p in roots):
                raise ValueError("Private buckets must not overlap each other")
            object.__setattr__(self, name, path)
            roots.append(path)

    @classmethod
    def for_database(cls, database: str, *, environment: bool = False):
        base = Path(database).resolve().parent / "capsule-private"
        values = {}
        for name in ("quarantine", "retained", "evidence"):
            value = os.environ.get(f"MARS_CAPSULE_{name.upper()}") if environment else None
            values[name] = Path(value) if value else base / name
        for name in (
            "max_bytes", "max_active", "expiry_seconds", "lease_seconds",
            "max_attempts", "retry_seconds", "evidence_seconds", "upload_seconds",
        ):
            value = os.environ.get(f"MARS_CAPSULE_{name.upper()}") if environment else None
            if value is not None:
                values[name] = int(value)
        if environment:
            values["scanner"] = os.environ.get("MARS_CAPSULE_SCANNER", "disabled")
            values["policy_version"] = os.environ.get("MARS_CAPSULE_POLICY_VERSION", POLICY_VERSION)
        return cls(**values)


class EvidenceResponse(BaseModel):
    version: int = Field(ge=1)
    artifactSha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    provider: str
    providerResultId: str
    policyVersion: str
    scannedAt: str
    expiresAt: str
    verdict: Literal["accepted", "rejected", "blocked", "error"]
    summary: str


class QueueResponse(BaseModel):
    status: Literal["pending", "leased", "complete", "blocked", "failed"]
    attempts: int = Field(ge=0)
    maxAttempts: int = Field(ge=1)
    nextAttemptAt: str | None
    lastError: str | None


class CapsuleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    releaseId: str = Field(pattern=r"^[a-f0-9]{32}$")
    ownerId: str
    project: str
    version: str
    sourceUrl: str
    createdAt: str
    artifactSha256: str | None
    state: State
    revision: int = Field(ge=1)
    updatedAt: str
    evidence: EvidenceResponse | None
    queue: QueueResponse | None
    publicDownloadAvailable: Literal[False] = False


class CapsulesResponse(BaseModel):
    capsules: list[CapsuleResponse]


def initialize_ingestion(db: sqlite3.Connection) -> None:
    initialize_capsules(db)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS capsule_migrations (
            version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS capsule_operations (
            release_id TEXT PRIMARY KEY REFERENCES capsule_releases(release_id),
            state TEXT NOT NULL CHECK(state IN (
                'reserved','uploading','quarantined','scan_pending','scan_blocked',
                'rejected','publishable','expired','withdrawn')),
            revision INTEGER NOT NULL CHECK(revision > 0),
            updated_at REAL NOT NULL, upload_token TEXT, upload_expires REAL
        );
        CREATE TABLE IF NOT EXISTS capsule_idempotency (
            owner_id TEXT NOT NULL REFERENCES users(id), key TEXT NOT NULL,
            release_id TEXT NOT NULL REFERENCES capsule_releases(release_id),
            PRIMARY KEY(owner_id,key)
        );
        CREATE TABLE IF NOT EXISTS capsule_transitions (
            release_id TEXT NOT NULL REFERENCES capsule_releases(release_id),
            revision INTEGER NOT NULL, state TEXT NOT NULL, recorded_at REAL NOT NULL,
            PRIMARY KEY(release_id,revision)
        );
        CREATE TABLE IF NOT EXISTS capsule_jobs (
            id INTEGER PRIMARY KEY, digest TEXT NOT NULL REFERENCES capsule_artifacts(sha256),
            policy_version TEXT NOT NULL, status TEXT NOT NULL
                CHECK(status IN ('pending','leased','complete','blocked','failed')),
            attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
            next_attempt REAL NOT NULL, lease_token TEXT, lease_owner TEXT,
            lease_expires REAL, last_error TEXT,
            UNIQUE(digest,policy_version)
        );
        CREATE INDEX IF NOT EXISTS capsule_jobs_ready ON capsule_jobs(status,next_attempt);
        CREATE TABLE IF NOT EXISTS capsule_attempts (
            job_id INTEGER NOT NULL REFERENCES capsule_jobs(id), attempt INTEGER NOT NULL,
            started_at REAL NOT NULL, finished_at REAL, result TEXT,
            PRIMARY KEY(job_id,attempt)
        );
        CREATE TABLE IF NOT EXISTS capsule_evidence (
            digest TEXT NOT NULL REFERENCES capsule_artifacts(sha256), version INTEGER NOT NULL,
            provider TEXT NOT NULL, provider_result_id TEXT NOT NULL, policy_version TEXT NOT NULL,
            scanned_at REAL NOT NULL, expires_at REAL NOT NULL,
            verdict TEXT NOT NULL CHECK(verdict IN ('accepted','rejected','blocked','error')),
            summary TEXT NOT NULL, raw_reference TEXT NOT NULL,
            PRIMARY KEY(digest,version)
        );
        CREATE TRIGGER IF NOT EXISTS capsule_evidence_no_update
            BEFORE UPDATE ON capsule_evidence BEGIN
                SELECT RAISE(ABORT, 'Evidence is immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_evidence_no_delete
            BEFORE DELETE ON capsule_evidence BEGIN
                SELECT RAISE(ABORT, 'Evidence is immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_evidence_no_replace
            BEFORE INSERT ON capsule_evidence
            WHEN EXISTS(SELECT 1 FROM capsule_evidence
                WHERE digest=NEW.digest AND version=NEW.version)
            BEGIN SELECT RAISE(ABORT, 'Evidence is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS capsule_revision_guard
            BEFORE UPDATE OF state ON capsule_operations
            WHEN NEW.revision != OLD.revision+1
            BEGIN SELECT RAISE(ABORT, 'State revision must increase'); END;
        CREATE TRIGGER IF NOT EXISTS capsule_state_guard
            BEFORE UPDATE OF state ON capsule_operations
            WHEN NOT (
                (OLD.state='reserved' AND NEW.state IN ('uploading','expired','withdrawn')) OR
                (OLD.state='uploading' AND NEW.state IN ('reserved','quarantined','expired','withdrawn')) OR
                (OLD.state='quarantined' AND NEW.state IN ('scan_pending','expired','withdrawn')) OR
                (OLD.state='scan_pending' AND NEW.state IN ('scan_blocked','rejected','publishable','expired','withdrawn')) OR
                (OLD.state='scan_blocked' AND NEW.state IN ('scan_pending','expired','withdrawn')) OR
                (OLD.state='rejected' AND NEW.state IN ('expired','withdrawn')) OR
                (OLD.state='publishable' AND NEW.state IN ('scan_blocked','expired','withdrawn'))
            )
            BEGIN SELECT RAISE(ABORT, 'Invalid capsule state transition'); END;
        CREATE TRIGGER IF NOT EXISTS capsule_transition_no_update
            BEFORE UPDATE ON capsule_transitions
            BEGIN SELECT RAISE(ABORT, 'Transition history is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS capsule_transition_no_delete
            BEFORE DELETE ON capsule_transitions
            BEGIN SELECT RAISE(ABORT, 'Transition history is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS capsule_transition_no_replace
            BEFORE INSERT ON capsule_transitions
            WHEN EXISTS(SELECT 1 FROM capsule_transitions
                WHERE release_id=NEW.release_id AND revision=NEW.revision)
            BEGIN SELECT RAISE(ABORT, 'Transition history is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS capsule_transition_insert
            AFTER INSERT ON capsule_operations BEGIN
                INSERT INTO capsule_transitions VALUES (
                    NEW.release_id,NEW.revision,NEW.state,NEW.updated_at);
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_transition_update
            AFTER UPDATE OF state ON capsule_operations BEGIN
                INSERT INTO capsule_transitions VALUES (
                    NEW.release_id,NEW.revision,NEW.state,NEW.updated_at);
            END;
        INSERT OR IGNORE INTO capsule_migrations VALUES (1,datetime('now'));
    """)
    # Existing Batch 2 internal facts stay private and retain their immutable identity.
    db.execute("""
        INSERT INTO capsule_operations(release_id,state,revision,updated_at)
        SELECT r.release_id, CASE WHEN b.artifact_sha256 IS NULL THEN 'reserved'
            ELSE 'scan_blocked' END, 1, CAST(strftime('%s',r.created_at) AS REAL)
        FROM capsule_releases r LEFT JOIN capsule_release_artifacts b USING(release_id)
        WHERE NOT EXISTS(SELECT 1 FROM capsule_operations o WHERE o.release_id=r.release_id)
    """)
    db.commit()


class PrivateBucket:
    def __init__(self, settings: IngestionSettings):
        self.settings = settings
        for path in (settings.quarantine, settings.retained, settings.evidence):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.restrict(path, directory=True)

    @staticmethod
    @cache
    def windows_sid() -> str:
        return subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"], check=True,
            capture_output=True, text=True,
        ).stdout.strip().split(",")[-1].strip('"')

    @staticmethod
    def restrict(path: Path, *, directory: bool = False):
        if os.name == "nt":
            # Set only the DACL: Set-Acl can attempt SACL writes requiring elevated
            # SeSecurityPrivilege, even for an ordinary service-owned directory.
            import ctypes
            from ctypes import wintypes

            sid = PrivateBucket.windows_sid()
            inheritance = "OICI" if directory else ""
            sddl = f"D:P(A;{inheritance};FA;;;{sid})(A;{inheritance};FA;;;SY)"
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(wintypes.DWORD),
            ]
            advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
            advapi.GetSecurityDescriptorDacl.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
            ]
            advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
            advapi.SetNamedSecurityInfoW.argtypes = [
                wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ]
            advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            kernel.LocalFree.restype = ctypes.c_void_p
            descriptor = ctypes.c_void_p()
            if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
                raise OSError("Private bucket ACL creation failed")
            try:
                present, defaulted = wintypes.BOOL(), wintypes.BOOL()
                dacl = ctypes.c_void_p()
                if not advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
                    raise OSError("Private bucket ACL reading failed")
                if advapi.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, dacl, None) != 0:
                    raise OSError("Private bucket ACL setup failed")
            finally:
                kernel.LocalFree(descriptor)
        else:
            os.chmod(path, 0o700 if directory else 0o600)

    def artifact(self, digest: str, *, retained: bool = False) -> Path:
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise CapsuleBlocked("artifact_invalid")
        root = self.settings.retained if retained else self.settings.quarantine
        path = root / f"{digest}.jar"
        if path.is_symlink() or path.is_junction():
            raise CapsuleBlocked("storage_unavailable")
        return path

    def validate(self, path: Path):
        try:
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if not entries or len(entries) > 10000:
                    raise ValueError("Entry bound")
                expanded = 0
                names = set()
                for entry in entries:
                    # ZipInfo normalizes backslashes on Windows; inspect the
                    # original spelling before accepting an archive member.
                    name = entry.orig_filename
                    parts = PurePosixPath(name).parts
                    mode = entry.external_attr >> 16
                    if (
                        not name or name in names or "\\" in name or ":" in name
                        or name.startswith("/") or ".." in parts or "\x00" in name
                        or any(ord(c) < 32 for c in name)
                        or stat.S_ISLNK(mode) or entry.flag_bits & 1
                    ):
                        raise ValueError("Unsafe entry")
                    names.add(name)
                    expanded += entry.file_size
                    if (
                        expanded > self.settings.max_bytes * 4
                        or entry.file_size > self.settings.max_bytes * 4
                        or entry.file_size > max(entry.compress_size, 1) * 100
                    ):
                        raise ValueError("Decompression bound")
                if not any(n.endswith(".class") or n.upper() == "META-INF/MANIFEST.MF" for n in names):
                    raise ValueError("Not a JAR")
                # CRC-check all data without extraction; declared expansion is bounded above.
                if archive.testzip() is not None:
                    raise ValueError("CRC mismatch")
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, ValueError, EOFError, zlib.error) as exc:
            raise CapsuleBlocked("artifact_invalid") from exc

    async def stream(self, chunks: AsyncIterable[bytes], token: str) -> tuple[Path, str, int]:
        path = self.settings.quarantine / f"upload-{token}.part"
        checksum = hashlib.sha256()
        size = 0
        try:
            with path.open("xb") as output:
                self.restrict(path)
                async with asyncio.timeout(self.settings.upload_seconds):
                    async for chunk in chunks:
                        size += len(chunk)
                        if size > self.settings.max_bytes:
                            raise CapsuleBlocked("artifact_too_large")
                        checksum.update(chunk)
                        await asyncio.to_thread(output.write, chunk)
                if not size:
                    raise CapsuleBlocked("artifact_empty")
                await asyncio.to_thread(output.flush)
                await asyncio.to_thread(os.fsync, output.fileno())
            await asyncio.to_thread(self.validate, path)
            return path, checksum.hexdigest(), size
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    @staticmethod
    def verify(path: Path, digest: str) -> bool:
        if not path.is_file() or path.is_symlink():
            return False
        checksum = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                checksum.update(chunk)
        return checksum.hexdigest() == digest

    def retain(self, digest: str):
        destination = self.artifact(digest, retained=True)
        if self.verify(destination, digest):
            return
        source = self.artifact(digest)
        if not self.verify(source, digest):
            raise CapsuleBlocked("artifact_unavailable")
        scratch = self.settings.retained / f"retain-{secrets.token_hex(16)}.part"
        try:
            with source.open("rb") as incoming, scratch.open("xb") as outgoing:
                self.restrict(scratch)
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            if not self.verify(scratch, digest):
                raise CapsuleBlocked("artifact_unavailable")
            os.replace(scratch, destination)
        finally:
            scratch.unlink(missing_ok=True)


@dataclass(frozen=True)
class ScanResult:
    provider_result_id: str
    verdict: Literal["accepted", "rejected", "blocked", "error"]
    summary: str
    retryable: bool = False


class Scanner(Protocol):
    provider: str
    def scan(self, digest: str, path: Path) -> ScanResult: ...


class DisabledScanner:
    provider = "disabled"

    def scan(self, digest: str, path: Path) -> ScanResult:
        return ScanResult("unconfigured", "blocked", "scanning_not_configured")


class CapsuleWorkflow:
    def __init__(
        self, store: CommunityStore, settings: IngestionSettings, *,
        trusted_provider: str | None = None,
    ):
        self.store = store
        self.settings = settings
        self.trusted_provider = trusted_provider
        self.bucket = PrivateBucket(settings)

    @staticmethod
    def owned(db, release_id: str, owner: str):
        row = db.execute(
            "SELECT r.*, b.artifact_sha256, o.state, o.revision, o.updated_at, "
            "o.upload_token,o.upload_expires FROM capsule_releases r "
            "JOIN capsule_operations o USING(release_id) "
            "LEFT JOIN capsule_release_artifacts b USING(release_id) "
            "WHERE r.release_id=? AND r.uploader_id=?", (release_id, owner),
        ).fetchone()
        if row is None:
            raise CapsuleBlocked("release_not_found")
        return row

    @staticmethod
    def transition(db, release_id: str, state: str, now: float):
        row = db.execute("SELECT state FROM capsule_operations WHERE release_id=?", (release_id,)).fetchone()
        if row["state"] == state:
            return
        if state not in TRANSITIONS[row["state"]]:
            logger.warning("capsule_unexpected_transition", extra={"state": row["state"], "target": state})
            raise CapsuleBlocked("invalid_state")
        db.execute(
            "UPDATE capsule_operations SET state=?,revision=revision+1,updated_at=?,"
            "upload_token=NULL,upload_expires=NULL WHERE release_id=?", (state, now, release_id),
        )

    def response(self, db, row) -> dict:
        evidence = db.execute(
            "SELECT * FROM capsule_evidence WHERE digest=? ORDER BY version DESC LIMIT 1",
            (row["artifact_sha256"],),
        ).fetchone()
        job = db.execute(
            "SELECT * FROM capsule_jobs WHERE digest=? AND policy_version=?",
            (row["artifact_sha256"], self.settings.policy_version),
        ).fetchone()
        return {
            "releaseId": row["release_id"], "ownerId": row["uploader_id"],
            "project": row["project"], "version": row["version"],
            "sourceUrl": row["declared_source"], "createdAt": row["created_at"],
            "artifactSha256": row["artifact_sha256"], "state": row["state"],
            "revision": row["revision"], "updatedAt": timestamp(row["updated_at"]),
            "publicDownloadAvailable": False,
            "evidence": {
                "version": evidence["version"], "artifactSha256": evidence["digest"],
                "provider": evidence["provider"], "providerResultId": evidence["provider_result_id"],
                "policyVersion": evidence["policy_version"], "scannedAt": timestamp(evidence["scanned_at"]),
                "expiresAt": timestamp(evidence["expires_at"]), "verdict": evidence["verdict"],
                "summary": evidence["summary"],
            } if evidence else None,
            "queue": {
                "status": job["status"], "attempts": job["attempts"], "maxAttempts": job["max_attempts"],
                "nextAttemptAt": timestamp(job["next_attempt"]) if job["status"] == "pending" else None,
                "lastError": job["last_error"],
            } if job else None,
        }

    def reserve(self, owner: str, project: str, version: str, source: str, key: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key):
            raise CapsuleBlocked("invalid_input")
        now = time.time()
        with self.store.connect() as db:
            existing = db.execute(
                "SELECT release_id FROM capsule_idempotency WHERE owner_id=? AND key=?", (owner, key),
            ).fetchone()
            if existing:
                row = self.owned(db, existing["release_id"], owner)
                if (row["project"], row["version"], row["declared_source"]) != (project, version, source):
                    raise CapsuleBlocked("idempotency_conflict")
                return self.response(db, row)
            count = db.execute(
                "SELECT count(*) FROM capsule_releases r JOIN capsule_operations o USING(release_id) "
                f"WHERE uploader_id=? AND state IN ({','.join('?' for _ in ACTIVE)})", (owner, *ACTIVE),
            ).fetchone()[0]
            if count >= self.settings.max_active:
                raise CapsuleBlocked("submission_limit")
            release_id = secrets.token_hex(16)
            db.execute("INSERT INTO capsule_releases VALUES (?,?,?,?,?,?)",
                       (release_id, owner, project, version, source, timestamp(now)))
            db.execute("INSERT INTO capsule_operations VALUES (?,'reserved',1,?,NULL,NULL)", (release_id, now))
            db.execute("INSERT INTO capsule_idempotency VALUES (?,?,?)", (owner, key, release_id))
            return self.response(db, self.owned(db, release_id, owner))

    def get(self, release_id: str, owner: str) -> dict:
        with self.store.connect() as db:
            row = self.owned(db, release_id, owner)
            if row["state"] == "publishable" and not self.publishable(db, row):
                self.transition(db, release_id, "scan_blocked", time.time())
                row = self.owned(db, release_id, owner)
            return self.response(db, row)

    def mine(self, owner: str) -> dict:
        with self.store.connect() as db:
            ids = [row[0] for row in db.execute(
                "SELECT release_id FROM capsule_releases WHERE uploader_id=? ORDER BY created_at DESC LIMIT 100",
                (owner,),
            )]
        return {"capsules": [self.get(release_id, owner) for release_id in ids]}

    async def upload(self, release_id: str, owner: str, chunks: AsyncIterable[bytes]) -> dict:
        token = secrets.token_hex(16)
        bound = None
        now = time.time()
        with self.store.connect() as db:
            row = self.owned(db, release_id, owner)
            if row["state"] in {"expired", "withdrawn"}:
                raise CapsuleBlocked("invalid_state")
            bound = row["artifact_sha256"]
            if bound is None:
                if row["state"] == "uploading" and row["upload_expires"] > now:
                    raise CapsuleBlocked("upload_in_progress")
                if row["state"] == "uploading":
                    self.transition(db, release_id, "reserved", now)
                if row["state"] != "reserved" and row["state"] != "uploading":
                    raise CapsuleBlocked("invalid_state")
                self.transition(db, release_id, "uploading", now)
                db.execute(
                    "UPDATE capsule_operations SET upload_token=?,upload_expires=? WHERE release_id=?",
                    (token, now + self.settings.upload_seconds + 30, release_id),
                )
        path = None
        try:
            path, digest, size = await self.bucket.stream(chunks, token)
            with self.store.connect() as db:
                row = self.owned(db, release_id, owner)
                if bound:
                    if row["state"] in {"withdrawn", "expired"}:
                        raise CapsuleBlocked("invalid_state")
                    if digest != bound:
                        raise CapsuleBlocked("release_already_bound")
                else:
                    if row["state"] != "uploading" or row["upload_token"] != token or row["upload_expires"] <= time.time():
                        raise CapsuleBlocked("invalid_state")
                    destination = self.bucket.artifact(digest)
                    if destination.exists():
                        if not self.bucket.verify(destination, digest):
                            raise CapsuleBlocked("storage_unavailable")
                    else:
                        os.replace(path, destination)
                    artifact = db.execute("SELECT size FROM capsule_artifacts WHERE sha256=?", (digest,)).fetchone()
                    if artifact is None:
                        db.execute("INSERT INTO capsule_artifacts(sha256,size) VALUES (?,?)", (digest, size))
                    elif artifact["size"] != size:
                        raise CapsuleBlocked("artifact_identity_conflict")
                    db.execute("INSERT INTO capsule_release_artifacts VALUES (?,?)", (release_id, digest))
                    self.transition(db, release_id, "quarantined", time.time())
                    db.execute(
                        "INSERT OR IGNORE INTO capsule_jobs(digest,policy_version,status,max_attempts,next_attempt) "
                        "VALUES (?,?,'pending',?,?)",
                        (digest, self.settings.policy_version, self.settings.max_attempts, time.time()),
                    )
                    self.transition(db, release_id, "scan_pending", time.time())
                    job = db.execute("SELECT status FROM capsule_jobs WHERE digest=? AND policy_version=?",
                                     (digest, self.settings.policy_version)).fetchone()
                    if job["status"] == "complete" and self.publishable(db, self.owned(db, release_id, owner)):
                        self.transition(db, release_id, "publishable", time.time())
                    elif job["status"] in {"blocked", "failed", "complete"}:
                        evidence = db.execute("SELECT verdict FROM capsule_evidence WHERE digest=? ORDER BY version DESC LIMIT 1",
                                              (digest,)).fetchone()
                        target = "rejected" if evidence and evidence["verdict"] == "rejected" else "scan_blocked"
                        self.transition(db, release_id, target, time.time())
            return self.get(release_id, owner)
        finally:
            if path is not None:
                path.unlink(missing_ok=True)
            if bound is None:
                with self.store.connect() as db:
                    row = self.owned(db, release_id, owner)
                    if row["state"] == "uploading" and row["upload_token"] == token:
                        self.transition(db, release_id, "reserved", time.time())

    def retry(self, release_id: str, owner: str) -> dict:
        with self.store.connect() as db:
            row = self.owned(db, release_id, owner)
            job = db.execute("SELECT * FROM capsule_jobs WHERE digest=? AND policy_version=?",
                             (row["artifact_sha256"], self.settings.policy_version)).fetchone()
            if row["state"] == "scan_pending" and job and job["status"] in {"pending", "leased"}:
                return self.response(db, row)
            if row["state"] != "scan_blocked" or not job or job["status"] == "leased":
                raise CapsuleBlocked("retry_not_eligible")
            if job["attempts"] >= job["max_attempts"]:
                raise CapsuleBlocked("retry_not_eligible")
            if not self.bucket.verify(self.bucket.artifact(row["artifact_sha256"]), row["artifact_sha256"]):
                raise CapsuleBlocked("artifact_unavailable")
            db.execute("UPDATE capsule_jobs SET status='pending',next_attempt=? WHERE id=?", (time.time(), job["id"]))
            self.transition(db, release_id, "scan_pending", time.time())
            return self.response(db, self.owned(db, release_id, owner))

    def withdraw(self, release_id: str, owner: str) -> dict:
        with self.store.connect() as db:
            row = self.owned(db, release_id, owner)
            if row["state"] != "withdrawn":
                self.transition(db, release_id, "withdrawn", time.time())
            return self.response(db, self.owned(db, release_id, owner))

    def publishable(self, db, row, *, trusted_provider: str | None = None) -> bool:
        digest = row["artifact_sha256"]
        evidence = db.execute(
            "SELECT * FROM capsule_evidence WHERE digest=? ORDER BY version DESC LIMIT 1", (digest,),
        ).fetchone()
        provider = trusted_provider or self.trusted_provider or self.settings.scanner
        return bool(
            digest and provider != "disabled" and row["declared_source"].startswith("https://")
            and evidence and evidence["digest"] == digest and evidence["verdict"] == "accepted"
            and evidence["provider"] == provider and evidence["policy_version"] == self.settings.policy_version
            and evidence["scanned_at"] <= time.time() < evidence["expires_at"]
            and self.bucket.verify(self.bucket.artifact(digest, retained=True), digest)
        )

    def claim(self, worker: str) -> dict | None:
        now = time.time()
        with self.store.connect() as db:
            expired = db.execute("SELECT * FROM capsule_jobs WHERE status='leased' AND lease_expires<=?", (now,)).fetchall()
            for job in expired:
                db.execute("UPDATE capsule_attempts SET finished_at=?,result='lease_expired' WHERE job_id=? AND attempt=?",
                           (now, job["id"], job["attempts"]))
                status = "failed" if job["attempts"] >= job["max_attempts"] else "pending"
                db.execute(
                    "UPDATE capsule_jobs SET status=?,lease_token=NULL,lease_owner=NULL,lease_expires=NULL,"
                    "last_error='lease_expired',next_attempt=? WHERE id=?",
                    (status, now + min(self.settings.retry_seconds * 2 ** min(job["attempts"] - 1, 10), 3600), job["id"]),
                )
                if status == "failed":
                    self.job_transition(db, job["digest"], "scan_blocked", now)
            row = db.execute(
                "SELECT j.* FROM capsule_jobs j WHERE j.status='pending' AND j.next_attempt<=? "
                "AND j.attempts<j.max_attempts AND j.policy_version=? "
                "AND EXISTS(SELECT 1 FROM capsule_release_artifacts b JOIN capsule_operations o USING(release_id) "
                "WHERE b.artifact_sha256=j.digest AND o.state='scan_pending') ORDER BY j.id LIMIT 1",
                (now, self.settings.policy_version),
            ).fetchone()
            if row is None:
                return None
            token = secrets.token_hex(16)
            db.execute(
                "UPDATE capsule_jobs SET status='leased',attempts=attempts+1,lease_token=?,lease_owner=?,lease_expires=? WHERE id=?",
                (token, worker, now + self.settings.lease_seconds, row["id"]),
            )
            db.execute("INSERT INTO capsule_attempts(job_id,attempt,started_at) VALUES (?,?,?)",
                       (row["id"], row["attempts"] + 1, now))
            return dict(db.execute("SELECT * FROM capsule_jobs WHERE id=?", (row["id"],)).fetchone())

    def job_transition(self, db, digest: str, state: str, now: float):
        rows = db.execute(
            "SELECT b.release_id FROM capsule_release_artifacts b JOIN capsule_operations o USING(release_id) "
            "WHERE b.artifact_sha256=? AND o.state='scan_pending'", (digest,),
        ).fetchall()
        for row in rows:
            self.transition(db, row["release_id"], state, now)

    def complete(self, job: dict, result: ScanResult, provider: str, *, trusted_provider: str | None = None):
        now = time.time()
        trusted_provider = trusted_provider or self.trusted_provider
        with self.store.connect() as db:
            current = db.execute("SELECT * FROM capsule_jobs WHERE id=?", (job["id"],)).fetchone()
            if (
                not current or current["status"] != "leased" or current["lease_token"] != job["lease_token"]
                or current["lease_expires"] <= now or current["policy_version"] != self.settings.policy_version
                or current["digest"] != job["digest"] or current["attempts"] != job["attempts"]
            ):
                raise CapsuleBlocked("stale_lease")
            if (
                not isinstance(result, ScanResult) or result.verdict not in {"accepted", "rejected", "blocked", "error"}
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,120}", provider)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,200}", result.provider_result_id)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,200}", result.summary)
            ):
                result = ScanResult("invalid-result", "error", "scanner_invalid_result")
                provider = "invalid"
            if result.verdict == "accepted" and (provider == "disabled" or provider != trusted_provider):
                result = ScanResult("untrusted-result", "blocked", "scanner_not_trusted")
            if result.verdict == "accepted":
                try:
                    self.bucket.retain(job["digest"])
                except (OSError, CapsuleBlocked):
                    result = ScanResult("retention-failed", "error", "artifact_unavailable", retryable=True)
            version = db.execute("SELECT COALESCE(MAX(version),0)+1 FROM capsule_evidence WHERE digest=?",
                                 (job["digest"],)).fetchone()[0]
            raw_reference = f"{job['digest']}-{version}.json"
            raw = self.settings.evidence / raw_reference
            scratch = self.settings.evidence / f"evidence-{secrets.token_hex(16)}.part"
            try:
                with scratch.open("x", encoding="utf-8") as output:
                    self.bucket.restrict(scratch)
                    json.dump({"provider": provider, "providerResultId": result.provider_result_id,
                               "verdict": result.verdict, "summary": result.summary}, output)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(scratch, raw)
            finally:
                scratch.unlink(missing_ok=True)
            db.execute("INSERT INTO capsule_evidence VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (job["digest"], version, provider, result.provider_result_id, self.settings.policy_version,
                        now, now + self.settings.evidence_seconds, result.verdict, result.summary, raw_reference))
            retry = result.verdict == "error" and result.retryable and current["attempts"] < current["max_attempts"]
            status = "pending" if retry else (
                "blocked" if result.verdict == "blocked" else "failed" if result.verdict == "error" else "complete"
            )
            db.execute(
                "UPDATE capsule_jobs SET status=?,next_attempt=?,last_error=?,lease_token=NULL,lease_owner=NULL,"
                "lease_expires=NULL WHERE id=?",
                (status, now + min(self.settings.retry_seconds * 2 ** min(current["attempts"] - 1, 10), 3600),
                 result.summary if result.verdict in {"blocked", "error"} else None, job["id"]),
            )
            db.execute("UPDATE capsule_attempts SET finished_at=?,result=? WHERE job_id=? AND attempt=?",
                       (now, result.summary, job["id"], current["attempts"]))
            if not retry:
                target = {"accepted": "publishable", "rejected": "rejected", "blocked": "scan_blocked", "error": "scan_blocked"}[result.verdict]
                if target == "publishable":
                    rows = db.execute(
                        "SELECT r.*,b.artifact_sha256 FROM capsule_releases r JOIN capsule_release_artifacts b USING(release_id) "
                        "JOIN capsule_operations o USING(release_id) WHERE b.artifact_sha256=? AND o.state='scan_pending'",
                        (job["digest"],),
                    ).fetchall()
                    for row in rows:
                        self.transition(db, row["release_id"],
                                        "publishable" if self.publishable(db, row, trusted_provider=trusted_provider) else "scan_blocked", now)
                else:
                    self.job_transition(db, job["digest"], target, now)
            if status == "failed":
                logger.warning("capsule_scan_failed", extra={"job_id": job["id"], "attempts": current["attempts"]})

    def process_one(self, worker: str, scanner: Scanner | None = None, *, trusted_provider: str | None = None) -> bool:
        job = self.claim(worker)
        if job is None:
            return False
        start = time.monotonic()
        scanner = scanner or DisabledScanner()
        try:
            path = self.bucket.artifact(job["digest"])
            if not self.bucket.verify(path, job["digest"]):
                result = ScanResult("missing-artifact", "error", "artifact_unavailable")
            else:
                result = scanner.scan(job["digest"], path)
        except Exception:
            # Provider exception text can contain credentials, URLs or local paths.
            logger.warning("capsule_scanner_exception", extra={"job_id": job["id"]})
            result = ScanResult("scanner-error", "error", "scanner_error", retryable=True)
        self.complete(job, result, scanner.provider, trusted_provider=trusted_provider)
        if time.monotonic() - start > self.settings.lease_seconds / 2:
            logger.warning("capsule_slow_job", extra={"job_id": job["id"]})
        return True

    def cleanup(self) -> int:
        now = time.time()
        expired = 0
        with self.store.connect() as db:
            for row in db.execute(
                "SELECT r.*,b.artifact_sha256 FROM capsule_releases r "
                "JOIN capsule_release_artifacts b USING(release_id) "
                "JOIN capsule_operations o USING(release_id) WHERE o.state='publishable'",
            ).fetchall():
                if not self.publishable(db, row):
                    self.transition(db, row["release_id"], "scan_blocked", now)
            rows = db.execute(
                "SELECT release_id,state FROM capsule_operations WHERE state NOT IN ('expired','withdrawn','publishable') "
                "AND updated_at<? AND (upload_expires IS NULL OR upload_expires<=?)",
                (now - self.settings.expiry_seconds, now),
            ).fetchall()
            for row in rows:
                self.transition(db, row["release_id"], "expired", now)
                expired += 1
            for row in db.execute(
                "SELECT release_id FROM capsule_operations WHERE state='uploading' AND upload_expires<=?", (now,),
            ).fetchall():
                self.transition(db, row["release_id"], "reserved", now)
            live = {row[0] for row in db.execute(
                "SELECT DISTINCT artifact_sha256 FROM capsule_release_artifacts b JOIN capsule_operations o USING(release_id) "
                "WHERE o.state NOT IN ('expired','withdrawn') OR o.updated_at>?",
                (now - self.settings.expiry_seconds,),
            )}
            leased = {row[0] for row in db.execute(
                "SELECT digest FROM capsule_jobs WHERE status='leased' AND lease_expires>?", (now,),
            )}
            uploading = {f"upload-{row[0]}.part" for row in db.execute(
                "SELECT upload_token FROM capsule_operations WHERE state='uploading' AND upload_expires>?",
                (now,),
            )}
            for root in (self.settings.quarantine, self.settings.retained):
                for path in root.glob("*.jar"):
                    if path.stem not in live | leased and path.stat().st_mtime < now - self.settings.expiry_seconds:
                        path.unlink()
            for root in (self.settings.quarantine, self.settings.retained, self.settings.evidence):
                for path in root.glob("*.part"):
                    if path.name not in uploading and path.stat().st_mtime < now - self.settings.expiry_seconds:
                        path.unlink()
        return expired
