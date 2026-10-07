import hashlib
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote, urlsplit

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

DEV_TOKEN_ENABLED = os.environ.get("DEV_TOKEN", "").lower() == "true"

if DEV_TOKEN_ENABLED:
    print("Dev Token // Enabled")
else:
    print("Dev Token // Disabled")

APP_ROOT = Path(__file__).resolve().parent
RELEASE_DIR = Path(
    os.environ.get("MARS_RELEASE_DIR", "/opt/mars-package-api/releases/1.0.0")
).resolve()
MODS_DIR = RELEASE_DIR / "mods"
MODS_METADATA_PATH = RELEASE_DIR / "mods.json"
MANAGED_DIRS = tuple(
    dict.fromkeys(
        item.strip()
        for item in os.environ.get(
            "MARS_MANAGED_DIRS",
            "mods,config,defaultconfigs,kubejs,resourcepacks,shaderpacks",
        ).split(",")
        if item.strip()
    )
)
MUTABLE_DIRS = tuple(
    item.strip()
    for item in os.environ.get("MARS_MUTABLE_DIRS", "config,defaultconfigs").split(",")
    if item.strip()
)
PUBLIC_API_BASE_URL = os.environ.get("MARS_PUBLIC_BASE_URL", "").rstrip("/")
PACK_VERSION = os.environ.get("MARS_PACK_VERSION", RELEASE_DIR.name)
MINECRAFT_VERSION = os.environ.get("MARS_MINECRAFT_VERSION", "1.21.1")
LOADER = os.environ.get("MARS_LOADER", "neoforge")
LOADER_VERSION = os.environ.get("MARS_LOADER_VERSION", "21.1.250")

if not RELEASE_DIR.is_dir():
    raise RuntimeError(f"Release directory does not exist: {RELEASE_DIR}")

if not MODS_DIR.is_dir():
    raise RuntimeError(f"Mods directory does not exist: {MODS_DIR}")

JWT_SECRET = os.environ.get("MARS_API_JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_AUDIENCE = "mars-client"
JWT_ISSUER = "mars-package-api"

if not JWT_SECRET:
    raise RuntimeError("MARS_API_JWT_SECRET must be set")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.mods = build_mod_inventory()
    app.state.manifest, app.state.release_files = build_release_manifest(app.state.mods)
    yield


app = FastAPI(
    title="Mars Package API",
    version="0.1.0",
    lifespan=lifespan,
)
bearer = HTTPBearer(auto_error=False)


class ModEntry(BaseModel):
    id: str
    name: str
    version: str
    filename: str
    size: int
    sha256: str
    downloadUrl: str


class ModListResponse(BaseModel):
    mods: list[ModEntry]


class ReleaseFile(BaseModel):
    path: str
    sha256: str
    size: int
    required: bool = True
    mutable: bool = False
    side: Literal["client", "both"] = "client"
    downloadUrl: str
    manualDownload: bool = False
    sourcePage: str | None = None


class ReleaseManifest(BaseModel):
    schemaVersion: int
    packVersion: str
    minecraftVersion: str
    loader: str
    loaderVersion: str
    generatedAt: str
    managedDirs: list[str]
    files: list[ReleaseFile]
    curseforgeMods: list[dict[str, Any]] = Field(default_factory=list)
    modsDir: str | None = "mods"


def load_mod_metadata() -> dict[str, dict[str, object]]:
    if not MODS_METADATA_PATH.is_file():
        return {}

    try:
        data = json.loads(MODS_METADATA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Could not read mod metadata {MODS_METADATA_PATH}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError("mods.json must contain an object keyed by JAR filename")

    metadata: dict[str, dict[str, object]] = {}
    for filename, details in data.items():
        if (
            not isinstance(filename, str)
            or Path(filename).name != filename
            or Path(filename).suffix.lower() != ".jar"
            or not isinstance(details, dict)
        ):
            raise RuntimeError(
                "mods.json entries must map JAR filenames to metadata objects"
            )

        allowed_keys = {"id", "name", "version"}
        unexpected = set(details) - allowed_keys
        if unexpected:
            raise RuntimeError(
                f"Unexpected metadata key(s) for {filename}: "
                f"{', '.join(sorted(unexpected))}"
            )
        for key in allowed_keys:
            if key in details and not isinstance(details[key], str):
                raise RuntimeError(
                    f"mods.json field '{key}' for {filename} must be a string"
                )

        metadata[filename] = details

    return metadata


def load_mods() -> dict[str, dict[str, str]]:
    metadata = load_mod_metadata()
    mods: dict[str, dict[str, str]] = {}
    id_pattern = re.compile(r"[a-z0-9][a-z0-9_-]*")
    version_pattern = re.compile(
        r"(?<![A-Za-z0-9])v?(\d+(?:\.\d+)+(?:[-+][A-Za-z][A-Za-z0-9.-]*)?)",
        re.IGNORECASE,
    )

    for path in sorted(MODS_DIR.iterdir(), key=lambda item: item.name.casefold()):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".jar":
            continue

        stem = path.stem
        version_matches = list(version_pattern.finditer(stem))
        version_match = version_matches[-1] if version_matches else None
        inferred_version = version_match.group(1) if version_match else "unknown"
        inferred_name = (
            stem[: version_match.start()].rstrip("-_.") if version_match else stem
        )
        inferred_name = re.sub(r"[-_.]+", " ", inferred_name).strip().title() or stem
        details = metadata.get(path.name, {})

        mod_id = details.get(
            "id", re.sub(r"[^a-z0-9_-]+", "-", stem.casefold()).strip("-")
        )
        name = details.get("name", inferred_name)
        version = details.get("version", inferred_version)
        if not isinstance(mod_id, str) or not id_pattern.fullmatch(mod_id):
            raise RuntimeError(f"Invalid mod id for {path.name}")
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError(f"Invalid mod name for {path.name}")
        if not isinstance(version, str) or not version.strip():
            raise RuntimeError(f"Invalid mod version for {path.name}")
        if mod_id in mods:
            raise RuntimeError(f"Duplicate mod id {mod_id!r} in {MODS_DIR}")

        mods[mod_id] = {
            "id": mod_id,
            "name": name.strip(),
            "version": version.strip(),
            "filename": path.name,
        }

    return mods


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


logger = logging.getLogger("mars-package-api")


def build_mod_inventory() -> dict[str, dict[str, Any]]:
    mods = load_mods()
    inventory: dict[str, dict[str, Any]] = {}

    for mod_id, mod in mods.items():
        path = resolve_mod_path(mod)
        stat = path.stat()
        inventory[mod_id] = {
            **mod,
            "size": stat.st_size,
            "sha256": sha256_file(path),
        }

    if not inventory:
        raise RuntimeError(f"No .jar files found in: {MODS_DIR}")

    logger.info("Loaded %d mod(s) from %s", len(inventory), MODS_DIR)
    return inventory


def safe_release_path(relative_path: str) -> Path:
    parts = relative_path.split("/")
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\\" in relative_path
        or ":" in relative_path
        or "\0" in relative_path
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(f"Unsafe release path: {relative_path}")

    path = RELEASE_DIR
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(
                f"Symlinks are not allowed in release paths: {relative_path}"
            )

    resolved = path.resolve()
    if RELEASE_DIR not in resolved.parents:
        raise ValueError(f"Release path escapes the release directory: {relative_path}")

    return resolved


def build_release_manifest(
    mods: dict[str, dict[str, Any]],
) -> tuple[ReleaseManifest, dict[str, Path]]:
    for directory in (*MANAGED_DIRS, *MUTABLE_DIRS):
        try:
            safe_release_path(directory)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

    release_files: dict[str, Path] = {}
    mod_files = {f"mods/{mod['filename']}": mod for mod in mods.values()}

    def add_file(relative_path: str) -> None:
        if relative_path in release_files:
            return
        try:
            safe_path = safe_release_path(relative_path)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        if not safe_path.is_file():
            raise RuntimeError(f"Managed release file is unavailable: {relative_path}")
        release_files[relative_path] = safe_path

    def fail_walk(error: OSError) -> None:
        raise RuntimeError(f"Could not scan managed release files: {error}") from error

    for directory in MANAGED_DIRS:
        base = safe_release_path(directory)
        if not base.exists():
            continue
        if not base.is_dir():
            raise RuntimeError(f"Managed release path is not a directory: {directory}")

        for current, subdirectories, filenames in os.walk(
            base,
            followlinks=False,
            onerror=fail_walk,
        ):
            current_path = Path(current)
            subdirectories[:] = sorted(
                name
                for name in subdirectories
                if not (current_path / name).is_symlink()
            )
            for filename in sorted(filenames, key=str.casefold):
                path = current_path / filename
                if path.is_symlink() or not path.is_file():
                    continue
                relative_path = path.relative_to(RELEASE_DIR).as_posix()
                add_file(relative_path)

    files: list[ReleaseFile] = []
    for relative_path, path in sorted(release_files.items()):
        mod = mod_files.get(relative_path)
        if mod:
            size = mod["size"]
            sha256 = mod["sha256"]
        else:
            size = path.stat().st_size
            sha256 = sha256_file(path)

        mutable = any(
            relative_path == directory or relative_path.startswith(f"{directory}/")
            for directory in MUTABLE_DIRS
        )
        files.append(
            ReleaseFile(
                path=relative_path,
                sha256=sha256,
                size=size,
                mutable=mutable,
                downloadUrl=f"/api/v1/files/{quote(relative_path, safe='/')}",
            )
        )

    manifest = ReleaseManifest(
        schemaVersion=1,
        packVersion=PACK_VERSION,
        minecraftVersion=MINECRAFT_VERSION,
        loader=LOADER,
        loaderVersion=LOADER_VERSION,
        generatedAt=datetime.now(timezone.utc).isoformat(),
        managedDirs=list(MANAGED_DIRS),
        files=files,
        modsDir="mods",
    )
    logger.info("Loaded %d release file(s) from %s", len(files), RELEASE_DIR)
    return manifest, release_files


def resolve_mod_path(mod: dict[str, str]) -> Path:
    path = (MODS_DIR / mod["filename"]).resolve()

    if MODS_DIR.resolve() not in path.parents or not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mod file is unavailable",
        )

    return path


def get_mod_path(mod_id: str) -> tuple[dict[str, Any], Path]:
    mod = app.state.mods.get(mod_id)

    if not mod:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown mod",
        )

    return mod, resolve_mod_path(mod)


def require_mars_client(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scope = payload.get("scope", "")
    scopes = set(scope.split())

    if "mods:read" not in scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing mods:read scope",
        )

    return payload


@app.get("/api/v1/manifest/preview", response_model=ReleaseManifest)
def get_release_manifest(
    _token: Annotated[dict, Depends(require_mars_client)],
) -> ReleaseManifest:
    parsed_base = urlsplit(PUBLIC_API_BASE_URL)
    if (
        parsed_base.scheme != "https"
        or not parsed_base.netloc
        or parsed_base.username
        or parsed_base.password
        or parsed_base.query
        or parsed_base.fragment
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MARS_PUBLIC_BASE_URL must be a public HTTPS base URL",
        )

    files = [
        item.model_copy(
            update={
                "downloadUrl": f"{PUBLIC_API_BASE_URL}{item.downloadUrl}",
            }
        )
        for item in app.state.manifest.files
    ]
    return app.state.manifest.model_copy(update={"files": files})


def published_artifact_path(filename: str) -> Path:
    try:
        path = safe_release_path(filename)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Signed release artifacts are unavailable",
        ) from exc
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Signed release artifacts are unavailable",
        )
    return path


@app.get("/api/v1/manifest.json")
def published_manifest() -> FileResponse:
    return FileResponse(
        path=published_artifact_path("manifest.json"),
        media_type="application/json",
        headers={
            "Cache-Control": "public, max-age=300",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/manifest.json.sig")
def published_manifest_signature() -> FileResponse:
    return FileResponse(
        path=published_artifact_path("manifest.json.sig"),
        media_type="text/plain",
        headers={
            "Cache-Control": "public, max-age=300",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/files/{relative_path:path}")
def download_release_file(
    relative_path: str,
) -> FileResponse:
    if relative_path not in app.state.release_files:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Release file is unavailable",
        )

    try:
        path = safe_release_path(relative_path)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Release file is unavailable",
        )
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Release file is unavailable",
        )

    return FileResponse(
        path=path,
        filename=path.name,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "private, max-age=3600",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/mods", response_model=ModListResponse)
def list_mods(
    _token: Annotated[dict, Depends(require_mars_client)],
) -> ModListResponse:
    entries = [
        ModEntry(
            id=mod["id"],
            name=mod["name"],
            version=mod["version"],
            filename=mod["filename"],
            size=mod["size"],
            sha256=mod["sha256"],
            downloadUrl=f"/api/v1/mods/{mod['id']}/download",
        )
        for mod in sorted(
            app.state.mods.values(),
            key=lambda item: (item["name"].casefold(), item["filename"].casefold()),
        )
    ]

    return ModListResponse(mods=entries)


@app.get("/api/v1/mods/{mod_id}/download")
def download_mod(
    mod_id: str,
    _token: Annotated[dict, Depends(require_mars_client)],
) -> FileResponse:
    mod, path = get_mod_path(mod_id)

    return FileResponse(
        path=path,
        filename=mod["filename"],
        media_type="application/java-archive",
        headers={
            "Cache-Control": "private, max-age=3600",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/health")
def health() -> dict:
    return {
        "service": "mars-package-api",
        "status": "nominal",
        "time": datetime.now(timezone.utc).isoformat(),
    }


# Development helper only. Remove or protect this endpoint in production.
if DEV_TOKEN_ENABLED:

    @app.post("/api/v1/dev-token")
    def create_dev_token() -> dict:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        token = jwt.encode(
            {
                "sub": "mars-client-development",
                "scope": "mods:read",
                "aud": JWT_AUDIENCE,
                "iss": JWT_ISSUER,
                "exp": expires_at,
            },
            JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_at": expires_at.isoformat(),
        }
