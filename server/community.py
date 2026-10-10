"""Durable metadata-only community API; separate from package download credentials."""

import hashlib
import ipaddress
import json
import logging
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

if __package__:
    from .capsules import initialize_capsules
    from .ingestion import (
        CapsuleBlocked, CapsuleResponse, CapsulesResponse, CapsuleWorkflow,
        IngestionSettings, initialize_ingestion,
    )
else:
    from capsules import initialize_capsules
    from ingestion import (
        CapsuleBlocked, CapsuleResponse, CapsulesResponse, CapsuleWorkflow,
        IngestionSettings, initialize_ingestion,
    )

SESSION_COOKIE = "mars_session"
STATE_COOKIE = "mars_oauth_binding"
DESKTOP_AUDIENCE = "mars-community-desktop"
ISSUER = "mars-community-api"
SESSION_TTL = 7 * 24 * 3600
DEVICE_TTL = 600
STATE_TTL = 600
TOKEN_TTL = 900
POLL_INTERVAL = 5
MAX_BODY = 128 * 1024
logger = logging.getLogger("mars-community-api")


def fail(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def origin(value: str, allow_local: bool = False) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid origin port") from exc
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(char.isspace() for char in value)
        or parsed.scheme not in {"https", "http"}
    ):
        raise ValueError(
            "Use an exact HTTP(S) origin without a path, credentials or query"
        )
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (allow_local and local):
        raise ValueError("HTTPS is required; local HTTP requires deliberate opt-in")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default = (parsed.scheme == "https" and port == 443) or (
        parsed.scheme == "http" and port == 80
    )
    return f"{parsed.scheme}://{host}" + (f":{port}" if port and not default else "")


@dataclass(frozen=True)
class Settings:
    website_url: str = ""
    backend_url: str = ""
    jwt_secret: str = ""
    database: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    allow_local_http: bool = False
    capsules: IngestionSettings | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.jwt_secret)

    @property
    def secure_cookie(self) -> bool:
        return self.backend_url.startswith("https://")

    @property
    def callback_url(self) -> str:
        return self.backend_url + "/api/auth/github/callback"

    def __post_init__(self):
        if not self.enabled:
            return
        if len(self.jwt_secret) < 32:
            raise ValueError("MARS_AUTH_JWT_SECRET must contain at least 32 characters")
        if not self.database:
            raise ValueError("MARS_COMMUNITY_DB must be set")
        if self.capsules is None:
            object.__setattr__(self, "capsules", IngestionSettings.for_database(self.database))
        object.__setattr__(
            self, "website_url", origin(self.website_url, self.allow_local_http)
        )
        object.__setattr__(
            self, "backend_url", origin(self.backend_url, self.allow_local_http)
        )
        if urlsplit(self.website_url).scheme != urlsplit(self.backend_url).scheme:
            raise ValueError("Website and backend must use the same scheme for cookies")
        # Lax cookies require a same-site deployment. Different origins/ports are fine.
        website_host = urlsplit(self.website_url).hostname
        backend_host = urlsplit(self.backend_url).hostname
        if (
            self.allow_local_http
            and self.backend_url.startswith("http://")
            and website_host != backend_host
        ):
            raise ValueError("Local website/backend must use the same hostname")

    @classmethod
    def from_env(cls) -> "Settings":
        secret = os.environ.get("MARS_AUTH_JWT_SECRET", "")
        if secret and secret == os.environ.get("MARS_API_JWT_SECRET"):
            raise ValueError("Community and package JWT secrets must be different")
        database = os.environ.get("MARS_COMMUNITY_DB", "")
        if database and not Path(database).is_absolute():
            database = str(Path(__file__).resolve().parent.parent / database)
        return cls(
            website_url=os.environ.get("WEBSITE_URL", ""),
            backend_url=os.environ.get("MARS_AUTH_PUBLIC_URL", ""),
            jwt_secret=secret,
            database=database,
            github_client_id=os.environ.get("GITHUB_CLIENT_ID", ""),
            github_client_secret=os.environ.get("GITHUB_CLIENT_SECRET", ""),
            allow_local_http=os.environ.get("MARS_AUTH_ALLOW_LOCAL_HTTP", "").lower()
            == "true",
            capsules=IngestionSettings.for_database(database, environment=True) if secret else None,
        )


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        # journal_mode must be selected outside a transaction, including on reopen.
        db = sqlite3.connect(path, timeout=10)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if mode.lower() != "wal":
                raise RuntimeError("Community database requires SQLite WAL mode")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA busy_timeout=10000")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, username TEXT NOT NULL, avatar_url TEXT NOT NULL,
                    roles TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    secret_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                    expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oauth_states (
                    secret_hash TEXT PRIMARY KEY, binding_hash TEXT NOT NULL,
                    request_id TEXT, expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS devices (
                    secret_hash TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                    expires INTEGER NOT NULL, status TEXT NOT NULL,
                    user_id TEXT REFERENCES users(id), last_poll INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS profiles (
                    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
                    name TEXT NOT NULL, description TEXT NOT NULL, mods TEXT NOT NULL,
                    visibility TEXT NOT NULL CHECK(visibility IN ('private', 'public')),
                    source_profile_id TEXT, updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS profiles_owner ON profiles(owner_id);
                CREATE TABLE IF NOT EXISTS rate_limits (
                    bucket TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL
                );
            """)
            initialize_capsules(db)
            initialize_ingestion(db)
        finally:
            db.close()
        if os.name != "nt":
            os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            # Serializes single-use state/device transitions across workers.
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def rate_limit(self, bucket: str, limit: int, seconds: int = 60):
        now = int(time.time())
        window = now // seconds
        with self.connect() as db:
            db.execute("DELETE FROM rate_limits WHERE window < ?", (window - 2,))
            db.execute("DELETE FROM oauth_states WHERE expires < ?", (now - 86400,))
            db.execute("DELETE FROM sessions WHERE expires < ?", (now,))
            db.execute("DELETE FROM devices WHERE expires < ?", (now - 86400,))
            row = db.execute(
                "SELECT * FROM rate_limits WHERE bucket = ?", (bucket,)
            ).fetchone()
            if row and row["window"] == window and row["count"] >= limit:
                raise HTTPException(
                    429,
                    detail={"code": "rate_limited", "message": "Try again later"},
                    headers={"Retry-After": str(seconds - now % seconds)},
                )
            db.execute(
                "INSERT INTO rate_limits VALUES (?, ?, 1) ON CONFLICT(bucket) DO UPDATE SET "
                "window=excluded.window, count=CASE WHEN rate_limits.window=excluded.window "
                "THEN rate_limits.count+1 ELSE 1 END",
                (bucket, window),
            )

    @staticmethod
    def user(db, user_id: str) -> dict:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise fail(401, "invalid_identity", "Identity is unavailable")
        return {
            "id": row["id"],
            "username": row["username"],
            "avatarUrl": row["avatar_url"],
            "roles": json.loads(row["roles"]),
        }

    @staticmethod
    def profile(db, row) -> dict:
        return {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "visibility": row["visibility"],
            "owner": Store.user(db, row["owner_id"]),
            "mods": json.loads(row["mods"]),
            "sourceProfileId": row["source_profile_id"],
            "updatedAt": row["updated_at"],
        }


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)


class ProfileMod(Input):
    name: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=80)
    sourceUrl: str = Field(min_length=1, max_length=2048)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")

    @field_validator("sourceUrl")
    @classmethod
    def safe_source(cls, value: str) -> str:
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid source URL") from exc
        host = parsed.hostname
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username
            or parsed.password
            or parsed.fragment
            or port not in {None, 443}
            or "\\" in value
            or any(ord(c) < 33 or ord(c) == 127 for c in value)
            or host.lower() == "localhost"
            or host.lower().endswith((".localhost", ".local"))
            or "." not in host
        ):
            raise ValueError(
                "Mod source must be a public HTTPS URL without credentials"
            )
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError("Private/reserved IP addresses are not allowed")
        return value

    @field_validator("sha256")
    @classmethod
    def lowercase_hash(cls, value: str) -> str:
        return value.lower()


class ProfileCreate(Input):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(max_length=4000)
    mods: list[ProfileMod] = Field(max_length=200)
    sourceProfileId: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")


class CapsuleCreate(Input):
    project: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=80)
    sourceUrl: str = Field(min_length=1, max_length=2048)

    @field_validator("sourceUrl")
    @classmethod
    def safe_source(cls, value: str) -> str:
        return ProfileMod.safe_source(value)


class ProfilePatch(Input):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=4000)
    mods: list[ProfileMod] | None = Field(default=None, max_length=200)
    sourceProfileId: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")

    @model_validator(mode="after")
    def no_null_fields(self):
        for key in ("name", "description", "mods"):
            if key in self.model_fields_set and getattr(self, key) is None:
                raise ValueError(f"{key} cannot be null")
        return self


class Empty(Input):
    pass


class Poll(Input):
    deviceCode: str = Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class Approve(Input):
    requestId: str = Field(pattern=r"^[a-f0-9]{32}$")


class User(BaseModel):
    id: str
    username: str
    avatarUrl: str
    roles: list[str]


class Profile(BaseModel):
    id: str
    name: str
    description: str
    visibility: Literal["private", "public"]
    owner: User
    mods: list[ProfileMod]
    sourceProfileId: str | None
    updatedAt: str


class SessionResponse(BaseModel):
    user: User | None


class ProfilesResponse(BaseModel):
    profiles: list[Profile]


class DeviceResponse(BaseModel):
    deviceCode: str
    requestId: str
    verificationUri: str
    expiresIn: int
    pollInterval: int


class PollResponse(BaseModel):
    status: Literal["pending", "approved", "expired", "denied"]
    accessToken: str | None = None
    user: User | None = None


class ApprovalResponse(BaseModel):
    status: Literal["approved"]


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    detail: str | ErrorDetail


class CommunityGuard:
    """Bound JSON request bodies and do not cache identities/private metadata."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith(
            ("/api/auth/", "/api/community/")
        ):
            return await self.app(scope, receive, send)

        async def private_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message["headers"]) + [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                ]
            await send(message)

        # Only the authenticated raw-artifact route may bypass the bounded JSON buffer.
        import re

        if scope["method"] == "PUT" and re.fullmatch(
            r"/api/community/capsules/[a-f0-9]{32}/artifact", scope["path"]
        ):
            return await self.app(scope, receive, private_send)
        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > MAX_BODY:
                response = JSONResponse(
                    {
                        "detail": {
                            "code": "body_too_large",
                            "message": "Request exceeds 128 KiB",
                        }
                    },
                    status_code=413,
                )
                return await response(scope, receive, private_send)
            chunks.append(message)
            if not message.get("more_body", False):
                break

        async def replay():
            if chunks:
                return chunks.pop(0)
            return await receive()

        await self.app(scope, replay, private_send)


async def github_identity(settings: Settings, code: str) -> dict:
    # No redirects; fixed provider endpoints only. No user-provided URLs fetched.
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": settings.callback_url,
            },
        )
        token_response.raise_for_status()
        token_payload = token_response.json()
        if not isinstance(token_payload, dict):
            raise TypeError("Invalid OAuth response")
        token = token_payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ValueError("OAuth exchange failed")
        identity_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        identity_response.raise_for_status()
        identity = identity_response.json()
        if not isinstance(identity, dict):
            raise TypeError("Invalid GitHub identity")
        user_id, login, avatar = (
            identity.get("id"),
            identity.get("login"),
            identity.get("avatar_url"),
        )
        if (
            not isinstance(user_id, int)
            or isinstance(user_id, bool)
            or user_id <= 0
            or not isinstance(login, str)
            or not 1 <= len(login) <= 100
            or not isinstance(avatar, str)
            or len(avatar) > 2048
            or not avatar.startswith("https://avatars.githubusercontent.com/")
        ):
            raise ValueError("Invalid GitHub identity")
        return {"id": f"github:{user_id}", "username": login, "avatarUrl": avatar}


def install_community(app: FastAPI, settings: Settings | None = None) -> None:
    settings = settings or Settings.from_env()
    store = Store(settings.database) if settings.enabled else None
    app.state.community_store = store
    app.state.community_settings = settings
    workflow = CapsuleWorkflow(store, settings.capsules) if store and settings.capsules else None
    app.state.capsule_workflow = workflow
    app.add_middleware(CommunityGuard)
    if settings.enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[settings.website_url],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "Authorization", "Idempotency-Key"],
        )
    router = APIRouter(
        responses={
            status: {"model": ErrorResponse}
            for status in (401, 403, 404, 408, 409, 413, 415, 422, 429, 503)
        }
    )

    async def validation_error(request: Request, exc: Exception) -> Response:
        if request.url.path.startswith(("/api/auth/", "/api/community/")):
            return JSONResponse(
                {
                    "detail": {
                        "code": "invalid_input",
                        "message": "Request fields are invalid",
                    }
                },
                status_code=422,
            )
        if isinstance(exc, RequestValidationError):
            return await request_validation_exception_handler(request, exc)
        raise exc

    app.add_exception_handler(RequestValidationError, validation_error)

    async def storage_error(request: Request, exc: Exception) -> Response:
        if request.url.path.startswith(("/api/auth/", "/api/community/")):
            # Keep the traceback, but never log SQL error text or request URLs/locals.
            logger.exception(
                "Community storage operation failed",
                exc_info=(
                    sqlite3.Error,
                    sqlite3.Error("Storage operation failed"),
                    exc.__traceback__,
                ),
            )
            return JSONResponse(
                {
                    "detail": {
                        "code": "storage_unavailable",
                        "message": "Community storage is unavailable",
                    }
                },
                status_code=503,
            )
        raise exc

    app.add_exception_handler(sqlite3.Error, storage_error)

    async def capsule_error(request: Request, exc: Exception) -> Response:
        if not request.url.path.startswith("/api/community/capsules"):
            raise exc
        if isinstance(exc, CapsuleBlocked):
            code = exc.code
            status = {
                "release_not_found": 404, "invalid_input": 422,
                "artifact_empty": 422, "artifact_invalid": 422,
                "artifact_too_large": 413, "storage_unavailable": 503,
                "artifact_unavailable": 503,
            }.get(code, 409)
        else:
            code, status = "storage_unavailable", 503
            logger.error("capsule_storage_failure")
        return JSONResponse(
            {"detail": {"code": code, "message": code.replace("_", " ").capitalize()}},
            status_code=status,
        )

    app.add_exception_handler(CapsuleBlocked, capsule_error)
    app.add_exception_handler(OSError, capsule_error)

    def ready() -> Store:
        if store is None:
            raise fail(
                503, "auth_not_configured", "Community authentication is not configured"
            )
        return store

    def limit(request: Request, action: str, count: int):
        # Do not trust user-controlled X-Forwarded-For; configure trusted proxies externally.
        client = request.client.host if request.client else "unknown"
        ready().rate_limit(f"{action}:{digest(client)}", count)

    def csrf(request: Request):
        if request.headers.get("origin") != settings.website_url:
            raise fail(403, "untrusted_origin", "A trusted website Origin is required")

    def session_user(request: Request) -> dict | None:
        secret = request.cookies.get(SESSION_COOKIE, "")
        if not secret or len(secret) > 128:
            return None
        with ready().connect() as db:
            row = db.execute(
                "SELECT user_id FROM sessions WHERE secret_hash=? AND expires>?",
                (digest(secret), int(time.time())),
            ).fetchone()
            return Store.user(db, row["user_id"]) if row else None

    def cookie_identity(request: Request) -> dict:
        ready()
        csrf(request)
        user = session_user(request)
        if user is None:
            raise fail(401, "authentication_required", "Website login is required")
        return user

    def identity(request: Request) -> dict:
        ready()
        authorization = request.headers.get("authorization")
        if authorization:
            try:
                scheme, token = authorization.split(" ", 1)
                if scheme.lower() != "bearer" or len(token) > 4096:
                    raise ValueError("Invalid bearer")
                payload = jwt.decode(
                    token,
                    settings.jwt_secret,
                    algorithms=["HS256"],
                    audience=DESKTOP_AUDIENCE,
                    issuer=ISSUER,
                    options={"require": ["exp", "iat", "sub", "aud", "iss", "jti"]},
                )
                if payload.get("scope") != "community" or not isinstance(
                    payload["sub"], str
                ):
                    raise ValueError("Invalid scope")
                with ready().connect() as db:
                    return Store.user(db, payload["sub"])
            except (jwt.InvalidTokenError, ValueError):
                raise fail(
                    401, "invalid_token", "A valid community desktop token is required"
                )
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            csrf(request)
        user = session_user(request)
        if user is None:
            raise fail(401, "authentication_required", "Community login is required")
        return user

    def capsules_ready() -> CapsuleWorkflow:
        ready()
        if workflow is None:
            raise fail(503, "storage_unavailable", "Capsule storage is unavailable")
        return workflow

    def capsule_limit(user: dict, action: str):
        ready().rate_limit(f"capsule-{action}:{digest(user['id'])}", 30)

    @router.post("/api/community/capsules", response_model=CapsuleResponse, status_code=201)
    def reserve_capsule(
        body: CapsuleCreate, user: Annotated[dict, Depends(identity)],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", pattern=r"^[A-Za-z0-9._:-]{1,128}$")],
    ):
        capsule_limit(user, "reserve")
        return capsules_ready().reserve(
            user["id"], body.project, body.version, body.sourceUrl,
            idempotency_key,
        )

    @router.get("/api/community/capsules/mine", response_model=CapsulesResponse)
    def my_capsules(user: Annotated[dict, Depends(identity)]):
        capsule_limit(user, "read")
        return capsules_ready().mine(user["id"])

    @router.get("/api/community/capsules/{release_id}", response_model=CapsuleResponse)
    def get_capsule(release_id: str, user: Annotated[dict, Depends(identity)]):
        capsule_limit(user, "read")
        return capsules_ready().get(release_id, user["id"])

    @router.put(
        "/api/community/capsules/{release_id}/artifact", response_model=CapsuleResponse,
        openapi_extra={"requestBody": {"required": True, "content": {
            "application/java-archive": {"schema": {"type": "string", "format": "binary"}},
            "application/octet-stream": {"schema": {"type": "string", "format": "binary"}},
        }}},
    )
    async def upload_capsule(release_id: str, request: Request, user: Annotated[dict, Depends(identity)]):
        capsule_limit(user, "upload")
        capsules = capsules_ready()
        # Ownership precedes media checks and consumption of untrusted bytes.
        capsules.get(release_id, user["id"])
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() not in {
            "application/java-archive", "application/octet-stream",
        }:
            raise fail(415, "unsupported_media_type", "Send a raw JAR, not multipart data")
        length = request.headers.get("content-length")
        if length is not None:
            if not length.isascii() or not length.isdigit():
                raise fail(422, "invalid_input", "Invalid Content-Length")
            if int(length) > capsules.settings.max_bytes:
                raise CapsuleBlocked("artifact_too_large")
        try:
            return await capsules.upload(release_id, user["id"], request.stream())
        except TimeoutError:
            raise fail(408, "upload_timeout", "Upload timed out; retry the same reservation")

    @router.post("/api/community/capsules/{release_id}/retry", response_model=CapsuleResponse)
    def retry_capsule(release_id: str, user: Annotated[dict, Depends(identity)]):
        capsule_limit(user, "retry")
        return capsules_ready().retry(release_id, user["id"])

    @router.post("/api/community/capsules/{release_id}/withdraw", response_model=CapsuleResponse)
    def withdraw_capsule(release_id: str, user: Annotated[dict, Depends(identity)]):
        capsule_limit(user, "withdraw")
        return capsules_ready().withdraw(release_id, user["id"])

    def callback_redirect(
        result: str, request_id: str | None, error: str | None = None
    ):
        query = {"authResult": result}
        if request_id:
            query["requestId"] = request_id
        if error:
            query["errorCode"] = error
        response = RedirectResponse(
            settings.website_url + "/auth/login?" + urlencode(query), status_code=303
        )
        response.delete_cookie(
            STATE_COOKIE,
            path="/api/auth/github",
            secure=settings.secure_cookie,
            httponly=True,
            samesite="lax",
        )
        return response

    @router.get("/api/auth/session", response_model=SessionResponse)
    def session(request: Request):
        ready()
        return {"user": session_user(request)}

    @router.post("/api/auth/logout", status_code=204)
    def logout(request: Request):
        ready()
        csrf(request)
        with ready().connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE secret_hash=?",
                (digest(request.cookies.get(SESSION_COOKIE, "")),),
            )
        response = Response(status_code=204)
        response.delete_cookie(
            SESSION_COOKIE,
            path="/api",
            secure=settings.secure_cookie,
            httponly=True,
            samesite="lax",
        )
        return response

    @router.get(
        "/api/auth/github/start", status_code=302, response_class=RedirectResponse
    )
    def github_start(
        request: Request,
        requestId: str | None = Query(default=None, pattern=r"^[a-f0-9]{32}$"),
        switchAccount: Literal["1"] | None = None,
    ):
        limit(request, "oauth-start", 10)
        if request.headers.get("origin"):
            csrf(request)
        if request.headers.get("sec-fetch-site") == "cross-site":
            raise fail(
                403, "untrusted_origin", "Start login from the configured website"
            )
        if not settings.github_client_id or not settings.github_client_secret:
            raise fail(
                503,
                "github_not_configured",
                "GitHub OAuth credentials are not configured",
            )
        now = int(time.time())
        with ready().connect() as db:
            if (
                requestId
                and not db.execute(
                    "SELECT 1 FROM devices WHERE request_id=? AND status='pending' AND expires>?",
                    (requestId, now),
                ).fetchone()
            ):
                raise fail(
                    409, "invalid_request", "Desktop request is unavailable or expired"
                )
            state, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO oauth_states VALUES (?, ?, ?, ?)",
                (digest(state), digest(binding), requestId, now + STATE_TTL),
            )
            if switchAccount:
                db.execute(
                    "DELETE FROM sessions WHERE secret_hash=?",
                    (digest(request.cookies.get(SESSION_COOKIE, "")),),
                )
        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.callback_url,
            "state": state,
            "scope": "read:user",
            # Explicit provider consent is a hint, NOT a guarantee of account switching/logout.
            "prompt": "select_account" if switchAccount else "consent",
        }
        response = RedirectResponse(
            "https://github.com/login/oauth/authorize?" + urlencode(params),
            status_code=302,
        )
        response.set_cookie(
            STATE_COOKIE,
            binding,
            max_age=STATE_TTL,
            httponly=True,
            secure=settings.secure_cookie,
            samesite="lax",
            path="/api/auth/github",
        )
        if switchAccount:
            response.delete_cookie(
                SESSION_COOKIE,
                path="/api",
                secure=settings.secure_cookie,
                httponly=True,
                samesite="lax",
            )
        return response

    @router.get(
        "/api/auth/github/callback", status_code=303, response_class=RedirectResponse
    )
    async def github_callback(
        request: Request,
        state: str = Query(default="", max_length=128),
        code: str = Query(default="", max_length=1024),
        error: str = Query(default="", max_length=128),
    ):
        limit(request, "oauth-callback", 30)
        now = int(time.time())
        with ready().connect() as db:
            row = db.execute(
                "SELECT * FROM oauth_states WHERE secret_hash=?", (digest(state),)
            ).fetchone()
            binding = request.cookies.get(STATE_COOKIE, "")
            if (
                not row
                or row["expires"] <= now
                or not secrets.compare_digest(row["binding_hash"], digest(binding))
            ):
                return callback_redirect(
                    "error", row["request_id"] if row else None, "invalid_state"
                )
            db.execute("DELETE FROM oauth_states WHERE secret_hash=?", (digest(state),))
            request_id = row["request_id"]
        if error or not code:
            return callback_redirect("error", request_id, "oauth_denied")
        try:
            user = await github_identity(settings, code)
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            # Provider exceptions may contain URLs, credentials or response bodies.
            logger.warning("GitHub OAuth exchange or identity verification failed")
            return callback_redirect("error", request_id, "oauth_failed")
        secret = secrets.token_urlsafe(32)
        with ready().connect() as db:
            db.execute(
                "INSERT INTO users(id, username, avatar_url) VALUES (?, ?, ?) ON CONFLICT(id) "
                "DO UPDATE SET username=excluded.username, avatar_url=excluded.avatar_url",
                (user["id"], user["username"], user["avatarUrl"]),
            )
            db.execute(
                "DELETE FROM sessions WHERE secret_hash=?",
                (digest(request.cookies.get(SESSION_COOKIE, "")),),
            )
            db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?)",
                (digest(secret), user["id"], now + SESSION_TTL),
            )
        response = callback_redirect("success", request_id)
        response.set_cookie(
            SESSION_COOKIE,
            secret,
            max_age=SESSION_TTL,
            secure=settings.secure_cookie,
            httponly=True,
            samesite="lax",
            path="/api",
        )
        return response

    @router.post("/api/auth/desktop", response_model=DeviceResponse)
    def desktop(body: Empty, request: Request):
        limit(request, "desktop-start", 10)
        device, request_id = secrets.token_urlsafe(32), secrets.token_hex(16)
        with ready().connect() as db:
            db.execute(
                "INSERT INTO devices(secret_hash, request_id, expires, status) VALUES (?, ?, ?, 'pending')",
                (digest(device), request_id, int(time.time()) + DEVICE_TTL),
            )
        return {
            "deviceCode": device,
            "requestId": request_id,
            "verificationUri": settings.website_url
            + "/auth/login?"
            + urlencode({"requestId": request_id}),
            "expiresIn": DEVICE_TTL,
            "pollInterval": POLL_INTERVAL,
        }

    @router.post(
        "/api/auth/desktop/poll",
        response_model=PollResponse,
        response_model_exclude_none=True,
    )
    def poll(body: Poll, request: Request):
        limit(request, "desktop-poll", 120)
        now = int(time.time())
        with ready().connect() as db:
            row = db.execute(
                "SELECT * FROM devices WHERE secret_hash=?", (digest(body.deviceCode),)
            ).fetchone()
            if not row or row["expires"] <= now:
                return {"status": "expired"}
            if row["status"] == "consumed":
                return {"status": "denied"}
            if row["last_poll"] and now - row["last_poll"] < POLL_INTERVAL:
                raise HTTPException(
                    429,
                    detail={"code": "slow_down", "message": "Respect pollInterval"},
                    headers={"Retry-After": str(POLL_INTERVAL)},
                )
            db.execute(
                "UPDATE devices SET last_poll=? WHERE secret_hash=?",
                (now, digest(body.deviceCode)),
            )
            if row["status"] != "approved":
                return {"status": row["status"]}
            user = Store.user(db, row["user_id"])
            token = jwt.encode(
                {
                    "sub": user["id"],
                    "iss": ISSUER,
                    "aud": DESKTOP_AUDIENCE,
                    "scope": "community",
                    "iat": now,
                    "exp": now + TOKEN_TTL,
                    "jti": secrets.token_hex(16),
                },
                settings.jwt_secret,
                algorithm="HS256",
            )
            db.execute(
                "UPDATE devices SET status='consumed' WHERE secret_hash=?",
                (digest(body.deviceCode),),
            )
            return {"status": "approved", "accessToken": token, "user": user}

    @router.post("/api/auth/desktop/approve", response_model=ApprovalResponse)
    def approve(
        body: Approve, request: Request, user: Annotated[dict, Depends(cookie_identity)]
    ):
        limit(request, "desktop-approve", 30)
        with ready().connect() as db:
            row = db.execute(
                "SELECT * FROM devices WHERE request_id=?", (body.requestId,)
            ).fetchone()
            if (
                not row
                or row["expires"] <= int(time.time())
                or row["status"] != "pending"
            ):
                raise fail(
                    409,
                    "invalid_request",
                    "Desktop request is unavailable, used or expired",
                )
            db.execute(
                "UPDATE devices SET status='approved', user_id=? WHERE request_id=?",
                (user["id"], body.requestId),
            )
        return {"status": "approved"}

    @router.get("/api/community/profiles", response_model=ProfilesResponse)
    def public_profiles(q: str = Query(default="", max_length=120)):
        with ready().connect() as db:
            # Python casefold provides Unicode-insensitive matching without SQL wildcard semantics.
            rows = db.execute(
                "SELECT * FROM profiles WHERE visibility='public' ORDER BY updated_at DESC"
            )
            needle = q.casefold()
            matches = []
            for row in rows:
                if (
                    needle in row["name"].casefold()
                    or needle in row["description"].casefold()
                ):
                    matches.append(Store.profile(db, row))
                if len(matches) == 100:
                    break
            return {"profiles": matches}

    @router.get("/api/community/profiles/mine", response_model=ProfilesResponse)
    def my_profiles(user: Annotated[dict, Depends(identity)]):
        with ready().connect() as db:
            rows = db.execute(
                "SELECT * FROM profiles WHERE owner_id=? ORDER BY updated_at DESC LIMIT 100",
                (user["id"],),
            ).fetchall()
            return {"profiles": [Store.profile(db, row) for row in rows]}

    def public_source(db, source_id):
        if (
            source_id
            and not db.execute(
                "SELECT 1 FROM profiles WHERE id=? AND visibility='public'",
                (source_id,),
            ).fetchone()
        ):
            raise fail(404, "source_not_found", "Source public profile is unavailable")

    def owned(db, profile_id, user):
        row = db.execute(
            "SELECT * FROM profiles WHERE id=? AND owner_id=?", (profile_id, user["id"])
        ).fetchone()
        if not row:
            raise fail(404, "profile_not_found", "Profile is unavailable")
        return row

    def timestamp():
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()

    @router.post("/api/community/profiles", response_model=Profile, status_code=201)
    def create_profile(
        body: ProfileCreate, user: Annotated[dict, Depends(cookie_identity)]
    ):
        with ready().connect() as db:
            public_source(db, body.sourceProfileId)
            count = db.execute(
                "SELECT count(*) FROM profiles WHERE owner_id=?", (user["id"],)
            ).fetchone()[0]
            if count >= 100:
                raise fail(409, "profile_limit", "Maximum 100 profiles per owner")
            profile_id = secrets.token_hex(16)
            db.execute(
                "INSERT INTO profiles VALUES (?, ?, ?, ?, ?, 'private', ?, ?)",
                (
                    profile_id,
                    user["id"],
                    body.name,
                    body.description,
                    json.dumps([mod.model_dump() for mod in body.mods]),
                    body.sourceProfileId,
                    timestamp(),
                ),
            )
            return Store.profile(db, owned(db, profile_id, user))

    @router.patch("/api/community/profiles/{profile_id}", response_model=Profile)
    def patch_profile(
        profile_id: str,
        body: ProfilePatch,
        user: Annotated[dict, Depends(cookie_identity)],
    ):
        with ready().connect() as db:
            row = owned(db, profile_id, user)
            values = dict(row)
            changes = body.model_dump(exclude_unset=True)
            if "sourceProfileId" in changes:
                public_source(db, body.sourceProfileId)
                values["source_profile_id"] = body.sourceProfileId
            for key in ("name", "description"):
                if key in changes:
                    values[key] = changes[key]
            if "mods" in changes:
                values["mods"] = json.dumps(changes["mods"])
            # Any edit withdraws previously public content until it is revalidated.
            db.execute(
                "UPDATE profiles SET name=?, description=?, mods=?, source_profile_id=?, "
                "visibility='private', updated_at=? WHERE id=?",
                (
                    values["name"],
                    values["description"],
                    values["mods"],
                    values["source_profile_id"],
                    timestamp(),
                    profile_id,
                ),
            )
            return Store.profile(db, owned(db, profile_id, user))

    @router.delete("/api/community/profiles/{profile_id}", status_code=204)
    def delete_profile(
        profile_id: str, user: Annotated[dict, Depends(cookie_identity)]
    ):
        with ready().connect() as db:
            owned(db, profile_id, user)
            db.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
        return Response(status_code=204)

    @router.post("/api/community/profiles/{profile_id}/submit", response_model=Profile)
    def submit_profile(
        profile_id: str, user: Annotated[dict, Depends(cookie_identity)]
    ):
        with ready().connect() as db:
            owned(db, profile_id, user)
        # There is deliberately no scan registry in batch 1. Empty lists also fail closed.
        raise fail(
            409,
            "scanning_not_configured",
            "Publishing requires backend-validated mods; scanning is not configured",
        )

    app.include_router(router)
