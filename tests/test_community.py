import importlib
import json
import secrets
import sqlite3
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server import community as api
from server.version import BACKEND_VERSION

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".test-work"
ORIGIN = "https://website.example.com"
BACKEND = "https://api.example.com"
ALICE = {"id": "github:123", "username": "alice", "avatarUrl": "https://avatars.githubusercontent.com/u/123", "roles": []}
BOB = {"id": "github:456", "username": "bob", "avatarUrl": "https://avatars.githubusercontent.com/u/456", "roles": []}
MOD = {"name": "Example", "version": "1.0.0", "sourceUrl": "https://modrinth.com/mod/example", "sha256": "a" * 64}


@pytest.fixture
def environment(monkeypatch):
    WORK.mkdir(exist_ok=True)
    folder = WORK / secrets.token_hex(8)
    folder.mkdir()
    settings = api.Settings(
        website_url=ORIGIN, backend_url=BACKEND, jwt_secret="test-community-secret-" + "a" * 40,
        database=str(folder / "community.sqlite3"),
        github_client_id="test-id", github_client_secret="test-provider-secret",
    )
    # Keep the advanced device-poll clock behind JWT's real iat verification clock.
    clock = [int(time.time()) - 10]
    monkeypatch.setattr(api, "time", SimpleNamespace(time=lambda: clock[0]))
    app = FastAPI()
    api.install_community(app, settings)
    with TestClient(app, base_url=BACKEND) as client:
        yield SimpleNamespace(
            app=app, client=client, store=app.state.community_store,
            settings=settings, clock=clock, folder=folder,
        )
    shutil.rmtree(folder)
    if not any(WORK.iterdir()):
        WORK.rmdir()


def login(env, user=ALICE):
    secret = secrets.token_urlsafe(32)
    with env.store.connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?)",
            (user["id"], user["username"], user["avatarUrl"], json.dumps(user["roles"])),
        )
        db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (api.digest(secret), user["id"], env.clock[0] + 3600))
    env.client.cookies.set(api.SESSION_COOKIE, secret, domain="api.example.com", path="/api")
    return secret


def create(env, **fields):
    return env.client.post(
        "/api/community/profiles", headers={"Origin": ORIGIN},
        json={"name": "Test", "description": "A profile", "mods": [MOD], **fields},
    )


def device(env):
    result = env.client.post("/api/auth/desktop", json={})
    assert result.status_code == 200
    return result.json()


def oauth_start(env, request_id=None, switch=False):
    params = {}
    if request_id:
        params["requestId"] = request_id
    if switch:
        params["switchAccount"] = "1"
    response = env.client.get("/api/auth/github/start", params=params, follow_redirects=False)
    assert response.status_code == 302
    return parse_qs(urlsplit(response.headers["location"]).query)["state"][0]


def mock_provider(monkeypatch, *, denied=False, invalid=False, network_error=False, malformed=False):
    calls = []
    original = httpx.AsyncClient

    def handle(request):
        calls.append(request)
        if network_error:
            raise httpx.ConnectError("provider failure with sensitive detail", request=request)
        if request.url.host == "github.com":
            assert request.method == "POST"
            assert b"client_secret=test-provider-secret" in request.content
            if malformed:
                return httpx.Response(200, json=[])
            return httpx.Response(200, json={"error": "secret-raw-provider-error"} if denied else {"access_token": "secret-provider-token"})
        assert request.url == "https://api.github.com/user"
        assert request.headers["authorization"] == "Bearer secret-provider-token"
        return httpx.Response(200, json={"id": 123, "login": "alice", "avatar_url": "http://bad"} if invalid else {
            "id": 123, "login": "alice", "avatar_url": ALICE["avatarUrl"],
        })

    monkeypatch.setattr(api.httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs))
    return calls


def test_session_cookie_persists_and_logout(environment):
    env = environment
    assert env.client.get("/api/auth/session").json() == {"user": None}
    secret = login(env)
    for _ in range(2):
        response = env.client.get("/api/auth/session")
        assert response.json() == {"user": ALICE}
        assert response.headers["cache-control"] == "no-store"
    assert env.client.post("/api/auth/logout", headers={"Origin": ORIGIN}).status_code == 204
    assert env.client.get("/api/auth/session").json() == {"user": None}
    with env.store.connect() as db:
        assert db.execute("SELECT 1 FROM sessions WHERE secret_hash=?", (api.digest(secret),)).fetchone() is None


def test_session_expires(environment):
    login(environment)
    environment.clock[0] += 3601
    assert environment.client.get("/api/auth/session").json() == {"user": None}
    assert environment.client.get("/api/community/profiles/mine").status_code == 401


def test_oauth_identity_cookie_state_replay_and_public_callback(environment, monkeypatch):
    env = environment
    request_id = device(env)["requestId"]
    calls = mock_provider(monkeypatch)
    state = oauth_start(env, request_id)
    with env.store.connect() as db:
        row = db.execute("SELECT * FROM oauth_states").fetchone()
        assert row["secret_hash"] != state
    response = env.client.get("/api/auth/github/callback", params={"state": state, "code": "test-code"}, follow_redirects=False)
    assert response.status_code == 303
    assert parse_qs(urlsplit(response.headers["location"]).query) == {"authResult": ["success"], "requestId": [request_id]}
    cookie = response.headers.get_list("set-cookie")[-1]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    assert env.client.get("/api/auth/session").json() == {"user": ALICE}
    assert len(calls) == 2
    replay = env.client.get("/api/auth/github/callback", params={"state": state, "code": "test-code"}, follow_redirects=False)
    assert "errorCode=invalid_state" in replay.headers["location"]
    assert len(calls) == 2
    assert env.client.post("/api/auth/desktop/poll", json={"deviceCode": "x" * 43}).json() == {"status": "expired"}
    with env.store.connect() as db:
        assert db.execute("SELECT status FROM devices WHERE request_id=?", (request_id,)).fetchone()[0] == "pending"


def test_expired_oauth_state_preserves_request_id(environment, monkeypatch):
    env = environment
    calls = mock_provider(monkeypatch)
    request_id = device(env)["requestId"]
    state = oauth_start(env, request_id)
    env.clock[0] += api.STATE_TTL + 1
    response = env.client.get("/api/auth/github/callback", params={"state": state, "code": "code"}, follow_redirects=False)
    assert parse_qs(urlsplit(response.headers["location"]).query) == {
        "authResult": ["error"], "errorCode": ["invalid_state"], "requestId": [request_id],
    }
    assert not calls


def test_oauth_requires_browser_binding(environment, monkeypatch):
    env = environment
    calls = mock_provider(monkeypatch)
    state = oauth_start(env)
    env.client.cookies.clear()
    response = env.client.get("/api/auth/github/callback", params={"state": state, "code": "code"}, follow_redirects=False)
    assert "errorCode=invalid_state" in response.headers["location"]
    assert not calls


@pytest.mark.parametrize("failure", ["denied", "invalid", "network_error", "malformed"])
def test_provider_failure_is_safe_and_state_consumed(environment, monkeypatch, failure, caplog):
    env = environment
    calls = mock_provider(monkeypatch, **{failure: True})
    state = oauth_start(env)
    response = env.client.get("/api/auth/github/callback", params={"state": state, "code": "code"}, follow_redirects=False)
    assert "errorCode=oauth_failed" in response.headers["location"]
    assert "secret" not in response.headers["location"]
    count = len(calls)
    env.client.get("/api/auth/github/callback", params={"state": state, "code": "code"}, follow_redirects=False)
    assert len(calls) == count
    assert env.client.get("/api/auth/session").json() == {"user": None}
    records = [record for record in caplog.records if record.name == "mars-community-api"]
    assert len(records) == 1
    assert records[0].getMessage() == "GitHub OAuth exchange or identity verification failed"
    assert records[0].exc_info is None
    assert "secret" not in records[0].getMessage()


def test_oauth_denial_and_switch_do_not_approve(environment, monkeypatch):
    env = environment
    login(env)
    item = device(env)
    calls = mock_provider(monkeypatch)
    state = oauth_start(env, item["requestId"], switch=True)
    assert env.client.get("/api/auth/session").json() == {"user": None}
    response = env.client.get("/api/auth/github/callback", params={"state": state, "error": "arbitrary-sensitive-error"}, follow_redirects=False)
    assert "errorCode=oauth_denied" in response.headers["location"]
    assert "arbitrary" not in response.headers["location"]
    assert not calls
    assert env.client.post("/api/auth/desktop/poll", json={"deviceCode": item["deviceCode"]}).json() == {"status": "pending"}
    assert env.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN}, json={"requestId": item["requestId"]}).status_code == 401


def test_desktop_approval_expiry_replay_jwt_and_secret_binding(environment):
    env = environment
    item = device(env)
    assert set(item) == {"deviceCode", "requestId", "verificationUri", "expiresIn", "pollInterval"}
    assert item["deviceCode"] not in item["verificationUri"]
    assert item["verificationUri"] == ORIGIN + "/auth/login?requestId=" + item["requestId"]
    with env.store.connect() as db:
        assert db.execute("SELECT secret_hash FROM devices").fetchone()[0] == api.digest(item["deviceCode"])
    assert env.client.post("/api/auth/desktop/poll", json={"deviceCode": item["deviceCode"]}).json() == {"status": "pending"}
    assert env.client.post("/api/auth/desktop/poll", json={"deviceCode": item["deviceCode"]}).status_code == 429
    login(env)
    approved = env.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN}, json={"requestId": item["requestId"]})
    assert approved.json() == {"status": "approved"}
    assert env.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN}, json={"requestId": item["requestId"]}).status_code == 409
    env.clock[0] += api.POLL_INTERVAL
    result = env.client.post("/api/auth/desktop/poll", json={"deviceCode": item["deviceCode"]}).json()
    assert result["status"] == "approved" and result["user"] == ALICE
    claims = jwt.decode(result["accessToken"], env.settings.jwt_secret, algorithms=["HS256"], audience=api.DESKTOP_AUDIENCE, issuer=api.ISSUER)
    assert claims["sub"] == ALICE["id"] and claims["exp"] - claims["iat"] == api.TOKEN_TTL
    assert env.client.post("/api/auth/desktop/poll", json={"deviceCode": item["deviceCode"]}).json() == {"status": "denied"}
    env.client.cookies.clear()
    assert env.client.get("/api/community/profiles/mine", headers={"Authorization": "Bearer " + result["accessToken"]}).json() == {"profiles": []}
    expired = device(env)
    env.clock[0] += api.DEVICE_TTL + 1
    login(env)
    assert env.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN}, json={"requestId": expired["requestId"]}).status_code == 409
    assert env.client.post("/api/auth/desktop/poll", json={"deviceCode": expired["deviceCode"]}).json() == {"status": "expired"}


def test_invalid_request_and_bearer_cannot_approve(environment):
    env = environment
    login(env)
    assert env.client.get("/api/auth/github/start", params={"requestId": "a" * 32}).status_code == 409
    assert env.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN}, json={"requestId": "a" * 32}).status_code == 409
    env.client.cookies.clear()
    token = desktop_token(env)
    assert env.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN, "Authorization": "Bearer " + token}, json={"requestId": device(env)["requestId"]}).status_code == 401


def test_concurrent_poll_issues_one_token(environment):
    env = environment
    item = device(env)
    login(env)
    assert env.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN}, json={"requestId": item["requestId"]}).status_code == 200

    def request_token(_):
        with TestClient(env.app, base_url=BACKEND) as client:
            return client.post("/api/auth/desktop/poll", json={"deviceCode": item["deviceCode"]}).json()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(request_token, range(2)))
    assert sorted(result["status"] for result in results) == ["approved", "denied"]
    assert sum("accessToken" in result for result in results) == 1


def desktop_token(env, **claims):
    with env.store.connect() as db:
        db.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, '[]')", (ALICE["id"], ALICE["username"], ALICE["avatarUrl"]))
    return jwt.encode({
        "sub": ALICE["id"], "iss": api.ISSUER, "aud": api.DESKTOP_AUDIENCE, "scope": "community",
        "iat": int(time.time()), "exp": int(time.time()) + 900, "jti": "test-id", **claims,
    }, env.settings.jwt_secret, algorithm="HS256")


@pytest.mark.parametrize("claims", [
    {"aud": "mars-client", "iss": "mars-package-api", "scope": "mods:read"},
    {"exp": 1}, {"scope": "mods:read"}, {"sub": "missing-user"}, {"aud": "website"},
])
def test_package_and_invalid_tokens_cannot_access_community(environment, claims):
    env = environment
    token = desktop_token(env, **claims)
    assert env.client.get("/api/community/profiles/mine", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_profile_private_ownership_partial_patch_delete(environment):
    env = environment
    login(env)
    response = create(env)
    assert response.status_code == 201
    profile = response.json()
    assert set(profile) == {"id", "name", "description", "visibility", "owner", "mods", "sourceProfileId", "updatedAt"}
    assert profile["visibility"] == "private" and profile["owner"] == ALICE
    assert env.client.get("/api/community/profiles?q=Test").json() == {"profiles": []}
    assert env.client.get("/api/community/profiles/mine").json() == {"profiles": [profile]}
    patched = env.client.patch("/api/community/profiles/" + profile["id"], headers={"Origin": ORIGIN}, json={"description": "Changed"})
    assert patched.json()["name"] == "Test" and patched.json()["description"] == "Changed"
    for field in ["name", "description", "mods"]:
        assert env.client.patch("/api/community/profiles/" + profile["id"], headers={"Origin": ORIGIN}, json={field: None}).status_code == 422
    login(env, BOB)
    assert env.client.get("/api/community/profiles/mine").json() == {"profiles": []}
    for method, suffix, body in [("patch", "", {"name": "stolen"}), ("delete", "", None), ("post", "/submit", None)]:
        result = env.client.request(method, "/api/community/profiles/" + profile["id"] + suffix, headers={"Origin": ORIGIN}, json=body)
        assert result.status_code == 404
    login(env)
    assert env.client.delete("/api/community/profiles/" + profile["id"], headers={"Origin": ORIGIN}).status_code == 204
    assert env.client.get("/api/community/profiles/mine").json() == {"profiles": []}


@pytest.mark.parametrize("mods", [[], [MOD]])
def test_submission_always_fails_closed(environment, mods):
    env = environment
    login(env)
    profile = create(env, mods=mods).json()
    result = env.client.post("/api/community/profiles/" + profile["id"] + "/submit", headers={"Origin": ORIGIN})
    assert result.status_code == 409
    assert result.json()["detail"]["code"] == "scanning_not_configured"
    assert env.client.get("/api/community/profiles").json() == {"profiles": []}
    assert env.client.get("/api/community/profiles/mine").json()["profiles"][0]["visibility"] == "private"


def test_public_search_copy_and_edits_withdraw_public(environment):
    env = environment
    login(env)
    source = create(env, name="Straße Pack", description="Amazing MODS").json()
    private = create(env, name="Straße private").json()
    assert create(env, sourceProfileId=private["id"]).status_code == 404
    with env.store.connect() as db:
        # Only test fixture creates public data: production cannot bypass the scan gate.
        db.execute("UPDATE profiles SET visibility='public' WHERE id=?", (source["id"],))
    assert len(env.client.get("/api/community/profiles?q=STRASSE").json()["profiles"]) == 1
    assert len(env.client.get("/api/community/profiles?q=amazing mods").json()["profiles"]) == 1
    assert env.client.get("/api/community/profiles?q=%").json() == {"profiles": []}
    login(env, BOB)
    copy = create(env, sourceProfileId=source["id"]).json()
    assert copy["owner"] == BOB and copy["visibility"] == "private"
    assert copy["sourceProfileId"] == source["id"] and copy["id"] != source["id"]
    env.client.patch("/api/community/profiles/" + copy["id"], headers={"Origin": ORIGIN}, json={"mods": []})
    assert env.client.get("/api/community/profiles").json()["profiles"][0]["mods"] == [MOD]
    login(env)
    patched = env.client.patch("/api/community/profiles/" + source["id"], headers={"Origin": ORIGIN}, json={"name": "Changed"})
    assert patched.json()["visibility"] == "private"
    assert env.client.get("/api/community/profiles").json() == {"profiles": []}


@pytest.mark.parametrize("untrusted", [None, "https://evil.example.com", "null", ORIGIN + ".evil", ORIGIN + "/"])
def test_csrf_cookie_mutations_require_exact_origin(environment, untrusted):
    env = environment
    login(env)
    profile = create(env).json()
    item = device(env)
    headers = {"Origin": untrusted} if untrusted else {}
    for method, path, body in [
        ("post", "/api/auth/logout", None),
        ("post", "/api/auth/desktop/approve", {"requestId": item["requestId"]}),
        ("post", "/api/community/profiles", {"name": "Test", "description": "", "mods": []}),
        ("patch", "/api/community/profiles/" + profile["id"], {"name": "Changed"}),
        ("delete", "/api/community/profiles/" + profile["id"], None),
        ("post", "/api/community/profiles/" + profile["id"] + "/submit", None),
    ]:
        assert env.client.request(method, path, headers=headers, json=body).status_code == 403


def test_cors_exact_origin_and_credentials(environment):
    env = environment
    headers = {"Origin": ORIGIN, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}
    response = env.client.options("/api/auth/desktop/approve", headers=headers)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    response = env.client.options("/api/auth/desktop/approve", headers={**headers, "Origin": "https://evil.example.com"})
    assert response.status_code == 400 and "access-control-allow-origin" not in response.headers
    response = env.client.get("/api/auth/github/start", headers={"Origin": "https://evil.example.com"}, follow_redirects=False)
    assert response.status_code == 403
    assert env.client.get("/api/auth/github/start", headers={"Sec-Fetch-Site": "cross-site"}, follow_redirects=False).status_code == 403


@pytest.mark.parametrize("url", [
    "http://example.com/mod", "javascript:alert(1)", "https://user:password@example.com/mod",
    "https://127.0.0.1/mod", "https://10.0.0.1/mod", "https://localhost/mod",
    "https://example.com:444/mod", "https://example.com/mod#fragment", "https://example.com\\evil/mod",
])
def test_unsafe_urls_rejected_without_fetch(environment, url):
    login(environment)
    result = create(environment, mods=[{**MOD, "sourceUrl": url}])
    assert result.status_code == 422
    assert result.json()["detail"]["code"] == "invalid_input"


def test_input_limits_and_no_client_scan_proof(environment):
    env = environment
    login(env)
    for fields in [
        {"name": ""}, {"name": "a" * 121}, {"description": "a" * 4001},
        {"mods": [MOD] * 201}, {"mods": [{**MOD, "sha256": "bad"}]},
        {"mods": [{**MOD, "scanned": True}]}, {"visibility": "public"},
    ]:
        assert create(env, **fields).status_code == 422
    result = env.client.post("/api/community/profiles", headers={"Origin": ORIGIN, "Content-Type": "application/json"}, content=b"x" * (api.MAX_BODY + 1))
    assert result.status_code == 413
    assert env.client.post("/api/auth/desktop", json={"deviceCode": "injected"}).status_code == 422


def test_profile_limit(environment):
    env = environment
    login(env)
    with env.store.connect() as db:
        for i in range(100):
            db.execute("INSERT INTO profiles VALUES (?, ?, 'test', '', '[]', 'private', NULL, '2026')", (str(i), ALICE["id"]))
    assert create(env).status_code == 409
    assert len(env.client.get("/api/community/profiles/mine").json()["profiles"]) == 100


def test_durable_session_profile_device_oauth_and_rate_limit(environment):
    env = environment
    secret = login(env)
    profile = create(env).json()
    item = device(env)
    state = oauth_start(env)
    another = FastAPI()
    api.install_community(another, env.settings)
    with TestClient(another, base_url=BACKEND) as client:
        client.cookies.set(api.SESSION_COOKIE, secret, domain="api.example.com", path="/api")
        assert client.get("/api/auth/session").json() == {"user": ALICE}
        assert client.get("/api/community/profiles/mine").json() == {"profiles": [profile]}
        assert client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN}, json={"requestId": item["requestId"]}).status_code == 200
        for _ in range(9):
            assert client.post("/api/auth/desktop", json={}).status_code == 200
        assert env.client.post("/api/auth/desktop", json={}).status_code == 429
        with another.state.community_store.connect() as db:
            assert db.execute("SELECT 1 FROM oauth_states WHERE secret_hash=?", (api.digest(state),)).fetchone()


def test_disabled_config_and_missing_github_credentials(environment):
    app = FastAPI()
    api.install_community(app, api.Settings())
    with TestClient(app) as client:
        assert client.get("/api/auth/session").status_code == 503
        assert client.post("/api/auth/desktop", json={}).status_code == 503
        assert client.get("/api/community/profiles").status_code == 503
    settings = api.Settings(website_url=ORIGIN, backend_url=BACKEND, jwt_secret="x" * 40, database=str(environment.folder / "missing-github.sqlite3"))
    app = FastAPI()
    api.install_community(app, settings)
    with TestClient(app) as client:
        assert client.get("/api/auth/github/start").json()["detail"]["code"] == "github_not_configured"


def test_storage_failure_is_sanitized_and_fails_closed(environment, caplog):
    with environment.store.connect() as db:
        db.execute("DROP TABLE profiles")
    result = environment.client.get("/api/community/profiles")
    assert result.status_code == 503
    assert result.json() == {"detail": {"code": "storage_unavailable", "message": "Community storage is unavailable"}}
    records = [record for record in caplog.records if record.name == "mars-community-api"]
    assert len(records) == 1
    assert records[0].getMessage() == "Community storage operation failed"
    assert records[0].exc_info is not None
    assert str(records[0].exc_info[1]) == "Storage operation failed"
    assert "no such table" not in caplog.text


def test_storage_logging_never_records_exception_message_or_query(environment, caplog):
    sensitive = "sensitive-" + secrets.token_urlsafe(32)
    app = FastAPI()
    api.install_community(app, environment.settings)

    @app.get("/api/community/logging-check")
    def broken_storage():
        raise sqlite3.OperationalError(sensitive)

    with TestClient(app, base_url=BACKEND) as client:
        response = client.get("/api/community/logging-check", params={"token": sensitive})
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "storage_unavailable"
    assert "Community storage operation failed" in caplog.text
    assert sensitive not in caplog.text and sensitive not in response.text


def test_deliberate_localhost_and_config_validation(environment, monkeypatch):
    fields = {"website_url": "http://localhost:5173", "backend_url": "http://localhost:8000", "jwt_secret": "x" * 40, "database": environment.settings.database}
    with pytest.raises(ValueError):
        api.Settings(**fields)
    settings = api.Settings(**fields, allow_local_http=True)
    assert settings.secure_cookie is False
    with pytest.raises(ValueError):
        api.Settings(**{**fields, "backend_url": "http://127.0.0.1:8000"}, allow_local_http=True)
    for website in ["https://user:pass@example.com", "https://example.com/api", "https://example.com?bad=1"]:
        with pytest.raises(ValueError):
            api.Settings(**{**fields, "website_url": website})
    monkeypatch.setenv("MARS_AUTH_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("MARS_API_JWT_SECRET", "x" * 40)
    with pytest.raises(ValueError):
        api.Settings.from_env()


def test_existing_pack_auth_and_routes_are_preserved(environment, monkeypatch):
    env = environment
    release = env.folder / "release"
    (release / "mods").mkdir(parents=True)
    (release / "mods" / "test-1.0.0.jar").write_bytes(b"test-jar-fixture")
    (release / "manifest.json").write_text('{"signed":true}', encoding="utf-8")
    (release / "manifest.json.sig").write_text("test-signature", encoding="utf-8")
    monkeypatch.setenv("MARS_RELEASE_DIR", str(release))
    monkeypatch.setenv("MARS_API_JWT_SECRET", "pack-test-secret-" + "p" * 40)
    monkeypatch.setenv("MARS_PUBLIC_BASE_URL", BACKEND)
    monkeypatch.delenv("MARS_AUTH_JWT_SECRET", raising=False)
    monkeypatch.setenv("DEV_TOKEN", "false")
    from server import main
    main = importlib.reload(main)
    assert BACKEND_VERSION == "0.3.0"
    assert main.app.version == BACKEND_VERSION
    checked_in_openapi = json.loads(
        (ROOT / "output" / "openapi.json").read_text(encoding="utf-8")
    )
    assert checked_in_openapi == main.app.openapi()
    assert checked_in_openapi["info"]["version"] == BACKEND_VERSION
    for path, media_type in {
        "/api/v1/manifest.json": "application/json",
        "/api/v1/manifest.json.sig": "text/plain",
        "/api/v1/files/{relative_path}": "application/octet-stream",
        "/api/v1/mods/{mod_id}/download": "application/java-archive",
    }.items():
        assert media_type in checked_in_openapi["paths"][path]["get"]["responses"]["200"][
            "content"
        ]
    monkeypatch.syspath_prepend(str(ROOT / "server"))
    legacy_module = importlib.import_module("main")
    assert legacy_module.app.title == "Mars Package API"
    pack_token = jwt.encode({
        "sub": "pack-user", "iss": main.JWT_ISSUER, "aud": main.JWT_AUDIENCE,
        "scope": "mods:read", "exp": int(time.time()) + 900,
    }, main.JWT_SECRET, algorithm="HS256")
    with TestClient(main.app, base_url=BACKEND) as client:
        assert client.get("/api/v1/health").status_code == 200
        assert client.get("/api/v1/mods").status_code == 401
        headers = {"Authorization": "Bearer " + pack_token}
        mods = client.get("/api/v1/mods", headers=headers)
        assert mods.status_code == 200
        assert client.get(mods.json()["mods"][0]["downloadUrl"], headers=headers).content == b"test-jar-fixture"
        assert client.get("/api/v1/manifest/preview", headers=headers).status_code == 200
        assert client.get("/api/v1/manifest.json").status_code == 200
        assert client.get("/api/v1/manifest.json.sig").status_code == 200
        assert client.get("/api/v1/files/mods/test-1.0.0.jar").content == b"test-jar-fixture"
        assert client.get("/api/v1/mods", headers={"Authorization": "Bearer " + desktop_token(env)}).status_code == 401
    assert env.client.get("/api/community/profiles/mine", headers=headers).status_code == 401
    secret = login(env)
    monkeypatch.setenv("MARS_AUTH_JWT_SECRET", env.settings.jwt_secret)
    monkeypatch.setenv("WEBSITE_URL", ORIGIN)
    monkeypatch.setenv("MARS_AUTH_PUBLIC_URL", BACKEND)
    monkeypatch.setenv("MARS_COMMUNITY_DB", env.settings.database)
    main = importlib.reload(main)
    with TestClient(main.app, base_url=BACKEND) as client:
        client.cookies.set(api.SESSION_COOKIE, secret, domain="api.example.com", path="/api")
        assert client.get("/api/auth/session").json() == {"user": ALICE}
        assert client.get("/api/community/profiles/mine").status_code == 200
        assert client.get("/api/community/profiles/mine", headers=headers).status_code == 401
        assert client.get("/api/v1/mods", headers=headers).status_code == 200
        assert client.get("/api/v1/mods").status_code == 401
