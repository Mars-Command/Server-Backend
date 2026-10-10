import asyncio
import hashlib
import io
import os
import secrets
import shutil
import sqlite3
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Literal

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server import community
from server.capsules import CapsuleBlocked
from server.ingestion import (
    CapsuleWorkflow, PrivateBucket, ScanResult,
)

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".test-work"
OWNER = "github:123"
OTHER = "github:456"
ORIGIN = "https://website.example.com"
METADATA = {"project": "Example", "version": "1.0", "sourceUrl": "https://modrinth.com/mod/example"}


def jar(entries=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in (entries or {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"}).items():
            archive.writestr(name, data)
    return output.getvalue()


async def chunks(data):
    for start in range(0, len(data), 17):
        yield data[start:start + 17]


@pytest.fixture
def env():
    WORK.mkdir(exist_ok=True)
    folder = WORK / secrets.token_hex(8)
    folder.mkdir()
    settings = community.Settings(
        website_url=ORIGIN, backend_url="https://api.example.com",
        jwt_secret="test-community-" + "a" * 40, database=str(folder / "community.sqlite3"),
    )
    app = FastAPI()
    community.install_community(app, settings)
    store = app.state.community_store
    with store.connect() as db:
        for user in (OWNER, OTHER):
            db.execute("INSERT INTO users VALUES (?,?,'','[]')", (user, user))
    with TestClient(app, base_url=settings.backend_url) as client:
        yield app.state.capsule_workflow, client, settings, folder
    shutil.rmtree(folder)
    if not any(WORK.iterdir()):
        WORK.rmdir()


def reserve(workflow, owner=OWNER, key=None, **metadata):
    values = {**METADATA, **metadata}
    return workflow.reserve(owner, values["project"], values["version"], values["sourceUrl"], key or secrets.token_hex(8))


def upload(workflow, release, data=None):
    return asyncio.run(workflow.upload(release["releaseId"], release["ownerId"], chunks(jar() if data is None else data)))


def token(settings, owner=OWNER):
    now = int(time.time())
    return jwt.encode({
        "sub": owner, "aud": community.DESKTOP_AUDIENCE, "iss": community.ISSUER,
        "iat": now - 1, "exp": now + 300, "jti": secrets.token_hex(8), "scope": "community",
    }, settings.jwt_secret, algorithm="HS256")


class DeterministicScanner:
    provider = "deterministic-test"

    def __init__(self, verdict: Literal["accepted", "rejected", "blocked", "error"] = "accepted", retryable=False):
        self.verdict: Literal["accepted", "rejected", "blocked", "error"] = verdict
        self.retryable = retryable
        self.calls = 0

    def scan(self, digest, path):
        assert PrivateBucket.verify(path, digest)
        self.calls += 1
        return ScanResult("test-result", self.verdict, "test_" + self.verdict, self.retryable)


def trusted(workflow):
    return CapsuleWorkflow(workflow.store, workflow.settings, trusted_provider="deterministic-test")


def test_reserve_idempotent_and_owner_scoped_cap(env):
    workflow, _, _, _ = env
    first = reserve(workflow, key="key")
    assert reserve(workflow, key="key") == first
    with pytest.raises(CapsuleBlocked, match="idempotency_conflict"):
        reserve(workflow, key="key", version="2")
    assert reserve(workflow, OTHER, key="key")["releaseId"] != first["releaseId"]
    for _ in range(9):
        reserve(workflow)
    with pytest.raises(CapsuleBlocked, match="submission_limit"):
        reserve(workflow)
    assert reserve(workflow, key="key") == first
    workflow.withdraw(first["releaseId"], OWNER)
    assert reserve(workflow)["state"] == "reserved"


def test_reserve_concurrency_and_reopen(env):
    workflow, _, _, _ = env
    with ThreadPoolExecutor(max_workers=4) as pool:
        releases = list(pool.map(lambda _: reserve(workflow, key="same-key"), range(4)))
    assert len({r["releaseId"] for r in releases}) == 1
    reopened = CapsuleWorkflow(community.Store(workflow.store.path), workflow.settings)
    assert reopened.get(releases[0]["releaseId"], OWNER) == releases[0]
    with reopened.store.connect() as db:
        assert db.execute("SELECT count(*) FROM capsule_migrations").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM capsule_transitions").fetchone()[0] == 1


def test_stream_hash_retry_dedup_and_disabled_worker(env):
    workflow, _, _, _ = env
    raw = jar()
    first = reserve(workflow)
    result = upload(workflow, first, raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert result["artifactSha256"] == digest
    assert result["state"] == "scan_pending"
    assert upload(workflow, first, raw) == result
    with pytest.raises(CapsuleBlocked, match="release_already_bound"):
        upload(workflow, first, jar({"Different.class": b"content"}))
    second = upload(workflow, reserve(workflow, OTHER), raw)
    assert second["artifactSha256"] == digest
    assert workflow.bucket.artifact(digest).read_bytes() == raw
    assert workflow.process_one("test-worker")
    assert not workflow.process_one("test-worker")
    result = workflow.get(first["releaseId"], OWNER)
    assert result["state"] == "scan_blocked"
    assert result["evidence"]["verdict"] == "blocked"
    assert result["evidence"]["provider"] == "disabled"
    assert result["evidence"]["artifactSha256"] == digest
    assert result["queue"]["lastError"] == "scanning_not_configured"
    assert result["publicDownloadAvailable"] is False
    assert workflow.get(second["releaseId"], OTHER)["state"] == "scan_blocked"
    assert not workflow.bucket.artifact(digest, retained=True).exists()
    with workflow.store.connect() as db:
        assert db.execute("SELECT count(*) FROM capsule_jobs").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM capsule_artifacts").fetchone()[0] == 1
        assert [r[0] for r in db.execute("SELECT state FROM capsule_transitions WHERE release_id=? ORDER BY revision",
                                        (first["releaseId"],))] == [
            "reserved", "uploading", "quarantined", "scan_pending", "scan_blocked",
        ]


@pytest.mark.parametrize("data,code", [
    (b"", "artifact_empty"), (b"not-a-jar", "artifact_invalid"),
    (jar({"../escape.class": b"x"}), "artifact_invalid"),
    (jar({"C:/escape.class": b"x"}), "artifact_invalid"),
    (jar({"a/escape.class": b"x"}).replace(b"a/escape.class", b"a\\escape.class"), "artifact_invalid"),
    (jar({"readme.txt": b"x"}), "artifact_invalid"),
])
def test_invalid_archive_or_empty_upload_rolls_back(env, data, code):
    workflow, _, _, _ = env
    release = reserve(workflow)
    with pytest.raises(CapsuleBlocked, match=code):
        upload(workflow, release, data)
    result = workflow.get(release["releaseId"], OWNER)
    assert result["state"] == "reserved" and result["artifactSha256"] is None
    assert not list(workflow.settings.quarantine.iterdir())
    with workflow.store.connect() as db:
        assert db.execute("SELECT count(*) FROM capsule_jobs").fetchone()[0] == 0


def test_stream_size_bound_and_interruption(env):
    workflow, _, _, _ = env
    workflow.settings = replace(workflow.settings, max_bytes=20)
    workflow.bucket.settings = workflow.settings
    release = reserve(workflow)
    with pytest.raises(CapsuleBlocked, match="artifact_too_large"):
        upload(workflow, release)

    async def broken():
        yield b"partial"
        raise OSError("private-local-path-and-secret")

    with pytest.raises(OSError):
        asyncio.run(workflow.upload(release["releaseId"], OWNER, broken()))
    assert workflow.get(release["releaseId"], OWNER)["state"] == "reserved"
    assert not list(workflow.settings.quarantine.iterdir())


def test_archive_bombs_symlink_crc_and_duplicate_entries(env):
    workflow, _, _, folder = env
    path = folder / "fixture.jar"
    for kind in ("ratio", "symlink", "duplicate", "crc", "entries"):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            if kind == "ratio":
                archive.writestr("Bomb.class", b"0" * 100000)
            elif kind == "symlink":
                info = zipfile.ZipInfo("Link.class")
                info.external_attr = 0o120777 << 16
                archive.writestr(info, b"target")
            elif kind == "duplicate":
                archive.writestr("D.class", b"a")
                with pytest.warns(UserWarning):
                    archive.writestr("D.class", b"b")
            elif kind == "entries":
                for i in range(10001):
                    archive.writestr(f"{i}.class", b"")
            else:
                archive.writestr("D.class", b"content")
        if kind == "crc":
            raw = bytearray(path.read_bytes())
            raw[14] ^= 1
            raw[raw.index(b"PK\x01\x02") + 16] ^= 1
            path.write_bytes(raw)
        with pytest.raises(CapsuleBlocked, match="artifact_invalid"):
            workflow.bucket.validate(path)


def test_lease_claim_is_atomic_stale_completion_and_recovery(env, monkeypatch):
    workflow, _, _, _ = env
    upload(workflow, reserve(workflow))
    clock = [time.time()]
    monkeypatch.setattr("server.ingestion.time.time", lambda: clock[0])
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(lambda n: workflow.claim(str(n)), range(4)))
    jobs = [j for j in claims if j]
    assert len(jobs) == 1
    first = jobs[0]
    clock[0] += workflow.settings.lease_seconds + 1
    with pytest.raises(CapsuleBlocked, match="stale_lease"):
        workflow.complete(first, ScanResult("old", "accepted", "test_accepted"), "deterministic-test", trusted_provider="deterministic-test")
    assert workflow.claim("recovery") is None
    clock[0] += workflow.settings.retry_seconds + 1
    next_job = workflow.claim("recovery")
    assert next_job["attempts"] == 2 and next_job["lease_token"] != first["lease_token"]
    with pytest.raises(CapsuleBlocked, match="stale_lease"):
        workflow.complete(first, ScanResult("old", "blocked", "test_blocked"), "disabled")
    workflow.complete(next_job, ScanResult("new", "blocked", "test_blocked"), "disabled")
    with workflow.store.connect() as db:
        assert db.execute("SELECT result FROM capsule_attempts WHERE attempt=1").fetchone()[0] == "lease_expired"
        assert db.execute("SELECT count(*) FROM capsule_evidence").fetchone()[0] == 1


@pytest.mark.parametrize("verdict,state", [
    ("accepted", "publishable"), ("rejected", "rejected"),
    ("blocked", "scan_blocked"), ("error", "scan_blocked"),
])
def test_normalized_scanner_results_and_private_gate(env, verdict, state):
    workflow = trusted(env[0])
    release = upload(workflow, reserve(workflow))
    scanner = DeterministicScanner(verdict)
    assert workflow.process_one("worker", scanner)
    result = workflow.get(release["releaseId"], OWNER)
    assert result["state"] == state
    assert not result["publicDownloadAvailable"]
    assert result["evidence"]["version"] == 1
    assert result["evidence"]["verdict"] == verdict
    with workflow.store.connect() as db:
        assert workflow.publishable(db, workflow.owned(db, release["releaseId"], OWNER)) == (verdict == "accepted")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE capsule_evidence SET verdict='accepted'")
    if verdict == "rejected":
        with pytest.raises(CapsuleBlocked, match="retry_not_eligible"):
            workflow.retry(release["releaseId"], OWNER)


def test_untrusted_or_malformed_scanner_can_never_accept(env):
    workflow = env[0]
    release = upload(workflow, reserve(workflow))
    workflow.process_one("worker", DeterministicScanner())
    assert workflow.get(release["releaseId"], OWNER)["evidence"]["summary"] == "scanner_not_trusted"
    workflow.retry(release["releaseId"], OWNER)
    job = workflow.claim("worker")
    workflow.complete(job, {"verdict": "accepted"}, "bad")
    result = workflow.get(release["releaseId"], OWNER)
    assert result["state"] == "scan_blocked"
    assert result["evidence"]["summary"] == "scanner_invalid_result"
    assert result["evidence"]["version"] == 2


def test_retry_backoff_exhaustion_and_idempotency(env, monkeypatch):
    workflow = env[0]
    release = upload(workflow, reserve(workflow))
    clock = [time.time()]
    monkeypatch.setattr("server.ingestion.time.time", lambda: clock[0])
    scanner = DeterministicScanner("error", retryable=True)
    result = release
    for attempt in range(1, 4):
        assert workflow.process_one("worker", scanner)
        result = workflow.get(release["releaseId"], OWNER)
        assert result["queue"]["attempts"] == attempt
        assert result["evidence"]["version"] == attempt
        if attempt < 3:
            assert result["state"] == "scan_pending"
            assert not workflow.process_one("worker", scanner)
            assert workflow.retry(release["releaseId"], OWNER) == result
            clock[0] += workflow.settings.retry_seconds * 2 ** (attempt - 1) + 1
    assert result["state"] == "scan_blocked"
    assert result["queue"]["status"] == "failed"
    with pytest.raises(CapsuleBlocked, match="retry_not_eligible"):
        workflow.retry(release["releaseId"], OWNER)
    assert not workflow.process_one("worker", scanner)


def test_gate_evidence_expiry_policy_and_missing_retention(env, monkeypatch):
    workflow = trusted(env[0])
    release = upload(workflow, reserve(workflow))
    workflow.process_one("worker", DeterministicScanner())
    assert workflow.get(release["releaseId"], OWNER)["state"] == "publishable"
    with workflow.store.connect() as db:
        row = workflow.owned(db, release["releaseId"], OWNER)
        workflow.settings = replace(workflow.settings, policy_version="next-policy")
        assert not workflow.publishable(db, row)
        workflow.settings = env[0].settings
        clock = time.time() + workflow.settings.evidence_seconds + 1
        monkeypatch.setattr("server.ingestion.time.time", lambda: clock)
        assert not workflow.publishable(db, row)
    assert workflow.get(release["releaseId"], OWNER)["state"] == "scan_blocked"


def test_retention_missing_or_modified_is_not_publishable(env):
    workflow = trusted(env[0])
    release = upload(workflow, reserve(workflow))
    workflow.process_one("worker", DeterministicScanner())
    workflow.bucket.artifact(release["artifactSha256"], retained=True).write_bytes(b"changed")
    assert workflow.get(release["releaseId"], OWNER)["state"] == "scan_blocked"


def test_withdraw_during_lease_cannot_revive_release(env):
    workflow = trusted(env[0])
    release = upload(workflow, reserve(workflow))
    job = workflow.claim("worker")
    assert job is not None
    result = workflow.withdraw(release["releaseId"], OWNER)
    assert workflow.withdraw(release["releaseId"], OWNER) == result
    workflow.complete(job, ScanResult("accepted", "accepted", "test_accepted"), "deterministic-test")
    assert workflow.get(release["releaseId"], OWNER)["state"] == "withdrawn"
    with pytest.raises(CapsuleBlocked, match="invalid_state"):
        upload(workflow, release)


def test_cleanup_expiry_reservation_and_shared_bytes(env, monkeypatch):
    workflow = env[0]
    reservation = reserve(workflow)
    first = upload(workflow, reserve(workflow))
    clock = [time.time() + workflow.settings.expiry_seconds + 1]
    monkeypatch.setattr("server.ingestion.time.time", lambda: clock[0])
    second = upload(workflow, reserve(workflow, OTHER))
    path = workflow.bucket.artifact(first["artifactSha256"])
    os.utime(path, (clock[0] - 2 * workflow.settings.expiry_seconds,) * 2)
    assert workflow.cleanup() == 2
    assert workflow.get(reservation["releaseId"], OWNER)["state"] == "expired"
    assert workflow.get(first["releaseId"], OWNER)["state"] == "expired"
    assert path.exists()
    workflow.withdraw(second["releaseId"], OTHER)
    clock[0] += workflow.settings.expiry_seconds + 1
    workflow.cleanup()
    assert not path.exists()
    assert not workflow.process_one("worker")


@pytest.mark.parametrize("field,value", [
    ("max_bytes", 0), ("max_active", -1), ("max_attempts", True),
    ("expiry_seconds", 0), ("lease_seconds", 0), ("scanner", "clean"),
    ("quarantine", Path("relative")), ("quarantine", ROOT / "output" / "quarantine"),
    ("quarantine", ROOT / "static"), ("retained", ROOT),
])
def test_storage_settings_fail_closed(env, field, value):
    with pytest.raises(ValueError):
        replace(env[0].settings, **{field: value})


def test_bucket_permissions(env):
    workflow = env[0]
    result = upload(workflow, reserve(workflow))
    path = workflow.bucket.artifact(result["artifactSha256"])
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
    else:
        import subprocess
        acl = subprocess.run(["icacls", str(path)], check=True, capture_output=True, text=True).stdout
        assert "(I)" not in acl
        assert "Everyone" not in acl and "BUILTIN\\Users" not in acl


def test_authenticated_http_contract_ownership_csrf_no_download(env):
    workflow, client, settings, folder = env
    headers = {"Authorization": "Bearer " + token(settings), "Idempotency-Key": "request-1"}
    result = client.post("/api/community/capsules", json=METADATA, headers=headers)
    assert result.status_code == 201
    release = result.json()
    assert client.post("/api/community/capsules", json=METADATA, headers=headers).json() == release
    route = "/api/community/capsules/" + release["releaseId"]
    assert client.get(route).status_code == 401
    assert client.get(route, headers={"Authorization": "Bearer " + token(settings, OTHER)}).status_code == 404
    result = client.put(route + "/artifact", content=jar(), headers={**headers, "Content-Type": "application/java-archive"})
    assert result.status_code == 200 and result.json()["state"] == "scan_pending"
    assert result.headers["cache-control"] == "no-store"
    assert str(folder) not in result.text and "lease_token" not in result.text
    assert client.get("/api/community/capsules/mine", headers=headers).json()["capsules"] == [result.json()]
    assert client.get(route + "/artifact", headers=headers).status_code == 405
    assert client.get(route + "/download", headers=headers).status_code == 404
    assert client.get("/api/community/capsules", headers=headers).status_code == 405
    with workflow.store.connect() as db:
        db.execute("INSERT INTO sessions VALUES (?,?,?)", (community.digest("session"), OWNER, time.time() + 1000))
    client.cookies.set(community.SESSION_COOKIE, "session", domain="api.example.com", path="/api")
    assert client.post(route + "/withdraw").status_code == 403
    assert client.post(route + "/withdraw", headers={"Origin": ORIGIN + "/"}).status_code == 403
    assert client.post(route + "/withdraw", headers={"Origin": ORIGIN}).json()["state"] == "withdrawn"
    preflight = client.options(route + "/artifact", headers={
        "Origin": ORIGIN, "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "content-type,idempotency-key",
    })
    assert preflight.status_code == 200
    schema = client.get("/openapi.json").json()
    assert "application/java-archive" in schema["paths"][route.replace(release["releaseId"], "{release_id}") + "/artifact"]["put"]["requestBody"]["content"]


def test_http_metadata_bounds_media_body_limits_and_storage_privacy(env, monkeypatch):
    workflow, client, settings, _ = env
    headers = {"Authorization": "Bearer " + token(settings), "Idempotency-Key": "key"}
    for changes in ({"sourceUrl": "http://example.com"}, {"sourceUrl": "https://127.0.0.1/x"},
                    {"sourceUrl": "https://u:p@example.com/x"}, {"project": ""}, {"sha256": "a" * 64}):
        assert client.post("/api/community/capsules", json={**METADATA, **changes}, headers=headers).status_code == 422
    assert client.post("/api/community/capsules", json=METADATA, headers={"Authorization": headers["Authorization"]}).status_code == 422
    release = client.post("/api/community/capsules", json=METADATA, headers=headers).json()
    route = "/api/community/capsules/" + release["releaseId"] + "/artifact"
    assert client.put(route, content=jar(), headers=headers).status_code == 415
    workflow.settings = replace(workflow.settings, max_bytes=20)
    assert client.put(route, content=jar(), headers={**headers, "Content-Type": "application/octet-stream"}).status_code == 413
    assert client.post("/api/community/capsules", content=b"x" * (community.MAX_BODY + 1), headers=headers).status_code == 413
    def broken(*_args, **_kwargs):
        raise OSError("secret-token and private-path")
    monkeypatch.setattr(workflow, "reserve", broken)
    response = client.post("/api/community/capsules", json=METADATA, headers=headers)
    assert response.status_code == 503 and "secret-token" not in response.text


def test_upload_owner_check_does_not_consume_stream(env):
    workflow = env[0]
    release = reserve(workflow)
    async def unread():
        pytest.fail("Unowned upload consumed bytes")
        yield b"unused"
    with pytest.raises(CapsuleBlocked, match="release_not_found"):
        asyncio.run(workflow.upload(release["releaseId"], OTHER, unread()))


def test_worker_command_disabled_scanner(env, monkeypatch):
    from server import worker
    workflow, _, settings, _ = env
    release = upload(workflow, reserve(workflow))
    monkeypatch.setattr(worker.Settings, "from_env", lambda: settings)
    monkeypatch.setattr("sys.argv", ["worker", "--once"])
    assert worker.main() == 0
    assert workflow.get(release["releaseId"], OWNER)["state"] == "scan_blocked"


def test_database_state_and_history_guards(env):
    workflow = env[0]
    release = reserve(workflow)
    with workflow.store.connect() as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE capsule_operations SET state='publishable',revision=revision+1")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE capsule_operations SET state='uploading'")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM capsule_transitions")
    assert workflow.get(release["releaseId"], OWNER) == release


def test_concurrent_upload_and_withdraw_during_stream(env):
    workflow = env[0]
    release = reserve(workflow)

    async def stream():
        with pytest.raises(CapsuleBlocked, match="upload_in_progress"):
            await workflow.upload(release["releaseId"], OWNER, chunks(jar()))
        workflow.withdraw(release["releaseId"], OWNER)
        yield jar()

    with pytest.raises(CapsuleBlocked, match="invalid_state"):
        asyncio.run(workflow.upload(release["releaseId"], OWNER, stream()))
    assert workflow.get(release["releaseId"], OWNER)["state"] == "withdrawn"
    assert not list(workflow.settings.quarantine.iterdir())


def test_upload_timeout_rolls_back(env):
    workflow = env[0]
    workflow.bucket.settings = replace(workflow.settings, upload_seconds=1)
    release = reserve(workflow)

    async def delayed():
        yield b"partial"
        await asyncio.sleep(1.1)
        yield jar()

    with pytest.raises(TimeoutError):
        asyncio.run(workflow.upload(release["releaseId"], OWNER, delayed()))
    assert workflow.get(release["releaseId"], OWNER)["state"] == "reserved"
    assert not list(workflow.settings.quarantine.iterdir())


def test_cleanup_demotes_expired_evidence(env, monkeypatch):
    workflow = trusted(env[0])
    release = upload(workflow, reserve(workflow))
    workflow.process_one("worker", DeterministicScanner())
    future = time.time() + workflow.settings.evidence_seconds + 1
    monkeypatch.setattr("server.ingestion.time.time", lambda: future)
    workflow.cleanup()
    with workflow.store.connect() as db:
        assert workflow.owned(db, release["releaseId"], OWNER)["state"] == "scan_blocked"


def test_migrates_existing_internal_capsule_facts(env):
    from server.capsules import CapsuleMetadata, CapsuleRegistry
    workflow = env[0]
    registry = CapsuleRegistry(workflow.store)
    release = registry.reserve(OWNER, CapsuleMetadata(
        project="Legacy", version="1", declared_source="https://example.com/mod",
    ))
    community.Store(workflow.store.path)
    migrated = workflow.get(release.release_id, OWNER)
    assert migrated["state"] == "reserved"
    assert migrated["project"] == "Legacy" and migrated["artifactSha256"] is None


def test_diagnostic_formatter_only_emits_allowed_context():
    import logging
    from server.worker import DiagnosticFormatter
    record = logging.LogRecord("mars-capsules", logging.WARNING, "", 0,
                               "capsule_scan_failed", (), None)
    record.job_id = 1
    record.attempts = 3
    record.provider_secret = "do-not-log"
    output = DiagnosticFormatter().format(record)
    assert '"job_id": 1' in output and '"attempts": 3' in output
    assert "do-not-log" not in output
