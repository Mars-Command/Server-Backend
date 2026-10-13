import base64
import hashlib
import importlib
import json
import secrets
import shutil
import time
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from server import release_publishing as publishing

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".test-work"
BASE = "https://api.example.com"
TOKEN = "release-only-fixture-" + "d" * 40
EXISTING = "mods/existing-1.0.0.jar"
NEW = "mods/mars-command-mod-0.4.0.jar"
PREFIX = publishing.PREFIX


@pytest.fixture
def environment(monkeypatch):
    WORK.mkdir(exist_ok=True)
    folder = WORK / secrets.token_hex(8)
    legacy = folder / "legacy"
    (legacy / "mods").mkdir(parents=True)
    (legacy / EXISTING).write_bytes(b"existing fixture")
    (legacy / "manifest.json").write_bytes(b'{"old":"manifest"}')
    (legacy / "manifest.json.sig").write_text("old signature", encoding="ascii")
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    values = {
        "MARS_RELEASE_DIR": str(legacy), "MARS_API_JWT_SECRET": "pack-fixture-" + "p" * 40,
        "MARS_PUBLIC_BASE_URL": BASE, "MARS_PACK_VERSION": "1.2.4",
        "MARS_RELEASE_DEPLOY_TOKEN": TOKEN, "MARS_RELEASE_PUBLIC_KEY": public,
        "MARS_RELEASE_PUBLISH_DIR": str(folder / "publisher"), "DEV_TOKEN": "false",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    for name in ("MARS_AUTH_JWT_SECRET", "MARS_MINECRAFT_SERVER_TOKEN",
                 "MARS_RELEASE_MAX_FILE_BYTES", "MARS_RELEASE_MAX_PACK_BYTES",
                 "MARS_RELEASE_MAX_STAGING", "MARS_RELEASE_EXPIRY_SECONDS",
                 "MARS_MANAGED_DIRS", "MARS_MUTABLE_DIRS"):
        monkeypatch.delenv(name, raising=False)
    from server import main
    main = importlib.reload(main)
    with TestClient(main.app, base_url=BASE) as client:
        yield SimpleNamespace(
            client=client, module=main, signer=signer, public=public, legacy=legacy,
            folder=folder, workflow=main.app.state.release_publisher,
            headers={"Authorization": "Bearer " + TOKEN},
        )
    shutil.rmtree(folder)
    if not any(WORK.iterdir()):
        WORK.rmdir()


def pack(files=None, version="1.2.5"):
    files = files if files is not None else {EXISTING: b"existing fixture", NEW: b"new fixture"}
    return {
        "schemaVersion": 1, "packVersion": version, "minecraftVersion": "1.21.1",
        "loader": "neoforge", "loaderVersion": "21.1.250", "generatedAt": "2026-10-13T00:00:00Z",
        "managedDirs": ["mods", "config"], "modsDir": "mods",
        "files": [
            {"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest(),
             "downloadUrl": BASE + "/api/v1/files/" + quote(name, safe="/"),
             "mutable": name.startswith("config/")}
            for name, content in files.items()
        ],
    }


def signed(env, manifest):
    raw = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return raw, {"manifestBase64": base64.b64encode(raw).decode("ascii"), "signature": env.signer.sign(raw).hex()}


def reserve(env, manifest=None):
    raw, body = signed(env, manifest if manifest is not None else pack())
    response = env.client.post(PREFIX, headers=env.headers, json=body)
    assert response.status_code == 200, response.text
    return raw, body, response.json()


def upload(env, deployment, index, content, offset=0):
    return env.client.put(f"{PREFIX}/{deployment}/files/{index}", params={"offset": offset},
                          headers={**env.headers, "Content-Type": "application/octet-stream"}, content=content)


def commit(env, deployment):
    return env.client.post(f"{PREFIX}/{deployment}/commit", headers=env.headers, json={})


def test_authentication_is_dedicated_and_checked_before_reading_uploads(environment):
    env = environment
    response = env.client.post(PREFIX, content=b"not-json", headers={"Content-Length": "999999999999"})
    assert response.status_code == 401
    pack_token = jwt.encode({
        "sub": "reader", "scope": "mods:read", "aud": env.module.JWT_AUDIENCE,
        "iss": env.module.JWT_ISSUER, "exp": int(time.time()) + 300,
    }, env.module.JWT_SECRET, algorithm="HS256")
    assert env.client.post(PREFIX, json={}, headers={"Authorization": "Bearer " + pack_token}).status_code == 401
    assert env.client.get("/api/v1/mods", headers=env.headers).status_code == 401
    assert env.client.post(PREFIX, headers={**env.headers, "Origin": BASE}, json={}).status_code == 403
    assert env.client.post(PREFIX, headers={**env.headers, "Sec-Fetch-Mode": "cors"}, json={}).status_code == 403


def test_invalid_signatures_never_create_a_deployment(environment):
    env = environment
    raw, body = signed(env, pack())
    body["signature"] = "00" * 64
    assert env.client.post(PREFIX, headers=env.headers, json=body).json()["detail"]["code"] == "invalid_signature"
    raw, body = signed(env, pack())
    body["manifestBase64"] = base64.b64encode(raw + b" ").decode("ascii")
    assert env.client.post(PREFIX, headers=env.headers, json=body).status_code == 422
    assert env.workflow.active_root() == (None, env.legacy)


@pytest.mark.parametrize("relative", [
    "../secret", "/mods/secret.jar", "mods/../secret", "mods\\secret.jar",
    "config//bad.cfg", "config/C:drive", "server/main.py", "config/.env/../secret", "config/trailing. ",
    "config/CON.txt", "config/unknown?.cfg",
])
def test_unsafe_or_undeclared_directories_are_rejected(environment, relative):
    env = environment
    _, body = signed(env, pack({relative: b"data"}))
    assert env.client.post(PREFIX, headers=env.headers, json=body).status_code == 422
    assert env.workflow.active_root()[0] is None


def test_duplicate_paths_bool_sizes_and_unhashed_curseforge_entries_fail(environment):
    env = environment
    for mutation in ("duplicate", "case", "bool", "schema_bool", "schema_float", "curseforge"):
        manifest = pack()
        if mutation == "duplicate":
            manifest["files"].append(manifest["files"][0].copy())
        elif mutation == "case":
            entry = manifest["files"][0].copy()
            entry["path"] = entry["path"].upper()
            manifest["files"].append(entry)
        elif mutation == "bool":
            manifest["files"][0]["size"] = True
        elif mutation == "schema_bool":
            manifest["schemaVersion"] = True
        elif mutation == "schema_float":
            manifest["schemaVersion"] = 1.0
        else:
            manifest["curseforgeMods"] = [{"projectId": 123, "fileId": 456}]
        _, body = signed(env, manifest)
        assert env.client.post(PREFIX, headers=env.headers, json=body).status_code == 422


def test_publish_refreshes_every_public_and_authenticated_surface_without_restart(environment):
    env = environment
    raw, body, deployment = reserve(env)
    assert deployment["files"][0]["reusable"]
    assert not deployment["files"][1]["reusable"]
    assert upload(env, deployment["deploymentId"], 1, b"new fixture").json()["complete"]
    response = commit(env, deployment["deploymentId"])
    assert response.status_code == 200, response.text
    assert response.json()["fileCount"] == 2
    assert env.client.get("/api/v1/manifest.json").content == raw
    assert env.client.get("/api/v1/manifest.json.sig").text == body["signature"]
    assert env.client.get("/api/v1/files/" + NEW).content == b"new fixture"
    assert env.client.get("/api/v1/files/" + EXISTING).content == b"existing fixture"
    assert env.client.get("/api/v1/manifest.json").headers["cache-control"] == "no-cache"
    token = jwt.encode({
        "sub": "reader", "scope": "mods:read", "aud": env.module.JWT_AUDIENCE,
        "iss": env.module.JWT_ISSUER, "exp": int(time.time()) + 300,
    }, env.module.JWT_SECRET, algorithm="HS256")
    headers = {"Authorization": "Bearer " + token}
    mods = env.client.get("/api/v1/mods", headers=headers).json()["mods"]
    assert {entry["filename"] for entry in mods} == {Path(EXISTING).name, Path(NEW).name}
    for entry in mods:
        assert env.client.get(entry["downloadUrl"], headers=headers).status_code == 200
    preview = env.client.get("/api/v1/manifest/preview", headers=headers).json()
    assert preview["packVersion"] == "1.2.5"
    assert all(entry["downloadUrl"].startswith(BASE + "/api/v1/files/") for entry in preview["files"])
    assert not (env.legacy / NEW).exists()
    assert (env.legacy / "manifest.json").read_bytes() == b'{"old":"manifest"}'


def test_partial_uploads_resume_and_retried_chunks_are_idempotent(environment):
    env = environment
    _, _, deployment = reserve(env)
    identifier = deployment["deploymentId"]
    assert upload(env, identifier, 1, b"new ").json() == {"uploadedBytes": 4, "complete": False}
    assert upload(env, identifier, 1, b"new ").json()["uploadedBytes"] == 4
    assert upload(env, identifier, 1, b"BAD ").status_code == 409
    assert upload(env, identifier, 1, b"fixture", offset=5).status_code == 422
    assert upload(env, identifier, 1, b"fixture", offset=4).json()["complete"]
    assert commit(env, identifier).status_code == 200
    assert commit(env, identifier).status_code == 200
    assert env.client.post(PREFIX, headers=env.headers, json=signed(env, pack())[1]).json()["active"]
    assert upload(env, identifier, 1, b"anything").status_code == 409


def test_missing_or_bad_payload_preserves_the_previous_release(environment):
    env = environment
    _, _, deployment = reserve(env)
    identifier = deployment["deploymentId"]
    assert commit(env, identifier).status_code == 409
    assert env.client.get("/api/v1/manifest.json").content == b'{"old":"manifest"}'
    assert upload(env, identifier, 1, b"bad fixture").status_code == 422
    assert env.client.get(f"{PREFIX}/{identifier}", headers=env.headers).json()["files"][1]["uploadedBytes"] == 0
    assert env.client.get("/api/v1/manifest.json").content == b'{"old":"manifest"}'
    assert upload(env, identifier, 1, b"new fixture").status_code == 200
    assert commit(env, identifier).status_code == 200


def test_zero_size_managed_file_is_verified_without_requiring_a_nonempty_chunk(environment):
    env = environment
    _, _, deployment = reserve(env, pack({EXISTING: b"existing fixture", "config/empty.cfg": b""}))
    assert upload(env, deployment["deploymentId"], 1, b"").json() == {"uploadedBytes": 0, "complete": True}
    assert commit(env, deployment["deploymentId"]).status_code == 200
    assert env.client.get("/api/v1/files/config/empty.cfg").content == b""


def test_unicode_paths_and_exact_manifest_bytes_survive_publication(environment):
    env = environment
    name = "resourcepacks/\u00a7eTorches[v1.8].zip"
    manifest = pack({EXISTING: b"existing fixture", name: b"pack"})
    manifest["managedDirs"].append("resourcepacks")
    raw, body, deployment = reserve(env, manifest)
    assert upload(env, deployment["deploymentId"], 1, b"pack").status_code == 200
    assert commit(env, deployment["deploymentId"]).status_code == 200
    assert env.client.get("/api/v1/manifest.json").content == raw
    env.signer.public_key().verify(bytes.fromhex(body["signature"]), raw)
    assert env.client.get("/api/v1/files/" + quote(name, safe="/")).content == b"pack"


def test_concurrent_publications_are_fenced_and_do_not_reactivate_old_releases(environment):
    env = environment
    _, _, first = reserve(env, pack({EXISTING: b"existing fixture"}))
    _, _, second = reserve(env, pack({EXISTING: b"existing fixture"}, version="1.2.6"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda identifier: commit(env, identifier).status_code,
                                (first["deploymentId"], second["deploymentId"])))
    assert sorted(results) == [200, 409]
    active, _ = env.workflow.active_root()
    other = first["deploymentId"] if active == second["deploymentId"] else second["deploymentId"]
    assert commit(env, other).status_code == 409


def test_staging_and_active_selection_persist_across_server_restart(environment):
    env = environment
    raw, _, deployment = reserve(env)
    identifier = deployment["deploymentId"]
    assert upload(env, identifier, 1, b"new ").status_code == 200
    restarted = publishing.Publisher(env.workflow.settings, env.workflow.validate_snapshot)
    assert restarted.status(identifier).files[1].uploadedBytes == 4
    assert restarted.upload(identifier, 1, 4, b"fixture").complete
    assert restarted.commit(identifier).packVersion == "1.2.5"
    assert env.workflow.active_root()[0] == identifier
    main = importlib.reload(env.module)
    with TestClient(main.app, base_url=BASE) as client:
        assert client.get("/api/v1/manifest.json").content == raw
        assert client.get("/api/v1/files/" + NEW).content == b"new fixture"

def test_prepared_generation_recovers_after_a_crash_before_pointer_commit(environment):
    env = environment
    _, _, deployment = reserve(env, pack({NEW: b"new fixture"}))
    identifier = deployment["deploymentId"]
    assert upload(env, identifier, 0, b"new fixture").status_code == 200
    prepared = env.workflow.root(identifier)
    prepared.parent.mkdir(parents=True, exist_ok=True)
    env.workflow.root(identifier, published=False).rename(prepared)
    assert env.workflow.active_root()[0] is None
    assert env.client.get(f"{PREFIX}/{identifier}", headers=env.headers).json()["files"][0]["complete"]
    assert upload(env, identifier, 0, b"new fixture").status_code == 409
    assert commit(env, identifier).status_code == 200
    assert env.client.get("/api/v1/files/" + NEW).content == b"new fixture"



def test_expired_deployment_cannot_accept_bytes_or_publish(environment, monkeypatch):
    env = environment
    _, body, deployment = reserve(env)
    future = deployment["expiresAt"] + 1
    monkeypatch.setattr(publishing, "time", SimpleNamespace(time=lambda: future))
    identifier = deployment["deploymentId"]
    assert upload(env, identifier, 1, b"new fixture").status_code == 410
    assert commit(env, identifier).status_code == 410
    replacement = env.client.post(PREFIX, headers=env.headers, json=body)
    assert replacement.status_code == 200
    assert replacement.json()["deploymentId"] == identifier
    assert replacement.json()["expiresAt"] > future


def test_existing_file_mutation_or_storage_failure_cannot_switch_active_release(environment, monkeypatch):
    env = environment
    _, _, deployment = reserve(env)
    (env.legacy / EXISTING).write_bytes(b"changed file")
    assert upload(env, deployment["deploymentId"], 1, b"new fixture").status_code == 200
    assert commit(env, deployment["deploymentId"]).status_code == 409
    assert env.workflow.active_root()[0] is None
    monkeypatch.setattr(env.workflow, "_copy_verified",
                        lambda *args: (_ for _ in ()).throw(OSError("injected storage failure")))
    assert commit(env, deployment["deploymentId"]).status_code == 503
    assert env.workflow.active_root()[0] is None


def test_invalid_serving_inventory_never_activates(environment, monkeypatch):
    env = environment
    _, _, deployment = reserve(env, pack({EXISTING: b"existing fixture"}))
    def invalid(root):
        raise ValueError("injected inventory failure")
    monkeypatch.setattr(env.workflow, "validate_snapshot", invalid)
    response = commit(env, deployment["deploymentId"])
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_inventory"
    assert env.workflow.active_root()[0] is None


def test_symlink_upload_paths_are_rejected_without_touching_the_target(environment):
    env = environment
    _, _, deployment = reserve(env)
    identifier = deployment["deploymentId"]
    root = env.workflow.root(identifier, published=False)
    outside = env.folder / "outside"
    outside.mkdir()
    (outside / "protected").write_bytes(b"do not replace")
    try:
        (root / "mods").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symbolic link creation requires Windows developer mode or elevation")
    assert upload(env, identifier, 1, b"new fixture").status_code == 409
    assert (outside / "protected").read_bytes() == b"do not replace"
    assert not (outside / Path(NEW).name).exists()


def test_chunk_body_limits_apply_to_declared_and_actual_lengths(environment, monkeypatch):
    env = environment
    monkeypatch.setattr(publishing, "CHUNK_BYTES", 8)
    _, _, deployment = reserve(env, pack({EXISTING: b"existing fixture", NEW: b"0123456789abcdef"}))
    identifier = deployment["deploymentId"]
    assert upload(env, identifier, 1, b"012345678").status_code == 413
    assert upload(env, identifier, 1, b"01234567").status_code == 200
    assert upload(env, identifier, 1, b"89abcdef", offset=8).status_code == 200
    assert commit(env, identifier).status_code == 200

def test_actual_eight_mib_chunk_boundary_is_accepted_and_next_byte_is_rejected(environment):
    env = environment
    payload = b"x" * publishing.CHUNK_BYTES + b"y"
    _, _, deployment = reserve(env, pack({NEW: payload}))
    identifier = deployment["deploymentId"]
    assert upload(env, identifier, 0, payload).status_code == 413
    assert upload(env, identifier, 0, payload[:-1]).json() == {
        "uploadedBytes": publishing.CHUNK_BYTES, "complete": False
    }
    assert upload(env, identifier, 0, b"y", offset=publishing.CHUNK_BYTES).json()["complete"]
    assert commit(env, identifier).status_code == 200


def test_declared_size_limits_accept_exact_thresholds_and_reject_overflow(environment):
    env = environment
    maximum = env.workflow.settings.max_file_bytes
    manifest = pack({NEW: b""})
    manifest["files"][0]["size"] = maximum
    _, _, deployment = reserve(env, manifest)
    assert deployment["files"][0]["size"] == maximum
    manifest["files"][0]["size"] += 1
    _, body = signed(env, manifest)
    response = env.client.post(PREFIX, headers=env.headers, json=body)
    assert response.status_code == 413 and response.json()["detail"]["code"] == "file_too_large"
    entries = []
    for index in range(env.workflow.settings.max_pack_bytes // maximum):
        entry = {**manifest["files"][0], "path": f"mods/large-{index}.jar", "size": maximum}
        entries.append(entry)
    manifest["files"] = entries
    _, _, exact = reserve(env, manifest)
    assert sum(entry["size"] for entry in exact["files"]) == env.workflow.settings.max_pack_bytes
    manifest["files"].append({**entries[0], "path": "mods/overflow.jar", "size": 1})
    _, body = signed(env, manifest)
    response = env.client.post(PREFIX, headers=env.headers, json=body)
    assert response.status_code == 413 and response.json()["detail"]["code"] == "pack_too_large"


def test_staging_capacity_is_bounded(environment):
    env = environment
    for patch in range(env.workflow.settings.max_staging):
        reserve(env, pack({EXISTING: b"existing fixture"}, version=f"2.0.{patch}"))
    _, body = signed(env, pack({EXISTING: b"existing fixture"}, version="3.0.0"))
    response = env.client.post(PREFIX, headers=env.headers, json=body)
    assert response.status_code == 429
    assert response.json()["detail"]["code"] == "staging_capacity"



def test_request_validation_does_not_echo_manifest_or_secret_input(environment):
    env = environment
    response = env.client.post(PREFIX, headers=env.headers, json={
        "manifestBase64": "sensitive-fixture", "signature": "bad", "unexpected": "private-fixture",
    })
    assert response.status_code == 422
    assert "sensitive-fixture" not in response.text and "private-fixture" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_new_file_only_inventory_removes_old_mods_from_active_downloads(environment):
    env = environment
    _, _, deployment = reserve(env, pack({NEW: b"new fixture"}))
    assert upload(env, deployment["deploymentId"], 0, b"new fixture").status_code == 200
    assert commit(env, deployment["deploymentId"]).status_code == 200
    assert env.client.get("/api/v1/files/" + EXISTING).status_code == 404
    assert (env.legacy / EXISTING).read_bytes() == b"existing fixture"

def test_server_owned_mod_metadata_is_preserved_for_published_generations(environment):
    env = environment
    (env.legacy / "mods.json").write_text(json.dumps({
        Path(EXISTING).name: {"id": "stable-mod-id", "name": "Operator mod name", "version": "operator-version"}
    }), encoding="utf-8")
    _, _, deployment = reserve(env, pack({EXISTING: b"existing fixture"}))
    assert commit(env, deployment["deploymentId"]).status_code == 200
    snapshot = env.module.current_package_snapshot()
    assert snapshot.mods["stable-mod-id"]["name"] == "Operator mod name"
    assert snapshot.mods["stable-mod-id"]["version"] == "operator-version"
    assert not (snapshot.root / "mods.json").exists()



def test_disabled_publishing_returns_503_without_affecting_current_downloads(environment, monkeypatch):
    env = environment
    monkeypatch.delenv("MARS_RELEASE_DEPLOY_TOKEN")
    main = importlib.reload(env.module)
    with TestClient(main.app, base_url=BASE) as client:
        assert client.post(PREFIX, headers=env.headers, json={}).status_code == 503
        assert client.get("/api/v1/files/" + EXISTING).content == b"existing fixture"


def test_credential_reuse_and_unsafe_storage_configuration_fail_at_startup(environment, monkeypatch):
    env = environment
    settings = env.workflow.settings
    with pytest.raises(ValueError):
        publishing.PublishSettings(**{**settings.__dict__, "directory": env.legacy / "config" / "publisher"})
    with pytest.raises(ValueError):
        publishing.PublishSettings(**{**settings.__dict__, "token": "short"})
    with pytest.raises(ValueError):
        publishing.PublishSettings(**{**settings.__dict__, "public_key": "bad"})
    with pytest.raises(ValueError):
        publishing.PublishSettings(**{**settings.__dict__, "directory": ROOT / "output" / "publisher"})
    monkeypatch.setenv("MARS_RELEASE_DEPLOY_TOKEN", env.module.JWT_SECRET)
    with pytest.raises(ValueError, match="separate"):
        publishing.PublishSettings.from_env(
            env.legacy, env.module.MANAGED_DIRS, "1.21.1", "neoforge", "21.1.250"
        )


def test_wrong_versions_and_published_version_rollback_are_rejected(environment):
    env = environment
    manifest = pack({EXISTING: b"existing fixture"})
    manifest["loaderVersion"] = "21.1.999"
    _, body = signed(env, manifest)
    assert env.client.post(PREFIX, headers=env.headers, json=body).json()["detail"]["code"] == "incompatible_pack"
    _, _, first = reserve(env, pack({EXISTING: b"existing fixture"}, version="1.2.6"))
    assert commit(env, first["deploymentId"]).status_code == 200
    _, _, older = reserve(env, pack({EXISTING: b"existing fixture"}, version="1.2.5"))
    response = commit(env, older["deploymentId"])
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "non_increasing_version"
    assert env.workflow.active_root()[0] == first["deploymentId"]


def test_public_key_rotation_can_activate_a_new_signed_generation(environment):
    env = environment
    _, _, first = reserve(env, pack({EXISTING: b"existing fixture"}))
    assert commit(env, first["deploymentId"]).status_code == 200
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    rotated = publishing.Publisher(replace(env.workflow.settings, public_key=public), env.workflow.validate_snapshot)
    raw = json.dumps(pack({EXISTING: b"existing fixture"}, version="1.2.6")).encode()
    identifier = rotated.reserve(publishing.Reserve(
        manifestBase64=base64.b64encode(raw).decode("ascii"), signature=signer.sign(raw).hex()
    ))
    assert rotated.commit(identifier).packVersion == "1.2.6"
    assert env.client.get("/api/v1/manifest.json").content == raw
