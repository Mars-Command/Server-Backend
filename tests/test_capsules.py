import hashlib
import secrets
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from server.capsules import CapsuleBlocked, CapsuleMetadata, CapsuleRegistry
from server.community import Store

WORK = Path(__file__).resolve().parent.parent / ".test-work"
ALICE = "github:123"
BOB = "github:456"
METADATA = {"project": "Example", "version": "1.0", "declared_source": "Author declaration"}


@pytest.fixture
def registry():
    WORK.mkdir(exist_ok=True)
    folder = WORK / secrets.token_hex(8)
    folder.mkdir()
    store = Store(str(folder / "community.sqlite3"))
    with store.connect() as db:
        for user in (ALICE, BOB):
            db.execute("INSERT INTO users VALUES (?, ?, '', '[]')", (user, user))
    try:
        yield CapsuleRegistry(store)
    finally:
        shutil.rmtree(folder)
        if not any(WORK.iterdir()):
            WORK.rmdir()


def reserve(registry, user=ALICE, **fields):
    return registry.reserve(user, CapsuleMetadata(**{**METADATA, **fields}))


def assert_blocked(registry, release, code):
    for gate in (registry.require_publishable, registry.require_downloadable):
        with pytest.raises(CapsuleBlocked) as error:
            gate(release.release_id, release.uploader_id)
        assert error.value.code == code


def test_pending_release_survives_reopen_and_cannot_publish_or_download(registry):
    release = reserve(registry)
    assert release.artifact_sha256 is None
    assert release.uploader_id == ALICE
    assert len(release.release_id) == 32
    reopened = CapsuleRegistry(Store(registry.store.path))
    assert reopened.get(release.release_id, ALICE) == release
    assert_blocked(reopened, release, "artifact_pending")


def test_capsule_schema_migrates_on_reopen_without_losing_community_data(registry):
    with registry.store.connect() as db:
        db.execute(
            "INSERT INTO profiles VALUES (?, ?, ?, ?, ?, 'private', NULL, ?)",
            ("legacy-profile", ALICE, "Legacy", "", "[]", "2026-01-01"),
        )
        db.execute("DROP TABLE capsule_release_artifacts")
        db.execute("DROP TABLE capsule_artifacts")
        db.execute("DROP TABLE capsule_releases")

    reopened = CapsuleRegistry(Store(registry.store.path))
    with reopened.store.connect() as db:
        assert db.execute(
            "SELECT name FROM profiles WHERE id='legacy-profile'"
        ).fetchone()[0] == "Legacy"
        tables = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {
            "capsule_releases",
            "capsule_artifacts",
            "capsule_release_artifacts",
        } <= tables
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert db.execute("PRAGMA synchronous").fetchone()[0] == 2

    assert reserve(reopened).artifact_sha256 is None


def test_observed_checksum_deduplicates_bytes_not_release_or_provenance(registry):
    first = reserve(registry)
    second = reserve(registry, BOB, version="2.0", declared_source="Different declaration")
    first = registry.observe(first.release_id, ALICE, [b"ja", b"r"], max_bytes=3)
    second = registry.observe(second.release_id, BOB, [b"jar"], max_bytes=3)
    assert first.release_id != second.release_id
    assert first.artifact_sha256 == second.artifact_sha256 == hashlib.sha256(b"jar").hexdigest()
    assert first.metadata != second.metadata
    assert first.uploader_id != second.uploader_id
    with registry.store.connect() as db:
        artifact = db.execute("SELECT * FROM capsule_artifacts").fetchone()
        assert artifact["size"] == 3
        assert artifact["scan_state"] == "unscanned"
        assert artifact["availability"] == "unavailable"
        assert db.execute("SELECT count(*) FROM capsule_artifacts").fetchone()[0] == 1
    assert_blocked(registry, first, "artifact_unavailable")
    assert_blocked(registry, second, "artifact_unavailable")


@pytest.mark.parametrize("field", ["sha256", "artifact_sha256", "scan_state", "clean", "available", "uploader_id", "release_id"])
def test_client_proof_and_identity_fields_are_not_metadata(field):
    with pytest.raises(ValidationError):
        CapsuleMetadata(**{**METADATA, field: "a" * 64})


def test_capsule_facts_and_binding_are_immutable(registry):
    release = reserve(registry)
    observed = registry.observe(release.release_id, ALICE, [b"first"], max_bytes=5)
    assert observed.metadata == release.metadata
    assert observed.created_at == release.created_at
    with pytest.raises(ValidationError):
        observed.metadata.version = "replacement"
    with pytest.raises(CapsuleBlocked, match="release_already_bound"):
        registry.observe(release.release_id, ALICE, [b"second"], max_bytes=6)
    for statement in (
        "UPDATE capsule_releases SET version='replacement'",
        "DELETE FROM capsule_releases",
        "UPDATE capsule_release_artifacts SET artifact_sha256='" + "a" * 64 + "'",
        "DELETE FROM capsule_release_artifacts",
        "UPDATE capsule_artifacts SET size=100",
        "INSERT OR REPLACE INTO capsule_releases "
        "SELECT release_id, uploader_id, project, 'replacement', declared_source, created_at "
        "FROM capsule_releases",
        "INSERT OR REPLACE INTO capsule_release_artifacts SELECT * FROM capsule_release_artifacts",
        "INSERT OR REPLACE INTO capsule_artifacts SELECT * FROM capsule_artifacts",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            with registry.store.connect() as db:
                db.execute(statement)
    assert registry.get(release.release_id, ALICE) == observed


@pytest.mark.parametrize("chunks,bound,code", [
    ([], 3, "artifact_empty"),
    ([b""], 3, "artifact_empty"),
    ([b"ab", b"cd"], 3, "artifact_too_large"),
])
def test_failed_observation_leaves_no_artifact_or_binding(registry, chunks, bound, code):
    release = reserve(registry)
    with pytest.raises(CapsuleBlocked, match=code):
        registry.observe(release.release_id, ALICE, chunks, max_bytes=bound)
    assert registry.get(release.release_id, ALICE) == release
    with registry.store.connect() as db:
        assert db.execute("SELECT count(*) FROM capsule_artifacts").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM capsule_release_artifacts").fetchone()[0] == 0


@pytest.mark.parametrize("chunks,bound", [(["a" * 64], 100), ([b"x"], 0), ([b"x"], True)])
def test_observation_requires_bytes_and_deliberate_bound(registry, chunks, bound):
    release = reserve(registry)
    with pytest.raises(ValueError):
        registry.observe(release.release_id, ALICE, chunks, max_bytes=bound)
    assert registry.get(release.release_id, ALICE) == release


def test_failed_stream_does_not_persist_partial_observation(registry):
    release = reserve(registry)

    def broken():
        yield b"partial"
        raise OSError("stream failed")

    with pytest.raises(OSError):
        registry.observe(release.release_id, ALICE, broken(), max_bytes=100)
    assert registry.get(release.release_id, ALICE) == release


def test_reservation_revalidates_constructed_metadata(registry):
    invalid = CapsuleMetadata.model_construct(**{**METADATA, "project": ""})
    with pytest.raises(ValidationError):
        registry.reserve(ALICE, invalid)
    with registry.store.connect() as db:
        assert db.execute("SELECT count(*) FROM capsule_releases").fetchone()[0] == 0


def test_owner_mismatch_is_not_found_and_does_not_read_bytes(registry):
    release = reserve(registry)

    def unread():
        pytest.fail("An unauthorized observation must not consume bytes")
        yield b"unused"

    for release_id in (release.release_id, "missing"):
        with pytest.raises(CapsuleBlocked, match="release_not_found"):
            registry.get(release_id, BOB)
        with pytest.raises(CapsuleBlocked, match="release_not_found"):
            registry.observe(release_id, BOB, unread(), max_bytes=100)
        for gate in (registry.require_publishable, registry.require_downloadable):
            with pytest.raises(CapsuleBlocked, match="release_not_found"):
                gate(release_id, BOB)


def test_concurrent_binding_has_one_winner(registry):
    release = reserve(registry)

    def bind(data):
        try:
            return registry.observe(release.release_id, ALICE, [data], max_bytes=100)
        except CapsuleBlocked as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(bind, (b"first", b"second")))
    assert results.count("release_already_bound") == 1
    with registry.store.connect() as db:
        assert db.execute("SELECT count(*) FROM capsule_artifacts").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM capsule_release_artifacts").fetchone()[0] == 1


@pytest.mark.parametrize("state", ["unscanned", "pending", "rejected", "error"])
def test_all_supported_scan_states_remain_blocked_and_dedup_preserves_state(registry, state):
    first = reserve(registry)
    registry.observe(first.release_id, ALICE, [b"jar"], max_bytes=3)
    with registry.store.connect() as db:
        db.execute("UPDATE capsule_artifacts SET scan_state=?", (state,))
    second = reserve(registry)
    registry.observe(second.release_id, ALICE, [b"jar"], max_bytes=3)
    with registry.store.connect() as db:
        assert db.execute("SELECT scan_state FROM capsule_artifacts").fetchone()[0] == state
    assert_blocked(registry, first, "artifact_unavailable")
    assert_blocked(registry, second, "artifact_unavailable")


def test_positive_flags_are_not_supported_proof_even_in_future_or_corrupt_database(registry):
    release = reserve(registry)
    registry.observe(release.release_id, ALICE, [b"jar"], max_bytes=3)
    for statement in (
        "UPDATE capsule_artifacts SET scan_state='clean'",
        "UPDATE capsule_artifacts SET availability='available'",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            with registry.store.connect() as db:
                db.execute(statement)
    # Simulate incompatible future/corrupt state; the final integration gate still denies.
    with registry.store.connect() as db:
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute("UPDATE capsule_artifacts SET scan_state='clean', availability='available'")
    assert_blocked(registry, release, "capsule_integration_not_configured")
    with registry.store.connect() as db:
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute("UPDATE capsule_artifacts SET scan_state='pending'")
    assert_blocked(registry, release, "artifact_not_clean")


def test_missing_artifact_fails_closed(registry):
    release = reserve(registry)
    registry.observe(release.release_id, ALICE, [b"jar"], max_bytes=3)
    db = sqlite3.connect(registry.store.path)
    try:
        db.execute("DELETE FROM capsule_artifacts")
        db.commit()
    finally:
        db.close()
    assert_blocked(registry, release, "artifact_unavailable")
