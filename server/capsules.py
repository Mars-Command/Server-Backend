"""Internal capsule facts only: no upload, storage, scan or public API."""

import hashlib
import secrets
import sqlite3
from collections.abc import Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class CapsuleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    project: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=80)
    declared_source: str = Field(min_length=1, max_length=2048)


@dataclass(frozen=True)
class ReleaseCapsule:
    release_id: str
    uploader_id: str
    metadata: CapsuleMetadata
    created_at: str
    artifact_sha256: str | None


class CapsuleBlocked(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class CommunityStore(Protocol):
    def connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


def initialize_capsules(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS capsule_releases (
            release_id TEXT PRIMARY KEY,
            uploader_id TEXT NOT NULL REFERENCES users(id),
            project TEXT NOT NULL, version TEXT NOT NULL,
            declared_source TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS capsule_artifacts (
            sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^a-f0-9]*'),
            size INTEGER NOT NULL CHECK(size > 0),
            scan_state TEXT NOT NULL DEFAULT 'unscanned'
                CHECK(scan_state IN ('unscanned', 'pending', 'rejected', 'error')),
            availability TEXT NOT NULL DEFAULT 'unavailable'
                CHECK(availability = 'unavailable')
        );
        CREATE TABLE IF NOT EXISTS capsule_release_artifacts (
            release_id TEXT PRIMARY KEY REFERENCES capsule_releases(release_id),
            artifact_sha256 TEXT NOT NULL REFERENCES capsule_artifacts(sha256)
        );
        CREATE INDEX IF NOT EXISTS capsule_releases_uploader ON capsule_releases(uploader_id);
        CREATE TRIGGER IF NOT EXISTS capsule_releases_no_replace
            BEFORE INSERT ON capsule_releases
            WHEN EXISTS(SELECT 1 FROM capsule_releases WHERE release_id=NEW.release_id)
            BEGIN
                SELECT RAISE(ABORT, 'Capsule release facts are immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_releases_no_update
            BEFORE UPDATE ON capsule_releases BEGIN
                SELECT RAISE(ABORT, 'Capsule release facts are immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_releases_no_delete
            BEFORE DELETE ON capsule_releases BEGIN
                SELECT RAISE(ABORT, 'Capsule release facts are immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_binding_no_update
            BEFORE UPDATE ON capsule_release_artifacts BEGIN
                SELECT RAISE(ABORT, 'Capsule artifact binding is immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_binding_no_replace
            BEFORE INSERT ON capsule_release_artifacts
            WHEN EXISTS(SELECT 1 FROM capsule_release_artifacts WHERE release_id=NEW.release_id)
            BEGIN
                SELECT RAISE(ABORT, 'Capsule artifact binding is immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_binding_no_delete
            BEFORE DELETE ON capsule_release_artifacts BEGIN
                SELECT RAISE(ABORT, 'Capsule artifact binding is immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_artifact_identity_no_update
            BEFORE UPDATE OF sha256, size ON capsule_artifacts BEGIN
                SELECT RAISE(ABORT, 'Artifact identity is immutable');
            END;
        CREATE TRIGGER IF NOT EXISTS capsule_artifacts_no_replace
            BEFORE INSERT ON capsule_artifacts
            WHEN EXISTS(SELECT 1 FROM capsule_artifacts WHERE sha256=NEW.sha256)
            BEGIN
                SELECT RAISE(ABORT, 'Artifact identity is immutable');
            END;
    """)


class CapsuleRegistry:
    """Trusted backend callers only; authentication must precede these operations."""

    def __init__(self, store: CommunityStore):
        self.store = store

    @staticmethod
    def _owned(db, release_id: str, uploader_id: str):
        row = db.execute(
            "SELECT r.*, b.artifact_sha256 FROM capsule_releases r "
            "LEFT JOIN capsule_release_artifacts b USING(release_id) "
            "WHERE r.release_id=? AND r.uploader_id=?",
            (release_id, uploader_id),
        ).fetchone()
        if row is None:
            raise CapsuleBlocked("release_not_found")
        return row

    @staticmethod
    def _capsule(row) -> ReleaseCapsule:
        return ReleaseCapsule(
            release_id=row["release_id"],
            uploader_id=row["uploader_id"],
            metadata=CapsuleMetadata(
                project=row["project"], version=row["version"],
                declared_source=row["declared_source"],
            ),
            created_at=row["created_at"],
            artifact_sha256=row["artifact_sha256"],
        )

    def reserve(self, uploader_id: str, metadata: CapsuleMetadata) -> ReleaseCapsule:
        metadata = CapsuleMetadata.model_validate(metadata.model_dump())
        release_id = secrets.token_hex(16)
        with self.store.connect() as db:
            db.execute(
                "INSERT INTO capsule_releases VALUES (?, ?, ?, ?, ?, ?)",
                (
                    release_id, uploader_id, metadata.project, metadata.version,
                    metadata.declared_source, datetime.now(timezone.utc).isoformat(),
                ),
            )
            return self._capsule(self._owned(db, release_id, uploader_id))

    def get(self, release_id: str, uploader_id: str) -> ReleaseCapsule:
        with self.store.connect() as db:
            return self._capsule(self._owned(db, release_id, uploader_id))

    def observe(
        self, release_id: str, uploader_id: str, chunks: Iterable[bytes], *,
        max_bytes: int,
    ) -> ReleaseCapsule:
        """Hash backend-observed bytes, not a supplied checksum. Does not store bytes."""
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("A positive byte bound is required")
        with self.store.connect() as db:
            row = self._owned(db, release_id, uploader_id)
            if row["artifact_sha256"] is not None:
                raise CapsuleBlocked("release_already_bound")
        checksum = hashlib.sha256()
        size = 0
        for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise ValueError("Observation requires bytes")
            size += len(chunk)
            if size > max_bytes:
                raise CapsuleBlocked("artifact_too_large")
            checksum.update(chunk)
        if size == 0:
            raise CapsuleBlocked("artifact_empty")
        sha256 = checksum.hexdigest()
        with self.store.connect() as db:
            row = self._owned(db, release_id, uploader_id)
            if row["artifact_sha256"] is not None:
                raise CapsuleBlocked("release_already_bound")
            # Deduplication never resets an existing artifact's scan/availability state.
            existing = db.execute(
                "SELECT size FROM capsule_artifacts WHERE sha256=?", (sha256,)
            ).fetchone()
            if existing is None:
                db.execute(
                    "INSERT INTO capsule_artifacts(sha256, size) VALUES (?, ?)",
                    (sha256, size),
                )
            elif existing["size"] != size:
                raise CapsuleBlocked("artifact_identity_conflict")
            db.execute(
                "INSERT INTO capsule_release_artifacts VALUES (?, ?)",
                (release_id, sha256),
            )
            return self._capsule(self._owned(db, release_id, uploader_id))

    def _require_artifact(self, release_id: str, uploader_id: str) -> None:
        with self.store.connect() as db:
            row = self._owned(db, release_id, uploader_id)
            if row["artifact_sha256"] is None:
                raise CapsuleBlocked("artifact_pending")
            artifact = db.execute(
                "SELECT * FROM capsule_artifacts WHERE sha256=?",
                (row["artifact_sha256"],),
            ).fetchone()
            if artifact is None or artifact["availability"] != "available":
                raise CapsuleBlocked("artifact_unavailable")
            if artifact["scan_state"] != "clean":
                raise CapsuleBlocked("artifact_not_clean")
        # Even forged/future positive flags cannot enable delivery in this increment.
        raise CapsuleBlocked("capsule_integration_not_configured")

    def require_publishable(self, release_id: str, uploader_id: str) -> None:
        self._require_artifact(release_id, uploader_id)

    def require_downloadable(self, release_id: str, uploader_id: str) -> None:
        self._require_artifact(release_id, uploader_id)
