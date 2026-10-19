"""Bound Minecraft arrival challenges; never issue website or desktop credentials."""

from __future__ import annotations

import json
import secrets
import sqlite3
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field

if __package__:
    from .auth_helpers import digest, fail
else:
    from auth_helpers import digest, fail

if TYPE_CHECKING:
    from .community import Store

UUID_PATTERN = r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
CHALLENGE_TTL = 600
POLL_INTERVAL = 5


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)


class ArrivalInput(Input):
    minecraftUuid: str = Field(pattern=UUID_PATTERN)
    playerName: str = Field(pattern=r"^[A-Za-z0-9_]{1,16}$")


class ChallengeInput(Input):
    minecraftUuid: str = Field(pattern=UUID_PATTERN)
    deviceCode: str = Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class ConfirmInput(ChallengeInput):
    expectedAccountName: str = Field(min_length=1, max_length=100)


class PlayerContext(BaseModel):
    minecraftUuid: str
    callSign: str = Field(pattern=r"^[0-9]{4}$")
    confirmed: bool
    accountName: str | None
    roles: list[str] = Field(max_length=64)


class ArrivalResponse(BaseModel):
    status: Literal["pending", "confirmed"]
    context: PlayerContext
    requestId: str | None = None
    deviceCode: str | None = None
    verificationUri: str | None = None
    expiresIn: int | None = None
    pollInterval: int | None = None


class ChallengeResponse(BaseModel):
    status: Literal["pending", "approved", "expired", "denied"]
    accountName: str | None = None


class RequestDetails(BaseModel):
    kind: Literal["desktop", "minecraft"]
    status: Literal["pending", "approved"]
    callSign: str | None = None
    playerName: str | None = None


def initialize_minecraft(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS minecraft_players (
            minecraft_uuid TEXT PRIMARY KEY,
            callsign TEXT NOT NULL UNIQUE CHECK(length(callsign)=4 AND callsign NOT GLOB '*[^0-9]*'),
            player_name TEXT NOT NULL,
            user_id TEXT UNIQUE REFERENCES users(id),
            created_at INTEGER NOT NULL,
            confirmed_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS minecraft_requests (
            request_id TEXT PRIMARY KEY REFERENCES devices(request_id) ON DELETE CASCADE,
            minecraft_uuid TEXT NOT NULL REFERENCES minecraft_players(minecraft_uuid)
        );
        CREATE INDEX IF NOT EXISTS minecraft_requests_player ON minecraft_requests(minecraft_uuid);
    """)


class MinecraftWorkflow:
    def __init__(self, store: Store, website_url: str):
        self.store = store
        self.website_url = website_url

    @staticmethod
    def _context(db: sqlite3.Connection, player: sqlite3.Row) -> dict:
        user = db.execute(
            "SELECT username, roles FROM users WHERE id=?", (player["user_id"],)
        ).fetchone()
        if player["user_id"] is not None and user is None:
            raise fail(
                503, "invalid_player_context", "Stored player account is unavailable"
            )
        try:
            roles = json.loads(user["roles"]) if user else []
        except json.JSONDecodeError:
            raise fail(
                503,
                "invalid_player_context",
                "Stored player roles require operator attention",
            )
        if (
            not isinstance(roles, list)
            or len(roles) > 64
            or any(
                not isinstance(role, str)
                or len(role) > 64
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in role
                )
                for role in roles
            )
        ):
            raise fail(
                503,
                "invalid_player_context",
                "Stored player context requires operator attention",
            )
        return {
            "minecraftUuid": player["minecraft_uuid"],
            "callSign": player["callsign"],
            "confirmed": player["user_id"] is not None,
            "accountName": user["username"] if user else None,
            "roles": roles,
        }

    def context(self, minecraft_uuid: str) -> dict:
        with self.store.connect() as db:
            player = db.execute(
                "SELECT * FROM minecraft_players WHERE minecraft_uuid=?",
                (minecraft_uuid,),
            ).fetchone()
            if not player:
                raise fail(
                    404, "player_not_registered", "Player has not registered arrival"
                )
            return self._context(db, player)

    def start(self, minecraft_uuid: str, name: str, now: int) -> dict:
        with self.store.connect() as db:
            player = db.execute(
                "SELECT * FROM minecraft_players WHERE minecraft_uuid=?",
                (minecraft_uuid,),
            ).fetchone()
            if not player:
                used = {
                    row[0]
                    for row in db.execute("SELECT callsign FROM minecraft_players")
                }
                start = secrets.randbelow(10000)
                callsign = next(
                    (
                        f"{(start + offset) % 10000:04d}"
                        for offset in range(10000)
                        if f"{(start + offset) % 10000:04d}" not in used
                    ),
                    None,
                )
                if callsign is None:
                    raise fail(
                        503,
                        "callsign_capacity",
                        "All 10,000 permanent callsigns are reserved",
                    )
                db.execute(
                    "INSERT INTO minecraft_players VALUES (?, ?, ?, NULL, ?, NULL)",
                    (minecraft_uuid, callsign, name, now),
                )
            else:
                db.execute(
                    "UPDATE minecraft_players SET player_name=? WHERE minecraft_uuid=?",
                    (name, minecraft_uuid),
                )
            player = db.execute(
                "SELECT * FROM minecraft_players WHERE minecraft_uuid=?",
                (minecraft_uuid,),
            ).fetchone()
            context = self._context(db, player)
            if context["confirmed"]:
                return {"status": "confirmed", "context": context}
            db.execute(
                "UPDATE devices SET status='consumed' WHERE request_id IN "
                "(SELECT request_id FROM minecraft_requests WHERE minecraft_uuid=?)",
                (minecraft_uuid,),
            )
            code, request_id = secrets.token_urlsafe(32), secrets.token_hex(16)
            db.execute(
                "INSERT INTO devices(secret_hash, request_id, expires, status) VALUES (?, ?, ?, 'pending')",
                (digest(code), request_id, now + CHALLENGE_TTL),
            )
            db.execute(
                "INSERT INTO minecraft_requests VALUES (?, ?)",
                (request_id, minecraft_uuid),
            )
            return {
                "status": "pending",
                "context": context,
                "deviceCode": code,
                "requestId": request_id,
                "verificationUri": self.website_url
                + "/auth/login?"
                + urlencode({"requestId": request_id}),
                "expiresIn": CHALLENGE_TTL,
                "pollInterval": POLL_INTERVAL,
            }

    @staticmethod
    def _challenge(
        db: sqlite3.Connection, minecraft_uuid: str, code: str
    ) -> sqlite3.Row | None:
        return db.execute(
            "SELECT devices.* FROM devices JOIN minecraft_requests USING(request_id) "
            "WHERE secret_hash=? AND minecraft_uuid=?",
            (digest(code), minecraft_uuid),
        ).fetchone()

    def poll(self, minecraft_uuid: str, code: str, now: int) -> dict:
        with self.store.connect() as db:
            row = self._challenge(db, minecraft_uuid, code)
            if not row or row["expires"] <= now:
                return {"status": "expired"}
            if row["status"] == "consumed":
                return {"status": "denied"}
            if row["last_poll"] and now - row["last_poll"] < POLL_INTERVAL:
                error = fail(429, "slow_down", "Respect the arrival poll interval")
                error.headers = {"Retry-After": str(POLL_INTERVAL)}
                raise error
            db.execute(
                "UPDATE devices SET last_poll=? WHERE secret_hash=?",
                (now, digest(code)),
            )
            result = {"status": row["status"]}
            if row["status"] == "approved":
                user = db.execute(
                    "SELECT username FROM users WHERE id=?", (row["user_id"],)
                ).fetchone()
                if not user:
                    raise fail(
                        409, "approval_unavailable", "Approved account is unavailable"
                    )
                result["accountName"] = user["username"]
            return result

    def approve(self, request_id: str, user_id: str, now: int) -> None:
        with self.store.connect() as db:
            row = db.execute(
                "SELECT devices.*, minecraft_uuid FROM devices "
                "JOIN minecraft_requests USING(request_id) WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if not row or row["expires"] <= now or row["status"] != "pending":
                raise fail(
                    409,
                    "invalid_request",
                    "Arrival request is unavailable, used or expired",
                )
            linked = db.execute(
                "SELECT minecraft_uuid FROM minecraft_players WHERE user_id=?",
                (user_id,),
            ).fetchone()
            if linked and linked["minecraft_uuid"] != row["minecraft_uuid"]:
                raise fail(
                    409,
                    "account_already_linked",
                    "This account is already linked to a different Minecraft player",
                )
            db.execute(
                "UPDATE devices SET status='approved', user_id=? WHERE request_id=?",
                (user_id, request_id),
            )

    def confirm(
        self, minecraft_uuid: str, code: str, account_name: str, now: int
    ) -> dict:
        with self.store.connect() as db:
            row = self._challenge(db, minecraft_uuid, code)
            if not row or row["expires"] <= now or row["status"] != "approved":
                raise fail(
                    409,
                    "invalid_request",
                    "Arrival approval is unavailable, used or expired",
                )
            user = db.execute(
                "SELECT username FROM users WHERE id=?", (row["user_id"],)
            ).fetchone()
            if not user or user["username"] != account_name:
                raise fail(
                    409,
                    "identity_changed",
                    "Review the approved account again before confirming",
                )
            linked = db.execute(
                "SELECT minecraft_uuid FROM minecraft_players WHERE user_id=?",
                (row["user_id"],),
            ).fetchone()
            if linked and linked["minecraft_uuid"] != minecraft_uuid:
                raise fail(
                    409,
                    "account_already_linked",
                    "Account is already linked to a different Minecraft player",
                )
            player = db.execute(
                "SELECT * FROM minecraft_players WHERE minecraft_uuid=?",
                (minecraft_uuid,),
            ).fetchone()
            if player["user_id"] is not None:
                raise fail(
                    409,
                    "already_confirmed",
                    "Player arrival has already been confirmed",
                )
            db.execute(
                "UPDATE minecraft_players SET user_id=?, confirmed_at=? WHERE minecraft_uuid=?",
                (row["user_id"], now, minecraft_uuid),
            )
            db.execute(
                "UPDATE devices SET status='consumed' WHERE request_id=?",
                (row["request_id"],),
            )
            player = db.execute(
                "SELECT * FROM minecraft_players WHERE minecraft_uuid=?",
                (minecraft_uuid,),
            ).fetchone()
            return self._context(db, player)
