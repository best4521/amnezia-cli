"""SQLite persistence layer.

The database is the single source of truth for *who* may connect. On every
mutating operation the manager rewrites the container's ``wg0.conf`` peer list
from the set of enabled, non-expired users recorded here.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .errors import UserExistsError, UserNotFoundError
from .logging_setup import get_logger
from .validators import is_expired, utcnow_iso

log = get_logger("db")

SCHEMA_VERSION = 3

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS users (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    username           TEXT    NOT NULL UNIQUE,
    private_key        TEXT    NOT NULL,
    public_key         TEXT    NOT NULL UNIQUE,
    preshared_key      TEXT    NOT NULL,
    address            TEXT    NOT NULL UNIQUE,
    enabled            INTEGER NOT NULL DEFAULT 1,
    expires_at         TEXT,
    note               TEXT,
    traffic_limit_bytes INTEGER,
    traffic_used_bytes  INTEGER NOT NULL DEFAULT 0,
    last_rx_bytes       INTEGER NOT NULL DEFAULT 0,
    last_tx_bytes       INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users (enabled);
CREATE INDEX IF NOT EXISTS idx_users_expires ON users (expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    action   TEXT NOT NULL,
    username TEXT,
    detail   TEXT,
    success  INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);

CREATE TABLE IF NOT EXISTS retired_keys (
    public_key TEXT PRIMARY KEY,
    username   TEXT,
    retired_at TEXT NOT NULL
);
"""


@dataclass
class User:
    id: int
    username: str
    private_key: str
    public_key: str
    preshared_key: str
    address: str
    enabled: bool
    expires_at: str | None
    note: str | None
    traffic_limit_bytes: int | None
    traffic_used_bytes: int
    last_rx_bytes: int
    last_tx_bytes: int
    created_at: str
    updated_at: str

    @property
    def expired(self) -> bool:
        return is_expired(self.expires_at)

    @property
    def quota_exceeded(self) -> bool:
        return self.traffic_limit_bytes is not None and self.traffic_used_bytes >= self.traffic_limit_bytes

    @property
    def active(self) -> bool:
        """Whether this user should currently be a live peer."""
        return self.enabled and not self.expired

    @property
    def status(self) -> str:
        if not self.enabled:
            return "disabled"
        if self.expired:
            return "expired"
        return "active"

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "User":
        return cls(
            id=row["id"],
            username=row["username"],
            private_key=row["private_key"],
            public_key=row["public_key"],
            preshared_key=row["preshared_key"],
            address=row["address"],
            enabled=bool(row["enabled"]),
            expires_at=row["expires_at"],
            note=row["note"],
            traffic_limit_bytes=row["traffic_limit_bytes"],
            traffic_used_bytes=row["traffic_used_bytes"],
            last_rx_bytes=row["last_rx_bytes"],
            last_tx_bytes=row["last_tx_bytes"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


class Database:
    """Thin wrapper around a single SQLite connection."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self.init_schema()

    # -- lifecycle ------------------------------------------------------
    def init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)
            row = self._conn.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
                )
                row_version = SCHEMA_VERSION
            else:
                row_version = row["version"]
            if row_version < SCHEMA_VERSION:
                self._migrate(row_version)
                self._conn.execute(
                    "UPDATE schema_version SET version = ?", (SCHEMA_VERSION,)
                )
        log.debug("schema ready at %s (v%d)", self.path, SCHEMA_VERSION)

    def _migrate(self, from_version: int) -> None:
        """Add columns introduced after ``from_version`` to a pre-existing DB."""
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(users)")}
        if from_version < 2:
            for column, ddl in (
                ("traffic_limit_bytes", "ALTER TABLE users ADD COLUMN traffic_limit_bytes INTEGER"),
                ("traffic_used_bytes", "ALTER TABLE users ADD COLUMN traffic_used_bytes INTEGER NOT NULL DEFAULT 0"),
                ("last_rx_bytes", "ALTER TABLE users ADD COLUMN last_rx_bytes INTEGER NOT NULL DEFAULT 0"),
                ("last_tx_bytes", "ALTER TABLE users ADD COLUMN last_tx_bytes INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in existing:
                    self._conn.execute(ddl)
            log.info("migrated database schema %d -> 2 (added traffic quota columns)", from_version)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- queries ------------------------------------------------------
    def get_user(self, username: str) -> User | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return User.from_row(row) if row else None

    def require_user(self, username: str) -> User:
        user = self.get_user(username)
        if user is None:
            raise UserNotFoundError(username)
        return user

    def list_users(self) -> list[User]:
        rows = self._conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        return [User.from_row(r) for r in rows]

    def active_users(self) -> list[User]:
        return [u for u in self.list_users() if u.active]

    def used_addresses(self) -> set[str]:
        rows = self._conn.execute("SELECT address FROM users").fetchall()
        return {r["address"] for r in rows}

    # -- mutations --------------------------------------------------
    def create_user(
        self,
        *,
        username: str,
        private_key: str,
        public_key: str,
        preshared_key: str,
        address: str,
        expires_at: str | None,
        note: str | None = None,
        traffic_limit_bytes: int | None = None,
    ) -> User:
        now = utcnow_iso()
        try:
            with self._conn:
                cur = self._conn.execute(
                    """
                    INSERT INTO users (username, private_key, public_key, preshared_key,
                                       address, enabled, expires_at, note,
                                       traffic_limit_bytes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (username, private_key, public_key, preshared_key, address,
                     expires_at, note, traffic_limit_bytes, now, now),
                )
        except sqlite3.IntegrityError as exc:
            # Which uniqueness constraint fired?
            if "username" in str(exc):
                raise UserExistsError(username) from exc
            raise
        return User.from_row(
            self._conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        )

    def set_enabled(self, username: str, enabled: bool) -> User:
        return self._update(username, {"enabled": 1 if enabled else 0})

    def set_expiration(self, username: str, expires_at: str | None) -> User:
        return self._update(username, {"expires_at": expires_at})

    def set_note(self, username: str, note: str | None) -> User:
        return self._update(username, {"note": note})

    def set_traffic_limit(self, username: str, limit_bytes: int | None) -> User:
        return self._update(username, {"traffic_limit_bytes": limit_bytes})

    def record_usage(self, username: str, *, used_bytes: int, rx_bytes: int, tx_bytes: int) -> User:
        """Persist an updated cumulative usage total and the raw counters seen this poll."""
        return self._update(username, {
            "traffic_used_bytes": used_bytes,
            "last_rx_bytes": rx_bytes,
            "last_tx_bytes": tx_bytes,
        })

    def rekey(self, username: str, *, private_key: str, public_key: str,
              preshared_key: str) -> User:
        old = self.require_user(username)
        self._retire_key(old.public_key, username)
        return self._update(username, {
            "private_key": private_key,
            "public_key": public_key,
            "preshared_key": preshared_key,
        })

    def delete_user(self, username: str) -> User:
        user = self.require_user(username)
        self._retire_key(user.public_key, username)
        with self._conn:
            self._conn.execute("DELETE FROM users WHERE username = ?", (username,))
        return user

    def _retire_key(self, public_key: str, username: str) -> None:
        """Remember a public key that used to belong to a managed peer.

        Without this, ``sync()``'s "preserve peers I don't manage" logic can't
        tell a peer this tool just removed (delete/rekey) apart from one a human
        added through the Amnezia app - and would keep re-adding the former
        forever as "unmanaged". Retired keys are looked up and dropped instead.
        """
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO retired_keys (public_key, username, retired_at) "
                "VALUES (?, ?, ?)",
                (public_key, username, utcnow_iso()),
            )

    def retired_keys(self) -> set[str]:
        rows = self._conn.execute("SELECT public_key FROM retired_keys").fetchall()
        return {r["public_key"] for r in rows}

    def _update(self, username: str, fields: dict[str, object]) -> User:
        self.require_user(username)
        fields = {**fields, "updated_at": utcnow_iso()}
        assignments = ", ".join(f"{k} = ?" for k in fields)
        with self._conn:
            self._conn.execute(
                f"UPDATE users SET {assignments} WHERE username = ?",
                (*fields.values(), username),
            )
        return self.require_user(username)

    # -- audit ------------------------------------------------------
    def audit(self, action: str, *, username: str | None = None,
              detail: str | None = None, success: bool = True) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO audit_log (ts, action, username, detail, success) "
                "VALUES (?, ?, ?, ?, ?)",
                (utcnow_iso(), action, username, detail, 1 if success else 0),
            )

    def recent_audit(self, limit: int = 20) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def iter_active(users: Iterable[User]) -> Iterator[User]:
    for user in users:
        if user.active:
            yield user
