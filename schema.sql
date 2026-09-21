-- Amnezia AWG2 Management CLI - SQLite schema
-- Applied automatically on first run by amnezia_manager.database.Database.init_schema()

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT    NOT NULL UNIQUE,
    private_key         TEXT    NOT NULL,          -- client WireGuard private key (base64)
    public_key          TEXT    NOT NULL UNIQUE,   -- client WireGuard public key  (base64)
    preshared_key       TEXT    NOT NULL,          -- per-peer PSK (base64)
    address             TEXT    NOT NULL UNIQUE,   -- assigned tunnel IP, e.g. 10.8.1.7/32
    enabled             INTEGER NOT NULL DEFAULT 1,-- 1 = active peer, 0 = disabled
    expires_at          TEXT,                      -- ISO-8601 UTC timestamp or NULL (never)
    note                TEXT,
    traffic_limit_bytes INTEGER,                   -- lifetime cap in bytes, or NULL (unlimited)
    traffic_used_bytes  INTEGER NOT NULL DEFAULT 0, -- cumulative rx+tx, updated by enforce-quotas
    last_rx_bytes       INTEGER NOT NULL DEFAULT 0, -- raw `wg show transfer` counter at last poll
    last_tx_bytes       INTEGER NOT NULL DEFAULT 0, -- (lets us compute deltas across interface reloads)
    created_at          TEXT    NOT NULL,          -- ISO-8601 UTC
    updated_at          TEXT    NOT NULL           -- ISO-8601 UTC
);

CREATE INDEX IF NOT EXISTS idx_users_enabled ON users (enabled);
CREATE INDEX IF NOT EXISTS idx_users_expires ON users (expires_at);

-- Append-only audit trail of every mutating CLI action.
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,   -- ISO-8601 UTC
    action     TEXT NOT NULL,   -- create-user | disable-user | ...
    username   TEXT,
    detail     TEXT,
    success    INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);
