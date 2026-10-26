"""SQLite connection handling and schema."""
import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name     TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    password_hash TEXT NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    actor_role  TEXT,
    action      TEXT NOT NULL,
    category    TEXT NOT NULL,
    resource    TEXT,
    source_ip   TEXT,
    http_method TEXT,
    route       TEXT,
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failed', 'denied')),
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    message     TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    origin      TEXT NOT NULL CHECK (origin IN ('live', 'simulated', 'seed')),
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_ts      ON audit_events (ts);
CREATE INDEX IF NOT EXISTS ix_events_actor   ON audit_events (actor, ts);
CREATE INDEX IF NOT EXISTS ix_events_ip      ON audit_events (source_ip, ts);
CREATE INDEX IF NOT EXISTS ix_events_action  ON audit_events (action, outcome, ts);

-- The audit trail is append-only: the database itself refuses edits and deletions.
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TABLE IF NOT EXISTS rules (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    threshold      INTEGER NOT NULL,
    window_minutes INTEGER NOT NULL,
    severity       TEXT NOT NULL,
    scope          TEXT NOT NULL,
    updated_at     TEXT,
    updated_by     TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id          TEXT NOT NULL REFERENCES rules (id),
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    group_key        TEXT NOT NULL,
    actor            TEXT,
    source_ip        TEXT,
    explanation      TEXT NOT NULL,
    threshold        INTEGER NOT NULL,
    window_minutes   INTEGER NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    trigger_event_id INTEGER REFERENCES audit_events (id),
    acknowledged_by  TEXT,
    acknowledged_at  TEXT,
    resolved_by      TEXT,
    resolved_at      TEXT,
    resolution       TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts (status, created_at);
CREATE INDEX IF NOT EXISTS ix_alerts_group  ON alerts (rule_id, group_key, status);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id   INTEGER NOT NULL REFERENCES alerts (id),
    event_id   INTEGER NOT NULL REFERENCES audit_events (id),
    is_trigger INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX IF NOT EXISTS ix_alert_events_event ON alert_events (event_id);

CREATE TABLE IF NOT EXISTS alert_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   INTEGER NOT NULL REFERENCES alerts (id),
    author     TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def is_seeded(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
