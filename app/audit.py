"""Audit event recording and hash-chain integrity verification.

Every write to the audit trail goes through :func:`record_event`. Each record
stores the SHA-256 hash of its own content plus the previous record's hash, so
editing or removing a stored row breaks the chain and is detected by
:func:`verify_chain`. SQLite triggers additionally refuse UPDATE and DELETE.
This is a local tamper-evidence control, not a guarantee of immutability: a
person with direct file access could rebuild the whole chain.
"""
import hashlib
import json
import re
import sqlite3
import threading

from .utils import event_uid, now_iso

WRITE_LOCK = threading.RLock()
GENESIS_HASH = "0" * 64

ACTIONS = {
    "auth.login": ("authentication", "Login"),
    "auth.logout": ("authentication", "Logout"),
    "file.create": ("file", "File creation"),
    "file.modify": ("file", "File modification"),
    "file.delete": ("file", "File deletion"),
    "admin.access": ("user_management", "User management"),
    "user.create": ("user_management", "User created"),
    "user.update": ("user_management", "User updated"),
    "user.activate": ("user_management", "User activated"),
    "user.deactivate": ("user_management", "User deactivated"),
    "user.password_reset": ("user_management", "Password reset"),
    "user.role_change": ("permission", "Role change"),
    "permission.change": ("permission", "Permission change"),
    "access.denied": ("authorization", "Access denied"),
    "alert.created": ("alert", "Alert created"),
    "alert.acknowledge": ("alert", "Alert acknowledged"),
    "alert.resolve": ("alert", "Alert resolved"),
    "alert.note": ("alert", "Investigation note"),
    "rule.update": ("configuration", "Rule settings changed"),
    "report.export": ("report", "Report exported"),
    "integrity.verify": ("configuration", "Integrity verification"),
}

# Groups used by filters and the distribution chart.
ACTION_GROUPS = {
    "login": ("Login", ["auth.login"]),
    "logout": ("Logout", ["auth.logout"]),
    "file_create": ("File creation", ["file.create"]),
    "file_modify": ("File modification", ["file.modify"]),
    "file_delete": ("File deletion", ["file.delete"]),
    "user_management": ("User management", ["admin.access", "user.create", "user.update", "user.activate",
                                             "user.deactivate", "user.password_reset"]),
    "permission": ("Permission changes", ["user.role_change", "permission.change"]),
    "alert": ("Alert handling", ["alert.created", "alert.acknowledge", "alert.resolve", "alert.note"]),
}
GROUPED_ACTIONS = {code for _, codes in ACTION_GROUPS.values() for code in codes}

OUTCOMES = ("success", "failed", "denied")
SEVERITIES = ("info", "low", "medium", "high", "critical")
ORIGINS = ("live", "simulated", "seed")

_SECRET_KEY_PATTERN = re.compile(r"pass|token|secret|csrf|cookie|session|hash", re.IGNORECASE)


def action_group(action: str) -> str:
    for key, (_, codes) in ACTION_GROUPS.items():
        if action in codes:
            return key
    return "other"


def action_label(action: str) -> str:
    return ACTIONS.get(action, ("other", action))[1]


def default_severity(action: str, outcome: str) -> str:
    if action in ("user.role_change", "permission.change"):
        return "high"
    if action == "auth.login":
        return "medium" if outcome == "failed" else "info"
    if outcome == "denied":
        return "medium"
    if action == "file.delete":
        return "medium" if outcome == "success" else "low"
    if action in ("file.create", "file.modify", "user.create", "user.update", "user.activate"):
        return "low"
    if action in ("user.deactivate", "user.password_reset"):
        return "medium"
    if outcome == "failed":
        return "low"
    return "info"


def sanitize_metadata(metadata: dict | None) -> dict:
    """Drop anything that looks like a credential before it reaches the log."""
    clean = {}
    for key, value in (metadata or {}).items():
        key = str(key)[:64]
        if _SECRET_KEY_PATTERN.search(key):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[key] = value if not isinstance(value, str) else value[:500]
        elif isinstance(value, (list, tuple)):
            clean[key] = [str(v)[:200] for v in list(value)[:50]]
        else:
            clean[key] = str(value)[:500]
    return clean


def _compute_hash(fields: dict, prev_hash: str) -> str:
    payload = json.dumps(
        [fields["ts"], fields["actor"], fields["actor_role"], fields["action"], fields["category"],
         fields["resource"], fields["source_ip"], fields["http_method"], fields["route"], fields["outcome"],
         fields["severity"], fields["message"], fields["metadata"], fields["origin"], prev_hash],
        ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_event(conn: sqlite3.Connection, *, actor: str, action: str, outcome: str, message: str,
                 resource: str | None = None, source_ip: str | None = None, http_method: str | None = None,
                 route: str | None = None, metadata: dict | None = None, origin: str = "live",
                 actor_role: str | None = None, severity: str | None = None, ts: str | None = None,
                 evaluate: bool = True, commit: bool = True) -> dict:
    """Append one event to the audit trail and run the detection engine on it.

    Returns ``{"event": <event dict>, "evaluations": [...]}``.
    """
    from . import detection  # local import: detection records alert events through this module

    if outcome not in OUTCOMES:
        raise ValueError(f"invalid outcome {outcome!r}")
    if origin not in ORIGINS:
        raise ValueError(f"invalid origin {origin!r}")
    severity = severity or default_severity(action, outcome)
    if severity not in SEVERITIES:
        raise ValueError(f"invalid severity {severity!r}")

    fields = {
        "ts": ts or now_iso(),
        "actor": (actor or "anonymous")[:64],
        "actor_role": actor_role,
        "action": action,
        "category": ACTIONS.get(action, ("other", action))[0],
        "resource": (resource or None) and str(resource)[:300],
        "source_ip": (source_ip or None) and str(source_ip)[:64],
        "http_method": http_method,
        "route": (route or None) and str(route)[:200],
        "outcome": outcome,
        "severity": severity,
        "message": str(message)[:500],
        "metadata": json.dumps(sanitize_metadata(metadata), ensure_ascii=False, sort_keys=True),
        "origin": origin,
    }
    with WRITE_LOCK:
        row = conn.execute("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row["hash"] if row else GENESIS_HASH
        fields["prev_hash"] = prev_hash
        fields["hash"] = _compute_hash(fields, prev_hash)
        cursor = conn.execute(
            """INSERT INTO audit_events (ts, actor, actor_role, action, category, resource, source_ip,
                   http_method, route, outcome, severity, message, metadata, origin, prev_hash, hash)
               VALUES (:ts, :actor, :actor_role, :action, :category, :resource, :source_ip, :http_method,
                   :route, :outcome, :severity, :message, :metadata, :origin, :prev_hash, :hash)""",
            fields,
        )
        event = dict(fields, id=cursor.lastrowid)
        evaluations = detection.evaluate(conn, event) if evaluate else []
        if commit:
            conn.commit()
    return {"event": event_to_dict(event), "evaluations": evaluations}


def event_to_dict(row) -> dict:
    data = dict(row)
    try:
        metadata = json.loads(data.get("metadata") or "{}")
    except (TypeError, ValueError):
        metadata = {}
    return {
        "id": data["id"],
        "uid": event_uid(data["id"]),
        "ts": data["ts"],
        "actor": data["actor"],
        "actor_role": data.get("actor_role"),
        "action": data["action"],
        "action_label": action_label(data["action"]),
        "category": data["category"],
        "resource": data.get("resource"),
        "source_ip": data.get("source_ip"),
        "http_method": data.get("http_method"),
        "route": data.get("route"),
        "outcome": data["outcome"],
        "severity": data["severity"],
        "message": data["message"],
        "metadata": metadata,
        "origin": data["origin"],
        "hash": data.get("hash"),
        "prev_hash": data.get("prev_hash"),
    }


def verify_chain(conn: sqlite3.Connection) -> dict:
    """Recompute every hash in order and report the first break, if any."""
    prev_hash = GENESIS_HASH
    checked = 0
    for row in conn.execute("SELECT * FROM audit_events ORDER BY id"):
        fields = dict(row)
        if fields["prev_hash"] != prev_hash:
            return {"ok": False, "checked": checked, "broken_at": event_uid(fields["id"]),
                    "reason": "Link to the previous record does not match (a record may have been removed or reordered)."}
        if _compute_hash(fields, prev_hash) != fields["hash"]:
            return {"ok": False, "checked": checked, "broken_at": event_uid(fields["id"]),
                    "reason": "Stored content does not match its hash (the record may have been edited)."}
        prev_hash = fields["hash"]
        checked += 1
    return {"ok": True, "checked": checked, "broken_at": None, "last_hash": prev_hash, "reason": None}
