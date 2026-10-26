"""Rule-based detection engine.

Each rule is a deterministic threshold over a sliding time window, evaluated
right after an audit event is written. No machine learning or external threat
intelligence is involved. A match opens an alert, or attaches the new evidence
to an unresolved alert for the same rule and subject if one is still active.
"""
import sqlite3
from datetime import timedelta

from . import audit
from .utils import ApiError, alert_uid, event_uid, iso, now_iso, parse_iso, utcnow

RULE_DEFAULTS = [
    ("R-01", "Repeated failed logins",
     "Failed sign-ins for the same account within the time window.", 5, 10, "high", "account"),
    ("R-02", "Multiple accounts from one IP",
     "Distinct accounts with failed sign-ins from one source IP within the time window.", 3, 15, "high", "source_ip"),
    ("R-03", "Repeated authorization denials",
     "Operations denied by the authorization layer for the same account.", 4, 30, "medium", "account"),
    ("R-04", "Excessive file deletions",
     "File deletions by one account within the time window.", 10, 5, "high", "account"),
    ("R-05", "Sensitive administrative changes",
     "Any role or permission change, whether it was allowed or denied.", 1, 60, "high", "account"),
]

TITLES = {
    "R-01": "Repeated authentication failures detected",
    "R-02": "Multiple accounts targeted from one source IP",
    "R-03": "Repeated authorization denials",
    "R-04": "Excessive file deletions",
    "R-05": "Sensitive administrative change",
}

UNITS = {"R-01": "failed sign-ins", "R-02": "accounts", "R-03": "denials", "R-04": "deletions", "R-05": "changes"}


def ensure_rules(conn: sqlite3.Connection) -> None:
    for rule_id, name, desc, threshold, window, severity, scope in RULE_DEFAULTS:
        conn.execute(
            """INSERT OR IGNORE INTO rules (id, name, description, enabled, threshold, window_minutes, severity, scope)
               VALUES (?, ?, ?, 1, ?, ?, ?, ?)""",
            (rule_id, name, desc, threshold, window, severity, scope),
        )
    conn.commit()


def load_rules(conn: sqlite3.Connection) -> dict:
    return {row["id"]: dict(row) for row in conn.execute("SELECT * FROM rules ORDER BY id")}


def _applies(rule_id: str, event: dict):
    """Return the grouping key when the rule applies to the event, else None."""
    action, outcome = event["action"], event["outcome"]
    if rule_id == "R-01" and action == "auth.login" and outcome == "failed":
        return (event["actor"] or "").lower()
    if rule_id == "R-02" and action == "auth.login" and outcome == "failed" and event.get("source_ip"):
        return event["source_ip"]
    if rule_id == "R-03" and outcome == "denied":
        return (event["actor"] or "").lower()
    if rule_id == "R-04" and action == "file.delete" and outcome == "success":
        return (event["actor"] or "").lower()
    if rule_id == "R-05" and action in ("user.role_change", "permission.change"):
        return (event["actor"] or "").lower()
    return None


def _collect(conn, rule_id: str, event: dict, start: str):
    """Return (count, evidence_ids, accounts) for the rule's window ending at this event."""
    base = "ts >= ? AND ts <= ? AND id <= ?"
    window = (start, event["ts"], event["id"])
    if rule_id == "R-01":
        rows = conn.execute(
            f"SELECT id FROM audit_events WHERE action = 'auth.login' AND outcome = 'failed' "
            f"AND actor = ? COLLATE NOCASE AND {base} ORDER BY id", (event["actor"], *window)).fetchall()
        return len(rows), [r["id"] for r in rows], [event["actor"]]
    if rule_id == "R-02":
        rows = conn.execute(
            f"SELECT id, actor FROM audit_events WHERE action = 'auth.login' AND outcome = 'failed' "
            f"AND source_ip = ? AND {base} ORDER BY id", (event["source_ip"], *window)).fetchall()
        accounts = sorted({r["actor"].lower() for r in rows})
        return len(accounts), [r["id"] for r in rows], accounts
    if rule_id == "R-03":
        rows = conn.execute(
            f"SELECT id FROM audit_events WHERE outcome = 'denied' AND actor = ? COLLATE NOCASE AND {base} ORDER BY id",
            (event["actor"], *window)).fetchall()
        return len(rows), [r["id"] for r in rows], [event["actor"]]
    if rule_id == "R-04":
        rows = conn.execute(
            f"SELECT id FROM audit_events WHERE action = 'file.delete' AND outcome = 'success' "
            f"AND actor = ? COLLATE NOCASE AND {base} ORDER BY id", (event["actor"], *window)).fetchall()
        return len(rows), [r["id"] for r in rows], [event["actor"]]
    # R-05: every sensitive change counts on its own.
    return 1, [event["id"]], [event["actor"]]


def _explain(rule: dict, event: dict, count: int, accounts: list) -> str:
    rid, window, threshold = rule["id"], rule["window_minutes"], rule["threshold"]
    if rid == "R-01":
        return (f"{count} failed sign-in attempts for account {event['actor']} were recorded within "
                f"{window} minutes (threshold {threshold}). The detection rule opened this alert for investigation.")
    if rid == "R-02":
        listed = ", ".join(accounts[:6]) + ("…" if len(accounts) > 6 else "")
        return (f"Failed sign-ins against {count} different accounts ({listed}) were recorded from "
                f"{event['source_ip']} within {window} minutes (threshold {threshold} accounts). "
                f"Suspicious activity requires investigation.")
    if rid == "R-03":
        return (f"{count} operations by {event['actor']} were denied by the authorization layer within "
                f"{window} minutes (threshold {threshold}). Potential unauthorized activity.")
    if rid == "R-04":
        return (f"{count} file deletions by {event['actor']} were recorded within {window} minutes "
                f"(threshold {threshold}). Review whether this destructive activity was expected.")
    state = "denied" if event["outcome"] == "denied" else "completed"
    return (f"A {state} role or permission change ({event.get('resource') or 'unspecified'}) was recorded for "
            f"{event['actor']}. Sensitive administrative changes always require review.")


def _raise_alert(conn, rule: dict, event: dict, key: str, start: str, evidence: list, count: int, accounts: list):
    explanation = _explain(rule, event, count, accounts)
    existing = conn.execute(
        """SELECT id FROM alerts WHERE rule_id = ? AND group_key = ? AND status != 'resolved'
           AND updated_at >= ? ORDER BY id DESC LIMIT 1""",
        (rule["id"], key, start)).fetchone()
    if existing:
        alert_id = existing["id"]
        conn.executemany("INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                         [(alert_id, eid) for eid in evidence])
        conn.execute("UPDATE alerts SET updated_at = ?, explanation = ? WHERE id = ?",
                     (event["ts"], explanation, alert_id))
        return alert_uid(alert_id), False

    severity = rule["severity"]
    if rule["id"] == "R-05":
        severity = "high" if event["outcome"] == "denied" or "admin" in (event.get("resource") or "") else "medium"
    cursor = conn.execute(
        """INSERT INTO alerts (rule_id, title, severity, status, group_key, actor, source_ip, explanation,
               threshold, window_minutes, created_at, updated_at, trigger_event_id)
           VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (rule["id"], TITLES[rule["id"]], severity, key,
         None if rule["id"] == "R-02" else event["actor"], event.get("source_ip"), explanation,
         rule["threshold"], rule["window_minutes"], event["ts"], event["ts"], event["id"]))
    alert_id = cursor.lastrowid
    conn.executemany("INSERT OR IGNORE INTO alert_events (alert_id, event_id, is_trigger) VALUES (?, ?, ?)",
                     [(alert_id, eid, 1 if eid == event["id"] else 0) for eid in evidence])
    uid = alert_uid(alert_id)
    audit.record_event(
        conn, actor="detection-engine", actor_role="system", action="alert.created", outcome="success",
        resource=uid, message=f"{rule['id']} matched — {TITLES[rule['id']]} ({uid}).",
        metadata={"rule": rule["id"], "threshold": rule["threshold"], "window_minutes": rule["window_minutes"],
                  "matched_count": count, "trigger_event": event_uid(event["id"])},
        origin="seed" if event["origin"] == "seed" else "live", severity=severity, ts=event["ts"],
        evaluate=False, commit=False)
    return uid, True


def evaluate(conn: sqlite3.Connection, event: dict) -> list:
    """Evaluate every applicable rule against a freshly inserted event."""
    results = []
    for rule in load_rules(conn).values():
        key = _applies(rule["id"], event)
        if key is None:
            continue
        result = {"rule_id": rule["id"], "rule_name": rule["name"], "enabled": bool(rule["enabled"]),
                  "threshold": rule["threshold"], "window_minutes": rule["window_minutes"],
                  "unit": UNITS[rule["id"]], "count": None, "matched": False, "alert_uid": None, "alert_new": False}
        if rule["enabled"]:
            start = iso(parse_iso(event["ts"]) - timedelta(minutes=rule["window_minutes"]))
            count, evidence, accounts = _collect(conn, rule["id"], event, start)
            result["count"] = count
            if count >= rule["threshold"]:
                uid, new = _raise_alert(conn, rule, event, key, start, evidence, count, accounts)
                result.update(matched=True, alert_uid=uid, alert_new=new)
        results.append(result)
    return results


def rule_overview(conn: sqlite3.Connection) -> list:
    since = iso(utcnow() - timedelta(hours=24))
    match_sql = {
        "R-01": "action = 'auth.login' AND outcome = 'failed'",
        "R-02": "action = 'auth.login' AND outcome = 'failed' AND source_ip IS NOT NULL",
        "R-03": "outcome = 'denied'",
        "R-04": "action = 'file.delete' AND outcome = 'success'",
        "R-05": "action IN ('user.role_change', 'permission.change')",
    }
    rules = []
    for rule in load_rules(conn).values():
        matches = conn.execute(f"SELECT COUNT(*) FROM audit_events WHERE {match_sql[rule['id']]} AND ts >= ?",
                               (since,)).fetchone()[0]
        stats = conn.execute(
            """SELECT COUNT(*) AS total, SUM(status != 'resolved') AS unresolved, MAX(created_at) AS last
               FROM alerts WHERE rule_id = ?""", (rule["id"],)).fetchone()
        rules.append(dict(rule, enabled=bool(rule["enabled"]), unit=UNITS[rule["id"]], matches_24h=matches,
                          alerts_total=stats["total"] or 0, alerts_unresolved=stats["unresolved"] or 0,
                          last_triggered=stats["last"]))
    return rules


def update_rule(conn: sqlite3.Connection, rule_id: str, data: dict, user: dict, request_info: dict) -> dict:
    rules = load_rules(conn)
    rule = rules.get(rule_id)
    if not rule:
        raise ApiError("Rule not found.", 404)
    changes = {}
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            raise ApiError("'enabled' must be true or false.", field="enabled")
        changes["enabled"] = int(data["enabled"])
    for field, low, high in (("threshold", 1, 100), ("window_minutes", 1, 1440)):
        if field in data:
            value = data[field]
            if isinstance(value, bool) or not isinstance(value, int) or not (low <= value <= high):
                raise ApiError(f"'{field}' must be a whole number between {low} and {high}.", field=field)
            changes[field] = value
    if rule_id == "R-05" and changes.get("threshold", 1) != 1:
        raise ApiError("R-05 always alerts on a single change; its threshold is fixed at 1.", field="threshold")
    if not changes:
        raise ApiError("No supported settings were provided.")
    before = {k: rule[k] for k in changes}
    with audit.WRITE_LOCK:
        conn.execute(
            f"UPDATE rules SET {', '.join(f'{k} = ?' for k in changes)}, updated_at = ?, updated_by = ? WHERE id = ?",
            (*changes.values(), now_iso(), user["username"], rule_id))
        audit.record_event(
            conn, actor=user["username"], actor_role=user["role"], action="rule.update", outcome="success",
            resource=rule_id, message=f"Detection rule {rule_id} settings changed by {user['username']}.",
            metadata={"before": str(before), "after": str(changes)}, **request_info)
    return next(r for r in rule_overview(conn) if r["id"] == rule_id)
