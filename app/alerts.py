"""Alert listing, investigation detail and analyst actions."""
import sqlite3
from datetime import timedelta

from . import audit
from .audit import event_to_dict
from .utils import ApiError, alert_uid, iso, like_escape, now_iso, parse_iso, parse_uid

STATUSES = ("open", "acknowledged", "resolved")
SEVERITIES = ("low", "medium", "high", "critical")

RECOMMENDED = {
    "R-01": ["Check whether any sign-in from the same source IP succeeded after the failures.",
             "Confirm with the account owner whether these attempts were theirs.",
             "Review other accounts touched by the same source IP.",
             "Decide on a password reset or temporary lock and record it in the notes."],
    "R-02": ["List every account targeted from this IP and check each for a later successful sign-in.",
             "Confirm whether the source address belongs to a known workstation.",
             "Consider blocking the address at the network edge if the activity continues.",
             "Notify the owners of the targeted accounts."],
    "R-03": ["Review the denied operations and the resources they targeted.",
             "Confirm the user's expected role and permissions.",
             "Check whether a role misconfiguration explains the denials.",
             "Record the conclusion in the notes before resolving."],
    "R-04": ["Review the deleted resources and confirm they were expected to be removed.",
             "Check whether backups exist for the affected items.",
             "Ask the account owner about the bulk deletion.",
             "Record the conclusion in the notes before resolving."],
    "R-05": ["Confirm the change was requested and approved.",
             "Verify the actor was authorized to request it.",
             "If unexpected, revert the change and reset the account's credentials.",
             "Record the approval reference in the notes."],
}


def alert_to_dict(row, event_count: int | None = None) -> dict:
    data = dict(row)
    return {
        "id": data["id"], "uid": alert_uid(data["id"]), "rule_id": data["rule_id"], "title": data["title"],
        "severity": data["severity"], "status": data["status"], "actor": data["actor"],
        "source_ip": data["source_ip"], "group_key": data["group_key"], "explanation": data["explanation"],
        "threshold": data["threshold"], "window_minutes": data["window_minutes"],
        "created_at": data["created_at"], "updated_at": data["updated_at"],
        "acknowledged_by": data["acknowledged_by"], "acknowledged_at": data["acknowledged_at"],
        "resolved_by": data["resolved_by"], "resolved_at": data["resolved_at"], "resolution": data["resolution"],
        "event_count": event_count if event_count is not None else data.get("event_count"),
        "rule_name": data.get("rule_name"),
    }


def list_alerts(conn: sqlite3.Connection, args) -> dict:
    clauses, params = [], []
    status = (args.get("status") or "").lower()
    if status == "unresolved":
        clauses.append("a.status != 'resolved'")
    elif status:
        if status not in STATUSES:
            raise ApiError("Unknown status filter.", field="status")
        clauses.append("a.status = ?")
        params.append(status)
    severity = (args.get("severity") or "").lower()
    if severity:
        if severity not in SEVERITIES:
            raise ApiError("Unknown severity filter.", field="severity")
        clauses.append("a.severity = ?")
        params.append(severity)
    rule = (args.get("rule") or "").upper()
    if rule:
        clauses.append("a.rule_id = ?")
        params.append(rule)
    q = (args.get("q") or "").strip()[:100]
    if q:
        aid = parse_uid(q, "ALR") if q.upper().startswith("ALR-") else None
        if aid:
            clauses.append("a.id = ?")
            params.append(aid)
        else:
            pattern = f"%{like_escape(q)}%"
            clauses.append("(a.title LIKE ? ESCAPE '\\' OR a.actor LIKE ? ESCAPE '\\' "
                           "OR a.source_ip LIKE ? ESCAPE '\\' OR a.group_key LIKE ? ESCAPE '\\')")
            params += [pattern] * 4
    for name, op in (("start", ">="), ("end", "<=")):
        value = (args.get(name) or "").strip()
        if value:
            try:
                params.append(iso(parse_iso(value)))
            except ValueError:
                raise ApiError(f"Invalid {name} date.", field=name) from None
            clauses.append(f"a.created_at {op} ?")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"""SELECT a.*, r.name AS rule_name,
                   (SELECT COUNT(*) FROM alert_events ae WHERE ae.alert_id = a.id) AS event_count
            FROM alerts a JOIN rules r ON r.id = a.rule_id {where}
            ORDER BY (a.status = 'resolved'), a.created_at DESC, a.id DESC LIMIT 200""", params).fetchall()
    counts = dict(conn.execute(
        """SELECT COUNT(*) AS all_count, COALESCE(SUM(status != 'resolved'), 0) AS unresolved,
                  COALESCE(SUM(status = 'open'), 0) AS open, COALESCE(SUM(status = 'acknowledged'), 0) AS acknowledged,
                  COALESCE(SUM(status = 'resolved'), 0) AS resolved FROM alerts""").fetchone())
    return {"items": [alert_to_dict(r) for r in rows], "counts": counts}


def _get(conn, uid: str):
    alert_id = parse_uid(uid, "ALR")
    row = conn.execute(
        "SELECT a.*, r.name AS rule_name FROM alerts a JOIN rules r ON r.id = a.rule_id WHERE a.id = ?",
        (alert_id or 0,)).fetchone()
    if row is None:
        raise ApiError("Alert not found.", 404)
    return row


def alert_detail(conn: sqlite3.Connection, uid: str) -> dict:
    row = _get(conn, uid)
    alert = alert_to_dict(row)
    evidence_rows = conn.execute(
        """SELECT e.*, ae.is_trigger FROM alert_events ae JOIN audit_events e ON e.id = ae.event_id
           WHERE ae.alert_id = ? ORDER BY e.id""", (row["id"],)).fetchall()
    evidence = []
    for r in evidence_rows:
        item = event_to_dict(r)
        item["is_trigger"] = bool(r["is_trigger"])
        evidence.append(item)
    alert["event_count"] = len(evidence)

    ips, accounts, actions = {}, {}, {}
    for e in evidence:
        for bucket, key in ((ips, e["source_ip"]), (accounts, e["actor"])):
            if not key:
                continue
            item = bucket.setdefault(key, {"name": key, "events": 0, "failed": 0, "denied": 0, "success": 0})
            item["events"] += 1
            item[e["outcome"]] += 1
        actions[e["action_label"]] = actions.get(e["action_label"], 0) + 1

    timeline, findings = [], []
    if evidence:
        first, last = parse_iso(evidence[0]["ts"]), parse_iso(evidence[-1]["ts"])
        start, end = iso(first - timedelta(minutes=30)), iso(last + timedelta(minutes=30))
        evidence_ids = {e["id"] for e in evidence}
        actor_list, ip_list = list(accounts) or [""], list(ips) or [""]
        context = conn.execute(
            f"""SELECT * FROM audit_events WHERE ts >= ? AND ts <= ? AND action NOT LIKE 'alert.%'
                AND (actor COLLATE NOCASE IN ({','.join('?' * len(actor_list))})
                     OR source_ip IN ({','.join('?' * len(ip_list))}))
                ORDER BY id LIMIT 120""", (start, end, *actor_list, *ip_list)).fetchall()
        lifecycle = conn.execute("SELECT * FROM audit_events WHERE action LIKE 'alert.%' AND resource = ? ORDER BY id",
                                 (alert["uid"],)).fetchall()
        merged = {r["id"]: r for r in list(context) + list(lifecycle)}
        trigger_id = row["trigger_event_id"]
        for event_id in sorted(set(merged) | evidence_ids):
            source = merged.get(event_id) or next(r for r in evidence_rows if r["id"] == event_id)
            item = event_to_dict(source)
            item["is_evidence"] = event_id in evidence_ids
            item["is_trigger"] = event_id == trigger_id
            item["phase"] = ("lifecycle" if item["action"].startswith("alert.")
                             else "evidence" if item["is_evidence"] else
                             "before" if item["ts"] < evidence[0]["ts"] else "after")
            timeline.append(item)

        if row["rule_id"] in ("R-01", "R-02") and ips:
            ok_after = conn.execute(
                f"""SELECT COUNT(*) FROM audit_events WHERE action = 'auth.login' AND outcome = 'success'
                    AND source_ip IN ({','.join('?' * len(ips))}) AND ts >= ?""",
                (*ips, evidence[0]["ts"])).fetchone()[0]
            findings.append({"ok": ok_after == 0,
                             "text": (f"No successful sign-in from {', '.join(ips)} was recorded after the first failure."
                                      if ok_after == 0 else
                                      f"{ok_after} successful sign-in(s) from {', '.join(ips)} were recorded after "
                                      f"the first failure — review them.")})
    notes = [dict(n) for n in conn.execute(
        "SELECT author, body, created_at FROM alert_notes WHERE alert_id = ? ORDER BY id", (row["id"],))]
    rule = dict(conn.execute("SELECT * FROM rules WHERE id = ?", (row["rule_id"],)).fetchone())
    return {
        "alert": alert,
        "rule": {"id": rule["id"], "name": rule["name"], "description": rule["description"],
                 "enabled": bool(rule["enabled"]), "threshold": rule["threshold"],
                 "window_minutes": rule["window_minutes"]},
        "evidence": evidence,
        "timeline": timeline,
        "entities": {"ips": list(ips.values()), "accounts": list(accounts.values()),
                     "actions": [{"name": k, "events": v} for k, v in actions.items()]},
        "findings": findings,
        "recommended": RECOMMENDED.get(row["rule_id"], []),
        "notes": notes,
    }


def acknowledge(conn: sqlite3.Connection, uid: str, user: dict, info: dict) -> dict:
    with audit.WRITE_LOCK:
        row = _get(conn, uid)
        if row["status"] != "open":
            raise ApiError(f"Only open alerts can be acknowledged (current status: {row['status']}).", 409)
        now = now_iso()
        conn.execute("UPDATE alerts SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = ?, "
                     "updated_at = ? WHERE id = ?", (user["username"], now, now, row["id"]))
        result = audit.record_event(
            conn, actor=user["username"], actor_role=user["role"], action="alert.acknowledge", outcome="success",
            resource=alert_uid(row["id"]), message=f"{alert_uid(row['id'])} acknowledged by {user['username']}.",
            metadata={"previous_status": row["status"]}, **info)
    return {"alert": alert_to_dict(_get(conn, uid)), "event_uid": result["event"]["uid"]}


def resolve(conn: sqlite3.Connection, uid: str, resolution: str, user: dict, info: dict) -> dict:
    resolution = (resolution or "").strip()
    if not 5 <= len(resolution) <= 1000:
        raise ApiError("A resolution summary of 5–1000 characters is required.", field="resolution")
    with audit.WRITE_LOCK:
        row = _get(conn, uid)
        if row["status"] == "resolved":
            raise ApiError("This alert is already resolved.", 409)
        now = now_iso()
        conn.execute("UPDATE alerts SET status = 'resolved', resolved_by = ?, resolved_at = ?, resolution = ?, "
                     "updated_at = ? WHERE id = ?", (user["username"], now, resolution, now, row["id"]))
        result = audit.record_event(
            conn, actor=user["username"], actor_role=user["role"], action="alert.resolve", outcome="success",
            resource=alert_uid(row["id"]), message=f"{alert_uid(row['id'])} resolved by {user['username']}.",
            metadata={"previous_status": row["status"], "resolution": resolution}, **info)
    return {"alert": alert_to_dict(_get(conn, uid)), "event_uid": result["event"]["uid"]}


def add_note(conn: sqlite3.Connection, uid: str, body: str, user: dict, info: dict) -> dict:
    body = (body or "").strip()
    if not 1 <= len(body) <= 2000:
        raise ApiError("A note must be 1–2000 characters.", field="body")
    with audit.WRITE_LOCK:
        row = _get(conn, uid)
        now = now_iso()
        conn.execute("INSERT INTO alert_notes (alert_id, author, body, created_at) VALUES (?, ?, ?, ?)",
                     (row["id"], user["username"], body, now))
        conn.execute("UPDATE alerts SET updated_at = ? WHERE id = ?", (now, row["id"]))
        result = audit.record_event(
            conn, actor=user["username"], actor_role=user["role"], action="alert.note", outcome="success",
            resource=alert_uid(row["id"]), message=f"Investigation note added to {alert_uid(row['id'])}.",
            metadata={"length": len(body)}, **info)
    return {"note": {"author": user["username"], "body": body, "created_at": now},
            "event_uid": result["event"]["uid"]}
