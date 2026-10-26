"""Server-side search, filtering, sorting and pagination of audit events."""
import sqlite3

from .audit import ACTION_GROUPS, ACTIONS, GROUPED_ACTIONS, ORIGINS, OUTCOMES, SEVERITIES, event_to_dict
from .utils import ApiError, clamp_int, iso, like_escape, parse_iso, parse_uid

SEV_RANK_SQL = ("CASE severity WHEN 'info' THEN 0 WHEN 'low' THEN 1 WHEN 'medium' THEN 2 "
                "WHEN 'high' THEN 3 ELSE 4 END")
SORTS = {
    "id": "id",
    "ts": "id",
    "actor": "actor COLLATE NOCASE",
    "action": "action",
    "resource": "resource",
    "source_ip": "source_ip",
    "outcome": "outcome",
    "severity": SEV_RANK_SQL,
}
LIKE = " LIKE ? ESCAPE '\\'"


def build_filters(args) -> tuple[str, list, dict]:
    """Translate request arguments into a parameterized WHERE clause."""
    clauses, params, applied = [], [], {}

    q = (args.get("q") or "").strip()[:100]
    if q:
        event_id = parse_uid(q, "EVT") if q.upper().startswith("EVT-") else None
        if event_id:
            clauses.append("id = ?")
            params.append(event_id)
        else:
            pattern = f"%{like_escape(q)}%"
            clauses.append("(" + " OR ".join(f"{col}{LIKE}" for col in
                                              ("actor", "source_ip", "resource", "message", "action")) + ")")
            params += [pattern] * 5
        applied["q"] = q

    actor = (args.get("actor") or "").strip()[:64]
    if actor:
        clauses.append("actor" + LIKE)
        params.append(f"%{like_escape(actor)}%")
        applied["actor"] = actor

    ip = (args.get("ip") or "").strip()[:64]
    if ip:
        clauses.append("source_ip" + LIKE)
        params.append(f"{like_escape(ip)}%")
        applied["ip"] = ip

    action = (args.get("action") or "").strip()
    if action:
        if action in ACTION_GROUPS:
            codes = ACTION_GROUPS[action][1]
            clauses.append(f"action IN ({','.join('?' * len(codes))})")
            params += codes
        elif action == "other":
            codes = sorted(GROUPED_ACTIONS)
            clauses.append(f"action NOT IN ({','.join('?' * len(codes))})")
            params += codes
        elif action in ACTIONS:
            clauses.append("action = ?")
            params.append(action)
        else:
            raise ApiError("Unknown action filter.", field="action")
        applied["action"] = action

    for name, allowed in (("outcome", OUTCOMES), ("severity", SEVERITIES), ("origin", ORIGINS)):
        value = (args.get(name) or "").strip().lower()
        if value:
            if value not in allowed:
                raise ApiError(f"Unknown {name} filter.", field=name)
            clauses.append(f"{name} = ?")
            params.append(value)
            applied[name] = value

    bounds = {}
    for name, op in (("start", ">="), ("end", "<=")):
        value = (args.get(name) or "").strip()
        if value:
            try:
                bounds[name] = parse_iso(value)
            except ValueError:
                raise ApiError(f"Invalid {name} date.", field=name) from None
            clauses.append(f"ts {op} ?")
            params.append(iso(bounds[name]))
            applied[name] = iso(bounds[name])
    if "start" in bounds and "end" in bounds and bounds["end"] < bounds["start"]:
        raise ApiError("The end date must be after the start date.", field="end")

    since_id = args.get("since_id")
    if since_id not in (None, ""):
        clauses.append("id > ?")
        params.append(clamp_int(since_id, 0, 0, 2**31))

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params, applied


def query_events(conn: sqlite3.Connection, args) -> dict:
    where, params, applied = build_filters(args)
    sort_key = args.get("sort") if args.get("sort") in SORTS else "ts"
    direction = "ASC" if (args.get("dir") or "").lower() == "asc" else "DESC"
    per_page = clamp_int(args.get("per_page"), 25, 1, 100)
    total = conn.execute(f"SELECT COUNT(*) FROM audit_events {where}", params).fetchone()[0]
    pages = max(1, -(-total // per_page))
    page = clamp_int(args.get("page"), 1, 1, pages)
    rows = conn.execute(
        f"SELECT * FROM audit_events {where} ORDER BY {SORTS[sort_key]} {direction}, id {direction} "
        f"LIMIT ? OFFSET ?", (*params, per_page, (page - 1) * per_page)).fetchall()
    return {
        "items": [event_to_dict(r) for r in rows],
        "total": total, "page": page, "pages": pages, "per_page": per_page,
        "sort": sort_key, "dir": direction.lower(), "filters": applied,
        "latest_id": conn.execute("SELECT COALESCE(MAX(id), 0) FROM audit_events").fetchone()[0],
    }


def event_detail(conn: sqlite3.Connection, event_id: int) -> dict:
    row = conn.execute("SELECT * FROM audit_events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise ApiError("Event not found.", 404)
    event = event_to_dict(row)
    alerts = conn.execute(
        """SELECT a.id, a.title, a.severity, a.status, a.rule_id, ae.is_trigger
           FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id WHERE ae.event_id = ? ORDER BY a.id""",
        (event_id,)).fetchall()
    from .utils import alert_uid
    related = [{"uid": alert_uid(a["id"]), "title": a["title"], "severity": a["severity"], "status": a["status"],
                "rule_id": a["rule_id"], "is_trigger": bool(a["is_trigger"])} for a in alerts]
    link = "(actor = ? COLLATE NOCASE OR source_ip = ?)"
    link_params = (row["actor"], row["source_ip"] or "")
    before = conn.execute(f"SELECT * FROM audit_events WHERE id < ? AND {link} ORDER BY id DESC LIMIT 3",
                          (event_id, *link_params)).fetchall()
    after = conn.execute(f"SELECT * FROM audit_events WHERE id > ? AND {link} ORDER BY id ASC LIMIT 3",
                         (event_id, *link_params)).fetchall()
    neighbours = [event_to_dict(r) for r in reversed(before)] + [event] + [event_to_dict(r) for r in after]
    return {"event": event, "related_alerts": related, "neighbours": neighbours}
