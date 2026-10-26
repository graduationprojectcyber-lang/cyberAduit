"""Dashboard statistics, system health and network relationships — all computed from the database."""
import sqlite3
import time
from datetime import timedelta

from .audit import ACTION_GROUPS, action_group, event_to_dict
from .utils import iso, parse_iso, utcnow

RANGES = {"24h": (24, "hour"), "7d": (7, "day"), "30d": (30, "day")}


def _counts(conn, where: str = "", params: tuple = ()) -> dict:
    row = conn.execute(
        f"""SELECT COUNT(*) AS total,
                   COALESCE(SUM(outcome = 'success'), 0) AS success,
                   COALESCE(SUM(outcome = 'failed'), 0) AS failed,
                   COALESCE(SUM(outcome = 'denied'), 0) AS denied
            FROM audit_events {where}""", params).fetchone()
    return dict(row)


def dashboard_stats(conn: sqlite3.Connection, range_key: str = "24h", tz_offset: int = 0) -> dict:
    """tz_offset is the browser's Date.getTimezoneOffset() (minutes, UTC minus local)."""
    if range_key not in RANGES:
        range_key = "24h"
    tz_offset = max(-900, min(900, tz_offset))
    now = utcnow()
    totals = _counts(conn)
    alerts = conn.execute(
        """SELECT COALESCE(SUM(status != 'resolved'), 0) AS open,
                  COALESCE(SUM(status != 'resolved' AND severity IN ('high', 'critical')), 0) AS high
           FROM alerts""").fetchone()

    day, prev_day = iso(now - timedelta(hours=24)), iso(now - timedelta(hours=48))
    last = _counts(conn, "WHERE ts > ?", (day,))
    prev = _counts(conn, "WHERE ts > ? AND ts <= ?", (prev_day, day))
    alerts_last = conn.execute("SELECT COUNT(*) FROM alerts WHERE created_at > ?", (day,)).fetchone()[0]
    alerts_prev = conn.execute("SELECT COUNT(*) FROM alerts WHERE created_at > ? AND created_at <= ?",
                               (prev_day, day)).fetchone()[0]
    high_last = conn.execute("SELECT COUNT(*) FROM alerts WHERE created_at > ? AND severity IN ('high','critical')",
                             (day,)).fetchone()[0]
    high_prev = conn.execute("""SELECT COUNT(*) FROM alerts WHERE created_at > ? AND created_at <= ?
                                AND severity IN ('high','critical')""", (prev_day, day)).fetchone()[0]

    # Time series
    count, unit = RANGES[range_key]
    local_shift = timedelta(minutes=-tz_offset)
    if unit == "hour":
        first = now.replace(minute=0, second=0) - timedelta(hours=count - 1)
        step = timedelta(hours=1)
    else:
        local_now = now + local_shift
        first = local_now.replace(hour=0, minute=0, second=0) - timedelta(days=count - 1) - local_shift
        step = timedelta(days=1)
    buckets = [{"start": iso(first + step * i), "success": 0, "failed": 0, "denied": 0} for i in range(count)]
    for row in conn.execute("SELECT ts, outcome FROM audit_events WHERE ts >= ?", (iso(first),)):
        index = int((parse_iso(row["ts"]) - first) / step)
        if 0 <= index < count:
            buckets[index][row["outcome"]] += 1

    # Distribution by action group
    labels = {key: label for key, (label, _) in ACTION_GROUPS.items() if key != "alert"}
    labels["other"] = "Other activity"
    dist = {key: 0 for key in labels}
    for row in conn.execute("SELECT action, COUNT(*) AS n FROM audit_events GROUP BY action"):
        key = action_group(row["action"])
        dist[key if key in dist else "other"] += row["n"]
    distribution = [{"key": k, "label": labels[k], "count": dist[k]} for k in labels]

    return {
        "generated_at": iso(now),
        "cards": {
            "total": totals["total"], "success": totals["success"], "failed": totals["failed"],
            "denied": totals["denied"], "open_alerts": alerts["open"], "high_alerts": alerts["high"],
        },
        "trends": {
            "total": last["total"] - prev["total"], "success": last["success"] - prev["success"],
            "failed": last["failed"] - prev["failed"], "denied": last["denied"] - prev["denied"],
            "open_alerts": alerts_last - alerts_prev, "high_alerts": high_last - high_prev,
        },
        "last_24h": last,
        "series": {"range": range_key, "unit": unit, "buckets": buckets},
        "distribution": distribution,
    }


def health(conn: sqlite3.Connection, version: str) -> dict:
    started = time.perf_counter()
    conn.execute("SELECT 1").fetchone()
    db_ms = round((time.perf_counter() - started) * 1000, 2)
    events = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    last = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    rules = conn.execute("SELECT COUNT(*) AS total, COALESCE(SUM(enabled), 0) AS enabled FROM rules").fetchone()
    unresolved = conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(severity IN ('high','critical')), 0) AS high "
        "FROM alerts WHERE status != 'resolved'").fetchone()
    return {
        "status": "ok",
        "server_time": iso(utcnow()),
        "application": {"ok": True, "version": version},
        "database": {"ok": True, "engine": "SQLite", "latency_ms": db_ms, "events": events},
        "detection": {"ok": rules["enabled"] > 0, "rules_total": rules["total"], "rules_enabled": rules["enabled"]},
        "last_event": event_to_dict(last) if last else None,
        "unresolved_alerts": {"total": unresolved["n"], "high": unresolved["high"]},
    }


def network(conn: sqlite3.Connection, hours: int = 24) -> dict:
    since = iso(utcnow() - timedelta(hours=hours))
    rows = conn.execute(
        """SELECT source_ip, actor, COUNT(*) AS n,
                  SUM(outcome = 'failed') AS failed, SUM(outcome = 'denied') AS denied,
                  SUM(outcome = 'success') AS success, MAX(ts) AS last_ts, MAX(id) AS last_id
           FROM audit_events
           WHERE ts >= ? AND source_ip IS NOT NULL AND actor != 'detection-engine'
           GROUP BY source_ip, actor""", (since,)).fetchall()
    ips, accounts = {}, {}
    for r in rows:
        for bucket, key in ((ips, r["source_ip"]), (accounts, r["actor"])):
            item = bucket.setdefault(key, {"id": key, "events": 0, "failed": 0, "denied": 0, "success": 0,
                                           "last_ts": "", "last_id": 0, "peers": {}})
            item["events"] += r["n"]
            item["failed"] += r["failed"]
            item["denied"] += r["denied"]
            item["success"] += r["success"]
            item["last_ts"] = max(item["last_ts"], r["last_ts"])
            item["last_id"] = max(item["last_id"], r["last_id"])
            peer = r["actor"] if bucket is ips else r["source_ip"]
            item["peers"][peer] = item["peers"].get(peer, 0) + r["n"]

    alert_rows = conn.execute(
        "SELECT source_ip, actor, rule_id, id FROM alerts WHERE status != 'resolved'").fetchall()
    flagged_ips = {a["source_ip"] for a in alert_rows if a["source_ip"] and a["rule_id"] in ("R-01", "R-02")}
    flagged_accounts = {(a["actor"] or "").lower() for a in alert_rows if a["actor"]}

    top_ips = sorted(ips.values(), key=lambda x: (x["id"] in flagged_ips, x["failed"], x["events"]),
                     reverse=True)[:5]
    wanted = {}
    for ip in top_ips:
        for acct, n in ip["peers"].items():
            wanted[acct] = wanted.get(acct, 0) + n
    top_accounts = sorted((accounts[a] for a in wanted), key=lambda x: (x["failed"], x["events"]), reverse=True)[:6]
    shown_accounts = {a["id"] for a in top_accounts}

    def ip_node(item):
        suspicious = item["id"] in flagged_ips or (item["failed"] >= 3 and item["failed"] >= item["events"] / 2)
        return {"id": item["id"], "kind": "ip", "events": item["events"], "failed": item["failed"],
                "denied": item["denied"], "success": item["success"], "last_ts": item["last_ts"],
                "last_id": item["last_id"], "suspicious": suspicious,
                "accounts": [a for a in item["peers"] if a in shown_accounts]}

    def account_node(item):
        return {"id": item["id"], "kind": "account", "events": item["events"], "failed": item["failed"],
                "denied": item["denied"], "success": item["success"], "last_ts": item["last_ts"],
                "last_id": item["last_id"], "suspicious": item["id"].lower() in flagged_accounts,
                "ips": [ip["id"] for ip in top_ips if item["id"] in ip["peers"]]}

    total = conn.execute("SELECT COUNT(*) FROM audit_events WHERE ts >= ?", (since,)).fetchone()[0]
    return {
        "hours": hours,
        "app": {"id": "app", "kind": "app", "events": total},
        "ips": [ip_node(i) for i in top_ips],
        "accounts": [account_node(a) for a in top_accounts],
        "open_alerts": len(alert_rows),
    }
