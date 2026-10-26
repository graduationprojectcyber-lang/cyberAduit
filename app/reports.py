"""Audit reports: summary queries, CSV export with formula escaping, printable HTML data."""
import csv
import io
import sqlite3
from datetime import timedelta

from .audit import ACTION_GROUPS, action_group, event_to_dict
from .events import build_filters
from .utils import ApiError, iso, utcnow

PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
CSV_COLUMNS = ["event_id", "timestamp_utc", "actor", "actor_role", "action", "resource", "source_ip",
               "http_method", "route", "outcome", "severity", "origin", "message"]
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
PREVIEW_LIMIT = 200
EXPORT_LIMIT = 50000


def resolve_args(args) -> dict:
    """Apply a named period (24h/7d/30d) unless explicit dates were given."""
    merged = {k: v for k, v in args.items()}
    period = merged.get("period") or ""
    if period and period != "custom":
        if period not in PERIODS:
            raise ApiError("Unknown report period.", field="period")
        if not merged.get("start"):
            merged["start"] = iso(utcnow() - PERIODS[period])
    return merged


def report_data(conn: sqlite3.Connection, args, limit: int = PREVIEW_LIMIT) -> dict:
    merged = resolve_args(args)
    where, params, applied = build_filters(merged)
    summary = dict(conn.execute(
        f"""SELECT COUNT(*) AS total,
                   COALESCE(SUM(outcome = 'success'), 0) AS success,
                   COALESCE(SUM(outcome = 'failed'), 0) AS failed,
                   COALESCE(SUM(outcome = 'denied'), 0) AS denied,
                   COUNT(DISTINCT actor) AS actors,
                   COUNT(DISTINCT source_ip) AS source_ips,
                   MIN(ts) AS first_ts, MAX(ts) AS last_ts
            FROM audit_events {where}""", params).fetchone())
    labels = {k: v[0] for k, v in ACTION_GROUPS.items()}
    labels["other"] = "Other activity"
    dist = {}
    for row in conn.execute(f"SELECT action, COUNT(*) AS n FROM audit_events {where} GROUP BY action", params):
        key = action_group(row["action"])
        dist[key] = dist.get(key, 0) + row["n"]
    distribution = sorted(({"key": k, "label": labels[k], "count": n} for k, n in dist.items()),
                          key=lambda d: -d["count"])
    severity = {r["severity"]: r["n"] for r in conn.execute(
        f"SELECT severity, COUNT(*) AS n FROM audit_events {where} GROUP BY severity", params)}

    alert_clauses, alert_params = [], []
    if "start" in applied:
        alert_clauses.append("created_at >= ?")
        alert_params.append(applied["start"])
    if "end" in applied:
        alert_clauses.append("created_at <= ?")
        alert_params.append(applied["end"])
    alert_where = ("WHERE " + " AND ".join(alert_clauses)) if alert_clauses else ""
    alert_summary = dict(conn.execute(
        f"""SELECT COUNT(*) AS total, COALESCE(SUM(status = 'open'), 0) AS open,
                   COALESCE(SUM(status = 'acknowledged'), 0) AS acknowledged,
                   COALESCE(SUM(status = 'resolved'), 0) AS resolved,
                   COALESCE(SUM(severity IN ('high', 'critical')), 0) AS high
            FROM alerts {alert_where}""", alert_params).fetchone())
    by_rule = [dict(r) for r in conn.execute(
        f"""SELECT a.rule_id, r.name, COUNT(*) AS n FROM alerts a JOIN rules r ON r.id = a.rule_id
            {alert_where.replace('created_at', 'a.created_at')} GROUP BY a.rule_id ORDER BY a.rule_id""", alert_params)]

    rows = conn.execute(f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
    return {
        "generated_at": iso(utcnow()),
        "period": merged.get("period") or "custom",
        "filters": applied,
        "summary": summary,
        "distribution": distribution,
        "severity": severity,
        "alerts": dict(alert_summary, by_rule=by_rule),
        "rows": [event_to_dict(r) for r in rows],
        "rows_truncated": summary["total"] > limit,
    }


def _safe_cell(value) -> str:
    text = "" if value is None else str(value)
    # Prevent spreadsheet formula injection (CSV injection).
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def export_csv(conn: sqlite3.Connection, args, generated_by: str) -> tuple[str, int]:
    merged = resolve_args(args)
    where, params, applied = build_filters(merged)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(["# CyberAudit Monitor audit report"])
    writer.writerow(["# generated_at_utc", iso(utcnow()), "generated_by", _safe_cell(generated_by)])
    writer.writerow(["# filters"] + [_safe_cell(f"{k}={v}") for k, v in applied.items()])
    writer.writerow(CSV_COLUMNS)
    count = 0
    for row in conn.execute(f"SELECT * FROM audit_events {where} ORDER BY id LIMIT ?", (*params, EXPORT_LIMIT)):
        e = event_to_dict(row)
        writer.writerow([_safe_cell(v) for v in (
            e["uid"], e["ts"], e["actor"], e["actor_role"], e["action"], e["resource"], e["source_ip"],
            e["http_method"], e["route"], e["outcome"], e["severity"], e["origin"], e["message"])])
        count += 1
    # BOM so Excel on Windows opens UTF-8 (arrows, Arabic names) correctly.
    return "﻿" + buffer.getvalue(), count
