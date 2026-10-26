"""Security event simulator.

Simulated events go through exactly the same recording and detection path as
real ones and are stored with origin='simulated'. The simulator never touches
files on the host or any network: resources are fixed 'demo://' labels and
source IPs must be private or documentation-range addresses.
"""
import ipaddress
import sqlite3

from . import audit
from .utils import ApiError

SIM_ACTIONS = {
    "login": ("auth.login", ("success", "failed")),
    "logout": ("auth.logout", ("success",)),
    "file_create": ("file.create", ("success", "failed", "denied")),
    "file_modify": ("file.modify", ("success", "failed", "denied")),
    "file_delete": ("file.delete", ("success", "failed", "denied")),
    "user_management": ("admin.access", ("success", "denied")),
    "permission_change": ("permission.change", ("success", "denied")),
}

SAFE_RESOURCES = {
    "login": ["/auth/login"],
    "logout": ["/auth/logout"],
    "file_create": ["demo://reports/q4-draft.docx", "demo://hr/onboarding.pdf", "demo://backups/nightly.tar"],
    "file_modify": ["demo://finance/q3-budget.xlsx", "demo://reports/q4-draft.docx", "demo://hr/policies.pdf"],
    "file_delete": ["demo://archive/old-notes.txt", "demo://archive/2019-logs.zip", "demo://reports/q4-draft.docx"],
    "user_management": ["/admin/users", "/admin/users/new"],
    "permission_change": ["role: viewer → analyst", "role: analyst → admin", "share: demo://finance → everyone"],
}

ROUTES = {
    "login": ("POST", "/api/auth/login"), "logout": ("POST", "/api/auth/logout"),
    "file_create": ("PUT", "/api/files"), "file_modify": ("PATCH", "/api/files"),
    "file_delete": ("DELETE", "/api/files"), "user_management": ("POST", "/api/admin/users"),
    "permission_change": ("PATCH", "/api/admin/permissions"),
}

PRESETS = [
    {"key": "successful_login", "label": "Successful login", "color": "success",
     "params": {"user": "s.karim", "action": "login", "outcome": "success", "ip": "192.168.1.15", "count": 1},
     "expect": "One success event is stored. No detection rule applies."},
    {"key": "failed_login", "label": "Failed login", "color": "failed",
     "params": {"user": "s.karim", "action": "login", "outcome": "failed", "ip": "10.0.4.23", "count": 1},
     "expect": "One failure is stored. R-01 counts it toward its threshold."},
    {"key": "multiple_failed_logins", "label": "Multiple failed logins", "color": "failed",
     "params": {"user": "m.ali", "action": "login", "outcome": "failed", "ip": "10.0.4.23", "count": 5},
     "expect": "Five failures inside one window meet R-01 and open an alert."},
    {"key": "file_creation", "label": "File creation", "color": "info",
     "params": {"user": "r.jawad", "action": "file_create", "outcome": "success", "ip": "192.168.1.15", "count": 1},
     "expect": "One file event inside demo storage. No host file is created."},
    {"key": "file_modification", "label": "File modification", "color": "info",
     "params": {"user": "r.jawad", "action": "file_modify", "outcome": "success", "ip": "192.168.1.15", "count": 1},
     "expect": "One modification event with demo metadata."},
    {"key": "file_deletion", "label": "File deletion", "color": "warning",
     "params": {"user": "r.jawad", "action": "file_delete", "outcome": "success", "ip": "192.168.1.15", "count": 1},
     "expect": "One deletion. R-04 counts it toward its threshold."},
    {"key": "unauthorized_operation", "label": "Unauthorized operation", "color": "warning",
     "params": {"user": "m.ali", "action": "user_management", "outcome": "denied", "ip": "192.168.1.40", "count": 1},
     "expect": "A viewer is denied an admin page. R-03 counts the denial."},
    {"key": "privilege_change", "label": "Privilege change", "color": "failed",
     "params": {"user": "n.saleh", "action": "permission_change", "outcome": "denied", "ip": "10.0.2.8",
                "count": 1, "resource": "role: analyst → admin"},
     "expect": "A denied role escalation. R-05 alerts on any sensitive change."},
    {"key": "multiple_accounts", "label": "Multiple accounts targeted", "color": "failed",
     "params": {"users": ["s.karim", "m.ali", "a.hassan"], "action": "login", "outcome": "failed",
                "ip": "10.0.4.23", "count": 1},
     "expect": "Failures against three accounts from one IP meet R-02."},
    {"key": "destructive_activity", "label": "Suspicious destructive activity", "color": "failed",
     "params": {"user": "r.jawad", "action": "file_delete", "outcome": "success", "ip": "192.168.1.15", "count": 12},
     "expect": "Twelve deletions within five minutes meet R-04."},
]
PRESETS_BY_KEY = {p["key"]: p for p in PRESETS}


def options(conn: sqlite3.Connection) -> dict:
    users = [dict(r) for r in conn.execute("SELECT username, role FROM users ORDER BY username")]
    return {
        "presets": PRESETS,
        "users": users,
        "actions": [{"key": k, "code": v[0], "label": audit.action_label(v[0]), "outcomes": list(v[1])}
                    for k, v in SIM_ACTIONS.items()],
        "resources": SAFE_RESOURCES,
    }


def _message(action_key: str, user: str, outcome: str, resource: str) -> str:
    label = audit.action_label(SIM_ACTIONS[action_key][0]).lower()
    if action_key == "login":
        return f"Simulated sign-in for {user} " + ("succeeded." if outcome == "success" else "failed: invalid credentials.")
    verb = {"success": "completed", "failed": "failed", "denied": "was denied"}[outcome]
    return f"Simulated {label} by {user} {verb} ({resource})."


def run(conn: sqlite3.Connection, data: dict, operator: dict) -> dict:
    preset = None
    if data.get("preset"):
        preset = PRESETS_BY_KEY.get(str(data["preset"]))
        if not preset:
            raise ApiError("Unknown preset scenario.", field="preset")
        params = dict(preset["params"])
        if data.get("user") and "users" not in params:  # allow the guided scenario to choose the account
            params["user"] = data["user"]
    else:
        params = data

    action_key = params.get("action")
    if action_key not in SIM_ACTIONS:
        raise ApiError("Choose a supported action.", field="action")
    action_code, allowed_outcomes = SIM_ACTIONS[action_key]
    outcome = params.get("outcome")
    if outcome not in allowed_outcomes:
        raise ApiError(f"Outcome must be one of: {', '.join(allowed_outcomes)}.", field="outcome")

    usernames = params.get("users") or [params.get("user")]
    users = []
    for name in usernames:
        row = conn.execute("SELECT username, role FROM users WHERE username = ? COLLATE NOCASE",
                           (str(name or ""),)).fetchone()
        if row is None:
            raise ApiError("Choose an existing demo user.", field="user")
        users.append(row)

    resource = params.get("resource") or SAFE_RESOURCES[action_key][0]
    if resource not in SAFE_RESOURCES[action_key]:
        raise ApiError("Choose one of the safe demo resources for this action.", field="resource")

    try:
        ip = ipaddress.ip_address(str(params.get("ip") or "").strip())
    except ValueError:
        raise ApiError("Enter a valid IPv4 or IPv6 address.", field="ip") from None
    if not ip.is_private:
        raise ApiError("Use a private or documentation-range address; simulated IPs never point at real hosts.",
                       field="ip")

    count = params.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 20:
        raise ApiError("Repeat count must be between 1 and 20.", field="count")

    method, route = ROUTES[action_key]
    created, alerts, evaluations = [], {}, []
    with audit.WRITE_LOCK:
        for user in users:
            for n in range(count):
                item_resource = resource
                if preset and preset["key"] == "destructive_activity":
                    item_resource = f"demo://archive/batch-{n + 1:02d}.txt"
                result = audit.record_event(
                    conn, actor=user["username"], actor_role=user["role"], action=action_code, outcome=outcome,
                    resource=item_resource, source_ip=str(ip), http_method=method, route=route,
                    message=_message(action_key, user["username"], outcome, item_resource),
                    metadata={"simulated": True, "scenario": preset["key"] if preset else "custom",
                              "triggered_by": operator["username"],
                              **({"reason": "invalid_credentials"} if outcome == "failed" and action_key == "login" else {})},
                    origin="simulated", commit=False)
                created.append(result["event"])
                evaluations = result["evaluations"]
                for ev in result["evaluations"]:
                    if ev["matched"] and ev["alert_uid"]:
                        entry = alerts.setdefault(ev["alert_uid"], {"uid": ev["alert_uid"], "rule_id": ev["rule_id"],
                                                                    "new": False})
                        entry["new"] = entry["new"] or ev["alert_new"]
        conn.commit()
    for uid, entry in alerts.items():
        row = conn.execute("SELECT title, severity FROM alerts WHERE id = ?", (int(uid[4:]),)).fetchone()
        entry.update(title=row["title"], severity=row["severity"])
    return {
        "preset": preset["key"] if preset else None,
        "events": [{"uid": e["uid"], "id": e["id"], "actor": e["actor"], "action_label": e["action_label"],
                    "outcome": e["outcome"], "severity": e["severity"], "ts": e["ts"]} for e in created],
        "evaluations": evaluations,
        "alerts": list(alerts.values()),
    }


def history(conn: sqlite3.Connection, limit: int = 12) -> list:
    rows = conn.execute("SELECT * FROM audit_events WHERE origin = 'simulated' ORDER BY id DESC LIMIT ?", (limit,))
    return [audit.event_to_dict(r) for r in rows]
