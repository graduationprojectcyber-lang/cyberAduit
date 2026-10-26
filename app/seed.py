"""Deterministic demonstration data.

All seeded records are fictional, stored in the real database with
origin='seed', and pass through the same recording and detection path as live
events, so the alerts they produce are genuine detection results.
"""
import heapq
import itertools
import random
import sqlite3
from datetime import datetime, timedelta

from . import audit, detection
from .security import hash_password
from .utils import iso, utcnow

# username, full name, role, password, usual workstation IP
DEMO_USERS = [
    ("admin", "System Administrator", "admin", "Admin@12345", "192.168.1.10"),
    ("s.karim", "Sara Karim", "analyst", "Analyst@12345", "192.168.1.21"),
    ("r.jawad", "Rana Jawad", "analyst", "Analyst@12345", "192.168.1.27"),
    ("m.ali", "Mustafa Ali", "viewer", "Viewer@12345", "192.168.1.34"),
    ("a.hassan", "Ali Hassan", "viewer", "Viewer@12345", "192.168.1.15"),
    ("n.saleh", "Noor Saleh", "viewer", "Viewer@12345", "192.168.1.40"),
    ("svc.backup", "Backup service account", "viewer", "Service@12345", "10.0.2.8"),
]
USER_IP = {u[0]: u[4] for u in DEMO_USERS}
USER_ROLE = {u[0]: u[2] for u in DEMO_USERS}
SUSPICIOUS_IP = "10.0.4.23"
FILES = ["demo://finance/q3-budget.xlsx", "demo://reports/weekly-summary.docx", "demo://hr/policies.pdf",
         "demo://projects/roadmap.pptx", "demo://shared/contacts.csv", "demo://reports/q4-draft.docx"]
ROUTES = {"auth.login": ("POST", "/login"), "auth.logout": ("POST", "/logout"), "file.create": ("PUT", "/api/files"),
          "file.modify": ("PATCH", "/api/files"), "file.delete": ("DELETE", "/api/files"),
          "admin.access": ("GET", "/admin/users"), "permission.change": ("PATCH", "/api/admin/permissions"),
          "user.role_change": ("PATCH", "/api/users")}
RESOLUTIONS = {
    "R-01": "Account owner confirmed a forgotten password. Password reset completed; no later successful sign-in from the source IP.",
    "R-02": "Source address traced to a misconfigured test script in the demo lab. Script disabled.",
    "R-03": "Service account path misconfiguration corrected; the denials were expected behaviour.",
    "R-04": "Archive clean-up approved by the department head (ticket DEMO-118).",
    "R-05": "Role change approved through change request DEMO-204.",
}
NOTES = {
    "R-01": "Contacted the account owner by phone; attempts were theirs after a password change.",
    "R-02": "All failures came from one address within minutes. Checking whether it belongs to the lab subnet.",
    "R-03": "Denials target folders outside the account's permitted path.",
    "R-04": "Deleted items were archive files older than two years.",
    "R-05": "Change matches an open change request.",
}


def create_demo_users(conn: sqlite3.Connection, created_at: str) -> None:
    for username, full_name, role, password, _ip in DEMO_USERS:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, full_name, role, password_hash, is_active, created_at) "
            "VALUES (?, ?, ?, ?, 1, ?)", (username, full_name, role, hash_password(password), created_at))
    conn.commit()


def _event(ts: datetime, actor: str, action: str, outcome: str, resource: str | None = None,
           ip: str | None = None, message: str | None = None, **meta) -> dict:
    method, route = ROUTES.get(action, (None, None))
    label = audit.action_label(action)
    if message is None:
        if action == "auth.login":
            message = f"{actor} signed in." if outcome == "success" else f"Sign-in for {actor} failed: invalid credentials."
        elif action == "auth.logout":
            message = f"{actor} signed out."
        else:
            verb = {"success": "completed", "failed": "failed", "denied": "was denied"}[outcome]
            message = f"{label} by {actor} {verb}" + (f" ({resource})." if resource else ".")
    if action == "auth.login" and outcome == "failed":
        meta.setdefault("reason", "invalid_credentials")
    return {"ts": ts, "actor": actor, "action": action, "outcome": outcome, "resource": resource,
            "ip": ip or USER_IP.get(actor), "method": method, "route": route, "message": message, "meta": meta}


def _background(rng: random.Random, now: datetime) -> list:
    events = []
    weights = {"s.karim": 18, "r.jawad": 18, "a.hassan": 16, "m.ali": 14, "n.saleh": 12, "admin": 10, "svc.backup": 12}
    names, w = list(weights), list(weights.values())
    for days_back in range(30, -1, -1):
        day = (now - timedelta(days=days_back)).replace(hour=0, minute=0, second=0)
        busy = day.weekday() not in (4, 5)  # Friday and Saturday are the weekend in Iraq
        for _ in range(rng.randint(58, 86) if busy else rng.randint(18, 32)):
            hour = rng.randint(5, 14) if rng.random() < 0.78 else rng.randint(0, 23)
            ts = day + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            if ts >= now - timedelta(minutes=2):
                continue
            actor = rng.choices(names, w)[0]
            role = USER_ROLE[actor]
            if actor == "svc.backup":
                action = "file.create" if rng.random() < 0.7 else "file.modify"
                events.append(_event(ts, actor, action, "success", f"demo://backups/nightly-{day:%m%d}.tar"))
                continue
            r = rng.random()
            if r < 0.31:
                events.append(_event(ts, actor, "auth.login", "success", "/login"))
            elif r < 0.55:
                events.append(_event(ts, actor, "auth.logout", "success", "/logout"))
            elif r < 0.72:
                events.append(_event(ts, actor, "file.modify", "success", rng.choice(FILES)))
            elif r < 0.83:
                events.append(_event(ts, actor, "file.create", "success", rng.choice(FILES)))
            elif r < 0.87:
                events.append(_event(ts, actor, "file.delete", "success", rng.choice(FILES)))
            elif r < 0.935:
                events.append(_event(ts, actor, "auth.login", "failed", "/login"))
            elif r < 0.97:
                if role == "viewer":
                    events.append(_event(ts, actor, rng.choice(["file.delete", "admin.access"]), "denied",
                                         rng.choice(FILES + ["/admin/users"])))
                else:
                    events.append(_event(ts, actor, "file.modify", "failed", rng.choice(FILES),
                                         error="file_locked"))
            elif role == "admin":
                events.append(_event(ts, actor, "admin.access", "success", "/admin/users"))
            else:
                events.append(_event(ts, actor, "file.modify", "success", rng.choice(FILES)))
    return events


def _bursts(now: datetime) -> list:
    events = []
    # 26 days ago: a forgotten password (R-01)
    t = (now - timedelta(days=26)).replace(hour=6, minute=12, second=5)
    for i in range(5):
        events.append(_event(t + timedelta(seconds=41 * i), "a.hassan", "auth.login", "failed", "/login"))
    events.append(_event(t + timedelta(minutes=9), "a.hassan", "auth.login", "success", "/login"))
    # 19 days ago: backup service writing outside its folder (R-03)
    t = (now - timedelta(days=19)).replace(hour=1, minute=30, second=0)
    for i in range(4):
        events.append(_event(t + timedelta(minutes=4 * i), "svc.backup", "file.create", "denied",
                             f"demo://finance/backup-{i + 1}.tar"))
    # 12 days ago: bulk deletion (R-04)
    t = (now - timedelta(days=12)).replace(hour=11, minute=5, second=0)
    for i in range(11):
        events.append(_event(t + timedelta(seconds=19 * i), "r.jawad", "file.delete", "success",
                             f"demo://archive/2019-batch-{i + 1:02d}.zip"))
    # 6 days ago: approved role change (R-05, medium)
    t = (now - timedelta(days=6)).replace(hour=8, minute=40, second=0)
    events.append(_event(t, "admin", "user.role_change", "success", "role: viewer → analyst",
                         message="admin changed the role of r.jawad from Viewer to Security Analyst.", target="r.jawad"))
    # 3 days ago: failed logins from an unknown address (R-01, acknowledged)
    t = (now - timedelta(days=3)).replace(hour=19, minute=2, second=0)
    for i in range(5):
        events.append(_event(t + timedelta(seconds=33 * i), "m.ali", "auth.login", "failed", "/login", SUSPICIOUS_IP))
    # Yesterday: viewer attempting privileged operations (R-03 + R-05)
    t = now - timedelta(hours=27)
    for i, (action, resource) in enumerate([("admin.access", "/admin/users"), ("file.delete", "demo://hr/policies.pdf"),
                                            ("admin.access", "/admin/users/new")]):
        events.append(_event(t + timedelta(minutes=3 * i), "n.saleh", action, "denied", resource))
    events.append(_event(t + timedelta(minutes=11), "n.saleh", "permission.change", "denied", "role: analyst → admin"))
    # Two hours ago: failures against several accounts from one address (R-01 ×3, R-02)
    t = now - timedelta(hours=2, minutes=4)
    sequence = ["s.karim", "m.ali", "a.hassan"] * 5 + ["s.karim"]
    for i, account in enumerate(sequence):
        events.append(_event(t + timedelta(seconds=11 * i), account, "auth.login", "failed", "/login", SUSPICIOUS_IP))
    return events


def seed_demo_data(conn: sqlite3.Connection, now: datetime | None = None) -> dict:
    now = now or utcnow()
    rng = random.Random(2026)
    detection.ensure_rules(conn)
    create_demo_users(conn, iso(now - timedelta(days=31)))

    events = sorted(_background(rng, now) + _bursts(now), key=lambda e: e["ts"])
    pending, counter = [], itertools.count()

    def schedule(uid: str, rule_id: str, created: datetime) -> None:
        age = now - created
        if age >= timedelta(days=4):
            plan = [(25, "ack"), (55, "note"), (60 * rng.randint(2, 6), "resolve")]
        elif age >= timedelta(days=2):
            plan = [(30, "ack"), (48, "note")]
        else:
            return
        for minutes, step in plan:
            when = created + timedelta(minutes=minutes)
            if when < now - timedelta(minutes=1):
                heapq.heappush(pending, (when, next(counter), step, uid, rule_id))

    def apply(when: datetime, step: str, uid: str, rule_id: str) -> None:
        ts, alert_id = iso(when), int(uid[4:])
        if step == "ack":
            conn.execute("UPDATE alerts SET status = 'acknowledged', acknowledged_by = 'admin', acknowledged_at = ?, "
                         "updated_at = ? WHERE id = ? AND status = 'open'", (ts, ts, alert_id))
            action, message, meta = "alert.acknowledge", f"{uid} acknowledged by admin.", {"previous_status": "open"}
        elif step == "note":
            conn.execute("INSERT INTO alert_notes (alert_id, author, body, created_at) VALUES (?, 'admin', ?, ?)",
                         (alert_id, NOTES[rule_id], ts))
            action, message, meta = "alert.note", f"Investigation note added to {uid}.", {"length": len(NOTES[rule_id])}
        else:
            conn.execute("UPDATE alerts SET status = 'resolved', resolved_by = 'admin', resolved_at = ?, resolution = ?, "
                         "updated_at = ? WHERE id = ?", (ts, RESOLUTIONS[rule_id], ts, alert_id))
            action, message, meta = "alert.resolve", f"{uid} resolved by admin.", {"resolution": RESOLUTIONS[rule_id]}
        audit.record_event(conn, actor="admin", actor_role="admin", action=action, outcome="success", resource=uid,
                           message=message, metadata=meta, source_ip=USER_IP["admin"], http_method="POST",
                           route=f"/api/alerts/{uid}", origin="seed", ts=ts, evaluate=False, commit=False)

    for event in events:
        while pending and pending[0][0] <= event["ts"]:
            when, _, step, uid, rule_id = heapq.heappop(pending)
            apply(when, step, uid, rule_id)
        result = audit.record_event(
            conn, actor=event["actor"], actor_role=USER_ROLE.get(event["actor"]), action=event["action"],
            outcome=event["outcome"], resource=event["resource"], source_ip=event["ip"],
            http_method=event["method"], route=event["route"], message=event["message"],
            metadata=dict(event["meta"], demo_seed=True), origin="seed", ts=iso(event["ts"]), commit=False)
        for evaluation in result["evaluations"]:
            if evaluation["alert_new"]:
                schedule(evaluation["alert_uid"], evaluation["rule_id"], event["ts"])
    while pending:
        when, _, step, uid, rule_id = heapq.heappop(pending)
        apply(when, step, uid, rule_id)
    conn.commit()
    return {
        "events": conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
    }
