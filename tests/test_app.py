import csv
import io
import sqlite3

import pytest

from app import audit, create_app, users
from app.db import connect
from tests.conftest import login_form


def events(session, **params):
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return session.get(f"/api/events?{query}").get_json()


# --- authentication & session -------------------------------------------------

def test_pages_and_api_require_login(app):
    client = app.test_client()
    assert client.get("/").status_code == 302
    assert "/login" in client.get("/").headers["Location"]
    assert client.get("/api/stats").status_code == 401


def test_failed_and_successful_logins_are_audited(app, login):
    client = app.test_client()
    bad = login_form(client, "s.karim", "wrong-password-1")
    assert bad.status_code == 401
    session = login("admin")
    failed = events(session, action="login", outcome="failed", actor="s.karim")
    assert failed["total"] == 1
    assert failed["items"][0]["origin"] == "live"
    assert "password" not in str(failed["items"][0]["metadata"]).lower()
    ok = events(session, action="login", outcome="success", actor="admin")
    assert ok["total"] >= 1


def test_open_redirect_is_blocked(app):
    client = app.test_client()
    page = client.get("/login").get_data(as_text=True)
    import re
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    response = client.post("/login?next=//evil.example.com", data={"username": "admin", "password": "Admin@12345",
                                                                   "csrf_token": token})
    assert response.headers["Location"] == "/"


def test_csrf_token_is_required(login):
    session = login("s.karim")
    response = session.client.post("/api/simulate", json={"preset": "failed_login"})
    assert response.status_code == 403
    assert "token" in response.get_json()["error"].lower()


def test_login_form_requires_csrf(app):
    client = app.test_client()
    response = client.post("/login", data={"username": "admin", "password": "Admin@12345"})
    assert response.status_code == 403


def test_security_headers_and_no_password_hash_exposed(login):
    session = login("admin")
    response = session.get("/api/me")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    body = session.get("/api/users").get_data(as_text=True)
    assert "password_hash" not in body and "scrypt" not in body and "pbkdf2" not in body


# --- role-based authorization -------------------------------------------------

def test_viewer_cannot_simulate_and_denial_is_audited(login):
    viewer = login("m.ali")
    response = viewer.post("/api/simulate", {"preset": "failed_login"})
    assert response.status_code == 403
    admin = login("admin")
    denied = events(admin, outcome="denied", actor="m.ali")
    assert denied["total"] == 1
    assert denied["items"][0]["action"] == "access.denied"


def test_role_restrictions(login):
    analyst = login("s.karim")
    assert analyst.get("/api/users").status_code == 403
    assert analyst.get("/users").status_code == 403
    assert analyst.put("/api/rules/R-01", {"threshold": 3}).status_code == 403
    assert analyst.post("/api/integrity/verify").status_code == 403
    viewer = login("m.ali")
    assert viewer.get("/reports/export.csv").status_code == 403
    assert login("admin").get("/api/users").status_code == 200


# --- simulator & detection ----------------------------------------------------

def test_simulated_failed_login_is_persisted(login):
    analyst = login("s.karim")
    response = analyst.post("/api/simulate", {"preset": "failed_login"})
    assert response.status_code == 201
    data = response.get_json()
    assert len(data["events"]) == 1
    stored = events(analyst, origin="simulated")
    assert stored["total"] == 1
    item = stored["items"][0]
    assert (item["actor"], item["action"], item["outcome"]) == ("s.karim", "auth.login", "failed")
    assert item["metadata"]["triggered_by"] == "s.karim"
    r01 = next(e for e in data["evaluations"] if e["rule_id"] == "R-01")
    assert r01["count"] == 1 and not r01["matched"]


def test_repeated_failed_logins_open_alert_with_evidence(login):
    analyst = login("s.karim")
    data = analyst.post("/api/simulate", {"preset": "multiple_failed_logins"}).get_json()
    assert len(data["events"]) == 5
    new_alert = next(a for a in data["alerts"] if a["rule_id"] == "R-01")
    assert new_alert["new"] is True
    listed = analyst.get("/api/alerts?status=unresolved").get_json()["items"]
    assert any(a["uid"] == new_alert["uid"] for a in listed)
    detail = analyst.get(f"/api/alerts/{new_alert['uid']}").get_json()
    assert detail["alert"]["actor"] == "m.ali"
    assert len(detail["evidence"]) == 5
    assert sum(1 for e in detail["evidence"] if e["is_trigger"]) == 1
    assert detail["rule"]["threshold"] == 5
    assert any(e["action"] == "alert.created" for e in detail["timeline"])
    # Running it again inside the window attaches evidence instead of duplicating the alert.
    again = analyst.post("/api/simulate", {"preset": "multiple_failed_logins"}).get_json()
    assert all(not a["new"] for a in again["alerts"] if a["rule_id"] == "R-01")


def test_real_failed_logins_trigger_r01(app, login):
    client = app.test_client()
    for _ in range(5):
        assert login_form(client, "a.hassan", "not-the-password").status_code == 401
    admin = login("admin")
    alerts = admin.get("/api/alerts?rule=R-01").get_json()["items"]
    assert any(a["actor"] == "a.hassan" for a in alerts)


def test_multiple_accounts_preset_triggers_r02(login):
    data = login("admin").post("/api/simulate", {"preset": "multiple_accounts"}).get_json()
    assert any(a["rule_id"] == "R-02" and a["new"] for a in data["alerts"])


def test_destructive_and_privilege_presets(login):
    analyst = login("r.jawad")
    destructive = analyst.post("/api/simulate", {"preset": "destructive_activity"}).get_json()
    assert len(destructive["events"]) == 12
    assert any(a["rule_id"] == "R-04" for a in destructive["alerts"])
    privilege = analyst.post("/api/simulate", {"preset": "privilege_change"}).get_json()
    assert any(a["rule_id"] == "R-05" and a["severity"] == "high" for a in privilege["alerts"])


def test_simulator_validation(login):
    analyst = login("s.karim")
    public_ip = analyst.post("/api/simulate", {"user": "s.karim", "action": "login", "outcome": "failed",
                                                "ip": "8.8.8.8", "count": 1})
    assert public_ip.status_code == 400 and public_ip.get_json()["field"] == "ip"
    bad_resource = analyst.post("/api/simulate", {"user": "s.karim", "action": "file_delete", "outcome": "success",
                                                  "ip": "10.0.0.5", "resource": "C:/Windows/System32", "count": 1})
    assert bad_resource.status_code == 400 and bad_resource.get_json()["field"] == "resource"
    too_many = analyst.post("/api/simulate", {"user": "s.karim", "action": "login", "outcome": "failed",
                                              "ip": "10.0.0.5", "count": 500})
    assert too_many.status_code == 400
    unknown_user = analyst.post("/api/simulate", {"user": "ghost", "action": "login", "outcome": "failed",
                                                  "ip": "10.0.0.5", "count": 1})
    assert unknown_user.status_code == 400


# --- alerts workflow ----------------------------------------------------------

def test_acknowledge_resolve_and_notes_are_audited(login):
    analyst = login("s.karim")
    uid = analyst.post("/api/simulate", {"preset": "multiple_failed_logins"}).get_json()["alerts"][0]["uid"]
    viewer = login("m.ali")
    assert viewer.post(f"/api/alerts/{uid}/acknowledge").status_code == 403

    ack = analyst.post(f"/api/alerts/{uid}/acknowledge")
    assert ack.status_code == 200 and ack.get_json()["alert"]["status"] == "acknowledged"
    assert analyst.post(f"/api/alerts/{uid}/acknowledge").status_code == 409
    assert analyst.post(f"/api/alerts/{uid}/notes", {"body": "Checked the source IP."}).status_code == 201
    assert analyst.post(f"/api/alerts/{uid}/resolve", {"resolution": "ok"}).status_code == 400
    resolved = analyst.post(f"/api/alerts/{uid}/resolve", {"resolution": "Owner confirmed; password reset."})
    assert resolved.get_json()["alert"]["status"] == "resolved"

    lifecycle = events(analyst, action="alert", q=uid)
    actions = {e["action"] for e in lifecycle["items"]}
    assert {"alert.created", "alert.acknowledge", "alert.note", "alert.resolve"} <= actions
    detail = analyst.get(f"/api/alerts/{uid}").get_json()
    assert detail["notes"][0]["body"] == "Checked the source IP."


# --- search, filters, injection -----------------------------------------------

def test_filters_sorting_pagination_and_injection(login):
    analyst = login("s.karim")
    analyst.post("/api/simulate", {"preset": "multiple_failed_logins"})
    analyst.post("/api/simulate", {"preset": "file_creation"})
    failed = events(analyst, actor="m.ali", outcome="failed", per_page=2, page=2)
    assert failed["total"] == 5 and failed["page"] == 2 and len(failed["items"]) == 2
    assert all(e["actor"] == "m.ali" and e["outcome"] == "failed" for e in failed["items"])
    files = events(analyst, action="file_create")
    assert files["total"] == 1 and files["items"][0]["action"] == "file.create"
    by_ip = events(analyst, ip="10.0.4")
    assert by_ip["total"] == 5
    asc = events(analyst, sort="ts", dir="asc")["items"]
    assert asc[0]["id"] < asc[-1]["id"]
    injection = analyst.get("/api/events?q=' OR 1=1 --&actor=x' OR '1'='1").get_json()
    assert injection["total"] == 0
    assert analyst.get("/api/events?outcome=hacked").status_code == 400
    assert analyst.get("/api/events?start=not-a-date").status_code == 400
    by_uid = events(analyst, q=files["items"][0]["uid"])
    assert by_uid["total"] == 1


# --- users ----------------------------------------------------------------------

def test_user_management_and_safeguards(app, login):
    admin = login("admin")
    weak = admin.post("/api/users", {"username": "h.kadhim", "full_name": "Hussein Kadhim", "role": "viewer",
                                     "password": "short"})
    assert weak.status_code == 400 and weak.get_json()["field"] == "password"
    created = admin.post("/api/users", {"username": "h.kadhim", "full_name": "Hussein Kadhim", "role": "viewer",
                                        "password": "Strong-pass-2026"})
    assert created.status_code == 201
    uid = created.get_json()["id"]
    assert admin.post("/api/users", {"username": "h.kadhim", "full_name": "x", "role": "viewer",
                                     "password": "Strong-pass-2026"}).status_code == 409

    me = admin.get("/api/me").get_json()["user"]["id"]
    assert admin.patch(f"/api/users/{me}", {"role": "viewer"}).status_code == 403
    assert admin.patch(f"/api/users/{me}", {"is_active": False}).status_code == 403
    promoted = admin.patch(f"/api/users/{uid}", {"role": "analyst"})
    assert promoted.get_json()["role"] == "analyst"
    assert any(a["rule_id"] == "R-05" for a in admin.get("/api/alerts").get_json()["items"])

    reset = admin.post(f"/api/users/{uid}/reset-password").get_json()
    client = app.test_client()
    assert login_form(client, "h.kadhim", reset["temporary_password"]).status_code == 302
    assert admin.patch(f"/api/users/{uid}", {"is_active": False}).status_code == 200
    assert login_form(app.test_client(), "h.kadhim", reset["temporary_password"]).status_code == 401
    assert reset["temporary_password"] not in admin.get("/api/events?per_page=100").get_data(as_text=True)

    with app.app_context():
        from app.db import get_db
        conn = get_db()
        admin_id = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[0]
        outsider = {"id": 999, "username": "other-admin", "role": "admin"}
        with pytest.raises(Exception) as exc:
            users.update_user(conn, admin_id, {"role": "viewer"}, outsider, {})
        assert "last active administrator" in str(exc.value)


# --- rules ----------------------------------------------------------------------

def test_rule_update_validation_and_effect(login):
    admin = login("admin")
    assert admin.put("/api/rules/R-01", {"threshold": 0}).status_code == 400
    assert admin.put("/api/rules/R-01", {"window_minutes": 5000}).status_code == 400
    assert admin.put("/api/rules/R-01", {"threshold": "3"}).status_code == 400
    assert admin.put("/api/rules/R-99", {"threshold": 3}).status_code == 404
    assert admin.put("/api/rules/R-01", {"threshold": 3}).get_json()["threshold"] == 3
    data = admin.post("/api/simulate", {"user": "n.saleh", "action": "login", "outcome": "failed",
                                        "ip": "10.0.9.9", "count": 3}).get_json()
    assert any(a["rule_id"] == "R-01" and a["new"] for a in data["alerts"])
    assert admin.put("/api/rules/R-01", {"enabled": False}).get_json()["enabled"] is False
    disabled = admin.post("/api/simulate", {"user": "r.jawad", "action": "login", "outcome": "failed",
                                            "ip": "10.0.9.8", "count": 5}).get_json()
    r01 = next(e for e in disabled["evaluations"] if e["rule_id"] == "R-01")
    assert r01["enabled"] is False and not r01["matched"]
    assert events(admin, q="R-01", action="other")["total"] >= 1  # rule.update audit events


# --- reports ------------------------------------------------------------------

def test_csv_export_escapes_formulas(app, login):
    login_form(app.test_client(), "=HYPERLINK(\"http://x\")", "whatever-123")
    analyst = login("s.karim")
    response = analyst.get("/reports/export.csv?period=24h")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    text = response.get_data(as_text=True).lstrip("\ufeff")
    rows = list(csv.reader(io.StringIO(text)))
    header = rows.index(next(r for r in rows if r and r[0] == "event_id"))
    actors = [r[2] for r in rows[header + 1:]]
    assert "'=HYPERLINK(\"http://x\")" in actors
    assert not any(a.startswith("=") for a in actors)
    assert events(analyst, action="other", q="report")["total"] >= 1


def test_report_summary_and_print(login):
    analyst = login("s.karim")
    analyst.post("/api/simulate", {"preset": "multiple_failed_logins"})
    summary = analyst.get("/api/reports/summary?period=24h&outcome=failed").get_json()
    assert summary["summary"]["total"] == summary["summary"]["failed"] >= 5
    assert summary["alerts"]["total"] >= 1
    page = analyst.get("/reports/print?period=7d")
    assert page.status_code == 200 and "Audit report" in page.get_data(as_text=True)
    assert analyst.get("/api/reports/summary?period=99y").status_code == 400


# --- integrity, health, stats -------------------------------------------------

def test_audit_trail_is_append_only_and_chain_detects_tampering(app, login):
    admin = login("admin")
    admin.post("/api/simulate", {"preset": "multiple_failed_logins"})
    verify = admin.post("/api/integrity/verify").get_json()
    assert verify["ok"] is True and verify["checked"] > 5
    conn = connect(app.config["DATABASE"])
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE audit_events SET outcome = 'success' WHERE id = 2")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM audit_events WHERE id = 2")
    conn.rollback()
    # Simulate an attacker with direct file access who removes the trigger and edits a row.
    conn.execute("DROP TRIGGER audit_events_no_update")
    conn.execute("UPDATE audit_events SET outcome = 'success' WHERE id = 2")
    conn.commit()
    result = audit.verify_chain(conn)
    conn.close()
    assert result["ok"] is False and result["broken_at"] == "EVT-000002"


def test_health_and_stats_reflect_database(login):
    analyst = login("s.karim")
    analyst.post("/api/simulate", {"preset": "multiple_failed_logins"})
    health = analyst.get("/api/health").get_json()
    assert health["status"] == "ok" and health["database"]["ok"] is True
    stats = analyst.get("/api/stats?range=24h&tz=-180").get_json()
    total = analyst.get("/api/events?per_page=1").get_json()["total"]
    assert stats["cards"]["total"] == total
    assert stats["cards"]["success"] + stats["cards"]["failed"] + stats["cards"]["denied"] == total
    assert stats["cards"]["open_alerts"] >= 1
    assert len(stats["series"]["buckets"]) == 24
    assert sum(b["failed"] for b in stats["series"]["buckets"]) == stats["cards"]["failed"]
    for rng, n in (("7d", 7), ("30d", 30)):
        assert len(analyst.get(f"/api/stats?range={rng}").get_json()["series"]["buckets"]) == n
    network = analyst.get("/api/network").get_json()
    assert any(ip["id"] == "10.0.4.23" and ip["suspicious"] for ip in network["ips"])


def test_all_pages_render(login):
    admin = login("admin")
    for url in ("/", "/?intro=1", "/logs", "/alerts", "/simulator", "/rules", "/users", "/reports", "/presentation"):
        response = admin.get(url)
        assert response.status_code == 200, url
    admin.post("/api/simulate", {"preset": "multiple_failed_logins"})
    uid = admin.get("/api/alerts").get_json()["items"][0]["uid"]
    assert admin.get(f"/alerts/{uid}").status_code == 200
    assert admin.get("/api/alerts/ALR-9999").status_code == 404
    assert admin.get("/does-not-exist").status_code == 404


def test_logout_is_audited_and_ends_session(login):
    session = login("s.karim")
    token = session.token
    assert session.client.post("/logout", data={"csrf_token": token}).status_code == 302
    assert session.client.get("/api/stats").status_code == 401


def test_full_demo_seed(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "seed.db"),
                      "SECRET_KEY": "seed-test-secret-0123456789abcdef-0123", "SEED_DEMO_DATA": True})
    conn = connect(app.config["DATABASE"])
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] > 1500
        statuses = {r[0] for r in conn.execute("SELECT status FROM alerts")}
        assert {"open", "acknowledged", "resolved"} <= statuses
        assert conn.execute("SELECT COUNT(*) FROM alerts WHERE rule_id = 'R-02'").fetchone()[0] >= 1
        assert audit.verify_chain(conn)["ok"] is True
    finally:
        conn.close()
