"""JSON API used by the frontend. Every endpoint requires an authenticated session."""
from flask import Blueprint, current_app, g, jsonify, request, session

from . import alerts, audit, detection, events, reports, simulator, stats, users
from .db import get_db
from .security import ROLE_LABELS, has_role, login_required, request_info, role_required
from .utils import ApiError, alert_uid, clamp_int, iso, parse_uid, utcnow

bp = Blueprint("api", __name__, url_prefix="/api")


def _body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Expected a JSON object in the request body.")
    return data


@bp.get("/me")
@login_required
def me():
    return jsonify(user=g.user, permissions={
        "simulate": has_role("analyst"), "handle_alerts": has_role("analyst"), "export": has_role("analyst"),
        "manage_users": has_role("admin"), "manage_rules": has_role("admin"), "verify_integrity": has_role("admin")})


@bp.get("/health")
@login_required
def health():
    try:
        return jsonify(stats.health(get_db(), current_app.config["VERSION"]))
    except Exception:  # report an honest failure instead of a fake "operational" state
        current_app.logger.exception("Health check failed")
        return jsonify(status="degraded", server_time=iso(utcnow()),
                       application={"ok": True, "version": current_app.config["VERSION"]},
                       database={"ok": False, "engine": "SQLite"}), 503


@bp.get("/stats")
@login_required
def dashboard_stats():
    return jsonify(stats.dashboard_stats(get_db(), request.args.get("range", "24h"),
                                         clamp_int(request.args.get("tz"), 0, -900, 900)))


@bp.get("/network")
@login_required
def network():
    return jsonify(stats.network(get_db(), clamp_int(request.args.get("hours"), 24, 1, 24 * 7)))


@bp.get("/events")
@login_required
def list_events():
    return jsonify(events.query_events(get_db(), request.args))


@bp.get("/events/<event_ref>")
@login_required
def event_detail(event_ref):
    event_id = parse_uid(event_ref, "EVT")
    if event_id is None:
        raise ApiError("Event not found.", 404)
    return jsonify(events.event_detail(get_db(), event_id))


# --- alerts ---------------------------------------------------------------

@bp.get("/alerts")
@login_required
def list_alerts():
    return jsonify(alerts.list_alerts(get_db(), request.args))


@bp.get("/alerts/<uid>")
@login_required
def alert_detail(uid):
    data = alerts.alert_detail(get_db(), uid)
    data["can_act"] = has_role("analyst")
    return jsonify(data)


@bp.post("/alerts/<uid>/acknowledge")
@role_required("analyst")
def acknowledge_alert(uid):
    return jsonify(alerts.acknowledge(get_db(), uid, g.user, request_info()))


@bp.post("/alerts/<uid>/resolve")
@role_required("analyst")
def resolve_alert(uid):
    return jsonify(alerts.resolve(get_db(), uid, _body().get("resolution"), g.user, request_info()))


@bp.post("/alerts/<uid>/notes")
@role_required("analyst")
def add_alert_note(uid):
    return jsonify(alerts.add_note(get_db(), uid, _body().get("body"), g.user, request_info())), 201


@bp.get("/notifications")
@login_required
def notifications():
    seen = session.get("notif_seen", "")
    rows = get_db().execute(
        "SELECT id, title, severity, status, created_at, rule_id FROM alerts ORDER BY created_at DESC, id DESC LIMIT 8"
    ).fetchall()
    items = [{"uid": alert_uid(r["id"]), "title": r["title"], "severity": r["severity"], "status": r["status"],
              "rule_id": r["rule_id"], "created_at": r["created_at"], "unread": r["created_at"] > seen}
             for r in rows]
    unread = get_db().execute("SELECT COUNT(*) FROM alerts WHERE created_at > ?", (seen,)).fetchone()[0]
    return jsonify(items=items, unread=unread)


@bp.post("/notifications/seen")
@login_required
def notifications_seen():
    session["notif_seen"] = iso(utcnow())
    return jsonify(unread=0)


# --- detection rules ------------------------------------------------------

@bp.get("/rules")
@login_required
def list_rules():
    return jsonify(items=detection.rule_overview(get_db()), can_edit=has_role("admin"))


@bp.put("/rules/<rule_id>")
@role_required("admin")
def update_rule(rule_id):
    return jsonify(detection.update_rule(get_db(), rule_id.upper(), _body(), g.user, request_info()))


# --- simulator --------------------------------------------------------------

@bp.get("/simulator/options")
@login_required
def simulator_options():
    data = simulator.options(get_db())
    data["can_simulate"] = has_role("analyst")
    return jsonify(data)


@bp.get("/simulator/history")
@login_required
def simulator_history():
    return jsonify(items=simulator.history(get_db()))


@bp.post("/simulate")
@role_required("analyst")
def simulate():
    return jsonify(simulator.run(get_db(), _body(), g.user)), 201


# --- users ------------------------------------------------------------------

@bp.get("/users")
@role_required("admin")
def list_users():
    return jsonify(items=users.list_users(get_db(), request.args.get("q", "")), roles=ROLE_LABELS,
                   current_user_id=g.user["id"])


@bp.post("/users")
@role_required("admin")
def create_user():
    return jsonify(users.create_user(get_db(), _body(), g.user, request_info())), 201


@bp.patch("/users/<int:user_id>")
@role_required("admin")
def update_user(user_id):
    return jsonify(users.update_user(get_db(), user_id, _body(), g.user, request_info()))


@bp.post("/users/<int:user_id>/reset-password")
@role_required("admin")
def reset_password(user_id):
    return jsonify(users.reset_password(get_db(), user_id, g.user, request_info()))


# --- reports and integrity --------------------------------------------------

@bp.get("/reports/summary")
@login_required
def report_summary():
    data = reports.report_data(get_db(), request.args)
    data["can_export"] = has_role("analyst")
    return jsonify(data)


@bp.post("/integrity/verify")
@role_required("admin")
def verify_integrity():
    conn = get_db()
    result = audit.verify_chain(conn)
    audit.record_event(conn, actor=g.user["username"], actor_role=g.user["role"], action="integrity.verify",
                       outcome="success" if result["ok"] else "failed", resource="audit_events",
                       message=(f"Audit chain verified: {result['checked']} records intact." if result["ok"] else
                                f"Audit chain verification failed at {result['broken_at']}."),
                       metadata={"checked": result["checked"], "broken_at": result["broken_at"]}, **request_info())
    result["verified_at"] = iso(utcnow())
    return jsonify(result)
