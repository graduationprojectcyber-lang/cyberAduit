"""HTML pages, sign-in/out and report exports."""
from flask import Blueprint, Response, g, redirect, render_template, request, session, url_for

from . import audit, reports
from .db import get_db
from .security import authenticate, login_required, login_user, request_info, role_required
from .utils import ApiError, iso, utcnow

bp = Blueprint("pages", __name__)


def _safe_next(target: str | None) -> str:
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("pages.dashboard")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user and request.method == "GET":
        return redirect(url_for("pages.dashboard"))
    error = None
    if request.method == "POST":
        row = authenticate(request.form.get("username", ""), request.form.get("password", ""))
        if row:
            login_user(row)
            session["intro_pending"] = True
            session["notif_seen"] = iso(utcnow())
            return redirect(_safe_next(request.args.get("next")))
        error = "Incorrect username or password, or the account is deactivated."
    return render_template("login.html", error=error), (401 if error else 200)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit.record_event(get_db(), actor=g.user["username"], actor_role=g.user["role"], action="auth.logout",
                       outcome="success", resource="/logout", message=f"{g.user['username']} signed out.",
                       **request_info())
    session.clear()
    return redirect(url_for("pages.login"))


@bp.route("/")
@login_required
def dashboard():
    play_intro = bool(session.pop("intro_pending", False)) or request.args.get("intro") == "1"
    return render_template("dashboard.html", active="overview", play_intro=play_intro)


@bp.route("/logs")
@login_required
def logs():
    return render_template("logs.html", active="logs")


@bp.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html", active="alerts")


@bp.route("/alerts/<uid>")
@login_required
def alert_detail(uid):
    return render_template("investigation.html", active="alerts", alert_uid=uid.upper())


@bp.route("/simulator")
@login_required
def simulator():
    return render_template("simulator.html", active="simulator")


@bp.route("/rules")
@login_required
def rules():
    return render_template("rules.html", active="rules")


@bp.route("/users")
@role_required("admin")
def users():
    return render_template("users.html", active="users")


@bp.route("/reports")
@login_required
def reports_page():
    return render_template("reports.html", active="reports")


@bp.route("/presentation")
@login_required
def presentation():
    return render_template("presentation.html", active="presentation")


@bp.route("/reports/export.csv")
@role_required("analyst")
def export_csv():
    content, count = reports.export_csv(get_db(), request.args, g.user["username"])
    audit.record_event(get_db(), actor=g.user["username"], actor_role=g.user["role"], action="report.export",
                       outcome="success", resource="report.csv",
                       message=f"{g.user['username']} exported {count} audit records to CSV.",
                       metadata={"format": "csv", "rows": count,
                                 **{f"filter_{k}": v for k, v in request.args.items() if k != "csrf_token"}},
                       **request_info())
    filename = f"cyberaudit-report-{utcnow():%Y%m%d-%H%M%S}.csv"
    return Response(content, mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@bp.route("/reports/print")
@role_required("analyst")
def print_report():
    data = reports.report_data(get_db(), request.args, limit=1000)
    audit.record_event(get_db(), actor=g.user["username"], actor_role=g.user["role"], action="report.export",
                       outcome="success", resource="report.html",
                       message=f"{g.user['username']} generated a printable report ({data['summary']['total']} records).",
                       metadata={"format": "html", "rows": data["summary"]["total"]}, **request_info())
    return render_template("report_print.html", report=data)
