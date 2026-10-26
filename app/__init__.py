"""CyberAudit Monitor — Flask application factory."""
import logging
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from . import detection, security
from .config import INSTANCE_DIR, Config, load_secret_key
from .db import close_db, connect, create_schema, is_seeded
from .seed import create_demo_users, seed_demo_data
from .utils import ApiError, iso, utcnow


def init_database(app: Flask) -> None:
    conn = connect(app.config["DATABASE"])
    try:
        create_schema(conn)
        detection.ensure_rules(conn)
        if not is_seeded(conn):
            if app.config["SEED_DEMO_DATA"]:
                result = seed_demo_data(conn)
                app.logger.info("Seeded demo data: %(events)s events, %(alerts)s alerts", result)
            else:
                create_demo_users(conn, iso(utcnow()))
    finally:
        conn.close()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = load_secret_key(Path(app.config.get("INSTANCE_PATH_OVERRIDE") or INSTANCE_DIR))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    init_database(app)
    app.teardown_appcontext(close_db)

    @app.before_request
    def _before():
        security.load_current_user()
        security.check_csrf()

    app.after_request(security.apply_security_headers)

    @app.context_processor
    def _context():
        return {
            "csrf_token": security.csrf_token,
            "current_user": g.get("user"),
            "has_role": security.has_role,
            "app_name": app.config["APP_NAME"],
            "app_subtitle": app.config["APP_SUBTITLE"],
            "app_version": app.config["VERSION"],
            "poll_interval": app.config["POLL_INTERVAL_MS"],
        }

    def _wants_json() -> bool:
        return request.path.startswith("/api/")

    @app.errorhandler(ApiError)
    def _api_error(err: ApiError):
        if _wants_json() or request.path.endswith(".csv"):
            return jsonify(error=err.message, field=err.field), err.status
        return render_template("error.html", code=err.status, message=err.message), err.status

    @app.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        messages = {403: "You do not have permission to open this page.", 404: "This page does not exist.",
                    405: "This request method is not allowed here.", 413: "The request is too large."}
        message = messages.get(err.code, err.description)
        if _wants_json():
            return jsonify(error=message), err.code
        return render_template("error.html", code=err.code, message=message), err.code

    @app.errorhandler(Exception)
    def _unexpected(err: Exception):
        app.logger.exception("Unhandled error on %s %s", request.method, request.path)
        message = "An unexpected server error occurred. The details were written to the server log."
        if _wants_json():
            return jsonify(error=message), 500
        return render_template("error.html", code=500, message=message), 500

    from .api import bp as api_bp
    from .views import bp as pages_bp
    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp)
    return app
