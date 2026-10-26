"""Authentication, role-based authorization, CSRF protection and security headers."""
import hmac
import re
import secrets
from functools import wraps

from flask import abort, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit
from .db import get_db
from .utils import ApiError, now_iso

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}
ROLE_LABELS = {"viewer": "Viewer", "analyst": "Security Analyst", "admin": "Administrator"}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < 10 or len(password) > 128:
        raise ApiError("Password must be 10–128 characters long.", field="password")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ApiError("Password must contain at least one letter and one digit.", field="password")


def generate_temporary_password() -> str:
    return "Tmp-" + secrets.token_urlsafe(9) + "7"


def request_info() -> dict:
    return {"source_ip": request.remote_addr, "http_method": request.method, "route": request.path}


def public_user(row) -> dict:
    """User fields that are safe to expose. Password hashes never leave the server."""
    return {
        "id": row["id"],
        "username": row["username"],
        "full_name": row["full_name"],
        "role": row["role"],
        "role_label": ROLE_LABELS[row["role"]],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
    }


# --- authentication -------------------------------------------------------

def authenticate(username: str, password: str):
    """Check credentials, record the attempt in the audit trail and return the user or None."""
    conn = get_db()
    username = (username or "").strip()[:64]
    row = conn.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    info = request_info()
    if row and row["is_active"] and check_password_hash(row["password_hash"], password or ""):
        with audit.WRITE_LOCK:
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_iso(), row["id"]))
            audit.record_event(conn, actor=row["username"], actor_role=row["role"], action="auth.login",
                               outcome="success", resource="/login",
                               message=f"{row['username']} signed in.", **info)
        return row
    reason = "account_disabled" if row and not row["is_active"] else "invalid_credentials"
    audit.record_event(
        conn, actor=username or "(blank)", actor_role=row["role"] if row else None, action="auth.login",
        outcome="failed", resource="/login",
        message=f"Sign-in for {username or '(blank)'} failed: "
                + ("account is deactivated." if reason == "account_disabled" else "invalid credentials."),
        metadata={"reason": reason, "known_account": bool(row)}, **info)
    return None


def login_user(row) -> None:
    session.clear()  # prevent session fixation
    session.permanent = True
    session["user_id"] = row["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)


def load_current_user() -> None:
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None or not row["is_active"]:
        session.clear()
        return
    g.user = public_user(row)


# --- CSRF -----------------------------------------------------------------

def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_csrf() -> None:
    if request.method not in UNSAFE_METHODS:
        return
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        if request.path.startswith("/api/"):
            raise ApiError("Security token missing or expired. Reload the page and try again.", 403)
        abort(403)


# --- authorization --------------------------------------------------------

def _is_api() -> bool:
    return request.path.startswith("/api/") or request.path.endswith(".csv")


def record_denied(required_role: str) -> None:
    user = g.get("user")
    audit.record_event(
        get_db(), actor=user["username"] if user else "anonymous", actor_role=user["role"] if user else None,
        action="access.denied", outcome="denied", resource=request.path,
        message=f"{user['username'] if user else 'anonymous'} was denied {request.method} {request.path} "
                f"(requires {ROLE_LABELS[required_role]}).",
        metadata={"required_role": required_role}, **request_info())


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            if _is_api():
                return jsonify(error="Authentication required."), 401
            return redirect(url_for("pages.login", next=request.full_path if request.query_string else request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(min_role: str):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if ROLE_RANK[g.user["role"]] < ROLE_RANK[min_role]:
                record_denied(min_role)
                if _is_api():
                    return jsonify(error=f"This action requires the {ROLE_LABELS[min_role]} role."), 403
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def has_role(min_role: str) -> bool:
    user = g.get("user")
    return bool(user) and ROLE_RANK[user["role"]] >= ROLE_RANK[min_role]


def apply_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response
