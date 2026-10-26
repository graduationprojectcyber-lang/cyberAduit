"""User administration with self-protection and last-administrator safeguards."""
import sqlite3

from . import audit
from .security import (ROLE_LABELS, USERNAME_RE, generate_temporary_password, hash_password, public_user,
                       validate_password)
from .utils import ApiError, like_escape, now_iso


def list_users(conn: sqlite3.Connection, q: str = "") -> list:
    q = (q or "").strip()[:64]
    if q:
        pattern = f"%{like_escape(q)}%"
        rows = conn.execute("SELECT * FROM users WHERE username LIKE ? ESCAPE '\\' OR full_name LIKE ? ESCAPE '\\' "
                            "ORDER BY username", (pattern, pattern))
    else:
        rows = conn.execute("SELECT * FROM users ORDER BY username")
    return [public_user(r) for r in rows]


def _get(conn, user_id: int):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise ApiError("User not found.", 404)
    return row


def _active_admins(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1").fetchone()[0]


def create_user(conn: sqlite3.Connection, data: dict, actor: dict, info: dict) -> dict:
    username = str(data.get("username") or "").strip().lower()
    if not USERNAME_RE.fullmatch(username):
        raise ApiError("Username must be 3–32 characters: lowercase letters, digits, '.', '_' or '-'.",
                       field="username")
    full_name = str(data.get("full_name") or "").strip()
    if not 1 <= len(full_name) <= 80:
        raise ApiError("Full name is required (up to 80 characters).", field="full_name")
    role = data.get("role")
    if role not in ROLE_LABELS:
        raise ApiError("Choose a valid role.", field="role")
    password = data.get("password") or ""
    validate_password(password)
    with audit.WRITE_LOCK:
        if conn.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone():
            raise ApiError("That username already exists.", 409, field="username")
        cursor = conn.execute(
            "INSERT INTO users (username, full_name, role, password_hash, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
            (username, full_name, role, hash_password(password), now_iso()))
        audit.record_event(
            conn, actor=actor["username"], actor_role=actor["role"], action="user.create", outcome="success",
            resource=f"user:{username}", message=f"{actor['username']} created user {username} ({ROLE_LABELS[role]}).",
            metadata={"target": username, "role": role}, **info)
    return public_user(_get(conn, cursor.lastrowid))


def update_user(conn: sqlite3.Connection, user_id: int, data: dict, actor: dict, info: dict) -> dict:
    with audit.WRITE_LOCK:
        row = _get(conn, user_id)
        target = row["username"]
        is_self = row["id"] == actor["id"]
        changes, events = {}, []

        if "full_name" in data:
            full_name = str(data["full_name"] or "").strip()
            if not 1 <= len(full_name) <= 80:
                raise ApiError("Full name is required (up to 80 characters).", field="full_name")
            if full_name != row["full_name"]:
                changes["full_name"] = full_name
                events.append(("user.update", f"{actor['username']} updated the name of {target}.", {"target": target}))

        if "role" in data and data["role"] != row["role"]:
            role = data["role"]
            if role not in ROLE_LABELS:
                raise ApiError("Choose a valid role.", field="role")
            if is_self:
                audit.record_event(
                    conn, actor=actor["username"], actor_role=actor["role"], action="user.role_change",
                    outcome="denied", resource=f"role: {row['role']} → {role}",
                    message=f"{actor['username']} tried to change their own role; self-service role changes are not allowed.",
                    metadata={"target": target}, **info)
                raise ApiError("You cannot change your own role.", 403, field="role")
            if row["role"] == "admin" and row["is_active"] and _active_admins(conn) <= 1:
                raise ApiError("This is the last active administrator; promote another user first.", 409, field="role")
            changes["role"] = role
            events.append(("user.role_change",
                           f"{actor['username']} changed the role of {target} from {ROLE_LABELS[row['role']]} "
                           f"to {ROLE_LABELS[role]}.",
                           {"target": target, "from": row["role"], "to": role, "resource": f"role: {row['role']} → {role}"}))

        if "is_active" in data:
            if not isinstance(data["is_active"], bool):
                raise ApiError("'is_active' must be true or false.", field="is_active")
            if data["is_active"] != bool(row["is_active"]):
                if not data["is_active"]:
                    if is_self:
                        raise ApiError("You cannot deactivate your own account.", 403, field="is_active")
                    if row["role"] == "admin" and _active_admins(conn) <= 1:
                        raise ApiError("This is the last active administrator and cannot be deactivated.", 409,
                                       field="is_active")
                changes["is_active"] = int(data["is_active"])
                verb = "activated" if data["is_active"] else "deactivated"
                events.append((f"user.{verb[:-1] if verb.endswith('d') else verb}",
                               f"{actor['username']} {verb} the account {target}.", {"target": target}))

        if not changes:
            raise ApiError("Nothing to change.")
        conn.execute(f"UPDATE users SET {', '.join(f'{k} = ?' for k in changes)} WHERE id = ?",
                     (*changes.values(), user_id))
        for action, message, meta in events:
            resource = meta.pop("resource", f"user:{target}")
            audit.record_event(conn, actor=actor["username"], actor_role=actor["role"], action=action,
                               outcome="success", resource=resource, message=message, metadata=meta,
                               commit=False, **info)
        conn.commit()
    return public_user(_get(conn, user_id))


def reset_password(conn: sqlite3.Connection, user_id: int, actor: dict, info: dict) -> dict:
    with audit.WRITE_LOCK:
        row = _get(conn, user_id)
        if row["id"] == actor["id"]:
            raise ApiError("Use a different administrator account to reset your own password.", 403)
        temporary = generate_temporary_password()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(temporary), user_id))
        audit.record_event(
            conn, actor=actor["username"], actor_role=actor["role"], action="user.password_reset", outcome="success",
            resource=f"user:{row['username']}", message=f"{actor['username']} reset the password of {row['username']}.",
            metadata={"target": row["username"]}, **info)
    # The temporary password is returned once to the administrator and never logged.
    return {"user": public_user(_get(conn, user_id)), "temporary_password": temporary}
