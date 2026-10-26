"""Small shared helpers: time handling, identifiers and validation errors."""
import re
from datetime import datetime, timezone

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


class ApiError(Exception):
    """An error that is safe to show to the client."""

    def __init__(self, message: str, status: int = 400, field: str | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.field = field


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO_FMT)


def now_iso() -> str:
    return iso(utcnow())


def parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are treated as UTC."""
    text = (value or "").strip()
    if not text:
        raise ValueError("empty timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0)


def event_uid(event_id: int) -> str:
    return f"EVT-{int(event_id):06d}"


def alert_uid(alert_id: int) -> str:
    return f"ALR-{int(alert_id):04d}"


def parse_uid(value: str, prefix: str) -> int | None:
    """Accept 'ALR-0042', 'alr-42' or '42' and return the integer id."""
    match = re.fullmatch(rf"(?:{prefix}-)?0*(\d{{1,9}})", (value or "").strip(), re.IGNORECASE)
    return int(match.group(1)) if match else None


def clamp_int(value, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
