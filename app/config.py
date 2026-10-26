"""Application configuration."""
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


def load_secret_key(instance_dir: Path) -> str:
    """Return a persistent random secret key stored outside the source tree."""
    instance_dir.mkdir(parents=True, exist_ok=True)
    key_file = instance_dir / "secret_key"
    if key_file.exists():
        key = key_file.read_text(encoding="utf-8").strip()
        if len(key) >= 32:
            return key
    key = secrets.token_hex(32)
    key_file.write_text(key, encoding="utf-8")
    return key


class Config:
    APP_NAME = "CyberAudit Monitor"
    APP_SUBTITLE = "Cybersecurity Audit and Monitoring System"
    VERSION = "1.0.0"
    DATABASE = str(INSTANCE_DIR / "cyberaudit.db")
    SEED_DEMO_DATA = True

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = "cyberaudit_session"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    MAX_CONTENT_LENGTH = 64 * 1024
    JSON_SORT_KEYS = False

    # Event stream polling interval used by the frontend (milliseconds).
    POLL_INTERVAL_MS = 3000
