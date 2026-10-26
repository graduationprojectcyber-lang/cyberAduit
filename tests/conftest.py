import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app  # noqa: E402

PASSWORDS = {"admin": "Admin@12345", "s.karim": "Analyst@12345", "r.jawad": "Analyst@12345",
             "m.ali": "Viewer@12345", "a.hassan": "Viewer@12345", "n.saleh": "Viewer@12345"}


@pytest.fixture
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "SECRET_KEY": "test-secret-key-0123456789abcdef-0123456789",
        "SEED_DEMO_DATA": False,
    })


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf[-_]token" (?:content|value)="([^"]+)"', html)
    assert match, "CSRF token not found in page"
    return match.group(1)


class Session:
    """A logged-in test client that sends the CSRF header automatically."""

    def __init__(self, client, token):
        self.client, self.token = client, token

    def get(self, url, **kw):
        return self.client.get(url, **kw)

    def post(self, url, json=None, **kw):
        return self.client.post(url, json=json if json is not None else {}, headers={"X-CSRF-Token": self.token}, **kw)

    def put(self, url, json=None):
        return self.client.put(url, json=json or {}, headers={"X-CSRF-Token": self.token})

    def patch(self, url, json=None):
        return self.client.patch(url, json=json or {}, headers={"X-CSRF-Token": self.token})


def login_form(client, username, password):
    token = _csrf(client.get("/login").get_data(as_text=True))
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token})


@pytest.fixture
def login(app):
    def _login(username, password=None):
        client = app.test_client()
        response = login_form(client, username, password or PASSWORDS[username])
        assert response.status_code == 302, response.get_data(as_text=True)[:300]
        token = _csrf(client.get("/logs").get_data(as_text=True))
        return Session(client, token)
    return _login
