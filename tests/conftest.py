import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.app import app
from config import LOGIN_USERNAME, LOGIN_PASSWORD


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def auth_client(client):
    """Client pre-authenticated as default administrator."""
    client.post(
        "/login",
        data={"username": LOGIN_USERNAME, "password": LOGIN_PASSWORD},
        follow_redirects=True,
    )
    return client


def login(client, username=LOGIN_USERNAME, password=LOGIN_PASSWORD):
    """Helper to log in via POST /login."""
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )

