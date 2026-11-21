import pytest
import io
import json
from dashboard.app import app
from config import LOGIN_USERNAME, LOGIN_PASSWORD, SAMPLES_DIR


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client


def login(client, username=LOGIN_USERNAME, password=LOGIN_PASSWORD):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def test_login_required_redirects(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_success(client):
    res = login(client)
    assert res.status_code == 200
    assert b"Security Operations Dashboard" in res.data or b"Dashboard" in res.data


def test_login_invalid_credentials(client):
    res = login(client, username="admin", password="wrongpassword")
    assert (
        b"No account found" in res.data
        or b"Incorrect password" in res.data
        or b"Invalid username or password" in res.data
    )


def test_dashboard_authenticated(client):
    login(client)
    res = client.get("/")
    assert res.status_code == 200
    assert b"Total Flows Inspected" in res.data or b"Total Flows" in res.data


def test_api_summary(client):
    login(client)
    res = client.get("/api/summary")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_flows" in data
    assert "attacks" in data
    assert "benign" in data


def test_api_alerts(client):
    login(client)
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)


def test_blocked_ips_lifecycle(client):
    login(client)
    # Add IP
    res = client.post(
        "/blocked-ips",
        data={"ip": "198.51.100.42", "reason": "Test malicious probe"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"198.51.100.42" in res.data


def test_sample_load_and_prediction(client):
    login(client)
    res = client.post("/upload/load-sample/sample_mixed_traffic.csv", follow_redirects=True)
    assert res.status_code == 200
    # Should redirect to upload_results with prediction data
    assert b"Analysis Completed Successfully" in res.data or b"Complete Analysis" in res.data
    assert b"Classified Flow Records" in res.data
    assert b"Export Predictions CSV" in res.data or b"Export CSV" in res.data


def test_upload_incompatible_file_shows_error(client):
    login(client)
    data = {
        "traffic_file": (io.BytesIO(b"name,age,city\nAlice,30,NYC\n"), "random.csv")
    }
    res = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"Analysis failed" in res.data or b"Incompatible dataset format" in res.data


def test_live_stream_toggle(client):
    login(client)
    res = client.post("/api/live/toggle", json={"action": "start", "mode": "demo"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] in ["running", "stopped"]

    res_stream = client.get("/api/live/stream")
    assert res_stream.status_code == 200
    stream_data = res_stream.get_json()
    assert "records" in stream_data
    assert "total_streamed" in stream_data

    # Test pause and resume
    res_pause = client.post("/api/live/toggle", json={"action": "pause"})
    assert res_pause.status_code == 200
    assert res_pause.get_json()["status"] == "paused"

    res_resume = client.post("/api/live/toggle", json={"action": "resume"})
    assert res_resume.status_code == 200
    assert res_resume.get_json()["status"] == "running"

    # Stop stream
    client.post("/api/live/toggle", json={"action": "stop"})


def test_api_live_interfaces(client):
    login(client)
    res = client.get("/api/live/interfaces")
    assert res.status_code == 200
    data = res.get_json()
    assert "interfaces" in data
    assert "can_sniff" in data


def test_download_alerts_csv(client):
    login(client)
    # First ensure at least one sample is analyzed to generate alerts
    client.post("/upload/load-sample/sample_attack_traffic.csv", follow_redirects=True)
    res = client.get("/download/alerts/csv")
    assert res.status_code == 200
    assert "text/csv" in res.content_type


def test_signin_page_redesign_elements_and_no_emojis(client):
    import re
    res = client.get("/login")
    assert res.status_code == 200
    data = res.get_data(as_text=True)

    # Layout elements
    assert "Email address" in data
    assert "Enter your email address" in data
    assert "Password" in data
    assert "Enter your password" in data
    assert "Remember Me" in data
    assert "Forgot password?" in data
    assert "Sign In" in data
    assert "Or continue with" in data
    assert "Continue with Google" in data
    assert "AI-BASED INTRUSION DETECTION SYSTEM" in data

    # Clean SVGs present
    assert "brand-shield" in data
    assert "eye-icon" in data
    assert "google-logo" in data

    # Strict zero emoji enforcement
    emoji_pattern = re.compile(r"[\U00010000-\U0010ffff]|[\u2600-\u27ff]")
    emojis = emoji_pattern.findall(data)
    assert len(emojis) == 0, f"Found unexpected emojis on login page: {emojis}"


def test_google_oauth_unconfigured_redirect(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "")
    res = client.get("/auth/google", follow_redirects=True)
    assert res.status_code == 200
    assert "Google OAuth is not configured" in res.get_data(as_text=True)


def test_google_oauth_redirect_when_configured(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "123456789-mock.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "mock-secret-456")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:5000/auth/google/callback")

    res = client.get("/auth/google", follow_redirects=False)
    assert res.status_code == 302
    location = res.headers["Location"]
    assert "accounts.google.com" in location
    assert "client_id=123456789-mock.apps.googleusercontent.com" in location
    assert "scope=openid+email+profile" in location or "scope=openid%20email%20profile" in location


def test_google_oauth_callback_success(client, monkeypatch):
    from unittest.mock import patch, MagicMock
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "123456789-mock.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "mock-secret-456")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:5000/auth/google/callback")

    with client.session_transaction() as sess:
        sess["oauth_state"] = "mock-state-abc"
        sess["oauth_nonce"] = "mock-nonce-xyz"

    mock_token_resp = MagicMock(status_code=200)
    mock_token_resp.json.return_value = {"access_token": "token-xyz-123"}

    mock_userinfo_resp = MagicMock(status_code=200)
    mock_userinfo_resp.json.return_value = {
        "email": "analyst@secureflow.ai",
        "email_verified": True,
        "name": "Security Analyst",
    }

    with patch("requests.post", return_value=mock_token_resp), patch("requests.get", return_value=mock_userinfo_resp):
        res = client.get("/auth/google/callback?code=mock-auth-code&state=mock-state-abc", follow_redirects=True)
        assert res.status_code == 200
        assert b"Security Operations Dashboard" in res.data or b"Dashboard" in res.data


def test_google_oauth_callback_user_cancelled(client):
    res = client.get("/auth/google/callback?error=access_denied&error_description=User+cancelled", follow_redirects=True)
    assert res.status_code == 200
    assert "cancelled" in res.get_data(as_text=True).lower()


def test_google_oauth_callback_invalid_state_rejected(client):
    with client.session_transaction() as sess:
        sess["oauth_state"] = "legit-state"

    res = client.get("/auth/google/callback?code=mock-code&state=tampered-state", follow_redirects=True)
    assert res.status_code == 200
    assert "Security validation failed" in res.get_data(as_text=True)


def test_google_oauth_callback_unverified_email_rejected(client, monkeypatch):
    from unittest.mock import patch, MagicMock
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "mock-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "mock-secret")

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-123"

    mock_token = MagicMock(status_code=200)
    mock_token.json.return_value = {"access_token": "tok"}

    mock_user = MagicMock(status_code=200)
    mock_user.json.return_value = {"email": "unverified@gmail.com", "email_verified": False}

    with patch("requests.post", return_value=mock_token), patch("requests.get", return_value=mock_user):
        res = client.get("/auth/google/callback?code=mock-code&state=state-123", follow_redirects=True)
        assert res.status_code == 200
        assert "not verified" in res.get_data(as_text=True)



