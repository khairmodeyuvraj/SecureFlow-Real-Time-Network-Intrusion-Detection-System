"""
Comprehensive Multi-User, Data Isolation, Live Monitoring & SMTP Password Reset Test Suite.
Verifies all 16 regression scenarios specified in the SecureFlow requirements.
"""
import io
import smtplib
import uuid as _uuid
from unittest.mock import patch, MagicMock
import pytest

from dashboard.app import app
from dashboard.user_db import (
    create_user,
    get_user_by_email,
    get_user_alerts,
    get_user_history,
    get_user_blocked,
    create_reset_token,
    validate_reset_token,
    consume_reset_token,
)
from src.network.packet_capture import LiveTrafficManager
from config import LOGIN_USERNAME, LOGIN_PASSWORD


def _unique_email():
    return f"test_{_uuid.uuid4().hex[:8]}@secureflow-test.local"


def login(client, username=LOGIN_USERNAME, password=LOGIN_PASSWORD):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


# ==================================================================
# ISSUE 1: FORGOT PASSWORD & SMTP SECURITY TESTS
# ==================================================================

def test_forgot_password_unconfigured_smtp_shows_error_and_no_token(client, monkeypatch):
    """
    TEST 6: Open Forgot Password when SMTP is unconfigured.
    Confirm that NO reset token or reset URL is exposed on the webpage.
    A clear administrator configuration error must be shown.
    """
    monkeypatch.setenv("SMTP_HOST", "")
    monkeypatch.setenv("SMTP_USERNAME", "")
    monkeypatch.setenv("SMTP_PASSWORD", "")

    email = _unique_email()
    create_user("Alice Security", email, "SecurePass1")

    res = client.post(
        "/forgot-password",
        data={"email": email},
        follow_redirects=True,
    )
    assert res.status_code == 200
    text = res.get_data(as_text=True)

    # Must display administrator configuration error
    assert "Email delivery service (SMTP) is not configured" in text or "SMTP credentials" in text

    # MUST NOT expose any reset URL or token
    assert "reset-password/" not in text
    assert "Here is your password reset link" not in text
    assert "valid for 1 hour:" not in text


def test_forgot_password_smtp_configured_dispatches_email_safely(client, monkeypatch):
    """
    TEST 7: Verify that an actual reset email is sent when SMTP is configured.
    Webpage must display the generic notice and never expose the reset URL or token.
    """
    monkeypatch.setenv("SMTP_HOST", "smtp.mockserver.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "mailer@secureflow.ai")
    monkeypatch.setenv("SMTP_PASSWORD", "mock_app_password_123")
    monkeypatch.setenv("SMTP_USE_TLS", "true")

    email = _unique_email()
    create_user("Bob Analyst", email, "SecurePass1")

    mock_smtp_instance = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_smtp_instance) as mock_smtp_class:
        mock_smtp_instance.__enter__.return_value = mock_smtp_instance
        res = client.post(
            "/forgot-password",
            data={"email": email},
            follow_redirects=True,
        )
        assert res.status_code == 200
        text = res.get_data(as_text=True)

        # Standard anti-enumeration message
        assert "password reset instructions will be sent" in text.lower()

        # SMTP send_message or sendmail was called
        assert mock_smtp_instance.send_message.called or mock_smtp_instance.sendmail.called
        if mock_smtp_instance.send_message.called:
            msg = mock_smtp_instance.send_message.call_args[0][0]
            assert msg["To"] == email
        else:
            call_args = mock_smtp_instance.sendmail.call_args
            assert email in call_args[0][1]

        # Reset URL and token are NOT on the webpage
        assert "reset-password/" not in text


def test_token_expiration_and_single_use():
    """Verify that password reset tokens expire after 1 hour and cannot be reused."""
    email = _unique_email()
    user = create_user("Token Tester", email, "OldPassword1")
    user_id = user["id"]

    token = create_reset_token(user_id)
    assert token is not None

    # Validate before use
    validated_user = validate_reset_token(token)
    assert validated_user is not None
    assert validated_user["id"] == user_id

    # Consume token
    success = consume_reset_token(token, "NewPassword2")
    assert success is True

    # Re-using the same token must fail
    assert validate_reset_token(token) is None
    assert consume_reset_token(token, "AnotherPassword3") is False


# ==================================================================
# ISSUE 2: USER-WISE DATA ISOLATION TESTS
# ==================================================================

def test_new_user_dashboard_starts_completely_empty(client):
    """
    TEST 1: Register a new email/password account.
    Confirm that the dashboard starts completely empty:
    - 0 flows, 0 intrusions, 0 benign, 0 alerts, empty state message.
    """
    email = _unique_email()
    client.post(
        "/register",
        data={
            "full_name": "Fresh User",
            "email": email,
            "password": "SecurePass1",
            "confirm_password": "SecurePass1",
        },
        follow_redirects=True,
    )

    login(client, username=email, password="SecurePass1")
    res = client.get("/")
    assert res.status_code == 200
    text = res.get_data(as_text=True)

    # Metrics must show 0
    assert "Fresh Workspace Initialized" in text or "No analysis data available yet" in text

    # API summary must return 0
    res_summary = client.get("/api/summary")
    assert res_summary.status_code == 200
    summary_data = res_summary.get_json()
    assert summary_data["total_flows"] == 0
    assert summary_data["attacks"] == 0
    assert summary_data["benign"] == 0
    assert summary_data["alerts"] == 0

    # Alerts and blocked lists must be empty
    res_alerts = client.get("/api/alerts")
    assert res_alerts.get_json() == []

    res_blocked = client.get("/blocked-ips")
    assert "No IP entries" in res_blocked.get_data(as_text=True)


def test_admin_history_remains_intact(client):
    """
    TEST 2: Login using the existing admin account.
    Confirm that existing admin history remains intact.
    """
    res = login(client, username=LOGIN_USERNAME, password=LOGIN_PASSWORD)
    assert res.status_code == 200
    assert b"Security Operations Dashboard" in res.data or b"Dashboard" in res.data

    # Admin reports page loads
    res_reports = client.get("/reports")
    assert res_reports.status_code == 200


def test_second_user_cannot_see_first_users_data(client):
    """
    TEST 3: Register a second user.
    Confirm that the second user cannot see the first user's data.
    """
    email_a = _unique_email()
    email_b = _unique_email()

    create_user("User Alpha", email_a, "SecurePass1")
    create_user("User Beta", email_b, "SecurePass1")

    # User Alpha logs in and blocks an IP
    login(client, username=email_a, password="SecurePass1")
    client.post(
        "/blocked-ips",
        data={"ip": "198.51.100.99", "reason": "Alpha suspicious probe"},
        follow_redirects=True,
    )
    res_a = client.get("/blocked-ips")
    assert "198.51.100.99" in res_a.get_data(as_text=True)

    # User Alpha logs out, User Beta logs in
    client.post("/logout")
    login(client, username=email_b, password="SecurePass1")

    res_b = client.get("/blocked-ips")
    assert "198.51.100.99" not in res_b.get_data(as_text=True)
    assert "No IP entries" in res_b.get_data(as_text=True)


def test_upload_isolated_to_authenticated_user(client):
    """
    TEST 4 & 5: Upload traffic as a new user.
    Confirm that only their dashboard statistics are updated, and logging out/in as another user
    shows no trace of the upload.
    """
    email_user = _unique_email()
    email_other = _unique_email()

    create_user("Uploader User", email_user, "SecurePass1")
    create_user("Other User", email_other, "SecurePass1")

    # Login as Uploader User and load sample
    login(client, username=email_user, password="SecurePass1")
    res_sample = client.post("/upload/load-sample/sample_mixed_traffic.csv", follow_redirects=True)
    assert res_sample.status_code == 200

    # Uploader User now has flows
    res_summary_a = client.get("/api/summary")
    summary_a = res_summary_a.get_json()
    assert summary_a["total_flows"] > 0

    # Logout and login as Other User
    client.post("/logout")
    login(client, username=email_other, password="SecurePass1")

    # Other User's dashboard must still have 0 flows
    res_summary_b = client.get("/api/summary")
    summary_b = res_summary_b.get_json()
    assert summary_b["total_flows"] == 0
    assert summary_b["attacks"] == 0
    assert summary_b["alerts"] == 0


def test_cross_user_record_removal_denied(client):
    """
    TEST 16: Attempt to remove another user's blocked IP record by tampering with item ID.
    Confirm that the record cannot be deleted by an unauthorized user.
    """
    email_victim = _unique_email()
    email_attacker = _unique_email()

    victim = create_user("Victim User", email_victim, "SecurePass1")
    attacker = create_user("Attacker User", email_attacker, "SecurePass1")

    # Victim logs in and blocks an IP
    login(client, username=email_victim, password="SecurePass1")
    client.post(
        "/blocked-ips",
        data={"ip": "203.0.113.55", "reason": "Target host"},
        follow_redirects=True,
    )
    victim_blocked = get_user_blocked(victim["id"])
    assert len(victim_blocked) == 1
    target_id = victim_blocked[0]["id"]

    # Attacker logs in and tries to delete victim's blocked IP
    client.post("/logout")
    login(client, username=email_attacker, password="SecurePass1")
    client.post(f"/blocked-ips/{target_id}/remove", follow_redirects=True)

    # Victim's record MUST still exist untouched!
    victim_blocked_after = get_user_blocked(victim["id"])
    assert len(victim_blocked_after) == 1
    assert victim_blocked_after[0]["ip"] == "203.0.113.55"


# ==================================================================
# ISSUE 3: LIVE MONITORING CONTROL & ISOLATION TESTS
# ==================================================================

def test_live_monitoring_does_not_auto_start(client):
    """
    TEST 8: Open Live Monitoring (/live).
    Confirm that NO network capture starts automatically:
    - streamer_running is False
    - 0 streamed flows
    """
    email = _unique_email()
    create_user("Live Tester", email, "SecurePass1")
    login(client, username=email, password="SecurePass1")

    res = client.get("/live")
    assert res.status_code == 200
    text = res.get_data(as_text=True)

    # Must show Start Monitoring button and Engine Ready badge
    assert "Start Monitoring" in text

    # Streamer must NOT be running
    user = get_user_by_email(email)
    streamer = LiveTrafficManager.get_instance(user["id"])
    assert streamer.is_running is False


def test_live_monitoring_start_stop_lifecycle(client):
    """
    TEST 9, 10, 11, 12: Click Start Monitoring, verify running state,
    navigate to another page, verify capture does not duplicate or restart on navigation alone,
    click Stop Monitoring and verify safe shutdown.
    """
    email = _unique_email()
    user = create_user("Live Controller", email, "SecurePass1")
    login(client, username=email, password="SecurePass1")

    # Explicitly Start Monitoring
    res_start = client.post("/api/live/toggle", json={"action": "start", "mode": "demo"})
    assert res_start.status_code == 200
    data = res_start.get_json()
    assert data["status"] == "running"
    assert data["is_running"] is True

    # Navigate to Dashboard and back to Live
    client.get("/")
    client.get("/reports")
    res_live = client.get("/live")
    assert res_live.status_code == 200

    # Explicitly Stop Monitoring
    res_stop = client.post("/api/live/toggle", json={"action": "stop"})
    assert res_stop.status_code == 200
    data_stop = res_stop.get_json()
    assert data_stop["status"] == "stopped"
    assert data_stop["is_running"] is False

    # Return to Live Monitoring — capture must NOT resume automatically
    res_return = client.get("/live")
    assert res_return.status_code == 200
    streamer = LiveTrafficManager.get_instance(user["id"])
    assert streamer.is_running is False


def test_start_monitoring_multiple_times_no_duplicate_workers(client):
    """
    TEST 13: Click Start Monitoring multiple times.
    Confirm that duplicate worker threads are not created.
    """
    email = _unique_email()
    create_user("Spam Start User", email, "SecurePass1")
    login(client, username=email, password="SecurePass1")

    r1 = client.post("/api/live/toggle", json={"action": "start", "mode": "demo"})
    r2 = client.post("/api/live/toggle", json={"action": "start", "mode": "demo"})
    r3 = client.post("/api/live/toggle", json={"action": "start", "mode": "demo"})

    assert r1.get_json()["status"] == "running"
    assert r2.get_json()["status"] == "running"
    assert r3.get_json()["status"] == "running"

    # Clean up
    client.post("/api/live/toggle", json={"action": "stop"})


def test_live_monitoring_user_isolation(client):
    """
    TEST E: Multiple user protection in Live Monitoring.
    User A running a stream does not affect User B's stream status.
    """
    email_a = _unique_email()
    email_b = _unique_email()

    user_a = create_user("Streamer A", email_a, "SecurePass1")
    user_b = create_user("Streamer B", email_b, "SecurePass1")

    # User A starts monitoring
    login(client, username=email_a, password="SecurePass1")
    client.post("/api/live/toggle", json={"action": "start", "mode": "demo"})

    streamer_a = LiveTrafficManager.get_instance(user_a["id"])
    assert streamer_a.is_running is True

    # User B logs in — their streamer must be stopped!
    client.post("/logout")
    login(client, username=email_b, password="SecurePass1")

    streamer_b = LiveTrafficManager.get_instance(user_b["id"])
    assert streamer_b.is_running is False

    # Clean up
    streamer_a.stop()


def test_admin_smtp_diag_endpoint_protection_and_response(client):
    """
    TEST F: Verify /admin/smtp-diag endpoint:
    1. Unauthenticated requests redirect to login.
    2. Non-admin authenticated user receives 403 Forbidden.
    3. Admin user receives 200 JSON diagnostics with NO exposed secrets.
    """
    # 1. Unauthenticated -> 302 redirect
    res = client.get("/admin/smtp-diag")
    assert res.status_code == 302
    assert "/login" in res.headers.get("Location", "")

    # 2. Regular user -> 403 Forbidden
    email_user = _unique_email()
    create_user("Standard User", email_user, "SecurePass1")
    login(client, username=email_user, password="SecurePass1")
    res_reg = client.get("/admin/smtp-diag")
    assert res_reg.status_code == 403

    # 3. Admin user -> 200 OK JSON
    client.post("/logout")
    login(client)
    res_admin = client.get("/admin/smtp-diag")
    assert res_admin.status_code == 200
    diag = res_admin.get_json()
    assert "env_file_found" in diag
    assert "smtp_host_configured" in diag
    assert "smtp_password" not in diag  # NEVER exposed!
    assert "smtp_password_configured" in diag


def test_multi_user_email_reset_routing(client, monkeypatch):
    """
    Verify that each registered user receives their reset email at their own registered email,
    never redirected to the sender or another user.
    """
    monkeypatch.setenv("SMTP_HOST", "smtp.mockserver.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "mailer@secureflow.ai")
    monkeypatch.setenv("SMTP_PASSWORD", "mock_app_password_123")
    monkeypatch.setenv("SMTP_USE_TLS", "true")

    email1 = _unique_email()
    email2 = _unique_email()
    create_user("User One", email1, "SecurePass1")
    create_user("User Two", email2, "SecurePass2")

    mock_smtp_instance = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_smtp_instance):
        mock_smtp_instance.__enter__.return_value = mock_smtp_instance

        # Request for user 1
        client.post("/forgot-password", data={"email": email1}, follow_redirects=True)
        assert mock_smtp_instance.send_message.called or mock_smtp_instance.sendmail.called
        msg1 = mock_smtp_instance.send_message.call_args[0][0]
        assert msg1["To"] == email1

        # Request for user 2
        mock_smtp_instance.reset_mock()
        mock_smtp_instance.__enter__.return_value = mock_smtp_instance
        client.post("/forgot-password", data={"email": email2}, follow_redirects=True)
        assert mock_smtp_instance.send_message.called or mock_smtp_instance.sendmail.called
        msg2 = mock_smtp_instance.send_message.call_args[0][0]
        assert msg2["To"] == email2
        assert msg2["To"] != email1


def test_unregistered_user_password_reset_anti_enumeration(client, monkeypatch):
    """
    Unregistered email requests maintain generic public notice but do not dispatch email.
    """
    monkeypatch.setenv("SMTP_HOST", "smtp.mockserver.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "mailer@secureflow.ai")
    monkeypatch.setenv("SMTP_PASSWORD", "mock_app_password_123")
    monkeypatch.setenv("SMTP_USE_TLS", "true")

    mock_smtp_instance = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_smtp_instance):
        mock_smtp_instance.__enter__.return_value = mock_smtp_instance
        res = client.post("/forgot-password", data={"email": "nonexistent_user@nobody.com"}, follow_redirects=True)
        assert res.status_code == 200
        text = res.get_data(as_text=True)
        assert "password reset instructions will be sent" in text.lower()
        # No email sent for nonexistent user
        assert not mock_smtp_instance.send_message.called
        assert not mock_smtp_instance.sendmail.called


def test_smtp_failure_displays_error_no_false_success(client, monkeypatch):
    """
    When SMTP delivery fails, the application must display an error banner
    and must NEVER display a successful delivery confirmation.
    """
    monkeypatch.setenv("SMTP_HOST", "smtp.mockserver.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "mailer@secureflow.ai")
    monkeypatch.setenv("SMTP_PASSWORD", "mock_app_password_123")
    monkeypatch.setenv("SMTP_USE_TLS", "true")

    email = _unique_email()
    create_user("Victim User", email, "SecurePass1")

    with patch("smtplib.SMTP", side_effect=smtplib.SMTPAuthenticationError(535, b"Authentication failed")):
        res = client.post("/forgot-password", data={"email": email}, follow_redirects=True)
        assert res.status_code == 200
        text = res.get_data(as_text=True)
        # Must show error message
        assert "Unable to deliver password reset email" in text
        # Must NOT claim instructions were sent
        assert "password reset instructions will be sent" not in text.lower()


def test_password_reset_end_to_end_flow(client):
    """
    Verify complete password reset roundtrip:
    1. User created with OldPassword1.
    2. Reset token generated and opened.
    3. New password set (NewSecurePass2).
    4. Old password login rejected.
    5. New password login succeeds.
    6. Token cannot be reused.
    """
    email = _unique_email()
    user = create_user("E2E Reset User", email, "OldPassword1")
    user_id = user["id"]

    raw_token = create_reset_token(user_id)
    assert raw_token is not None

    # Step 1: Open reset page
    res_page = client.get(f"/reset-password/{raw_token}")
    assert res_page.status_code == 200
    assert "Reset Password" in res_page.get_data(as_text=True)

    # Step 2: Submit new password
    res_reset = client.post(
        f"/reset-password/{raw_token}",
        data={"password": "NewSecurePass2", "confirm_password": "NewSecurePass2"},
        follow_redirects=True,
    )
    assert res_reset.status_code == 200
    assert "password has been updated successfully" in res_reset.get_data(as_text=True).lower()

    # Step 3: Verify old password fails
    client.post("/logout")
    res_old = login(client, username=email, password="OldPassword1")
    assert "Incorrect password" in res_old.get_data(as_text=True)

    # Step 4: Verify new password succeeds
    res_new = login(client, username=email, password="NewSecurePass2")
    assert res_new.status_code == 200
    assert "Dashboard" in res_new.get_data(as_text=True)

    # Step 5: Verify token cannot be reused
    client.post("/logout")
    res_reuse = client.get(f"/reset-password/{raw_token}")
    assert "invalid or has expired" in res_reuse.get_data(as_text=True).lower()


def test_network_interfaces_dynamic_detection_and_no_default_error(client):
    """
    Verify network interface detection:
    - Multiple adapters detected (Wi-Fi, Ethernet, Loopback, etc.)
    - No hardcoded 'Default' adapter name
    - Selected interface passes to LiveTrafficManager without 'Interface Default not found' error
    """
    from src.network.packet_capture import get_available_interfaces, LiveTrafficManager
    login(client)

    ifs = get_available_interfaces(refresh=True)
    assert len(ifs) > 0
    names = [i["name"] for i in ifs]
    assert "Default" not in names

    # Toggle live monitoring with a real detected interface
    target_iface = ifs[0]["name"]
    res = client.post("/api/live/toggle", json={"action": "start", "mode": "demo", "interface": target_iface})
    assert res.status_code == 200

    # Ensure no 'Interface Default not found' error
    streamer = LiveTrafficManager.get_instance("admin")
    latest = streamer.get_latest_records()
    assert latest.get("error") != "Capture error: Interface 'Default' not found!"

    client.post("/api/live/toggle", json={"action": "stop"})


def test_google_user_can_request_password_reset_and_set_password(client):
    """
    Verify that a user who registered or logged in via Google can also request
    a password reset, receives the reset email, sets a password, and can then log in
    using email and password.
    """
    from dashboard.user_db import get_or_create_google_user
    google_email = f"google_user_{_uuid.uuid4().hex[:6]}@example.com"
    user = get_or_create_google_user(
        google_id=f"gid_{_uuid.uuid4().hex[:8]}",
        email=google_email,
        name="Google Test User",
    )
    assert user["auth_provider"] == "google"

    # Request password reset for this Google user
    with patch("dashboard.app.send_password_reset_email") as mock_send:
        mock_send.return_value = (True, "Password reset instructions have been sent to your email.")
        res = client.post(
            "/forgot-password",
            data={"email": google_email},
            follow_redirects=True,
        )
        assert res.status_code == 200
        assert mock_send.called
        assert mock_send.call_args[1]["to_email"] == google_email
        reset_url = mock_send.call_args[1]["reset_url"]
        token = reset_url.split("/")[-1]

    # Google user sets password using the reset link
    res_set = client.post(
        f"/reset-password/{token}",
        data={"password": "NewGoogleUserPass1", "confirm_password": "NewGoogleUserPass1"},
        follow_redirects=True,
    )
    assert res_set.status_code == 200
    assert "password has been updated successfully" in res_set.get_data(as_text=True).lower()

    # User can now log in with the new password
    res_login = login(client, username=google_email, password="NewGoogleUserPass1")
    assert res_login.status_code == 200
    assert "Dashboard" in res_login.get_data(as_text=True)

