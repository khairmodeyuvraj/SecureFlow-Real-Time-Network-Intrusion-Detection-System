"""
SecureFlow User Database & Per-User Data Isolation Manager.

Manages:
  - User accounts (local credentials & Google OAuth)
  - Password reset tokens (cryptographically secure, time-limited, SHA-256 hashed)
  - Isolated security telemetry per user:
      * user_alerts
      * user_blocked_ips
      * user_analysis_history
  - SMTP email dispatch for secure password recovery
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import smtplib
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Database File Location
# ---------------------------------------------------------------------------
_DB_PATH = Path(__file__).resolve().parent / "users.db"


@contextmanager
def _conn():
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Schema Initialization & Migration
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create all user and telemetry tables and migrate legacy global records."""
    with _conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            full_name     TEXT NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            google_id     TEXT UNIQUE,
            google_email  TEXT,
            auth_provider TEXT NOT NULL DEFAULT 'local',
            created_at    TEXT NOT NULL,
            is_active     INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash  TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS user_analysis_history (
            id                TEXT PRIMARY KEY,
            user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            filename          TEXT NOT NULL,
            timestamp         TEXT NOT NULL,
            total_records     INTEGER NOT NULL,
            attacks_detected  INTEGER NOT NULL,
            normal_traffic    INTEGER NOT NULL,
            threat_percentage REAL NOT NULL,
            avg_confidence    REAL
        );

        CREATE TABLE IF NOT EXISTS user_alerts (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            time        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            type        TEXT NOT NULL,
            source      TEXT NOT NULL,
            src_ip      TEXT NOT NULL,
            dst_ip      TEXT NOT NULL,
            protocol    TEXT NOT NULL,
            confidence  TEXT NOT NULL,
            details     TEXT NOT NULL,
            status      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_blocked_ips (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            ip          TEXT NOT NULL,
            reason      TEXT NOT NULL,
            added_at    TEXT NOT NULL,
            source      TEXT NOT NULL
        );
        """)

        # Ensure baseline admin account is registered in users table
        con.execute(
            """INSERT OR IGNORE INTO users
               (id, full_name, email, auth_provider, created_at, is_active)
               VALUES ('admin', 'Administrator', 'admin@secureflow.ai', 'local', ?, 1)""",
            (_now_iso(),),
        )

    _migrate_legacy_data()


def _migrate_legacy_data() -> None:
    """Safely migrate legacy JSON stores to SQLite under 'admin' user without deleting files."""
    from config import ALERTS_FILE, BLOCKED_FILE, HISTORY_FILE

    with _conn() as con:
        # Migrate Alerts
        if ALERTS_FILE.exists():
            try:
                alerts_data = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))
                if isinstance(alerts_data, list):
                    for a in alerts_data:
                        aid = a.get("id") or uuid.uuid4().hex[:10]
                        con.execute(
                            """INSERT OR IGNORE INTO user_alerts
                               (id, user_id, time, severity, type, source, src_ip, dst_ip, protocol, confidence, details, status)
                               VALUES (?, 'admin', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                aid,
                                a.get("time", ""),
                                a.get("severity", "Medium"),
                                a.get("type", "Security Alert"),
                                a.get("source", "Legacy Import"),
                                a.get("src_ip", "-"),
                                a.get("dst_ip", "-"),
                                a.get("protocol", "TCP"),
                                str(a.get("confidence", "100.0%")),
                                a.get("details", ""),
                                a.get("status", "Active"),
                            ),
                        )
            except Exception:
                pass

        # Migrate History
        if HISTORY_FILE.exists():
            try:
                history_data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
                if isinstance(history_data, list):
                    for h in history_data:
                        hid = h.get("id") or uuid.uuid4().hex[:8]
                        con.execute(
                            """INSERT OR IGNORE INTO user_analysis_history
                               (id, user_id, filename, timestamp, total_records, attacks_detected, normal_traffic, threat_percentage, avg_confidence)
                               VALUES (?, 'admin', ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                hid,
                                h.get("filename", "unknown.csv"),
                                h.get("timestamp", ""),
                                int(h.get("total_records", 0)),
                                int(h.get("attacks_detected", 0)),
                                int(h.get("normal_traffic", 0)),
                                float(h.get("threat_percentage", 0.0)),
                                float(h.get("avg_confidence")) if h.get("avg_confidence") is not None else None,
                            ),
                        )
            except Exception:
                pass

        # Migrate Blocked IPs
        if BLOCKED_FILE.exists():
            try:
                blocked_data = json.loads(BLOCKED_FILE.read_text(encoding="utf-8"))
                if isinstance(blocked_data, list):
                    for b in blocked_data:
                        bid = b.get("id") or uuid.uuid4().hex[:10]
                        con.execute(
                            """INSERT OR IGNORE INTO user_blocked_ips
                               (id, user_id, ip, reason, added_at, source)
                               VALUES (?, 'admin', ?, ?, ?, ?)""",
                            (
                                bid,
                                b.get("ip", ""),
                                b.get("reason", "Administrator added"),
                                b.get("added_at", ""),
                                b.get("source", "Legacy"),
                            ),
                        )
            except Exception:
                pass


# ---------------------------------------------------------------------------
# User Account Operations
# ---------------------------------------------------------------------------

def create_user(
    full_name: str,
    email: str,
    password: str,
) -> dict:
    """Create a local user with hashed password and initialized empty workspace."""
    user_id = uuid.uuid4().hex
    pw_hash = generate_password_hash(password, method="pbkdf2:sha256")
    with _conn() as con:
        con.execute(
            """INSERT INTO users
               (id, full_name, email, password_hash, auth_provider, created_at)
               VALUES (?, ?, ?, ?, 'local', ?)""",
            (user_id, full_name.strip(), email.lower().strip(), pw_hash, _now_iso()),
        )
    # Initialize clean user data directory
    get_user_data_dir(user_id)
    return get_user_by_id(user_id)  # type: ignore[return-value]


def get_user_by_email(email: str) -> Optional[dict]:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = 1",
            (email.lower().strip(),),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: str) -> Optional[dict]:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM users WHERE id = ? AND is_active = 1",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_google_id(google_id: str) -> Optional[dict]:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM users WHERE google_id = ? AND is_active = 1",
            (google_id,),
        ).fetchone()
    return dict(row) if row else None


def email_exists(email: str) -> bool:
    with _conn() as con:
        row = con.execute(
            "SELECT 1 FROM users WHERE email = ?",
            (email.lower().strip(),),
        ).fetchone()
    return row is not None


def verify_password(email: str, password: str) -> Optional[dict]:
    """Verify password against database hash. Returns user dict on success, None on failure."""
    user = get_user_by_email(email)
    if not user:
        return None
    if not user.get("password_hash"):
        return None  # Google OAuth accounts do not have local passwords
    if check_password_hash(user["password_hash"], password):
        return user
    return None


def get_or_create_google_user(
    google_id: str,
    email: str,
    name: str,
) -> dict:
    """Look up existing Google account or create a new isolated user."""
    user = get_user_by_google_id(google_id)
    if user:
        return user
    user_id = uuid.uuid4().hex
    with _conn() as con:
        con.execute(
            """INSERT INTO users
               (id, full_name, email, google_id, google_email, auth_provider, created_at)
               VALUES (?, ?, ?, ?, ?, 'google', ?)""",
            (user_id, name, email.lower().strip(), google_id, email.lower().strip(), _now_iso()),
        )
    get_user_data_dir(user_id)
    return get_user_by_id(user_id)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Password Reset Tokens (Cryptographically Secure, SHA-256 Hashed, 1-Hour Expiry)
# ---------------------------------------------------------------------------

def is_reset_rate_limited(user_id: str) -> bool:
    """
    Enforce rate limiting on password reset requests:
    - Maximum 5 reset requests per 15 minutes.
    - At least 30 seconds cooldown between consecutive requests.
    """
    with _conn() as con:
        rows = con.execute(
            """SELECT expires_at FROM password_reset_tokens
               WHERE user_id = ?
               ORDER BY expires_at DESC LIMIT 5""",
            (user_id,),
        ).fetchall()
        if not rows:
            return False

        now = datetime.now(timezone.utc)
        # Check cooldown from most recent request
        latest_expires_at = datetime.fromisoformat(rows[0]["expires_at"])
        if latest_expires_at.tzinfo is None:
            latest_expires_at = latest_expires_at.replace(tzinfo=timezone.utc)

        # Token was issued for 30 mins; if it has > 29m 30s remaining, cooldown is active (30s)
        time_since_creation = (latest_expires_at - timedelta(minutes=30))
        if (now - time_since_creation).total_seconds() < 30:
            return True

        # Check if 5 requests within the last 15 minutes
        if len(rows) >= 5:
            fifth_expires_at = datetime.fromisoformat(rows[-1]["expires_at"])
            if fifth_expires_at.tzinfo is None:
                fifth_expires_at = fifth_expires_at.replace(tzinfo=timezone.utc)
            fifth_created = fifth_expires_at - timedelta(minutes=30)
            if (now - fifth_created).total_seconds() < 900:  # 15 minutes
                return True

    return False


def create_reset_token(user_id: str) -> str:
    """
    Generate a 32-byte URL-safe token.
    Store only the SHA-256 hash in the database with a 30-minute expiration.
    Returns the unhashed raw token to be delivered securely via email.
    """
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    with _conn() as con:
        # Invalidate any prior active tokens for this user
        con.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0",
            (user_id,),
        )
        con.execute(
            """INSERT INTO password_reset_tokens
               (id, user_id, token_hash, expires_at)
               VALUES (?, ?, ?, ?)""",
            (uuid.uuid4().hex, user_id, token_hash, expires_at),
        )
    return raw


def validate_reset_token(raw_token: str) -> Optional[dict]:
    """
    Check if the token hash exists, is unused, and has not expired.
    Returns the associated User dict if valid, else None.
    """
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with _conn() as con:
        row = con.execute(
            """SELECT prt.user_id, prt.expires_at
               FROM password_reset_tokens prt
               WHERE prt.token_hash = ? AND prt.used = 0""",
            (token_hash,),
        ).fetchone()
    if not row:
        return None

    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        return None

    return get_user_by_id(row["user_id"])


def consume_reset_token(raw_token: str, new_password: str) -> bool:
    """
    Update the user password hash and invalidate the reset token immediately.
    Returns True on success, False if token is invalid or expired.
    """
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with _conn() as con:
        row = con.execute(
            "SELECT id, user_id, expires_at FROM password_reset_tokens WHERE token_hash = ? AND used = 0",
            (token_hash,),
        ).fetchone()
        if not row:
            return False

        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expires_at:
            return False

        pw_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
        con.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (pw_hash, row["user_id"]),
        )
        con.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
            (row["id"],),
        )
    return True


# ---------------------------------------------------------------------------
# SMTP Email Sending & Connectivity Diagnostics
# ---------------------------------------------------------------------------

def verify_smtp_credentials() -> Dict[str, Any]:
    """
    Administrator diagnostic helper that checks SMTP settings and authentication
    without exposing any passwords, secrets, or tokens.
    """
    import socket
    from config import get_smtp_config, ENV_FILE

    cfg = get_smtp_config()
    host = cfg["host"]
    port = cfg["port"]
    username = cfg["username"]
    password = cfg["password"].replace(" ", "")
    use_tls = cfg["use_tls"]
    sender = cfg["sender"]

    diag: Dict[str, Any] = {
        "env_file_found": ENV_FILE.exists(),
        "smtp_host_configured": bool(host),
        "smtp_host": host or "Not set",
        "smtp_port_configured": bool(port),
        "smtp_port": port,
        "smtp_username_configured": bool(username),
        "smtp_password_configured": bool(password),
        "smtp_use_tls_configured": bool(use_tls),
        "smtp_sender_configured": bool(sender),
        "connection_successful": False,
        "tls_successful": False,
        "authentication_successful": False,
        "status_message": "",
    }

    if not host or not username or not password:
        diag["status_message"] = "SMTP configuration incomplete. Host, username, and password are required in .env."
        return diag

    try:
        with smtplib.SMTP(host, port, timeout=12) as server:
            server.ehlo()
            diag["connection_successful"] = True

            if use_tls:
                server.starttls()
                server.ehlo()
                diag["tls_successful"] = True
            else:
                diag["tls_successful"] = True  # Not requested

            server.login(username, password)
            diag["authentication_successful"] = True
            diag["status_message"] = f"SMTP authentication succeeded with {host}:{port}."

    except smtplib.SMTPAuthenticationError as auth_err:
        diag["status_message"] = (
            "SMTP authentication rejected by server. "
            "For Gmail: Ensure 2-Step Verification is active and an App Password "
            "(not your standard Google account password) is configured in .env."
        )
    except smtplib.SMTPServerDisconnected:
        diag["status_message"] = (
            "SMTP server unexpectedly closed the connection during authentication. "
            "Please verify that the SMTP_USERNAME is a valid Gmail address and SMTP_PASSWORD is an active App Password."
        )
    except (socket.timeout, TimeoutError):
        diag["status_message"] = f"Connection to SMTP host {host}:{port} timed out after 12 seconds."
    except smtplib.SMTPConnectError as conn_err:
        diag["status_message"] = f"Could not establish connection to {host}:{port}: {conn_err.smtp_error}"
    except smtplib.SMTPException as smtp_err:
        diag["status_message"] = f"SMTP protocol error: {smtp_err}"
    except OSError as net_err:
        diag["status_message"] = f"Network connectivity error reaching {host}:{port}: {net_err}"
    except Exception as err:
        diag["status_message"] = f"Unexpected SMTP diagnostic failure: {err}"

    return diag


def send_password_reset_email(
    to_email: str,
    recipient_name: str,
    reset_url: str,
) -> Tuple[bool, str]:
    """
    Deliver a branded HTML and plain-text password reset email via configured SMTP.
    Credentials and reset URLs are never logged to console or persisted in plaintext.
    """
    import socket
    from config import get_smtp_config

    cfg = get_smtp_config()
    host = cfg["host"]
    port = cfg["port"]
    username = cfg["username"]
    password = cfg["password"].replace(" ", "")
    use_tls = cfg["use_tls"]
    sender = cfg["sender"]

    if not host or not username or not password:
        return False, "SMTP server credentials are not configured in .env."

    subject = "SecureFlow · Password Reset Request"

    text_body = f"""Hello {recipient_name},

We received a request to reset your password for your SecureFlow AI-IDS account.

To choose a new password, visit the link below (valid for 30 minutes):
{reset_url}

If you did not make this request, you can safely ignore this message. Your account remains secure.

SecureFlow Network Defense Console
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #06101b; color: #d0deee; margin: 0; padding: 24px; }}
  .box {{ max-width: 520px; margin: 0 auto; background: #0c1a29; border: 1px solid #1a3a54; border-radius: 12px; padding: 32px; }}
  .title {{ color: #20dce8; font-size: 22px; font-weight: 700; margin: 0 0 8px; letter-spacing: -0.5px; }}
  .sub {{ color: #8da2bb; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 24px; }}
  p {{ font-size: 14px; line-height: 1.6; color: #c5d5e5; }}
  .btn-wrap {{ text-align: center; margin: 28px 0; }}
  .btn {{ display: inline-block; background: linear-gradient(100deg, #08e7bc 0%, #00b4ed 100%); color: #04192a; font-weight: 700; font-size: 14px; padding: 12px 28px; text-decoration: none; border-radius: 8px; box-shadow: 0 4px 16px rgba(0, 219, 221, 0.25); }}
  .muted {{ font-size: 11.5px; color: #7f91a3; line-height: 1.5; margin-top: 24px; border-top: 1px solid #14283b; padding-top: 16px; }}
</style>
</head>
<body>
  <div class="box">
    <div class="title">Secure<span style="color:#1fe4d7;">Flow</span></div>
    <div class="sub">AI-BASED INTRUSION DETECTION SYSTEM</div>
    <p>Hello <strong>{recipient_name}</strong>,</p>
    <p>A request was received to reset your password for the SecureFlow AI-IDS console. Click the button below to set a new password. This link is valid for <strong>30 minutes</strong>.</p>
    <div class="btn-wrap">
      <a href="{reset_url}" class="btn" target="_blank">Reset Password</a>
    </div>
    <p class="muted">If the button above does not work, copy and paste this link into your browser:<br><a href="{reset_url}" style="color: #35dce6; word-break: break-all;">{reset_url}</a></p>
    <p class="muted">If you did not request this reset, you can safely ignore this email. No changes will be made to your account.</p>
  </div>
</body>
</html>"""

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"SecureFlow AI-IDS <{sender}>"
    msg["To"] = to_email
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            server.login(username, password)
            server.send_message(msg)
        return True, "Password reset instructions have been sent to your email."
    except smtplib.SMTPAuthenticationError:
        return False, "Gmail SMTP authentication failed. Please verify your Gmail address and Google App Password."
    except smtplib.SMTPServerDisconnected:
        return False, "SMTP server disconnected unexpectedly during transmission. Verify your credentials in .env."
    except (socket.timeout, TimeoutError):
        return False, f"Connection to SMTP server {host}:{port} timed out."
    except smtplib.SMTPConnectError as conn_err:
        return False, f"Could not establish connection to {host}:{port}: {conn_err.smtp_error}"
    except smtplib.SMTPException as smtp_err:
        return False, f"SMTP protocol error: {smtp_err}"
    except OSError as net_err:
        return False, f"Network connectivity error reaching {host}:{port}: {net_err}"
    except Exception as err:
        return False, f"Failed to deliver email via SMTP: {err}"


# ---------------------------------------------------------------------------
# Per-User Data Isolation Helpers (Alerts, History, Blocked IPs, Flow CSV)
# ---------------------------------------------------------------------------

def get_user_data_dir(user_id: str) -> Path:
    """Return the isolated storage directory for the authenticated user."""
    from config import DASHBOARD_RESULTS_DIR
    if user_id in ("admin", ""):
        return DASHBOARD_RESULTS_DIR
    user_dir = DASHBOARD_RESULTS_DIR / "users" / user_id
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


def get_user_flows_file(user_id: str) -> Path:
    """Return the path to the user's latest classified flows CSV."""
    from config import DASHBOARD_RESULTS_DIR
    if user_id in ("admin", ""):
        # Check admin user directory first, then fallback to dashboard results
        admin_file = DASHBOARD_RESULTS_DIR / "latest_flows.csv"
        return admin_file
    return get_user_data_dir(user_id) / "latest_flows.csv"


def get_user_alerts(user_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
    """Retrieve alerts belonging strictly to the specified user."""
    with _conn() as con:
        rows = con.execute(
            """SELECT id, time, severity, type, source, src_ip, dst_ip, protocol, confidence, details, status
               FROM user_alerts
               WHERE user_id = ?
               ORDER BY time DESC
               LIMIT ?""",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def add_user_alert(user_id: str, alert: Dict[str, Any]) -> None:
    """Insert an alert record scoped to the authenticated user."""
    aid = alert.get("id") or uuid.uuid4().hex[:10]
    with _conn() as con:
        con.execute(
            """INSERT INTO user_alerts
               (id, user_id, time, severity, type, source, src_ip, dst_ip, protocol, confidence, details, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                aid,
                user_id,
                alert.get("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                alert.get("severity", "High"),
                alert.get("type", "Detected Threat"),
                alert.get("source", "Network Telemetry"),
                alert.get("src_ip", "-"),
                alert.get("dst_ip", "-"),
                alert.get("protocol", "TCP"),
                str(alert.get("confidence", "100.0%")),
                alert.get("details", ""),
                alert.get("status", "Active"),
            ),
        )


def get_user_history(user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve audit history records belonging strictly to the specified user."""
    with _conn() as con:
        rows = con.execute(
            """SELECT id, filename, timestamp, total_records, attacks_detected, normal_traffic, threat_percentage, avg_confidence
               FROM user_analysis_history
               WHERE user_id = ?
               ORDER BY timestamp DESC
               LIMIT ?""",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def add_user_history(user_id: str, item: Dict[str, Any]) -> None:
    """Record an analysis session execution for the specified user."""
    hid = item.get("id") or uuid.uuid4().hex[:8]
    with _conn() as con:
        con.execute(
            """INSERT INTO user_analysis_history
               (id, user_id, filename, timestamp, total_records, attacks_detected, normal_traffic, threat_percentage, avg_confidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hid,
                user_id,
                item.get("filename", "unknown.csv"),
                item.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                int(item.get("total_records", 0)),
                int(item.get("attacks_detected", 0)),
                int(item.get("normal_traffic", 0)),
                float(item.get("threat_percentage", 0.0)),
                float(item.get("avg_confidence")) if item.get("avg_confidence") is not None else None,
            ),
        )


def get_user_blocked(user_id: str) -> List[Dict[str, Any]]:
    """Retrieve blocked IP records belonging strictly to the specified user."""
    with _conn() as con:
        rows = con.execute(
            """SELECT id, ip, reason, added_at, source
               FROM user_blocked_ips
               WHERE user_id = ?
               ORDER BY added_at DESC""",
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def add_user_blocked(user_id: str, ip: str, reason: str, source: str = "Administrator") -> bool:
    """Add a blocked IP record scoped to the specified user. Returns False if already blocked."""
    with _conn() as con:
        existing = con.execute(
            "SELECT 1 FROM user_blocked_ips WHERE user_id = ? AND ip = ?",
            (user_id, ip),
        ).fetchone()
        if existing:
            return False
        con.execute(
            """INSERT INTO user_blocked_ips
               (id, user_id, ip, reason, added_at, source)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                uuid.uuid4().hex[:10],
                user_id,
                ip,
                reason[:160],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                source,
            ),
        )
    return True


def remove_user_blocked(user_id: str, item_id: str) -> bool:
    """
    Remove a blocked IP record.
    Strictly verifies ownership against user_id so users cannot remove records of others.
    """
    with _conn() as con:
        cur = con.execute(
            "DELETE FROM user_blocked_ips WHERE user_id = ? AND id = ?",
            (user_id, item_id),
        )
        return cur.rowcount > 0


# Initialize schema and migrate on module import
init_db()
