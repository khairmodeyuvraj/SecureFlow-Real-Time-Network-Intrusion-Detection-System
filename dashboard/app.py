from pathlib import Path
from datetime import datetime
from functools import wraps
import ipaddress
import json
import os
import re
import sys
import uuid
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
    session,
)
from werkzeug.utils import secure_filename

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import (
    SECRET_KEY,
    LOGIN_USERNAME,
    LOGIN_PASSWORD,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    is_google_oauth_configured,
    is_smtp_configured,
    APP_BASE_URL,
    MAX_CONTENT_LENGTH,
    ALLOWED_EXTENSIONS,
    UPLOAD_DIR,
    DASHBOARD_RESULTS_DIR,
    LATEST_FLOWS_FILE as DATA_FILE,
    ALERTS_FILE,
    BLOCKED_FILE,
    HISTORY_FILE,
    SAMPLES_DIR,
)
from dashboard.user_db import (
    create_user,
    email_exists,
    get_user_by_email,
    get_user_by_id,
    get_or_create_google_user,
    verify_password,
    create_reset_token,
    validate_reset_token,
    consume_reset_token,
    is_reset_rate_limited,
    send_password_reset_email,
    verify_smtp_credentials,
    get_user_data_dir,
    get_user_flows_file,
    get_user_alerts,
    add_user_alert,
    get_user_history,
    add_user_history,
    get_user_blocked,
    add_user_blocked,
    remove_user_blocked,
)
from src.inference.predictor import get_predictor
from src.network.pcap_reader import extract_flows_from_pcap
from src.network.packet_capture import (
    check_capture_capabilities,
    LiveTrafficManager,
    get_available_interfaces,
)
from src.data.loader import load_csv
from src.utils.logger import get_logger

logger = get_logger("SecureFlowApp")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Pre-initialize predictor singleton at startup
try:
    predictor = get_predictor()
    logger.info("IDS Predictor successfully bound to application.")
except Exception as err:
    logger.error(f"Failed to load IDS Predictor at startup: {err}")
    predictor = None


# --------------------------------------------------
# AUTHENTICATION DECORATOR & USER HELPERS
# --------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def get_current_user_id() -> str:
    """Return the authenticated user ID from active Flask session, defaulting to 'admin'."""
    return session.get("user_id", "admin")


def _is_strong_password(pw: str) -> bool:
    """Validate password complexity: minimum 8 characters, at least one letter and one number."""
    return len(pw) >= 8 and bool(re.search(r"[A-Za-z]", pw)) and bool(re.search(r"\d", pw))


# --------------------------------------------------
# USER-ISOLATED DATA ACCESS HELPERS
# --------------------------------------------------

def get_alerts(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve security alerts belonging strictly to the user."""
    uid = user_id or get_current_user_id()
    return get_user_alerts(uid)


def get_blocked(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve defensive blocked IPs belonging strictly to the user."""
    uid = user_id or get_current_user_id()
    return get_user_blocked(uid)


def get_history(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve historical analysis audit records belonging strictly to the user."""
    uid = user_id or get_current_user_id()
    return get_user_history(uid)


def load_flows(user_id: Optional[str] = None) -> pd.DataFrame:
    """Load classified network flows belonging strictly to the user."""
    uid = user_id or get_current_user_id()
    flows_file = get_user_flows_file(uid)
    try:
        return pd.read_csv(flows_file, low_memory=False) if flows_file.exists() else pd.DataFrame()
    except (pd.errors.ParserError, OSError, UnicodeDecodeError):
        return pd.DataFrame()


def summary(df: pd.DataFrame, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Calculate summary statistics for the user's active flow dataset."""
    uid = user_id or get_current_user_id()
    total = len(df)
    if not df.empty and "Prediction" in df.columns:
        preds = df["Prediction"].astype(str).str.strip().str.upper()
        attacks = int(preds.isin(["ATTACK", "MALICIOUS", "1"]).sum())
        benign = int(preds.isin(["BENIGN", "NORMAL", "0"]).sum())
        status = "AI Model Active (Real Predictions)"
    else:
        attacks = 0
        benign = 0
        status = "Ready (Awaiting Traffic)"

    threat_rate = round((attacks / total) * 100, 1) if total > 0 else 0.0

    return {
        "total_flows": total,
        "attacks": attacks,
        "benign": benign,
        "threat_percentage": threat_rate,
        "alerts": len(get_alerts(uid)),
        "prediction_status": status,
    }


def record_alerts_from_predictions(
    df: pd.DataFrame,
    source_filename: str,
    user_id: Optional[str] = None,
) -> int:
    """
    Generate actionable alert records for all rows classified as ATTACK,
    persisting them strictly isolated under user_id.
    """
    if "Prediction" not in df.columns:
        return 0

    uid = user_id or get_current_user_id()
    preds = df["Prediction"].astype(str).str.strip().str.upper()
    attack_rows = df[preds.isin(["ATTACK", "MALICIOUS", "1"])]

    if attack_rows.empty:
        return 0

    new_alerts_count = 0
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for _, row in attack_rows.head(100).iterrows():
        attack_type = str(row.get("Attack_Type", "Malicious Flow"))
        conf = row.get("Confidence", 95.0)
        src_ip = str(row.get("Source_IP", row.get("src_ip", "Unknown")))
        dst_ip = str(row.get("Destination_IP", row.get("dst_ip", "Unknown")))
        src_port = str(row.get("Source_Port", row.get("src_port", "-")))
        dst_port = str(row.get("Destination_Port", row.get("dst_port", "-")))
        proto = str(row.get("Protocol", "TCP"))

        alert_item = {
            "id": uuid.uuid4().hex[:10],
            "time": now_str,
            "severity": "High" if conf >= 85 else "Medium",
            "type": f"{attack_type} Detected",
            "source": source_filename,
            "src_ip": f"{src_ip}:{src_port}",
            "dst_ip": f"{dst_ip}:{dst_port}",
            "protocol": proto,
            "confidence": f"{conf:.1f}%" if isinstance(conf, (int, float)) else str(conf),
            "details": f"AI model classified flow as {attack_type} with {conf}% confidence.",
            "status": "Active",
        }
        add_user_alert(uid, alert_item)
        new_alerts_count += 1

    return new_alerts_count


def record_analysis_history(
    filename: str,
    total: int,
    attacks: int,
    benign: int,
    confidence: Optional[float],
    user_id: Optional[str] = None,
) -> None:
    """Persist an analysis session audit entry strictly under user_id."""
    uid = user_id or get_current_user_id()
    threat_rate = round((attacks / total) * 100, 2) if total > 0 else 0.0

    history_item = {
        "id": uuid.uuid4().hex[:8],
        "filename": filename,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_records": total,
        "attacks_detected": attacks,
        "normal_traffic": benign,
        "threat_percentage": threat_rate,
        "avg_confidence": confidence,
    }
    add_user_history(uid, history_item)


# --------------------------------------------------
# AUTHENTICATION ROUTES (LOGIN, REGISTER, GOOGLE, RESET)
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # ── 1. Hardcoded admin account (backward compatibility) ───────────────
        valid_usernames = {
            LOGIN_USERNAME.lower(),
            f"{LOGIN_USERNAME.lower()}@secureflow.ai",
            "admin@secureflow.ai",
            "admin@gmail.com",
        }
        if (username.lower() in valid_usernames or username == LOGIN_USERNAME) and password == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            session["user_id"] = "admin"
            session["user_name"] = "Administrator"
            session["auth_provider"] = "local"
            session.permanent = request.form.get("remember") == "on"
            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        # ── 2. Registered multi-user database lookup ──────────────────────────
        db_user = get_user_by_email(username)
        if db_user:
            verified = verify_password(username, password)
            if verified:
                session.clear()
                session["logged_in"] = True
                session["username"] = verified["email"]
                session["user_id"] = verified["id"]
                session["user_name"] = verified["full_name"]
                session["auth_provider"] = "local"
                session.permanent = request.form.get("remember") == "on"
                next_url = request.args.get("next", "")
                if next_url.startswith("/") and not next_url.startswith("//"):
                    return redirect(next_url)
                return redirect(url_for("dashboard"))
            else:
                flash("Incorrect password. Please try again.", "error")
        else:
            flash(
                "No account found with this email address. Please create an account first.",
                "error",
            )

    google_configured = is_google_oauth_configured()
    return render_template("login.html", google_configured=google_configured)


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or len(full_name) < 2:
            flash("Please enter your full name (at least 2 characters).", "error")
            return render_template("register.html")

        if not email or "@" not in email:
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")

        if not _is_strong_password(password):
            flash(
                "Password must be at least 8 characters and contain at least one letter and one number.",
                "error",
            )
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return render_template("register.html")

        if email_exists(email):
            flash(
                "An account with this email already exists. Please sign in or use a different email.",
                "error",
            )
            return render_template("register.html")

        try:
            user = create_user(full_name=full_name, email=email, password=password)
            flash(
                f"Account created successfully. Welcome, {user['full_name']}! Please sign in.",
                "success",
            )
            return redirect(url_for("login"))
        except Exception as err:
            logger.error(f"User registration failed: {err}")
            flash("Registration failed due to an internal error. Please try again.", "error")

    return render_template("register.html")


@app.route("/auth/google")
def google_login():
    """Initiates Google OAuth 2.0 OpenID Connect authentication flow."""
    if not is_google_oauth_configured():
        flash(
            "Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file to enable Google Sign-In.",
            "info",
        )
        return redirect(url_for("login"))

    import secrets
    import urllib.parse

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session["oauth_nonce"] = nonce

    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", GOOGLE_REDIRECT_URI) or url_for("google_callback", _external=True)

    next_url = request.args.get("next", "")
    if next_url.startswith("/") and not next_url.startswith("//"):
        session["oauth_next_url"] = next_url

    client_id = os.environ.get("GOOGLE_CLIENT_ID", GOOGLE_CLIENT_ID).strip()
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "access_type": "online",
        "prompt": "select_account",
    }
    google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    logger.info(f"Initiating Google OAuth flow -> redirecting to Google auth endpoint with client_id={client_id[:8]}...")
    return redirect(google_auth_url)


@app.route("/auth/google/callback")
def google_callback():
    """Handles Google OAuth 2.0 response callback and validates OpenID Connect credentials."""
    error = request.args.get("error")
    if error:
        error_desc = request.args.get("error_description", error)
        logger.warning(f"Google OAuth callback error reported: {error}")
        flash(f"Google Sign-In was cancelled or failed ({error_desc}).", "info")
        return redirect(url_for("login"))

    code = request.args.get("code")
    state = request.args.get("state")
    expected_state = session.pop("oauth_state", None)
    session.pop("oauth_nonce", None)

    import secrets
    if not code or not state or not expected_state or not secrets.compare_digest(state, expected_state):
        logger.warning("Google OAuth state mismatch or missing authorization code.")
        flash("Security validation failed (OAuth state verification mismatch). Please try again.", "error")
        return redirect(url_for("login"))

    client_id = os.environ.get("GOOGLE_CLIENT_ID", GOOGLE_CLIENT_ID).strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", GOOGLE_CLIENT_SECRET).strip()
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", GOOGLE_REDIRECT_URI) or url_for("google_callback", _external=True)

    try:
        import requests
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        if token_resp.status_code != 200:
            logger.error(f"Google token exchange failed ({token_resp.status_code}): {token_resp.text}")
            flash("Failed to authenticate with Google. Please verify Client ID and Secret in .env.", "error")
            return redirect(url_for("login"))

        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            flash("No access token received from Google.", "error")
            return redirect(url_for("login"))

        userinfo_resp = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10,
        )
        if userinfo_resp.status_code != 200:
            flash("Failed to retrieve verified user profile from Google.", "error")
            return redirect(url_for("login"))

        user_info = userinfo_resp.json()
        email = user_info.get("email")
        email_verified = user_info.get("email_verified", False)

        if not email:
            flash("Unable to obtain verified email address from Google account.", "error")
            return redirect(url_for("login"))

        if not email_verified:
            flash("Your Google email is not verified by Google. Please verify your email with Google first.", "error")
            return redirect(url_for("login"))

        google_id = user_info.get("sub", email)
        db_user = get_or_create_google_user(
            google_id=google_id,
            email=email,
            name=user_info.get("name", email.split("@")[0]),
        )

        session.clear()
        session["logged_in"] = True
        session["username"] = email
        session["user_email"] = email
        session["user_id"] = db_user["id"]
        session["auth_provider"] = "google"
        session["user_name"] = db_user["full_name"]
        session["user_picture"] = user_info.get("picture", "")
        session.permanent = True

        logger.info(f"Successful Google OAuth login for user: {email}")
        flash(f"Welcome back, {session['user_name']}!", "success")

        next_url = session.pop("oauth_next_url", "")
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("dashboard"))

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during Google OAuth request: {e}")
        flash("Network error while connecting to Google. Please check your internet connection.", "error")
        return redirect(url_for("login"))
    except Exception as e:
        logger.error(f"Unexpected error in Google OAuth callback: {e}")
        flash("An unexpected error occurred during Google Sign-In.", "error")
        return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """
    Handle secure password reset requests.
    Tokens and reset URLs are NEVER exposed on the webpage, in responses, or in logs.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        # 1. Check if SMTP is configured
        if not is_smtp_configured():
            flash(
                "Email delivery service (SMTP) is not configured by the system administrator. "
                "Password reset emails cannot be delivered. "
                "Please configure SMTP credentials (SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD) in your .env file.",
                "error",
            )
            return render_template("forgot_password.html")

        # 2. Anti-enumeration standard message
        standard_notice = "If an account exists with this email address, password reset instructions will be sent."

        user = get_user_by_email(email)
        if user:
            logger.info(f"[ForgotPassword] Password reset request for user '{email}' (id: {user.get('id')}, provider: {user.get('auth_provider')})")
            if is_reset_rate_limited(user["id"]):
                logger.warning(f"[ForgotPassword] Rate limit hit for user '{email}'")
                flash(
                    "Too many password reset requests. Please wait a moment before trying again.",
                    "error",
                )
                return render_template("forgot_password.html")

            raw_token = create_reset_token(user["id"])
            if APP_BASE_URL:
                reset_url = f"{APP_BASE_URL}/reset-password/{raw_token}"
            else:
                reset_url = url_for("reset_password", token=raw_token, _external=True)

            logger.info(f"[ForgotPassword] Sending password reset email to '{email}' via SMTP...")
            sent, err_msg = send_password_reset_email(
                to_email=email,
                recipient_name=user.get("full_name", "User"),
                reset_url=reset_url,
            )

            if not sent:
                logger.error(f"[ForgotPassword] Failed to dispatch password reset email via SMTP: {err_msg}")
                flash(
                    "Unable to deliver password reset email due to a mail server connection or authentication error. "
                    "Please verify mail server credentials in .env or try again later.",
                    "error",
                )
                return render_template("forgot_password.html")

            logger.info(f"[ForgotPassword] Successfully dispatched password reset email to '{email}'.")
        else:
            logger.info(f"[ForgotPassword] Email '{email}' not found in database. Returned standard anti-enumeration message.")

        flash(standard_notice, "info")

    return render_template("forgot_password.html")


@app.route("/admin/smtp-diag", methods=["GET", "POST"])
@login_required
def admin_smtp_diag():
    """
    Administrator diagnostic endpoint for SMTP configuration and live reachability.
    Protected by admin authorization; never exposes sensitive passwords, keys, or reset tokens.
    """
    current_uid = get_current_user_id()
    current_user = session.get("username", "")
    if current_uid != "admin" and current_user != LOGIN_USERNAME:
        return jsonify({"status": "error", "message": "Administrator privileges required"}), 403

    diag = verify_smtp_credentials()

    test_email = ""
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        test_email = data.get("test_email", "").strip() if data else ""
    elif request.method == "GET" and request.args.get("send_to"):
        test_email = request.args.get("send_to", "").strip()

    if test_email:
        sent, msg = send_password_reset_email(
            to_email=test_email,
            recipient_name="Administrator Test",
            reset_url=url_for("login", _external=True),
        )
        diag["test_email_target"] = test_email
        diag["test_email_sent"] = sent
        diag["test_email_message"] = msg

    return jsonify(diag)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Secure password reset route validating one-time, 1-hour cryptographic tokens."""
    user = validate_reset_token(token)
    if not user:
        flash("This password reset link is invalid or has expired. Please request a new one.", "error")
        return render_template("reset_password.html", valid=False)

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not _is_strong_password(new_password):
            flash(
                "Password must be at least 8 characters with at least one letter and one number.",
                "error",
            )
            return render_template("reset_password.html", valid=True)

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", valid=True)

        if consume_reset_token(token, new_password):
            flash("Your password has been updated successfully. Please sign in with your new password.", "success")
            return redirect(url_for("login"))
        else:
            flash("Reset link expired or already used. Please request a new reset link.", "error")
            return render_template("reset_password.html", valid=False)

    return render_template("reset_password.html", valid=True)


# --------------------------------------------------
# DASHBOARD OVERVIEW (USER-ISOLATED)
# --------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    user_id = get_current_user_id()
    df = load_flows(user_id)
    stats = summary(df, user_id)
    alerts = get_alerts(user_id)[:8]
    protocols = []

    if not df.empty:
        proto_col = next((c for c in ["Protocol", "protocol"] if c in df.columns), None)
        if proto_col:
            protocols = [
                {"name": str(name), "count": int(count)}
                for name, count in (
                    df[proto_col]
                    .fillna("Unknown")
                    .astype(str)
                    .value_counts()
                    .head(8)
                    .items()
                )
            ]

    return render_template(
        "dashboard.html",
        summary=stats,
        alerts=alerts,
        protocols=protocols,
    )


# --------------------------------------------------
# TRAFFIC UPLOAD AND PREDICTION PIPELINE
# --------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@login_required
def traffic_upload():
    user_id = get_current_user_id()
    user_flows_file = get_user_flows_file(user_id)

    if request.method == "POST":
        uploaded_file = request.files.get("traffic_file")

        if not uploaded_file or not uploaded_file.filename:
            flash("Please choose a CSV flow dataset or PCAP capture file.", "error")
            return redirect(url_for("traffic_upload"))

        original_filename = secure_filename(uploaded_file.filename)
        if not original_filename:
            original_filename = "network_traffic.csv"

        extension = Path(original_filename).suffix.lower()

        if extension not in ALLOWED_EXTENSIONS:
            flash(
                f"Unsupported file format '{extension}'. Please upload .csv, .pcap, or .pcapng.",
                "error",
            )
            return redirect(url_for("traffic_upload"))

        saved_file = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{original_filename}"
        try:
            uploaded_file.save(saved_file)
        except Exception as e:
            flash(f"Failed to save uploaded file: {e}", "error")
            return redirect(url_for("traffic_upload"))

        try:
            active_predictor = get_predictor()
            if not active_predictor:
                raise RuntimeError("IDS Machine Learning Predictor is not available.")

            # Process input file
            if extension == ".csv":
                raw_df = load_csv(saved_file)
                if raw_df.empty:
                    raise ValueError("The uploaded CSV contains 0 rows.")

                # Run ML Prediction Pipeline
                analyzed_df, analysis_summary = active_predictor.predict_dataframe(raw_df)

            else:
                # PCAP / PCAPNG packet extraction + prediction
                flows_df = extract_flows_from_pcap(saved_file, max_packets=10000)
                analyzed_df, analysis_summary = active_predictor.predict_dataframe(flows_df)

            # Save the enriched analysis table strictly to user's isolated storage
            user_flows_file.parent.mkdir(parents=True, exist_ok=True)
            analyzed_df.to_csv(user_flows_file, index=False)

            # Record alerts and audit history scoped to authenticated user
            new_alerts = record_alerts_from_predictions(analyzed_df, original_filename, user_id=user_id)
            record_analysis_history(
                filename=original_filename,
                total=analysis_summary["total"],
                attacks=analysis_summary["attacks"],
                benign=analysis_summary["benign"],
                confidence=analysis_summary["confidence"],
                user_id=user_id,
            )

            # Store session state for results page
            session["analysis_filename"] = original_filename
            session["analysis_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Clean up uploaded file securely to save disk space
            try:
                if saved_file.exists():
                    saved_file.unlink()
            except OSError:
                pass

            flash(
                f"Successfully analyzed {analysis_summary['total']:,} network flows: "
                f"{analysis_summary['attacks']:,} attacks detected, "
                f"{analysis_summary['benign']:,} benign flows.",
                "success",
            )
            return redirect(url_for("upload_results"))

        except Exception as error:
            logger.exception("Traffic analysis failed")
            try:
                if saved_file.exists():
                    saved_file.unlink()
            except OSError:
                pass

            flash(f"Analysis failed: {error}", "error")
            return redirect(url_for("traffic_upload"))

    # Also list available sample files for easy testing
    sample_files = []
    if SAMPLES_DIR.is_dir():
        for sfile in SAMPLES_DIR.glob("*.csv"):
            sample_files.append({"name": sfile.name, "path": sfile.name})

    return render_template(
        "upload.html",
        flow_count=len(load_flows(user_id)),
        sample_files=sample_files,
    )


@app.route("/upload/load-sample/<filename>", methods=["POST"])
@login_required
def load_sample_file(filename):
    """Convenience action to load a curated sample directly into the authenticated user's workspace."""
    safe_name = secure_filename(filename)
    sample_path = SAMPLES_DIR / safe_name

    if not sample_path.is_file():
        flash(f"Sample file {safe_name} not found.", "error")
        return redirect(url_for("traffic_upload"))

    user_id = get_current_user_id()
    user_flows_file = get_user_flows_file(user_id)

    try:
        active_predictor = get_predictor()
        raw_df = load_csv(sample_path)
        analyzed_df, analysis_summary = active_predictor.predict_dataframe(raw_df)

        user_flows_file.parent.mkdir(parents=True, exist_ok=True)
        analyzed_df.to_csv(user_flows_file, index=False)

        record_alerts_from_predictions(analyzed_df, safe_name, user_id=user_id)
        record_analysis_history(
            filename=safe_name,
            total=analysis_summary["total"],
            attacks=analysis_summary["attacks"],
            benign=analysis_summary["benign"],
            confidence=analysis_summary["confidence"],
            user_id=user_id,
        )

        session["analysis_filename"] = safe_name
        session["analysis_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        flash(
            f"Loaded sample '{safe_name}': {analysis_summary['attacks']:,} attacks, "
            f"{analysis_summary['benign']:,} benign records.",
            "success",
        )
        return redirect(url_for("upload_results"))

    except Exception as e:
        flash(f"Could not load sample file: {e}", "error")
        return redirect(url_for("traffic_upload"))


# --------------------------------------------------
# UPLOAD ANALYSIS RESULTS VIEW (USER-ISOLATED)
# --------------------------------------------------

@app.route("/upload-results")
@login_required
def upload_results():
    user_id = get_current_user_id()
    df = load_flows(user_id)

    if df.empty:
        flash("No analyzed flow data is available. Please upload a dataset first.", "error")
        return redirect(url_for("traffic_upload"))

    filename = session.get("analysis_filename", "latest_flows.csv")
    analysis_time = session.get("analysis_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    total = len(df)
    pred_col = "Prediction" if "Prediction" in df.columns else None

    if pred_col:
        preds = df[pred_col].astype(str).str.strip().str.upper()
        attacks = int(preds.isin(["ATTACK", "MALICIOUS", "1"]).sum())
        benign = int(preds.isin(["BENIGN", "NORMAL", "0"]).sum())
        predictions_available = True
    else:
        attacks = 0
        benign = total
        predictions_available = False

    threat_percentage = round((attacks / total) * 100, 1) if total > 0 else 0.0

    conf_col = next((c for c in ["Confidence", "confidence", "Attack_Probability"] if c in df.columns), None)
    if conf_col:
        conf_numeric = pd.to_numeric(df[conf_col], errors="coerce").dropna()
        if not conf_numeric.empty:
            avg_conf = float(conf_numeric.mean())
            if 0.0 <= avg_conf <= 1.0:
                avg_conf *= 100.0
            confidence = round(avg_conf, 1)
        else:
            confidence = None
    else:
        confidence = None

    # Attack category distribution
    attack_mask = df[pred_col].astype(str).str.strip().str.upper().isin(["ATTACK", "MALICIOUS", "1"]) if pred_col else pd.Series(False, index=df.index)
    if attack_mask.any():
        type_col = next((c for c in ["Attack_Type", "attack_type", "Label"] if c in df.columns), None)
        if type_col:
            dist = df.loc[attack_mask, type_col].astype(str).str.strip().value_counts()
            attack_labels = dist.index.tolist()
            attack_counts = [int(v) for v in dist.tolist()]
        else:
            attack_labels = ["ATTACK"]
            attack_counts = [int(attack_mask.sum())]
    else:
        attack_labels = ["No Attacks"]
        attack_counts = [0]

    records_preview = []
    for idx, row in df.iterrows():
        conf_val = float(row.get("Confidence", 100.0)) if pd.notna(row.get("Confidence")) else 100.0
        records_preview.append({
            "id": int(row.get("Flow_ID", idx + 1)),
            "flow_id": int(row.get("Flow_ID", idx + 1)),
            "timestamp": str(row.get("Timestamp", "-")),
            "protocol": str(row.get("Protocol", row.get("protocol", "TCP"))),
            "source_ip": str(row.get("Source_IP", row.get("src_ip", "-"))),
            "source_port": int(row.get("Source_Port", row.get("src_port", 0))),
            "destination_ip": str(row.get("Destination_IP", row.get("dst_ip", "-"))),
            "destination_port": int(row.get("Destination_Port", row.get("dst_port", 0))),
            "prediction": str(row.get("Prediction", "BENIGN")),
            "attack_type": str(row.get("Attack_Type", row.get("Label", "Normal Traffic"))),
            "confidence": conf_val,
            "confidence_str": f"{conf_val:.1f}%",
            "duration": float(row.get("Duration", 0.0)) if pd.notna(row.get("Duration")) else 0.0,
            "source_bytes": int(row.get("Source_Bytes", 0)) if pd.notna(row.get("Source_Bytes")) else 0,
            "download_bytes": int(row.get("Download_Bytes", 0)) if pd.notna(row.get("Download_Bytes")) else 0,
            "fwd_packets": int(row.get("Fwd_Packets", 1)) if pd.notna(row.get("Fwd_Packets")) else 1,
            "bwd_packets": int(row.get("Bwd_Packets", 1)) if pd.notna(row.get("Bwd_Packets")) else 1,
            "mode": "CSV Analysis",
        })

    return render_template(
        "upload_results.html",
        filename=filename,
        analysis_time=analysis_time,
        total=total,
        attacks=attacks,
        benign=benign,
        confidence=confidence,
        threat_percentage=threat_percentage,
        predictions_available=predictions_available,
        attack_labels=attack_labels,
        attack_counts=attack_counts,
        records=records_preview,
    )


# --------------------------------------------------
# LIVE MONITORING (USER-CONTROLLED, DOES NOT AUTO-START)
# --------------------------------------------------

@app.route("/live")
@login_required
def live_monitoring():
    """
    Renders the live telemetry console.
    CRITICAL: Does NOT automatically start packet capture or stream replay.
    Monitoring starts ONLY when the user explicitly clicks Start Monitoring.
    """
    user_id = get_current_user_id()
    df = load_flows(user_id)
    flow_count = len(df)
    caps = check_capture_capabilities()
    interfaces = get_available_interfaces()
    streamer = LiveTrafficManager.get_instance(user_id)

    return render_template(
        "live.html",
        flow_count=flow_count,
        capabilities=caps,
        interfaces=interfaces,
        streamer_running=streamer.is_running,
        streamer_paused=streamer.is_paused,
        streamer_mode=streamer.mode,
    )


@app.route("/api/live/interfaces")
@login_required
def api_live_interfaces():
    """Returns detected physical and virtual network adapters."""
    refresh = request.args.get("refresh", "false").lower() in ("true", "1", "yes")
    ifs = get_available_interfaces(refresh=refresh)
    caps = check_capture_capabilities(refresh=refresh)
    return jsonify({
        "interfaces": ifs,
        "can_sniff": caps["can_sniff"],
        "message": caps["message"],
    })


@app.route("/api/live/stream")
@login_required
def api_live_stream():
    """Returns real-time streaming classification items for the authenticated user."""
    user_id = get_current_user_id()
    streamer = LiveTrafficManager.get_instance(user_id)
    records = streamer.get_latest_records(count=100)
    return jsonify(records)


@app.route("/api/live/toggle", methods=["POST"])
@login_required
def api_live_toggle():
    """
    Explicit start, pause, resume, or stop control for live monitoring.
    Scoped strictly to the authenticated user's session to prevent cross-user interference.
    """
    user_id = get_current_user_id()
    streamer = LiveTrafficManager.get_instance(user_id)
    payload = request.get_json(silent=True) or {}
    action = payload.get("action", "toggle")
    mode = payload.get("mode", "demo")
    interface = payload.get("interface", None)

    if action == "start":
        if not streamer.is_running or streamer.is_paused:
            streamer.start(mode=mode, interface=interface, interval_seconds=1.2)
        if streamer.error_message:
            status = "error"
        else:
            status = "running"
    elif action == "pause":
        streamer.pause()
        status = "paused"
    elif action == "resume":
        streamer.resume()
        status = "running"
    elif action == "stop":
        streamer.stop()
        status = "stopped"
    elif action == "clear":
        streamer.clear()
        status = "cleared"
    else:
        # Toggle fallback
        if not streamer.is_running or streamer.is_paused:
            streamer.start(mode=mode, interface=interface, interval_seconds=1.2)
            status = "running"
        else:
            streamer.stop()
            status = "stopped"

    return jsonify({
        "status": status,
        "is_running": streamer.is_running,
        "is_paused": streamer.is_paused,
        "mode": streamer.mode,
        "interface": streamer.current_interface,
        "error": streamer.error_message,
    })


@app.route("/api/live/clear", methods=["POST"])
@login_required
def api_live_clear():
    """Reset live monitoring session buffer for the authenticated user."""
    user_id = get_current_user_id()
    streamer = LiveTrafficManager.get_instance(user_id)
    streamer.clear()
    return jsonify({"status": "cleared", "total_streamed": 0})


# --------------------------------------------------
# THREAT REPORTS & HISTORY (USER-ISOLATED)
# --------------------------------------------------

@app.route("/reports")
@login_required
def threat_reports():
    user_id = get_current_user_id()
    df = load_flows(user_id)
    stats = summary(df, user_id)
    alerts = get_alerts(user_id)
    history = get_history(user_id)

    category_counts = {}
    if not df.empty and "Prediction" in df.columns:
        preds = df["Prediction"].astype(str).str.strip().str.upper()
        attacks_df = df[preds.isin(["ATTACK", "MALICIOUS", "1"])]
        if not attacks_df.empty:
            type_col = next((c for c in ["Attack_Type", "attack_type", "Label"] if c in attacks_df.columns), None)
            if type_col:
                category_counts = attacks_df[type_col].value_counts().to_dict()
    if not category_counts and alerts:
        category_counts = pd.Series([a.get("type", "Unknown") for a in alerts]).value_counts().to_dict()

    return render_template(
        "reports.html",
        summary=stats,
        alerts=alerts,
        history=history,
        category_counts=category_counts,
    )


@app.route("/download/alerts/csv")
@login_required
def download_alerts_csv():
    """Export the authenticated user's security alerts as CSV file."""
    user_id = get_current_user_id()
    alerts = get_alerts(user_id)
    if not alerts:
        flash("No logged alerts available for CSV export.", "error")
        return redirect(url_for("threat_reports"))

    user_dir = get_user_data_dir(user_id)
    csv_file = user_dir / "exported_alerts.csv"
    alerts_df = pd.DataFrame(alerts)
    alerts_df.to_csv(csv_file, index=False)
    return send_file(
        csv_file,
        as_attachment=True,
        download_name="secureflow_alerts.csv",
        mimetype="text/csv",
    )


# --------------------------------------------------
# BLOCKED IP LIST (USER-ISOLATED WITH AUTHORIZATION CHECK)
# --------------------------------------------------

@app.route("/blocked-ips", methods=["GET", "POST"])
@login_required
def blocked_ips():
    user_id = get_current_user_id()

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        reason = request.form.get("reason", "").strip() or "Manually added by user"

        if ":" in ip and not ip.startswith("["):
            ip = ip.split(":")[0].strip()

        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_clean = str(ip_obj)

            added = add_user_blocked(user_id, ip_clean, reason, source="User Console")
            if added:
                flash(f"Added {ip_clean} to dashboard blocked list.", "success")
            else:
                flash(f"IP address {ip_clean} is already in your blocked list.", "error")

        except ValueError:
            flash(f"Invalid IP address: '{ip}'. Enter a valid IPv4 or IPv6 address.", "error")

        return redirect(url_for("blocked_ips"))

    blocked = get_blocked(user_id)
    return render_template(
        "blocked_ips.html",
        blocked=blocked,
    )


@app.post("/blocked-ips/<item_id>/remove")
@login_required
def remove_blocked_ip(item_id):
    """
    Remove a blocked IP.
    Enforces user_id check in DB query to prevent cross-user record removal.
    """
    user_id = get_current_user_id()
    removed = remove_user_blocked(user_id, item_id)
    if removed:
        flash("Removed IP from dashboard block list.", "success")
    else:
        flash("Unable to remove IP from blocked list or permission denied.", "error")
    return redirect(url_for("blocked_ips"))


# --------------------------------------------------
# JSON APIs (USER-ISOLATED)
# --------------------------------------------------

@app.route("/api/summary")
@login_required
def api_summary():
    user_id = get_current_user_id()
    return jsonify(summary(load_flows(user_id), user_id))


@app.route("/api/alerts")
@login_required
def api_alerts():
    user_id = get_current_user_id()
    return jsonify(get_alerts(user_id)[:100])


# --------------------------------------------------
# FILE DOWNLOADS (USER-ISOLATED)
# --------------------------------------------------

@app.route("/download/flows")
@app.route("/download/predictions")
@login_required
def download_flows():
    user_id = get_current_user_id()
    flows_file = get_user_flows_file(user_id)
    if not flows_file.exists():
        flash("No analyzed flow dataset is available for download yet.", "error")
        return redirect(url_for("traffic_upload"))

    return send_file(
        flows_file,
        as_attachment=True,
        download_name="secureflow_ids_predictions.csv",
        mimetype="text/csv",
    )


@app.route("/download/alerts")
@login_required
def download_alerts():
    user_id = get_current_user_id()
    alerts = get_alerts(user_id)
    if not alerts:
        flash("No alerts recorded yet.", "error")
        return redirect(url_for("threat_reports"))

    user_dir = get_user_data_dir(user_id)
    json_file = user_dir / "exported_alerts.json"
    json_file.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

    return send_file(
        json_file,
        as_attachment=True,
        download_name="secureflow_alerts.json",
        mimetype="application/json",
    )


# --------------------------------------------------
# APPLICATION ENTRYPOINT
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
