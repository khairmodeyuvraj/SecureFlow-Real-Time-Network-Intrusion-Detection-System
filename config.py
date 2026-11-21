import os
from pathlib import Path

# ============================================================
# PROJECT ROOT AND DIRECTORY STRUCTURE
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

# Automatically load environment variables from .env file
ENV_FILE = PROJECT_ROOT / ".env"


def load_project_env(override: bool = True) -> bool:
    """Explicitly load environment variables from the project root .env file."""
    if not ENV_FILE.exists():
        return False
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=ENV_FILE, override=override)
        return True
    except ImportError:
        try:
            with open(ENV_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k and (override or k not in os.environ):
                            os.environ[k] = v
            return True
        except Exception:
            return False


# Initial environment load on module import
load_project_env(override=True)

MODELS_DIR = PROJECT_ROOT / "models"
MODEL_PATH = MODELS_DIR / "final_ids_model.pkl"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw" / "CICIDS2017"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLES_DIR = DATA_DIR / "samples"
FEATURE_CONFIG_PATH = PROCESSED_DATA_DIR / "feature_config.json"

RESULTS_DIR = PROJECT_ROOT / "results"
ALERTS_DIR = RESULTS_DIR / "alerts"
PREDICTIONS_DIR = RESULTS_DIR / "predictions"
FIGURES_DIR = RESULTS_DIR / "figures"
METRICS_DIR = RESULTS_DIR / "metrics"

DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
UPLOAD_DIR = DASHBOARD_DIR / "uploads"
DASHBOARD_RESULTS_DIR = DASHBOARD_DIR / "results"

# Standard runtime data stores
LATEST_FLOWS_FILE = DASHBOARD_RESULTS_DIR / "latest_flows.csv"
ALERTS_FILE = DASHBOARD_RESULTS_DIR / "alerts.json"
BLOCKED_FILE = DASHBOARD_RESULTS_DIR / "blocked_ips.json"
HISTORY_FILE = DASHBOARD_RESULTS_DIR / "history.json"

# Ensure runtime directories exist
for directory in [
    MODELS_DIR,
    DATA_DIR,
    PROCESSED_DATA_DIR,
    SAMPLES_DIR,
    RESULTS_DIR,
    ALERTS_DIR,
    PREDICTIONS_DIR,
    FIGURES_DIR,
    METRICS_DIR,
    DASHBOARD_DIR,
    UPLOAD_DIR,
    DASHBOARD_RESULTS_DIR,
]:
    directory.mkdir(parents=True, exist_ok=True)


# ============================================================
# APPLICATION SETTINGS
# ============================================================

SECRET_KEY = os.environ.get(
    "SECUREFLOW_SECRET_KEY",
    "secureflow-production-secret-key-ids-ai",
)

LOGIN_USERNAME = os.environ.get("SECUREFLOW_USERNAME", "admin")
LOGIN_PASSWORD = os.environ.get("SECUREFLOW_PASSWORD", "SecureFlow@123")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI",
    "http://127.0.0.1:5000/auth/google/callback",
).strip()

APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000").strip().rstrip("/")


def is_google_oauth_configured() -> bool:
    """Returns True if Google OAuth Client ID and Secret are configured with real values."""
    cid = os.environ.get("GOOGLE_CLIENT_ID", GOOGLE_CLIENT_ID).strip()
    csec = os.environ.get("GOOGLE_CLIENT_SECRET", GOOGLE_CLIENT_SECRET).strip()
    placeholders = {
        "",
        "your_google_client_id",
        "your_google_client_secret",
        "your_google_client_id_here.apps.googleusercontent.com",
        "your_google_client_secret_here",
    }
    return bool(cid and csec and cid not in placeholders and csec not in placeholders)


# ============================================================
# SMTP & EMAIL NOTIFICATION CONFIGURATION
# ============================================================

def get_smtp_config() -> dict:
    """
    Retrieve and parse all SMTP parameters dynamically from environment.
    Always parses SMTP_PORT as int, SMTP_USE_TLS as boolean, and defaults
    SMTP_SENDER_EMAIL to SMTP_USERNAME if empty.
    """
    load_project_env(override=False)

    host = os.environ.get("SMTP_HOST", "").strip()

    port_raw = os.environ.get("SMTP_PORT", "587").strip()
    try:
        port = int(port_raw)
    except (ValueError, TypeError):
        port = 587

    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "").strip().replace(" ", "")

    tls_raw = os.environ.get("SMTP_USE_TLS", "true").strip().lower()
    use_tls = tls_raw in ("true", "1", "yes", "on", "t")

    sender = os.environ.get("SMTP_SENDER_EMAIL", "").strip() or username

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "use_tls": use_tls,
        "sender": sender,
    }


def is_smtp_configured() -> bool:
    """
    Returns True if SMTP_HOST, SMTP_USERNAME, and SMTP_PASSWORD are non-empty.
    Does NOT use hardcoded placeholder blacklists so valid credentials are never rejected.
    """
    cfg = get_smtp_config()
    return bool(cfg["host"] and cfg["username"] and cfg["password"])


# Static module-level accessors for backward compatibility
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
except (ValueError, TypeError):
    SMTP_PORT = 587
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")
SMTP_SENDER_EMAIL = os.environ.get("SMTP_SENDER_EMAIL", "").strip() or SMTP_USERNAME


MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 Megabytes
ALLOWED_EXTENSIONS = {".csv", ".pcap", ".pcapng"}

# Model classification target mapping
TARGET_MAPPING = {
    0: "BENIGN",
    1: "ATTACK",
}
CLASS_COLORS = {
    "BENIGN": "#16a36a",
    "ATTACK": "#e34f55",
}
