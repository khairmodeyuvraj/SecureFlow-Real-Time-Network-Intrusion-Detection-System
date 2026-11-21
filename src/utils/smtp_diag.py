"""
SecureFlow SMTP Safe Diagnostic Utility.

Inspects environment variable loading and tests SMTP connectivity
WITHOUT exposing passwords, secrets, or sensitive credentials.
"""
import argparse
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import ENV_FILE, get_smtp_config, load_project_env
from dashboard.user_db import verify_smtp_credentials, send_password_reset_email


def run_diagnostics(test_recipient: str = None) -> bool:
    load_project_env(override=True)
    cfg = get_smtp_config()

    print("=" * 65)
    print(" SecureFlow AI-IDS · Safe SMTP Configuration Diagnostics")
    print("=" * 65)

    print(f"1. .env File Status:")
    print(f"   - Target Path: {ENV_FILE}")
    print(f"   - Exists: {'YES' if ENV_FILE.exists() else 'NO (Missing)'}")

    print(f"\n2. Environment Variables Configuration Status:")
    print(f"   - SMTP_HOST:         {'Configured (' + cfg['host'] + ')' if cfg['host'] else 'NOT CONFIGURED'}")
    print(f"   - SMTP_PORT:         {cfg['port']} ({'Configured' if cfg['port'] else 'Default: 587'})")
    print(f"   - SMTP_USERNAME:     {'Configured (Length: ' + str(len(cfg['username'])) + ' chars)' if cfg['username'] else 'NOT CONFIGURED'}")
    print(f"   - SMTP_PASSWORD:     {'Configured (Length: ' + str(len(cfg['password'])) + ' chars, Masked: [PROTECTED])' if cfg['password'] else 'NOT CONFIGURED'}")
    print(f"   - SMTP_USE_TLS:      {cfg['use_tls']} (STARTTLS enabled)")
    print(f"   - SMTP_SENDER_EMAIL: {'Configured (' + cfg['sender'] + ')' if cfg['sender'] else 'Defaults to SMTP_USERNAME'}")

    print(f"\n3. Live Handshake & Authentication Test:")
    diag = verify_smtp_credentials()
    print(f"   - TCP Connection:     {'SUCCESS' if diag['connection_successful'] else 'FAILED'}")
    print(f"   - STARTTLS Layer:     {'SUCCESS' if diag['tls_successful'] else 'FAILED'}")
    print(f"   - Authentication:     {'SUCCESS' if diag['authentication_successful'] else 'FAILED'}")
    print(f"   - Detailed Status:    {diag['status_message']}")

    if test_recipient:
        print(f"\n4. Test Email Dispatch to {test_recipient}:")
        success, msg = send_password_reset_email(
            to_email=test_recipient,
            recipient_name="SecureFlow Administrator",
            reset_url="http://127.0.0.1:5000/reset-password/sample-test-token",
        )
        print(f"   - Result: {'DELIVERED' if success else 'FAILED'}")
        print(f"   - Response: {msg}")

    print("=" * 65)
    return diag["authentication_successful"]


def main():
    parser = argparse.ArgumentParser(description="SecureFlow Safe SMTP Diagnostics")
    parser.add_argument("--send-test", dest="recipient", default=None, help="Send a real test email to specified address")
    args = parser.parse_args()
    success = run_diagnostics(test_recipient=args.recipient)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

