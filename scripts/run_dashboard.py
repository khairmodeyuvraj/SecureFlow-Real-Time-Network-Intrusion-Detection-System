from pathlib import Path
import os
import sys

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.app import app

if __name__ == "__main__":
    host = os.environ.get("SECUREFLOW_HOST", "127.0.0.1")
    port = int(os.environ.get("SECUREFLOW_PORT", 5000))
    debug = os.environ.get("SECUREFLOW_DEBUG", "True").lower() == "true"

    print("=" * 70)
    print("Starting SecureFlow AI-Based Intrusion Detection System")
    print(f"Server URL: http://{host}:{port}")
    print(f"Default login: admin / SecureFlow@123")
    print("=" * 70)

    app.run(
        host=host,
        port=port,
        debug=debug,
    )
