
from pathlib import Path
import os
import sys

# Ensure project root is in Python module search path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env", override=False)
except ImportError:
    pass

from dashboard.app import app

if __name__ == "__main__":
    host = os.environ.get("SECUREFLOW_HOST", "127.0.0.1")
    port = int(os.environ.get("SECUREFLOW_PORT", 5000))
    debug = os.environ.get("SECUREFLOW_DEBUG", "False").lower() == "true"

    print("=" * 70)
    print("SecureFlow: A Real-Time Network Intrusion Detection System")
    print("=" * 70)
    print(f"  Access Dashboard at : http://{host}:{port}")
    print("=" * 70)

    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False
    )
