# SecureFlow Flask dashboard starter

Flask + HTML/CSS/JavaScript + Chart.js starter based on your reference screenshot.

## Install/run
Place this folder at `D:\AI-IDS\dashboard_flask`, then in PowerShell:

```powershell
cd D:\AI-IDS\dashboard_flask
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

PCAP uploads call the existing `D:\AI-IDS\src\network\pcap_reader.py`. Use your small test PCAP first. CSV uploads load extracted flow data.

Important:
- This starter does not run the ML model. Prediction integration is intentionally pending feature-unit validation.
- Alerts are recorded only if an uploaded CSV already contains a `Prediction` column with `ATTACK`, `MALICIOUS`, or `1`.
- The live page is a batch-data placeholder, not live packet sniffing.
- The Blocked IPs page stores a dashboard list only; it does not change Windows Firewall.
- Before exposing this app beyond localhost, add authentication, CSRF protection, upload size limits, and a production WSGI server.


## Login page
- Demo username: `admin`
- Demo password: `SecureFlow@123`
- Set `SECUREFLOW_USERNAME`, `SECUREFLOW_PASSWORD`, and `SECUREFLOW_SECRET_KEY` environment variables before using beyond local testing.
- Forgot-password is a placeholder; email reset is not configured.
