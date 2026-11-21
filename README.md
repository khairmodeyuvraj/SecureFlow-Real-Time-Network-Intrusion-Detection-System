# SecureFlow: AI-Based Intrusion Detection System (IDS)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-orange.svg)](https://scikit-learn.org/)
[![Dashboard](https://img.shields.io/badge/Frontend-Flask%20%7C%20Chart.js-green.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-58%20Passed-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/Security-AES%20%7C%20PBKDF2%20%7C%20OAuth2-cyan.svg)]()

SecureFlow is an enterprise-grade **AI-Based Intrusion Detection System (IDS)** designed to analyze bidirectional network traffic telemetry and detect malicious intrusions in real time. Leveraging an optimized Random Forest classifier trained on the benchmark **CICIDS2017** dataset, SecureFlow inspects bidirectional network flows, extracts 74 statistical flow metrics, and flags anomalous or hostile traffic with **99.86% classification accuracy**.

---

## 1. Project Objectives

- **High-Precision Intrusion Detection**: Detect network attacks (DDoS, PortScan, Brute Force, Web Attacks, Botnets, Infiltration) with near-zero false positive rates.
- **Real-Time Network Telemetry**: Provide live flow aggregation, packet feature extraction, and instantaneous threat classification.
- **Multi-Format Ingestion**: Ingest raw CICIDS2017 datasets, preprocessed ML matrices, PCAP captures, and live hardware network packet streams.
- **Enterprise Multi-User Isolation**: Ensure complete multi-tenant privacy where every security analyst operates within an isolated workspace.
- **Manual, Safe Monitoring Workflow**: Give security operators complete control over packet sniffing without unauthorized or automatic background capture.

---

## 2. Main Features

- **Automated AI Inference Engine**:
  - Pre-trained Random Forest ensemble model (`models/final_ids_model.pkl`) evaluating 74 statistical flow features.
  - Predicts binary classifications (`BENIGN` vs. `ATTACK`) with high-confidence probability metrics.
  - Generates deep telemetry feature vectors for inspection modals.
- **Controlled Live Network Monitoring**:
  - **Manual 5-Step Workflow**: Opening the monitoring page never captures packets automatically; capture initiates strictly upon an explicit click on **Start Monitoring**.
  - **Dual Telemetry Modes**:
    1. *Live Hardware Packet Capture (Scapy)*: Real-time network adapter sniffing with Npcap integration and Windows privilege validation.
    2. *Demonstration Stream (Recorded Benchmark Flows)*: High-fidelity benchmark traffic replay through the live inference engine.
  - Dynamic timeline charts, throughput meters, and progressive confidence indicators.
  - Safe session termination, buffer flushing, and worker thread lifecycle management.
- **Deep Flow Telemetry & Classification Grid**:
  - Detailed table with sortable columns: `#`, `IP Address`, `Destination IP`, `Prediction`, `Attack Type`, `Confidence`, `Duration`, `Source Bytes`, `Download Bytes`, `Timestamp`, and `Protocol`.
  - **Deep Telemetry Modal**: View bidirectional packet counts, forward/backward header lengths, inter-arrival times (IAT), TCP flags, and one-click IP blocking.
- **Enterprise Authentication & User Isolation**:
  - Local email/password registration with PBKDF2-SHA256 password hashing.
  - Google OAuth 2.0 / OpenID Connect Single Sign-On (SSO).
  - Cryptographic password recovery via one-time SHA-256 tokens and Gmail SMTP delivery.
  - User-specific SQLite databases, audit trails, and defensive blacklists.
- **Threat Reports & Defensive Blacklisting**:
  - Historical analysis run logging with threat percentage breakdowns and CSV alert exports.
  - Blocked IP management with IPv4/IPv6 validation.

---

## 3. Technology Stack

- **Language & Runtime**: Python 3.10+ (tested on Python 3.12 and Python 3.14 on Windows & Linux)
- **Machine Learning & Data Science**: Scikit-Learn, NumPy, Pandas, Joblib, SciPy
- **Web Application & Backend**: Flask, Werkzeug, Jinja2, Python-Dotenv
- **Network Packet Capture & Telemetry**: Scapy, Psutil, Npcap (Windows) / libpcap (Linux)
- **Frontend & Visualizations**: HTML5, Modern Glassmorphic CSS3 (Dark Navy & Cyan theme), JavaScript (ES6+), Chart.js
- **Database & Storage**: SQLite 3 (WAL mode enabled), JSON, CSV
- **Testing & Quality Assurance**: Pytest (58 comprehensive unit & integration tests)

---

## 4. Project Architecture

```
                     ┌───────────────────────────────────────────────┐
                     │               Network Sources                 │
                     │  • Live Hardware Interface (Scapy / Npcap)    │
                     │  • PCAP Files (.pcap / .pcapng)               │
                     │  • CSV Flow Datasets (CICIDS2017 / Custom)    │
                     └───────────────────────┬───────────────────────┘
                                             │ Raw Packets / Flows
                                             ▼
                     ┌───────────────────────────────────────────────┐
                     │          Network Telemetry Pipeline           │
                     │  • FlowManager (5-tuple bi-directional agg)   │
                     │  • Feature Extractor (74 statistical metrics) │
                     │  • Robust Scaler & NaN/Inf Sanitizer          │
                     └───────────────────────┬───────────────────────┘
                                             │ Normalized 74-Feature Vector
                                             ▼
                     ┌───────────────────────────────────────────────┐
                     │          Machine Learning Classifier          │
                     │   RandomForestClassifier (74 Flow Features)   │
                     │       Binary Inference & Confidence Scores    │
                     └───────────────────────┬───────────────────────┘
                                             │ Prediction, Confidence, Type
                                             ▼
                     ┌───────────────────────────────────────────────┐
                     │          SecureFlow Flask Backend             │
                     │  • User Data Isolation & SQLite Persistence   │
                     │  • Session Security, Google OAuth, SMTP Mail  │
                     │  • Real-time REST APIs (/api/live/stream)     │
                     └───────────────────────┬───────────────────────┘
                                             │ JSON & HTML Telemetry
                                             ▼
                     ┌───────────────────────────────────────────────┐
                     │        Security Operations Dashboard          │
                     │  • Overview & Attack Severity Meters          │
                     │  • Real-Time Threat Ingestion Timeline        │
                     │  • Detailed Classified Records & Modal        │
                     └───────────────────────────────────────────────┘
```

---

## 5. Project Folder Structure

```text
AI-IDS/
├── app.py                      # Application root entry point
├── config.py                   # Central paths, thresholds, and environment configuration
├── requirements.txt            # Python package dependencies
├── pytest.ini                  # Pytest configuration and test options
├── README.md                   # Comprehensive project documentation
├── .gitignore                  # Git ignore rules (protects credentials and databases)
│
├── dashboard/                  # Flask web application module
│   ├── app.py                  # Web application routes, authentication, and REST APIs
│   ├── user_db.py              # SQLite user management, isolation, and SMTP functions
│   ├── users.db                # Auto-generated local SQLite database (git-ignored)
│   ├── static/
│   │   ├── css/style.css       # SecureFlow dark navy & cyan UI stylesheet
│   │   └── js/app.js           # Client-side validation and interactive utilities
│   ├── templates/              # Jinja2 HTML templates
│   │   ├── base.html           # Master layout with sidebar navigation
│   │   ├── dashboard.html      # Overview metrics, charts, and alert tables
│   │   ├── live.html           # Live intrusion monitoring console
│   │   ├── upload.html         # CSV and PCAP file upload interface
│   │   ├── upload_results.html # Detailed classified flow records grid
│   │   ├── reports.html        # Historical session logs and alert exports
│   │   ├── blocked_ips.html    # Defensive IP blacklist management
│   │   ├── login.html          # Sign-in portal with Google OAuth button
│   │   ├── register.html       # User account registration page
│   │   ├── forgot_password.html# Password reset request form
│   │   └── reset_password.html # New password confirmation form
│   ├── results/                # User session analysis history and alert stores
│   └── uploads/                # Secure temporary directory for file processing
│
├── models/                     # Trained machine learning model artifacts
│   ├── final_ids_model.pkl     # Trained Random Forest Scikit-learn Pipeline (69.1 MB)
│   └── model_metadata.json     # Feature list, hyperparameters, and benchmark metrics
│
├── src/                        # Core source code modules
│   ├── data/                   # Data ingestion, schema validation, and dataset splitting
│   ├── features/               # 74 flow feature extraction, ratio engineering, and cleaning
│   ├── inference/              # Multi-format preprocessor and singleton predictor engine
│   ├── network/                # Flow aggregation, packet capture, and adapter enumeration
│   │   ├── flow_builder.py     # Bidirectional 5-tuple flow aggregation
│   │   └── packet_capture.py   # Psutil adapter detection and Scapy capture engine
│   └── utils/                  # Centralized logging and evaluation utilities
│
├── realtime/                   # Standalone console intrusion detection engine
│   └── realtime_ids.py         # Terminal-based live capture runner and CSV detection logger
│
├── data/                       # Datasets and samples
│   ├── samples/                # Curated demonstration CSVs (mixed, attacks, benign)
│   └── pcap/                   # Packet capture files
│
├── scripts/                    # Command-line utility scripts
│   ├── run_dashboard.py        # Web console launcher
│   ├── evaluate_model.py       # Performance evaluation on benchmark datasets
│   └── capture_traffic.py      # Standalone adapter discovery test utility
│
└── tests/                      # Automated test suite (58 tests)
    ├── test_dashboard.py       # Flask endpoints, authentication, and file upload tests
    ├── test_registration.py    # Multi-user isolation, SMTP recovery, and adapter detection
    ├── test_inference.py       # Predictor and preprocessor schema validation tests
    ├── test_model.py           # Model loading, metadata, and synthetic inference
    ├── test_features.py        # Flow feature calculations and numerical sanitization
    ├── test_data.py            # Dataset loading and stratification tests
    └── test_network.py         # FlowManager session timeouts and packet aggregation
```

---

## 6. Installation & Setup

### Step 1: Clone or Navigate to the Repository
```powershell
git clone https://github.com/your-username/SecureFlow-AI-IDS.git
cd SecureFlow-AI-IDS
```

### Step 2: Set Up Virtual Environment
On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 7. Environment Configuration Instructions

SecureFlow loads application settings from a local `.env` file in the project root directory.

Create a `.env` file in the project root with the following parameters:

```env
# Flask Application Security
SECRET_KEY=generate_a_secure_random_hex_string_here
FLASK_DEBUG=0
APP_BASE_URL=http://127.0.0.1:5000

# Administrator Credentials (Backward Compatibility)
SECUREFLOW_USERNAME=admin
SECUREFLOW_PASSWORD=YourStrongPasswordHere

# Google OAuth 2.0 Single Sign-On (Optional)
GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REDIRECT_URI=http://127.0.0.1:5000/auth/google/callback

# SMTP Email Delivery (Password Reset Service)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_gmail_address@gmail.com
SMTP_PASSWORD=your_16_char_gmail_app_password
SMTP_USE_TLS=true
SMTP_SENDER_EMAIL=your_gmail_address@gmail.com
```

> [!IMPORTANT]
> Never commit your `.env` file to version control. The `.gitignore` file automatically excludes all `.env` files to prevent credential leakage.

---

## 8. Google OAuth 2.0 Setup

SecureFlow provides Google Sign-In alongside standard email/password authentication.

1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Create or select a Google Cloud project.
3. Configure the **OAuth Consent Screen**:
   - Set User Type to **External**.
   - Add scopes: `.../auth/userinfo.email`, `.../auth/userinfo.profile`, `openid`.
   - Add your test user email addresses under **Test Users**.
4. Create **OAuth 2.0 Client Credentials**:
   - Application Type: **Web application**.
   - Name: `SecureFlow IDS`.
   - **Authorized JavaScript origins**: `http://127.0.0.1:5000`
   - **Authorized redirect URIs**: `http://127.0.0.1:5000/auth/google/callback`
5. Copy your **Client ID** and **Client Secret** into your `.env` file.

---

## 9. Gmail SMTP Setup

SecureFlow delivers password reset links via standard SMTP with STARTTLS encryption.

1. Enable **2-Step Verification** on your Google Account:
   - Go to [Google Account Security](https://myaccount.google.com/security).
2. Generate an **App Password**:
   - Navigate to **App passwords** (search "App passwords" in account settings).
   - Create a new App Password named `SecureFlow IDS`.
   - Google will provide a 16-character code (e.g. `abcd efgh ijkl mnop`).
3. Set the credentials in `.env`:
   - `SMTP_HOST=smtp.gmail.com`
   - `SMTP_PORT=587`
   - `SMTP_USERNAME=your_email@gmail.com`
   - `SMTP_PASSWORD=your_16_character_app_password`
   - `SMTP_USE_TLS=true`
   - `SMTP_SENDER_EMAIL=your_email@gmail.com`
4. Verify SMTP reachability:
   - While logged in as `admin`, visit: `http://127.0.0.1:5000/admin/smtp-diag`
   - Send a live test email by appending: `?send_to=your_email@gmail.com`

---

## 10. Database Initialization

SecureFlow uses an isolated SQLite database (`dashboard/users.db`) to manage user accounts, sessions, alerts, analysis history, and blocked IPs.

- **Automatic Initialization**: You do not need to run manual migration scripts. When the Flask server starts, `init_db()` in `dashboard/user_db.py` automatically checks and creates all necessary SQLite tables:
  - `users`: Stores user profiles, PBKDF2 password hashes, and Google OAuth IDs.
  - `password_reset_tokens`: Stores SHA-256 hashed one-time tokens with 30-minute expiration.
  - `user_alerts`: User-isolated intrusion detection events.
  - `user_analysis_history`: User-isolated batch upload records.
  - `user_blocked_ips`: User-isolated defensive IP blacklists.
- The baseline administrator account (`admin`) is seeded automatically on initial launch.

---

## 11. Application Execution Commands

Launch SecureFlow from the project root using any of the following methods:

```powershell
# Method 1: Root entry point (Recommended)
python app.py

# Method 2: Module execution
python -m dashboard.app

# Method 3: Script runner
python scripts/run_dashboard.py
```

Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

### Initial Administrator Credentials
- **Username**: `admin`
- **Password**: `SecureFlow@123`

---

## 12. CSV Traffic Analysis Instructions

1. Click **Traffic Upload** in the sidebar.
2. Choose a network capture file:
   - Upload any custom CSV or PCAP file.
   - Or click one of the pre-packaged demonstration datasets:
     - **Test Mixed Traffic**: Representative balance of benign and attack flows.
     - **Test Attacks Only**: High-density hostile traffic (DDoS, PortScan, Infiltration).
     - **Test Benign Only**: Clean enterprise baseline traffic.
3. Click **Run AI Detection**.
4. The system validates the schema, computes 74 statistical flow metrics, classifies each flow, logs threat alerts, and redirects to the **Analysis Results** page.
5. In Analysis Results:
   - Filter by classification (`All`, `Attacks Only`, `Normal Only`).
   - Search across IP endpoints, ports, protocols, or attack categories.
   - Click **View Details (⌕)** on any row to open the Deep Telemetry Modal.
   - Download the full classified CSV with **↓ Export Predictions CSV**.

---

## 13. Live Monitoring Instructions

SecureFlow implements a strict **5-Step Manual Workflow** for real-time monitoring:

```
[ Step 1: Open Live Monitoring ]
         │ (Console opens in IDLE state; zero capture threads, zero driver calls)
         ▼
[ Step 2: Select Telemetry Mode ]
         │ (Choose 'Demonstration Stream' or 'Live Hardware Packet Capture')
         ▼
[ Step 3: Select Network Interface ]
         │ (Choose your active physical network adapter, e.g. Wi-Fi or Ethernet)
         ▼
[ Step 4: Click ▶ Start Monitoring ]
         │ (Validates mode & interface, checks OS permissions, starts capture & ML)
         ▼
[ Step 5: Click ⏹ Stop Monitoring ]
         │ (Terminates capture immediately, safely joins threads, releases handles)
```

1. **Open Live Monitoring**: Click **Live Monitoring** in the sidebar. The engine loads in an **idle state** (`● Engine Ready`). No background threads or network sniffers execute.
2. **Select Telemetry Mode**:
   - **Demonstration Stream (Recorded Benchmark Flows)**: Safe, high-fidelity real-time flow replay passing 74 features through the live ML predictor.
   - **Live Hardware Packet Capture (Scapy)**: Direct hardware packet sniffing on physical/virtual network adapters.
3. **Select Network Interface**: When hardware capture is selected, choose your target adapter from the detected network interfaces.
4. **Start Monitoring**: Click **▶ Start Monitoring**. The backend validates the inputs, initializes capture, aggregates flows via `FlowManager`, classifies each flow, and streams records to the UI every 1.2 seconds.
5. **Stop Monitoring**: Click **⏹ Stop**. The capture thread terminates immediately, network socket handles are released, polling stops, and the engine returns to the stopped state.

---

## 14. Required Scapy Permissions on Windows

- **Driver Requirement**: Live raw hardware packet sniffing on Windows requires **Npcap** (or WinPcap). Download and install Npcap from [npcap.com](https://npcap.com).
- **Administrator Privileges**: On Windows, capturing raw physical packets requires Administrator privileges. If running without Administrator permissions:
  - SecureFlow detects this condition gracefully without crashing or silently elevating.
  - An informative notification is displayed:
    > *"Live packet capture requires Administrator privileges on Windows. Please restart your terminal using 'Run as administrator' and launch SecureFlow again (`python run.py`). Alternatively, select 'Demonstration Stream (Benchmark Flows)'."*
  - The application remains completely stable and responsive.

---

## 15. Screenshots Section

| Screen | Description |
| :--- | :--- |
| **Sign-In Portal** | Dark navy & cyan glassmorphism design with Email/Password fields and Google Single Sign-On button. |
| **Security Operations Dashboard** | Real-time counters, threat percentage gauge, protocol distribution chart, and persistent alert table. |
| **Traffic Upload & Quick Samples** | Multi-format CSV/PCAP ingestion with built-in benchmark datasets. |
| **Detailed Classified Records** | Full-width flow grid with progressive confidence bars, attack type tags, and pagination. |
| **Deep Flow Inspection Modal** | Inspection of all 16 extracted ML features, bidirectional byte counts, and quick IP blocking. |
| **Live Intrusion Monitoring** | Real-time telemetry console with dual modes, interface selection, and live throughput timeline. |
| **Threat Reports & Audit Logs** | Comprehensive history tracking session metrics, attack severity, and CSV alert report exports. |
| **Defensive IP Blacklist** | Quarantine management with IP format validation and analyst notes. |

---

## 16. Security Considerations

- **Credential Separation**: Sensitive credentials (`SECRET_KEY`, Google OAuth secrets, Gmail App Passwords) reside strictly in `.env` and are excluded from version control via `.gitignore`.
- **Anti-Enumeration Protection**: The password reset endpoint returns generic status messages for both registered and unregistered addresses to prevent user enumeration attacks.
- **Cryptographic Token Security**: Password reset tokens are generated using 32 bytes of cryptographic randomness (`secrets.token_urlsafe`), stored exclusively as SHA-256 hashes, and expire after 30 minutes.
- **Data Isolation**: Strict multi-tenant isolation ensures user workspaces cannot view, edit, or delete another analyst's analysis history, alerts, or blacklists.
- **Zero Raw Device Probing on Navigation**: Interface detection uses standard user-space OS APIs (`psutil`), preventing unwanted driver prompts or permission requests when browsing the application.

---

## 17. Automated Testing

Run the automated test suite using `pytest`:

```powershell
python -m pytest tests/ -v
```

All 58 test cases pass covering:
- Random Forest model pipeline integrity, attributes, and probability predictions.
- Feature extraction, zero-division protection, and ratio engineering.
- Multi-format CSV dataset ingestion and schema compatibility checks.
- Bidirectional flow aggregation, inactivity timers, and expiration handling.
- Dynamic network interface enumeration without Scapy driver elevation prompts.
- Google OAuth 2.0 authentication flow, CSRF state verification, and callback processing.
- Multi-user account registration, login verification, and complete workspace data isolation.
- Password reset token generation, single-use enforcement, and SMTP delivery.
- Live monitoring manual control (idle on page load, start/stop lifecycle, duplicate thread prevention).

---

## 18. Future Enhancements

- **Multi-Class Deep Learning Classifier**: Supplement the binary Random Forest model with a multi-class deep neural network (e.g., 1D-CNN or BiLSTM) for granular classification of specialized attack variants.
- **Automated Firewall Rule Push**: Automatically synchronize blocked IPs with Windows Defender Firewall (`New-NetFirewallRule`) and Linux `iptables` / `nftables`.
- **SIEM & Syslog Forwarding**: Export real-time intrusion alerts to external SIEM platforms (Splunk, Elastic SIEM, Wazuh) via CEF or Syslog RFC 5424.
- **Distributed Sensor Architecture**: Support remote sensor agents capturing traffic across edge switches and reporting back to a central SecureFlow controller.

---

## 19. Contributing

1. Fork the repository.
2. Create a descriptive feature branch (`git checkout -b feature/network-enhancement`).
3. Commit your changes (`git commit -m 'Add network telemetry feature'`).
4. Push to the branch (`git push origin feature/network-enhancement`).
5. Open a Pull Request.

---

## 20. License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
