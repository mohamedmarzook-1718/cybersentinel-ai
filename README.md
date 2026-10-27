# 🛡️ CyberSentinel AI — Predictive Cyber Attack Detection & Website Security Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4.2-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-40%2F40%20Passing-brightgreen?style=for-the-badge)](tests/)

**CyberSentinel AI** is an advanced, dual-engine cybersecurity platform combining:
1. **Predictive AI Security Monitoring:** Real-time event ingestion, machine learning anomaly detection (`Isolation Forest`), attack classification (`Random Forest`), early-warning risk scoring (0–100), and an explainable AI Copilot with bilingual support (English and Tamil).
2. **Comprehensive Website Security Intelligence Platform:** Safe, authorized multi-layer attack surface mapping, breadth-first web crawling, client-side secret scanning, OWASP Top 10 passive checks, API auditing, threat intelligence CVE matching, and prioritized remediation workflows.

---

## 🌟 Key Features

### 1. Dual AI/ML Threat Detection Engine
- **Unsupervised Anomaly Detection:** Tuned `Isolation Forest` evaluating behavioral feature vectors (request frequency, error rates, payload entropy, unusual port distributions).
- **Supervised Attack Classifier:** `Random Forest Classifier` identifying multi-class threat categories:
  - `Normal Traffic`
  - `Brute Force Login`
  - `DDoS / Flood Volumetric`
  - `Port Scanning / Reconnaissance`
  - `SQL Injection (SQLi)`
  - `Web Application Attacks (XSS, Path Traversal)`
- **Composite Risk Scoring (0–100):** Weighted risk index correlating anomaly scores, attack probabilities, velocity metrics, and asset criticality.
- **Explainable AI (XAI):** Clear rationale, contributing risk factors, and actionable mitigation playbooks for every detected event.
- **Bilingual Security Copilot:** Interactive AI assistant answering security queries in both **English** and **Tamil** (தமிழ்).

### 2. Multi-Layer Website Security Assessment Engine
- **Attack Surface & DNS Intelligence:**
  - Automated DNS record inspection (`A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`).
  - Strict email spoofing protection auditing (permissive SPF `+all` flags and missing/neutral DMARC policies).
  - Passive public subdomain discovery via Certificate Transparency logs.
  - Sensitive route probing (`/.env`, `/.git/HEAD`).
- **Safe, Robots-Aware Crawler:**
  - Breadth-first same-origin crawler with configurable depth and budget limits.
  - Automatic avoidance of dangerous mutating actions (`logout`, `delete`, `drop`, `destroy`).
- **Client-Side Secret & Leak Detection:**
  - High-precision pattern matcher for exposed API keys and secrets (AWS, GitHub, Google, Stripe, Slack, Private Keys, JWTs).
  - Strict automated redaction (e.g. `AKIA************3F2A`) to ensure zero credential disclosure in logs and reports.
  - Detection of DOM XSS sinks (`innerHTML`, `document.write`), mixed-content scripts, and exposed source maps.
- **API Security Auditing:**
  - Discovery of internal endpoints from HTML/JS bundles.
  - OpenAPI / Swagger schema auditing for sensitive operations.
  - CORS Origin reflection testing with credential exposure validation (`Access-Control-Allow-Credentials: true`).
  - Dangerous HTTP method detection (e.g., HTTP `TRACE`).
- **Passive OWASP Top 10 Checks:**
  - Verbose SQL error message disclosures and uncaught framework debug stack traces.
  - Password input fields transmitted over insecure HTTP.
  - Directory listing exposure and open redirect parameters.
  - Unprotected file upload endpoints lacking CSRF tokens.
- **Threat Intelligence & CVE Correlation:**
  - Signature-based detection of defacement markers and obfuscated script payloads.
  - Curated CVE correlation for exposed service versions (e.g., Apache 2.4.49 path traversal, Heartbleed, EOL PHP, vulnerable jQuery versions).
- **Prioritized Remediation & RFC-4180 Exports:**
  - Automated generation of actionable remediation checklists ordered by severity (Critical, High, Medium, Low).
  - Export capabilities in both JSON and RFC-4180 compliant CSV formats.

---

## 🏗️ Architecture

```
cyber-main/
├── app/
│   ├── main.py                  # FastAPI application entrypoint
│   ├── database.py              # SQLite + SQLAlchemy session with auto-migration
│   ├── config.py                # Environment configuration & JWT settings
│   ├── ml/                      # Machine learning training & inference
│   │   ├── train.py             # Isolation Forest & Random Forest model training
│   │   ├── predictor.py         # Real-time event scoring and early warnings
│   │   └── explainer.py         # Feature contribution & remediation generator
│   ├── models/                  # SQLAlchemy ORM database models
│   ├── routers/                 # REST API endpoints (auth, events, alerts, scans, copilot)
│   ├── scanner/                 # Modular Web Security Assessment Engine
│   │   ├── engine.py            # Master scanner orchestrator & scoring
│   │   ├── ssrf.py              # Strict SSRF & private IP range protection
│   │   ├── crawler.py           # BFS same-origin web crawler
│   │   ├── discovery.py         # DNS intelligence & attack surface mapping
│   │   ├── client_checker.py    # Client-side secrets & DOM vulnerability detector
│   │   ├── owasp_checker.py     # Passive OWASP Top 10 security checks
│   │   ├── api_checker.py       # API endpoint discovery & CORS auditing
│   │   ├── threat_intel.py      # CVE correlation & threat intelligence
│   │   ├── tls_checker.py       # SSL/TLS & certificate health checks
│   │   └── headers_checker.py   # Security headers & cookie attribute audit
│   ├── schemas/                 # Pydantic validation schemas
│   └── static/                  # Responsive Glassmorphic Web Dashboard
│       ├── index.html           # Unified dashboard interface
│       ├── style.css            # Cyber-themed CSS styles & responsive layout
│       └── app.js               # Frontend application logic & scanner controller
├── models_store/                # Serialized Joblib ML models & metadata
├── tests/                       # Comprehensive automated test suite
│   ├── test_cyber_sentinel.py   # Core backend, ML inference, and auth tests
│   └── test_web_scanner.py      # Multi-layer web scanner & security checks tests
├── requirements.txt             # Python dependencies
└── .gitignore                   # Standard git exclusions
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.11+
- Virtual environment tool (`venv`)
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/<your-username>/cybersentinel-ai.git
cd cybersentinel-ai

# Create and activate a virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 🧪 Running Automated Tests

CyberSentinel AI includes 40 comprehensive unit and integration tests covering:
- Authentication & JWT issuance
- ML model training & real-time inference
- Early warning indicator calculations
- SSRF prevention & private IP address blocking
- BFS web crawler budget and URL canonicalization
- Client secret pattern matching & redaction
- Passive OWASP Top 10 detection
- Multi-format (CSV/JSON) scan exports

To run the test suite:
```bash
pytest -v
```

---

## 🔒 Security & Safe Scanning Policy

- **Non-Destructive Testing:** The Web Security Assessment engine strictly performs safe, passive inspection and controlled read-only requests. It does **not** perform destructive payloads, brute-force attacks, or unauthorized exploitation.
- **SSRF Defense:** Built-in safeguards prohibit requests targeting `localhost`, `127.0.0.1`, private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local addresses, and cloud provider metadata services (`169.254.169.254`).
- **Data Privacy:** Credential and API key pattern matchers automatically apply cryptographic masking (`AKIA************1234`) to ensure sensitive strings never appear in database entries, UI displays, or exported logs.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
