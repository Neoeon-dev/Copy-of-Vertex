# MailTrace — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

> Analyze suspicious emails, detect phishing, reconstruct relay paths, verify cryptographic evidence integrity, and generate forensic reports with a single `.eml` upload.

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](https://github.com/your-org/mailtrace)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141+-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.2-61DAFB.svg)](https://react.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-v4.3-38B2AC.svg)](https://tailwindcss.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org)
[![Alembic](https://img.shields.io/badge/Alembic-1.13+-red.svg)](https://alembic.sqlalchemy.org)
[![Tests](https://img.shields.io/badge/tests-158%20passed-brightgreen.svg)]()
[![SIH](https://img.shields.io/badge/SIH-2026%20Problem%20SIH26106-orange.svg)](https://sih.gov.in)

---

## 📑 Table of Contents

- [🚀 User Manual / Getting Started](#-user-manual--getting-started)
  - [What This Application Does](#what-this-application-does)
  - [Prerequisites](#prerequisites)
  - [Clone the Repository](#clone-the-repository)
  - [Environment Setup](#environment-setup)
  - [Database Setup](#database-setup)
  - [Required Data Files](#required-data-files)
  - [Start the Application](#start-the-application)
  - [Verify the Installation](#verify-the-installation)
  - [Local URLs](#local-urls)
  - [First-Time User Workflow](#first-time-user-workflow)
  - [Dashboard & Forensic Analysis Guide](#dashboard--forensic-analysis-guide)
  - [Stopping & Restarting](#stopping-the-application)
  - [Troubleshooting](#troubleshooting)
- [👨‍💻 Developer Quick Start](#-developer-quick-start)
  - [Repository Architecture](#repository-architecture)
  - [Feature & Code Locator](#feature--code-locator)
  - [Database Migrations (Alembic)](#database-migrations-alembic)
  - [Running Automated Tests](#running-tests)
- [📖 Project Overview & Problem Statement](#-project-overview)
- [💡 Proposed Solution & Key Features](#-proposed-solution)
- [🏗️ System Architecture](#️-system-architecture)
- [📧 Email Analysis Pipeline](#-email-analysis-pipeline)
- [🛠️ Technology Stack](#️-technology-stack)
- [📚 Module Reference](#-module-reference)
- [📡 API Reference](#-api-reference)
- [🗄️ Database Architecture](#️-database-architecture)
- [🤖 AI / ML Threat Classification](#-ai--ml)
- [📊 Explainable Multi-Signal Risk Engine](#-risk-scoring)
- [🔗 Threat Correlation Graph & Campaign Detection](#-correlation-graph)
- [📋 Evidence Chain of Custody & Tamper-Evidence](#-evidence--chain-of-custody)
- [🐳 Docker Architecture](#-docker-architecture)
- [🗺️ Supabase Deployment](#️-supabase-deployment)
- [📋 SIH Requirement Mapping](#-sih-requirement-mapping)
- [📊 Project Status & Changelog](#-project-status)
- [🤝 Contributing & License](#-contributing)

---

## 🚀 User Manual / Getting Started

### What This Application Does

**MailTrace** is a comprehensive, production-grade email forensic intelligence platform built to investigate suspicious emails, spear-phishing attacks, and Business Email Compromise (BEC) campaigns.

**What happens after you upload a `.eml` email file:**

1. **Tamper-Evident SHA-256 Hashing:** Raw byte SHA-256 evidence fingerprint is computed before parsing to preserve the cryptographic chain of custody.
2. **RFC 822 / MIME Parsing:** Headers, body (plain text & HTML), inline components, and attachments are parsed and isolated safely.
3. **Independent Authentication Checks:** Independent DNS queries evaluate SPF records, verify DKIM cryptographic signatures (`dkimpy`), and evaluate DMARC policy alignment.
4. **Relay Path Reconstruction:** The complete transit hop path is parsed from `Received` headers, detecting delays, hop anomalies, and suspicious relays.
5. **IP Intelligence & Geolocation:** All extracted IP addresses are analyzed for public/private status, reverse DNS, ASN, and GeoIP location.
6. **Domain & Lookalike Intelligence:** Sender and transit domains are inspected for typosquatting, suspicious TLDs, and Unicode homoglyph attacks.
7. **Phishing URL Analysis:** URLs extracted from body and headers are scanned for IP-based hosts, punycode, open redirects, and URL shorteners without ever visiting malicious hosts.
8. **Inert Attachment Threat Analysis:** Attachments are stored as inert raw binary bytes (never executed), fingerprinting files via SHA-256, verifying MIME consistency, and detecting dangerous double extensions (e.g. `.pdf.exe`).
9. **Machine Learning Classification:** A TF-IDF + Logistic Regression model categorizes threats (`legitimate`, `suspicious`, `phishing`, `spammer`) and surfaces explainable risk triggers.
10. **Weighted Multi-Signal Risk Engine:** 8 distinct categories are scored (0–100) with detailed FACT → OBSERVATION → INFERENCE → CONFIDENCE explainability breakdowns.
11. **Threat Correlation Matrix:** Emails, shared IPs, domains, and malicious attachments are mapped into an interactive Cytoscape.js correlation graph to detect coordinated threat campaigns.
12. **Incident Case Dossiers:** Suspicious emails can be linked into investigative case files (`/cases`).
13. **Cryptographic Audit Ledger:** An immutable, append-only hash chain tracks every action with one-click real-time integrity verification (`/audit`).
14. **Forensic Report Generation:** Export full court-ready forensic reports in PDF format (via WeasyPrint) with graceful HTML download fallback.

**Target Users:** SOC analysts, digital forensics and incident response (DFIR) specialists, cybersecurity students, and IT administrators.

---

### Prerequisites

| Software | Required Version | Why It Is Needed | How to Verify |
|---|---|---|---|
| **Git** | Any recent version | Clone and manage the codebase | `git --version` |
| **Docker** | ≥ 20.10 | Run PostgreSQL and full-stack containers | `docker --version` |
| **Docker Compose** | ≥ 2.0 | Orchestrate database, backend, and frontend | `docker compose version` |
| **Python** | ≥ 3.11 (3.12+ recommended) | Backend FastAPI server, forensics engine, and ML | `python3 --version` |
| **Node.js** | ≥ 20 (LTS recommended) | Frontend build system and development server | `node --version` |
| **npm** | ≥ 10.0 | Manage frontend dependencies | `npm --version` |

> ⚠️ **PostgreSQL is required.** MailTrace strictly enforces PostgreSQL (version 15+ or 16). SQLite is explicitly disabled and rejected on startup to guarantee relational integrity, JSON querying, and concurrency.

---

### Clone the Repository

```bash
git clone <repository-url>
cd mailtrace
```

---

### Environment Setup

MailTrace uses environment variables for configuration. All variables have sensible defaults for local development.

Copy the example environment configuration:

```bash
cp backend/.env.example backend/.env
```

#### Environment Variables Reference

| Variable | Required? | Purpose | Default |
|---|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string | `postgresql+psycopg2://mailtrace:mailtrace@localhost:5432/mailtrace` |
| `DEMO_MODE` | No | Enable offline deterministic fixtures for DNS/GeoIP | `true` |
| `MAX_UPLOAD_SIZE_MB` | No | Maximum allowed `.eml` upload file size in MB | `10` |
| `GEOIP_DB_DIR` | No | Directory containing MaxMind GeoLite2 `.mmdb` files | `/usr/share/GeoIP` |
| `SUPABASE_URL` | Optional | Supabase project URL (for Supabase deployment) | `""` |
| `SUPABASE_ANON_KEY` | Optional | Supabase client anon key | `""` |
| `SUPABASE_SERVICE_ROLE_KEY` | Optional | Supabase service role key (backend only) | `""` |

> 🔒 **Security Notice:** Never commit actual API keys, database credentials, or service role keys to version control.

---

### Database Setup

#### Start PostgreSQL via Docker Compose

```bash
docker compose up -d db
```

This starts a PostgreSQL 16 container with a persistent volume (`pgdata`). The database and credentials are automatically configured.

To verify the database container is healthy:

```bash
docker compose ps db
```

Expected status: `Up (healthy)`.

---

### Required Data Files (Optional GeoIP)

| File | Mandatory? | Purpose | Source / Placement | Fallback Behavior |
|---|---|---|---|---|
| **GeoLite2-City.mmdb** | No | IP city/coordinate lookups | [MaxMind Free Signup](https://www.maxmind.com/en/geolite2/signup) → Place in `backend/data/geoip/` | Geolocation returns `null`; non-Geo IP intelligence remains active. |
| **GeoLite2-ASN.mmdb** | No | Autonomous System Number & Org lookups | MaxMind Free Signup → Place in `backend/data/geoip/` | ASN returns `null`; non-ASN IP analysis remains active. |

*Even without GeoIP databases, the entire platform is fully functional in offline/demo mode.*

---

### Start the Application

You can start MailTrace using any of the following three workflows:

#### Method 1: Full-Stack Docker Compose (Recommended)

Orchestrate the database, backend, and production frontend with a single command:

```bash
docker compose up --build
```

This brings up:
1. **db**: PostgreSQL 16 on `localhost:5432` with healthchecks and persistent storage.
2. **backend**: FastAPI on `http://localhost:8000` (auto-initializes database tables upon healthy connection to db).
3. **frontend**: Production multi-stage Nginx container on `http://localhost:3000` with reverse proxy for `/api/` and `/health`.

#### Method 2: Hybrid Development (Docker DB + Hot-Reload Local Servers)

**Terminal 1 — Database:**
```bash
docker compose up -d db
```

**Terminal 2 — FastAPI Backend:**
```bash
cd backend
bash run.sh
```
*(Runs uvicorn on `http://localhost:8000` with auto-reload).*

**Terminal 3 — React Frontend:**
```bash
cd frontend
npm install
npm run dev
```
*(Runs Vite dev server on `http://localhost:5173` with instant HMR).*

#### Method 3: Manual Python Virtual Environment Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

### Verify the Installation

Run the health check endpoint:

```bash
curl http://localhost:8000/health
# Expected response: {"status":"ok"}
```

Verification Checklist:
```
[✓] PostgreSQL 16 running on port 5432
[✓] FastAPI Backend running on port 8000 (status: ok)
[✓] Frontend accessible at http://localhost:3000 (Docker) or http://localhost:5173 (Dev)
[✓] Interactive API docs accessible at http://localhost:8000/docs
[✓] ReDoc API docs accessible at http://localhost:8000/redoc
```

---

### Local URLs

| Service | Local URL | Description |
|---|---|---|
| **Production Frontend (Docker)** | `http://localhost:3000` | Nginx reverse-proxied React 19 web application |
| **Development Frontend (Vite)** | `http://localhost:5173` | Vite dev server with Hot Module Replacement |
| **Backend REST API** | `http://localhost:8000` | FastAPI core application |
| **Swagger UI Documentation** | `http://localhost:8000/docs` | Interactive OpenAPI documentation and test runner |
| **ReDoc Documentation** | `http://localhost:8000/redoc` | Clean, readable OpenAPI documentation |
| **PostgreSQL Database** | `localhost:5432` | Primary database (`mailtrace` / `mailtrace_test`) |

---

### First-Time User Workflow

#### 1. Open the Web Application
Open `http://localhost:3000` (or `http://localhost:5173` in development mode) in your web browser. Note the live green **Backend: Online** health status badge in the navigation sidebar.

#### 2. Upload a `.eml` Email File
On the **Upload Email** screen (`/`):
- Drag and drop any raw `.eml` file into the upload zone or click to select from your file manager.
- The client validates that the file has a `.eml` extension and is within the 10 MB upload guard.
- The backend immediately computes the raw byte **SHA-256 evidence fingerprint** and stores headers and body parts safely.

> **Where to find a `.eml` sample:**
> - **Gmail:** Open an email → click the 3 dots (More) → **Show original** → **Download Original**.
> - **Outlook:** Drag an email message onto your desktop or save as `.eml`.
> - **Apple Mail:** File → Save As → Raw Message Source (`.eml`).

#### 3. Automatic Navigation to Investigation Dossier
Upon upload, you are automatically redirected to `/emails/:id`. You will see:
- Message Subject, Sender, Display Name, Date, and Message-ID.
- The immutable SHA-256 evidence hash and file size.
- Pre-parsed MIME structure, headers, and safe attachment listings.

#### 4. Run Full Forensic Analysis
Click the **"Run Full Analysis"** button to trigger all diagnostic engines concurrently:
- **Authentication Engine:** SPF, DKIM, and DMARC verification.
- **Relay Path Forensics:** Hop-by-hop Received header reconstruction and delay anomaly analysis.
- **IP & ASN Intelligence:** Geolocation and Autonomous System mapping.
- **Domain Intelligence:** Homoglyph detection, typosquatting checks, and suspicious TLD flags.
- **URL Phishing Inspection:** Embedded links parsed, checked for IP hosts, shorteners, and abnormal structures.
- **Attachment Threat Analysis:** MIME mismatches and dangerous execution extensions flagged.
- **Machine Learning Threat Classifier:** Predictions across 4 threat classes with explainable indicator breakdown.
- **Multi-Signal Risk Score:** Comprehensive 0–100 composite risk score with severity grading.

#### 5. Review Findings, Correlate, and Export
- **Review Breakdown:** Inspect individual risk categories (ML, Authentication, Domain, URL, Attachments, Hops).
- **Export Forensic Report:** Click **"📄 Export Report"** to download an official investigation dossier in PDF (or HTML) format.
- **Verify Evidence Chain:** Click **"🛡️ Verify Evidence"** to execute a cryptographic proof validating that the SHA-256 hash chain matches the raw uploaded bytes.
- **Correlate with Campaign Graph:** Click **"🌐 Add to Graph"** to link the email to the entity correlation matrix.
- **Organize Incident Cases:** Navigate to `/cases` to group related emails into incident dossiers.
- **Inspect Audit Trail:** Navigate to `/audit` and click **"Verify Hash Chain Integrity"** to validate the tamper-evident system audit log.

---

### Dashboard & Forensic Analysis Guide

#### Composite Risk Score (0–100)

| Score Range | Severity Level | Visual Badge | Meaning & Recommended Action |
|---|---|---|---|
| **0 – 24** | **LOW** | 🟢 Green | Clean email. Authentication passes; no anomalous domains or hostile payloads. |
| **25 – 49** | **MEDIUM** | 🟡 Yellow | Suspicious indicators present (e.g. minor SPF softfail or unusual relay delays). Review recommended. |
| **50 – 74** | **HIGH** | 🟠 Orange | Multiple high-risk signals (failed authentication, lookalike domain, suspicious URLs). Likely phishing. |
| **75 – 100** | **CRITICAL** | 🔴 Red | High-confidence malicious threat (spoofed brand, malicious attachment, severe auth failure, high ML phishing score). Quarantine immediately. |

#### Email Authentication Statuses

| Check | Result | Forensic Interpretation |
|---|---|---|
| **SPF** | `PASS` | Sending IP is explicitly authorized by sender domain's SPF DNS record. |
| **SPF** | `FAIL` / `SOFTFAIL` | Sending IP is NOT authorized. Strong indicator of spoofing or unauthorized relay. |
| **DKIM** | `PASS` | Digital cryptographic signature verified against public key published in DNS. |
| **DKIM** | `FAIL` | Signature verification failed — message content or headers were modified in transit. |
| **DMARC** | `PASS` | SPF or DKIM passed AND the authenticated domain aligns with the `From:` header domain. |
| **DMARC** | `FAIL` | Both SPF and DKIM failed alignment with the `From:` header. Sender is unverified. |

---

### Stopping the Application

Press `Ctrl+C` in your active terminal windows.

```bash
# Stop Docker services
docker compose down

# To also delete persistent database volume (Warning: wipes all emails!):
docker compose down -v
```

---

### Restarting the Application

```bash
# Start database
docker compose up -d db

# Start backend
cd backend && bash run.sh

# Start frontend (in a separate terminal)
cd frontend && npm run dev
```

---

### Troubleshooting

#### Backend Port 8000 in Use
```bash
lsof -ti :8000 | xargs kill -9
```

#### Database Connection Refused
1. Verify container status: `docker compose ps db`
2. Check logs: `docker compose logs db`
3. If connecting from host, ensure `DATABASE_URL` uses `localhost:5432`. If connecting inside Docker Compose, ensure it uses `db:5432`.

#### Stale Python Bytecode / Caches
```bash
find backend -name "__pycache__" -exec rm -rf {} +
find backend -name "*.pyc" -delete
```

#### Frontend Package Installation Issues
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run dev
```

---

## 👨‍💻 Developer Quick Start

### Repository Architecture

```
mailtrace/
├── docker-compose.yml        # PostgreSQL 16 + FastAPI + React 19 Nginx orchestration
├── .gitignore                # Comprehensive protection against debris and secrets
├── README.md                 # Root platform documentation (v0.3.0)
│
├── backend/                  # FastAPI & Cyber-Forensics Engine
│   ├── alembic.ini           # Alembic database migration configuration
│   ├── Dockerfile            # Production Python 3.12-slim container
│   ├── .dockerignore         # Docker build exclude rules
│   ├── pyproject.toml        # Build system metadata & dependencies
│   ├── requirements.txt      # Pinned Python package dependencies
│   ├── run.sh                # Clean quick-start development launcher
│   ├── .env.example          # Environment variable template
│   │
│   ├── app/                  # Main Application Package
│   │   ├── main.py           # FastAPI entrypoint, CORS, lifespan, router registry
│   │   ├── config.py         # Pydantic BaseSettings environment loader
│   │   ├── db.py             # PostgreSQL SQLAlchemy engine & session factory
│   │   ├── models.py         # SQLAlchemy ORM database models (7 tables)
│   │   ├── utils.py          # Header parsing and HTML sanitization utilities
│   │   │
│   │   ├── routers/          # API Route Controllers (9 modules)
│   │   │   ├── emails.py     # Ingestion & email retrieval (/api/emails)
│   │   │   ├── authentication.py # SPF / DKIM / DMARC (/api/emails/{id}/authentication)
│   │   │   ├── received.py   # Received relay analysis (/api/emails/{id}/received)
│   │   │   ├── ip_intel.py   # IP & Geo intelligence (/api/emails/{id}/ip-intel)
│   │   │   ├── ml.py         # ML classification (/api/emails/{id}/classify)
│   │   │   ├── risk.py       # Multi-signal risk assessment (/api/emails/{id}/risk)
│   │   │   ├── analysis.py   # Unified forensic pipeline (/api/emails/{id}/analyze-full)
│   │   │   ├── cases.py      # Case dossiers & audit log (/api/cases, /api/audit)
│   │   │   └── correlation.py# Cytoscape graph & PDF reports (/api/graph, /api/reports)
│   │   │
│   │   ├── forensics/        # Specialized Forensic Analysis Engines
│   │   │   ├── spf_analyzer.py        # Independent DNS SPF verification
│   │   │   ├── dkim_analyzer.py       # DKIM public key signature verification
│   │   │   ├── dmarc_analyzer.py      # DMARC policy & domain alignment logic
│   │   │   ├── received_analyzer.py   # Relay hop parser & timing anomaly detection
│   │   │   ├── ip_intelligence.py     # GeoIP2 & ASN intelligence resolution
│   │   │   ├── domain_intel.py        # Homoglyphs, typosquatting & suspicious TLDs
│   │   │   ├── url_analyzer.py        # Phishing link extraction & reputation checks
│   │   │   ├── attachment_analyzer.py # MIME verification & dangerous file detection
│   │   │   ├── risk_engine.py         # Explainable 8-category scoring engine
│   │   │   ├── evidence.py            # Append-only hash chain & audit verification
│   │   │   └── correlation.py         # NetworkX entity relationship graph
│   │   │
│   │   ├── ml/               # Machine Learning Subsystem
│   │   │   └── classifier.py # TF-IDF + Logistic Regression threat model
│   │   │
│   │   ├── parsers/          # Email MIME Parsers
│   │   │   └── mime_parser.py# RFC 822 parser & SHA-256 byte hasher
│   │   │
│   │   └── schemas/          # Pydantic Schemas & DTOs
│   │       └── email.py      # Input validation & response models
│   │
│   ├── migrations/           # Alembic Database Migrations
│   │   ├── env.py            # Alembic environment runner (loads Base metadata)
│   │   ├── script.py.mako    # Migration template
│   │   └── versions/         # Migration revision scripts
│   │       └── 9557d637c8b2_initial_schema.py # Initial PostgreSQL schema
│   │
│   ├── supabase/             # Hosted Supabase Preparation
│   │   ├── README.md         # Supabase connection & deployment instructions
│   │   └── migrations/       # Supabase SQL DDL scripts
│   │       └── 001_initial_schema.sql
│   │
│   ├── tests/                # Automated Pytest Suite (158 Tests)
│   │   ├── conftest.py       # PostgreSQL test fixtures and isolated database setup
│   │   ├── test_authentication.py
│   │   ├── test_cases_evidence_reports.py
│   │   ├── test_domain_url_attachment.py
│   │   ├── test_email_api.py
│   │   ├── test_ip_intel.py
│   │   ├── test_ml.py
│   │   ├── test_received.py
│   │   └── test_risk_engine.py
│   │
│   └── data/geoip/           # Optional GeoLite2 .mmdb files
│
└── frontend/                 # React 19 / Vite / Tailwind CSS v4 Client
    ├── Dockerfile            # Multi-stage production container (Node 20 -> Nginx)
    ├── nginx.conf            # Nginx production reverse proxy config
    ├── package.json          # React 19, Tailwind v4, Axios, React Router v7
    ├── vite.config.js        # Vite build & local development proxy config
    ├── README.md             # Frontend specific documentation
    │
    └── src/
        ├── App.jsx           # Sidebar navigation, route definitions, health badge
        ├── api.js            # Axios client with centralized API methods
        ├── main.jsx          # React DOM root entrypoint
        ├── index.css         # Tailwind CSS imports & theme definitions
        │
        └── pages/            # Application Views
            ├── UploadPage.jsx         # .eml drag-and-drop ingestion
            ├── EmailListPage.jsx      # Dossier index of analyzed emails
            ├── EmailDetailPage.jsx    # Full forensic breakdown & analysis actions
            ├── CasesPage.jsx          # Incident management & email grouping
            ├── CorrelationGraphPage.jsx # Cytoscape.js campaign threat graph
            └── AuditTrailPage.jsx     # Cryptographic audit ledger & proof verification
```

---

### Feature & Code Locator

| Platform Feature | Primary Implementation Files |
|---|---|
| **Raw Byte Evidence Hashing (SHA-256)** | [`backend/app/parsers/mime_parser.py`](backend/app/parsers/mime_parser.py) |
| **RFC 822 MIME Parser** | [`backend/app/parsers/mime_parser.py`](backend/app/parsers/mime_parser.py) |
| **SPF Analysis & DNS Evaluation** | [`backend/app/forensics/spf_analyzer.py`](backend/app/forensics/spf_analyzer.py) |
| **DKIM Cryptographic Verification** | [`backend/app/forensics/dkim_analyzer.py`](backend/app/forensics/dkim_analyzer.py) |
| **DMARC Policy & Alignment Analysis** | [`backend/app/forensics/dmarc_analyzer.py`](backend/app/forensics/dmarc_analyzer.py) |
| **Received Relay Path & Delay Analysis** | [`backend/app/forensics/received_analyzer.py`](backend/app/forensics/received_analyzer.py) |
| **IP Intelligence & GeoIP Lookup** | [`backend/app/forensics/ip_intelligence.py`](backend/app/forensics/ip_intelligence.py) |
| **Lookalike Domain & Homoglyph Engine** | [`backend/app/forensics/domain_intel.py`](backend/app/forensics/domain_intel.py) |
| **URL Phishing & Shortener Scanner** | [`backend/app/forensics/url_analyzer.py`](backend/app/forensics/url_analyzer.py) |
| **Inert Attachment Threat Scanner** | [`backend/app/forensics/attachment_analyzer.py`](backend/app/forensics/attachment_analyzer.py) |
| **TF-IDF + Logistic Regression ML Model** | [`backend/app/ml/classifier.py`](backend/app/ml/classifier.py) |
| **Weighted Multi-Signal Risk Engine** | [`backend/app/forensics/risk_engine.py`](backend/app/forensics/risk_engine.py) |
| **Append-Only Evidence Hash Chain** | [`backend/app/forensics/evidence.py`](backend/app/forensics/evidence.py) |
| **Threat Correlation & Shared Infrastructure** | [`backend/app/forensics/correlation.py`](backend/app/forensics/correlation.py) |
| **Forensic PDF/HTML Report Generator** | [`backend/app/routers/correlation.py`](backend/app/routers/correlation.py) |
| **Database ORM Schema** | [`backend/app/models.py`](backend/app/models.py) |
| **Alembic Database Migrations** | [`backend/migrations/`](backend/migrations/) |
| **Frontend Central API Client** | [`frontend/src/api.js`](frontend/src/api.js) |
| **Interactive Investigation UI** | [`frontend/src/pages/EmailDetailPage.jsx`](frontend/src/pages/EmailDetailPage.jsx) |

---

### Database Migrations (Alembic)

MailTrace includes a fully configured Alembic migration environment:

```bash
cd backend

# Apply all pending migrations to the latest revision:
alembic upgrade head

# Generate a new migration after modifying models.py:
alembic revision --autogenerate -m "describe_schema_changes"

# Check current migration revision status:
alembic current
```

---

### Running Tests

The test suite runs 100% against an isolated PostgreSQL test database (`mailtrace_test`), created and migrated automatically by `conftest.py`.

```bash
cd backend
python3 -m pytest -v
```

Output:
```
============================== 158 passed in 7.14s ==============================
```

---

## 📖 Project Overview

MailTrace was created for the **Smart India Hackathon 2026** (Problem Statement **SIH26106**: *AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform*).

### Problem Statement

Email remains the primary initial attack vector for advanced persistent threats (APTs), ransomware distribution, Business Email Compromise (BEC), and credential harvesting. Investigators face multiple challenges:
1. **Third-party dependence:** Many tools rely on public cloud reputation APIs that fail in air-gapped forensic laboratories.
2. **Black-box scoring:** Security analysts need defensible explanations (FACT → OBSERVATION → INFERENCE) rather than arbitrary scores.
3. **Chain of custody breakdown:** Analysis tools often alter line endings or re-serialize email data, destroying original cryptographic signatures and evidence admissibility in court.
4. **Siloed investigations:** Incident responders analyze emails in isolation without discovering cross-incident shared infrastructure.

### Proposed Solution

MailTrace provides a self-contained, enterprise-grade forensic platform that:
- Runs completely on-premises or air-gapped without mandatory external API dependencies.
- Freezes evidence upon arrival with raw SHA-256 byte hashing and append-only hash chains.
- Executes independent DNS and cryptographic checks for SPF, DKIM, and DMARC.
- Detects sophisticated domain impersonation, IDN homoglyphs, and lookalikes.
- Extracts URLs and attachments without executing hostile code.
- Explains every risk assessment with category breakdowns and confidence levels.
- Automatically connects indicators of compromise (IOCs) into campaign graphs.
- Generates official forensic PDF reports for incident documentation and law enforcement referral.

---

## 🏗️ System Architecture

```
                                  USER BROWSER
                     ┌────────────────────────────────────┐
                     │  React 19 + Tailwind v4 Dashboard  │
                     │  (Vite Dev :5173 / Nginx :3000)    │
                     └─────────────────┬──────────────────┘
                                       │ HTTP / REST
                                       ▼
                     ┌────────────────────────────────────┐
                     │          FastAPI Backend           │
                     │            (Port 8000)             │
                     └─────────────────┬──────────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
 ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
 │   Forensics Suite    │   │      AI / ML Engine  │   │  Cryptographic Proof │
 │ • SPF/DKIM/DMARC     │   │ • TF-IDF Vectorizer  │   │ • SHA-256 Hasher     │
 │ • Received Hops Path │   │ • Logistic Classifier│   │ • Evidence Chain     │
 │ • IP / GeoIP / ASN   │   │ • Explainable Signals│   │ • Audit Trail Ledger │
 │ • Domain Homoglyphs  │   └──────────────────────┘   └──────────────────────┘
 │ • URL Phishing Scan  │              │
 │ • Attachment Scanner │              │
 └──────────┬───────────┘              │
            │                          │
            └──────────────────────────┼──────────────────────────┐
                                       │                          │
                                       ▼                          ▼
                     ┌────────────────────────────────────┐ ┌─────────────────┐
                     │       PostgreSQL 16 Engine         │ │ Forensic Report │
                     │  (SQLAlchemy 2.0 + Alembic / Supa) │ │ (WeasyPrint PDF)│
                     └────────────────────────────────────┘ └─────────────────┘
```

---

## 🛠️ Technology Stack

| Layer | Component | Version | Role in MailTrace |
|---|---|---|---|
| **Frontend** | React | 19.2.x | Reactive UI components, state hooks, and routing |
| **Frontend Bundler** | Vite | 8.2.x | Ultra-fast bundling, HMR, and development proxy |
| **Styling** | Tailwind CSS | 4.3.x | Cyber-forensics dark theme styling via `@tailwindcss/vite` |
| **Routing** | React Router | 7.18.x | Client-side routing across all forensic views |
| **HTTP Client** | Axios | 1.20.x | Async REST communication with the FastAPI backend |
| **Backend Framework** | FastAPI | 0.141.x | Async high-performance RESTful API endpoints |
| **ASGI Server** | Uvicorn | 0.32.x | High-concurrency ASGI server |
| **ORM** | SQLAlchemy | 2.0.x | Relational mapping, models, and type-safe querying |
| **Migrations** | Alembic | 1.13.x | Schema version control and database migration runner |
| **Database Driver** | psycopg2-binary | 2.9.x | High-speed C-optimized PostgreSQL client |
| **Database** | PostgreSQL | 16 | ACID-compliant storage for emails, headers, and audit trails |
| **Machine Learning** | scikit-learn | 1.4.x | TF-IDF text feature extraction and threat categorization |
| **Graph Intelligence** | NetworkX | 3.0+ | Graph data modeling for cross-incident threat correlation |
| **DNS Resolution** | dnspython | 2.0+ | Independent DNS TXT querying for SPF and DMARC |
| **DKIM Verification** | dkimpy | 1.0+ | Native cryptographic verification of RFC 6376 signatures |
| **IP Intelligence** | geoip2 | 4.0+ | City and ASN lookups from MaxMind MMDB format |
| **Validation** | Pydantic | 2.x | Request/response data contract enforcement |
| **Test Framework** | pytest + httpx | 8.x | 158 integration and unit tests against PostgreSQL |

---

## 📚 Module Reference

| Engine Module | Location | Responsibilities |
|---|---|---|
| `mime_parser` | `backend/app/parsers/mime_parser.py` | RFC 822 decoding, header un-folding, safe text/HTML isolation, SHA-256 computation |
| `spf_analyzer` | `backend/app/forensics/spf_analyzer.py` | DNS TXT querying for SPF records, CIDR ip4/ip6 match, `all` mechanism evaluation |
| `dkim_analyzer` | `backend/app/forensics/dkim_analyzer.py` | DKIM-Signature extraction, selector resolution via DNS, signature verification |
| `dmarc_analyzer` | `backend/app/forensics/dmarc_analyzer.py` | DMARC policy lookup (`_dmarc.<domain>`), identifier alignment checks (strict vs relaxed) |
| `received_analyzer` | `backend/app/forensics/received_analyzer.py` | Reverse chronologically parses `Received` headers, detects transit delays and fake hops |
| `ip_intelligence` | `backend/app/forensics/ip_intelligence.py` | Separates public/private/bogon IPs, looks up GeoIP2 City & ASN databases |
| `domain_intel` | `backend/app/forensics/domain_intel.py` | Detects Punycode, Cyrillic/Greek homoglyphs, typosquatting of known brands, risky TLDs |
| `url_analyzer` | `backend/app/forensics/url_analyzer.py` | Extracts URLs from text/HTML, flags IP hosts, URL shorteners, punycode, open redirects |
| `attachment_analyzer` | `backend/app/forensics/attachment_analyzer.py` | Analyzes file extensions, double extensions (`.doc.exe`), MIME mismatches, file hashes |
| `classifier` | `backend/app/ml/classifier.py` | TF-IDF vectorizer + Logistic Regression with linguistic risk signal extraction |
| `risk_engine` | `backend/app/forensics/risk_engine.py` | Computes weighted 8-category 0–100 risk score with human-readable reasoning |
| `evidence` | `backend/app/forensics/evidence.py` | Manages append-only audit log and per-email SHA-256 cryptographic chain proofs |
| `correlation` | `backend/app/forensics/correlation.py` | Builds Cytoscape-formatted entity graphs and detects shared campaign infrastructure |

---

## 📡 API Reference

### Email Ingestion & Inspection (`/api/emails`)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/emails/analyze` | Upload and analyze `.eml` file; calculates SHA-256 evidence fingerprint. |
| `GET` | `/api/emails` | List all analyzed emails (supports `skip` and `limit` pagination). |
| `GET` | `/api/emails/{id}` | Retrieve complete email detail, raw headers in original order, and attachments. |

### Forensics & Analysis (`/api/emails/{id}`)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/emails/{id}/authentication` | Execute and store SPF, DKIM, and DMARC analysis. |
| `GET` | `/api/emails/{id}/authentication` | Retrieve cached authentication analysis results. |
| `POST` | `/api/emails/{id}/received` | Execute relay path hop reconstruction and anomaly inspection. |
| `GET` | `/api/emails/{id}/received` | Retrieve relay path hop analysis. |
| `POST` | `/api/emails/{id}/ip-intel` | Execute IP classification, geolocation, and ASN intelligence. |
| `GET` | `/api/emails/{id}/ip-intel` | Retrieve IP intelligence findings. |
| `POST` | `/api/emails/{id}/classify` | Run ML classifier and extract explainable signals. |
| `GET` | `/api/emails/{id}/classify` | Retrieve ML classification results. |
| `POST` | `/api/emails/{id}/risk` | Calculate multi-signal weighted composite risk assessment. |
| `GET` | `/api/emails/{id}/risk` | Retrieve risk assessment breakdown. |
| `POST` | `/api/emails/{id}/analyze-full` | Run the complete forensic pipeline across all modules. |
| `GET` | `/api/emails/{id}/analyze-full` | Retrieve complete forensic pipeline results. |

### Cases & Incident Dossiers (`/api/cases`)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/cases` | Create a new investigation case dossier. |
| `GET` | `/api/cases` | List all cases with associated email counts. |
| `GET` | `/api/cases/{id}` | Get case metadata and timestamps. |
| `PUT` | `/api/cases/{id}` | Update case title and description. |
| `POST` | `/api/cases/{case_id}/emails/{email_id}` | Assign an analyzed email to an investigation case. |
| `GET` | `/api/cases/{case_id}/emails` | List all emails assigned to a specific case. |

### Audit Ledger & Evidence Proofs

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/audit` | Retrieve immutable append-only audit ledger entries. |
| `POST` | `/api/audit/verify` | Execute real-time cryptographic audit log hash chain validation. |
| `GET` | `/api/evidence/verify/{email_id}` | Verify the SHA-256 evidence chain integrity for an email. |

### Threat Correlation & Reporting

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/graph/email/{id}` | Add an email and its extracted entities to the correlation graph. |
| `GET` | `/api/graph` | Retrieve the complete Cytoscape.js correlation graph. |
| `GET` | `/api/graph/shared` | Detect shared infrastructure (IPs/domains common to multiple emails). |
| `GET` | `/api/reports/{id}/pdf` | Generate and download official forensic report in PDF format (or HTML fallback). |

### System Utility

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Live backend health check (`{"status":"ok"}`). |

---

## 🗄️ Database Architecture

MailTrace uses 7 relational tables in PostgreSQL:

```
┌──────────────┐          ┌───────────────────┐
│    cases     │1       * │      emails       │
│──────────────│─────────▶│───────────────────│
│ id (PK)      │          │ id (PK)           │
│ title        │          │ case_id (FK)      │
│ description  │          │ sha256            │
│ created_at   │          │ sender, subject   │
└──────────────┘          │ body_text/html    │
                          └─────────┬─────────┘
                                    │
       ┌────────────────┬───────────┼───────────────┬────────────────┐
      1│               1│          1│              1│               1│
       ▼*              *▼          *▼              *▼               *▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│email_headers │ │ attachments  │ │email_auth_   │ │evidence_chain│ │  audit_log   │
│              │ │              │ │   results    │ │              │ │              │
│──────────────│ │──────────────│ │──────────────│ │──────────────│ │──────────────│
│ id (PK)      │ │ id (PK)      │ │ id (PK)      │ │ id (PK)      │ │ id (PK)      │
│ email_id(FK) │ │ email_id(FK) │ │ email_id(FK) │ │ email_id(FK) │ │ timestamp    │
│ name         │ │ filename     │ │ mechanism    │ │ action       │ │ action       │
│ value        │ │ content_type │ │ result       │ │ content_hash │ │ actor        │
│ position     │ │ sha256       │ │ domain       │ │ chain_hash   │ │ entry_hash   │
│              │ │ content      │ │ aligned      │ │ previous_hash│ │ previous_hash│
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

---

## 🤖 AI / ML

The machine learning subsystem features a dual-layer threat engine:
1. **Classifier Model:** TF-IDF text vectorization paired with a multi-class Logistic Regression classifier trained on high-volume email datasets (`legitimate`, `suspicious`, `phishing`, `spammer`).
2. **Explainable Signal Extraction:** Regex-grounded linguistic feature detection identifying:
   - `urgency_language`: Artificial time pressure ("act immediately", "account suspended").
   - `credential_request`: Requests for passwords, tokens, pins, or 2FA codes.
   - `payment_request`: Wire transfers, cryptocurrency, gift cards, or fraudulent invoices.
   - `suspicious_url`: IP-based links, misleading anchors, or shorteners.
   - `impersonation`: Executive spoofing or well-known brand impersonation.
   - `auth_anomalies`: Contradictory header claims vs sender domain.

---

## 📊 Risk Scoring

The Risk Engine calculates a normalized score (0–100) using 8 weighted categories:

```
Total Risk Score = Σ (Category Weight × Category Severity)
```

| Category | Weight | Evaluated Signals |
|---|---|---|
| **ML Classification** | 25% | ML model prediction, classification confidence, linguistic urgency/threat triggers |
| **Email Authentication** | 20% | SPF FAIL/SOFTFAIL, DKIM FAIL, DMARC FAIL, unaligned domains |
| **Identity Mismatch** | 10% | Display name spoofing, `Reply-To` mismatch, mismatched envelope senders |
| **Domain Intelligence** | 10% | Lookalike domain detection, homoglyphs (e.g. `pаypal.com`), suspicious TLDs (`.top`, `.xyz`) |
| **URL Analysis** | 10% | Direct IP URLs, free URL shorteners (`bit.ly`), credential harvesting paths, Punycode |
| **Attachment Risk** | 10% | Executable payloads (`.exe`, `.scr`, `.bat`), double extensions (`.pdf.exe`), MIME spoofing |
| **Header Anomalies** | 10% | Missing mandatory RFC headers (`Date`, `Message-ID`), clock skew, abnormal hop count |
| **Infrastructure** | 5% | Bogon IP origins, suspicious ASN, high-risk geolocation flags |

---

## 🔗 Correlation Graph

MailTrace constructs a multi-entity correlation graph (NetworkX backend, Cytoscape.js frontend) to automatically detect coordinated campaigns across multiple uploaded emails:
- **Graph Nodes:** Emails, Senders, Sender Domains, Transit IPs, URLs, Attachments, and Cases.
- **Shared Infrastructure Detection:** The `/api/graph/shared` endpoint identifies when separate phishing emails sent to different individuals share the same malicious IP, sending domain, or attachment hash.
- **Interactive Filtering:** Filter by node type (Email, IP, Domain, Sender, Case) with responsive layout zooming and pan controls.

---

## 📋 Evidence & Chain of Custody

MailTrace satisfies digital forensics chain-of-custody requirements:
1. **Raw Byte Hashing:** SHA-256 hash is computed on uploaded bytes **before** decoding or MIME manipulation.
2. **Append-Only Evidence Chain:** Every analysis, case assignment, or report generation produces an `EvidenceChain` entry containing `content_hash`, `previous_hash`, and a verifiable `chain_hash`.
3. **Audit Trail Verification:** The `/api/audit/verify` endpoint recomputes every block in the audit ledger from the genesis block to prove no records have been altered, inserted, or deleted.

---

## 🐳 Docker Architecture

The `docker-compose.yml` file provides a complete production environment:

```yaml
services:
  db:
    image: postgres:16
    ports: ["5432:5432"]
    healthcheck: ["CMD-SHELL", "pg_isready -U mailtrace"]
    volumes: [pgdata:/var/lib/postgresql/data]

  backend:
    build: { context: ./backend, dockerfile: Dockerfile }
    ports: ["8000:8000"]
    depends_on: { db: { condition: service_healthy } }
    healthcheck: ["CMD-SHELL", "curl http://localhost:8000/health"]

  frontend:
    build: { context: ./frontend, dockerfile: Dockerfile }
    ports: ["3000:80"]
    depends_on: { backend: { condition: service_healthy } }
```

To run the complete container stack:
```bash
docker compose up --build
```

---

## 🗺️ Supabase Deployment

MailTrace can run with **Supabase** as its hosted PostgreSQL database without modifying application code:

1. Create a project at [supabase.com](https://supabase.com).
2. Retrieve your PostgreSQL connection string from **Project Settings → Database → Connection Pooling (Transaction Mode)**.
3. Update `DATABASE_URL` in `backend/.env`:
   ```bash
   DATABASE_URL="postgresql+psycopg2://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres"
   ```
4. Run schema initialization:
   ```bash
   cd backend && alembic upgrade head
   ```

*See [`backend/supabase/README.md`](backend/supabase/README.md) for full deployment instructions.*

---

## 📋 SIH Requirement Mapping

| SIH26106 Requirement | Implementation Module |
|---|---|
| **Email MIME Parsing & Ingestion** | [`backend/app/parsers/mime_parser.py`](backend/app/parsers/mime_parser.py) |
| **Independent SPF / DKIM / DMARC Verification** | [`backend/app/forensics/spf_analyzer.py`](backend/app/forensics/spf_analyzer.py), [`dkim_analyzer.py`](backend/app/forensics/dkim_analyzer.py), [`dmarc_analyzer.py`](backend/app/forensics/dmarc_analyzer.py) |
| **Relay Path Forensics & Delay Detection** | [`backend/app/forensics/received_analyzer.py`](backend/app/forensics/received_analyzer.py) |
| **IP Geolocation & ASN Intelligence** | [`backend/app/forensics/ip_intelligence.py`](backend/app/forensics/ip_intelligence.py) |
| **Domain Impersonation & Homoglyphs** | [`backend/app/forensics/domain_intel.py`](backend/app/forensics/domain_intel.py) |
| **URL Phishing & Shortener Detection** | [`backend/app/forensics/url_analyzer.py`](backend/app/forensics/url_analyzer.py) |
| **Inert Attachment Threat Analysis** | [`backend/app/forensics/attachment_analyzer.py`](backend/app/forensics/attachment_analyzer.py) |
| **AI / ML Threat Classification** | [`backend/app/ml/classifier.py`](backend/app/ml/classifier.py) |
| **Explainable Multi-Signal Risk Engine** | [`backend/app/forensics/risk_engine.py`](backend/app/forensics/risk_engine.py) |
| **Threat Correlation Graph & Campaign Detection** | [`backend/app/forensics/correlation.py`](backend/app/forensics/correlation.py) |
| **Evidence Chain of Custody (SHA-256)** | [`backend/app/forensics/evidence.py`](backend/app/forensics/evidence.py) |
| **Case Dossier Management** | [`backend/app/routers/cases.py`](backend/app/routers/cases.py) |
| **Court-Ready PDF Forensic Reports** | [`backend/app/routers/correlation.py`](backend/app/routers/correlation.py) |

---

## 📊 Project Status

**Current Version:** `0.3.0` (Full-Stack Docker Compose, Alembic Migrations & Advanced Forensics)

- 100% of core and extended forensic engines implemented and tested.
- 158 / 158 tests passing against PostgreSQL 16.
- SQLite strictly prohibited and disabled.
- Full-Stack Docker Compose ready (PostgreSQL + FastAPI + React 19 Nginx).
- Supabase-ready hosted database configuration.

---

## 📝 Changelog

### v0.3.0 (September 2026)

**New Features & Enhancements:**
- **Full-Stack Docker Compose Orchestration:** Containerized React 19 / Vite frontend with production multi-stage Nginx container on port 3000, unified with PostgreSQL 16 and FastAPI backend.
- **Alembic Database Migration Engine:** Integrated Alembic framework (`alembic.ini`, `backend/migrations/`) supporting automated versioned schema migrations (`alembic upgrade head`) alongside raw Supabase DDL.
- **Enhanced Frontend UI:**
  - Modern cybersecurity dark theme using React 19 and Tailwind CSS v4.
  - Live backend health polling indicator in sidebar.
  - Interactive Cytoscape.js correlation graph with node type filtering (Email, IP, Domain, Sender, Case).
  - Case dossier management (`/cases`) to group related incident emails.
  - Audit ledger (`/audit`) with one-click real-time cryptographic hash chain verification.
  - Forensic PDF report generation via WeasyPrint with automatic HTML fallback download.
- **API Enhancements:**
  - Added `GET /api/cases/{case_id}/emails` endpoint for case email retrieval.
  - Synchronized version endpoints to v0.3.0 across FastAPI, `pyproject.toml`, and `package.json`.
  - Added Docker health checks across backend and frontend containers.
- **158 Passing Tests:** Comprehensive PostgreSQL test suite covering all forensic modules, APIs, and tamper-evident chains.

### v0.2.0 (September 2026)

- SQLite completely removed — PostgreSQL strictly enforced.
- Supabase deployment preparation (`backend/supabase/`).
- Initial PostgreSQL DDL migration schema.
- Comprehensive `.env.example` and `.gitignore` protection.
- Docker Compose health checks for database container.

### v0.1.1 (September 2026)

- Multi-header `Received` parsing improvements.
- Enhanced URL extraction from HTML bodies.
- Robust exception handling across analysis routers.
- Upgraded FastAPI and Uvicorn dependencies.

### v0.1.0 (Initial Release)

- Core email forensics pipeline and RFC 822 MIME parser.
- SPF, DKIM, and DMARC verification modules.
- Scikit-learn TF-IDF threat classifier.
- Weighted risk scoring engine.
- Cryptographic evidence chain and audit log.

---

## 🤝 Contributing

1. Clone or fork the repository.
2. Create a feature branch: `git checkout -b feature/forensics-enhancement`.
3. Make your changes and add tests under `backend/tests/`.
4. Ensure all tests pass: `python3 -m pytest -v`.
5. Submit a pull request with a detailed description of your changes.

---

## 📄 License

Developed for **Smart India Hackathon 2026** (Problem Statement SIH26106). All rights reserved. Subject to Smart India Hackathon competition guidelines.
