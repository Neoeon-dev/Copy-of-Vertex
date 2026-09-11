# MailTrace — Backend Application & Forensics Engine

> High-performance FastAPI backend, email parsing pipeline, forensic intelligence engines, and machine learning threat classifier for MailTrace.

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141+-009688.svg)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org)
[![Alembic](https://img.shields.io/badge/Alembic-1.13+-red.svg)](https://alembic.sqlalchemy.org)
[![Tests](https://img.shields.io/badge/tests-158%20passed-brightgreen.svg)]()

---

## 🏛️ Architecture Overview

The MailTrace backend is structured into specialized forensic layers:

```
backend/
├── app/
│   ├── main.py              # FastAPI application, lifespan handler, CORS, router mounting
│   ├── config.py            # Pydantic BaseSettings environment loader
│   ├── db.py                # PostgreSQL SQLAlchemy engine, session maker, SQLite rejection
│   ├── models.py            # SQLAlchemy ORM models (7 relational tables)
│   ├── utils.py             # Header normalization and HTML sanitization utilities
│   │
│   ├── parsers/
│   │   └── mime_parser.py   # RFC 822 email parser and raw SHA-256 byte hasher
│   │
│   ├── forensics/           # Cyber-forensics analysis engines
│   │   ├── spf_analyzer.py        # Independent DNS SPF record evaluation
│   │   ├── dkim_analyzer.py       # Cryptographic DKIM signature verification
│   │   ├── dmarc_analyzer.py      # DMARC policy & identifier alignment logic
│   │   ├── received_analyzer.py   # Relay path parser & timing anomaly detection
│   │   ├── ip_intelligence.py     # GeoIP2 & ASN intelligence resolution
│   │   ├── domain_intel.py        # Homoglyphs, lookalikes & risky TLD analysis
│   │   ├── url_analyzer.py        # Phishing link extraction & reputation checks
│   │   ├── attachment_analyzer.py # Safe attachment threat & MIME scanner
│   │   ├── risk_engine.py         # 8-category weighted risk engine (0–100)
│   │   ├── evidence.py            # Append-only hash chain & cryptographic audit proofs
│   │   └── correlation.py         # NetworkX entity graph & shared infrastructure engine
│   │
│   ├── ml/
│   │   └── classifier.py    # TF-IDF + Logistic Regression threat classifier
│   │
│   ├── routers/             # FastAPI REST route controllers (9 modules)
│   │   ├── emails.py        # Upload & retrieval (/api/emails)
│   │   ├── authentication.py# SPF/DKIM/DMARC analysis (/api/emails/{id}/authentication)
│   │   ├── received.py      # Received relay analysis (/api/emails/{id}/received)
│   │   ├── ip_intel.py      # IP & Geo intelligence (/api/emails/{id}/ip-intel)
│   │   ├── ml.py            # ML threat classification (/api/emails/{id}/classify)
│   │   ├── risk.py          # Composite risk scoring (/api/emails/{id}/risk)
│   │   ├── analysis.py      # Full pipeline orchestrator (/api/emails/{id}/analyze-full)
│   │   ├── cases.py         # Case dossiers & audit log (/api/cases, /api/audit)
│   │   └── correlation.py   # Cytoscape graph & PDF reports (/api/graph, /api/reports)
│   │
│   └── schemas/             # Pydantic response models and DTOs
│       └── email.py
│
├── migrations/              # Alembic database migrations
│   ├── env.py
│   ├── alembic.ini
│   └── versions/
│       └── 9557d637c8b2_initial_schema.py
│
├── supabase/                # Hosted Supabase PostgreSQL deployment assets
│   ├── README.md
│   └── migrations/001_initial_schema.sql
│
├── tests/                   # 158 automated PostgreSQL tests
│   ├── conftest.py
│   ├── test_authentication.py
│   ├── test_cases_evidence_reports.py
│   ├── test_domain_url_attachment.py
│   ├── test_email_api.py
│   ├── test_ip_intel.py
│   ├── test_ml.py
│   ├── test_received.py
│   └── test_risk_engine.py
│
├── Dockerfile               # Production container definition (Python 3.12-slim)
├── .dockerignore            # Container build excludes
├── requirements.txt         # Pinned Python package dependencies
├── pyproject.toml           # Project metadata & pytest configuration
└── run.sh                   # Quick-start backend runner script
```

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.11+ (Python 3.12 or 3.14 supported)
- PostgreSQL 15+ running on port 5432 (e.g. via `docker compose up -d db` from repo root)

### 2. Environment Setup
```bash
cp .env.example .env
```

Review the `.env` settings:
```bash
DATABASE_URL=postgresql+psycopg2://mailtrace:mailtrace@localhost:5432/mailtrace
DEMO_MODE=true
MAX_UPLOAD_SIZE_MB=10
```

### 3. Run with Helper Script
```bash
bash run.sh
```
This script cleans Python caches, checks ports, sets environment defaults, and starts Uvicorn on `http://localhost:8000`.

### 4. Or Run Manually
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🗄️ Database Migrations (Alembic)

MailTrace includes full declarative database migration support via Alembic:

```bash
# Upgrade database to latest revision
alembic upgrade head

# Generate a new migration after editing models.py
alembic revision --autogenerate -m "add_new_feature"

# Show current database revision
alembic current

# Show migration history
alembic history --verbose
```

---

## 🧪 Testing

All 158 tests run against an isolated PostgreSQL test database (`mailtrace_test`), created and migrated automatically:

```bash
# Run full test suite
python3 -m pytest -v

# Run tests with short summary
python3 -m pytest -q

# Run specific test file
python3 -m pytest tests/test_risk_engine.py -v
```

---

## 📡 API Endpoints Summary

- **Health:** `GET /health`
- **Emails:**
  - `POST /api/emails/analyze` (Upload `.eml`)
  - `GET /api/emails`
  - `GET /api/emails/{id}`
- **Forensic Engines:**
  - `POST/GET /api/emails/{id}/authentication` (SPF, DKIM, DMARC)
  - `POST/GET /api/emails/{id}/received` (Relay path reconstruction)
  - `POST/GET /api/emails/{id}/ip-intel` (GeoIP & ASN lookup)
  - `POST/GET /api/emails/{id}/classify` (TF-IDF + Logistic Regression ML)
  - `POST/GET /api/emails/{id}/risk` (Weighted multi-signal risk assessment)
  - `POST/GET /api/emails/{id}/analyze-full` (Full diagnostic pipeline)
- **Cases & Audit:**
  - `POST/GET /api/cases`
  - `GET/PUT /api/cases/{id}`
  - `POST /api/cases/{case_id}/emails/{email_id}`
  - `GET /api/cases/{case_id}/emails`
  - `GET /api/audit`
  - `POST /api/audit/verify` (Tamper-evident hash chain check)
  - `GET /api/evidence/verify/{email_id}` (Evidence proof validation)
- **Graph & Reports:**
  - `POST /api/graph/email/{id}`
  - `GET /api/graph` (Cytoscape.js format)
  - `GET /api/graph/shared` (Campaign shared infrastructure)
  - `GET /api/reports/{id}/pdf` (Forensic report export)
