#!/bin/bash
# MailTrace — Quick Start (PostgreSQL mode)
# Requires PostgreSQL running via Docker Compose: docker compose up -d db

set -e

cd "$(dirname "$0")"

# Clear stale Python caches to prevent stale code from loading
find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Default PostgreSQL connection string
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg2://mailtrace:mailtrace@localhost:5432/mailtrace}"
export DEMO_MODE="${DEMO_MODE:-true}"

# Kill any existing server on port 8000
lsof -ti :8000 | xargs kill -9 2>/dev/null || true
sleep 1

echo "=== MailTrace — Email Forensic Intelligence Platform ==="
echo ""
echo "Database: PostgreSQL"
echo "Starting backend on http://localhost:8000"
echo "API docs at http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop"
echo ""

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
