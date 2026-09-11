"""Shared test fixtures.

Uses a PostgreSQL test database (mailtrace_test) on the same PostgreSQL
instance as the application. Set DATABASE_URL to your PostgreSQL connection
string before running tests. The test database is created/destroyed per test.
"""
from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

# Use a dedicated test database on PostgreSQL
_raw_db_url = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://mailtrace:mailtrace@localhost:5432/mailtrace",
)

# Replace only the database name (last path component) with mailtrace_test
_test_db_url = re.sub(
    r"(/[^/?]+)(\?.*)?$",
    r"/mailtrace_test\2",
    _raw_db_url,
)
os.environ["DATABASE_URL"] = _test_db_url
# Disable .env file loading during tests
os.environ["DEMO_MODE"] = "false"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app

# Create engine for the test database
_test_engine = create_engine(_test_db_url, pool_pre_ping=True)
_TestSession = sessionmaker(bind=_test_engine, autocommit=False, autoflush=False)


def _create_test_database():
    """Create the test database if it does not exist."""
    # Connect to the default 'postgres' database to create/drop test db
    default_url = re.sub(
        r"(/[^/?]+)(\?.*)?$",
        r"/postgres\2",
        _raw_db_url,
    )
    default_engine = create_engine(default_url, isolation_level="AUTOCOMMIT")
    try:
        with default_engine.connect() as conn:
            result = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": "mailtrace_test"},
            )
            if not result.fetchone():
                conn.execute(text("CREATE DATABASE mailtrace_test"))
                logger.info("Created test database: mailtrace_test")
    except Exception as exc:
        logger.warning("Could not create test database: %s", exc)
    finally:
        default_engine.dispose()


# Try to create test database at import time
try:
    _create_test_database()
except Exception:
    pass


def _override_get_db():
    db = _TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture(autouse=True)
def _create_tables():
    """Create all tables before each test, drop after."""
    Base.metadata.create_all(bind=_test_engine)
    yield
    Base.metadata.drop_all(bind=_test_engine)


@pytest.fixture()
def client():
    return TestClient(app)


# ── Sample .eml fixtures ────────────────────────────────────────────

SAMPLE_EML = b"""\
From: John Doe <john@example.com>
To: jane@example.com
Cc: bob@example.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test-001@example.com>
Reply-To: reply@example.com
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello, this is a test email body.
"""

SAMPLE_EML_MULTIPART = b"""\
From: Sender <sender@evil.com>
To: victim@target.com
Subject: Important Invoice
Date: Tue, 02 Jan 2024 14:30:00 +0000
Message-ID: <test-002@evil.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

Please see the attached invoice.

--boundary123
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjAKMSAwIG9iago=
--boundary123--
"""

SAMPLE_EML_HEADERS_ONLY = b"""\
From: Attacker <attacker@phish.net>
To: ceo@company.com
Subject: Urgent: Wire Transfer Required
Received: from mail.phish.net (phish.net [192.168.1.1])
        by mx.company.com (8.14.4/8.14.4) with ESMTP id abc123
        for <ceo@company.com>; Mon, 01 Jan 2024 12:00:00 +0000
Received: from unknown (HELO local) (10.0.0.1)
        by mail.phish.net with SMTP; Mon, 01 Jan 2024 11:59:00 +0000
Authentication-Results: mx.company.com;
        spf=fail (domain of attacker@phish.net does not designate 192.168.1.1 as permitted sender);
        dkim=none header.d=phish.net;
        dmarc=fail (p=REJECT) header.from=phish.net
Content-Type: text/plain; charset="utf-8"

Wire the money immediately.
"""
