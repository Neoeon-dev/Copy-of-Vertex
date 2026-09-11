-- MailTrace Database Schema
-- Migration: 001_initial_schema.sql
-- Description: Create all tables for the MailTrace forensic platform

-- Cases table
CREATE TABLE IF NOT EXISTS cases (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Emails table
CREATE TABLE IF NOT EXISTS emails (
    id SERIAL PRIMARY KEY,
    case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    sha256 VARCHAR(64) NOT NULL,
    filename VARCHAR(512),
    size BIGINT NOT NULL,
    subject TEXT,
    sender VARCHAR(512),
    sender_name VARCHAR(512),
    reply_to VARCHAR(512),
    "to" JSONB,
    cc JSONB,
    message_id VARCHAR(512),
    date TIMESTAMPTZ,
    body_text TEXT,
    body_html TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_emails_sha256 ON emails(sha256);
CREATE INDEX IF NOT EXISTS idx_emails_case_id ON emails(case_id);

-- Email headers table
CREATE TABLE IF NOT EXISTS email_headers (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    value TEXT NOT NULL,
    position INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_headers_email_id ON email_headers(email_id);

-- Attachments table
CREATE TABLE IF NOT EXISTS attachments (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    filename VARCHAR(512),
    content_type VARCHAR(256) NOT NULL,
    size BIGINT NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    content BYTEA
);

CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id);

-- Email authentication results table
CREATE TABLE IF NOT EXISTS email_authentication_results (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    mechanism VARCHAR(32) NOT NULL,
    result VARCHAR(32) NOT NULL,
    domain VARCHAR(255),
    selector VARCHAR(255),
    aligned BOOLEAN,
    source VARCHAR(32) NOT NULL,
    details TEXT,
    checked_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_results_email_id ON email_authentication_results(email_id);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    action VARCHAR(64) NOT NULL,
    entity_type VARCHAR(32) NOT NULL,
    entity_id INTEGER,
    actor VARCHAR(128) DEFAULT 'system',
    details TEXT,
    previous_hash VARCHAR(64),
    entry_hash VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);

-- Evidence chain table
CREATE TABLE IF NOT EXISTS evidence_chain (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    evidence_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64),
    chain_hash VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_evidence_chain_email_id ON evidence_chain(email_id);
CREATE INDEX IF NOT EXISTS idx_evidence_chain_evidence_id ON evidence_chain(evidence_id);
