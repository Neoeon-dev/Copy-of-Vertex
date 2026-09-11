"""Tests for case management, evidence chain, audit log, correlation graph, and forensic reports."""
from __future__ import annotations

import io

from app.forensics.evidence import (
    add_audit_entry,
    add_evidence_entry,
    verify_audit_log_integrity,
    verify_chain_integrity,
)
from app.forensics.correlation import CorrelationEngine
from tests.conftest import SAMPLE_EML, SAMPLE_EML_HEADERS_ONLY, _TestSession


def _get_test_db():
    db = _TestSession()
    try:
        yield db
    finally:
        db.close()


# ── Evidence Chain Tests ─────────────────────────────────────────────


class TestEvidenceChain:

    def test_add_evidence_entry(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
        )
        eid = resp.json()["id"]
        sha256 = resp.json()["sha256"]

        db = _TestSession()
        try:
            entry = add_evidence_entry(db, eid, sha256, "uploaded", "Initial upload")
            db.commit()
            assert entry.chain_hash
            assert entry.previous_hash is None
        finally:
            db.close()

    def test_chain_integrity(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
        )
        eid = resp.json()["id"]
        sha256 = resp.json()["sha256"]

        db = _TestSession()
        try:
            add_evidence_entry(db, eid, sha256, "uploaded")
            add_evidence_entry(db, eid, sha256, "analyzed", "Full analysis complete")
            db.commit()
            is_valid, errors = verify_chain_integrity(db, eid)
            assert is_valid is True
            assert errors == []
        finally:
            db.close()

    def test_verify_evidence_endpoint(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
        )
        eid = resp.json()["id"]
        sha256 = resp.json()["sha256"]

        db = _TestSession()
        try:
            add_evidence_entry(db, eid, sha256, "uploaded")
            db.commit()
        finally:
            db.close()

        resp = client.get(f"/api/evidence/verify/{eid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["email_id"] == eid


# ── Audit Log Tests ─────────────────────────────────────────────────


class TestAuditLog:

    def test_add_audit_entry(self):
        db = _TestSession()
        try:
            entry = add_audit_entry(db, "email.uploaded", "email", 1, details="test upload")
            db.commit()
            assert entry.entry_hash
            assert entry.action == "email.uploaded"
        finally:
            db.close()

    def test_audit_chain_integrity(self):
        db = _TestSession()
        try:
            add_audit_entry(db, "email.uploaded", "email", 1)
            add_audit_entry(db, "email.analyzed", "email", 1)
            add_audit_entry(db, "case.created", "case", 1)
            db.commit()
            is_valid, errors = verify_audit_log_integrity(db)
            assert is_valid is True
            assert errors == []
        finally:
            db.close()

    def test_audit_log_endpoint(self, client):
        db = _TestSession()
        try:
            add_audit_entry(db, "email.uploaded", "email", 1, details="test")
            db.commit()
        finally:
            db.close()

        resp = client.get("/api/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        assert data[0]["action"] == "email.uploaded"

    def test_audit_verify_endpoint(self, client):
        db = _TestSession()
        try:
            add_audit_entry(db, "test.action", "email", 1)
            db.commit()
        finally:
            db.close()

        resp = client.post("/api/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True


# ── Case Management Tests ───────────────────────────────────────────


class TestCaseManagement:

    def test_create_case(self, client):
        resp = client.post("/api/cases", json={"title": "Phishing Investigation", "description": "Test case"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Phishing Investigation"
        assert data["id"] > 0

    def test_list_cases(self, client):
        client.post("/api/cases", json={"title": "Case 1"})
        client.post("/api/cases", json={"title": "Case 2"})
        resp = client.get("/api/cases")
        assert resp.status_code == 200
        assert len(resp.json()) >= 2

    def test_get_case(self, client):
        resp = client.post("/api/cases", json={"title": "Test Case"})
        case_id = resp.json()["id"]
        resp = client.get(f"/api/cases/{case_id}")
        assert resp.status_code == 200
        assert resp.json()["title"] == "Test Case"

    def test_update_case(self, client):
        resp = client.post("/api/cases", json={"title": "Old Title"})
        case_id = resp.json()["id"]
        resp = client.put(f"/api/cases/{case_id}", json={"title": "New Title"})
        assert resp.status_code == 200
        assert resp.json()["title"] == "New Title"

    def test_assign_email_to_case(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
        )
        eid = resp.json()["id"]
        resp = client.post("/api/cases", json={"title": "Test Case"})
        case_id = resp.json()["id"]
        resp = client.post(f"/api/cases/{case_id}/emails/{eid}")
        assert resp.status_code == 200
        resp = client.get(f"/api/cases/{case_id}/emails")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_case_not_found(self, client):
        resp = client.get("/api/cases/99999")
        assert resp.status_code == 404


# ── Correlation Graph Tests ─────────────────────────────────────────


class TestCorrelationGraph:

    def test_add_email_to_graph(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML_HEADERS_ONLY), "message/rfc822")},
        )
        eid = resp.json()["id"]
        resp = client.post(f"/api/graph/email/{eid}")
        assert resp.status_code == 200

    def test_get_graph(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML_HEADERS_ONLY), "message/rfc822")},
        )
        eid = resp.json()["id"]
        client.post(f"/api/graph/email/{eid}")
        resp = client.get("/api/graph")
        assert resp.status_code == 200
        data = resp.json()
        assert "elements" in data
        assert len(data["elements"]["nodes"]) > 0

    def test_get_shared_infrastructure(self, client):
        resp = client.get("/api/graph/shared")
        assert resp.status_code == 200

    def test_correlation_engine_unit(self):
        engine = CorrelationEngine()
        engine.add_email({"id": 1, "subject": "Test", "sender": "attacker@evil.com"})
        engine.add_ips(1, [{"ip": "1.2.3.4", "is_public": True, "asn": {"asn": 15169, "organization": "Google"}}])
        engine.add_urls(1, [{"url": "http://1.2.3.4/steal"}])
        engine.add_domains(1, [{"domain": "evil.com", "risk_score": 0.3, "lookalikes": []}])
        graph = engine.build_cytoscape_graph()
        assert len(graph.nodes) > 0
        assert len(graph.edges) > 0


# ── PDF Report Tests ────────────────────────────────────────────────


class TestPDFReport:

    def test_generate_pdf(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML_HEADERS_ONLY), "message/rfc822")},
        )
        eid = resp.json()["id"]
        resp = client.get(f"/api/reports/{eid}/pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] in ("application/pdf", "text/html")

    def test_pdf_not_found(self, client):
        resp = client.get("/api/reports/99999/pdf")
        assert resp.status_code == 404
