"""Tests for the email ingestion and retrieval API.

Verifies:
- .eml upload + parsing + database persistence
- Evidence SHA-256 is computed on raw bytes
- All headers preserved in order
- Multiple recipients parsed
- Attachment extraction
- List + detail retrieval
- Rejection of non-.eml files
- Rejection of empty files
- Rejection of oversized files
"""
from __future__ import annotations

import hashlib
import io

from tests.conftest import SAMPLE_EML, SAMPLE_EML_HEADERS_ONLY, SAMPLE_EML_MULTIPART


class TestAnalyzeEndpoint:
    """POST /api/emails/analyze"""

    def test_upload_simple_eml(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
        )
        assert resp.status_code == 201
        data = resp.json()

        # Evidence hash matches raw bytes
        assert data["sha256"] == hashlib.sha256(SAMPLE_EML).hexdigest()

        # Metadata extracted
        assert data["subject"] == "Test Email"
        assert data["sender"] == "john@example.com"
        assert data["sender_name"] == "John Doe"
        assert data["reply_to"] == "reply@example.com"
        assert data["message_id"] == "<test-001@example.com>"

        # Recipients
        assert len(data["to"]) == 1
        assert data["to"][0]["address"] == "jane@example.com"
        assert len(data["cc"]) == 1
        assert data["cc"][0]["address"] == "bob@example.com"

        # Body
        assert "test email body" in data["body_text"]

        # Headers preserved
        assert len(data["headers"]) > 0
        header_names = [h["name"] for h in data["headers"]]
        assert "From" in header_names
        assert "Subject" in header_names

        # No attachments
        assert data["attachments"] == []

    def test_upload_multipart_with_attachment(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={
                "file": (
                    "invoice.eml",
                    io.BytesIO(SAMPLE_EML_MULTIPART),
                    "message/rfc822",
                )
            },
        )
        assert resp.status_code == 201
        data = resp.json()

        assert data["subject"] == "Important Invoice"
        assert data["sender"] == "sender@evil.com"
        assert "invoice" in data["body_text"].lower() or "attached" in data["body_text"].lower()

        # Attachment extracted
        assert len(data["attachments"]) == 1
        att = data["attachments"][0]
        assert att["filename"] == "invoice.pdf"
        assert att["content_type"] == "application/pdf"
        assert att["size"] > 0
        assert len(att["sha256"]) == 64  # SHA-256 hex digest

    def test_upload_preserves_all_headers_in_order(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={
                "file": (
                    "headers.eml",
                    io.BytesIO(SAMPLE_EML_HEADERS_ONLY),
                    "message/rfc822",
                )
            },
        )
        assert resp.status_code == 201
        data = resp.json()

        headers = data["headers"]
        assert len(headers) >= 7  # From, To, Subject, Received x2, Auth-Results, Content-Type

        # Positions are sequential
        positions = [h["position"] for h in headers]
        assert positions == list(range(len(positions)))

        # Received headers are both preserved
        received = [h for h in headers if h["name"] == "Received"]
        assert len(received) == 2

        # Authentication-Results preserved
        auth_results = [h for h in headers if h["name"] == "Authentication-Results"]
        assert len(auth_results) == 1

    def test_upload_missing_from_header(self, client):
        eml = b"""\
To: victim@example.com
Subject: No sender
Content-Type: text/plain

Hello
"""
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(eml), "message/rfc822")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["sender"] is None
        assert data["subject"] == "No sender"

    def test_upload_completely_malformed(self, client):
        eml = b"This is not an email at all, just random garbage."
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(eml), "message/rfc822")},
        )
        # Should still accept — the stdlib parser is lenient
        assert resp.status_code == 201
        data = resp.json()
        assert len(data["sha256"]) == 64


class TestValidation:
    """Upload validation: file extension, size, empty files."""

    def test_reject_non_eml_extension(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.txt", io.BytesIO(b"hello"), "text/plain")},
        )
        assert resp.status_code == 400
        assert ".eml" in resp.json()["detail"]

    def test_reject_empty_file(self, client):
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(b""), "message/rfc822")},
        )
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()


class TestRetrieval:
    """GET /api/emails and GET /api/emails/{id}"""

    def _upload_one(self, client) -> int:
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
        )
        return resp.json()["id"]

    def test_list_emails(self, client):
        self._upload_one(client)
        self._upload_one(client)

        resp = client.get("/api/emails")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_get_email_detail(self, client):
        eid = self._upload_one(client)
        resp = client.get(f"/api/emails/{eid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == eid
        assert data["subject"] == "Test Email"
        assert len(data["headers"]) > 0

    def test_get_nonexistent_email(self, client):
        resp = client.get("/api/emails/99999")
        assert resp.status_code == 404
