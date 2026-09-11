"""Phase B Forensic Evidence Preservation & Authentication Tests.

Tests for:
1. Exact raw .eml evidence byte preservation in PostgreSQL and retrieval via GET /api/emails/{id}/raw.
2. DKIM cryptographic verification with dkimpy on pristine raw bytes (valid, tampered, multi-sig).
3. DMARC domain extraction, Public Suffix List (PSL) organizational domain handling, and strict vs relaxed alignment.
4. SPF RFC 7208 compliance: IPv4/IPv6 CIDR evaluation, 10-lookup limit enforcement, and loop detection.
5. MIME parser robustness: nested message/rfc822 attachment extraction and header preservation.
6. Evidence chain and audit log cryptographic tamper-detection.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
from unittest.mock import patch

import dkim
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.forensics.dkim_analyzer import (
    DKIM_FAIL,
    DKIM_PASS,
    DKIM_PERMERROR,
    analyze_dkim,
)
from app.forensics.dmarc_analyzer import (
    DMARC_PASS,
    DMARC_FAIL,
    _check_dkim_alignment,
    _check_spf_alignment,
    analyze_dmarc,
    extract_domain_from_address,
    get_organizational_domain,
)
from app.forensics.evidence import (
    add_audit_entry,
    add_evidence_entry,
    verify_audit_log_integrity,
    verify_chain_integrity,
)
from app.forensics.spf_analyzer import (
    SPF_FAIL,
    SPF_PASS,
    SPF_PERMERROR,
    _evaluate_spf_record,
    analyze_spf,
)
from app.models import AuditLog, Email, EmailRawPayload, EvidenceChain
from app.parsers.mime_parser import parse_email
from app.utils import get_headers_dict
from tests.conftest import _TestSession


# ── Fixtures for Cryptographic Keys and Signed Emails ─────────────────────────


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate a temporary 2048-bit RSA keypair for deterministic DKIM tests."""
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_key = priv_key.public_key()
    pub_der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    dns_txt = f"v=DKIM1; k=rsa; p={pub_b64}"
    return priv_pem, dns_txt


# ── 1. Raw .eml Evidence Preservation & Retrieval Tests ───────────────────────


class TestRawEvidencePreservation:
    """Test raw .eml storage in EmailRawPayload and GET /api/emails/{id}/raw."""

    def test_raw_bytes_preserved_exact_and_retrievable(self, client):
        # Create an RFC 822 payload with specific CRLF, trailing spaces and UTF-8
        raw_eml = (
            b"From: investigator@agency.gov.in\r\n"
            b"To: target@corp.example.com\r\n"
            b"Subject: Subpoena Evidence Verification \r\n"
            b"X-Custom-Tracking-ID: CASE-2026-X99 \r\n"
            b"Date: Sun, 06 Sep 2026 12:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Preserve this exact byte stream without normalization.\r\n"
            b"\x00\x01\x02Inert binary sequence test.\r\n"
        )
        expected_sha256 = hashlib.sha256(raw_eml).hexdigest()

        # Ingest via API
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("evidence_case_01.eml", io.BytesIO(raw_eml), "message/rfc822")},
        )
        assert resp.status_code == 201
        data = resp.json()
        email_id = data["id"]
        assert data["sha256"] == expected_sha256

        # Check DB model directly: EmailRawPayload must contain exact byte stream
        db = _TestSession()
        try:
            payload_row = db.query(EmailRawPayload).filter(EmailRawPayload.email_id == email_id).first()
            assert payload_row is not None
            assert payload_row.sha256 == expected_sha256
            assert payload_row.raw_bytes == raw_eml
            assert len(payload_row.raw_bytes) == len(raw_eml)
        finally:
            db.close()

        # Retrieve raw evidence via GET /api/emails/{id}/raw
        raw_resp = client.get(f"/api/emails/{email_id}/raw")
        assert raw_resp.status_code == 200
        assert raw_resp.content == raw_eml
        assert raw_resp.headers["Content-Type"].startswith("message/rfc822")
        assert raw_resp.headers["X-Evidence-SHA256"] == expected_sha256
        assert "evidence_case_01.eml" in raw_resp.headers["Content-Disposition"]

    def test_raw_retrieval_404_for_nonexistent_email(self, client):
        resp = client.get("/api/emails/999999/raw")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()


# ── 2. DKIM Verification on Pristine Raw Bytes ────────────────────────────────


class TestDKIMCryptographicVerification:
    """Test cryptographic DKIM signature verification using dkimpy."""

    def test_dkim_valid_signature_passes(self, rsa_keypair):
        priv_pem, dns_txt = rsa_keypair
        msg = (
            b"From: security@example.com\r\n"
            b"To: audit@example.com\r\n"
            b"Subject: Integrity Test\r\n"
            b"\r\n"
            b"Pristine authentic email body.\r\n"
        )
        sig = dkim.sign(
            message=msg,
            selector=b"s2026",
            domain=b"example.com",
            privkey=priv_pem,
            include_headers=[b"From", b"To", b"Subject"],
        )
        signed_msg = sig + msg

        parsed = parse_email(signed_msg)
        headers = get_headers_dict(parsed.headers)

        def fake_dnsfunc(subdomain, timeout=5):
            return dns_txt.encode("ascii")

        results = analyze_dkim(
            headers=headers,
            raw_email_bytes=signed_msg,
            email_sender_domain="example.com",
            dnsfunc=fake_dnsfunc,
        )

        assert len(results) == 1
        res = results[0]
        assert res.result == DKIM_PASS
        assert res.domain == "example.com"
        assert res.selector == "s2026"
        assert "verified" in (res.details or "").lower()

    def test_dkim_tampered_body_fails_with_diagnostic(self, rsa_keypair):
        priv_pem, dns_txt = rsa_keypair
        msg = (
            b"From: security@example.com\r\n"
            b"To: audit@example.com\r\n"
            b"Subject: Tamper Test\r\n"
            b"\r\n"
            b"Original body before tampering.\r\n"
        )
        sig = dkim.sign(
            message=msg,
            selector=b"s2026",
            domain=b"example.com",
            privkey=priv_pem,
            include_headers=[b"From", b"To", b"Subject"],
        )
        # Tamper body text after signature generation
        tampered_msg = sig + msg.replace(b"Original body", b"Modified attacker payload")

        parsed = parse_email(tampered_msg)
        headers = get_headers_dict(parsed.headers)

        def fake_dnsfunc(subdomain, timeout=5):
            return dns_txt.encode("ascii")

        results = analyze_dkim(
            headers=headers,
            raw_email_bytes=tampered_msg,
            email_sender_domain="example.com",
            dnsfunc=fake_dnsfunc,
        )

        assert len(results) == 1
        res = results[0]
        assert res.result == DKIM_FAIL
        assert "body hash mismatch" in (res.details or "").lower()

    def test_dkim_tampered_header_fails(self, rsa_keypair):
        priv_pem, dns_txt = rsa_keypair
        msg = (
            b"From: security@example.com\r\n"
            b"To: audit@example.com\r\n"
            b"Subject: Official Notice\r\n"
            b"\r\n"
            b"Authentic content.\r\n"
        )
        sig = dkim.sign(
            message=msg,
            selector=b"s2026",
            domain=b"example.com",
            privkey=priv_pem,
            include_headers=[b"From", b"To", b"Subject"],
        )
        # Tamper subject in the headers
        tampered_msg = sig + msg.replace(b"Subject: Official Notice", b"Subject: Spoofed Notice")

        parsed = parse_email(tampered_msg)
        headers = get_headers_dict(parsed.headers)

        def fake_dnsfunc(subdomain, timeout=5):
            return dns_txt.encode("ascii")

        results = analyze_dkim(
            headers=headers,
            raw_email_bytes=tampered_msg,
            email_sender_domain="example.com",
            dnsfunc=fake_dnsfunc,
        )

        assert len(results) == 1
        assert results[0].result == DKIM_FAIL

    def test_dkim_missing_selector_returns_permerror(self):
        headers = {"dkim-signature": "v=1; a=rsa-sha256; d=example.com; b=bad"}
        results = analyze_dkim(headers=headers, raw_email_bytes=b"...")
        assert len(results) == 1
        assert results[0].result == DKIM_PERMERROR


# ── 3. DMARC Address Extraction & PSL Alignment Tests ─────────────────────────


class TestDMARCAlignmentAndPSL:
    """Test RFC 7489 DMARC domain extraction and PSL alignment."""

    def test_extract_domain_from_address(self):
        assert extract_domain_from_address("user@example.com") == "example.com"
        assert extract_domain_from_address("Alice Smith <alice@sub.domain.co.uk>") == "sub.domain.co.uk"
        assert extract_domain_from_address("<admin@dept.gov.in>") == "dept.gov.in"
        assert extract_domain_from_address("example.com") == "example.com"
        assert extract_domain_from_address("") is None
        assert extract_domain_from_address(None) is None

    def test_get_organizational_domain_with_psl(self):
        # ccSLDs and multi-part TLDs
        assert get_organizational_domain("mail.nic.in") == "mail.nic.in"
        assert get_organizational_domain("pmo.gov.in") == "pmo.gov.in"
        assert get_organizational_domain("portal.cyber.police.gov.in") == "police.gov.in"
        assert get_organizational_domain("sub.corp.example.co.uk") == "example.co.uk"
        assert get_organizational_domain("finance.amazon.co.jp") == "amazon.co.jp"
        # Standard gTLDs
        assert get_organizational_domain("deep.nested.sub.domain.com") == "domain.com"
        assert get_organizational_domain("example.com") == "example.com"

    def test_check_alignment_modes(self):
        # Strict vs Relaxed SPF alignment (aspf)
        assert _check_spf_alignment("mail.example.com", "example.com", "r") is True
        assert _check_spf_alignment("mail.example.com", "example.com", "s") is False
        assert _check_spf_alignment("example.com", "example.com", "s") is True

        # Strict vs Relaxed DKIM alignment (adkim)
        assert _check_dkim_alignment("marketing.example.com", "example.com", "r") is True
        assert _check_dkim_alignment("marketing.example.com", "example.com", "s") is False
        assert _check_dkim_alignment("example.com", "example.com", "s") is True

        # ccSLD alignment under relaxed mode
        assert _check_spf_alignment("dept.ministry.gov.in", "agency.ministry.gov.in", "r") is True
        assert _check_spf_alignment("dept.ministry.gov.in", "agency.ministry.gov.in", "s") is False

        # Unaligned domains
        assert _check_spf_alignment("attacker.com", "victim.com", "r") is False

    def test_analyze_dmarc_evaluates_policy_and_alignment(self):
        with patch("app.forensics.dmarc_analyzer._lookup_dmarc_policy") as mock_lookup:
            mock_lookup.return_value = (
                {"v": "DMARC1", "p": "reject", "aspf": "s", "adkim": "r"},
                None,
            )

            # Case A: Strict SPF with sub-domain fails alignment, but relaxed DKIM passes
            res = analyze_dmarc(
                email_sender_domain="example.com",
                spf_result="PASS",
                spf_envelope_domain="mail.example.com",  # Not exact match -> strict aspf fails
                dkim_result="PASS",
                dkim_domain="sub.example.com",  # Same org domain -> relaxed adkim passes
            )
            assert res.spf_aligned is False
            assert res.dkim_aligned is True
            assert res.result == DMARC_PASS
            assert res.policy == "reject"

            # Case B: Both fail alignment -> DMARC fails
            res_fail = analyze_dmarc(
                email_sender_domain="example.com",
                spf_result="PASS",
                spf_envelope_domain="unrelated.org",
                dkim_result="PASS",
                dkim_domain="phishing.net",
            )
            assert res_fail.spf_aligned is False
            assert res_fail.dkim_aligned is False
            assert res_fail.result == DMARC_FAIL


# ── 4. SPF RFC 7208 Compliance & Lookup Limits ───────────────────────────────


class TestSPFStandardsCompliance:
    """Test SPF evaluation, IPv4/IPv6 CIDR matching, lookup limits, and loops."""

    def test_match_ip_ipv4_and_ipv6_cidrs(self):
        # IPv4 CIDRs
        rec_ipv4 = "v=spf1 ip4:192.168.1.0/24 ip4:10.0.0.5 -all"
        assert _evaluate_spf_record(rec_ipv4, "192.168.1.15", "example.com") == SPF_PASS
        assert _evaluate_spf_record(rec_ipv4, "192.168.2.15", "example.com") == SPF_FAIL
        assert _evaluate_spf_record(rec_ipv4, "10.0.0.5", "example.com") == SPF_PASS

        # IPv6 CIDRs
        rec_ipv6 = "v=spf1 ip6:2001:db8::/32 ip6:fe80::1/128 -all"
        assert _evaluate_spf_record(rec_ipv6, "2001:db8::1", "example.com") == SPF_PASS
        assert _evaluate_spf_record(rec_ipv6, "2001:db9::1", "example.com") == SPF_FAIL
        assert _evaluate_spf_record(rec_ipv6, "fe80::1", "example.com") == SPF_PASS

    def test_evaluate_spf_record_with_cidrs(self):
        rec = "v=spf1 ip4:192.168.1.0/24 ip6:2001:db8::/32 -all"
        assert _evaluate_spf_record(rec, "192.168.1.42", "example.com") == SPF_PASS
        assert _evaluate_spf_record(rec, "2001:db8::abcd", "example.com") == SPF_PASS
        assert _evaluate_spf_record(rec, "10.0.0.1", "example.com") == SPF_FAIL

    def test_spf_lookup_limit_enforcement_returns_permerror(self):
        """RFC 7208 Sec 4.6.4: SPF evaluation must abort with PermError after 10 DNS lookups."""
        lookup_counter = [10]  # Already reached 10 lookups

        # When evaluating an include that would trigger an 11th lookup
        rec = "v=spf1 include:overflow.example.com -all"
        res = _evaluate_spf_record(rec, "1.2.3.4", "example.com", lookup_count=lookup_counter)
        assert res == SPF_PERMERROR

    def test_spf_include_loop_detection(self):
        """Circular includes must be detected and return PermError."""
        visited = {"loop-a.com", "loop-b.com"}
        rec = "v=spf1 include:loop-a.com -all"
        res = _evaluate_spf_record(
            rec, "1.2.3.4", "loop-b.com",
            visited_domains=visited,
        )
        assert res == SPF_PERMERROR


# ── 5. MIME Parser Robustness & Nested .eml ───────────────────────────────────


class TestMIMEParserRobustness:
    """Test recursive MIME multipart handling and nested message/rfc822 attachments."""

    def test_nested_rfc822_extracted_as_eml_attachment(self):
        from email.message import EmailMessage

        outer_msg = EmailMessage()
        outer_msg["From"] = "outer-sender@victim.com"
        outer_msg["To"] = "soc@victim.com"
        outer_msg["Subject"] = "FW: Suspicious Phish"
        outer_msg["Date"] = "Sun, 06 Sep 2026 14:00:00 +0000"
        outer_msg["X-Custom-Header"] = "CustomValue123"
        outer_msg["X-Originating-IP"] = "[203.0.113.195]"
        outer_msg.set_content("Investigator: review the attached malicious email.")

        # Inner nested hostile email
        inner_msg = EmailMessage()
        inner_msg["From"] = "ceo@attacker-lookalike.com"
        inner_msg["To"] = "finance@victim.com"
        inner_msg["Subject"] = "URGENT WIRE TRANSFER"
        inner_msg.set_content("Please wire $50,000 immediately to offshore account.")

        # Attach inner email
        outer_msg.add_attachment(inner_msg, filename="suspicious_phish.eml")
        raw_eml = outer_msg.as_bytes()

        parsed = parse_email(raw_eml)

        # Outer metadata
        assert parsed.sender == "outer-sender@victim.com"
        assert "attached malicious email" in (parsed.body_text or "")

        # Nested email attachment must be captured with non-zero bytes
        assert len(parsed.attachments) == 1
        att = parsed.attachments[0]
        assert att.filename == "suspicious_phish.eml"
        assert att.content_type == "message/rfc822"
        assert att.size > 0
        assert b"URGENT WIRE TRANSFER" in att.content
        assert b"ceo@attacker-lookalike.com" in att.content

        # Headers preserved with order and custom headers
        h_names = [h.name for h in parsed.headers]
        assert "X-Custom-Header" in h_names
        assert "X-Originating-IP" in h_names

    def test_malformed_email_does_not_crash(self):
        # Truncated boundary and invalid control characters
        raw_malformed = (
            b"Content-Type: multipart/mixed; boundary=\"bound\"\r\n"
            b"--bound\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Incomplete email with unclosed boundary and \xff\xfe\xfd garbage."
        )
        parsed = parse_email(raw_malformed)
        assert parsed.raw_sha256 == hashlib.sha256(raw_malformed).hexdigest()
        assert parsed.raw_size == len(raw_malformed)


# ── 6. Evidence Chain and Audit Log Tampering Detection ────────────────────────


class TestEvidenceChainTamperDetection:
    """Test cryptographic verification of EvidenceChain and AuditLog records."""

    def test_evidence_chain_detects_row_tampering(self):
        db = _TestSession()
        try:
            # Create a valid parent email record
            email_row = Email(
                sha256="sha256-hash-01",
                filename="test.eml",
                size=100,
            )
            db.add(email_row)
            db.commit()
            email_id = email_row.id

            # Create a valid chain with 3 entries
            e1 = add_evidence_entry(db, email_id, "sha256-hash-01", "uploaded", "Initial upload")
            e2 = add_evidence_entry(db, email_id, "sha256-hash-01", "analyzed", "SPF/DKIM verified")
            e3 = add_evidence_entry(db, email_id, "sha256-hash-01", "exported", "Case exported to DFIR")
            db.commit()

            # Baseline integrity check must pass
            is_valid, errors = verify_chain_integrity(db, email_id=email_id)
            assert is_valid is True
            assert errors == []

            # Simulate malicious tampering with details in entry 2
            e2_row = db.query(EvidenceChain).filter(EvidenceChain.id == e2.id).first()
            e2_row.details = "Tampered details injected by attacker"
            db.commit()

            # Verification must fail and detect content_hash mismatch
            is_valid_tampered, errors_tampered = verify_chain_integrity(db, email_id=email_id)
            assert is_valid_tampered is False
            assert any("content_hash mismatch" in err for err in errors_tampered)

        finally:
            db.close()

    def test_audit_log_detects_record_tampering(self):
        db = _TestSession()
        try:
            # Create valid audit entries
            a1 = add_audit_entry(db, action="create", entity_type="email", entity_id=202, actor="analyst_1")
            a2 = add_audit_entry(db, action="update", entity_type="email", entity_id=202, actor="system", details="risk assessed")
            db.commit()

            # Baseline check passes
            is_valid, errors = verify_audit_log_integrity(db)
            assert is_valid is True
            assert errors == []

            # Tamper with actor in audit log
            a1_row = db.query(AuditLog).filter(AuditLog.id == a1.id).first()
            a1_row.actor = "malicious_actor"
            db.commit()

            # Verification must catch entry_hash mismatch
            is_valid_tampered, errors_tampered = verify_audit_log_integrity(db)
            assert is_valid_tampered is False
            assert any("entry_hash mismatch" in err for err in errors_tampered)

        finally:
            db.close()
