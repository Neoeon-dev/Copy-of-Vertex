"""Tests for SPF/DKIM/DMARC authentication analysis.

Uses mocked DNS responses so no external internet access is required.
"""
from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import dns.resolver
import dns.exception
import pytest

from app.forensics.spf_analyzer import (
    SPF_FAIL,
    SPF_NEUTRAL,
    SPF_NONE,
    SPF_NOT_CHECKED,
    SPF_PASS,
    SPF_PERMERROR,
    SPF_SOFTFAIL,
    SPF_TEMPERROR,
    SPFResult,
    _extract_return_path_domain,
    analyze_spf,
)
from app.forensics.dkim_analyzer import (
    DKIM_FAIL,
    DKIM_NONE,
    DKIM_NOT_CHECKED,
    DKIM_PASS,
    DKIM_PERMERROR,
    DKIMResult,
    analyze_dkim,
)
from app.forensics.dmarc_analyzer import (
    DMARC_FAIL,
    DMARC_NONE,
    DMARC_PASS,
    DMARC_TEMPERROR,
    DMARC_PERMERROR,
    DMARCResult,
    analyze_dmarc,
)
from tests.conftest import SAMPLE_EML, SAMPLE_EML_HEADERS_ONLY


def _make_mock_dns_answer(txt_value: str):
    """Create a mock DNS answer that yields a single TXT record."""
    mock_rdata = MagicMock()
    # dnspython returns TXT record strings as bytes tuples
    mock_rdata.strings = (txt_value.encode("utf-8"),)
    mock_answer = MagicMock()
    mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
    return mock_answer


# ── SPF Tests ────────────────────────────────────────────────────────


class TestSPFAnalyzer:

    def test_spf_pass(self):
        headers = {
            "return-path": "<sender@example.com>",
            "received": "from mail.example.com [192.168.1.100] by mx.target.com",
        }
        with patch(
            "app.forensics.spf_analyzer.dns.resolver.resolve",
            return_value=_make_mock_dns_answer("v=spf1 ip4:192.168.1.0/24 +all"),
        ):
            result = analyze_spf(headers, email_sender_domain="example.com")
        assert result.result == SPF_PASS
        assert result.domain == "example.com"
        assert result.connecting_ip == "192.168.1.100"

    def test_spf_fail(self):
        headers = {
            "return-path": "<sender@example.com>",
            "received": "from mail.evil.com [10.0.0.1] by mx.target.com",
        }
        with patch(
            "app.forensics.spf_analyzer.dns.resolver.resolve",
            return_value=_make_mock_dns_answer("v=spf1 ip4:192.168.1.0/24 -all"),
        ):
            result = analyze_spf(headers)
        assert result.result == SPF_FAIL
        assert result.connecting_ip == "10.0.0.1"

    def test_spf_softfail(self):
        headers = {
            "return-path": "<sender@example.com>",
            "received": "from mail.evil.com [10.0.0.1] by mx.target.com",
        }
        with patch(
            "app.forensics.spf_analyzer.dns.resolver.resolve",
            return_value=_make_mock_dns_answer("v=spf1 ip4:192.168.1.0/24 ~all"),
        ):
            result = analyze_spf(headers)
        assert result.result == SPF_SOFTFAIL

    def test_spf_none_no_record(self):
        """SPF NONE when domain has no SPF record (NXDOMAIN)."""
        headers = {
            "return-path": "<sender@example.com>",
            "received": "from mail.evil.com [10.0.0.1] by mx.target.com",
        }
        with patch(
            "app.forensics.spf_analyzer._lookup_spf_record",
            return_value=(None, "Domain does not exist (NXDOMAIN)"),
        ):
            result = analyze_spf(headers)
        assert result.result == SPF_NONE

    def test_spf_temperror_dns_timeout(self):
        headers = {
            "return-path": "<sender@example.com>",
            "received": "from mail.evil.com [10.0.0.1] by mx.target.com",
        }
        with patch(
            "app.forensics.spf_analyzer._lookup_spf_record",
            return_value=(None, "DNS query timed out"),
        ):
            result = analyze_spf(headers)
        assert result.result == SPF_TEMPERROR

    def test_spf_permerror(self):
        headers = {
            "return-path": "<sender@example.com>",
            "received": "from mail.evil.com [10.0.0.1] by mx.target.com",
        }
        with patch(
            "app.forensics.spf_analyzer._lookup_spf_record",
            return_value=(None, "DNS error: SERVFAIL"),
        ):
            result = analyze_spf(headers)
        assert result.result == SPF_PERMERROR

    def test_spf_not_checked_no_return_path(self):
        headers = {
            "received": "from mail.evil.com [10.0.0.1] by mx.target.com",
        }
        result = analyze_spf(headers)
        assert result.result == SPF_NOT_CHECKED

    def test_spf_not_checked_no_ip(self):
        headers = {
            "return-path": "<sender@example.com>",
        }
        result = analyze_spf(headers)
        assert result.result == SPF_NOT_CHECKED

    def test_spf_alignment_info(self):
        headers = {
            "return-path": "<sender@evil.com>",
            "received": "from mail.evil.com [10.0.0.1] by mx.target.com",
        }
        with patch(
            "app.forensics.spf_analyzer.dns.resolver.resolve",
            return_value=_make_mock_dns_answer("v=spf1 ip4:10.0.0.0/8 +all"),
        ):
            result = analyze_spf(headers, email_sender_domain="legit.com")
        assert result.result == SPF_PASS
        assert "differs from visible From domain" in result.details

    def test_spf_neutral(self):
        headers = {
            "return-path": "<sender@example.com>",
            "received": "from mail.evil.com [10.0.0.1] by mx.target.com",
        }
        with patch(
            "app.forensics.spf_analyzer.dns.resolver.resolve",
            return_value=_make_mock_dns_answer("v=spf1 ?all"),
        ):
            result = analyze_spf(headers)
        assert result.result == SPF_NEUTRAL

    def test_extract_return_path_domain(self):
        assert _extract_return_path_domain({"return-path": "<user@example.com>"}) == "example.com"
        assert _extract_return_path_domain({"return-path": "user@example.com"}) == "example.com"
        assert _extract_return_path_domain({}) is None
        assert _extract_return_path_domain({"return-path": ""}) is None


# ── DKIM Tests ───────────────────────────────────────────────────────


class TestDKIMAnalyzer:

    def test_dkim_none_no_signature(self):
        headers = {"from": "sender@example.com"}
        results = analyze_dkim(headers)
        assert len(results) == 1
        assert results[0].result == DKIM_NONE

    def test_dkim_pass(self):
        headers = {
            "dkim-signature": "v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to:subject;",
        }
        with patch("app.forensics.dkim_analyzer.dkim.verify", return_value=True):
            results = analyze_dkim(headers, raw_email_bytes=b"raw email")
        assert len(results) == 1
        assert results[0].result == DKIM_PASS
        assert results[0].domain == "example.com"
        assert results[0].selector == "selector1"

    def test_dkim_fail(self):
        headers = {
            "dkim-signature": "v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to;",
        }
        with patch("app.forensics.dkim_analyzer.dkim.verify", return_value=False):
            results = analyze_dkim(headers, raw_email_bytes=b"raw email")
        assert len(results) == 1
        assert results[0].result == DKIM_FAIL

    def test_dkim_permerror_without_raw_bytes_no_key(self):
        """DKIM PERMERROR when no raw bytes and key lookup fails."""
        headers = {
            "dkim-signature": "v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to;",
        }
        with patch(
            "app.forensics.dkim_analyzer._lookup_dkim_key",
            return_value=(None, "DKIM key not found"),
        ):
            results = analyze_dkim(headers, raw_email_bytes=None)
        assert len(results) == 1
        assert results[0].result == DKIM_PERMERROR

    def test_multiple_dkim_signatures(self):
        headers = {
            "dkim-signature": [
                "v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to;",
                "v=1; a=rsa-sha256; d=other.com; s=selector2; h=from:to;",
            ],
        }
        with patch("app.forensics.dkim_analyzer.dkim.verify", return_value=True):
            results = analyze_dkim(headers, raw_email_bytes=b"raw email")
        assert len(results) == 2
        assert results[0].domain == "example.com"
        assert results[1].domain == "other.com"

    def test_dkim_permerror_missing_fields(self):
        headers = {
            "dkim-signature": "v=1; a=rsa-sha256; h=from:to;",
        }
        results = analyze_dkim(headers)
        assert len(results) == 1
        assert results[0].result == DKIM_PERMERROR

    def test_dkim_alignment_info(self):
        """DKIM result includes alignment info when domain doesn't match."""
        headers = {
            "dkim-signature": "v=1; a=rsa-sha256; d=evil.com; s=selector1; h=from:to;",
        }
        with patch("app.forensics.dkim_analyzer.dkim.verify", return_value=True):
            results = analyze_dkim(
                headers,
                raw_email_bytes=b"raw email",
                email_sender_domain="legit.com",
            )
        assert results[0].result == DKIM_PASS
        # The alignment info should be present in the details
        assert "does not align" in results[0].details or results[0].domain == "evil.com"


# ── DMARC Tests ──────────────────────────────────────────────────────


class TestDMARCAnalyzer:

    def _mock_dmarc_policy(self, policy_str: str = "v=DMARC1; p=reject;"):
        mock_rdata = MagicMock()
        mock_rdata.strings = (policy_str.encode("utf-8"),)
        mock = MagicMock()
        mock.__iter__ = MagicMock(return_value=iter([mock_rdata]))
        return mock

    def test_dmarc_pass_spf_aligned(self):
        with patch(
            "app.forensics.dmarc_analyzer.dns.resolver.resolve",
            return_value=self._mock_dmarc_policy("v=DMARC1; p=reject; sp=reject;"),
        ):
            result = analyze_dmarc(
                email_sender_domain="example.com",
                spf_result="PASS",
                spf_envelope_domain="example.com",
            )
        assert result.result == DMARC_PASS
        assert result.policy == "reject"
        assert result.spf_aligned is True

    def test_dmarc_pass_dkim_aligned(self):
        with patch(
            "app.forensics.dmarc_analyzer.dns.resolver.resolve",
            return_value=self._mock_dmarc_policy("v=DMARC1; p=quarantine;"),
        ):
            result = analyze_dmarc(
                email_sender_domain="example.com",
                dkim_result="PASS",
                dkim_domain="example.com",
            )
        assert result.result == DMARC_PASS
        assert result.policy == "quarantine"
        assert result.dkim_aligned is True

    def test_dmarc_fail_no_alignment(self):
        with patch(
            "app.forensics.dmarc_analyzer.dns.resolver.resolve",
            return_value=self._mock_dmarc_policy("v=DMARC1; p=reject;"),
        ):
            result = analyze_dmarc(
                email_sender_domain="example.com",
                spf_result="PASS",
                spf_envelope_domain="evil.com",
                dkim_result="PASS",
                dkim_domain="evil.com",
            )
        assert result.result == DMARC_FAIL
        assert result.spf_aligned is False
        assert result.dkim_aligned is False

    def test_dmarc_fail_spf_pass_not_aligned(self):
        with patch(
            "app.forensics.dmarc_analyzer.dns.resolver.resolve",
            return_value=self._mock_dmarc_policy("v=DMARC1; p=reject;"),
        ):
            result = analyze_dmarc(
                email_sender_domain="legit.com",
                spf_result="PASS",
                spf_envelope_domain="other.com",
            )
        assert result.result == DMARC_FAIL

    def test_dmarc_none_no_policy(self):
        with patch(
            "app.forensics.dmarc_analyzer._lookup_dmarc_policy",
            return_value=(None, "No DMARC record (NXDOMAIN) for _dmarc.example.com"),
        ):
            result = analyze_dmarc(email_sender_domain="example.com")
        assert result.result == DMARC_NONE

    def test_dmarc_temperror_dns_failure(self):
        with patch(
            "app.forensics.dmarc_analyzer._lookup_dmarc_policy",
            return_value=(None, "DNS query timed out for _dmarc.example.com"),
        ):
            result = analyze_dmarc(email_sender_domain="example.com")
        assert result.result == DMARC_TEMPERROR

    def test_dmarc_not_checked_no_domain(self):
        result = analyze_dmarc(email_sender_domain=None)
        assert result.result == "NOT_CHECKED"

    def test_dmarc_fail_spf_failed_but_aligned(self):
        with patch(
            "app.forensics.dmarc_analyzer.dns.resolver.resolve",
            return_value=self._mock_dmarc_policy("v=DMARC1; p=reject;"),
        ):
            result = analyze_dmarc(
                email_sender_domain="example.com",
                spf_result="FAIL",
                spf_envelope_domain="example.com",
            )
        assert result.result == DMARC_FAIL
        assert result.spf_aligned is True  # aligned but SPF failed


# ── Integration Tests ────────────────────────────────────────────────


class TestAuthenticationEndpoint:

    def _upload_email(self, client, eml_bytes=SAMPLE_EML) -> int:
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )
        assert resp.status_code == 201
        return resp.json()["id"]

    def test_authentication_endpoint_works(self, client):
        eid = self._upload_email(client)
        resp = client.post(f"/api/emails/{eid}/authentication")
        assert resp.status_code == 200
        data = resp.json()
        assert "spf" in data
        assert "dkim" in data
        assert "dmarc" in data
        assert "all_results" in data
        assert len(data["all_results"]) >= 3

    def test_get_authentication(self, client):
        eid = self._upload_email(client)
        client.post(f"/api/emails/{eid}/authentication")
        resp = client.get(f"/api/emails/{eid}/authentication")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["all_results"]) >= 3

    def test_authentication_with_auth_results_header(self, client):
        eid = self._upload_email(client, SAMPLE_EML_HEADERS_ONLY)
        resp = client.post(f"/api/emails/{eid}/authentication")
        assert resp.status_code == 200
        data = resp.json()
        assert data["spf"] is not None
        assert data["dkim"] is not None
        assert data["dmarc"] is not None

    def test_authentication_nonexistent_email(self, client):
        resp = client.post("/api/emails/99999/authentication")
        assert resp.status_code == 404

    def test_authentication_idempotent(self, client):
        eid = self._upload_email(client)
        resp1 = client.post(f"/api/emails/{eid}/authentication")
        resp2 = client.post(f"/api/emails/{eid}/authentication")
        assert resp1.json()["spf"]["result"] == resp2.json()["spf"]["result"]
