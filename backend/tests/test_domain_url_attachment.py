"""Tests for domain intelligence, URL analysis, attachment analysis, and full analysis."""
from __future__ import annotations

import io

from app.forensics.domain_intel import analyze_domain, extract_domains_from_headers, _levenshtein
from app.forensics.url_analyzer import analyze_url, extract_urls_from_email
from app.forensics.attachment_analyzer import analyze_attachment
from tests.conftest import SAMPLE_EML, SAMPLE_EML_MULTIPART, SAMPLE_EML_HEADERS_ONLY


# ── Domain Intelligence Tests ────────────────────────────────────────


class TestDomainIntel:

    def test_levenshtein_distance(self):
        assert _levenshtein("paypal.com", "paypal.com") == 0
        assert _levenshtein("paypal.com", "paypa1.com") == 1
        assert _levenshtein("paypal.com", "paypai.com") == 1
        assert _levenshtein("paypal.com", "paypa1-security.com") > 1

    def test_lookalike_detection(self):
        result = analyze_domain("paypa1.com")
        assert len(result.lookalikes) > 0
        assert result.lookalikes[0].brand_domain == "paypal.com"
        assert result.lookalikes[0].distance == 1

    def test_suspicious_tld(self):
        result = analyze_domain("phishing.xyz")
        assert result.suspicious_tld is True
        assert any("Suspicious TLD" in w for w in result.warnings)

    def test_homoglyph_detection(self):
        # Cyrillic 'a' (U+0430) looks like Latin 'a'
        result = analyze_domain("ex\u0430mple.com")
        assert result.has_homoglyphs is True
        assert any("homoglyph" in w.lower() for w in result.warnings)

    def test_exact_match_not_flagged(self):
        result = analyze_domain("paypal.com")
        assert len(result.lookalikes) == 0
        assert result.risk_score == 0.0

    def test_risk_score_calculation(self):
        # paypai.com is 1-edit from paypal.com
        result = analyze_domain("paypai.com")
        assert result.risk_score > 0
        assert len(result.lookalikes) > 0

    def test_extract_domains_from_headers(self):
        headers = {
            "from": "sender@example.com",
            "reply-to": "reply@evil.com",
        }
        domains = extract_domains_from_headers(headers)
        assert "example.com" in domains
        assert "evil.com" in domains


# ── URL Analysis Tests ───────────────────────────────────────────────


class TestURLAnalysis:

    def test_normal_url(self):
        result = analyze_url("https://www.example.com/page")
        assert result.is_ip_url is False
        assert result.is_shortener is False
        assert result.risk_score == 0.0

    def test_ip_url(self):
        result = analyze_url("http://192.168.1.1/login")
        assert result.is_ip_url is True
        assert any("IP address" in w for w in result.warnings)
        assert result.risk_score > 0

    def test_shortener(self):
        result = analyze_url("https://bit.ly/abc123")
        assert result.is_shortener is True

    def test_suspicious_tld(self):
        result = analyze_url("https://login.phishing.xyz/steal")
        assert result.suspicious_tld is True

    def test_excessive_subdomains(self):
        result = analyze_url("https://a.b.c.d.e.example.com/path")
        assert result.excessive_subdomains is True

    def test_punycode(self):
        result = analyze_url("https://xn--exmple-cua.com/path")
        assert result.has_punycode is True

    def test_suspicious_path(self):
        result = analyze_url("https://example.com/login")
        assert result.suspicious_path is True

    def test_extract_from_text(self):
        text = "Visit https://example.com and http://evil.com for more info."
        urls = extract_urls_from_email(body_text=text)
        assert "https://example.com" in urls
        assert "http://evil.com" in urls

    def test_extract_from_html(self):
        html = '<a href="https://example.com">Link</a>'
        urls = extract_urls_from_email(body_html=html)
        assert "https://example.com" in urls


# ── Attachment Analysis Tests ────────────────────────────────────────


class TestAttachmentAnalysis:

    def test_safe_pdf(self):
        result = analyze_attachment(
            filename="document.pdf",
            content_type="application/pdf",
            size=1024,
            sha256="abc123",
        )
        assert result.is_dangerous_extension is False
        assert result.risk_score == 0.0

    def test_dangerous_exe(self):
        result = analyze_attachment(
            filename="malware.exe",
            content_type="application/x-msdownload",
            size=51200,
            sha256="def456",
        )
        assert result.is_dangerous_extension is True
        assert result.risk_score > 0.4

    def test_double_extension(self):
        result = analyze_attachment(
            filename="invoice.pdf.exe",
            content_type="application/x-msdownload",
            size=51200,
            sha256="ghi789",
        )
        assert result.has_double_extension is True
        assert result.has_suspicious_extension is True

    def test_archive(self):
        result = analyze_attachment(
            filename="files.zip",
            content_type="application/zip",
            size=2048,
            sha256="jkl012",
        )
        assert result.is_archive is True

    def test_empty_attachment(self):
        result = analyze_attachment(
            filename="empty.txt",
            content_type="text/plain",
            size=0,
            sha256="mno345",
        )
        assert any("Empty" in w for w in result.warnings)

    def test_large_attachment(self):
        result = analyze_attachment(
            filename="big.bin",
            content_type="application/octet-stream",
            size=20 * 1024 * 1024,  # 20MB
            sha256="pqr678",
        )
        assert any("Large" in w for w in result.warnings)


# ── Full Analysis Endpoint Tests ─────────────────────────────────────


class TestFullAnalysisEndpoint:

    def _upload_email(self, client, eml=SAMPLE_EML) -> int:
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(eml), "message/rfc822")},
        )
        assert resp.status_code == 201
        return resp.json()["id"]

    def test_full_analysis_works(self, client):
        eid = self._upload_email(client, SAMPLE_EML_HEADERS_ONLY)
        resp = client.post(f"/api/emails/{eid}/analyze-full")
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_id"] == eid
        assert data["spf"] is not None
        assert data["dkim"] is not None
        assert data["dmarc"] is not None
        assert "ip_analysis" in data
        assert "domain_analysis" in data
        assert "urls" in data
        assert "attachment_analysis" in data
        assert "overall_risk_score" in data

    def test_full_analysis_with_attachments(self, client):
        eid = self._upload_email(client, SAMPLE_EML_MULTIPART)
        resp = client.post(f"/api/emails/{eid}/analyze-full")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["attachment_analysis"]) == 1
        assert data["attachment_analysis"][0]["filename"] == "invoice.pdf"

    def test_full_analysis_nonexistent(self, client):
        resp = client.post("/api/emails/99999/analyze-full")
        assert resp.status_code == 404

    def test_get_full_analysis(self, client):
        eid = self._upload_email(client, SAMPLE_EML_HEADERS_ONLY)
        resp = client.get(f"/api/emails/{eid}/analyze-full")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_hops"] == 2
