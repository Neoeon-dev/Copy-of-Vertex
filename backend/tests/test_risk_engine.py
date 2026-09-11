"""Tests for the Risk Engine.

Verifies:
- Weight validation and normalization
- Individual category scorers
- Full assessment with all signals
- Assessment with partial signals
- Risk level classification
- Explainable breakdown
- Edge cases (empty inputs, all pass, all fail)
- API endpoint integration
"""
from __future__ import annotations

import io

from app.forensics.risk_engine import RiskEngine, RiskLevel, _score_to_level, get_risk_engine
from tests.conftest import SAMPLE_EML, SAMPLE_EML_HEADERS_ONLY


class TestRiskLevel:
    """Risk level classification tests."""

    def test_low(self):
        assert _score_to_level(10) == RiskLevel.LOW
        assert _score_to_level(0) == RiskLevel.LOW
        assert _score_to_level(24.9) == RiskLevel.LOW

    def test_medium(self):
        assert _score_to_level(25) == RiskLevel.MEDIUM
        assert _score_to_level(40) == RiskLevel.MEDIUM
        assert _score_to_level(49.9) == RiskLevel.MEDIUM

    def test_high(self):
        assert _score_to_level(50) == RiskLevel.HIGH
        assert _score_to_level(65) == RiskLevel.HIGH
        assert _score_to_level(74.9) == RiskLevel.HIGH

    def test_critical(self):
        assert _score_to_level(75) == RiskLevel.CRITICAL
        assert _score_to_level(90) == RiskLevel.CRITICAL
        assert _score_to_level(100) == RiskLevel.CRITICAL


class TestRiskEngineUnit:
    """Unit tests for individual category scorers."""

    def test_engine_initializes(self):
        engine = RiskEngine()
        assert abs(sum(engine.weights.values()) - 1.0) < 0.01

    def test_custom_weights(self):
        engine = RiskEngine(weights={"ml_classification": 0.5, "authentication": 0.5})
        assert engine.weights["ml_classification"] == 0.5

    def test_weight_normalization(self):
        engine = RiskEngine(weights={"a": 2.0, "b": 3.0})
        assert abs(sum(engine.weights.values()) - 1.0) < 0.01

    def test_empty_assessment(self):
        engine = RiskEngine()
        result = engine.assess()
        assert result.score == 0.0
        assert result.level == RiskLevel.LOW.value
        # Empty assessment has no ML result signal
        assert all(c.contribution == 0 for c in result.contributions)

    def test_ml_phishing_high_risk(self):
        engine = RiskEngine()
        result = engine.assess(
            ml_label="phishing",
            ml_confidence=0.9,
            ml_risk_score=0.8,
            ml_signals={"urgency_language": 0.75, "credential_request": 0.6},
        )
        # ML phishing with 0.9 confidence: 80 * 0.9 = 72 category score * 0.25 weight = 18
        # Plus signal contributions
        assert result.score > 15
        ml_contribs = [c for c in result.contributions if c.category == "ml_classification"]
        assert len(ml_contribs) >= 1

    def test_ml_legitimate_low_risk(self):
        engine = RiskEngine()
        result = engine.assess(
            ml_label="legitimate",
            ml_confidence=0.85,
            ml_risk_score=0.05,
        )
        assert result.score < 30

    def test_auth_fail_increases_risk(self):
        engine = RiskEngine()
        result_pass = engine.assess(spf_result="PASS", dkim_result="PASS", dmarc_result="PASS")
        result_fail = engine.assess(spf_result="FAIL", dkim_result="FAIL", dmarc_result="FAIL")
        assert result_fail.score > result_pass.score

    def test_auth_none_moderate_risk(self):
        engine = RiskEngine()
        result = engine.assess(spf_result="NONE", dkim_result="NONE")
        assert result.score > 0

    def test_identity_mismatch(self):
        engine = RiskEngine()
        result = engine.assess(
            sender="attacker@evil.com",
            sender_name="PayPal Security Team",
            reply_to="different@other.com",
        )
        identity_contribs = [c for c in result.contributions if c.category == "identity_mismatch"]
        assert len(identity_contribs) >= 1

    def test_lookalike_domain(self):
        engine = RiskEngine()
        result = engine.assess(
            domain_analyses=[{
                "domain": "paypa1.com",
                "risk_score": 0.5,
                "has_homoglyphs": False,
                "suspicious_tld": False,
                "lookalikes": [{"brand_domain": "paypal.com", "distance": 1}],
                "has_punycode": False,
            }]
        )
        assert result.score > 0
        domain_contribs = [c for c in result.contributions if c.category == "domain_intelligence"]
        assert len(domain_contribs) >= 1

    def test_homoglyph_domain(self):
        engine = RiskEngine()
        result = engine.assess(
            domain_analyses=[{
                "domain": "ex\u0430mple.com",
                "risk_score": 0.4,
                "has_homoglyphs": True,
                "suspicious_tld": False,
                "lookalikes": [],
                "has_punycode": False,
            }]
        )
        assert result.score > 0

    def test_ip_url(self):
        engine = RiskEngine()
        result = engine.assess(
            url_analyses=[{
                "url": "http://192.168.1.1/steal",
                "is_ip_url": True,
                "is_shortener": False,
                "suspicious_path": False,
                "has_punycode": False,
            }]
        )
        assert result.score > 0

    def test_double_extension_attachment(self):
        engine = RiskEngine()
        result = engine.assess(
            attachment_analyses=[{
                "filename": "invoice.pdf.exe",
                "is_dangerous_extension": True,
                "has_double_extension": True,
                "mime_mismatch": False,
            }]
        )
        # Double ext: 85 * 0.1 weight = 8.5
        assert result.score > 5

    def test_header_anomaly(self):
        engine = RiskEngine()
        result = engine.assess(
            received_anomalies=["non_monotonic_timestamps"],
            total_hops=3,
        )
        assert result.score > 0
        header_contribs = [c for c in result.contributions if c.category == "header_anomalies"]
        assert len(header_contribs) >= 1

    def test_full_assessment_all_signals(self):
        """Test with signals from every category simultaneously."""
        engine = RiskEngine()
        result = engine.assess(
            ml_label="phishing",
            ml_confidence=0.85,
            ml_risk_score=0.75,
            ml_signals={"urgency_language": 0.75, "credential_request": 0.6},
            ml_signal_details={"urgency_language": "Found: urgent, immediately", "credential_request": "Found: password"},
            spf_result="FAIL",
            dkim_result="FAIL",
            dmarc_result="FAIL",
            sender="attacker@evil.com",
            sender_name="PayPal Security",
            reply_to="different@phish.com",
            domain_analyses=[{
                "domain": "paypa1.com",
                "risk_score": 0.5,
                "has_homoglyphs": False,
                "suspicious_tld": True,
                "lookalikes": [{"brand_domain": "paypal.com", "distance": 1}],
                "has_punycode": False,
            }],
            url_analyses=[{
                "url": "http://192.168.1.1/steal",
                "is_ip_url": True,
                "is_shortener": False,
                "suspicious_path": False,
                "has_punycode": False,
            }],
            attachment_analyses=[{
                "filename": "invoice.pdf.exe",
                "is_dangerous_extension": True,
                "has_double_extension": True,
                "mime_mismatch": False,
            }],
            received_anomalies=["non_monotonic_timestamps"],
            total_hops=5,
            ip_analyses=[{"ip": "192.168.1.1", "warnings": ["private", "no geo", "no asn"]}],
        )
        assert result.score > 40
        assert result.level in (RiskLevel.MEDIUM.value, RiskLevel.HIGH.value, RiskLevel.CRITICAL.value)
        assert len(result.contributions) > 5
        assert len(result.limitations) > 0
        assert "Risk level" in result.summary

    def test_category_scores_are_independent(self):
        """Each category should score independently."""
        engine = RiskEngine()
        result = engine.assess(
            ml_label="phishing",
            ml_confidence=0.9,
            ml_risk_score=0.8,
            spf_result="FAIL",
            domain_analyses=[{
                "domain": "test.xyz",
                "risk_score": 0.3,
                "has_homoglyphs": False,
                "suspicious_tld": True,
                "lookalikes": [],
                "has_punycode": False,
            }],
        )
        assert "ml_classification" in result.category_scores
        assert "authentication" in result.category_scores
        assert "domain_intelligence" in result.category_scores
        assert result.category_scores["ml_classification"] > 0
        assert result.category_scores["authentication"] > 0
        assert result.category_scores["domain_intelligence"] > 0

    def test_contributions_have_descriptions(self):
        engine = RiskEngine()
        result = engine.assess(
            ml_label="phishing",
            ml_confidence=0.8,
            ml_risk_score=0.7,
        )
        for contrib in result.contributions:
            assert contrib.description
            assert contrib.category
            assert contrib.signal
            assert 0 <= contrib.raw_value <= 1


class TestRiskEndpoint:
    """Integration tests for POST /api/emails/{id}/risk."""

    def _upload_email(self, client) -> int:
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML_HEADERS_ONLY), "message/rfc822")},
        )
        assert resp.status_code == 201
        return resp.json()["id"]

    def test_risk_endpoint_works(self, client):
        eid = self._upload_email(client)
        resp = client.post(f"/api/emails/{eid}/risk")
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_id"] == eid
        assert "score" in data
        assert "level" in data
        assert "category_scores" in data
        assert "contributions" in data
        assert "summary" in data
        assert "limitations" in data
        assert 0 <= data["score"] <= 100
        assert data["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_get_risk(self, client):
        eid = self._upload_email(client)
        resp = client.get(f"/api/emails/{eid}/risk")
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] >= 0

    def test_risk_nonexistent(self, client):
        resp = client.post("/api/emails/99999/risk")
        assert resp.status_code == 404

    def test_risk_simple_email(self, client):
        """A simple email should have low risk."""
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
        )
        eid = resp.json()["id"]
        resp = client.get(f"/api/emails/{eid}/risk")
        assert resp.status_code == 200
        data = resp.json()
        # Should be low or medium (no auth failures, no suspicious content)
        assert data["level"] in ("LOW", "MEDIUM")

    def test_risk_phishing_email_higher(self, client):
        """Email with auth failures and suspicious headers should score higher."""
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("phish.eml", io.BytesIO(SAMPLE_EML_HEADERS_ONLY), "message/rfc822")},
        )
        eid = resp.json()["id"]
        resp = client.get(f"/api/emails/{eid}/risk")
        data = resp.json()
        # Should be higher than a clean email due to auth failures + identity mismatch
        assert data["score"] > 10
