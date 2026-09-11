"""
Phase D5 Test Suite — Canonical Forensic Risk Engine & Evidence-Aware Decision Layer.
Tests:
- Pure unit tests of CanonicalRiskEngine, RiskFactorRegistry, calculate_tvd, shannon_entropy, score_to_severity
- 30 adversarial & edge cases ensuring mathematical determinism, bounded scores,
  separation of threat probability from forensic risk, and 'missing != failed' invariant.
"""
from __future__ import annotations

import json
import math
import pytest

from app.engine.schemas import (
    RiskLevel,
    score_to_severity,
    EvidenceState,
    RiskFactorCategory,
    EvidenceProvenance,
    RiskFactor,
    RiskAssessment,
)
from app.engine.registry import (
    RiskFactorRegistry,
    CATEGORY_CAPS,
    FactorDefinition,
    get_default_registry,
)
from app.engine.risk_engine import (
    CanonicalRiskEngine,
    get_canonical_risk_engine,
    calculate_tvd,
    shannon_entropy,
    ENGINE_VERSION,
)
from app.ml.fusion.schemas import FusionPrediction, EvidenceQuality


# ── 1. Pure Unit Tests: Math & Utility Functions ──────────────────────

class TestMathAndUtilityFunctions:
    """Verifies mathematical correctness of metrics used by the decision layer."""

    def test_calculate_tvd_identical_distributions(self):
        p1 = {"legitimate": 0.7, "spam": 0.2, "phishing": 0.1}
        p2 = {"legitimate": 0.7, "spam": 0.2, "phishing": 0.1}
        assert calculate_tvd(p1, p2) == 0.0

    def test_calculate_tvd_orthogonal_distributions(self):
        p1 = {"legitimate": 1.0, "spam": 0.0, "phishing": 0.0}
        p2 = {"legitimate": 0.0, "spam": 0.0, "phishing": 1.0}
        assert calculate_tvd(p1, p2) == 1.0

    def test_calculate_tvd_partial_overlap(self):
        p1 = {"legitimate": 0.5, "spam": 0.5, "phishing": 0.0}
        p2 = {"legitimate": 0.0, "spam": 0.5, "phishing": 0.5}
        # 0.5 * (|0.5-0| + |0.5-0.5| + |0-0.5|) = 0.5 * (0.5 + 0 + 0.5) = 0.5
        assert abs(calculate_tvd(p1, p2) - 0.5) < 1e-6

    def test_shannon_entropy_empty_or_single_char(self):
        assert shannon_entropy("") == 0.0
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_shannon_entropy_random_domain(self):
        low_ent = shannon_entropy("google.com")
        high_ent = shannon_entropy("x7k9mq2z1p8w.xyz")
        assert high_ent > low_ent
        assert high_ent > 3.0

    @pytest.mark.parametrize(
        "score,expected_severity",
        [
            (-10.0, RiskLevel.LOW),
            (0.0, RiskLevel.LOW),
            (15.5, RiskLevel.LOW),
            (24.99, RiskLevel.LOW),
            (25.0, RiskLevel.MEDIUM),
            (35.0, RiskLevel.MEDIUM),
            (49.99, RiskLevel.MEDIUM),
            (50.0, RiskLevel.HIGH),
            (60.0, RiskLevel.HIGH),
            (74.99, RiskLevel.HIGH),
            (75.0, RiskLevel.CRITICAL),
            (90.0, RiskLevel.CRITICAL),
            (100.0, RiskLevel.CRITICAL),
            (150.0, RiskLevel.CRITICAL),
        ],
    )
    def test_score_to_severity_thresholds(self, score, expected_severity):
        assert score_to_severity(score) == expected_severity


# ── 2. Factor Registry Tests ──────────────────────────────────────────

class TestRiskFactorRegistry:
    """Verifies that the factor registry is loaded, complete, and enforces category caps."""

    def test_registry_contains_standard_factors(self):
        all_factors = RiskFactorRegistry.list_all()
        factor_ids = [f.factor_id for f in all_factors]
        assert len(all_factors) >= 25
        assert "AUTH_SPF_FAIL" in factor_ids
        assert "AUTH_DKIM_FAIL" in factor_ids
        assert "AUTH_DMARC_FAIL" in factor_ids
        assert "IDENTITY_DISPLAY_NAME_MISMATCH" in factor_ids
        assert "DOMAIN_LOOKALIKE" in factor_ids
        assert "URL_IP_BASED" in factor_ids
        assert "ATT_DOUBLE_EXTENSION" in factor_ids
        assert "BEC_CREDENTIAL_REQUEST" in factor_ids

    def test_category_caps_defined_and_bounded(self):
        caps = CATEGORY_CAPS
        assert caps["MODEL"] == 35.0
        assert caps["AUTHENTICATION"] == 20.0
        assert caps["IDENTITY"] == 15.0
        assert caps["DOMAIN"] == 15.0
        assert caps["URL"] == 15.0
        assert caps["ATTACHMENT"] == 15.0
        assert caps["INFRASTRUCTURE_RELAY"] == 10.0
        assert caps["CONTENT_BEC"] == 15.0
        assert caps["EVIDENCE"] == 10.0
        assert sum(caps.values()) >= 100.0

    def test_get_by_category(self):
        auth_factors = RiskFactorRegistry.list_by_category("AUTHENTICATION")
        assert len(auth_factors) >= 4
        assert any(f.factor_id == "AUTH_SPF_FAIL" for f in auth_factors)
        assert any(f.factor_id == "AUTH_ALL_PASS" for f in auth_factors)


# ── 3. 30 Adversarial & Edge Cases ───────────────────────────────────

class TestPhaseD5AdversarialAndEdgeCases:
    """
    Comprehensive suite of 30 edge, adversarial, and forensic operational scenarios.
    """

    @pytest.fixture
    def engine(self):
        return CanonicalRiskEngine()

    # Case 1: Clean Legitimate Email
    def test_01_clean_legitimate_email(self, engine):
        res = engine.assess(
            fused_probabilities={"legitimate": 0.98, "spam": 0.01, "phishing": 0.01},
            ml_label="legitimate",
            ml_confidence=0.98,
            spf_result="PASS",
            dkim_result="PASS",
            dmarc_result="PASS",
            sender="billing@stripe.com",
            sender_name="Stripe Billing",
            domain_analyses=[{"domain": "stripe.com", "risk_score": 0.0}],
            subject="Your monthly Stripe receipt",
            body="Thank you for your business. Here is your summary for August.",
        )
        assert res.risk_score < 25.0
        assert res.severity == RiskLevel.LOW.value
        assert res.predicted_threat_label == "legitimate"
        assert res.confidence > 0.85
        assert res.uncertainty < 0.15
        assert any(f.factor_id == "AUTH_ALL_PASS" for f in res.risk_factors)

    # Case 2: Phishing Content with Perfect Passing Auth (Auth Whitewashing Attempt)
    def test_02_phishing_whitewashed_with_perfect_auth(self, engine):
        res = engine.assess(
            fused_probabilities={"legitimate": 0.02, "spam": 0.03, "phishing": 0.95},
            ml_label="phishing",
            ml_confidence=0.95,
            spf_result="PASS",
            dkim_result="PASS",
            dmarc_result="PASS",
            sender="alerts@compromised-corp.com",
            sender_name="Microsoft 365 Support",
            subject="Urgent: Your account is suspended, verify password immediately",
            body="Click here to login and confirm your password before termination.",
        )
        # Auth passed, but ML + Identity spoof + BEC content must NOT allow this to be LOW
        assert res.risk_score >= 50.0
        assert res.severity in (RiskLevel.HIGH.value, RiskLevel.CRITICAL.value)
        assert res.predicted_threat_label == "phishing"

    # Case 3: Phishing Content with Hard Auth Failures
    def test_03_phishing_with_hard_auth_failures(self, engine):
        res = engine.assess(
            fused_probabilities={"legitimate": 0.01, "spam": 0.02, "phishing": 0.97},
            ml_label="phishing",
            ml_confidence=0.97,
            spf_result="FAIL",
            dkim_result="FAIL",
            dmarc_result="FAIL",
            sender="attacker@fake-paypal.com",
            sender_name="PayPal Verification",
            url_analyses=[{"url": "http://192.168.1.50/login", "is_ip_url": True, "risk_score": 0.9}],
            subject="Account Locked - Action Required",
            body="Immediate action required. Verify your credentials.",
        )
        assert res.risk_score >= 75.0
        assert res.severity == RiskLevel.CRITICAL.value
        assert any(f.factor_id == "AUTH_SPF_FAIL" for f in res.risk_factors)
        assert any(f.factor_id == "AUTH_DMARC_FAIL" for f in res.risk_factors)

    # Case 4: Missing Authentication (Missing != Failed Invariant)
    def test_04_missing_auth_headers_no_penalty(self, engine):
        # Email has no SPF/DKIM/DMARC headers recorded (internal or stripped relay)
        res_missing = engine.assess(
            fused_probabilities={"legitimate": 0.85, "spam": 0.10, "phishing": 0.05},
            ml_label="legitimate",
            ml_confidence=0.85,
            spf_result=None,
            dkim_result=None,
            dmarc_result=None,
            subject="Team meeting notes",
            body="Here are the notes from our sync.",
        )
        # Verified failing email for comparison
        res_failed = engine.assess(
            fused_probabilities={"legitimate": 0.85, "spam": 0.10, "phishing": 0.05},
            ml_label="legitimate",
            ml_confidence=0.85,
            spf_result="FAIL",
            dkim_result="FAIL",
            dmarc_result="FAIL",
            subject="Team meeting notes",
            body="Here are the notes from our sync.",
        )
        # Missing auth must NOT be penalized like failed auth!
        assert res_missing.risk_score < res_failed.risk_score
        assert res_missing.category_scores["AUTHENTICATION"] == 0.0
        # But missing auth should lower evidence availability and confidence
        assert res_missing.confidence <= res_failed.confidence + 0.15

    # Case 5: Short Text Email (< 10 words)
    def test_05_short_text_elevates_uncertainty(self, engine):
        res = engine.assess(
            fused_probabilities={"legitimate": 0.33, "spam": 0.33, "phishing": 0.34},
            subject="Hi",
            body="Please call me.",
        )
        assert res.evidence_quality.body_chars < 50
        assert res.uncertainty > 0.30
        assert res.evidence_quality.tier in ("DEGRADED", "LOW", "MEDIUM")

    # Case 6: Empty Subject and Body
    def test_06_empty_subject_and_body_graceful_fallback(self, engine):
        res = engine.assess(
            subject="",
            body="",
            spf_result="PASS",
            dkim_result="PASS",
        )
        assert 0.0 <= res.risk_score <= 100.0
        assert res.evidence_quality.body_chars == 0
        assert res.uncertainty > 0.25

    # Case 7: Missing Tabular D2 Model Predictions
    def test_07_missing_d2_tabular_model(self, engine):
        res = engine.assess(
            d2_probabilities=None,
            d3_probabilities={"legitimate": 0.05, "spam": 0.10, "phishing": 0.85},
            subject="Urgent Security Alert",
            body="Your credentials have been compromised.",
        )
        assert res.predicted_threat_label == "phishing"
        assert res.model_evidence.d2_available is False
        assert res.model_evidence.d3_available is True
        assert res.model_evidence.disagreement_tvd == 0.0

    # Case 8: Missing Semantic Text D3 Model Predictions
    def test_08_missing_d3_semantic_model(self, engine):
        res = engine.assess(
            d2_probabilities={"legitimate": 0.10, "spam": 0.10, "phishing": 0.80},
            d3_probabilities=None,
            features={"auth_spf_fail": 1.0, "url_count": 3.0},
        )
        assert res.predicted_threat_label == "phishing"
        assert res.model_evidence.d2_available is True
        assert res.model_evidence.d3_available is False

    # Case 9: Both D2 and D3 Missing (Forensic Rules Only)
    def test_09_both_models_missing_pure_forensic_fallback(self, engine):
        res = engine.assess(
            d2_probabilities=None,
            d3_probabilities=None,
            fused_probabilities=None,
            spf_result="FAIL",
            dmarc_result="FAIL",
            url_analyses=[{"url": "http://evil-site.xyz/steal", "is_ip_url": False, "risk_score": 0.8}],
            attachment_analyses=[{"filename": "payload.exe", "is_dangerous_extension": True}],
        )
        assert res.risk_score >= 40.0
        assert res.model_evidence.d2_available is False
        assert res.model_evidence.d3_available is False
        # Missing both models penalizes confidence
        assert res.confidence < 0.80
        assert any(f.factor_id == "AUTH_SPF_FAIL" for f in res.risk_factors)
        assert any(f.factor_id == "ATT_DANGEROUS_EXTENSION" for f in res.risk_factors)

    # Case 10: Extreme Modality Disagreement (D2 legit vs D3 phish)
    def test_10_extreme_modality_disagreement(self, engine):
        d2 = {"legitimate": 0.95, "spam": 0.03, "phishing": 0.02}
        d3 = {"legitimate": 0.02, "spam": 0.03, "phishing": 0.95}
        res = engine.assess(
            d2_probabilities=d2,
            d3_probabilities=d3,
            subject="Invoice Notification",
            body="Review attached wire instructions.",
        )
        assert res.model_evidence.disagreement_tvd > 0.80
        # Disagreement raises uncertainty
        assert res.uncertainty >= 0.25
        assert "disagreement" in res.explanation.lower() or "tvd" in res.explanation.lower()

    # Case 11: Invalid / Unnormalized Probability Distribution
    def test_11_invalid_unnormalized_probabilities(self, engine):
        # Probabilities summing to 5.0 instead of 1.0
        res = engine.assess(
            fused_probabilities={"legitimate": 2.0, "spam": 1.0, "phishing": 2.0},
            subject="Test",
        )
        # Must normalize to sum = 1.0
        prob_sum = sum(res.threat_probabilities.values())
        assert abs(prob_sum - 1.0) < 1e-4

    # Case 12: Negative and NaN Inputs Sanitization
    def test_12_nan_and_negative_inputs_sanitized(self, engine):
        res = engine.assess(
            fused_probabilities={"legitimate": float("nan"), "spam": -0.5, "phishing": 1.5},
            features={"bad_val": float("inf")},
            subject="Test NaN",
        )
        assert not math.isnan(res.risk_score)
        assert 0.0 <= res.risk_score <= 100.0
        assert not math.isnan(res.confidence)
        assert not math.isnan(res.uncertainty)

    # Case 13: Correlated Domain & URL Signals (Category Caps Prevent Double Counting)
    def test_13_correlated_domain_and_url_capped(self, engine):
        # Pass 10 high-risk domains and 10 high-risk URLs
        domains = [
            {"domain": f"phish{i}.xyz", "risk_score": 1.0, "suspicious_tld": True, "has_homoglyphs": True, "lookalikes": [{"brand_domain": "paypal.com"}]}
            for i in range(10)
        ]
        urls = [
            {"url": f"http://192.168.1.{i}/phish", "is_ip_url": True, "is_shortener": True, "risk_score": 1.0}
            for i in range(10)
        ]
        res = engine.assess(domain_analyses=domains, url_analyses=urls)
        # Check that category caps prevent runaway score inflation
        assert res.category_scores["DOMAIN"] <= CATEGORY_CAPS["DOMAIN"]
        assert res.category_scores["URL"] <= CATEGORY_CAPS["URL"]
        assert res.risk_score <= 100.0

    # Case 14: Attachment Double Extension (.pdf.exe)
    def test_14_attachment_double_extension(self, engine):
        attachments = [
            {
                "filename": "Q4_Financial_Report.pdf.exe",
                "is_dangerous_extension": True,
                "has_double_extension": True,
                "size": 524288,
            }
        ]
        res = engine.assess(attachment_analyses=attachments)
        assert any(f.factor_id == "ATT_DOUBLE_EXTENSION" for f in res.risk_factors)
        assert any(f.factor_id == "ATT_DANGEROUS_EXTENSION" for f in res.risk_factors)
        assert res.category_scores["ATTACHMENT"] <= CATEGORY_CAPS["ATTACHMENT"]

    # Case 15: Urgent BEC Wire Transfer (No URLs or Attachments)
    def test_15_bec_pure_text_urgency_wire_transfer(self, engine):
        res = engine.assess(
            subject="URGENT: Direct bank wire transfer required before 5pm",
            body="Kindly execute immediate bank transfer using the routing number provided. Final notice.",
        )
        assert any(f.factor_id in ("BEC_PAYMENT_DEMAND", "BEC_URGENCY_PRESSURE") for f in res.risk_factors)
        assert res.category_scores["CONTENT_BEC"] > 0.0

    # Case 16: Display Name Spoofing
    def test_16_display_name_spoofing(self, engine):
        res = engine.assess(
            sender="random_user992@gmail.com",
            sender_name="Microsoft Security Team",
            subject="Verify your Office 365 Tenant",
        )
        assert any(f.factor_id == "IDENTITY_DISPLAY_NAME_MISMATCH" for f in res.risk_factors)

    # Case 17: Reply-To Mismatch
    def test_17_reply_to_mismatch(self, engine):
        res = engine.assess(
            sender="official@apple.com",
            reply_to="stealer@harvest-creds.com",
            subject="Apple ID Verification",
        )
        assert any(f.factor_id == "IDENTITY_REPLY_TO_MISMATCH" for f in res.risk_factors)

    # Case 18: Punycode / IDN Homoglyph Domain
    def test_18_punycode_homoglyph_domain(self, engine):
        domains = [
            {
                "domain": "xn--pple-43d.com",
                "has_punycode": True,
                "has_homoglyphs": True,
                "risk_score": 0.8,
            }
        ]
        res = engine.assess(domain_analyses=domains)
        assert any(f.factor_id in ("DOMAIN_HOMOGLYPH", "DOMAIN_LOOKALIKE") for f in res.risk_factors)

    # Case 19: Suspicious High-Risk TLD
    def test_19_suspicious_tld(self, engine):
        domains = [
            {
                "domain": "support-center.xyz",
                "suspicious_tld": True,
                "risk_score": 0.5,
            }
        ]
        res = engine.assess(domain_analyses=domains)
        assert any(f.factor_id == "DOMAIN_SUSPICIOUS_TLD" for f in res.risk_factors)

    # Case 20: IP-Based URL Host
    def test_20_ip_based_url_host(self, engine):
        urls = [
            {
                "url": "http://185.220.101.5/admin/login.php",
                "is_ip_url": True,
                "risk_score": 0.85,
            }
        ]
        res = engine.assess(url_analyses=urls)
        assert any(f.factor_id == "URL_IP_BASED" for f in res.risk_factors)

    # Case 21: URL Shortener Detected
    def test_21_url_shortener_detected(self, engine):
        urls = [
            {
                "url": "https://bit.ly/3xYqz",
                "is_shortener": True,
                "risk_score": 0.4,
            }
        ]
        res = engine.assess(url_analyses=urls)
        assert any(f.factor_id == "URL_SHORTENER" for f in res.risk_factors)

    # Case 22: Non-Monotonic Relay Timestamps
    def test_22_non_monotonic_relay_timestamps(self, engine):
        res = engine.assess(
            received_anomalies=["non_monotonic_timestamps"],
            total_hops=4,
        )
        assert any(f.factor_id == "RELAY_NON_MONOTONIC_TIME" for f in res.risk_factors)

    # Case 23: Anomalous Hop Count (> 8 Hops)
    def test_23_anomalous_hop_count(self, engine):
        res = engine.assess(total_hops=12)
        assert any(f.factor_id == "RELAY_ANOMALOUS_HOP_COUNT" for f in res.risk_factors)

    # Case 24: RFC1918 Private Originating IP
    def test_24_private_originating_ip(self, engine):
        res = engine.assess(
            ip_analyses=[{"ip": "10.0.0.1", "warnings": ["private"], "is_public": False}],
            features={"infra_private_originating_ip": 1.0},
        )
        assert any(f.factor_id == "INFRA_PRIVATE_ORIGINATING_IP" for f in res.risk_factors)

    # Case 25: Evidence Quality Tier Degradation
    def test_25_evidence_quality_tier_impact(self, engine):
        eq_full = EvidenceQuality(
            overall_quality=0.95,
            tier="HIGH",
            dimension_scores={},
            dimension_details=[],
            missing_evidence_flags=[],
            active_features_count=100,
        )
        eq_deg = EvidenceQuality(
            overall_quality=0.15,
            tier="DEGRADED",
            dimension_scores={},
            dimension_details=[],
            missing_evidence_flags=["missing_rfc822_headers"],
            active_features_count=10,
        )

        res_full = engine.assess(
            fused_probabilities={"legitimate": 0.90, "spam": 0.05, "phishing": 0.05},
            evidence_quality=eq_full,
        )
        res_deg = engine.assess(
            fused_probabilities={"legitimate": 0.90, "spam": 0.05, "phishing": 0.05},
            evidence_quality=eq_deg,
        )
        assert res_full.confidence > res_deg.confidence
        assert res_full.uncertainty < res_deg.uncertainty

    # Case 26: Strict Mathematical Determinism
    def test_26_strict_determinism_50_iterations(self, engine):
        kwargs = dict(
            fused_probabilities={"legitimate": 0.2, "spam": 0.1, "phishing": 0.7},
            ml_label="phishing",
            ml_confidence=0.7,
            spf_result="FAIL",
            dkim_result="PASS",
            dmarc_result="FAIL",
            sender="security@service.xyz",
            sender_name="Service Security",
            subject="Immediate password update required",
            body="Click here to login and update your password now.",
        )
        baseline = engine.assess(**kwargs)
        for _ in range(50):
            current = engine.assess(**kwargs)
            assert current.risk_score == baseline.risk_score
            assert current.severity == baseline.severity
            assert current.confidence == baseline.confidence
            assert current.uncertainty == baseline.uncertainty
            assert current.explanation == baseline.explanation
            assert len(current.risk_factors) == len(baseline.risk_factors)

    # Case 27: Strict Bounds Enforcement
    def test_27_strict_bounds_enforcement(self, engine):
        # Massive risk inputs
        res = engine.assess(
            fused_probabilities={"legitimate": 0.0, "spam": 0.0, "phishing": 1.0},
            spf_result="FAIL",
            dkim_result="FAIL",
            dmarc_result="FAIL",
            domain_analyses=[{"domain": "evil.xyz", "risk_score": 1.0, "suspicious_tld": True}],
            url_analyses=[{"url": "http://192.168.1.1/phish", "is_ip_url": True, "risk_score": 1.0}],
            attachment_analyses=[{"filename": "virus.exe", "is_dangerous_extension": True}],
            received_anomalies=["non_monotonic_timestamps"],
            total_hops=15,
            subject="Urgent password payment wire",
            body="Immediate password wire transfer required now",
        )
        assert 0.0 <= res.risk_score <= 100.0
        assert 0.0 <= res.confidence <= 1.0
        assert 0.0 <= res.uncertainty <= 1.0
        assert abs(res.confidence + res.uncertainty - 1.0) < 1e-4

    # Case 28: JSON Serializability and Legacy Contract Parity
    def test_28_serializability_and_legacy_contracts(self, engine):
        res = engine.assess(
            fused_probabilities={"legitimate": 0.90, "spam": 0.05, "phishing": 0.05},
            ml_label="legitimate",
            spf_result="PASS",
            dkim_result="PASS",
            dmarc_result="PASS",
        )
        d = res.to_dict()
        # Ensure it serializes cleanly to JSON without TypeError
        json_str = json.dumps(d)
        assert len(json_str) > 50

        # Check legacy aliases
        assert "score" in d and d["score"] == round(res.risk_score, 1)
        assert "level" in d and d["level"] == res.severity
        assert "summary" in d and d["summary"] == res.explanation
        assert "contributions" in d and isinstance(d["contributions"], list)
        assert "limitations" in d and isinstance(d["limitations"], list)

        # Check canonical fields
        assert "risk_score" in d
        assert "severity" in d
        assert "threat_probabilities" in d
        assert "confidence" in d
        assert "uncertainty" in d
        assert "evidence_quality" in d
        assert "model_evidence" in d
        assert "risk_factors" in d
        assert "engine_version" in d

    # Case 29: Direct FusionPrediction Object Ingestion
    def test_29_direct_fusion_prediction_ingestion(self, engine):
        eq = EvidenceQuality(
            overall_quality=0.88,
            tier="HIGH",
            dimension_scores={},
            dimension_details=[],
            missing_evidence_flags=[],
            active_features_count=90,
        )
        fp = FusionPrediction(
            predicted_label="phishing",
            predicted_index=2,
            confidence=0.80,
            probabilities={"legitimate": 0.05, "spam": 0.15, "phishing": 0.80},
            risk_score=0.80,
            fusion_strategy="DYNAMIC_GATING",
            alpha=0.5,
            evidence_quality=eq,
            disagreement_category="AGREEMENT",
            uncertainty_escalation=False,
            escalation_reasons=[],
            reasoning=["High phishing intent detected"],
        )
        res = engine.assess(fusion_prediction=fp)
        assert res.predicted_threat_label == "phishing"
        assert res.threat_probabilities["phishing"] == 0.80
        assert res.model_evidence.selected_strategy == "DYNAMIC_GATING"

    # Case 30: Mitigating Factors for Highly Authenticated Benign Email
    def test_30_mitigating_factors_reduce_risk(self, engine):
        res = engine.assess(
            fused_probabilities={"legitimate": 0.99, "spam": 0.005, "phishing": 0.005},
            ml_label="legitimate",
            spf_result="PASS",
            dkim_result="PASS",
            dmarc_result="PASS",
            sender="no-reply@amazon.com",
            sender_name="Amazon Orders",
            domain_analyses=[{"domain": "amazon.com", "risk_score": 0.0}],
            subject="Your Amazon.com order has shipped",
            body="Track your package with carrier UPS.",
        )
        # Has mitigating factors with negative contribution
        mitigating = [f for f in res.risk_factors if f.contribution < 0]
        assert len(mitigating) >= 1
        assert any(f.factor_id == "AUTH_ALL_PASS" for f in mitigating)
        assert res.risk_score <= 10.0
        assert res.severity == RiskLevel.LOW.value
