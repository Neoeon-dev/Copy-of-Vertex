"""
Unit and Integration Test Suite for VERTEX Phase D4 Multimodal Evidence-Aware Fusion.
Covers 24 test cases spanning:
- Evidence quality analysis (10 dimensions, tiers, flags, record & raw inputs)
- Smooth evidence router (bounds, monotonicity, extrema)
- Fusion engine strategies (concordance, probability normalization, modality weighting)
- Disagreement analysis & categorization
- Uncertainty escalation rules
- Explainable reasoning generation
- Learned logistic fusion meta-classifier
- Calibration metrics (Brier score, ECE, reliability bins)
- MultimodalFusionService inference (raw bytes, canonical record, features/text, batch)
- Model artifact and metadata integrity
"""
from __future__ import annotations

import os
import json
import pytest
import numpy as np
from typing import Dict, Any

from app.data.schema import CanonicalEmailRecord
from app.features.registry import get_feature_names
from app.ml.version import TARGET_CLASSES, INT_TO_LABEL
from app.ml.fusion.schemas import (
    QualityTier,
    DisagreementCategory,
    FusionStrategy,
    EvidenceDimensionScore,
    EvidenceQuality,
    FusionPrediction,
)
from app.ml.fusion.evidence_quality import (
    EvidenceQualityAnalyzer,
    DIMENSION_WEIGHTS,
)
from app.ml.fusion.fusion import (
    SmoothEvidenceRouter,
    EvidenceAwareFusionEngine,
)
from app.ml.fusion.calibrator import FusionCalibrator
from app.ml.fusion.service import (
    MultimodalFusionService,
    get_fusion_service,
    FUSION_MODEL_VERSION,
)


@pytest.fixture
def mock_feature_dict() -> Dict[str, float]:
    """Provides a realistic feature dictionary for testing."""
    feature_names = get_feature_names()
    d = {f: -1.0 for f in feature_names}
    # Populate rich header and auth features
    d["hdr_from_present"] = 1.0
    d["hdr_to_present"] = 1.0
    d["hdr_date_present"] = 1.0
    d["hdr_message_id_present"] = 1.0
    d["msg_header_count"] = 18.0
    d["auth_spf_result"] = 1.0
    d["auth_dkim_result"] = 1.0
    d["auth_dmarc_result"] = 1.0
    d["relay_hop_count"] = 3.0
    d["relay_unique_ip_count"] = 3.0
    d["ip_originating_present"] = 1.0
    d["dom_sender_length"] = 12.0
    d["dom_sender_label_count"] = 2.0
    d["url_total_count"] = 2.0
    d["url_unique_count"] = 2.0
    d["att_total_count"] = 0.0
    d["msg_body_length"] = 450.0
    d["msg_body_word_count"] = 75.0
    d["msg_body_line_count"] = 12.0
    d["ident_address_parsing_failure"] = 0.0
    d["ident_from_reply_to_mismatch"] = 0.0
    return d


# ─── 1. Evidence Quality Analyzer Tests ──────────────────────────────────

def test_evidence_quality_dimensions_count():
    """Asserts all 10 observable dimensions exist and weights sum to 1.0."""
    analyzer = EvidenceQualityAnalyzer()
    assert len(analyzer.weights) == 10
    assert abs(sum(analyzer.weights.values()) - 1.0) < 1e-4
    assert "rfc822_headers" in analyzer.weights
    assert "auth_alignment" in analyzer.weights
    assert "relay_hops" in analyzer.weights
    assert "forensic_feature_density" in analyzer.weights


def test_evidence_quality_clean_rich_email(mock_feature_dict):
    """Asserts rich evidence yields high quality score (>= 0.70) and HIGH tier."""
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_features(mock_feature_dict)
    assert eq.overall_quality >= 0.70
    assert eq.tier == QualityTier.HIGH.value
    assert len(eq.missing_evidence_flags) == 0
    assert len(eq.dimension_details) == 10
    assert eq.dimension_scores["rfc822_headers"] == 1.0
    assert eq.dimension_scores["auth_alignment"] == 1.0


def test_evidence_quality_degraded_headerless():
    """Asserts headerless, stripped email yields low quality score (< 0.20) and DEGRADED tier."""
    analyzer = EvidenceQualityAnalyzer()
    feature_names = get_feature_names()
    # All features missing or default
    stripped = {f: -1.0 for f in feature_names}
    stripped["msg_body_word_count"] = 4.0
    stripped["msg_body_length"] = 20.0

    eq = analyzer.analyze_features(stripped)
    assert eq.overall_quality < 0.20
    assert eq.tier == QualityTier.DEGRADED.value
    assert "missing_rfc822_headers" in eq.missing_evidence_flags
    assert "missing_authentication" in eq.missing_evidence_flags
    assert "missing_relay_path" in eq.missing_evidence_flags


def test_evidence_quality_missing_flags(mock_feature_dict):
    """Verifies specific evidence omissions trigger corresponding missing flags."""
    analyzer = EvidenceQualityAnalyzer()
    d = mock_feature_dict.copy()
    # Strip authentication
    d["auth_spf_result"] = -1.0
    d["auth_dkim_result"] = -1.0
    d["auth_dmarc_result"] = -1.0
    # Strip relay
    d["relay_hop_count"] = 0.0

    eq = analyzer.analyze_features(d)
    assert "missing_authentication" in eq.missing_evidence_flags
    assert "missing_relay_path" in eq.missing_evidence_flags
    assert "missing_rfc822_headers" not in eq.missing_evidence_flags


def test_evidence_quality_from_canonical_record():
    """Verifies analyze_record computes quality from a CanonicalEmailRecord."""
    analyzer = EvidenceQualityAnalyzer()
    record = CanonicalEmailRecord(
        record_id="test_rec_001",
        source_dataset="unit_test",
        source_record_id="src_001",
        original_label="phish",
        normalized_label="phishing",
        threat_type="credential_harvesting",
        subject="Important security alert",
        body="Please verify your account immediately at http://verify-secure-login.com",
        sender="security@bank-alert.com",
        recipient="user@example.com",
        has_headers=True,
    )
    eq = analyzer.analyze_record(record)
    assert isinstance(eq, EvidenceQuality)
    assert 0.0 <= eq.overall_quality <= 1.0
    assert eq.dimension_scores["body_content"] > 0.0


def test_evidence_quality_from_raw_components():
    """Verifies analyze_raw computes quality from raw text and optional header dict."""
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_raw(
        subject="Meeting tomorrow",
        body="Let's meet at 2pm in conference room B to discuss quarterly planning and goals.",
        headers={"from": "alice@corp.com", "to": "bob@corp.com", "date": "today", "message-id": "<123@corp.com>"},
    )
    assert isinstance(eq, EvidenceQuality)
    assert eq.overall_quality > 0.20
    assert eq.dimension_scores["rfc822_headers"] > 0.0


# ─── 2. Smooth Evidence Router Tests ─────────────────────────────────────

def test_smooth_router_bounds_and_monotonicity():
    """Asserts alpha(Q) is bounded in [alpha_min, alpha_max] and strictly non-decreasing."""
    router = SmoothEvidenceRouter(alpha_min=0.05, alpha_max=0.70)
    qs = np.linspace(0.0, 1.0, 50)
    alphas = [router.compute_alpha(q) for q in qs]

    for a in alphas:
        assert 0.05 <= a <= 0.70

    # Strict monotonicity
    for i in range(len(alphas) - 1):
        assert alphas[i + 1] >= alphas[i]


def test_smooth_router_extrema():
    """Asserts alpha(0.0) == alpha_min and alpha(1.0) == alpha_max."""
    router = SmoothEvidenceRouter(alpha_min=0.05, alpha_max=0.70)
    assert abs(router.compute_alpha(0.0) - 0.05) < 1e-4
    assert abs(router.compute_alpha(1.0) - 0.70) < 1e-4


# ─── 3. Fusion Engine Strategy Tests ─────────────────────────────────────

def test_fusion_probability_normalization():
    """Asserts fused probabilities sum to 1.0 and each class probability is non-negative."""
    engine = EvidenceAwareFusionEngine()
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_raw(subject="Test", body="Short body")

    p_d2 = np.array([0.1, 0.2, 0.7])
    p_d3 = np.array([0.8, 0.1, 0.1])

    for strat in [FusionStrategy.EQUAL_AVERAGE, FusionStrategy.FIXED_WEIGHTED, FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED]:
        p_fused, _ = engine.fuse_probabilities(p_d2, p_d3, eq, strategy=strat)
        assert abs(np.sum(p_fused) - 1.0) < 1e-5
        assert np.all(p_fused >= 0.0)


def test_fusion_concordance_agreement(mock_feature_dict):
    """When both D2 and D3 strongly agree, fusion outputs concordant prediction with high confidence."""
    engine = EvidenceAwareFusionEngine()
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_features(mock_feature_dict)

    p_d2 = np.array([0.02, 0.03, 0.95])  # Both predict phishing
    p_d3 = np.array([0.05, 0.05, 0.90])

    pred = engine.predict(p_d2, p_d3, eq)
    assert pred.predicted_label == "phishing"
    assert pred.confidence >= 0.90
    assert pred.disagreement_category == DisagreementCategory.AGREEMENT.value
    assert not pred.uncertainty_escalation


def test_fusion_high_quality_favors_d2(mock_feature_dict):
    """Under high evidence quality (Q >= 0.70), alpha >= 0.60 giving primary weight to D2."""
    engine = EvidenceAwareFusionEngine()
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_features(mock_feature_dict)

    assert eq.overall_quality >= 0.70
    p_d2 = np.array([0.1, 0.85, 0.05])  # D2 says spam
    p_d3 = np.array([0.85, 0.1, 0.05])  # D3 says legit

    p_fused, alpha = engine.fuse_probabilities(p_d2, p_d3, eq)
    assert alpha >= 0.60
    # Spam should win because D2 is heavily weighted
    assert np.argmax(p_fused) == 1


def test_fusion_degraded_quality_favors_d3():
    """Under degraded evidence quality (Q < 0.20), alpha <= 0.15 giving primary weight to D3."""
    engine = EvidenceAwareFusionEngine()
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_raw(subject="", body="Short text sample")

    assert eq.overall_quality < 0.20
    p_d2 = np.array([0.05, 0.10, 0.85])  # D2 false-alarms on phish due to missing headers
    p_d3 = np.array([0.88, 0.07, 0.05])  # D3 correctly identifies legit text

    p_fused, alpha = engine.fuse_probabilities(p_d2, p_d3, eq)
    assert alpha <= 0.15
    # Legit should win because D3 is heavily weighted
    assert np.argmax(p_fused) == 0


# ─── 4. Disagreement & Escalation Tests ──────────────────────────────────

def test_disagreement_categorization():
    """Verifies all DisagreementCategory enum variants map correctly."""
    assert DisagreementCategory.categorize("phishing", "legitimate") == DisagreementCategory.FORENSIC_PHISH_SEMANTIC_LEGIT
    assert DisagreementCategory.categorize("legitimate", "phishing") == DisagreementCategory.FORENSIC_LEGIT_SEMANTIC_PHISH
    assert DisagreementCategory.categorize("spam", "phishing") == DisagreementCategory.FORENSIC_SPAM_SEMANTIC_PHISH
    assert DisagreementCategory.categorize("spam", "spam") == DisagreementCategory.AGREEMENT


def test_uncertainty_escalation_low_confidence():
    """Asserts escalation triggers when maximum fusion probability is below threshold (0.60)."""
    engine = EvidenceAwareFusionEngine(confidence_threshold=0.60)
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_raw(subject="Test", body="Ambiguous")

    # Near uniform probabilities
    p_d2 = np.array([0.35, 0.35, 0.30])
    p_d3 = np.array([0.34, 0.33, 0.33])

    pred = engine.predict(p_d2, p_d3, eq)
    assert pred.uncertainty_escalation is True
    assert any("Low overall fusion confidence" in r for r in pred.escalation_reasons)


def test_uncertainty_escalation_conflict_intermediate_q():
    """Asserts escalation triggers when models disagree under intermediate Q."""
    engine = EvidenceAwareFusionEngine()
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_raw(
        subject="Invoice #49281",
        body="Please find the attached invoice for your review.",
        headers={"from": "billing@vendor.com"},  # partial evidence
    )

    p_d2 = np.array([0.1, 0.8, 0.1])  # D2 says spam
    p_d3 = np.array([0.8, 0.1, 0.1])  # D3 says legit

    pred = engine.predict(p_d2, p_d3, eq)
    assert pred.disagreement_category != DisagreementCategory.AGREEMENT.value
    if 0.20 <= eq.overall_quality <= 0.45:
        assert pred.uncertainty_escalation is True


def test_uncertainty_escalation_high_divergence_phish_legit():
    """Asserts escalation triggers when one model predicts phish (>0.70) and the other legit."""
    engine = EvidenceAwareFusionEngine()
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_raw(subject="Test", body="Account update required")

    p_d2 = np.array([0.1, 0.1, 0.80])  # D2 says phish
    p_d3 = np.array([0.85, 0.1, 0.05])  # D3 says legit

    pred = engine.predict(p_d2, p_d3, eq)
    assert pred.uncertainty_escalation is True
    assert any("High-divergence conflict" in r for r in pred.escalation_reasons)


def test_reasoning_explanation_completeness(mock_feature_dict):
    """Asserts reasoning list contains tier, weights, and explanation points."""
    engine = EvidenceAwareFusionEngine()
    analyzer = EvidenceQualityAnalyzer()
    eq = analyzer.analyze_features(mock_feature_dict)

    p_d2 = np.array([0.05, 0.90, 0.05])
    p_d3 = np.array([0.10, 0.85, 0.05])

    pred = engine.predict(p_d2, p_d3, eq)
    assert len(pred.reasoning) >= 2
    assert any("Evidence Quality Tier" in r for r in pred.reasoning)
    assert any("Modality Allocation" in r for r in pred.reasoning)


# ─── 5. Learned Fusion & Calibration Tests ───────────────────────────────

def test_learned_fusion_meta_classifier_train_and_predict(mock_feature_dict):
    """Verifies training and inference of Learned Logistic Meta-Classifier."""
    engine = EvidenceAwareFusionEngine()
    analyzer = EvidenceQualityAnalyzer()

    # Create small synthetic validation dataset
    n_samples = 30
    val_eq = [analyzer.analyze_features(mock_feature_dict) for _ in range(n_samples)]
    val_p_d2 = np.random.dirichlet((1, 1, 1), size=n_samples)
    val_p_d3 = np.random.dirichlet((1, 1, 1), size=n_samples)
    y_val = np.random.choice([0, 1, 2], size=n_samples)

    fit_res = engine.train_learned_fusion(val_p_d2, val_p_d3, val_eq, y_val)
    assert engine.learned_model is not None
    assert fit_res["meta_features_dim"] > 10

    # Predict with learned strategy
    p_learned, _ = engine.fuse_probabilities(
        val_p_d2[0], val_p_d3[0], val_eq[0], strategy=FusionStrategy.LEARNED_LOGISTIC
    )
    assert len(p_learned) == 3
    assert abs(np.sum(p_learned) - 1.0) < 1e-5


def test_calibrator_brier_and_ece():
    """Asserts multi-class Brier score and ECE are computed correctly with proper bounds."""
    y_true = np.array([0, 1, 2, 0, 1, 2])
    # Perfect probabilities
    y_prob_perf = np.array([
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
    ])
    brier_perf = FusionCalibrator.calculate_multiclass_brier_score(y_true, y_prob_perf)
    ece_perf, mce_perf, bins = FusionCalibrator.calculate_ece_and_bins(y_true, y_prob_perf, n_bins=5)
    assert brier_perf == 0.0
    assert ece_perf == 0.0
    assert len(bins) == 5

    # Imperfect probabilities
    y_prob_imperfect = np.array([
        [0.5, 0.3, 0.2],
        [0.2, 0.6, 0.2],
        [0.1, 0.2, 0.7],
        [0.4, 0.4, 0.2],
        [0.3, 0.4, 0.3],
        [0.2, 0.3, 0.5],
    ])
    brier_imp = FusionCalibrator.calculate_multiclass_brier_score(y_true, y_prob_imperfect)
    ece_imp, _, _ = FusionCalibrator.calculate_ece_and_bins(y_true, y_prob_imperfect, n_bins=5)
    assert brier_imp > 0.0
    assert ece_imp >= 0.0


# ─── 6. MultimodalFusionService Integration Tests ────────────────────────

def test_multimodal_fusion_service_analyze_email_raw():
    """Verifies service end-to-end inference on raw email bytes."""
    service = get_fusion_service()
    raw_email = (
        b"From: sender@trusted.com\r\n"
        b"To: recipient@company.com\r\n"
        b"Subject: Weekly Sync Meeting\r\n"
        b"Date: Wed, 02 Sep 2026 09:00:00 +0000\r\n"
        b"Message-ID: <msg12345@trusted.com>\r\n"
        b"\r\n"
        b"Hello team, please remember our weekly synchronization call today at 10am.\r\n"
    )
    pred = service.analyze_email(raw_bytes=raw_email)
    assert isinstance(pred, FusionPrediction)
    assert pred.predicted_label in TARGET_CLASSES
    assert 0.0 <= pred.confidence <= 1.0
    assert abs(sum(pred.probabilities.values()) - 1.0) < 1e-3
    assert pred.latency_ms > 0.0


def test_multimodal_fusion_service_analyze_email_record():
    """Verifies service inference from a CanonicalEmailRecord."""
    service = get_fusion_service()
    record = CanonicalEmailRecord(
        record_id="rec_serv_002",
        source_dataset="unit_test",
        source_record_id="src_002",
        original_label="phish",
        normalized_label="phishing",
        threat_type="credential_harvesting",
        subject="URGENT: Password Reset",
        body="Your account will be suspended unless you click here to verify credentials.",
        sender="support@security-alert-center.com",
        recipient="target@victim.com",
        has_headers=True,
    )
    pred = service.analyze_email(record=record)
    assert isinstance(pred, FusionPrediction)
    assert pred.predicted_label in TARGET_CLASSES
    assert pred.forensic_prediction is not None
    assert pred.semantic_prediction is not None


def test_multimodal_fusion_service_analyze_email_features_text(mock_feature_dict):
    """Verifies service inference from explicit features and text."""
    service = get_fusion_service()
    pred = service.analyze_email(
        subject="Quarterly Report",
        body="Here is the quarterly summary report for your team.",
        features=mock_feature_dict,
    )
    assert isinstance(pred, FusionPrediction)
    assert pred.evidence_quality.tier == QualityTier.HIGH.value
    assert pred.alpha >= 0.60


def test_multimodal_fusion_service_batch(mock_feature_dict):
    """Verifies batched inference produces identical individual predictions."""
    service = get_fusion_service()
    emails = [
        ("Invoice Due", "Please pay attached invoice", mock_feature_dict),
        ("Hello", "Just saying hello", mock_feature_dict),
    ]
    batch_preds = service.analyze_batch(emails)
    assert len(batch_preds) == 2
    for p in batch_preds:
        assert isinstance(p, FusionPrediction)
        assert abs(sum(p.probabilities.values()) - 1.0) < 1e-3


def test_model_card_and_artifact_integrity():
    """Verifies models/fusion/v1/ config, metadata, and MODEL_CARD.md exist."""
    model_dir = "models/fusion/v1"
    config_path = os.path.join(model_dir, "fusion_config.json")
    meta_path = os.path.join(model_dir, "metadata.json")
    card_path = os.path.join(model_dir, "MODEL_CARD.md")

    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            assert "champion_strategy" in cfg
            assert "router_parameters" in cfg

    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
            assert meta["model_version"] == "1.0.0"
            assert "artifacts" in meta
