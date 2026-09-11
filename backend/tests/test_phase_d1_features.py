"""
Test suite for VERTEX Phase D1: Forensic Feature Engineering Foundation.
Validates:
- Feature registry schema integrity and completeness
- Determinism and idempotency of feature extraction
- Explicit missing value handling (no NaN/Inf)
- Zero target leakage into feature dictionaries
- All 11 forensic signal groups
- Dual support: raw .eml RFC822 evidence vs canonical records
"""
import pytest
import math
import copy

from app.features.schema import (
    FeatureType,
    FeatureDefinition,
    FeatureVector,
    SPF_RESULT_ENCODING,
    DKIM_RESULT_ENCODING,
    DMARC_RESULT_ENCODING,
)
from app.features.registry import (
    FEATURE_REGISTRY,
    get_feature_registry,
    get_feature_names,
    get_feature_by_name,
    get_features_by_group,
)
from app.features.validators import (
    validate_features_dict,
    validate_feature_vector,
    FORBIDDEN_TARGET_KEYS,
)
from app.features.extractor import ForensicFeatureExtractor
from app.data.schema import CanonicalEmailRecord


# ── 1. Registry Integrity & Schema Tests ─────────────────────────────────────

def test_registry_size_and_features():
    """Verify registry contains >= 85 features and matches exact registered count."""
    names = get_feature_names()
    assert len(names) >= 85
    assert len(names) == len(FEATURE_REGISTRY)
    assert len(names) == len(set(names)), "Duplicate feature names in registry"


def test_registry_group_coverage():
    """Verify all 11 required forensic groups are populated."""
    expected_groups = {
        "message_basics",
        "header_signals",
        "authentication_signals",
        "identity_consistency",
        "relay_path",
        "ip_infrastructure",
        "domain_signals",
        "url_signals",
        "attachment_signals",
        "content_structure",
        "bec_phish_signals",
    }
    registry = get_feature_registry()
    found_groups = {f.group for f in registry}
    missing = expected_groups - found_groups
    assert not missing, f"Missing groups in registry: {missing}"

    for grp in expected_groups:
        grp_features = get_features_by_group(grp)
        assert len(grp_features) >= 5, f"Group {grp} has too few features: {len(grp_features)}"


def test_registry_feature_definitions():
    """Ensure every feature definition has valid types, documentation, and defaults."""
    for f in FEATURE_REGISTRY:
        assert isinstance(f.name, str) and len(f.name) > 0
        assert f.name.islower()
        assert isinstance(f.dtype, FeatureType)
        assert isinstance(f.description, str) and len(f.description) > 0
        assert isinstance(f.source, str) and len(f.source) > 0
        assert isinstance(f.default_value, (int, float))
        assert not math.isnan(f.default_value)
        assert not math.isinf(f.default_value)
        assert f.safe_for_ml is True
        assert f.requires_network is False, "Forensic features must be 100% offline-computable"


# ── 2. Validator & Target Leakage Tests ───────────────────────────────────────

def test_validator_rejects_target_leakage():
    """Verify validator catches any attempt to leak ground-truth labels into features."""
    ext = ForensicFeatureExtractor()
    record = {
        "record_id": "test_leak_01",
        "source_dataset": "test_set",
        "subject": "Hello",
        "body": "World",
        "normalized_label": "phishing",
    }
    vec = ext.extract_from_canonical_record(record)
    assert "normalized_label" not in vec.features
    assert "threat_type" not in vec.features

    # Force leakage into features dict to test validator
    leaked_features = copy.deepcopy(vec.features)
    leaked_features["normalized_label"] = 1.0
    is_valid, errors = validate_features_dict(leaked_features)
    assert not is_valid
    assert any("TARGET LEAKAGE" in err for err in errors)


def test_validator_rejects_nan_and_inf():
    """Verify validator detects NaN or Infinite values."""
    ext = ForensicFeatureExtractor()
    record = {"record_id": "test_nan", "source_dataset": "test_set", "subject": "", "body": ""}
    vec = ext.extract_from_canonical_record(record)

    corrupted_nan = copy.deepcopy(vec.features)
    corrupted_nan["msg_subject_length"] = float("nan")
    is_valid, errors = validate_features_dict(corrupted_nan)
    assert not is_valid
    assert any("NaN" in err for err in errors)

    corrupted_inf = copy.deepcopy(vec.features)
    corrupted_inf["msg_body_length"] = float("inf")
    is_valid, errors = validate_features_dict(corrupted_inf)
    assert not is_valid
    assert any("Infinite" in err for err in errors)


# ── 3. Determinism & Idempotency Tests ────────────────────────────────────────

def test_feature_extraction_determinism():
    """Repeated extraction on identical input produces strictly identical numeric features."""
    ext = ForensicFeatureExtractor()
    record = {
        "record_id": "det_01",
        "source_dataset": "det_set",
        "subject": "Urgent update required for your account",
        "body": "Dear customer, please click http://192.168.1.1/update to wire transfer funds immediately.",
        "sender": "Security <security@bank-update.xyz>",
        "has_html": False,
    }

    vec1 = ext.extract_from_canonical_record(record)
    vec2 = ext.extract_from_canonical_record(record)

    assert vec1.features == vec2.features
    assert vec1.get_features_only() == vec2.get_features_only()


# ── 4. Raw Email Extraction Tests ────────────────────────────────────────────

def test_raw_email_feature_extraction():
    """Extract features from realistic raw RFC822 bytes."""
    raw_eml = b"""From: "Executive Officer" <ceo@company-spoof.top>
To: target@victim.org
Subject: STRICTLY CONFIDENTIAL: Wire Transfer Request
Date: Mon, 15 Sep 2025 08:30:00 +0000
Message-ID: <msg999@company-spoof.top>
Reply-To: external-drop@gmail.com
Received: from gateway.attacker.net ([198.51.100.42]) by mx.victim.org with ESMTP; Mon, 15 Sep 2025 08:31:00 +0000
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Keep this between us. Please wire transfer $45,000 to the new bank account today.</p>
<p>Invoice attached: <a href="http://198.51.100.50:8080/invoice.exe">Download Invoice</a></p>
</body>
</html>
"""
    ext = ForensicFeatureExtractor()
    vec = ext.extract_from_raw_bytes(
        raw_eml,
        record_id="raw_sample_01",
        source_dataset="unit_test",
        normalized_label="phishing",
        threat_type="impersonation",
    )

    assert vec.raw_evidence_available is True
    assert vec.record_id == "raw_sample_01"
    assert vec.normalized_label == "phishing"

    # Message Basics
    assert vec.features["msg_has_html"] == 1.0
    assert vec.features["msg_header_count"] > 0

    # Header Signals
    assert vec.features["hdr_from_present"] == 1.0
    assert vec.features["hdr_reply_to_present"] == 1.0
    assert vec.features["hdr_received_count"] >= 1.0

    # Identity Consistency
    assert vec.features["ident_from_reply_to_mismatch"] == 1.0
    assert vec.features["ident_display_name_role_spoof"] == 1.0

    # Domain Signals
    assert vec.features["dom_sender_suspicious_tld"] == 1.0  # .top

    # URL Signals
    assert vec.features["url_total_count"] >= 1.0
    assert vec.features["url_ip_literal_count"] >= 1.0
    assert vec.features["url_has_port"] == 1.0  # :8080

    # BEC Cues
    assert vec.features["bec_secrecy_cues"] >= 1.0
    assert vec.features["bec_wire_transfer_cues"] >= 1.0
    assert vec.features["bec_invoice_cues"] >= 1.0
    assert vec.features["bec_executive_terms_count"] >= 1.0


# ── 5. Canonical Record Fallback & Missing Value Tests ────────────────────────

def test_canonical_record_graceful_fallbacks():
    """Ensure pure tabular canonical records cleanly assign -1.0 to unobserved evidence."""
    record = CanonicalEmailRecord(
        record_id="can_test_01",
        source_dataset="spam_assassin",
        source_record_id="sa_001",
        original_label="ham",
        normalized_label="legitimate",
        threat_type="clean",
        subject="Meeting notes for Monday",
        body="Let's sync at 10am tomorrow to review the quarterly roadmap.",
        sender="colleague@legitcorp.com",
        recipient="team@legitcorp.com",
        raw_email_available=False,
    )
    ext = ForensicFeatureExtractor()
    vec = ext.extract_from_canonical_record(record)

    assert vec.raw_evidence_available is False
    assert vec.features["auth_spf_result"] == SPF_RESULT_ENCODING["unknown"]
    assert vec.features["auth_dkim_result"] == DKIM_RESULT_ENCODING["unknown"]
    assert vec.features["auth_dmarc_result"] == DMARC_RESULT_ENCODING["unknown"]
    assert vec.features["relay_hop_count"] == -1.0
    assert vec.features["msg_header_count"] == -1.0

    # Available signals correctly populated
    assert vec.features["msg_subject_length"] == len("Meeting notes for Monday")
    assert vec.features["dom_sender_suspicious_tld"] == 0.0
    assert vec.features["bec_urgency_score"] == 0.0
    assert vec.features["bec_wire_transfer_cues"] == 0.0


# ── 6. Lexical, Homoglyph, and Anomaly Signals ───────────────────────────────

def test_domain_homoglyph_and_punycode():
    """Verify homoglyph and punycode detection."""
    from app.features.groups.domain_signals import extract_domain_signals

    # Punycode domain
    f_puny, _ = extract_domain_signals(domain="xn--pple-43d.com")
    assert f_puny["dom_sender_punycode"] == 1.0

    # Homoglyph domain (Cyrillic 'а' U+0430)
    homoglyph_domain = "p\u0430ypal.com"
    f_homo, _ = extract_domain_signals(domain=homoglyph_domain)
    assert f_homo["dom_sender_homoglyph"] == 1.0

    # Normal domain
    f_norm, _ = extract_domain_signals(domain="google.com")
    assert f_norm["dom_sender_homoglyph"] == 0.0
    assert f_norm["dom_sender_punycode"] == 0.0
    assert f_norm["dom_sender_entropy"] > 0.0


def test_content_structure_hidden_text_and_caps():
    """Verify detection of hidden CSS text and excessive capitalization."""
    from app.features.groups.content_structure import extract_content_structure

    # Excessive CAPS
    f_caps, _ = extract_content_structure(
        subject="URGENT ACTION REQUIRED IMMEDIATELY",
        body_text="YOUR ACCOUNT WILL BE TERMINATED IN 24 HOURS UNLESS YOU ACT RIGHT NOW!",
    )
    assert f_caps["cnt_excessive_capitalization"] == 1.0
    assert f_caps["cnt_exclamation_count"] >= 1.0

    # Hidden text in HTML
    html_hidden = '<html><body>Visible text <span style="display:none">hidden secret keywords</span></body></html>'
    f_hidden, _ = extract_content_structure(
        subject="Notice",
        body_text="Visible text",
        body_html=html_hidden,
    )
    assert f_hidden["cnt_hidden_text_detected"] == 1.0


def test_url_signals_extraction():
    """Verify URL feature extraction including shorteners, IP literals, and queries."""
    from app.features.groups.url_signals import extract_url_signals

    text = """
    Check out: http://192.168.1.10:8080/login?user=victim
    Also visit: https://bit.ly/3xyz
    And clean: https://example.com/info
    """
    f_url, _ = extract_url_signals(body_text=text)
    assert f_url["url_total_count"] == 3.0
    assert f_url["url_http_count"] == 1.0
    assert f_url["url_https_count"] == 2.0
    assert f_url["url_ip_literal_count"] == 1.0
    assert f_url["url_has_port"] == 1.0
    assert f_url["url_has_query"] == 1.0
    assert f_url["url_has_shortener"] == 1.0


def test_attachment_signals_extraction():
    """Verify attachment risk features including double extensions and macros."""
    from app.features.groups.attachment_signals import extract_attachment_signals

    sample_atts = [
        {"filename": "document.pdf.exe", "content_type": "application/x-msdownload", "size": 102400},
        {"filename": "macro_sheet.xlsm", "content_type": "application/vnd.ms-excel", "size": 20480},
        {"filename": "payload.zip", "content_type": "application/zip", "size": 512000},
    ]
    f_att, _ = extract_attachment_signals(attachments_list=sample_atts)
    assert f_att["att_total_count"] == 3.0
    assert f_att["att_executable_count"] >= 1.0
    assert f_att["att_double_extension_count"] == 1.0
    assert f_att["att_macro_count"] == 1.0
    assert f_att["att_archive_count"] == 1.0
    assert f_att["att_max_size_bytes"] == 512000.0


def test_feature_vector_serialization():
    """Verify FeatureVector to_flat_dict preserves metadata and cleanly segregates features."""
    ext = ForensicFeatureExtractor()
    record = {
        "record_id": "rec_ser_01",
        "source_dataset": "corpus_v1",
        "normalized_label": "phishing",
        "threat_type": "credential_harvesting",
        "subject": "Reset Password",
        "body": "Click here to reset your password immediately.",
        "sender": "support@secure-login.xyz",
    }
    vec = ext.extract_from_canonical_record(record)
    flat = vec.to_flat_dict()

    # Metadata present in flat dict
    assert flat["record_id"] == "rec_ser_01"
    assert flat["source_dataset"] == "corpus_v1"
    assert flat["normalized_label"] == "phishing"
    assert flat["threat_type"] == "credential_harvesting"
    assert flat["raw_evidence_available"] == 0.0

    # Features only dictionary strictly excludes metadata
    feats_only = vec.get_features_only()
    assert "record_id" not in feats_only
    assert "normalized_label" not in feats_only
    assert "threat_type" not in feats_only
    assert len(feats_only) == len(get_feature_names())


def test_export_feature_schema_json():
    """Verify JSON schema export is valid and matches registry length."""
    import json
    from app.features import export_feature_schema_json

    schema_str = export_feature_schema_json()
    data = json.loads(schema_str)
    assert isinstance(data, list)
    assert len(data) == len(FEATURE_REGISTRY)
    first = data[0]
    assert "name" in first
    assert "group" in first
    assert "dtype" in first
    assert "default_value" in first
    assert "forensic_rationale" in first
