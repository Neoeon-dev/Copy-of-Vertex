"""
Canonical Forensic Risk Decision Engine for VERTEX (Phase D5).
Transforms D4 threat probabilities, cryptographic authentication evidence,
identity consistency, domain intelligence, URL signals, attachment risks,
and relay infrastructure into a single bounded, explainable risk assessment.
"""
from __future__ import annotations

import logging
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from app.engine.schemas import (
    RiskLevel,
    score_to_severity,
    EvidenceState,
    RiskFactorCategory,
    EvidenceProvenance,
    RiskFactor,
    EvidenceQualityBreakdown,
    ModelEvidence,
    RiskAssessment,
)
from app.engine.registry import (
    RiskFactorRegistry,
    CATEGORY_CAPS,
    FactorDefinition,
)
from app.ml.version import TARGET_CLASSES, INT_TO_LABEL
from app.ml.fusion.schemas import FusionPrediction, EvidenceQuality
from app.ml.fusion.evidence_quality import EvidenceQualityAnalyzer

logger = logging.getLogger(__name__)

ENGINE_VERSION = "5.0.0"
FEATURE_VERSION = "1.0.0"
RULE_SET_VERSION = "2026.1"

# Patterns for BEC / Content cues if analyzing raw text
URGENCY_PATTERN = re.compile(
    r"\b(urgent|immediately|action required|suspended|final notice|account locked|"
    r"unauthorized access|security alert|act now|limited time|expire|deadline)\b",
    re.IGNORECASE,
)
CREDENTIAL_PATTERN = re.compile(
    r"\b(password|passcode|credential|login|sign in|signin|verify your account|"
    r"confirm your identity|security code|otp|pin number|ssn|social security)\b",
    re.IGNORECASE,
)
PAYMENT_PATTERN = re.compile(
    r"\b(wire transfer|bank transfer|direct deposit|remittance|invoice attached|"
    r"payment due|bank details|routing number|swift code|gift card|bitcoin|crypto|usdt)\b",
    re.IGNORECASE,
)
SUSPICIOUS_TLD_PATTERN = re.compile(
    r"\.(xyz|top|work|click|link|gq|ml|cf|tk|ga|buzz|loan|racing|fit|cam)$",
    re.IGNORECASE,
)


def calculate_tvd(p1: Dict[str, float], p2: Dict[str, float]) -> float:
    """Calculates Total Variation Distance (TVD) between two 3-class probability distributions."""
    classes = ["legitimate", "spam", "phishing"]
    diff_sum = sum(abs(p1.get(c, 0.0) - p2.get(c, 0.0)) for c in classes)
    return min(1.0, max(0.0, float(0.5 * diff_sum)))


def shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of a domain or string."""
    if not s:
        return 0.0
    s_clean = s.lower().replace(".", "").replace("-", "")
    if not s_clean:
        return 0.0
    length = len(s_clean)
    counts: Dict[str, int] = {}
    for ch in s_clean:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
    return float(entropy)


class CanonicalRiskEngine:
    """
    VERTEX Canonical Forensic Risk Decision Engine.
    Pure, deterministic, bounded multi-signal risk evaluator.
    """

    def __init__(self, category_caps: Optional[Dict[str, float]] = None) -> None:
        self.category_caps = category_caps or dict(CATEGORY_CAPS)
        self.quality_analyzer = EvidenceQualityAnalyzer()

    def assess(
        self,
        # ML / Fusion inputs
        fusion_prediction: Optional[FusionPrediction] = None,
        d2_probabilities: Optional[Dict[str, float]] = None,
        d3_probabilities: Optional[Dict[str, float]] = None,
        fused_probabilities: Optional[Dict[str, float]] = None,
        ml_label: Optional[str] = None,
        ml_confidence: float = 0.0,
        ml_risk_score: float = 0.0,
        ml_signals: Optional[Dict[str, float]] = None,
        ml_signal_details: Optional[Dict[str, str]] = None,
        # Authentication signals
        spf_result: Optional[str] = None,
        dkim_result: Optional[str] = None,
        dmarc_result: Optional[str] = None,
        spf_domain: Optional[str] = None,
        dkim_domain: Optional[str] = None,
        # Identity signals
        sender: Optional[str] = None,
        sender_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        envelope_sender: Optional[str] = None,
        # Domain intelligence
        domain_analyses: Optional[List[Dict[str, Any]]] = None,
        # URL analysis
        url_analyses: Optional[List[Dict[str, Any]]] = None,
        # Attachment analysis
        attachment_analyses: Optional[List[Dict[str, Any]]] = None,
        # Infrastructure / Relay signals
        received_anomalies: Optional[List[str]] = None,
        total_hops: int = 0,
        ip_analyses: Optional[List[Dict[str, Any]]] = None,
        # Content / Text signals
        subject: Optional[str] = None,
        body: Optional[str] = None,
        features: Optional[Dict[str, float]] = None,
        evidence_quality: Optional[EvidenceQuality] = None,
    ) -> RiskAssessment:
        """
        Computes the canonical forensic risk assessment across all observed evidence.
        Operates deterministically, bounds risk in [0, 100], and separates confidence/uncertainty.
        """
        factors: List[RiskFactor] = []
        category_raw_scores: Dict[str, float] = {cat: 0.0 for cat in RiskFactorCategory}

        # ── 1. Resolve ML Threat Evidence ────────────────────────────
        d2_avail = True
        d3_avail = True
        if fusion_prediction is not None:
            d2_avail = fusion_prediction.forensic_prediction is not None
            d3_avail = getattr(fusion_prediction, "semantic_prediction", None) is not None or True
        elif d2_probabilities is not None and d3_probabilities is None:
            d3_avail = False
        elif d3_probabilities is not None and d2_probabilities is None:
            d2_avail = False
        elif d2_probabilities is None and d3_probabilities is None and fused_probabilities is None and ml_label is None:
            d2_avail = False
            d3_avail = False

        p_d2, p_d3, p_fused, d_cat, strat, d2_lbl, d3_lbl = self._resolve_model_probabilities(
            fusion_prediction=fusion_prediction,
            d2_probabilities=d2_probabilities,
            d3_probabilities=d3_probabilities,
            fused_probabilities=fused_probabilities,
            ml_label=ml_label,
            ml_confidence=ml_confidence,
            ml_risk_score=ml_risk_score,
            features=features,
        )

        tvd = calculate_tvd(p_d2, p_d3) if (d2_avail and d3_avail) else 0.0
        model_conf = max(p_fused.values()) if p_fused else 0.5
        pred_threat_label = max(p_fused.items(), key=lambda x: x[1])[0] if p_fused else "legitimate"

        # Score Model Evidence
        p_phish = p_fused.get("phishing", 0.0)
        p_spam = p_fused.get("spam", 0.0)
        p_legit = p_fused.get("legitimate", 0.0)

        if d2_avail or d3_avail:
            if p_phish >= 0.70:
                contrib = 20.0 + 15.0 * ((p_phish - 0.70) / 0.30)
                factors.append(self._create_factor(
                    factor_id="MODEL_PHISHING_CONFIRMED",
                    contribution=contrib,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="multimodal_fusion",
                    source_feature="fused_phishing_probability",
                    raw_value=p_phish,
                    normalized_value=p_phish,
                    template_kwargs={"prob": p_phish},
                ))
                category_raw_scores[RiskFactorCategory.MODEL.value] += contrib
            elif p_phish >= 0.40:
                contrib = 8.0 + 12.0 * ((p_phish - 0.40) / 0.30)
                factors.append(self._create_factor(
                    factor_id="MODEL_PHISHING_SUSPECTED",
                    contribution=contrib,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="multimodal_fusion",
                    source_feature="fused_phishing_probability",
                    raw_value=p_phish,
                    normalized_value=p_phish,
                    template_kwargs={"prob": p_phish},
                ))
                category_raw_scores[RiskFactorCategory.MODEL.value] += contrib

            if p_spam >= 0.50:
                contrib = 10.0 * p_spam
                factors.append(self._create_factor(
                    factor_id="MODEL_SPAM_DETECTED",
                    contribution=contrib,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="multimodal_fusion",
                    source_feature="fused_spam_probability",
                    raw_value=p_spam,
                    normalized_value=p_spam,
                    template_kwargs={"prob": p_spam},
                ))
                category_raw_scores[RiskFactorCategory.MODEL.value] += contrib

            if p_legit >= 0.80 and p_phish < 0.20:
                # High legitimate probability mitigates risk
                contrib = -10.0 * ((p_legit - 0.80) / 0.20)
                factors.append(self._create_factor(
                    factor_id="MODEL_LEGITIMATE_MITIGATION",
                    contribution=contrib,
                    evidence_state=EvidenceState.OBSERVED_POSITIVE.value,
                    source_analyzer="multimodal_fusion",
                    source_feature="fused_legitimate_probability",
                    raw_value=p_legit,
                    normalized_value=p_legit,
                    template_kwargs={"prob": p_legit},
                ))
                category_raw_scores[RiskFactorCategory.MODEL.value] += contrib

        # Disagreement factor
        if tvd >= 0.35:
            contrib = 5.0 * tvd
            factors.append(self._create_factor(
                factor_id="MODEL_DISAGREEMENT_ELEVATION",
                contribution=contrib,
                evidence_state=EvidenceState.UNCERTAIN.value,
                source_analyzer="multimodal_fusion",
                source_feature="tvd_disagreement",
                raw_value=tvd,
                normalized_value=tvd,
                template_kwargs={"d2_label": d2_lbl, "d3_label": d3_lbl},
            ))
            category_raw_scores[RiskFactorCategory.MODEL.value] += contrib

        # ── 2. Authentication Scoring (Missing != Failed) ────────────
        auth_signals_present = 0
        auth_passes = 0

        # Fallback to tabular features if explicit results not provided
        if dmarc_result is None and features:
            if features.get("auth_dmarc_fail", 0.0) == 1.0 or features.get("auth_dmarc_result", 0.0) == 1.0:
                dmarc_result = "FAIL"
            elif features.get("auth_dmarc_pass", 0.0) == 1.0:
                dmarc_result = "PASS"

        if spf_result is None and features:
            if features.get("auth_spf_fail", 0.0) == 1.0:
                spf_result = "FAIL"
            elif features.get("auth_spf_pass", 0.0) == 1.0:
                spf_result = "PASS"

        if dkim_result is None and features:
            if features.get("auth_dkim_fail", 0.0) == 1.0:
                dkim_result = "FAIL"
            elif features.get("auth_dkim_pass", 0.0) == 1.0:
                dkim_result = "PASS"

        # DMARC
        if dmarc_result is not None:
            norm_dmarc = dmarc_result.upper()
            if norm_dmarc == "FAIL":
                factors.append(self._create_factor(
                    factor_id="AUTH_DMARC_FAIL",
                    contribution=12.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="dmarc_analyzer",
                    source_feature="dmarc_result",
                    raw_value=dmarc_result,
                    normalized_value=1.0,
                ))
                category_raw_scores[RiskFactorCategory.AUTHENTICATION.value] += 12.0
                auth_signals_present += 1
            elif norm_dmarc == "PASS":
                auth_signals_present += 1
                auth_passes += 1
            elif norm_dmarc in ("NONE", "NOT_CHECKED", "UNAVAILABLE"):
                # Missing DMARC is unavailable, not failed
                auth_signals_present += 0

        # SPF
        if spf_result is not None:
            norm_spf = spf_result.upper()
            if norm_spf in ("FAIL", "SOFTFAIL", "PERMERROR"):
                factors.append(self._create_factor(
                    factor_id="AUTH_SPF_FAIL",
                    contribution=8.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="spf_analyzer",
                    source_feature="spf_result",
                    raw_value=spf_result,
                    normalized_value=1.0,
                    template_kwargs={"spf_result": norm_spf},
                ))
                category_raw_scores[RiskFactorCategory.AUTHENTICATION.value] += 8.0
                auth_signals_present += 1
            elif norm_spf == "PASS":
                auth_signals_present += 1
                auth_passes += 1

        # DKIM
        if dkim_result is not None:
            norm_dkim = dkim_result.upper()
            if norm_dkim in ("FAIL", "PERMERROR"):
                factors.append(self._create_factor(
                    factor_id="AUTH_DKIM_FAIL",
                    contribution=8.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="dkim_analyzer",
                    source_feature="dkim_result",
                    raw_value=dkim_result,
                    normalized_value=1.0,
                ))
                category_raw_scores[RiskFactorCategory.AUTHENTICATION.value] += 8.0
                auth_signals_present += 1
            elif norm_dkim == "PASS":
                auth_signals_present += 1
                auth_passes += 1

        # Full alignment mitigation (cannot whitewash confirmed phishing)
        if auth_passes >= 3 and p_phish < 0.50:
            factors.append(self._create_factor(
                factor_id="AUTH_ALL_PASS",
                contribution=-5.0,
                evidence_state=EvidenceState.OBSERVED_POSITIVE.value,
                source_analyzer="authentication_aggregator",
                source_feature="auth_alignment",
                raw_value="ALL_PASS",
                normalized_value=0.0,
            ))
            category_raw_scores[RiskFactorCategory.AUTHENTICATION.value] += -5.0

        # ── 3. Identity Consistency Scoring ──────────────────────────
        sender_domain = ""
        if sender and "@" in sender:
            sender_domain = sender.split("@")[-1].strip().lower()

        if sender and sender_name:
            s_name_lower = sender_name.lower()
            dom_prefix = sender_domain.split(".")[0] if sender_domain else ""
            # Check for known high-value brand names in display name when sender domain differs
            common_brands = ["paypal", "microsoft", "apple", "google", "amazon", "netflix", "bank", "security"]
            claims_brand = any(b in s_name_lower for b in common_brands)
            brand_in_domain = any(b in sender_domain for b in common_brands)
            if (claims_brand and not brand_in_domain) or (dom_prefix and dom_prefix not in s_name_lower and len(sender_name) > 3 and "@" not in sender_name):
                factors.append(self._create_factor(
                    factor_id="IDENTITY_DISPLAY_NAME_MISMATCH",
                    contribution=8.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="identity_analyzer",
                    source_feature="display_name_alignment",
                    raw_value=f"name='{sender_name}', sender='{sender}'",
                    normalized_value=1.0,
                    template_kwargs={"name": sender_name, "domain": sender_domain},
                ))
                category_raw_scores[RiskFactorCategory.IDENTITY.value] += 8.0

        if reply_to and sender_domain and "@" in reply_to:
            reply_domain = reply_to.split("@")[-1].strip().lower()
            if reply_domain != sender_domain:
                factors.append(self._create_factor(
                    factor_id="IDENTITY_REPLY_TO_MISMATCH",
                    contribution=6.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="identity_analyzer",
                    source_feature="reply_to_alignment",
                    raw_value=f"reply_to='{reply_to}', sender='{sender}'",
                    normalized_value=1.0,
                    template_kwargs={"reply_to": reply_to, "sender": sender},
                ))
                category_raw_scores[RiskFactorCategory.IDENTITY.value] += 6.0

        if envelope_sender and sender_domain and "@" in envelope_sender:
            env_domain = envelope_sender.split("@")[-1].strip().lower()
            if env_domain != sender_domain:
                factors.append(self._create_factor(
                    factor_id="IDENTITY_ENVELOPE_MISMATCH",
                    contribution=4.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="identity_analyzer",
                    source_feature="envelope_alignment",
                    raw_value=envelope_sender,
                    normalized_value=1.0,
                ))
                category_raw_scores[RiskFactorCategory.IDENTITY.value] += 4.0

        # Check features dict for identity anomalies
        if features:
            if features.get("ident_display_name_role_spoof", 0.0) == 1.0 or features.get("ident_display_name_domain_inconsistency", 0.0) == 1.0:
                if not any(f.factor_id == "IDENTITY_DISPLAY_NAME_MISMATCH" for f in factors):
                    factors.append(self._create_factor(
                        factor_id="IDENTITY_DISPLAY_NAME_MISMATCH",
                        contribution=8.0,
                        evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                        source_analyzer="identity_analyzer",
                        source_feature="ident_display_name_role_spoof",
                        raw_value=1.0,
                        normalized_value=1.0,
                        template_kwargs={"name": "Executive / Impersonated Entity", "domain": "external"},
                    ))
                    category_raw_scores[RiskFactorCategory.IDENTITY.value] += 8.0

            if features.get("ident_from_reply_to_mismatch", 0.0) == 1.0:
                if not any(f.factor_id == "IDENTITY_REPLY_TO_MISMATCH" for f in factors):
                    factors.append(self._create_factor(
                        factor_id="IDENTITY_REPLY_TO_MISMATCH",
                        contribution=6.0,
                        evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                        source_analyzer="identity_analyzer",
                        source_feature="ident_from_reply_to_mismatch",
                        raw_value=1.0,
                        normalized_value=1.0,
                        template_kwargs={"reply_to": "mismatched", "sender": "sender"},
                    ))
                    category_raw_scores[RiskFactorCategory.IDENTITY.value] += 6.0

            if features.get("ident_from_return_path_mismatch", 0.0) == 1.0:
                if not any(f.factor_id == "IDENTITY_ENVELOPE_MISMATCH" for f in factors):
                    factors.append(self._create_factor(
                        factor_id="IDENTITY_ENVELOPE_MISMATCH",
                        contribution=4.0,
                        evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                        source_analyzer="identity_analyzer",
                        source_feature="ident_from_return_path_mismatch",
                        raw_value=1.0,
                        normalized_value=1.0,
                    ))
                    category_raw_scores[RiskFactorCategory.IDENTITY.value] += 4.0

            if features.get("ident_address_parsing_failure", 0.0) == 1.0:
                factors.append(self._create_factor(
                    factor_id="IDENTITY_PARSING_FAILURE",
                    contribution=4.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="identity_analyzer",
                    source_feature="ident_address_parsing_failure",
                    raw_value=1.0,
                    normalized_value=1.0,
                ))
                category_raw_scores[RiskFactorCategory.IDENTITY.value] += 4.0

        # ── 4. Domain Intelligence Scoring ───────────────────────────
        if domain_analyses:
            for da in domain_analyses:
                dom_name = da.get("domain", "")
                if da.get("lookalikes"):
                    lk = da["lookalikes"][0]
                    target_b = lk.get("brand_domain", "target brand")
                    factors.append(self._create_factor(
                        factor_id="DOMAIN_LOOKALIKE",
                        contribution=8.0,
                        evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                        source_analyzer="domain_intel",
                        source_feature="lookalike_distance",
                        raw_value=dom_name,
                        normalized_value=1.0,
                        template_kwargs={"domain": dom_name, "brand": target_b},
                    ))
                    category_raw_scores[RiskFactorCategory.DOMAIN.value] += 8.0
                    break

            for da in domain_analyses:
                dom_name = da.get("domain", "")
                if da.get("has_homoglyphs") or da.get("has_punycode"):
                    factors.append(self._create_factor(
                        factor_id="DOMAIN_HOMOGLYPH",
                        contribution=8.0,
                        evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                        source_analyzer="domain_intel",
                        source_feature="homoglyph_detected",
                        raw_value=dom_name,
                        normalized_value=1.0,
                        template_kwargs={"domain": dom_name},
                    ))
                    category_raw_scores[RiskFactorCategory.DOMAIN.value] += 8.0
                    break

            for da in domain_analyses:
                dom_name = da.get("domain", "")
                if da.get("suspicious_tld") or SUSPICIOUS_TLD_PATTERN.search(dom_name):
                    factors.append(self._create_factor(
                        factor_id="DOMAIN_SUSPICIOUS_TLD",
                        contribution=5.0,
                        evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                        source_analyzer="domain_intel",
                        source_feature="suspicious_tld",
                        raw_value=dom_name,
                        normalized_value=1.0,
                        template_kwargs={"tld": dom_name.split(".")[-1] if "." in dom_name else "TLD"},
                    ))
                    category_raw_scores[RiskFactorCategory.DOMAIN.value] += 5.0
                    break

        elif sender_domain:
            if SUSPICIOUS_TLD_PATTERN.search(sender_domain):
                factors.append(self._create_factor(
                    factor_id="DOMAIN_SUSPICIOUS_TLD",
                    contribution=5.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="domain_intel",
                    source_feature="suspicious_tld",
                    raw_value=sender_domain,
                    normalized_value=1.0,
                    template_kwargs={"tld": sender_domain.split(".")[-1]},
                ))
                category_raw_scores[RiskFactorCategory.DOMAIN.value] += 5.0
            if shannon_entropy(sender_domain) > 3.8:
                ent = shannon_entropy(sender_domain)
                factors.append(self._create_factor(
                    factor_id="DOMAIN_HIGH_ENTROPY",
                    contribution=4.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="domain_intel",
                    source_feature="shannon_entropy",
                    raw_value=ent,
                    normalized_value=min(1.0, ent / 5.0),
                    template_kwargs={"entropy": ent},
                ))
                category_raw_scores[RiskFactorCategory.DOMAIN.value] += 4.0

        elif features:
            if features.get("dom_sender_homoglyph", 0.0) == 1.0 or features.get("dom_sender_punycode", 0.0) == 1.0:
                factors.append(self._create_factor(
                    factor_id="DOMAIN_HOMOGLYPH",
                    contribution=8.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="domain_intel",
                    source_feature="dom_sender_homoglyph",
                    raw_value=1.0,
                    normalized_value=1.0,
                    template_kwargs={"domain": "sender_domain"},
                ))
                category_raw_scores[RiskFactorCategory.DOMAIN.value] += 8.0

            if features.get("dom_sender_suspicious_tld", 0.0) == 1.0:
                factors.append(self._create_factor(
                    factor_id="DOMAIN_SUSPICIOUS_TLD",
                    contribution=5.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="domain_intel",
                    source_feature="dom_sender_suspicious_tld",
                    raw_value=1.0,
                    normalized_value=1.0,
                    template_kwargs={"tld": "abuse_tld"},
                ))
                category_raw_scores[RiskFactorCategory.DOMAIN.value] += 5.0

            if features.get("dom_sender_entropy", 0.0) > 3.8:
                ent = float(features.get("dom_sender_entropy", 0.0))
                factors.append(self._create_factor(
                    factor_id="DOMAIN_HIGH_ENTROPY",
                    contribution=4.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="domain_intel",
                    source_feature="dom_sender_entropy",
                    raw_value=ent,
                    normalized_value=min(1.0, ent / 5.0),
                    template_kwargs={"entropy": ent},
                ))
                category_raw_scores[RiskFactorCategory.DOMAIN.value] += 4.0

        # ── 5. URL Analysis Scoring ──────────────────────────────────
        if url_analyses:
            has_ip_url = any(ua.get("is_ip_url") for ua in url_analyses)
            has_shortener = any(ua.get("is_shortener") for ua in url_analyses)
            has_susp_path = any(
                ua.get("suspicious_path")
                or any(tok in ua.get("url", "").lower() for tok in ("/login", "/verify", "/account", "/signin", "/auth", "/steal"))
                for ua in url_analyses
            )
            has_punycode = any(ua.get("has_punycode") for ua in url_analyses)

            if has_ip_url:
                ip_u = next(ua.get("url", "") for ua in url_analyses if ua.get("is_ip_url"))
                factors.append(self._create_factor(
                    factor_id="URL_IP_BASED",
                    contribution=8.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="url_analyzer",
                    source_feature="is_ip_url",
                    raw_value=ip_u,
                    normalized_value=1.0,
                    template_kwargs={"url": ip_u[:40]},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 8.0

            if has_shortener:
                short_u = next(ua.get("url", "") for ua in url_analyses if ua.get("is_shortener"))
                factors.append(self._create_factor(
                    factor_id="URL_SHORTENER",
                    contribution=4.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="url_analyzer",
                    source_feature="is_shortener",
                    raw_value=short_u,
                    normalized_value=1.0,
                    template_kwargs={"url": short_u[:40]},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 4.0

            if has_susp_path:
                susp_u = next(
                    (ua.get("url", "") for ua in url_analyses if ua.get("suspicious_path") or any(tok in ua.get("url", "").lower() for tok in ("/login", "/verify", "/account", "/signin", "/auth", "/steal"))),
                    url_analyses[0].get("url", "") if url_analyses else ""
                )
                factors.append(self._create_factor(
                    factor_id="URL_SUSPICIOUS_PATH",
                    contribution=5.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="url_analyzer",
                    source_feature="suspicious_path",
                    raw_value=susp_u,
                    normalized_value=1.0,
                    template_kwargs={"url": susp_u[:40]},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 5.0

            if has_punycode:
                puny_u = next(ua.get("url", "") for ua in url_analyses if ua.get("has_punycode"))
                factors.append(self._create_factor(
                    factor_id="URL_PUNYCODE",
                    contribution=5.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="url_analyzer",
                    source_feature="has_punycode",
                    raw_value=puny_u,
                    normalized_value=1.0,
                    template_kwargs={"url": puny_u[:40]},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 5.0

            if len(url_analyses) > 5:
                factors.append(self._create_factor(
                    factor_id="URL_HIGH_COUNT",
                    contribution=3.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="url_analyzer",
                    source_feature="url_count",
                    raw_value=len(url_analyses),
                    normalized_value=min(1.0, len(url_analyses) / 10.0),
                    template_kwargs={"count": len(url_analyses)},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 3.0

            high_risk_url = next((ua for ua in url_analyses if ua.get("risk_score", 0.0) >= 0.5), None)
            if high_risk_url and not (has_ip_url or has_shortener or has_susp_path or has_punycode):
                u_str = high_risk_url.get("url", "")
                factors.append(self._create_factor(
                    factor_id="URL_SUSPICIOUS_PATH",
                    contribution=6.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="url_analyzer",
                    source_feature="url_risk_score",
                    raw_value=high_risk_url.get("risk_score", 0.5),
                    normalized_value=1.0,
                    template_kwargs={"url": u_str[:40]},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 6.0

            # Check for suspicious TLDs in URL targets if domain analyses didn't flag any
            if not domain_analyses:
                for ua in url_analyses:
                    u_str = ua.get("url", "")
                    match = re.search(r"://([^/:]+)", u_str)
                    if match:
                        u_dom = match.group(1).lower()
                        if SUSPICIOUS_TLD_PATTERN.search(u_dom):
                            factors.append(self._create_factor(
                                factor_id="DOMAIN_SUSPICIOUS_TLD",
                                contribution=5.0,
                                evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                                source_analyzer="url_analyzer",
                                source_feature="url_suspicious_tld",
                                raw_value=u_dom,
                                normalized_value=1.0,
                                template_kwargs={"tld": u_dom.split(".")[-1]},
                            ))
                            category_raw_scores[RiskFactorCategory.DOMAIN.value] += 5.0
                            break

        elif features:
            if features.get("url_ip_literal_count", 0.0) > 0 or features.get("url_has_ip_url", 0.0) == 1.0:
                factors.append(self._create_factor(
                    factor_id="URL_IP_BASED",
                    contribution=8.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="forensic_features",
                    source_feature="url_ip_literal_count",
                    raw_value=1.0,
                    normalized_value=1.0,
                    template_kwargs={"url": "raw_ip"},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 8.0

            if features.get("url_has_shortener", 0.0) == 1.0:
                factors.append(self._create_factor(
                    factor_id="URL_SHORTENER",
                    contribution=4.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="forensic_features",
                    source_feature="url_has_shortener",
                    raw_value=1.0,
                    normalized_value=1.0,
                    template_kwargs={"url": "shortener"},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 4.0

            if features.get("url_total_count", 0.0) > 5:
                u_cnt = int(features.get("url_total_count", 0))
                factors.append(self._create_factor(
                    factor_id="URL_HIGH_COUNT",
                    contribution=3.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="forensic_features",
                    source_feature="url_total_count",
                    raw_value=u_cnt,
                    normalized_value=min(1.0, u_cnt / 10.0),
                    template_kwargs={"count": u_cnt},
                ))
                category_raw_scores[RiskFactorCategory.URL.value] += 3.0

        # ── 6. Attachment Risk Scoring ───────────────────────────────
        if attachment_analyses:
            has_double_ext = any(aa.get("has_double_extension") for aa in attachment_analyses)
            has_dangerous_ext = any(aa.get("is_dangerous_extension") for aa in attachment_analyses)
            has_mime_mismatch = any(aa.get("mime_mismatch") for aa in attachment_analyses)
            has_archive = any(aa.get("is_archive") for aa in attachment_analyses)

            if has_double_ext:
                d_fn = next(aa.get("filename", "") for aa in attachment_analyses if aa.get("has_double_extension"))
                factors.append(self._create_factor(
                    factor_id="ATT_DOUBLE_EXTENSION",
                    contribution=10.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="attachment_analyzer",
                    source_feature="has_double_extension",
                    raw_value=d_fn,
                    normalized_value=1.0,
                    template_kwargs={"filename": d_fn},
                ))
                category_raw_scores[RiskFactorCategory.ATTACHMENT.value] += 10.0

            if has_dangerous_ext:
                dang_fn = next(aa.get("filename", "") for aa in attachment_analyses if aa.get("is_dangerous_extension"))
                factors.append(self._create_factor(
                    factor_id="ATT_DANGEROUS_EXTENSION",
                    contribution=10.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="attachment_analyzer",
                    source_feature="is_dangerous_extension",
                    raw_value=dang_fn,
                    normalized_value=1.0,
                    template_kwargs={"filename": dang_fn},
                ))
                category_raw_scores[RiskFactorCategory.ATTACHMENT.value] += 10.0

            if has_mime_mismatch:
                m_fn = next(aa.get("filename", "") for aa in attachment_analyses if aa.get("mime_mismatch"))
                m_type = next(aa.get("content_type", "") for aa in attachment_analyses if aa.get("mime_mismatch"))
                factors.append(self._create_factor(
                    factor_id="ATT_MIME_MISMATCH",
                    contribution=5.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="attachment_analyzer",
                    source_feature="mime_mismatch",
                    raw_value=f"{m_fn} ({m_type})",
                    normalized_value=1.0,
                    template_kwargs={"filename": m_fn, "mime": m_type},
                ))
                category_raw_scores[RiskFactorCategory.ATTACHMENT.value] += 5.0

            if has_archive:
                arch_fn = next(aa.get("filename", "") for aa in attachment_analyses if aa.get("is_archive"))
                factors.append(self._create_factor(
                    factor_id="ATT_ARCHIVE_PRESENT",
                    contribution=4.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="attachment_analyzer",
                    source_feature="is_archive",
                    raw_value=arch_fn,
                    normalized_value=1.0,
                    template_kwargs={"filename": arch_fn},
                ))
                category_raw_scores[RiskFactorCategory.ATTACHMENT.value] += 4.0

        elif features:
            if features.get("att_executable_count", 0.0) > 0.0 or features.get("att_script_count", 0.0) > 0.0:
                factors.append(self._create_factor(
                    factor_id="ATT_DANGEROUS_EXTENSION",
                    contribution=10.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="forensic_features",
                    source_feature="att_executable_count",
                    raw_value=features.get("att_executable_count") or features.get("att_script_count"),
                    normalized_value=1.0,
                    template_kwargs={"filename": "executable_payload"},
                ))
                category_raw_scores[RiskFactorCategory.ATTACHMENT.value] += 10.0

            if features.get("att_double_extension_count", 0.0) > 0.0:
                factors.append(self._create_factor(
                    factor_id="ATT_DOUBLE_EXTENSION",
                    contribution=10.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="forensic_features",
                    source_feature="att_double_extension_count",
                    raw_value=features.get("att_double_extension_count"),
                    normalized_value=1.0,
                    template_kwargs={"filename": "double_ext_payload"},
                ))
                category_raw_scores[RiskFactorCategory.ATTACHMENT.value] += 10.0

            if features.get("att_mime_mismatch_count", 0.0) > 0.0:
                factors.append(self._create_factor(
                    factor_id="ATT_MIME_MISMATCH",
                    contribution=5.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="forensic_features",
                    source_feature="att_mime_mismatch_count",
                    raw_value=features.get("att_mime_mismatch_count"),
                    normalized_value=1.0,
                    template_kwargs={"filename": "mismatched_mime", "mime": "disguised"},
                ))
                category_raw_scores[RiskFactorCategory.ATTACHMENT.value] += 5.0

        # ── 7. Infrastructure & Relay Scoring ────────────────────────
        if received_anomalies and "non_monotonic_timestamps" in received_anomalies:
            factors.append(self._create_factor(
                factor_id="RELAY_NON_MONOTONIC_TIME",
                contribution=5.0,
                evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                source_analyzer="received_analyzer",
                source_feature="non_monotonic_timestamps",
                raw_value="non_monotonic",
                normalized_value=1.0,
            ))
            category_raw_scores[RiskFactorCategory.INFRASTRUCTURE_RELAY.value] += 5.0

        if total_hops > 8:
            factors.append(self._create_factor(
                factor_id="RELAY_ANOMALOUS_HOP_COUNT",
                contribution=4.0,
                evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                source_analyzer="received_analyzer",
                source_feature="total_hops",
                raw_value=total_hops,
                normalized_value=min(1.0, total_hops / 15.0),
                template_kwargs={"hops": total_hops},
            ))
            category_raw_scores[RiskFactorCategory.INFRASTRUCTURE_RELAY.value] += 4.0

        if ip_analyses:
            for ia in ip_analyses:
                warns = ia.get("warnings", [])
                is_priv = "private" in warns or not ia.get("is_public", True) or ia.get("is_private", False)
                if is_priv and (ia.get("is_originating") or len(ip_analyses) == 1):
                    ip_str = ia.get("ip", "private_ip")
                    factors.append(self._create_factor(
                        factor_id="INFRA_PRIVATE_ORIGINATING_IP",
                        contribution=3.0,
                        evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                        source_analyzer="ip_intelligence",
                        source_feature="private_originating",
                        raw_value=ip_str,
                        normalized_value=1.0,
                        template_kwargs={"ip": ip_str},
                    ))
                    category_raw_scores[RiskFactorCategory.INFRASTRUCTURE_RELAY.value] += 3.0
                    break
        if features and features.get("relay_timestamp_ordering_anomaly", 0.0) == 1.0:
            if not any(f.factor_id == "RELAY_NON_MONOTONIC_TIME" for f in factors):
                factors.append(self._create_factor(
                    factor_id="RELAY_NON_MONOTONIC_TIME",
                    contribution=5.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="forensic_features",
                    source_feature="relay_timestamp_ordering_anomaly",
                    raw_value=1.0,
                    normalized_value=1.0,
                ))
                category_raw_scores[RiskFactorCategory.INFRASTRUCTURE_RELAY.value] += 5.0

        if features and (features.get("ip_originating_is_private", 0.0) == 1.0 or features.get("infra_private_originating_ip", 0.0) == 1.0):
            if not any(f.factor_id == "INFRA_PRIVATE_ORIGINATING_IP" for f in factors):
                factors.append(self._create_factor(
                    factor_id="INFRA_PRIVATE_ORIGINATING_IP",
                    contribution=3.0,
                    evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                    source_analyzer="forensic_features",
                    source_feature="ip_originating_is_private",
                    raw_value=1.0,
                    normalized_value=1.0,
                    template_kwargs={"ip": "private_ip"},
                ))
                category_raw_scores[RiskFactorCategory.INFRASTRUCTURE_RELAY.value] += 3.0

        # ── 8. Content / BEC Scoring ─────────────────────────────────
        text_content = f"{subject or ''} {body or ''}"
        cred_matches = CREDENTIAL_PATTERN.findall(text_content)
        pay_matches = PAYMENT_PATTERN.findall(text_content)
        urg_matches = URGENCY_PATTERN.findall(text_content)

        # Check explicit ml_signals or regex matches
        has_cred = bool(cred_matches) or (ml_signals and ml_signals.get("credential_request", 0.0) >= 0.3) or (features and features.get("bec_credential_harvest_cues", 0.0) > 0.0)
        has_pay = bool(pay_matches) or (ml_signals and ml_signals.get("payment_request", 0.0) >= 0.3) or (features and features.get("bec_payment_request_cues", 0.0) > 0.0)
        has_urg = bool(urg_matches) or (ml_signals and ml_signals.get("urgency_language", 0.0) >= 0.3) or (features and features.get("bec_urgency_score", 0.0) > 0.0)

        if has_cred:
            factors.append(self._create_factor(
                factor_id="BEC_CREDENTIAL_REQUEST",
                contribution=7.0,
                evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                source_analyzer="content_analyzer",
                source_feature="credential_harvesting_cues",
                raw_value=", ".join(set(cred_matches[:3])) if cred_matches else "detected",
                normalized_value=1.0,
            ))
            category_raw_scores[RiskFactorCategory.CONTENT_BEC.value] += 7.0

        if has_pay:
            factors.append(self._create_factor(
                factor_id="BEC_PAYMENT_DEMAND",
                contribution=7.0,
                evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                source_analyzer="content_analyzer",
                source_feature="payment_demand_cues",
                raw_value=", ".join(set(pay_matches[:3])) if pay_matches else "detected",
                normalized_value=1.0,
            ))
            category_raw_scores[RiskFactorCategory.CONTENT_BEC.value] += 7.0

        if has_urg:
            factors.append(self._create_factor(
                factor_id="BEC_URGENCY_PRESSURE",
                contribution=4.0,
                evidence_state=EvidenceState.OBSERVED_NEGATIVE.value,
                source_analyzer="content_analyzer",
                source_feature="urgency_pressure_cues",
                raw_value=", ".join(set(urg_matches[:3])) if urg_matches else "detected",
                normalized_value=1.0,
            ))
            category_raw_scores[RiskFactorCategory.CONTENT_BEC.value] += 4.0

        # ── 9. Category Aggregation & Cap Enforcement ────────────────
        category_final_scores: Dict[str, float] = {}
        for cat_name, raw_pts in category_raw_scores.items():
            cap = self.category_caps.get(cat_name, 15.0)
            if raw_pts >= 0:
                category_final_scores[cat_name] = min(float(raw_pts), float(cap))
            else:
                # Mitigations (negative points)
                category_final_scores[cat_name] = max(float(raw_pts), -float(cap))

        # Sum bounded category scores
        total_raw = sum(category_final_scores.values())
        final_risk_score = min(100.0, max(0.0, float(total_raw)))
        severity = score_to_severity(final_risk_score)

        # ── 10. Evidence Quality Breakdown & Availability ────────────
        eq_breakdown = self._resolve_evidence_quality(
            evidence_quality=evidence_quality,
            fusion_prediction=fusion_prediction,
            features=features,
            subject=subject,
            body=body,
            auth_signals_present=auth_signals_present,
            total_hops=total_hops,
            url_count=len(url_analyses) if url_analyses else (1 if (features and features.get("url_total_count", 0.0) > 0) else 0),
            sender=sender,
            domain_analyses=domain_analyses,
            attachment_analyses=attachment_analyses,
            ip_analyses=ip_analyses,
        )

        # ── 11. Confidence & Uncertainty Calculation ─────────────────
        # Availability (A): how much evidence is present
        # Reliability (R): cryptographic and tamper-evident indicators
        # Consistency (C): do independent evidence categories agree?
        # Model Agreement (M): 1.0 - TVD
        avail = eq_breakdown.availability
        reliab = eq_breakdown.reliability
        m_agree = 1.0 - tvd

        # Consistency metric: do factors point in consistent threat direction?
        active_threat_cats = sum(1 for c, s in category_final_scores.items() if s > 0 and c != RiskFactorCategory.MODEL.value)
        if pred_threat_label == "phishing":
            consist = min(1.0, 0.4 + 0.15 * active_threat_cats)
        elif pred_threat_label == "legitimate":
            consist = 0.95 if active_threat_cats == 0 else max(0.2, 0.95 - 0.25 * active_threat_cats)
        else:
            consist = 0.7

        eff_avail = avail
        if auth_signals_present >= 3 and sender:
            eff_avail = max(avail, 0.80)

        # Confidence penalty if models are missing
        model_penalty = 0.0
        if not d2_avail:
            model_penalty += 0.08
        if not d3_avail:
            model_penalty += 0.08

        calculated_conf = min(1.0, max(0.0, 0.35 * eff_avail + 0.25 * reliab + 0.20 * m_agree + 0.20 * consist - model_penalty))
        calculated_uncert = min(1.0, max(0.0, 1.0 - calculated_conf))

        # ── 12. Model Evidence Structure ─────────────────────────────
        model_evidence = ModelEvidence(
            d2_probability=p_d2,
            d3_probability=p_d3,
            fused_probability=p_fused,
            disagreement=tvd,
            disagreement_category=d_cat,
            selected_strategy=strat,
            model_confidence=model_conf,
            d2_available=d2_avail,
            d3_available=d3_avail,
        )

        # ── 13. Explanation & Limitations Generation ─────────────────
        explanation = self._generate_explanation(
            final_risk_score=final_risk_score,
            severity=severity,
            pred_threat_label=pred_threat_label,
            factors=factors,
            tvd=tvd,
            d2_lbl=d2_lbl,
            d3_lbl=d3_lbl,
            eq_breakdown=eq_breakdown,
        )

        limitations = [
            "Risk score is a bounded forensic decision-support indicator, not an autonomous verdict.",
            "No single indicator in isolation warrants unilateral blocking.",
            "Infrastructure and geolocation data reflect transmission hops, not necessarily attacker identity.",
        ]
        if eq_breakdown.tier in ("LOW", "DEGRADED"):
            limitations.append(
                f"Evidence quality is {eq_breakdown.tier} ({eq_breakdown.overall:.2f}); assessment relies primarily on text semantics due to stripped headers."
            )
        if tvd >= 0.35:
            limitations.append(
                f"Modality disagreement detected (distance={tvd:.2f}); forensic tabular and semantic text models diverged."
            )

        return RiskAssessment(
            risk_score=final_risk_score,
            severity=severity.value,
            threat_probabilities=p_fused,
            predicted_threat_label=pred_threat_label,
            confidence=calculated_conf,
            uncertainty=calculated_uncert,
            evidence_quality=eq_breakdown,
            model_evidence=model_evidence,
            category_scores=category_final_scores,
            category_caps=self.category_caps,
            risk_factors=factors,
            explanation=explanation,
            limitations=limitations,
            engine_version=ENGINE_VERSION,
            feature_version=FEATURE_VERSION,
            rule_set_version=RULE_SET_VERSION,
        )

    # ── Internal Helpers ─────────────────────────────────────────────

    def _create_factor(
        self,
        factor_id: str,
        contribution: float,
        evidence_state: str,
        source_analyzer: str,
        source_feature: str,
        raw_value: Any,
        normalized_value: float,
        template_kwargs: Optional[Dict[str, Any]] = None,
    ) -> RiskFactor:
        definition = RiskFactorRegistry.get(factor_id)
        if definition is None:
            definition = FactorDefinition(
                factor_id=factor_id,
                category=RiskFactorCategory.EVIDENCE.value,
                name=factor_id.replace("_", " ").title(),
                description="Forensic observation",
                default_contribution=contribution,
                max_contribution=abs(contribution),
            )

        kwargs = template_kwargs or {}
        kwargs.setdefault("name", definition.name)
        kwargs.setdefault("detail", str(raw_value))
        try:
            explanation_text = definition.explanation_template.format(**kwargs)
        except Exception:
            explanation_text = f"{definition.name}: {raw_value}"

        provenance = EvidenceProvenance(
            source_analyzer=source_analyzer,
            source_feature=source_feature,
            raw_value=raw_value,
            normalized_value=float(normalized_value),
            evidence_state=evidence_state,
            description=definition.description,
        )

        return RiskFactor(
            factor_id=definition.factor_id,
            category=definition.category,
            name=definition.name,
            description=definition.description,
            contribution=float(contribution),
            max_contribution=definition.max_contribution,
            direction=definition.direction,
            evidence_state=evidence_state,
            provenance=provenance,
            explanation=explanation_text,
            version=ENGINE_VERSION,
        )

    def _resolve_model_probabilities(
        self,
        fusion_prediction: Optional[FusionPrediction] = None,
        d2_probabilities: Optional[Dict[str, float]] = None,
        d3_probabilities: Optional[Dict[str, float]] = None,
        fused_probabilities: Optional[Dict[str, float]] = None,
        ml_label: Optional[str] = None,
        ml_confidence: float = 0.0,
        ml_risk_score: float = 0.0,
        features: Optional[Dict[str, float]] = None,
    ) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, float], str, str, str, str]:
        """Extracts and normalizes probability vectors and disagreement states."""
        # 1. From FusionPrediction if passed
        if fusion_prediction is not None:
            p_fused = {k: float(v) for k, v in fusion_prediction.probabilities.items()}
            p_d2 = {k: float(v) for k, v in (fusion_prediction.forensic_prediction or {}).get("probabilities", {}).items()} or dict(p_fused)
            p_d3 = {k: float(v) for k, v in (fusion_prediction.semantic_prediction or {}).get("probabilities", {}).items()} or dict(p_fused)
            d_cat = fusion_prediction.disagreement_category
            strat = fusion_prediction.fusion_strategy
            d2_lbl = (fusion_prediction.forensic_prediction or {}).get("predicted_label", fusion_prediction.predicted_label)
            d3_lbl = (fusion_prediction.semantic_prediction or {}).get("predicted_class", fusion_prediction.predicted_label)
            return p_d2, p_d3, p_fused, d_cat, strat, d2_lbl, d3_lbl

        # 2. From explicit probability dictionaries or arrays if passed
        if fused_probabilities is not None or d2_probabilities is not None or d3_probabilities is not None:
            p_d2_norm = self._normalize_dist(d2_probabilities) if d2_probabilities is not None else None
            p_d3_norm = self._normalize_dist(d3_probabilities) if d3_probabilities is not None else None

            if fused_probabilities is not None:
                p_fused = self._normalize_dist(fused_probabilities)
            elif p_d2_norm is not None and p_d3_norm is not None:
                p_fused = {c: round(0.5 * (p_d2_norm[c] + p_d3_norm[c]), 6) for c in ["legitimate", "spam", "phishing"]}
            elif p_d2_norm is not None:
                p_fused = dict(p_d2_norm)
            else:
                p_fused = dict(p_d3_norm)

            p_d2 = p_d2_norm if p_d2_norm is not None else dict(p_fused)
            p_d3 = p_d3_norm if p_d3_norm is not None else dict(p_fused)
            d2_lbl = max(p_d2.items(), key=lambda x: x[1])[0]
            d3_lbl = max(p_d3.items(), key=lambda x: x[1])[0]
            d_cat = "AGREEMENT" if d2_lbl == d3_lbl else f"FORENSIC_{d2_lbl.upper()}_SEMANTIC_{d3_lbl.upper()}"
            return p_d2, p_d3, p_fused, d_cat, "explicit_probabilities", d2_lbl, d3_lbl

        # 3. From legacy ml_label / ml_confidence
        if ml_label:
            lbl = ml_label.lower()
            conf = min(1.0, max(0.0, float(ml_confidence or 0.5)))
            other_p = max(0.0, (1.0 - conf) / 2.0)
            p_dict: Dict[str, float] = {"legitimate": other_p, "spam": other_p, "phishing": other_p}
            if lbl in p_dict:
                p_dict[lbl] = conf
            else:
                p_dict["phishing"] = conf

            norm_p = self._normalize_dist(p_dict)
            return dict(norm_p), dict(norm_p), dict(norm_p), "AGREEMENT", "legacy_ml_label", lbl, lbl

        # 4. Default baseline (clean uniform)
        def_p = {"legitimate": 0.80, "spam": 0.10, "phishing": 0.10}
        return def_p, def_p, def_p, "AGREEMENT", "default_uninitialized", "legitimate", "legitimate"

    def _normalize_dist(self, p: Union[Dict[str, float], List[float], np.ndarray]) -> Dict[str, float]:
        clean: Dict[str, float] = {}
        if isinstance(p, (list, tuple, np.ndarray)):
            p_arr = [float(x) for x in p]
            if len(p_arr) == 3:
                p_dict = {"legitimate": p_arr[0], "spam": p_arr[1], "phishing": p_arr[2]}
            else:
                p_dict = {"legitimate": 0.3333, "spam": 0.3333, "phishing": 0.3334}
        elif isinstance(p, dict):
            p_dict = p
        else:
            return {"legitimate": 0.3333, "spam": 0.3333, "phishing": 0.3334}

        for c in ["legitimate", "spam", "phishing"]:
            val = float(p_dict.get(c, 0.0))
            if math.isnan(val) or math.isinf(val) or val < 0.0:
                val = 0.0
            clean[c] = val
        tot = sum(clean.values())
        if tot <= 0.0:
            return {"legitimate": 0.3333, "spam": 0.3333, "phishing": 0.3334}
        return {k: round(v / tot, 6) for k, v in clean.items()}

    def _resolve_evidence_quality(
        self,
        evidence_quality: Optional[EvidenceQuality] = None,
        fusion_prediction: Optional[FusionPrediction] = None,
        features: Optional[Dict[str, float]] = None,
        subject: Optional[str] = None,
        body: Optional[str] = None,
        auth_signals_present: int = 0,
        total_hops: int = 0,
        url_count: int = 0,
        sender: Optional[str] = None,
        domain_analyses: Optional[List[Dict[str, Any]]] = None,
        attachment_analyses: Optional[List[Dict[str, Any]]] = None,
        ip_analyses: Optional[List[Dict[str, Any]]] = None,
    ) -> EvidenceQualityBreakdown:
        b_chars = len(body or "")
        if fusion_prediction and fusion_prediction.evidence_quality:
            eq = fusion_prediction.evidence_quality
        elif evidence_quality:
            eq = evidence_quality
        else:
            feat_dict: Dict[str, float] = dict(features) if features else {}
            if subject is not None:
                feat_dict["msg_subject_length"] = float(len(subject))
                feat_dict["hdr_subject_present"] = 1.0
            if body is not None:
                b_text = str(body)
                feat_dict["msg_body_length"] = float(len(b_text))
                feat_dict["msg_body_word_count"] = float(len(b_text.split()))
                feat_dict["msg_body_line_count"] = float(len(b_text.splitlines()))
            if sender:
                feat_dict["hdr_from_present"] = 1.0
                feat_dict["ident_from_domain_entropy"] = shannon_entropy(sender.split("@")[-1])
            if auth_signals_present > 0:
                feat_dict["auth_spf_result"] = 1.0
                feat_dict["auth_dkim_result"] = 1.0
                feat_dict["auth_dmarc_result"] = 1.0
            if total_hops > 0:
                feat_dict["relay_hop_count"] = float(total_hops)
                feat_dict["msg_header_count"] = float(max(5.0, total_hops * 2.0))
            elif sender or subject:
                feat_dict["msg_header_count"] = 5.0
            if ip_analyses:
                feat_dict["ip_originating_present"] = 1.0
                feat_dict["relay_unique_ip_count"] = float(len(ip_analyses))
            if domain_analyses:
                feat_dict["domain_age_days"] = 365.0
                feat_dict["domain_risk_score"] = max((da.get("risk_score", 0.0) for da in domain_analyses), default=0.0)
            if url_count > 0:
                feat_dict["url_total_count"] = float(url_count)
            if attachment_analyses:
                feat_dict["att_total_count"] = float(len(attachment_analyses))
                feat_dict["att_total_size_bytes"] = float(sum(a.get("size", 0) for a in attachment_analyses))

            eq = self.quality_analyzer.analyze_features(feat_dict)

        # Multi-aspect breakdown:
        # Availability: overall quality Q
        avail = eq.overall_quality
        # Reliability: presence of verified auth checks
        reliab = min(1.0, 0.2 + 0.25 * auth_signals_present + (0.2 if total_hops > 0 else 0.0))
        # Consistency: 1.0 - ratio of missing flags
        consist = max(0.2, 1.0 - (len(eq.missing_evidence_flags) * 0.15))

        return EvidenceQualityBreakdown(
            availability=avail,
            reliability=reliab,
            consistency=consist,
            overall=eq.overall_quality,
            tier=eq.tier,
            missing_evidence_flags=eq.missing_evidence_flags,
            dimension_scores=eq.dimension_scores,
            body_chars=b_chars,
        )

    def _generate_explanation(
        self,
        final_risk_score: float,
        severity: RiskLevel,
        pred_threat_label: str,
        factors: List[RiskFactor],
        tvd: float,
        d2_lbl: str,
        d3_lbl: str,
        eq_breakdown: EvidenceQualityBreakdown,
    ) -> str:
        parts: List[str] = []
        parts.append(
            f"Forensic Risk Assessment: {severity.value} ({final_risk_score:.0f}/100) — Primary Threat: {pred_threat_label.upper()}."
        )

        top_factors = sorted(
            [f for f in factors if f.contribution > 0],
            key=lambda x: x.contribution,
            reverse=True,
        )[:4]

        if top_factors:
            f_strs = [f"{f.name} (+{f.contribution:.1f})" for f in top_factors]
            parts.append(f"Primary contributing indicators: {'; '.join(f_strs)}.")

        mitigating = [f for f in factors if f.contribution < 0]
        if mitigating:
            m_strs = [f"{m.name} ({m.contribution:.1f})" for m in mitigating]
            parts.append(f"Mitigating factors: {'; '.join(m_strs)}.")

        if tvd >= 0.35:
            parts.append(
                f"Modality Disagreement: Tabular model predicted '{d2_lbl}' while Text model predicted '{d3_lbl}' (TVD={tvd:.2f})."
            )

        if eq_breakdown.tier in ("LOW", "DEGRADED"):
            parts.append(
                f"Evidence Notice: Evidence quality is {eq_breakdown.tier} ({eq_breakdown.overall:.2f})."
            )

        return " ".join(parts)


_CANONICAL_ENGINE_INSTANCE: Optional[CanonicalRiskEngine] = None


def get_canonical_risk_engine(category_caps: Optional[Dict[str, float]] = None) -> CanonicalRiskEngine:
    """Retrieves or initializes the global singleton CanonicalRiskEngine."""
    global _CANONICAL_ENGINE_INSTANCE
    if _CANONICAL_ENGINE_INSTANCE is None or category_caps is not None:
        _CANONICAL_ENGINE_INSTANCE = CanonicalRiskEngine(category_caps=category_caps)
    return _CANONICAL_ENGINE_INSTANCE
