"""
Evidence Quality Analyzer for VERTEX Multimodal Fusion (Phase D4).
Measures observable email evidence availability and integrity across 10 dimensions.
Produces a continuous evidence score Q in [0.0, 1.0] and categorical quality tier.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union
import numpy as np

from app.features.registry import get_feature_names
from app.data.schema import CanonicalEmailRecord
from app.ml.fusion.schemas import (
    EvidenceDimensionScore,
    EvidenceQuality,
    QualityTier,
)

logger = logging.getLogger(__name__)


# Standardized weights across the 10 observable dimensions (sums to 1.00)
DIMENSION_WEIGHTS: Dict[str, float] = {
    "rfc822_headers": 0.15,
    "auth_alignment": 0.15,
    "relay_hops": 0.10,
    "network_ip": 0.10,
    "domain_reputation": 0.10,
    "url_signals": 0.10,
    "attachment_metadata": 0.05,
    "body_content": 0.10,
    "sender_envelope_alignment": 0.05,
    "forensic_feature_density": 0.10,
}


class EvidenceQualityAnalyzer:
    """
    Evaluates evidence quality across 10 observable dimensions.
    Operates on feature dictionaries, numpy arrays, CanonicalEmailRecords, or raw components.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights = weights or dict(DIMENSION_WEIGHTS)
        total_w = sum(self.weights.values())
        if abs(total_w - 1.0) > 1e-4:
            self.weights = {k: v / total_w for k, v in self.weights.items()}

        self.feature_names = get_feature_names()
        self.feature_name_to_idx = {name: idx for idx, name in enumerate(self.feature_names)}

    def analyze_features(self, features: Union[Dict[str, float], np.ndarray]) -> EvidenceQuality:
        """
        Analyzes evidence quality from a dictionary or array of 125 tabular features.
        """
        if isinstance(features, np.ndarray):
            feat_dict = {
                name: float(features[idx]) if idx < len(features) else -1.0
                for idx, name in enumerate(self.feature_names)
            }
        else:
            feat_dict = features

        dimension_scores: Dict[str, float] = {}
        dimension_details: List[EvidenceDimensionScore] = []
        missing_flags: List[str] = []

        # 1. RFC822 Headers
        hdr_from = feat_dict.get("hdr_from_present", -1.0)
        hdr_to = feat_dict.get("hdr_to_present", -1.0)
        hdr_date = feat_dict.get("hdr_date_present", -1.0)
        hdr_msg_id = feat_dict.get("hdr_message_id_present", -1.0)
        hdr_count = feat_dict.get("msg_header_count", -1.0)
        core_hdrs = sum(1 for s in [hdr_from, hdr_to, hdr_date, hdr_msg_id] if s > 0.0)

        if hdr_count >= 5.0 and core_hdrs >= 2:
            hdr_score = 1.0
        elif hdr_count > 0.0 or core_hdrs > 0:
            hdr_score = min(1.0, 0.2 + 0.2 * max(core_hdrs, 1))
        else:
            hdr_score = 0.0
            missing_flags.append("missing_rfc822_headers")

        dimension_scores["rfc822_headers"] = hdr_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="rfc822_headers",
                score=hdr_score,
                weight=self.weights["rfc822_headers"],
                active_signals=core_hdrs + (1 if hdr_count > 0 else 0),
                total_signals=5,
                description=f"RFC822 header count: {max(0.0, hdr_count)}, core headers: {core_hdrs}/4",
            )
        )

        # 2. Authentication Alignment (SPF, DKIM, DMARC)
        spf_res = feat_dict.get("auth_spf_result", -1.0)
        dkim_res = feat_dict.get("auth_dkim_result", -1.0)
        dmarc_res = feat_dict.get("auth_dmarc_result", -1.0)
        auth_signals = [spf_res, dkim_res, dmarc_res]
        active_auth = sum(1 for a in auth_signals if a != -1.0)
        auth_score = active_auth / 3.0
        if auth_score == 0.0:
            missing_flags.append("missing_authentication")
        dimension_scores["auth_alignment"] = auth_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="auth_alignment",
                score=auth_score,
                weight=self.weights["auth_alignment"],
                active_signals=active_auth,
                total_signals=3,
                description=f"Authentication records available: {active_auth}/3 (SPF, DKIM, DMARC)",
            )
        )

        # 3. Relay Hops
        hop_count = feat_dict.get("relay_hop_count", -1.0)
        relay_ips = feat_dict.get("relay_unique_ip_count", -1.0)
        if hop_count > 0:
            relay_score = min(1.0, 0.4 + 0.2 * min(hop_count, 3))
        else:
            relay_score = 0.0
            missing_flags.append("missing_relay_path")
        dimension_scores["relay_hops"] = relay_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="relay_hops",
                score=relay_score,
                weight=self.weights["relay_hops"],
                active_signals=1 if hop_count > 0 else 0,
                total_signals=2,
                description=f"Received relay hops: {max(0.0, hop_count)}, unique relay IPs: {max(0.0, relay_ips)}",
            )
        )

        # 4. Network IP
        ip_orig_pres = feat_dict.get("ip_originating_present", -1.0)
        if ip_orig_pres > 0.0:
            ip_score = 1.0
        else:
            ip_score = 0.0
            missing_flags.append("missing_originating_ip")
        dimension_scores["network_ip"] = ip_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="network_ip",
                score=ip_score,
                weight=self.weights["network_ip"],
                active_signals=1 if ip_orig_pres > 0.0 else 0,
                total_signals=1,
                description=f"Originating network IP identified: {ip_orig_pres > 0.0}",
            )
        )

        # 5. Domain Reputation / Signals
        dom_len = feat_dict.get("dom_sender_length", -1.0)
        if dom_len > 0.0:
            dom_score = 1.0
        else:
            dom_score = 0.0
            missing_flags.append("missing_sender_domain")
        dimension_scores["domain_reputation"] = dom_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="domain_reputation",
                score=dom_score,
                weight=self.weights["domain_reputation"],
                active_signals=1 if dom_len > 0.0 else 0,
                total_signals=1,
                description=f"Sender domain metadata extracted (len={max(0.0, dom_len)})",
            )
        )

        # 6. URL Signals
        url_cnt = feat_dict.get("url_total_count", -1.0)
        url_uniq = feat_dict.get("url_unique_count", -1.0)
        if url_cnt > 0.0:
            url_score = 1.0
        elif url_cnt == 0.0:
            url_score = 0.6 if hdr_score > 0.0 else 0.1
        else:
            url_score = 0.0
            missing_flags.append("missing_url_extraction")
        dimension_scores["url_signals"] = url_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="url_signals",
                score=url_score,
                weight=self.weights["url_signals"],
                active_signals=1 if url_cnt >= 0.0 else 0,
                total_signals=2,
                description=f"URLs detected: {max(0.0, url_cnt)}, unique: {max(0.0, url_uniq)}",
            )
        )

        # 7. Attachment Metadata
        att_cnt = feat_dict.get("att_total_count", -1.0)
        if att_cnt > 0.0:
            att_score = 1.0
        elif att_cnt == 0.0:
            att_score = 0.6 if hdr_score > 0.0 else 0.1
        else:
            att_score = 0.0
            missing_flags.append("missing_attachment_metadata")
        dimension_scores["attachment_metadata"] = att_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="attachment_metadata",
                score=att_score,
                weight=self.weights["attachment_metadata"],
                active_signals=1 if att_cnt >= 0.0 else 0,
                total_signals=1,
                description=f"Attachment inspection active: {att_cnt >= 0.0} (count: {max(0.0, att_cnt)})",
            )
        )

        # 8. Body Content Richness
        body_words = feat_dict.get("msg_body_word_count", -1.0)
        body_chars = feat_dict.get("msg_body_length", -1.0)
        if body_words >= 50.0:
            body_score = 1.0
        elif body_words >= 20.0:
            body_score = 0.85
        elif body_words >= 10.0:
            body_score = 0.55
        elif body_words >= 3.0:
            body_score = 0.30
        elif body_words > 0.0:
            body_score = 0.15
        else:
            body_score = 0.0
            missing_flags.append("empty_body_text")
        dimension_scores["body_content"] = body_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="body_content",
                score=body_score,
                weight=self.weights["body_content"],
                active_signals=1 if body_words > 0 else 0,
                total_signals=2,
                description=f"Body length: {max(0.0, body_chars)} chars, {max(0.0, body_words)} words",
            )
        )

        # 9. Sender Envelope Alignment
        addr_fail = feat_dict.get("ident_address_parsing_failure", -1.0)
        mismatch = feat_dict.get("ident_from_reply_to_mismatch", -1.0)
        if addr_fail == 0.0 and hdr_from > 0.0:
            env_score = 1.0
        elif addr_fail != -1.0 and hdr_from > 0.0:
            env_score = 0.5
        else:
            env_score = 0.0
            missing_flags.append("missing_sender_identity")
        dimension_scores["sender_envelope_alignment"] = env_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="sender_envelope_alignment",
                score=env_score,
                weight=self.weights["sender_envelope_alignment"],
                active_signals=1 if addr_fail != -1.0 else 0,
                total_signals=2,
                description=f"Address parsing valid: {addr_fail == 0.0}, reply-to mismatch: {mismatch == 1.0}",
            )
        )

        # 10. Forensic Feature Density
        non_neg = sum(1 for v in feat_dict.values() if v != -1.0)
        raw_density = non_neg / 125.0
        density_score = raw_density if hdr_score > 0.0 else raw_density * 0.25
        dimension_scores["forensic_feature_density"] = density_score
        dimension_details.append(
            EvidenceDimensionScore(
                dimension_name="forensic_feature_density",
                score=density_score,
                weight=self.weights["forensic_feature_density"],
                active_signals=non_neg,
                total_signals=125,
                description=f"Active non-missing tabular features: {non_neg}/125 ({raw_density:.1%})",
            )
        )

        # Overall weighted Q in [0.0, 1.0]
        overall_q = sum(dimension_scores[dim] * self.weights[dim] for dim in self.weights)
        overall_q = min(max(overall_q, 0.0), 1.0)

        # Categorical Tier assignment
        if overall_q >= 0.70:
            tier = QualityTier.HIGH.value
        elif overall_q >= 0.40:
            tier = QualityTier.MEDIUM.value
        elif overall_q >= 0.20:
            tier = QualityTier.LOW.value
        else:
            tier = QualityTier.DEGRADED.value

        return EvidenceQuality(
            overall_quality=overall_q,
            tier=tier,
            dimension_scores=dimension_scores,
            dimension_details=dimension_details,
            missing_evidence_flags=missing_flags,
            active_features_count=non_neg,
            total_features_count=125,
        )

    def analyze_record(self, record: CanonicalEmailRecord) -> EvidenceQuality:
        """
        Analyzes evidence quality directly from a CanonicalEmailRecord.
        """
        from app.features.extractor import ForensicFeatureExtractor
        extractor = ForensicFeatureExtractor()
        if hasattr(extractor, "extract_from_record"):
            vec = extractor.extract_from_record(record)
        else:
            vec = extractor.extract_from_canonical_record(record)
        return self.analyze_features(vec.features)

    def analyze_raw(
        self,
        subject: Optional[str] = None,
        body: Optional[str] = None,
        headers: Optional[Dict[str, Any]] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> EvidenceQuality:
        """
        Analyzes evidence quality from raw components.
        """
        if raw_bytes is not None:
            from app.features.extractor import ForensicFeatureExtractor
            extractor = ForensicFeatureExtractor()
            vec = extractor.extract_from_raw_bytes(raw_bytes)
            return self.analyze_features(vec.features)

        feat_dict: Dict[str, float] = {fname: -1.0 for fname in self.feature_names}

        s_len = len(subject or "")
        b_text = body or ""
        b_len = len(b_text)
        b_words = len(b_text.split()) if b_text else 0
        b_lines = len(b_text.splitlines()) if b_text else 0

        feat_dict["msg_subject_length"] = float(s_len)
        feat_dict["msg_body_length"] = float(b_len)
        feat_dict["msg_body_word_count"] = float(b_words)
        feat_dict["msg_body_line_count"] = float(b_lines)

        if headers:
            feat_dict["msg_header_count"] = float(len(headers))
            h_lower = {k.lower(): v for k, v in headers.items()}
            feat_dict["hdr_from_present"] = 1.0 if "from" in h_lower else 0.0
            feat_dict["hdr_to_present"] = 1.0 if "to" in h_lower else 0.0
            feat_dict["hdr_date_present"] = 1.0 if "date" in h_lower else 0.0
            feat_dict["hdr_message_id_present"] = 1.0 if "message-id" in h_lower else 0.0

        return self.analyze_features(feat_dict)
