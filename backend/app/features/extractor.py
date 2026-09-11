"""
VERTEX Forensic Feature Extraction Orchestrator.
Orchestrates 11 feature groups across raw email evidence and canonical tabular records,
guaranteeing complete schema compliance, zero-target-leakage, and deterministic outputs.
"""
from typing import Dict, Any, Optional, Union, List
import os
import logging
import email.utils

from app.features.schema import FeatureVector
from app.features.registry import get_feature_registry, get_feature_names
from app.features.validators import validate_feature_vector
from app.features.version import FORENSIC_FEATURE_VERSION, FEATURE_EXTRACTOR_VERSION

from app.parsers.mime_parser import parse_email, ParsedEmail
from app.data.schema import CanonicalEmailRecord

from app.features.groups.message_basics import extract_message_basics
from app.features.groups.header_signals import extract_header_signals
from app.features.groups.authentication_signals import extract_authentication_signals
from app.features.groups.identity_consistency import extract_identity_consistency
from app.features.groups.relay_path import extract_relay_path
from app.features.groups.ip_infrastructure import extract_ip_infrastructure
from app.features.groups.domain_signals import extract_domain_signals
from app.features.groups.url_signals import extract_url_signals
from app.features.groups.attachment_signals import extract_attachment_signals
from app.features.groups.content_structure import extract_content_structure
from app.features.groups.bec_phish_signals import extract_bec_phish_signals

from app.forensics.spf_analyzer import analyze_spf
from app.forensics.dkim_analyzer import analyze_dkim
from app.forensics.dmarc_analyzer import analyze_dmarc, extract_domain_from_address

logger = logging.getLogger(__name__)


class ForensicFeatureExtractor:
    """
    Extracts forensic features from parsed MIME structures, raw RFC822 bytes,
    or Phase C canonical records.
    """

    def __init__(self):
        self.registry = get_feature_registry()
        self.registry_names = get_feature_names()
        self._defaults = {f.name: f.default_value for f in self.registry}

    def _build_auth_results(
        self,
        parsed: ParsedEmail,
        raw_bytes: Optional[bytes],
    ) -> Dict[str, Any]:
        """Runs SPF, DKIM, and DMARC analyzers on raw headers and bytes."""
        headers_dict: Dict[str, Union[str, List[str]]] = {}
        for h in parsed.headers:
            name_lower = h.name.lower()
            if name_lower in headers_dict:
                existing = headers_dict[name_lower]
                if isinstance(existing, list):
                    existing.append(h.value)
                else:
                    headers_dict[name_lower] = [existing, h.value]
            else:
                headers_dict[name_lower] = h.value

        from_domain = extract_domain_from_address(parsed.sender or "")

        spf = analyze_spf(headers=headers_dict, email_sender_domain=from_domain)
        dkim_results = analyze_dkim(
            headers=headers_dict,
            raw_email_bytes=raw_bytes,
            email_sender_domain=from_domain,
        )
        dkim_best = dkim_results[0] if dkim_results else None

        spf_envelope_domain = spf.domain if spf.domain != from_domain else None
        dmarc = analyze_dmarc(
            email_sender_domain=from_domain,
            spf_result=spf.result,
            spf_envelope_domain=spf_envelope_domain,
            dkim_result=dkim_best.result if dkim_best else None,
            dkim_domain=dkim_best.domain if dkim_best else None,
        )

        return {
            "spf": {"result": spf.result, "domain": spf.domain},
            "dkim": {
                "result": dkim_best.result if dkim_best else "none",
                "signature_count": len(dkim_results),
                "reason": dkim_best.details if dkim_best else "",
            },
            "dmarc": {
                "result": dmarc.result,
                "policy": dmarc.policy,
                "alignment": {
                    "spf_aligned": dmarc.spf_aligned,
                    "dkim_aligned": dmarc.dkim_aligned,
                },
            },
        }

    def extract_from_parsed_email(
        self,
        parsed: ParsedEmail,
        raw_bytes: Optional[bytes] = None,
        record_id: Optional[str] = None,
        source_dataset: str = "raw_eml",
        normalized_label: Optional[str] = None,
        threat_type: Optional[str] = None,
    ) -> FeatureVector:
        """Extracts complete feature vector from a ParsedEmail object."""
        rec_id = record_id or (parsed.raw_sha256[:16] if parsed.raw_sha256 else "unknown_record")
        raw_evidence_available = True

        all_features: Dict[str, float] = {}
        all_explanations: Dict[str, str] = {}

        # 1. Message Basics
        f, e = extract_message_basics(
            parsed=parsed,
            subject=parsed.subject,
            body=parsed.body_text or parsed.body_html,
            has_html_flag=bool(parsed.body_html),
        )
        all_features.update(f)
        all_explanations.update(e)

        # 2. Header Signals
        f, e = extract_header_signals(parsed=parsed)
        all_features.update(f)
        all_explanations.update(e)

        # 3. Authentication Signals
        auth_res = self._build_auth_results(parsed, raw_bytes)
        f, e = extract_authentication_signals(auth_res, raw_evidence_available=True)
        all_features.update(f)
        all_explanations.update(e)

        # 4. Identity Consistency
        from_header_val = None
        reply_to_val = None
        return_path_val = None
        for h in parsed.headers:
            nl = h.name.lower()
            if nl == "from" and not from_header_val:
                from_header_val = h.value
            elif nl == "reply-to":
                reply_to_val = h.value
            elif nl == "return-path":
                return_path_val = h.value

        if not from_header_val and parsed.sender:
            from_header_val = f'"{parsed.sender_name}" <{parsed.sender}>' if parsed.sender_name else parsed.sender

        f, e = extract_identity_consistency(
            from_raw=from_header_val,
            reply_to_raw=reply_to_val,
            return_path_raw=return_path_val,
        )
        all_features.update(f)
        all_explanations.update(e)

        # 5. Relay Path
        f, e = extract_relay_path(parsed=parsed, raw_evidence_available=True)
        all_features.update(f)
        all_explanations.update(e)

        # 6. IP Infrastructure
        f, e = extract_ip_infrastructure(parsed=parsed, raw_evidence_available=True)
        all_features.update(f)
        all_explanations.update(e)

        # 7. Domain Signals
        f, e = extract_domain_signals(from_raw=parsed.sender)
        all_features.update(f)
        all_explanations.update(e)

        # 8. URL Signals
        f, e = extract_url_signals(body_text=parsed.body_text, body_html=parsed.body_html)
        all_features.update(f)
        all_explanations.update(e)

        # 9. Attachment Signals
        f, e = extract_attachment_signals(parsed=parsed)
        all_features.update(f)
        all_explanations.update(e)

        # 10. Content Structure
        f, e = extract_content_structure(
            subject=parsed.subject,
            body_text=parsed.body_text,
            body_html=parsed.body_html,
        )
        all_features.update(f)
        all_explanations.update(e)

        # 11. BEC & Phish Semantic Cues
        f, e = extract_bec_phish_signals(
            subject=parsed.subject,
            body_text=parsed.body_text or parsed.body_html,
            sender_name=parsed.sender_name,
        )
        all_features.update(f)
        all_explanations.update(e)

        # Ensure all registered features are present
        for name, default_val in self._defaults.items():
            if name not in all_features:
                all_features[name] = default_val

        vec = FeatureVector(
            record_id=rec_id,
            source_dataset=source_dataset,
            normalized_label=normalized_label,
            threat_type=threat_type,
            raw_evidence_available=raw_evidence_available,
            feature_version=FORENSIC_FEATURE_VERSION,
            extractor_version=FEATURE_EXTRACTOR_VERSION,
            features=all_features,
            explanations=all_explanations,
        )

        is_valid, errors = validate_feature_vector(vec)
        if not is_valid:
            raise ValueError(f"Feature vector validation failed: {errors}")

        return vec

    def extract_from_raw_bytes(
        self,
        raw_bytes: bytes,
        record_id: Optional[str] = None,
        source_dataset: str = "raw_eml",
        normalized_label: Optional[str] = None,
        threat_type: Optional[str] = None,
    ) -> FeatureVector:
        """Parses raw RFC822 bytes and extracts features."""
        parsed = parse_email(raw_bytes)
        return self.extract_from_parsed_email(
            parsed=parsed,
            raw_bytes=raw_bytes,
            record_id=record_id,
            source_dataset=source_dataset,
            normalized_label=normalized_label,
            threat_type=threat_type,
        )

    def extract_from_canonical_record(
        self,
        record: Union[CanonicalEmailRecord, Dict[str, Any]],
    ) -> FeatureVector:
        """
        Extracts feature vector from a CanonicalEmailRecord or dictionary.
        Gracefully leverages raw file on disk if available; otherwise falls back
        to textual, domain, URL, content, and semantic extraction with calibrated defaults.
        """
        if isinstance(record, dict):
            rec_id = record.get("record_id", "rec_unknown")
            src_ds = record.get("source_dataset", "unknown")
            norm_label = record.get("normalized_label")
            threat_type = record.get("threat_type")
            sub = record.get("subject") or ""
            body = record.get("body") or ""
            sender = record.get("sender") or ""
            recipient = record.get("recipient") or ""
            reply_to = record.get("reply_to") or ""
            date_val = str(record.get("date") or "")
            msg_id = record.get("message_id") or ""
            has_html_flag = bool(record.get("has_html", False))
            raw_available = bool(record.get("raw_email_available", False))
            raw_path = record.get("raw_file_path")
        else:
            rec_id = record.record_id
            src_ds = record.source_dataset
            norm_label = record.normalized_label
            threat_type = record.threat_type
            sub = record.subject or ""
            body = record.body or ""
            sender = record.sender or ""
            recipient = record.recipient or ""
            reply_to = record.reply_to or ""
            date_val = str(record.date or "")
            msg_id = record.message_id or ""
            has_html_flag = record.has_html
            raw_available = record.raw_email_available
            raw_path = record.raw_file_path

        # If raw email file is present on disk, parse it for full forensic depth
        if raw_available and raw_path and os.path.exists(raw_path):
            try:
                with open(raw_path, "rb") as f:
                    raw_bytes = f.read()
                return self.extract_from_raw_bytes(
                    raw_bytes=raw_bytes,
                    record_id=rec_id,
                    source_dataset=src_ds,
                    normalized_label=norm_label,
                    threat_type=threat_type,
                )
            except Exception as e:
                logger.warning("Failed to parse raw email at %s: %s; falling back to tabular", raw_path, e)

        # Tabular / text-only extraction
        all_features: Dict[str, float] = {}
        all_explanations: Dict[str, str] = {}

        # 1. Message Basics
        f, e = extract_message_basics(
            parsed=None,
            subject=sub,
            body=body,
            has_html_flag=has_html_flag,
        )
        all_features.update(f)
        all_explanations.update(e)

        # 2. Header Signals (fallback defaults)
        f, e = extract_header_signals(
            parsed=None,
            sender=sender,
            recipient=recipient,
            reply_to=reply_to,
            date=date_val,
            message_id=msg_id,
        )
        all_features.update(f)
        all_explanations.update(e)

        # 3. Authentication Signals (calibrated missing defaults)
        f, e = extract_authentication_signals(auth_results=None, raw_evidence_available=False)
        all_features.update(f)
        all_explanations.update(e)

        # 4. Identity Consistency
        f, e = extract_identity_consistency(
            from_raw=sender,
            reply_to_raw=reply_to,
            return_path_raw=None,
        )
        all_features.update(f)
        all_explanations.update(e)

        # 5. Relay Path (calibrated missing defaults)
        f, e = extract_relay_path(parsed=None, raw_evidence_available=False)
        all_features.update(f)
        all_explanations.update(e)

        # 6. IP Infrastructure (calibrated missing defaults)
        f, e = extract_ip_infrastructure(parsed=None, raw_evidence_available=False)
        all_features.update(f)
        all_explanations.update(e)

        # 7. Domain Signals
        f, e = extract_domain_signals(from_raw=sender)
        all_features.update(f)
        all_explanations.update(e)

        # 8. URL Signals
        f, e = extract_url_signals(body_text=body, body_html=None)
        all_features.update(f)
        all_explanations.update(e)

        # 9. Attachment Signals
        f, e = extract_attachment_signals(parsed=None)
        all_features.update(f)
        all_explanations.update(e)

        # 10. Content Structure
        f, e = extract_content_structure(subject=sub, body_text=body, body_html=None)
        all_features.update(f)
        all_explanations.update(e)

        # 11. BEC & Phish Semantic Cues
        disp_name, _ = email.utils.parseaddr(sender or "")
        f, e = extract_bec_phish_signals(subject=sub, body_text=body, sender_name=disp_name)
        all_features.update(f)
        all_explanations.update(e)

        # Ensure all registered features are present
        for name, default_val in self._defaults.items():
            if name not in all_features:
                all_features[name] = default_val

        vec = FeatureVector(
            record_id=rec_id,
            source_dataset=src_ds,
            normalized_label=norm_label,
            threat_type=threat_type,
            raw_evidence_available=False,
            feature_version=FORENSIC_FEATURE_VERSION,
            extractor_version=FEATURE_EXTRACTOR_VERSION,
            features=all_features,
            explanations=all_explanations,
        )

        is_valid, errors = validate_feature_vector(vec)
        if not is_valid:
            raise ValueError(f"Feature vector validation failed: {errors}")

        return vec

    extract_from_record = extract_from_canonical_record
