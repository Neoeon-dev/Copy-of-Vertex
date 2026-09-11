"""
Feature Group 2: Header Structure & Presence Signals.
Analyzes standard RFC 5322 header topology, security-critical field presence,
mailer telemetry, and header duplication anomalies.
"""
from typing import Dict, Any, Tuple, Optional
from collections import Counter
from app.parsers.mime_parser import ParsedEmail


def extract_header_signals(
    parsed: Optional[ParsedEmail],
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    reply_to: Optional[str] = None,
    date: Optional[str] = None,
    message_id: Optional[str] = None,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts structural header presence and anomaly indicators.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    if parsed and parsed.headers:
        header_names = [h.name.lower() for h in parsed.headers]
        h_set = set(header_names)
        h_counts = Counter(header_names)

        feats["hdr_from_present"] = 1.0 if "from" in h_set else 0.0
        feats["hdr_to_present"] = 1.0 if "to" in h_set else 0.0
        feats["hdr_cc_present"] = 1.0 if "cc" in h_set else 0.0
        feats["hdr_reply_to_present"] = 1.0 if "reply-to" in h_set else 0.0
        feats["hdr_return_path_present"] = 1.0 if "return-path" in h_set else 0.0
        feats["hdr_message_id_present"] = 1.0 if "message-id" in h_set else 0.0
        feats["hdr_date_present"] = 1.0 if "date" in h_set else 0.0
        feats["hdr_received_present"] = 1.0 if "received" in h_set else 0.0
        feats["hdr_auth_results_present"] = 1.0 if "authentication-results" in h_set else 0.0
        feats["hdr_x_originating_ip_present"] = 1.0 if "x-originating-ip" in h_set else 0.0
        feats["hdr_user_agent_present"] = 1.0 if "user-agent" in h_set else 0.0
        feats["hdr_x_mailer_present"] = 1.0 if "x-mailer" in h_set else 0.0
        feats["hdr_list_unsubscribe_present"] = 1.0 if "list-unsubscribe" in h_set else 0.0

        feats["hdr_received_count"] = float(h_counts.get("received", 0))

        # Check for illegal duplicate security-sensitive headers (RFC 5322 Section 3.6)
        security_headers = ["from", "to", "subject", "date", "message-id"]
        has_dup = any(h_counts.get(h, 0) > 1 for h in security_headers)
        feats["hdr_duplicate_security_headers"] = 1.0 if has_dup else 0.0
        exps["hdr_duplicate_security_headers"] = (
            "Duplicate security-sensitive headers detected (potential header injection/evasion)."
            if has_dup else "No duplicate security headers found."
        )
    else:
        # Fallback when only canonical structured fields are provided
        feats["hdr_from_present"] = 1.0 if sender else 0.0
        feats["hdr_to_present"] = 1.0 if recipient else 0.0
        feats["hdr_cc_present"] = 0.0
        feats["hdr_reply_to_present"] = 1.0 if reply_to else 0.0
        feats["hdr_return_path_present"] = -1.0  # unknown without raw headers
        feats["hdr_message_id_present"] = 1.0 if message_id else 0.0
        feats["hdr_date_present"] = 1.0 if date else 0.0
        feats["hdr_received_present"] = -1.0
        feats["hdr_auth_results_present"] = -1.0
        feats["hdr_x_originating_ip_present"] = -1.0
        feats["hdr_user_agent_present"] = -1.0
        feats["hdr_x_mailer_present"] = -1.0
        feats["hdr_list_unsubscribe_present"] = -1.0
        feats["hdr_received_count"] = -1.0
        feats["hdr_duplicate_security_headers"] = 0.0

    return feats, exps
