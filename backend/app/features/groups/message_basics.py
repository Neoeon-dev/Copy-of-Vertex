"""
Feature Group 1: Message Basics & Structural Container Telemetry.
Measures structural email envelope attributes, MIME boundary topologies,
header volumes, and basic length properties.
"""
from typing import Dict, Any, Tuple, Optional
import re
from app.parsers.mime_parser import ParsedEmail


def extract_message_basics(
    parsed: Optional[ParsedEmail],
    subject: Optional[str] = None,
    body: Optional[str] = None,
    has_html_flag: bool = False,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts deterministic message-level structural features.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    sub = parsed.subject if parsed and parsed.subject is not None else (subject or "")
    b = parsed.body_text or parsed.body_html if parsed else (body or "")
    b = b or ""

    # 1. Lengths and Counts
    feats["msg_subject_length"] = float(len(sub))
    exps["msg_subject_length"] = f"Subject line length is {len(sub)} characters."

    feats["msg_body_length"] = float(len(b))
    exps["msg_body_length"] = f"Body length is {len(b)} characters."

    words = re.findall(r"\w+", b)
    feats["msg_body_word_count"] = float(len(words))
    exps["msg_body_word_count"] = f"Body contains {len(words)} whitespace-delimited words."

    lines = b.splitlines()
    feats["msg_body_line_count"] = float(len(lines))
    exps["msg_body_line_count"] = f"Body contains {len(lines)} line breaks."

    # 2. Content Topologies
    has_html = bool(parsed.body_html) if parsed else has_html_flag
    feats["msg_has_html"] = 1.0 if has_html else 0.0
    exps["msg_has_html"] = "HTML formatting part present." if has_html else "No HTML part detected."

    has_plain = bool(parsed.body_text) if parsed else (not has_html_flag)
    feats["msg_has_plaintext"] = 1.0 if has_plain else 0.0
    exps["msg_has_plaintext"] = "Plaintext body part present." if has_plain else "No plaintext part detected."

    if parsed and parsed.raw_size is not None:
        raw_headers = parsed.headers
        feats["msg_header_count"] = float(len(raw_headers))
        feats["msg_is_multipart"] = 1.0 if len(parsed.attachments) > 0 or (has_html and has_plain) else 0.0
        feats["msg_mime_part_count"] = float(1 + len(parsed.attachments) + (1 if has_html and has_plain else 0))

        custom_h = sum(1 for h in raw_headers if h.name.lower().startswith("x-"))
        feats["msg_custom_header_count"] = float(custom_h)

        encoded_h = sum(1 for h in raw_headers if "=?" in h.value and "?=" in h.value)
        feats["msg_encoded_header_count"] = float(encoded_h)

        malformed_h = sum(1 for h in raw_headers if ":" not in f"{h.name}:{h.value}" or len(h.name.strip()) == 0)
        feats["msg_malformed_header_count"] = float(malformed_h)
    else:
        # Fallback when raw email headers unavailable
        feats["msg_header_count"] = -1.0
        feats["msg_is_multipart"] = 0.0
        feats["msg_mime_part_count"] = 1.0
        feats["msg_custom_header_count"] = -1.0
        feats["msg_encoded_header_count"] = 0.0
        feats["msg_malformed_header_count"] = 0.0

    return feats, exps
