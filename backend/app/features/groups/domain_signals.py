"""
Feature Group 7: Domain Structure & Brand Impersonation Telemetry.
Calculates lexical, entropy, punycode, and homoglyph metrics for sender domains.
"""
from typing import Dict, Any, Tuple, Optional
import math
from collections import Counter
import email.utils

from app.forensics.dmarc_analyzer import extract_domain_from_address
from app.forensics.domain_intel import SUSPICIOUS_TLDS, _has_homoglyphs


def _compute_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy (base 2) of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_domain_signals(
    from_raw: Optional[str] = None,
    domain: Optional[str] = None,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts deterministic domain features for the sender domain.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    target_domain = domain
    if not target_domain and from_raw:
        _, addr = email.utils.parseaddr(from_raw)
        target_domain = extract_domain_from_address(addr or from_raw)

    if not target_domain:
        feats["dom_sender_length"] = 0.0
        feats["dom_sender_label_count"] = 0.0
        feats["dom_sender_subdomain_depth"] = 0.0
        feats["dom_sender_numeric_count"] = 0.0
        feats["dom_sender_hyphen_count"] = 0.0
        feats["dom_sender_digit_ratio"] = 0.0
        feats["dom_sender_punycode"] = 0.0
        feats["dom_sender_suspicious_tld"] = 0.0
        feats["dom_sender_cctld"] = 0.0
        feats["dom_sender_homoglyph"] = 0.0
        feats["dom_sender_entropy"] = 0.0
        return feats, exps

    d_clean = target_domain.lower().strip().rstrip(".")
    d_len = len(d_clean)
    labels = d_clean.split(".")

    feats["dom_sender_length"] = float(d_len)
    feats["dom_sender_label_count"] = float(len(labels))
    feats["dom_sender_subdomain_depth"] = float(max(0, len(labels) - 2))

    num_count = sum(1 for c in d_clean if c.isdigit())
    hyphen_count = d_clean.count("-")
    feats["dom_sender_numeric_count"] = float(num_count)
    feats["dom_sender_hyphen_count"] = float(hyphen_count)
    feats["dom_sender_digit_ratio"] = float(num_count / d_len) if d_len > 0 else 0.0

    # Punycode
    is_puny = 1.0 if ("xn--" in d_clean) else 0.0
    feats["dom_sender_punycode"] = is_puny

    # TLD checks
    tld = labels[-1] if labels else ""
    feats["dom_sender_suspicious_tld"] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
    feats["dom_sender_cctld"] = 1.0 if (len(tld) == 2 and tld.isalpha()) else 0.0

    # Homoglyphs
    feats["dom_sender_homoglyph"] = 1.0 if _has_homoglyphs(target_domain) else 0.0

    # Shannon entropy
    feats["dom_sender_entropy"] = round(_compute_shannon_entropy(d_clean), 4)

    return feats, exps
