"""Domain intelligence and lookalike detection.

Analyzes domains found in email headers and body for:
- Brand impersonation via Levenshtein distance
- Homoglyph / punycode detection
- Token similarity
- Suspicious TLDs
- Configurable brand dictionary
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Common suspicious TLDs used in phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "info", "buzz", "icu", "tk", "ml", "ga",
    "cf", "gq", "click", "download", "racing", "win", "bid", "loan",
}

# Common brand dictionary for lookalike detection
DEFAULT_BRANDS = {
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "netflix.com", "bankofamerica.com", "wellsfargo.com", "chase.com",
    "dropbox.com", "dhl.com", "fedex.com", "ups.com",
}

# Homoglyph mapping (characters that look like Latin letters)
HOMOGLYPHS = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0501": "o",  # Cyrillic Ԁ
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
    "\uff10": "0", "\uff11": "1", "\uff12": "2", "\uff13": "3",
    "\uff14": "4", "\uff15": "5", "\uff16": "6", "\uff17": "7",
    "\uff18": "8", "\uff19": "9",
}


def _normalize_domain(domain: str) -> str:
    """Normalize a domain: lowercase, strip, normalize unicode."""
    d = domain.lower().strip().rstrip(".")
    # NFKC normalization catches many unicode tricks
    d = unicodedata.normalize("NFKC", d)
    return d


def _to_ascii(domain: str) -> str:
    """Convert to ASCII/punycode form if possible."""
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain


def _has_homoglyphs(domain: str) -> bool:
    """Check if the domain contains non-Latin characters that look like Latin."""
    for char in domain:
        if char in HOMOGLYPHS:
            return True
    return False


def _homoglyph_to_latin(domain: str) -> str:
    """Replace homoglyphs with their Latin equivalents."""
    return "".join(HOMOGLYPHS.get(c, c) for c in domain)


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _domain_tokens(domain: str) -> set[str]:
    """Split a domain into meaningful tokens (subdomains, labels)."""
    parts = re.split(r"[.\-]", domain.lower())
    return set(p for p in parts if len(p) > 1)


@dataclass
class DomainLookalike:
    """A potential lookalike match."""

    brand_domain: str
    distance: int
    similarity_pct: float
    match_type: str  # levenshtein | homoglyph | token | punycode


@dataclass
class DomainAnalysis:
    """Complete domain intelligence analysis."""

    domain: str
    normalized: str
    ascii_form: str | None = None
    has_homoglyphs: bool = False
    has_punycode: bool = False
    suspicious_tld: bool = False
    lookalikes: list[DomainLookalike] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 – 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "normalized": self.normalized,
            "ascii_form": self.ascii_form,
            "has_homoglyphs": self.has_homoglyphs,
            "has_punycode": self.has_punycode,
            "suspicious_tld": self.suspicious_tld,
            "lookalikes": [
                {
                    "brand_domain": l.brand_domain,
                    "distance": l.distance,
                    "similarity_pct": l.similarity_pct,
                    "match_type": l.match_type,
                }
                for l in self.lookalikes
            ],
            "warnings": self.warnings,
            "risk_score": self.risk_score,
        }


def analyze_domain(
    domain: str,
    brands: set[str] | None = None,
) -> DomainAnalysis:
    """Perform domain intelligence analysis.

    Args:
        domain: The domain to analyze
        brands: Set of legitimate brand domains to check against
    """
    if brands is None:
        brands = DEFAULT_BRANDS

    normalized = _normalize_domain(domain)
    ascii_form = _to_ascii(normalized)

    analysis = DomainAnalysis(
        domain=domain,
        normalized=normalized,
        ascii_form=ascii_form if ascii_form != normalized else None,
    )

    # Check for punycode
    if ascii_form and ascii_form.startswith("xn--"):
        analysis.has_punycode = True
        analysis.warnings.append("Domain uses punycode encoding")

    # Check for homoglyphs
    if _has_homoglyphs(normalized):
        analysis.has_homoglyphs = True
        latin_version = _homoglyph_to_latin(normalized)
        analysis.warnings.append(
            f"Domain contains non-Latin homoglyphs; Latin equivalent: {latin_version}"
        )

    # Check suspicious TLD
    tld = normalized.rsplit(".", 1)[-1] if "." in normalized else ""
    if tld in SUSPICIOUS_TLDS:
        analysis.suspicious_tld = True
        analysis.warnings.append(f"Suspicious TLD: .{tld}")

    # Lookalike detection
    check_domain = _homoglyph_to_latin(normalized) if analysis.has_homoglyphs else normalized
    for brand in brands:
        brand_norm = _normalize_domain(brand)

        # Skip exact matches
        if check_domain == brand_norm:
            continue

        # Check main domain (without subdomains)
        check_main = check_domain.rsplit(".", 2)[-2] + "." + check_domain.rsplit(".", 2)[-1] if check_domain.count(".") >= 1 else check_domain
        brand_main = brand_norm

        # Levenshtein distance on the main domain
        dist = _levenshtein(check_main, brand_main)
        max_len = max(len(check_main), len(brand_main))
        similarity = (1 - dist / max_len) * 100 if max_len > 0 else 0

        if dist <= 3 and dist > 0:
            analysis.lookalikes.append(DomainLookalike(
                brand_domain=brand,
                distance=dist,
                similarity_pct=round(similarity, 1),
                match_type="levenshtein",
            ))
            analysis.warnings.append(
                f"Possible lookalike of {brand} (distance={dist}, similarity={similarity:.0f}%)"
            )

    # Compute risk score
    risk = 0.0
    if analysis.has_homoglyphs:
        risk += 0.4
    if analysis.has_punycode:
        risk += 0.3
    if analysis.suspicious_tld:
        risk += 0.15
    if analysis.lookalikes:
        risk += min(0.3, len(analysis.lookalikes) * 0.15)
    analysis.risk_score = min(1.0, risk)

    return analysis


def extract_domains_from_headers(
    headers: dict[str, str | list[str]],
) -> list[str]:
    """Extract unique domains from email headers (From, Reply-To, etc.)."""
    domains: set[str] = set()
    email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

    for key in ("from", "reply-to", "sender"):
        values = headers.get(key, [])
        if not isinstance(values, list):
            values = [values]
        for val in values:
            if val:
                for match in email_pattern.finditer(val):
                    domains.add(match.group(1).lower().rstrip("."))

    return sorted(domains)
