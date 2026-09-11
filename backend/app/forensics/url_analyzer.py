"""URL analysis module.

Safely extracts URLs from email text and HTML, then analyzes them for:
- IP-based URLs
- Suspicious TLDs
- Excessive subdomains
- Punycode
- URL shorteners
- Suspicious paths (login, credential harvesting)
- URL obfuscation

NEVER automatically visits suspicious URLs.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

# Common URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "lnkd.in", "rb.gy", "cutt.ly",
    "shorturl.at", "v.gd", "j.mp",
}

# Suspicious path patterns (credential harvesting, login pages)
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"/(login|signin|auth|verify|secure|update|confirm)", re.IGNORECASE),
    re.compile(r"/(account|password|credential|banking)", re.IGNORECASE),
]

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "info", "buzz", "icu", "tk", "ml", "ga",
    "cf", "gq", "click", "download", "racing", "win", "bid", "loan",
}


@dataclass
class URLAnalysis:
    """Analysis result for a single URL."""

    url: str
    parsed_url: Any = None
    domain: str | None = None
    is_ip_url: bool = False
    is_shortener: bool = False
    suspicious_tld: bool = False
    excessive_subdomains: bool = False
    has_punycode: bool = False
    suspicious_path: bool = False
    warnings: list[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "is_ip_url": self.is_ip_url,
            "is_shortener": self.is_shortener,
            "suspicious_tld": self.suspicious_tld,
            "excessive_subdomains": self.excessive_subdomains,
            "has_punycode": self.has_punycode,
            "suspicious_path": self.suspicious_path,
            "warnings": self.warnings,
            "risk_score": self.risk_score,
        }


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from plain text."""
    url_pattern = re.compile(
        r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
        re.IGNORECASE,
    )
    return url_pattern.findall(text)


def _extract_urls_from_html(html: str) -> list[str]:
    """Extract URLs from HTML, including href attributes and embedded URLs."""
    urls: list[str] = []

    # href="..." and href='...'
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    urls.extend(href_pattern.findall(html))

    # src="..."
    src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
    urls.extend(src_pattern.findall(html))

    # Also extract bare URLs from text content
    text_urls = _extract_urls_from_text(html)
    urls.extend(text_urls)

    return urls


def analyze_url(url: str) -> URLAnalysis:
    """Analyze a single URL for suspicious characteristics."""
    analysis = URLAnalysis(url=url)

    try:
        parsed = urlparse(url)
        analysis.parsed_url = parsed
    except Exception:
        analysis.warnings.append("Failed to parse URL")
        analysis.risk_score = 0.5
        return analysis

    domain = parsed.hostname or ""
    analysis.domain = domain

    # Check for IP-based URL
    try:
        ipaddress.ip_address(domain)
        analysis.is_ip_url = True
        analysis.warnings.append("URL uses an IP address instead of a domain name")
    except ValueError:
        pass

    # Check for URL shortener
    if domain.lower() in SHORTENER_DOMAINS:
        analysis.is_shortener = True
        analysis.warnings.append(f"URL uses a shortener service ({domain})")

    # Check suspicious TLD
    if "." in domain:
        tld = domain.rsplit(".", 1)[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            analysis.suspicious_tld = True
            analysis.warnings.append(f"Suspicious TLD: .{tld}")

    # Check excessive subdomains (more than 3 levels)
    subdomain_count = domain.count(".")
    if subdomain_count > 3:
        analysis.excessive_subdomains = True
        analysis.warnings.append(f"Excessive subdomains ({subdomain_count} levels)")

    # Check for punycode
    if domain.startswith("xn--"):
        analysis.has_punycode = True
        analysis.warnings.append("Domain uses punycode encoding")

    # Check suspicious path
    path = parsed.path or ""
    for pattern in SUSPICIOUS_PATH_PATTERNS:
        if pattern.search(path):
            analysis.suspicious_path = True
            analysis.warnings.append(f"Suspicious path pattern: {path}")
            break

    # Compute risk score
    risk = 0.0
    if analysis.is_ip_url:
        risk += 0.3
    if analysis.is_shortener:
        risk += 0.2
    if analysis.suspicious_tld:
        risk += 0.15
    if analysis.excessive_subdomains:
        risk += 0.15
    if analysis.has_punycode:
        risk += 0.2
    if analysis.suspicious_path:
        risk += 0.15
    analysis.risk_score = min(1.0, risk)

    return analysis


def analyze_urls(urls: list[str]) -> list[URLAnalysis]:
    """Analyze a list of URLs."""
    return [analyze_url(url) for url in urls]


def extract_urls_from_email(
    body_text: str | None = None,
    body_html: str | None = None,
) -> list[str]:
    """Extract all unique URLs from email body."""
    urls: set[str] = set()

    if body_text:
        urls.update(_extract_urls_from_text(body_text))
    if body_html:
        urls.update(_extract_urls_from_html(body_html))

    return sorted(urls)
