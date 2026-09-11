"""
Feature Group 8: URL Structural & Redirection Telemetry.
Safely parses URLs from email body/HTML (WITHOUT network requests)
and extracts topological, protocol, IP-literal, and shortener features.
"""
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlparse
import ipaddress

from app.forensics.url_analyzer import extract_urls_from_email, SHORTENER_DOMAINS, SUSPICIOUS_TLDS


def extract_url_signals(
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
    url_list: Optional[List[str]] = None,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts deterministic URL topological features from body content.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    urls: List[str] = url_list if url_list is not None else extract_urls_from_email(body_text, body_html)

    if not urls:
        feats["url_total_count"] = 0.0
        feats["url_unique_count"] = 0.0
        feats["url_http_count"] = 0.0
        feats["url_https_count"] = 0.0
        feats["url_ip_literal_count"] = 0.0
        feats["url_max_length"] = 0.0
        feats["url_avg_length"] = 0.0
        feats["url_has_query"] = 0.0
        feats["url_has_port"] = 0.0
        feats["url_has_userinfo"] = 0.0
        feats["url_has_shortener"] = 0.0
        feats["url_suspicious_tld_count"] = 0.0
        return feats, exps

    total_count = len(urls)
    unique_urls = list(set(urls))
    unique_count = len(unique_urls)

    http_count = 0
    https_count = 0
    ip_literal_count = 0
    lengths = []
    has_query = False
    has_port = False
    has_userinfo = False
    has_shortener = False
    suspicious_tld_count = 0

    for u in unique_urls:
        lengths.append(len(u))
        try:
            parsed = urlparse(u)
        except Exception:
            continue

        try:
            scheme = (parsed.scheme or "").lower()
            if scheme == "http":
                http_count += 1
            elif scheme == "https":
                https_count += 1

            try:
                hostname = (parsed.hostname or "").lower()
            except ValueError:
                hostname = ""

            # Check IP literal
            if hostname:
                try:
                    ipaddress.ip_address(hostname)
                    ip_literal_count += 1
                except ValueError:
                    pass

            # Check query
            if parsed.query:
                has_query = True

            # Check port safely
            try:
                if parsed.port and parsed.port not in (80, 443):
                    has_port = True
            except ValueError:
                has_port = True  # Non-integer port string in URL is an anomaly

            # Check userinfo (@ in authority)
            try:
                if parsed.username or "@" in (parsed.netloc or ""):
                    has_userinfo = True
            except ValueError:
                has_userinfo = True

            # Check shortener
            if hostname in SHORTENER_DOMAINS:
                has_shortener = True

            # Check suspicious TLD
            if "." in hostname:
                tld = hostname.rsplit(".", 1)[-1]
                if tld in SUSPICIOUS_TLDS:
                    suspicious_tld_count += 1
        except Exception:
            continue

    feats["url_total_count"] = float(total_count)
    feats["url_unique_count"] = float(unique_count)
    feats["url_http_count"] = float(http_count)
    feats["url_https_count"] = float(https_count)
    feats["url_ip_literal_count"] = float(ip_literal_count)
    feats["url_max_length"] = float(max(lengths)) if lengths else 0.0
    feats["url_avg_length"] = round(float(sum(lengths) / len(lengths)), 2) if lengths else 0.0
    feats["url_has_query"] = 1.0 if has_query else 0.0
    feats["url_has_port"] = 1.0 if has_port else 0.0
    feats["url_has_userinfo"] = 1.0 if has_userinfo else 0.0
    feats["url_has_shortener"] = 1.0 if has_shortener else 0.0
    feats["url_suspicious_tld_count"] = float(suspicious_tld_count)

    return feats, exps
