"""
VERTEX Phase D6 — IOC Normalization and Validation.

Canonical representation and validation for Indicators of Compromise.
All normalization is deterministic and safe — never performs external requests.
SSRF protections are built in: no URL fetching, no DNS resolution of attacker-controlled domains.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class IOCType(str, Enum):
    """Supported IOC types for threat intelligence queries."""
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE_HASH = "FILE_HASH"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"


class IOCValidationError(Exception):
    """Raised when an IOC fails validation."""
    pass


@dataclass(frozen=True)
class IOC:
    """
    Canonical normalized IOC.
    
    All fields are deterministic. The same input will always produce the same IOC.
    """
    ioc_type: IOCType
    normalized_value: str          # Canonical form for provider queries
    display_value: str             # Original/preserved form for display
    source_location: str           # Where extracted: header, body_text, body_html, attachment
    extraction_context: str = ""   # Additional context: header name, URL anchor text, etc.
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0        # Extraction confidence 0.0-1.0
    
    def __post_init__(self):
        # Ensure datetimes are timezone-aware
        if self.first_seen.tzinfo is None:
            object.__setattr__(self, 'first_seen', self.first_seen.replace(tzinfo=timezone.utc))
        if self.last_seen.tzinfo is None:
            object.__setattr__(self, 'last_seen', self.last_seen.replace(tzinfo=timezone.utc))
    
    def cache_key(self) -> str:
        """Deterministic cache key: type + normalized value."""
        return f"{self.ioc_type.value}:{self.normalized_value}"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_type": self.ioc_type.value,
            "normalized_value": self.normalized_value,
            "display_value": self.display_value,
            "source_location": self.source_location,
            "extraction_context": self.extraction_context,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
            "cache_key": self.cache_key(),
        }


# ─── Private IP / SSRF Protection ─────────────────────────────────────

# RFC1918 private ranges
_PRIVATE_IPV4_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Loopback
_LOOPBACK_IPV4 = ipaddress.ip_network("127.0.0.0/8")
_LOOPBACK_IPV6 = ipaddress.ip_network("::1/128")

# Link-local
_LINK_LOCAL_IPV4 = ipaddress.ip_network("169.254.0.0/16")
_LINK_LOCAL_IPV6 = ipaddress.ip_network("fe80::/10")

# Cloud metadata endpoints (IPv4)
_METADATA_IPV4 = [
    ipaddress.ip_address("169.254.169.254"),  # AWS, GCP, Azure, DigitalOcean
    ipaddress.ip_address("169.254.169.253"),  # Azure
]

# Multicast
_MULTICAST_IPV4 = ipaddress.ip_network("224.0.0.0/4")
_MULTICAST_IPV6 = ipaddress.ip_network("ff00::/8")

# Reserved
_RESERVED_IPV4 = ipaddress.ip_network("0.0.0.0/8")
_RESERVED_IPV6 = ipaddress.ip_network("::/128")


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """
    Check if an IP is private, reserved, loopback, link-local, or metadata endpoint.
    
    Used to prevent SSRF by blocking queries to internal infrastructure.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # Invalid IP = treat as unsafe
    
    if addr.version == 4:
        # Check private ranges
        for net in _PRIVATE_IPV4_NETWORKS:
            if addr in net:
                return True
        # Check loopback
        if addr in _LOOPBACK_IPV4:
            return True
        # Check link-local
        if addr in _LINK_LOCAL_IPV4:
            return True
        # Check multicast
        if addr in _MULTICAST_IPV4:
            return True
        # Check reserved
        if addr in _RESERVED_IPV4:
            return True
        # Check metadata endpoints
        if addr in _METADATA_IPV4:
            return True
    else:  # IPv6
        if addr in _LOOPBACK_IPV6:
            return True
        if addr in _LINK_LOCAL_IPV6:
            return True
        if addr in _MULTICAST_IPV6:
            return True
        if addr in _RESERVED_IPV6:
            return True
        # IPv6 ULA (fc00::/7) - unique local addresses
        if addr.is_private:
            return True
    
    return False


# ─── Normalization Functions ──────────────────────────────────────────

# IPv4 regex (strict)
_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# IPv6 regex (basic validation via ipaddress module)
def _is_valid_ipv6(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip.version == 6
    except ValueError:
        return False


def normalize_ipv4(value: str) -> str:
    """Normalize IPv4 address to canonical form.
    
    Strips leading zeros from octets to handle non-standard notation
    (e.g., "001.002.003.004" -> "1.2.3.4").
    """
    # Strip leading zeros from each octet
    octets = value.strip().split('.')
    if len(octets) != 4:
        raise ValueError(f"Invalid IPv4 format: {value}")
    
    normalized_octets = []
    for octet in octets:
        # Remove leading zeros, but keep at least one digit
        stripped = octet.lstrip('0')
        if stripped == '':
            stripped = '0'
        # Validate it's a valid number
        if not stripped.isdigit():
            raise ValueError(f"Invalid octet: {octet}")
        num = int(stripped)
        if num > 255:
            raise ValueError(f"Octet > 255: {octet}")
        normalized_octets.append(str(num))
    
    normalized = '.'.join(normalized_octets)
    # Final validation using ipaddress
    ipaddress.IPv4Address(normalized)
    return normalized


def normalize_ipv6(value: str) -> str:
    """Normalize IPv6 address to canonical compressed form."""
    ip = ipaddress.IPv6Address(value)
    return str(ip)  # Returns compressed form


# Domain normalization
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# IDNA punycode prefix
_PUNYCODE_PREFIX = "xn--"


def normalize_domain(value: str) -> tuple[str, bool]:
    """
    Normalize a domain name.
    
    Returns:
        (normalized_domain, has_punycode)
    
    Normalization:
    - Lowercase
    - Strip trailing dot
    - IDNA normalization (NFKC + punycode)
    - Validates domain structure
    """
    if not value or not isinstance(value, str):
        raise IOCValidationError("Domain cannot be empty")
    
    # Strip whitespace and trailing dot
    domain = value.strip().lower().rstrip(".")
    
    if not domain:
        raise IOCValidationError("Domain cannot be empty after stripping")
    
    # Basic structural validation
    if len(domain) > 253:
        raise IOCValidationError(f"Domain too long: {len(domain)} > 253")
    
    # Check for invalid characters (only alphanumeric, hyphen, dot)
    if not re.match(r"^[a-zA-Z0-9.\-]+$", domain):
        # May contain Unicode - try IDNA
        try:
            domain = domain.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError) as e:
            raise IOCValidationError(f"Invalid domain characters: {e}")
    
    # Validate structure after normalization
    if not _DOMAIN_PATTERN.match(domain):
        # For auto-detection, single-label domains should be rejected
        # Only allow them if explicitly requested via IOCType.DOMAIN
        raise IOCValidationError(f"Invalid domain structure: {domain} (must have valid TLD)")
    
    # Check for punycode
    has_punycode = _PUNYCODE_PREFIX in domain
    
    return domain, has_punycode


# URL normalization
_URL_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def normalize_url(value: str) -> tuple[str, str]:
    """
    Normalize a URL for threat intelligence queries.
    
    Returns:
        (normalized_url, canonical_hostname)
    
    Normalization:
    - Parse with urllib.parse
    - Canonicalize hostname (lowercase, IDNA)
    - Preserve scheme, port, path, query, fragment
    - Does NOT fetch or resolve the URL
    
    Raises:
        IOCValidationError: If URL is malformed or uses unsafe scheme
    """
    if not value or not isinstance(value, str):
        raise IOCValidationError("URL cannot be empty")
    
    value = value.strip()
    
    # Must have a valid scheme
    if not _URL_SCHEME_PATTERN.match(value):
        raise IOCValidationError(f"Invalid URL scheme: {value[:50]}")
    
    # Only allow http/https schemes for threat intel queries
    parsed = urlparse(value)
    if parsed.scheme.lower() not in ("http", "https"):
        raise IOCValidationError(f"Unsupported URL scheme for threat intel: {parsed.scheme}")
    
    # Canonicalize hostname
    hostname = parsed.hostname or ""
    if not hostname:
        raise IOCValidationError("URL missing hostname")
    
    # Normalize hostname (domain or IP)
    try:
        # Try IP first
        ip = ipaddress.ip_address(hostname)
        canonical_host = str(ip)
        # For IP URLs, preserve the IP in the URL
        normalized_netloc = canonical_host
        if parsed.port:
            normalized_netloc = f"{canonical_host}:{parsed.port}"
    except ValueError:
        # It's a domain - normalize it
        canonical_host, _ = normalize_domain(hostname)
        normalized_netloc = canonical_host
        if parsed.port:
            normalized_netloc = f"{canonical_host}:{parsed.port}"
    
    # Reconstruct URL with canonical hostname
    # Preserve path, query, fragment exactly
    normalized = parsed._replace(netloc=normalized_netloc).geturl()
    
    return normalized, canonical_host


# File hash normalization
_HASH_PATTERNS = {
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "SHA512": re.compile(r"^[a-fA-F0-9]{128}$"),
}

_SUPPORTED_HASH_TYPES = {"MD5", "SHA1", "SHA256", "SHA512"}


def normalize_hash(value: str) -> tuple[str, str]:
    """
    Normalize and validate a file hash.
    
    Returns:
        (normalized_lowercase_hash, hash_type)
    
    Raises:
        IOCValidationError: If hash is not a recognized format
    """
    if not value or not isinstance(value, str):
        raise IOCValidationError("Hash cannot be empty")
    
    value = value.strip().lower()
    
    for hash_type, pattern in _HASH_PATTERNS.items():
        if pattern.match(value):
            return value, hash_type
    
    raise IOCValidationError(f"Unrecognized hash format: {value[:20]}...")


# Email address normalization
_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


def normalize_email(value: str) -> tuple[str, str]:
    """
    Normalize an email address.
    
    Returns:
        (normalized_email, normalized_domain)
    
    Normalization:
    - Lowercase domain part
    - Preserve local part case (per RFC)
    - IDNA normalize domain
    """
    if not value or not isinstance(value, str):
        raise IOCValidationError("Email cannot be empty")
    
    value = value.strip()
    
    # Split local and domain parts
    if "@" not in value:
        raise IOCValidationError(f"Invalid email format: {value}")
    
    local_part, domain = value.rsplit("@", 1)
    
    # Validate local part (ASCII only per RFC)
    if not re.match(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$", local_part):
        raise IOCValidationError(f"Invalid email local part: {local_part}")
    
    # Normalize domain (handles Unicode/IDNA)
    normalized_domain, _ = normalize_domain(domain)
    
    normalized = f"{local_part}@{normalized_domain}"
    
    return normalized, normalized_domain


# ─── Main Normalization Entry Point ───────────────────────────────────


def normalize_ioc(
    value: str,
    ioc_type: Optional[IOCType] = None,
    source_location: str = "unknown",
    extraction_context: str = "",
    confidence: float = 1.0,
) -> IOC:
    """
    Normalize a raw indicator value into a canonical IOC.
    
    If ioc_type is not provided, attempts auto-detection.
    Auto-detection priority: hash > IP > email > URL > domain
    
    Args:
        value: Raw indicator value
        ioc_type: Optional explicit type hint
        source_location: Where extracted (header, body_text, body_html, attachment)
        extraction_context: Additional context (header name, anchor text, etc.)
        confidence: Extraction confidence 0.0-1.0
    
    Returns:
        Normalized IOC
    
    Raises:
        IOCValidationError: If value cannot be normalized as the given/auto type
    """
    if not value or not isinstance(value, str):
        raise IOCValidationError("IOC value cannot be empty")
    
    value = value.strip()
    
    # Auto-detect type if not provided
    if ioc_type is None:
        ioc_type = _auto_detect_type(value)
    
    # Normalize based on type
    if ioc_type == IOCType.IPV4:
        normalized = normalize_ipv4(value)
        # SSRF check
        if is_private_or_reserved_ip(normalized):
            logger.warning("Private/reserved IP detected, marking as internal: %s", normalized)
        return IOC(
            ioc_type=IOCType.IPV4,
            normalized_value=normalized,
            display_value=value,
            source_location=source_location,
            extraction_context=extraction_context,
            confidence=confidence,
        )
    
    elif ioc_type == IOCType.IPV6:
        normalized = normalize_ipv6(value)
        if is_private_or_reserved_ip(normalized):
            logger.warning("Private/reserved IPv6 detected, marking as internal: %s", normalized)
        return IOC(
            ioc_type=IOCType.IPV6,
            normalized_value=normalized,
            display_value=value,
            source_location=source_location,
            extraction_context=extraction_context,
            confidence=confidence,
        )
    
    elif ioc_type == IOCType.DOMAIN:
        normalized, has_punycode = normalize_domain(value)
        return IOC(
            ioc_type=IOCType.DOMAIN,
            normalized_value=normalized,
            display_value=value,
            source_location=source_location,
            extraction_context=f"{extraction_context}; punycode={has_punycode}",
            confidence=confidence,
        )
    
    elif ioc_type == IOCType.URL:
        normalized, canonical_host = normalize_url(value)
        # Also extract and validate the hostname
        parsed = urlparse(normalized)
        host = parsed.hostname or ""
        try:
            ipaddress.ip_address(host)
            is_ip_host = True
        except ValueError:
            is_ip_host = False
        
        # SSRF check on hostname if it's an IP
        if is_ip_host and is_private_or_reserved_ip(host):
            logger.warning("URL points to private/reserved IP: %s", host)
        
        return IOC(
            ioc_type=IOCType.URL,
            normalized_value=normalized,
            display_value=value,
            source_location=source_location,
            extraction_context=f"{extraction_context}; host={canonical_host}; ip_host={is_ip_host}",
            confidence=confidence,
        )
    
    elif ioc_type == IOCType.FILE_HASH:
        normalized, hash_type = normalize_hash(value)
        return IOC(
            ioc_type=IOCType.FILE_HASH,
            normalized_value=normalized,
            display_value=value,
            source_location=source_location,
            extraction_context=f"{extraction_context}; hash_type={hash_type}",
            confidence=confidence,
        )
    
    elif ioc_type == IOCType.EMAIL_ADDRESS:
        normalized, domain = normalize_email(value)
        return IOC(
            ioc_type=IOCType.EMAIL_ADDRESS,
            normalized_value=normalized,
            display_value=value,
            source_location=source_location,
            extraction_context=f"{extraction_context}; domain={domain}",
            confidence=confidence,
        )
    
    else:
        raise IOCValidationError(f"Unsupported IOC type: {ioc_type}")


def _auto_detect_type(value: str) -> IOCType:
    """Auto-detect IOC type from value."""
    v = value.strip()
    
    # Check hash first (most specific)
    for hash_type, pattern in _HASH_PATTERNS.items():
        if pattern.match(v.lower()):
            return IOCType.FILE_HASH
    
    # Check IP addresses
    if _IPV4_PATTERN.match(v):
        return IOCType.IPV4
    if _is_valid_ipv6(v):
        return IOCType.IPV6
    
    # Check email
    if _EMAIL_PATTERN.match(v):
        return IOCType.EMAIL_ADDRESS
    
    # Check URL
    if _URL_SCHEME_PATTERN.match(v):
        return IOCType.URL
    
    # Default to domain
    return IOCType.DOMAIN


# ─── Batch Normalization with Deduplication ───────────────────────────


def normalize_iocs(
    values: list[str],
    ioc_type: Optional[IOCType] = None,
    source_location: str = "unknown",
    extraction_context: str = "",
    confidence: float = 1.0,
) -> list[IOC]:
    """
    Normalize a list of IOC values with deduplication.
    
    Deduplication is based on cache_key (type + normalized value).
    """
    seen: set[str] = set()
    results: list[IOC] = []
    
    for value in values:
        try:
            ioc = normalize_ioc(
                value=value,
                ioc_type=ioc_type,
                source_location=source_location,
                extraction_context=extraction_context,
                confidence=confidence,
            )
            key = ioc.cache_key()
            if key not in seen:
                seen.add(key)
                results.append(ioc)
        except IOCValidationError as e:
            logger.debug("Failed to normalize IOC '%s': %s", value[:50], e)
            continue
    
    return results


def _extract_emails_from_headers(
    headers: dict[str, str | list[str]],
) -> list[str]:
    """Extract unique email addresses from email headers (From, To, CC, Reply-To, etc.)."""
    import re
    emails: set[str] = set()
    email_pattern = re.compile(
        r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
    )
    
    for key in ("from", "to", "cc", "bcc", "reply-to", "sender", "return-path"):
        values = headers.get(key, [])
        if not isinstance(values, list):
            values = [values]
        for val in values:
            if val:
                for match in email_pattern.finditer(val):
                    emails.add(match.group(0).lower())
    
    return sorted(emails)


# ─── IOC Extraction from Email ────────────────────────────────────────


def extract_iocs_from_email(
    headers: dict[str, Any],
    body_text: str | None = None,
    body_html: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
) -> list[IOC]:
    """
    Extract all IOCs from an email.
    
    Combines existing extractors with new IOC normalization.
    """
    iocs: list[IOC] = []
    
    # IPs from headers
    try:
        from app.forensics.ip_intelligence import extract_ips_from_headers
        ips = extract_ips_from_headers(headers)
        iocs.extend(normalize_iocs(
            ips, source_location="headers", extraction_context="received_header"
        ))
    except Exception as e:
        logger.debug("IP extraction failed: %s", e)
    
    # Domains from headers
    try:
        from app.forensics.domain_intel import extract_domains_from_headers
        domains = extract_domains_from_headers(headers)
        iocs.extend(normalize_iocs(
            domains, IOCType.DOMAIN, source_location="headers", extraction_context="email_address"
        ))
    except Exception as e:
        logger.debug("Domain extraction failed: %s", e)
    
    # Email addresses from headers
    try:
        email_iocs = _extract_emails_from_headers(headers)
        iocs.extend(normalize_iocs(
            email_iocs, IOCType.EMAIL_ADDRESS, source_location="headers", extraction_context="email_header"
        ))
    except Exception as e:
        logger.debug("Email address extraction failed: %s", e)

    # URLs from body
    try:
        from app.forensics.url_analyzer import extract_urls_from_email
        urls = extract_urls_from_email(body_text=body_text, body_html=body_html)
        iocs.extend(normalize_iocs(
            urls, IOCType.URL, source_location="body", extraction_context="extracted_url"
        ))
    except Exception as e:
        logger.debug("URL extraction failed: %s", e)
    
    # File hashes from attachments
    if attachments:
        for att in attachments:
            sha256 = att.get("sha256")
            if sha256:
                try:
                    ioc = normalize_ioc(
                        sha256, IOCType.FILE_HASH,
                        source_location="attachment",
                        extraction_context=f"attachment:{att.get('filename', 'unknown')}"
                    )
                    iocs.append(ioc)
                except IOCValidationError:
                    pass
    
    return iocs