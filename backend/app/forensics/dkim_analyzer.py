"""DKIM (DomainKeys Identified Mail) analyzer.

Performs DKIM analysis by:
1. Extracting DKIM-Signature headers
2. Performing cryptographic verification where possible
3. Checking alignment with the visible From domain

Supports multiple DKIM signatures per email.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import dns.resolver
import dns.exception
import dkim

logger = logging.getLogger(__name__)

# DKIM result statuses
DKIM_PASS = "PASS"
DKIM_FAIL = "FAIL"
DKIM_NONE = "NONE"
DKIM_TEMPERROR = "TEMPERROR"
DKIM_PERMERROR = "PERMERROR"
DKIM_NOT_CHECKED = "NOT_CHECKED"


@dataclass
class DKIMSignature:
    """One DKIM-Signature parsed from headers."""

    selector: str | None = None
    domain: str | None = None
    headers: str | None = None  # signed header list (h=)
    body_hash: str | None = None
    signature: str | None = None
    algorithm: str | None = None
    canonicalization: str | None = None


@dataclass
class DKIMResult:
    """Result of DKIM analysis for a single signature."""

    result: str = DKIM_NOT_CHECKED
    domain: str | None = None
    selector: str | None = None
    source: str = "independent_check"
    details: str | None = None
    error: str | None = None

    # Raw signature data
    raw_signature: DKIMSignature | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "domain": self.domain,
            "selector": self.selector,
            "source": self.source,
            "details": self.details,
            "error": self.error,
        }


def _parse_dkim_signature(header_value: str) -> DKIMSignature:
    """Parse a DKIM-Signature header into structured fields."""
    sig = DKIMSignature()

    # Simple field extraction
    for part in header_value.split(";"):
        part = part.strip()
        if part.startswith("d="):
            sig.domain = part[2:].strip()
        elif part.startswith("s="):
            sig.selector = part[2:].strip()
        elif part.startswith("h="):
            sig.headers = part[2:].strip()
        elif part.startswith("bh="):
            sig.body_hash = part[3:].strip()
        elif part.startswith("b="):
            sig.signature = part[2:].strip()
        elif part.startswith("a="):
            sig.algorithm = part[2:].strip()
        elif part.startswith("c="):
            sig.canonicalization = part[2:].strip()

    return sig


def _extract_dkim_signatures(
    headers: dict[str, str | list[str]],
) -> list[DKIMSignature]:
    """Extract all DKIM-Signature headers.

    Handles both single and multiple DKIM-Signature headers.
    """
    raw = headers.get("dkim-signature", "")
    if not raw:
        return []

    # dkim-signature can be a list if there are multiple
    if isinstance(raw, list):
        values = raw
    else:
        values = [raw]

    return [_parse_dkim_signature(v) for v in values]


def _verify_dkim_signature(
    raw_email_bytes: bytes,
    signature: DKIMSignature,
) -> tuple[str, str | None]:
    """Attempt cryptographic DKIM verification.

    Returns (result, details_or_error).
    """
    if not signature.domain or not signature.selector:
        return DKIM_FAIL, "Missing domain or selector in DKIM-Signature"

    try:
        # Use dkimpy for verification
        # dkim.verify() expects the raw email bytes
        result = dkim.verify(raw_email_bytes)
        if result:
            return DKIM_PASS, f"DKIM signature verified for {signature.selector}._domainkey.{signature.domain}"
        else:
            return DKIM_FAIL, f"DKIM signature verification failed for {signature.domain}"
    except dkim.DKIMException as e:
        return DKIM_PERMERROR, f"DKIM verification error: {e}"
    except Exception as e:
        logger.warning("DKIM verification failed: %s: %s", type(e).__name__, e)
        return DKIM_TEMPERROR, f"DKIM verification could not complete: {type(e).__name__}"


def _lookup_dkim_key(selector: str, domain: str) -> tuple[str | None, str | None]:
    """Look up the DKIM public key for a selector and domain.

    Returns (public_key_dns_record, error_or_none).
    """
    dns_name = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(dns_name, "TXT", lifetime=5)
        for rdata in answers:
            return b"".join(rdata.strings).decode("utf-8", errors="replace"), None
        return None, f"No TXT record found for {dns_name}"
    except dns.resolver.NXDOMAIN:
        return None, f"DKIM key not found (NXDOMAIN) for {dns_name}"
    except dns.resolver.NoAnswer:
        return None, f"No answer for {dns_name}"
    except dns.resolver.NoNameservers:
        return None, f"DNS server unreachable for {dns_name}"
    except dns.exception.Timeout:
        return None, f"DNS query timed out for {dns_name}"
    except Exception as e:
        return None, f"DNS error: {type(e).__name__}: {e}"


def analyze_dkim(
    headers: dict[str, str | list[str]],
    raw_email_bytes: bytes | None = None,
    email_sender_domain: str | None = None,
) -> list[DKIMResult]:
    """Perform DKIM analysis on email headers.

    Args:
        headers: Dictionary of header name (lowercase) -> value(s)
        raw_email_bytes: Original raw email bytes for cryptographic verification
        email_sender_domain: The visible From domain (for alignment check)

    Returns:
        List of DKIMResult, one per DKIM-Signature
    """
    signatures = _extract_dkim_signatures(headers)

    if not signatures:
        return [DKIMResult(
            result=DKIM_NONE,
            details="No DKIM-Signature header found",
            source="independent_check",
        )]

    results: list[DKIMResult] = []

    for sig in signatures:
        result = DKIMResult(
            domain=sig.domain,
            selector=sig.selector,
            source="independent_check",
            raw_signature=sig,
        )

        if not sig.domain or not sig.selector:
            result.result = DKIM_PERMERROR
            result.details = "DKIM-Signature missing required fields (d= or s=)"
            results.append(result)
            continue

        # First, check if the signing domain aligns with visible From
        alignment_note = None
        if email_sender_domain:
            signing_domain = sig.domain.lower()
            from_domain = email_sender_domain.lower()
            if signing_domain != from_domain and not from_domain.endswith(f".{signing_domain}"):
                alignment_note = (
                    f"Signing domain ({signing_domain}) does not align with "
                    f"visible From domain ({from_domain})"
                )

        # Attempt cryptographic verification if we have raw bytes
        if raw_email_bytes:
            dkim_result, details = _verify_dkim_signature(raw_email_bytes, sig)
            result.result = dkim_result
            # Combine alignment info with verification details
            if alignment_note and details:
                result.details = f"{details}. {alignment_note}"
            elif alignment_note:
                result.details = alignment_note
            else:
                result.details = details
        else:
            # Can't verify cryptographically; check if key exists
            key_record, error = _lookup_dkim_key(sig.selector, sig.domain)
            if error:
                result.result = DKIM_PERMERROR
                result.details = error
            else:
                result.result = DKIM_NOT_CHECKED
                result.details = (
                    f"DKIM key found for {sig.selector}._domainkey.{sig.domain} "
                    f"but cryptographic verification not performed"
                )

        results.append(result)

    return results


def extract_auth_results_dkim(
    auth_results_header: str | None,
) -> list[dict[str, str | None]]:
    """Extract DKIM results from an Authentication-Results header.

    These are claims in the header, not our independent verification.
    """
    if not auth_results_header:
        return []

    results: list[dict[str, str | None]] = []
    parts = auth_results_header.split(";")
    for part in parts:
        part = part.strip()
        if part.startswith("dkim="):
            parts2 = part.split()
            result_val = parts2[0].split("=", 1)[1] if "=" in parts2[0] else None
            domain = None
            detail = None
            for p in parts2[1:]:
                if p.startswith("header.d="):
                    domain = p.split("=", 1)[1]
                elif "=" in p:
                    detail = p
            results.append({
                "result": result_val,
                "domain": domain,
                "details": detail,
                "source": "header_claim",
            })

    return results
