"""DMARC (Domain-based Message Authentication, Reporting & Conformance) analyzer.

DMARC evaluates:
1. SPF authentication result + alignment with visible From domain
2. DKIM authentication result + alignment with visible From domain
3. DMARC policy published by the visible From domain

DMARC passes only if:
- SPF passes AND aligns with From domain, OR
- DKIM passes AND aligns with From domain
(and the policy allows the disposition)

Important: DMARC is NOT simply "SPF + DKIM both passed."
It requires ALIGNMENT with the visible From domain.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# DMARC result statuses
DMARC_PASS = "PASS"
DMARC_FAIL = "FAIL"
DMARC_NONE = "NONE"
DMARC_TEMPERROR = "TEMPERROR"
DMARC_PERMERROR = "PERMERROR"
DMARC_NOT_CHECKED = "NOT_CHECKED"


@dataclass
class DMARCResult:
    """Structured DMARC analysis result."""

    result: str = DMARC_NOT_CHECKED
    domain: str | None = None  # the domain that published DMARC policy
    policy: str | None = None  # none | quarantine | reject
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None
    spf_result: str | None = None
    dkim_result: str | None = None
    source: str = "independent_check"
    details: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "domain": self.domain,
            "policy": self.policy,
            "spf_aligned": self.spf_aligned,
            "dkim_aligned": self.dkim_aligned,
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "source": self.source,
            "details": self.details,
            "error": self.error,
        }


def _lookup_dmarc_policy(domain: str) -> tuple[dict[str, str] | None, str | None]:
    """Look up the DMARC policy record for a domain.

    Returns (policy_dict, error_or_none).
    """
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=DMARC1"):
                return _parse_dmarc_record(txt), None
        return None, f"No DMARC record found for {dmarc_domain}"
    except dns.resolver.NXDOMAIN:
        return None, f"No DMARC record (NXDOMAIN) for {dmarc_domain}"
    except dns.resolver.NoAnswer:
        return None, f"No TXT records for {dmarc_domain}"
    except dns.resolver.NoNameservers:
        return None, f"DNS server unreachable for {dmarc_domain}"
    except dns.exception.Timeout:
        return None, f"DNS query timed out for {dmarc_domain}"
    except Exception as e:
        return None, f"DNS error: {type(e).__name__}: {e}"


def _parse_dmarc_record(record: str) -> dict[str, str]:
    """Parse a DMARC TXT record into key-value pairs."""
    policy: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            policy[key.strip()] = value.strip()
    return policy


def _check_spf_alignment(
    envelope_domain: str | None,
    from_domain: str | None,
) -> bool | None:
    """Check if SPF aligns with the visible From domain.

    Alignment can be strict (exact match) or relaxed (subdomain match).
    """
    if not envelope_domain or not from_domain:
        return None

    envelope = envelope_domain.lower()
    from_d = from_domain.lower()

    # Strict alignment
    if envelope == from_d:
        return True

    # Relaxed alignment (subdomain)
    if from_d.endswith(f".{envelope}") or envelope.endswith(f".{from_d}"):
        return True

    return False


def _check_dkim_alignment(
    dkim_domain: str | None,
    from_domain: str | None,
) -> bool | None:
    """Check if DKIM signing domain aligns with the visible From domain."""
    if not dkim_domain or not from_domain:
        return None

    dkim_d = dkim_domain.lower()
    from_d = from_domain.lower()

    # Strict alignment
    if dkim_d == from_d:
        return True

    # Relaxed alignment (subdomain)
    if from_d.endswith(f".{dkim_d}") or dkim_d.endswith(f".{from_d}"):
        return True

    return False


def analyze_dmarc(
    email_sender_domain: str | None,
    spf_result: str | None = None,
    spf_envelope_domain: str | None = None,
    dkim_result: str | None = None,
    dkim_domain: str | None = None,
) -> DMARCResult:
    """Perform DMARC analysis.

    Args:
        email_sender_domain: The visible From domain
        spf_result: SPF authentication result (PASS/FAIL/etc.)
        spf_envelope_domain: The envelope sender domain (from Return-Path)
        dkim_result: DKIM authentication result (PASS/FAIL/etc.)
        dkim_domain: The DKIM signing domain (d= tag)

    Returns:
        DMARCResult with the analysis outcome
    """
    result = DMARCResult(source="independent_check")

    if not email_sender_domain:
        result.result = DMARC_NOT_CHECKED
        result.details = "No visible From domain available for DMARC evaluation"
        return result

    result.domain = email_sender_domain

    # Look up DMARC policy
    policy_record, error = _lookup_dmarc_policy(email_sender_domain)
    if error:
        if "timed out" in str(error).lower() or "unreachable" in str(error).lower():
            result.result = DMARC_TEMPERROR
        elif "not found" in str(error).lower() or "NXDOMAIN" in str(error):
            result.result = DMARC_NONE
            result.details = f"No DMARC policy published by {email_sender_domain}"
        else:
            result.result = DMARC_PERMERROR
        result.error = error
        return result

    # Extract policy
    result.policy = policy_record.get("p", "none")

    # Check SPF alignment
    if spf_envelope_domain:
        result.spf_aligned = _check_spf_alignment(spf_envelope_domain, email_sender_domain)
    result.spf_result = spf_result

    # Check DKIM alignment
    if dkim_domain:
        result.dkim_aligned = _check_dkim_alignment(dkim_domain, email_sender_domain)
    result.dkim_result = dkim_result

    # DMARC passes if EITHER SPF aligns and passes OR DKIM aligns and passes
    spf_aligned_pass = (
        result.spf_aligned is True
        and spf_result == "PASS"
    )
    dkim_aligned_pass = (
        result.dkim_aligned is True
        and dkim_result == "PASS"
    )

    if spf_aligned_pass or dkim_aligned_pass:
        result.result = DMARC_PASS
        passing = "SPF" if spf_aligned_pass else "DKIM"
        result.details = (
            f"DMARC passed via {passing} alignment. "
            f"Policy: {result.policy}"
        )
    else:
        result.result = DMARC_FAIL
        reasons = []
        if spf_result:
            reasons.append(
                f"SPF result={spf_result}, aligned={result.spf_aligned}"
            )
        if dkim_result:
            reasons.append(
                f"DKIM result={dkim_result}, aligned={result.dkim_aligned}"
            )
        if not reasons:
            reasons.append("No SPF or DKIM authentication available")
        result.details = (
            f"DMARC failed. Policy: {result.policy}. "
            f"Reasons: {'; '.join(reasons)}"
        )

    return result


def extract_auth_results_dmarc(
    auth_results_header: str | None,
) -> list[dict[str, str | None]]:
    """Extract DMARC results from an Authentication-Results header."""
    if not auth_results_header:
        return []

    results: list[dict[str, str | None]] = []
    parts = auth_results_header.split(";")
    for part in parts:
        part = part.strip()
        if part.startswith("dmarc="):
            parts2 = part.split()
            result_val = parts2[0].split("=", 1)[1] if "=" in parts2[0] else None
            details_parts = []
            for p in parts2[1:]:
                details_parts.append(p)
            results.append({
                "result": result_val,
                "details": " ".join(details_parts) if details_parts else None,
                "source": "header_claim",
            })

    return results
