"""SPF (Sender Policy Framework) analyzer.

Performs independent SPF verification by:
1. Extracting the envelope sender domain (Return-Path / MAIL FROM)
2. Looking up the SPF DNS TXT record for that domain
3. Evaluating the connecting IP against the SPF record
4. Distinguishing between header claims and independent verification

SPF only validates the envelope sender, NOT the visible From address.
Alignment with the visible From domain is a separate DMARC concept.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# SPF result statuses
SPF_PASS = "PASS"
SPF_FAIL = "FAIL"
SPF_SOFTFAIL = "SOFTFAIL"
SPF_NEUTRAL = "NEUTRAL"
SPF_NONE = "NONE"
SPF_TEMPERROR = "TEMPERROR"
SPF_PERMERROR = "PERMERROR"
SPF_NOT_CHECKED = "NOT_CHECKED"

# Maximum DNS lookups in SPF (per RFC 7208 Section 4.6.4)
_MAX_DNS_LOOKUPS = 10


@dataclass
class SPFResult:
    """Structured SPF analysis result."""

    result: str = SPF_NOT_CHECKED
    domain: str | None = None  # envelope sender domain
    connecting_ip: str | None = None
    spf_record: str | None = None
    explanation: str | None = None
    source: str = "independent_check"  # or "header_claim"
    details: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "domain": self.domain,
            "connecting_ip": self.connecting_ip,
            "spf_record": self.spf_record,
            "explanation": self.explanation,
            "source": self.source,
            "details": self.details,
            "error": self.error,
        }


def _extract_return_path_domain(headers: dict[str, str | list[str]]) -> str | None:
    """Extract the envelope sender domain from the Return-Path header."""
    return_path = headers.get("return-path", "")
    # Handle list values (multiple headers with same name)
    if isinstance(return_path, list):
        return_path = return_path[0] if return_path else ""
    if not return_path:
        return None

    # Return-Path: <user@domain.com>
    match = re.search(r"<[^@]*@([^>]+)>", return_path)
    if match:
        return match.group(1).lower().strip(".")

    # Fallback: bare address without angle brackets
    match = re.search(r"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", return_path)
    if match:
        return match.group(1).split("@")[1].lower().strip(".")

    return None


def _extract_connecting_ip(headers: dict[str, str | list[str]]) -> str | None:
    """Extract the most likely connecting IP from the first Received header.

    This is an approximation — the first Received header's source is often
    the connecting IP, but not always trustworthy.
    """
    received = headers.get("received", "")
    # Handle list values (multiple Received headers)
    if isinstance(received, list):
        received = received[0] if received else ""
    if not received:
        return None

    # Look for IP address in square brackets or parentheses
    ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", received)
    if ip_match:
        return ip_match.group(1)

    ip_match = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", received)
    if ip_match:
        return ip_match.group(1)

    return None


def _lookup_spf_record(domain: str) -> tuple[str | None, str | None]:
    """Look up the SPF TXT record for a domain.

    Returns (spf_record, error_or_none).
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=spf1"):
                return txt, None
        return None, "No SPF record found"
    except dns.resolver.NXDOMAIN:
        return None, "Domain does not exist (NXDOMAIN)"
    except dns.resolver.NoAnswer:
        return None, "No TXT records found"
    except dns.resolver.NoNameservers:
        return None, "DNS server unreachable"
    except dns.exception.Timeout:
        return None, "DNS query timed out"
    except Exception as e:
        return None, f"DNS error: {type(e).__name__}: {e}"


def _evaluate_spf_record(
    spf_record: str,
    ip: str,
    domain: str,
) -> str:
    """Evaluate an IP against a simple SPF record.

    This handles common cases: ip4, a, mx, include, all.
    A full SPF evaluator is complex; this covers the most common scenarios.
    """
    if not spf_record:
        return SPF_NONE

    mechanisms = spf_record.split()
    ip_int = _ip_to_int(ip)

    # Process mechanisms (skip the v=spf1 prefix)
    qualifier_results = {
        "+": SPF_PASS,
        "-": SPF_FAIL,
        "~": SPF_SOFTFAIL,
        "?": SPF_NEUTRAL,
    }

    last_result: str = SPF_NEUTRAL  # default if no mechanism matches

    for mechanism in mechanisms[1:]:  # skip "v=spf1"
        if not mechanism:
            continue

        # Determine qualifier
        qualifier = "+"
        if mechanism[0] in qualifier_results:
            qualifier = mechanism[0]
            mechanism = mechanism[1:]

        if mechanism.startswith("ip4:"):
            cidr = mechanism[4:]
            if "/" in cidr:
                network, prefix = cidr.split("/", 1)
                prefix = int(prefix)
            else:
                network, prefix = cidr, 32
            network_int = _ip_to_int(network)
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            if (ip_int & mask) == (network_int & mask):
                return qualifier_results[qualifier]
            last_result = SPF_NEUTRAL

        elif mechanism.startswith("ip6:"):
            # Simplified — for full support, use ipv6 CIDR matching
            pass

        elif mechanism == "a" or mechanism.startswith("a/"):
            # Check if IP matches A record of domain
            try:
                answers = dns.resolver.resolve(domain, "A", lifetime=5)
                for rdata in answers:
                    if str(rdata) == ip:
                        return qualifier_results[qualifier]
            except Exception:
                pass

        elif mechanism == "mx" or mechanism.startswith("mx/"):
            try:
                answers = dns.resolver.resolve(domain, "MX", lifetime=5)
                for rdata in answers:
                    mx_domain = str(rdata.exchange).rstrip(".")
                    try:
                        mx_answers = dns.resolver.resolve(mx_domain, "A", lifetime=5)
                        for mx_rdata in mx_answers:
                            if str(mx_rdata) == ip:
                                return qualifier_results[qualifier]
                    except Exception:
                        pass
            except Exception:
                pass

        elif mechanism.startswith("include:"):
            # Recursive include — simplified: just note it
            pass

        elif mechanism == "all":
            return qualifier_results[qualifier]

    return last_result


def _ip_to_int(ip: str) -> int:
    """Convert an IPv4 address string to an integer."""
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def analyze_spf(
    headers: dict[str, str],
    email_sender_domain: str | None = None,
    connecting_ip: str | None = None,
) -> SPFResult:
    """Perform independent SPF analysis on email headers.

    Args:
        headers: Dictionary of header name (lowercase) -> value
        email_sender_domain: The visible From domain (for alignment check)
        connecting_ip: Override connecting IP (if known from elsewhere)

    Returns:
        SPFResult with the analysis outcome
    """
    result = SPFResult()

    # Extract envelope sender domain from Return-Path
    envelope_domain = _extract_return_path_domain(headers)
    if not envelope_domain:
        result.result = SPF_NOT_CHECKED
        result.details = "No Return-Path header found; cannot determine envelope domain"
        return result

    result.domain = envelope_domain

    # Extract connecting IP
    if not connecting_ip:
        connecting_ip = _extract_connecting_ip(headers)

    if not connecting_ip:
        result.result = SPF_NOT_CHECKED
        result.details = "No connecting IP found in headers"
        return result

    result.connecting_ip = connecting_ip

    # Look up SPF record
    spf_record, error = _lookup_spf_record(envelope_domain)
    if error:
        if "timed out" in str(error).lower() or "unreachable" in str(error).lower():
            result.result = SPF_TEMPERROR
        elif "not found" in str(error).lower() or "does not exist" in str(error).lower():
            result.result = SPF_NONE
        else:
            result.result = SPF_PERMERROR
        result.error = error
        result.spf_record = spf_record
        return result

    result.spf_record = spf_record

    # Evaluate the IP against the SPF record
    try:
        result.result = _evaluate_spf_record(spf_record, connecting_ip, envelope_domain)
    except Exception as e:
        result.result = SPF_TEMPERROR
        result.error = f"Evaluation error: {e}"
        return result

    # Add details about alignment with visible From domain
    if email_sender_domain and email_sender_domain.lower() != envelope_domain:
        result.details = (
            f"Envelope domain ({envelope_domain}) differs from visible From domain "
            f"({email_sender_domain}). SPF validates the envelope, not the visible From."
        )
    else:
        result.details = f"SPF record for {envelope_domain} evaluated against {connecting_ip}"

    return result


def extract_auth_results_spf(
    auth_results_header: str | None,
) -> list[dict[str, str | None]]:
    """Extract SPF results from an Authentication-Results header.

    Returns a list of {result, domain, details} dicts for each SPF entry.
    These are *claims* in the header, not our independent verification.
    """
    if not auth_results_header:
        return []

    results: list[dict[str, str | None]] = []
    # Authentication-Results: mx.company.com; spf=pass header.from=example.com
    # Parse multiple semicolon-separated results
    parts = auth_results_header.split(";")
    for part in parts:
        part = part.strip()
        if part.startswith("spf="):
            parts2 = part.split()
            result_val = parts2[0].split("=", 1)[1] if "=" in parts2[0] else None
            domain = None
            detail = None
            for p in parts2[1:]:
                if p.startswith("header.from="):
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
