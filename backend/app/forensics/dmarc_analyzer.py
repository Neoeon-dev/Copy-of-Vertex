"""DMARC (Domain-based Message Authentication, Reporting & Conformance) analyzer.

DMARC evaluates:
1. SPF authentication result + alignment with visible From domain
2. DKIM authentication result + alignment with visible From domain
3. DMARC policy published by the visible From domain (or organizational domain fallback)

DMARC passes only if:
- SPF passes AND aligns with From domain, OR
- DKIM passes AND aligns with From domain
(and the policy allows the disposition)

Standards Conformance:
- RFC 7489 (DMARC)
- RFC 5322 (Internet Message Format)
- Uses Public Suffix List (PSL) to accurately determine Organizational Domains across ccSLDs.
"""
from __future__ import annotations

import email.utils
import logging
import re
from dataclasses import dataclass
from typing import Any

import dns.resolver
import dns.exception

try:
    from publicsuffixlist import PublicSuffixList
    _psl = PublicSuffixList()
except Exception:
    _psl = None

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
    organizational_domain: str | None = None  # PSL-derived root domain
    policy: str | None = None  # none | quarantine | reject
    subdomain_policy: str | None = None  # sp tag
    aspf: str = "r"  # relaxed (r) or strict (s)
    adkim: str = "r"  # relaxed (r) or strict (s)
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
            "organizational_domain": self.organizational_domain,
            "policy": self.policy,
            "subdomain_policy": self.subdomain_policy,
            "aspf": self.aspf,
            "adkim": self.adkim,
            "spf_aligned": self.spf_aligned,
            "dkim_aligned": self.dkim_aligned,
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "source": self.source,
            "details": self.details,
            "error": self.error,
        }


def extract_domain_from_address(addr_or_header: str | None) -> str | None:
    """Extract clean domain name from an email address or header string.

    Correctly handles:
      'Display Name <user@example.com>' -> 'example.com'
      'user@example.co.uk' -> 'example.co.uk'
      'example.com' -> 'example.com'
    Never constructs '_dmarc.user@example.com'.
    """
    if not addr_or_header:
        return None
    raw = addr_or_header.strip()
    name, addr = email.utils.parseaddr(raw)
    target = addr if addr else raw
    if "@" in target:
        domain = target.split("@", 1)[1]
    else:
        domain = target
    domain = domain.strip().strip("<>").rstrip(".").lower()
    return domain if domain else None


def get_organizational_domain(domain: str | None) -> str | None:
    """Extract organizational domain using Public Suffix List rules.

    Accurately parses ccSLD domains:
      sub.example.com -> example.com
      sub.example.co.uk -> example.co.uk
      mail.sub.example.gov.in -> example.gov.in
      example.com -> example.com
    """
    if not domain:
        return None
    d = domain.strip().rstrip(".").lower()
    if _psl is not None:
        try:
            org = _psl.privatesuffix(d)
            if org:
                return org.lower()
        except Exception as e:
            logger.debug("PSL lookup exception: %s", e)

    # Resilient fallback for common multi-part ccTLDs
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    second_level_tlds = {
        "co.uk", "gov.uk", "org.uk", "ac.uk", "net.uk",
        "gov.in", "co.in", "ac.in", "net.in", "org.in", "nic.in",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz", "govt.nz",
        "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
        "com.br", "org.br", "net.br", "gov.br",
    }
    two_part = ".".join(parts[-2:])
    if two_part in second_level_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _parse_dmarc_record(record: str) -> dict[str, str]:
    """Parse a DMARC TXT record into key-value pairs."""
    policy: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            policy[key.strip().lower()] = value.strip()
    return policy


def _lookup_dmarc_policy(domain: str) -> tuple[dict[str, str] | None, str | None]:
    """Look up the DMARC policy record for a domain.

    Supports RFC 7489 Section 6.6.3 organizational domain fallback
    if subdomain does not publish its own record.
    Returns (policy_dict, error_or_none).
    """
    clean_domain = extract_domain_from_address(domain)
    if not clean_domain:
        return None, "Invalid domain provided"

    dmarc_domain = f"_dmarc.{clean_domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=DMARC1"):
                return _parse_dmarc_record(txt), None
        return None, f"No DMARC record found for {dmarc_domain}"
    except dns.resolver.NXDOMAIN:
        # Fallback to organizational domain if this was a subdomain
        org_domain = get_organizational_domain(clean_domain)
        if org_domain and org_domain != clean_domain:
            org_dmarc = f"_dmarc.{org_domain}"
            try:
                answers = dns.resolver.resolve(org_dmarc, "TXT", lifetime=5)
                for rdata in answers:
                    txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    if txt.startswith("v=DMARC1"):
                        return _parse_dmarc_record(txt), None
            except Exception:
                pass
        return None, f"No DMARC record (NXDOMAIN) for {dmarc_domain}"
    except dns.resolver.NoAnswer:
        return None, f"No TXT records for {dmarc_domain}"
    except dns.resolver.NoNameservers:
        return None, f"DNS server unreachable for {dmarc_domain}"
    except dns.exception.Timeout:
        return None, f"DNS query timed out for {dmarc_domain}"
    except Exception as e:
        return None, f"DNS error: {type(e).__name__}: {e}"


def _check_spf_alignment(
    envelope_domain: str | None,
    from_domain: str | None,
    mode: str = "r",
) -> bool | None:
    """Check if SPF aligns with the visible From domain.

    Alignment modes per RFC 7489 Section 3.1:
    - strict (s): exact match between RFC5321.MailFrom and RFC5322.From
    - relaxed (r): organizational domain match
    """
    env_clean = extract_domain_from_address(envelope_domain)
    from_clean = extract_domain_from_address(from_domain)
    if not env_clean or not from_clean:
        return None

    if mode.lower() == "s":
        return env_clean == from_clean

    # Relaxed mode: compare organizational domains
    org_env = get_organizational_domain(env_clean)
    org_from = get_organizational_domain(from_clean)
    return org_env == org_from


def _check_dkim_alignment(
    dkim_domain: str | None,
    from_domain: str | None,
    mode: str = "r",
) -> bool | None:
    """Check if DKIM signing domain (d= tag) aligns with the visible From domain.

    Alignment modes per RFC 7489 Section 3.1:
    - strict (s): exact match between d= and RFC5322.From
    - relaxed (r): organizational domain match
    """
    dkim_clean = extract_domain_from_address(dkim_domain)
    from_clean = extract_domain_from_address(from_domain)
    if not dkim_clean or not from_clean:
        return None

    if mode.lower() == "s":
        return dkim_clean == from_clean

    # Relaxed mode: compare organizational domains
    org_dkim = get_organizational_domain(dkim_clean)
    org_from = get_organizational_domain(from_clean)
    return org_dkim == org_from


def analyze_dmarc(
    email_sender_domain: str | None,
    spf_result: str | None = None,
    spf_envelope_domain: str | None = None,
    dkim_result: str | None = None,
    dkim_domain: str | None = None,
) -> DMARCResult:
    """Perform standards-aware DMARC analysis.

    Args:
        email_sender_domain: The visible From address or domain
        spf_result: SPF authentication result (PASS/FAIL/etc.)
        spf_envelope_domain: The envelope sender domain (from Return-Path)
        dkim_result: DKIM authentication result (PASS/FAIL/etc.)
        dkim_domain: The DKIM signing domain (d= tag)

    Returns:
        DMARCResult with alignment results and disposition
    """
    result = DMARCResult(source="independent_check")

    clean_from_domain = extract_domain_from_address(email_sender_domain)
    if not clean_from_domain:
        result.result = DMARC_NOT_CHECKED
        result.details = "No visible From domain available for DMARC evaluation"
        return result

    result.domain = clean_from_domain
    result.organizational_domain = get_organizational_domain(clean_from_domain)

    # Look up DMARC policy
    policy_record, error = _lookup_dmarc_policy(clean_from_domain)
    if error:
        if "timed out" in str(error).lower() or "unreachable" in str(error).lower():
            result.result = DMARC_TEMPERROR
        elif "not found" in str(error).lower() or "NXDOMAIN" in str(error):
            result.result = DMARC_NONE
            result.details = f"No DMARC policy published by {clean_from_domain}"
        else:
            result.result = DMARC_PERMERROR
        result.error = error
        return result

    # Extract policy tags
    result.policy = policy_record.get("p", "none")
    result.subdomain_policy = policy_record.get("sp", result.policy)
    result.aspf = policy_record.get("aspf", "r").lower()
    result.adkim = policy_record.get("adkim", "r").lower()

    # Check SPF alignment
    if spf_envelope_domain:
        result.spf_aligned = _check_spf_alignment(
            spf_envelope_domain, clean_from_domain, mode=result.aspf
        )
    result.spf_result = spf_result

    # Check DKIM alignment
    if dkim_domain:
        result.dkim_aligned = _check_dkim_alignment(
            dkim_domain, clean_from_domain, mode=result.adkim
        )
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
        passing = []
        if spf_aligned_pass:
            passing.append(f"SPF (aligned mode={result.aspf})")
        if dkim_aligned_pass:
            passing.append(f"DKIM (aligned mode={result.adkim})")
        result.details = (
            f"DMARC passed via {' and '.join(passing)}. "
            f"Policy: {result.policy}"
        )
    else:
        result.result = DMARC_FAIL
        reasons = []
        if spf_result:
            reasons.append(
                f"SPF result={spf_result}, aligned={result.spf_aligned} (mode={result.aspf})"
            )
        if dkim_result:
            reasons.append(
                f"DKIM result={dkim_result}, aligned={result.dkim_aligned} (mode={result.adkim})"
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
