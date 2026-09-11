"""SPF (Sender Policy Framework) analyzer.

Performs standards-compliant independent SPF verification (RFC 7208) by:
1. Extracting the envelope sender domain (Return-Path / MAIL FROM)
2. Looking up the SPF DNS TXT record for that domain
3. Evaluating the connecting IP against mechanisms: ip4, ip6, a, mx, include, redirect, all
4. Enforcing RFC 7208 Section 4.6.4 DNS lookup limits (max 10 lookups)
5. Detecting and preventing circular recursion loops

SPF validates the RFC 5321 envelope sender, NOT the visible From address.
Alignment with the visible From domain is evaluated under DMARC (RFC 7489).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# SPF result statuses (RFC 7208 Section 2.6)
SPF_PASS = "PASS"
SPF_FAIL = "FAIL"
SPF_SOFTFAIL = "SOFTFAIL"
SPF_NEUTRAL = "NEUTRAL"
SPF_NONE = "NONE"
SPF_TEMPERROR = "TEMPERROR"
SPF_PERMERROR = "PERMERROR"
SPF_NOT_CHECKED = "NOT_CHECKED"

# Maximum DNS-mechanism lookups per RFC 7208 Section 4.6.4
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
    dns_lookups_count: int = 0

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
            "dns_lookups_count": self.dns_lookups_count,
        }


def _extract_return_path_domain(headers: dict[str, str | list[str]]) -> str | None:
    """Extract the envelope sender domain from the Return-Path header."""
    return_path = headers.get("return-path", "")
    if isinstance(return_path, list):
        return_path = return_path[0] if return_path else ""
    if not return_path:
        return None

    # Return-Path: <user@domain.com>
    match = re.search(r"<[^@]*@([^>]+)>", return_path)
    if match:
        return match.group(1).lower().strip(".")

    # Bare email without angle brackets
    match = re.search(r"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", return_path)
    if match:
        return match.group(1).split("@")[1].lower().strip(".")

    return None


def _extract_connecting_ip(headers: dict[str, str | list[str]]) -> str | None:
    """Extract the most likely connecting IP from Received headers."""
    received = headers.get("received", "")
    if isinstance(received, list):
        received = received[0] if received else ""
    if not received:
        return None

    # Look for IPv4 in brackets or parentheses
    ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", received)
    if ip_match:
        return ip_match.group(1)

    ip_match = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", received)
    if ip_match:
        return ip_match.group(1)

    # Look for IPv6 in brackets
    ipv6_match = re.search(r"\[([0-9a-fA-F:]{3,39})\]", received)
    if ipv6_match:
        return ipv6_match.group(1)

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
    visited_domains: set[str] | None = None,
    lookup_count: list[int] | None = None,
) -> str:
    """Evaluate an IP against an SPF record conforming to RFC 7208.

    Handles: ip4, ip6, a, mx, include, redirect, all.
    Enforces RFC 7208 lookup limits (<=10) and recursion safeguards.
    """
    if not spf_record:
        return SPF_NONE

    if visited_domains is None:
        visited_domains = set()
    if lookup_count is None:
        lookup_count = [0]

    domain_clean = domain.strip().lower()
    if domain_clean in visited_domains:
        logger.warning("SPF infinite loop detected for domain %s", domain_clean)
        return SPF_PERMERROR
    visited_domains.add(domain_clean)

    try:
        ip_obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        return SPF_PERMERROR

    qualifier_results = {
        "+": SPF_PASS,
        "-": SPF_FAIL,
        "~": SPF_SOFTFAIL,
        "?": SPF_NEUTRAL,
    }

    mechanisms = spf_record.split()
    redirect_domain: str | None = None
    last_result: str = SPF_NEUTRAL

    for mechanism in mechanisms[1:]:  # skip v=spf1
        if not mechanism:
            continue

        # Check for redirect modifier
        if mechanism.startswith("redirect="):
            redirect_domain = mechanism.split("=", 1)[1].strip()
            continue

        # Extract qualifier
        qualifier = "+"
        if mechanism[0] in qualifier_results:
            qualifier = mechanism[0]
            mechanism = mechanism[1:]

        # 1. ip4:<cidr>
        if mechanism.startswith("ip4:"):
            cidr = mechanism[4:]
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if isinstance(network, ipaddress.IPv4Network) and ip_obj.version == 4:
                    if ip_obj in network:
                        return qualifier_results[qualifier]
            except ValueError:
                return SPF_PERMERROR

        # 2. ip6:<cidr>
        elif mechanism.startswith("ip6:"):
            cidr = mechanism[4:]
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if isinstance(network, ipaddress.IPv6Network) and ip_obj.version == 6:
                    if ip_obj in network:
                        return qualifier_results[qualifier]
            except ValueError:
                return SPF_PERMERROR

        # 3. a or a/<cidr> or a:<domain>
        elif mechanism == "a" or mechanism.startswith("a/") or mechanism.startswith("a:"):
            lookup_count[0] += 1
            if lookup_count[0] > _MAX_DNS_LOOKUPS:
                return SPF_PERMERROR

            target_domain = domain_clean
            prefix_len = None
            if mechanism.startswith("a:"):
                target = mechanism[2:]
                if "/" in target:
                    target_domain, prefix_len = target.split("/", 1)
                else:
                    target_domain = target
            elif "/" in mechanism:
                prefix_len = mechanism.split("/", 1)[1]

            try:
                qtype = "AAAA" if ip_obj.version == 6 else "A"
                answers = dns.resolver.resolve(target_domain, qtype, lifetime=5)
                for rdata in answers:
                    resolved_ip = ipaddress.ip_address(str(rdata))
                    if prefix_len:
                        net = ipaddress.ip_network(f"{resolved_ip}/{prefix_len}", strict=False)
                        if ip_obj in net:
                            return qualifier_results[qualifier]
                    elif ip_obj == resolved_ip:
                        return qualifier_results[qualifier]
            except Exception:
                pass

        # 4. mx or mx/<cidr> or mx:<domain>
        elif mechanism == "mx" or mechanism.startswith("mx/") or mechanism.startswith("mx:"):
            lookup_count[0] += 1
            if lookup_count[0] > _MAX_DNS_LOOKUPS:
                return SPF_PERMERROR

            target_domain = domain_clean
            prefix_len = None
            if mechanism.startswith("mx:"):
                target = mechanism[3:]
                if "/" in target:
                    target_domain, prefix_len = target.split("/", 1)
                else:
                    target_domain = target
            elif "/" in mechanism:
                prefix_len = mechanism.split("/", 1)[1]

            try:
                answers = dns.resolver.resolve(target_domain, "MX", lifetime=5)
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip(".")
                    try:
                        qtype = "AAAA" if ip_obj.version == 6 else "A"
                        mx_ips = dns.resolver.resolve(mx_host, qtype, lifetime=5)
                        for mx_rdata in mx_ips:
                            resolved_ip = ipaddress.ip_address(str(mx_rdata))
                            if prefix_len:
                                net = ipaddress.ip_network(f"{resolved_ip}/{prefix_len}", strict=False)
                                if ip_obj in net:
                                    return qualifier_results[qualifier]
                            elif ip_obj == resolved_ip:
                                return qualifier_results[qualifier]
                    except Exception:
                        pass
            except Exception:
                pass

        # 5. include:<domain> (RFC 7208 Section 5.2)
        elif mechanism.startswith("include:"):
            lookup_count[0] += 1
            if lookup_count[0] > _MAX_DNS_LOOKUPS:
                return SPF_PERMERROR

            inc_domain = mechanism[8:].strip()
            inc_record, err = _lookup_spf_record(inc_domain)
            if err or not inc_record:
                # Include target missing SPF record is a PermError per RFC 7208
                return SPF_PERMERROR

            inc_res = _evaluate_spf_record(
                inc_record,
                ip,
                inc_domain,
                visited_domains=visited_domains.copy(),
                lookup_count=lookup_count,
            )

            if inc_res == SPF_PASS:
                return qualifier_results[qualifier]
            elif inc_res in (SPF_TEMPERROR, SPF_PERMERROR):
                return inc_res
            # Fail, SoftFail, Neutral in include do NOT match; continue evaluation

        # 6. all
        elif mechanism == "all":
            return qualifier_results[qualifier]

    # If no mechanisms matched and redirect= is present, evaluate redirect
    if redirect_domain:
        lookup_count[0] += 1
        if lookup_count[0] > _MAX_DNS_LOOKUPS:
            return SPF_PERMERROR
        red_record, err = _lookup_spf_record(redirect_domain)
        if err or not red_record:
            return SPF_PERMERROR
        return _evaluate_spf_record(
            red_record,
            ip,
            redirect_domain,
            visited_domains=visited_domains.copy(),
            lookup_count=lookup_count,
        )

    return last_result


def analyze_spf(
    headers: dict[str, str | list[str]],
    email_sender_domain: str | None = None,
    connecting_ip: str | None = None,
) -> SPFResult:
    """Perform independent SPF analysis conforming to RFC 7208.

    Args:
        headers: Dictionary of headers (lowercase name -> value)
        email_sender_domain: Visible From domain (for alignment note)
        connecting_ip: Override connecting IP (if extracted by caller)

    Returns:
        SPFResult with evaluation status and DNS lookup diagnostics
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

    # Evaluate IP against SPF record
    lookup_count = [0]
    try:
        eval_result = _evaluate_spf_record(
            spf_record,
            connecting_ip,
            envelope_domain,
            lookup_count=lookup_count,
        )
        result.result = eval_result
        result.dns_lookups_count = lookup_count[0]
    except Exception as e:
        result.result = SPF_TEMPERROR
        result.error = f"Evaluation error: {e}"
        return result

    # Add alignment note if visible From differs from envelope
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
    """Extract SPF results from an Authentication-Results header."""
    if not auth_results_header:
        return []

    results: list[dict[str, str | None]] = []
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
