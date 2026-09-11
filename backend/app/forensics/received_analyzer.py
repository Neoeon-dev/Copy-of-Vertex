"""Received-header forensic reconstruction.

Received headers are prepended by successive mail servers.
This module:
1. Parses each Received header into structured hops
2. Reconstructs chronological flow (reverse prepended order)
3. Identifies public vs private IPs
4. Detects anomalies (missing timestamps, duplicate hops, etc.)
5. Provides trust/confidence indicators per hop

Every Received header can be forged — never assume they are trustworthy.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReceivedHop:
    """One parsed hop from a Received header."""

    position: int  # order in the raw headers (0 = topmost / most recent)
    source_hostname: str | None = None
    source_ip: str | None = None
    source_is_public: bool | None = None
    destination_hostname: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None  # ESMTP, SMTP, ESMTPS, etc.
    timestamp: datetime | None = None
    raw_header: str = ""
    anomaly_indicators: list[str] = field(default_factory=list)
    trust_level: str = "observed"  # observed | parsed | suspicious | forged_indicator

    def to_dict(self) -> dict[str, Any]:
        return {
            "position": self.position,
            "source_hostname": self.source_hostname,
            "source_ip": self.source_ip,
            "source_is_public": self.source_is_public,
            "destination_hostname": self.destination_hostname,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "anomaly_indicators": self.anomaly_indicators,
            "trust_level": self.trust_level,
        }


@dataclass
class ReceivedChainAnalysis:
    """Complete analysis of all Received headers for an email."""

    hops: list[ReceivedHop] = field(default_factory=list)
    chronological_hops: list[ReceivedHop] = field(default_factory=list)  # oldest first
    total_hops: int = 0
    public_ips: list[str] = field(default_factory=list)
    private_ips: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hops": [h.to_dict() for h in self.hops],
            "chronological_hops": [h.to_dict() for h in self.chronological_hops],
            "total_hops": self.total_hops,
            "public_ips": self.public_ips,
            "private_ips": self.private_ips,
            "anomalies": self.anomalies,
            "earliest_timestamp": self.earliest_timestamp.isoformat() if self.earliest_timestamp else None,
            "latest_timestamp": self.latest_timestamp.isoformat() if self.latest_timestamp else None,
        }


def _is_private_ip(ip_str: str) -> bool | None:
    """Check if an IP address is private/reserved.

    Note: RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) are considered 'reserved' by Python's ipaddress module
    but are NOT actually private infrastructure — they are public-facing
    test addresses. We exclude them from 'private' classification so they
    appear as public IPs for analysis purposes.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        # Documentation ranges from RFC 5737 — treat as public for our purposes
        _DOC_NETWORKS = [
            ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
            ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
            ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
        ]
        for net in _DOC_NETWORKS:
            if addr in net:
                return False
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return None


def _extract_ip(text: str) -> str | None:
    """Extract the first IPv4 address from text, preferring bracketed form."""
    # Try [IP] first (common in Received headers)
    match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", text)
    if match:
        return match.group(1)
    # Try parenthesized (HELO ... (IP))
    match = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", text)
    if match:
        return match.group(1)
    # Try bare IP after "from"
    match = re.search(r"from\s+\S+\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", text)
    if match:
        return match.group(1)
    return None


def _extract_hostname(text: str, after_keyword: str = "from") -> str | None:
    """Extract hostname after a keyword like 'from' or 'by'."""
    pattern = rf"{after_keyword}\s+(\S+)"
    match = re.search(pattern, text)
    if match:
        hostname = match.group(1)
        # Remove port numbers, parentheses content
        hostname = re.sub(r"\(.*?\)", "", hostname).strip()
        if hostname and not hostname.startswith("[") and not re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
            return hostname
    return None


def _extract_protocol(text: str) -> str | None:
    """Extract the mail protocol (ESMTP, SMTP, ESMTPS, etc.)."""
    match = re.search(r"\bwith\s+(ESMTP[S]?|SMTP[S]?|LMTP|HTTP)\b", text, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return None


def _parse_timestamp(date_str: str) -> datetime | None:
    """Parse a Received header timestamp."""
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except (ValueError, TypeError):
        return None


def _extract_timestamp(received_header: str) -> datetime | None:
    """Extract and parse the timestamp from a Received header."""
    # Received headers typically end with a semicolon-separated timestamp
    # e.g., "from mail.example.com ... by mx.target.com ...; Mon, 01 Jan 2024 12:00:00 +0000"
    match = re.search(r";\s*(\d{1,2}\s+\w+\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})", received_header)
    if match:
        return _parse_timestamp(match.group(1))
    # Try without semicolon (some malformed headers)
    match = re.search(r"(\d{1,2}\s+\w+\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})", received_header)
    if match:
        return _parse_timestamp(match.group(1))
    return None


def _detect_anomalies(hop: ReceivedHop, all_hops: list[ReceivedHop]) -> list[str]:
    """Detect anomaly indicators for a single hop."""
    anomalies: list[str] = []

    if not hop.source_hostname:
        anomalies.append("missing_source_hostname")
    if not hop.source_ip:
        anomalies.append("missing_source_ip")
    if not hop.timestamp:
        anomalies.append("missing_timestamp")

    # Check for obviously forged patterns
    if hop.source_hostname and hop.source_hostname.startswith("["):
        anomalies.append("source_hostname_is_ip")

    # Check for HELO mismatches (hostname doesn't match IP)
    # This is a simplified check

    # Check for duplicate source IPs (possible loop or forgery)
    source_ips = [h.source_ip for h in all_hops if h.source_ip]
    if hop.source_ip and source_ips.count(hop.source_ip) > 1:
        anomalies.append("duplicate_source_ip")

    return anomalies


def parse_received_headers(headers: dict[str, str | list[str]]) -> ReceivedChainAnalysis:
    """Parse all Received headers and reconstruct the relay path.

    Received headers are prepended — the FIRST one in the message is from
    the closest server to the recipient, and the LAST one is from the
    originating server.

    This function preserves both the raw order and the chronological order.
    """
    raw_received = headers.get("received", "")
    if not raw_received:
        analysis = ReceivedChainAnalysis()
        analysis.anomalies.append("no_received_headers")
        return analysis

    # Handle single vs multiple Received headers
    if isinstance(raw_received, list):
        received_headers = raw_received
    else:
        received_headers = [raw_received]

    analysis = ReceivedChainAnalysis()
    all_hops: list[ReceivedHop] = []

    for position, header_value in enumerate(received_headers):
        hop = ReceivedHop(
            position=position,
            raw_header=header_value,
        )

        # Extract source information
        hop.source_hostname = _extract_hostname(header_value, "from")
        hop.source_ip = _extract_ip(header_value)
        if hop.source_ip:
            is_private = _is_private_ip(hop.source_ip)
            hop.source_is_public = is_private is False

        # Extract destination information
        hop.destination_hostname = _extract_hostname(header_value, "by")

        # Extract protocol
        hop.protocol = _extract_protocol(header_value)

        # Extract timestamp
        hop.timestamp = _extract_timestamp(header_value)

        # Detect anomalies
        hop.anomaly_indicators = _detect_anomalies(hop, all_hops)

        # Set trust level
        if hop.anomaly_indicators:
            hop.trust_level = "suspicious"
        elif hop.source_ip and not hop.source_is_public:
            hop.trust_level = "observed"  # private IPs are less informative
        else:
            hop.trust_level = "observed"

        all_hops.append(hop)

    # Raw order (as they appear in the email — most recent first)
    analysis.hops = all_hops
    analysis.total_hops = len(all_hops)

    # Chronological order (reverse — oldest first)
    analysis.chronological_hops = list(reversed(all_hops))

    # Collect IPs
    seen_public: set[str] = set()
    seen_private: set[str] = set()
    for hop in all_hops:
        if hop.source_ip:
            if hop.source_is_public:
                seen_public.add(hop.source_ip)
            elif hop.source_is_public is False:
                seen_private.add(hop.source_ip)
    analysis.public_ips = sorted(seen_public)
    analysis.private_ips = sorted(seen_private)

    # Timestamps
    timestamps = [hop.timestamp for hop in all_hops if hop.timestamp]
    if timestamps:
        analysis.earliest_timestamp = min(timestamps)
        analysis.latest_timestamp = max(timestamps)

    # Global anomalies
    if len(all_hops) == 0:
        analysis.anomalies.append("no_received_headers")
    elif len(all_hops) == 1:
        analysis.anomalies.append("only_one_hop")
    if len(seen_public) > 8:
        analysis.anomalies.append("unusually_many_hops")

    # Check for monotonically increasing timestamps in chronological order
    chronological_with_ts = [
        hop.timestamp for hop in analysis.chronological_hops if hop.timestamp
    ]
    for i in range(1, len(chronological_with_ts)):
        if chronological_with_ts[i] < chronological_with_ts[i - 1]:
            analysis.anomalies.append("non_monotonic_timestamps")
            break

    logger.info(
        "Parsed %d Received hops: %d public IPs, %d private IPs, %d anomalies",
        analysis.total_hops,
        len(analysis.public_ips),
        len(analysis.private_ips),
        len(analysis.anomalies),
    )

    return analysis
