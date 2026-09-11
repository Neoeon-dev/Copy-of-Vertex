"""
Feature Group 5: Relay Path & Hop Telemetry.
Parses Received headers into chronological hops, counts IP distributions,
and detects relay transit anomalies and delays.
"""
from typing import Dict, Any, Tuple, Optional, List
import ipaddress
import re
from datetime import datetime, timezone

from app.parsers.mime_parser import ParsedEmail
from app.forensics.received_analyzer import parse_received_headers, ReceivedChainAnalysis


def extract_relay_path(
    parsed: Optional[ParsedEmail] = None,
    raw_evidence_available: bool = False,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts forensic features from the email Received header relay path.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    if not raw_evidence_available or not parsed:
        feats["relay_hop_count"] = -1.0
        feats["relay_unique_ip_count"] = -1.0
        feats["relay_ipv4_count"] = -1.0
        feats["relay_ipv6_count"] = -1.0
        feats["relay_private_ip_count"] = -1.0
        feats["relay_public_ip_count"] = -1.0
        feats["relay_malformed_ip_count"] = 0.0
        feats["relay_missing_timestamp_count"] = -1.0
        feats["relay_max_hop_delay_sec"] = -1.0
        feats["relay_avg_hop_delay_sec"] = -1.0
        feats["relay_timestamp_ordering_anomaly"] = 0.0
        feats["relay_first_public_ip_present"] = 0.0
        return feats, exps

    # Build header dict for received_analyzer
    received_headers = [h.value for h in parsed.headers if h.name.lower() == "received"]

    if not received_headers:
        feats["relay_hop_count"] = 0.0
        feats["relay_unique_ip_count"] = 0.0
        feats["relay_ipv4_count"] = 0.0
        feats["relay_ipv6_count"] = 0.0
        feats["relay_private_ip_count"] = 0.0
        feats["relay_public_ip_count"] = 0.0
        feats["relay_malformed_ip_count"] = 0.0
        feats["relay_missing_timestamp_count"] = 0.0
        feats["relay_max_hop_delay_sec"] = -1.0
        feats["relay_avg_hop_delay_sec"] = -1.0
        feats["relay_timestamp_ordering_anomaly"] = 0.0
        feats["relay_first_public_ip_present"] = 0.0
        return feats, exps

    analysis: ReceivedChainAnalysis = parse_received_headers({"received": received_headers})

    feats["relay_hop_count"] = float(analysis.total_hops)
    exps["relay_hop_count"] = f"Parsed {analysis.total_hops} Received hops in mail path."

    # Extract all IPs across all hops (including IPv6 checks)
    all_ips: List[str] = []
    ipv4_count = 0
    ipv6_count = 0
    malformed_count = 0
    private_count = 0
    public_count = 0

    ipv4_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    ipv6_pattern = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

    for raw in received_headers:
        # IPv4
        for match in ipv4_pattern.findall(raw):
            try:
                ip_obj = ipaddress.ip_address(match)
                all_ips.append(match)
                ipv4_count += 1
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    private_count += 1
                else:
                    public_count += 1
            except ValueError:
                malformed_count += 1

        # IPv6
        for match in ipv6_pattern.findall(raw):
            try:
                ip_obj = ipaddress.ip_address(match)
                all_ips.append(match)
                ipv6_count += 1
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    private_count += 1
                else:
                    public_count += 1
            except ValueError:
                malformed_count += 1

    unique_ips = set(all_ips)
    feats["relay_unique_ip_count"] = float(len(unique_ips))
    feats["relay_ipv4_count"] = float(ipv4_count)
    feats["relay_ipv6_count"] = float(ipv6_count)
    feats["relay_private_ip_count"] = float(private_count)
    feats["relay_public_ip_count"] = float(public_count)
    feats["relay_malformed_ip_count"] = float(malformed_count)

    # Missing timestamps
    missing_ts = sum(1 for h in analysis.hops if h.timestamp is None)
    feats["relay_missing_timestamp_count"] = float(missing_ts)

    # First public IP
    first_pub = None
    # Chronological hops are oldest first (originating server to recipient)
    for hop in analysis.chronological_hops:
        if hop.source_ip and hop.source_is_public:
            first_pub = hop.source_ip
            break
    if not first_pub and analysis.public_ips:
        first_pub = analysis.public_ips[0]

    feats["relay_first_public_ip_present"] = 1.0 if first_pub else 0.0

    # Delay and ordering anomalies
    def _to_utc(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    ts_list = [_to_utc(h.timestamp) for h in analysis.chronological_hops if h.timestamp]
    if len(ts_list) >= 2:
        delays = []
        ordering_anomaly = False
        for i in range(1, len(ts_list)):
            diff_sec = (ts_list[i] - ts_list[i - 1]).total_seconds()
            if diff_sec < -60.0:  # jumped backward by more than 1 min
                ordering_anomaly = True
            delays.append(max(0.0, diff_sec))

        feats["relay_max_hop_delay_sec"] = float(max(delays)) if delays else 0.0
        feats["relay_avg_hop_delay_sec"] = float(sum(delays) / len(delays)) if delays else 0.0
        feats["relay_timestamp_ordering_anomaly"] = 1.0 if ordering_anomaly else 0.0
    else:
        feats["relay_max_hop_delay_sec"] = -1.0
        feats["relay_avg_hop_delay_sec"] = -1.0
        feats["relay_timestamp_ordering_anomaly"] = 0.0

    return feats, exps
