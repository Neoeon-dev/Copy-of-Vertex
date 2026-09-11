"""
Feature Group 6: IP Infrastructure & Geolocation Telemetry.
Evaluates originating IP provenance, ASN registration, country assignment,
and cloud-hosting footprint.
"""
from typing import Dict, Any, Tuple, Optional, List
import ipaddress
import re

from app.parsers.mime_parser import ParsedEmail
from app.forensics.received_analyzer import parse_received_headers
from app.forensics.ip_intelligence import analyze_ip, IPIntelligence
from app.features.schema import IP_VERSION_ENCODING

CLOUD_HOSTING_PATTERNS = {
    "amazon", "aws", "microsoft", "azure", "google", "digitalocean",
    "cloudflare", "ovh", "hetzner", "linode", "akamai", "oracle", "vultr", "fastly",
}


def extract_ip_infrastructure(
    parsed: Optional[ParsedEmail] = None,
    raw_evidence_available: bool = False,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts forensic features from the originating IP address.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    if not raw_evidence_available or not parsed:
        feats["ip_originating_present"] = 0.0
        feats["ip_originating_is_private"] = -1.0
        feats["ip_originating_version"] = IP_VERSION_ENCODING["none"]
        feats["ip_originating_asn_present"] = 0.0
        feats["ip_originating_org_present"] = 0.0
        feats["ip_originating_country_present"] = 0.0
        feats["ip_originating_cloud_hosting"] = 0.0
        feats["ip_originating_confidence"] = 0.0
        return feats, exps

    # 1. Identify originating IP candidate
    originating_ip: Optional[str] = None
    attribution_confidence = 0.0

    # Primary candidate: X-Originating-IP or X-Sender-IP
    for h in parsed.headers:
        name_lower = h.name.lower()
        if name_lower in ("x-originating-ip", "x-sender-ip"):
            match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{3,39})", h.value)
            if match:
                originating_ip = match.group(1).strip("[]")
                attribution_confidence = 0.9
                break

    # Secondary candidate: First public IP from chronological Received path (oldest hop)
    if not originating_ip:
        received_headers = [h.value for h in parsed.headers if h.name.lower() == "received"]
        if received_headers:
            analysis = parse_received_headers({"received": received_headers})
            for hop in analysis.chronological_hops:
                if hop.source_ip and hop.source_is_public:
                    originating_ip = hop.source_ip
                    attribution_confidence = 0.75
                    break
            if not originating_ip and analysis.public_ips:
                originating_ip = analysis.public_ips[0]
                attribution_confidence = 0.5
            elif not originating_ip and analysis.private_ips:
                originating_ip = analysis.private_ips[0]
                attribution_confidence = 0.3

    if not originating_ip:
        feats["ip_originating_present"] = 0.0
        feats["ip_originating_is_private"] = -1.0
        feats["ip_originating_version"] = IP_VERSION_ENCODING["none"]
        feats["ip_originating_asn_present"] = 0.0
        feats["ip_originating_org_present"] = 0.0
        feats["ip_originating_country_present"] = 0.0
        feats["ip_originating_cloud_hosting"] = 0.0
        feats["ip_originating_confidence"] = 0.0
        return feats, exps

    feats["ip_originating_present"] = 1.0
    feats["ip_originating_confidence"] = attribution_confidence

    # Parse IP version & private status
    try:
        ip_obj = ipaddress.ip_address(originating_ip)
        feats["ip_originating_version"] = IP_VERSION_ENCODING["ipv4"] if ip_obj.version == 4 else IP_VERSION_ENCODING["ipv6"]
        is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        feats["ip_originating_is_private"] = 1.0 if is_priv else 0.0
    except ValueError:
        feats["ip_originating_version"] = IP_VERSION_ENCODING["none"]
        feats["ip_originating_is_private"] = -1.0

    # ASN & Geo analysis (via offline GeoLite2 if present)
    intel: IPIntelligence = analyze_ip(originating_ip)
    has_asn = bool(intel.asn and intel.asn.asn)
    has_org = bool(intel.asn and intel.asn.organization)
    has_geo = bool(intel.geo and intel.geo.country_code)

    feats["ip_originating_asn_present"] = 1.0 if has_asn else 0.0
    feats["ip_originating_org_present"] = 1.0 if has_org else 0.0
    feats["ip_originating_country_present"] = 1.0 if has_geo else 0.0

    is_cloud = False
    if has_org and intel.asn and intel.asn.organization:
        org_name = intel.asn.organization.lower()
        if any(cloud in org_name for cloud in CLOUD_HOSTING_PATTERNS):
            is_cloud = True
    feats["ip_originating_cloud_hosting"] = 1.0 if is_cloud else 0.0

    return feats, exps
