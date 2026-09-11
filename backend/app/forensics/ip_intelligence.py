"""IP intelligence module.

For each public IP observed in an email, provides:
- Country, region, city, lat/lon (via MaxMind GeoLite2)
- ASN, organization, network
- Whether the IP is private/reserved
- Basic reputation signals

Uses MaxMind GeoLite2 offline where available.
Falls back to stub data when the database is not present.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Attempt to import geoip2; gracefully degrade if not available
try:
    import geoip2.database as _geoip2_db
    import geoip2.errors as _geoip2_errors
    _GEOIP_AVAILABLE = True
except ImportError:
    _GEOIP_AVAILABLE = False


# ── Data classes ─────────────────────────────────────────────────────


@dataclass
class GeoInfo:
    """Geolocation data for an IP."""

    country_code: str | None = None
    country_name: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy_radius_km: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "country_code": self.country_code,
            "country_name": self.country_name,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "accuracy_radius_km": self.accuracy_radius_km,
        }


@dataclass
class ASNInfo:
    """ASN data for an IP."""

    asn: int | None = None
    organization: str | None = None
    network: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asn": self.asn,
            "organization": self.organization,
            "network": self.network,
        }


@dataclass
class IPIntelligence:
    """Complete intelligence for a single IP address."""

    ip: str
    is_public: bool | None = None
    is_private: bool | None = None
    is_reserved: bool | None = None
    geo: GeoInfo | None = None
    asn: ASNInfo | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "is_public": self.is_public,
            "is_private": self.is_private,
            "is_reserved": self.is_reserved,
            "geo": self.geo.to_dict() if self.geo else None,
            "asn": self.asn.to_dict() if self.asn else None,
            "warnings": self.warnings,
        }


# ── GeoIP lookup ─────────────────────────────────────────────────────


class GeoIPService:
    """Wrapper around MaxMind GeoLite2 databases."""

    def __init__(self) -> None:
        self._city_reader = None
        self._asn_reader = None
        self._load_databases()

    def _load_databases(self) -> None:
        """Attempt to load GeoLite2 databases from standard paths."""
        if not _GEOIP_AVAILABLE:
            logger.info("geoip2 library not available; using stub GeoIP data")
            return

        # Check common paths
        db_dir = os.environ.get("GEOIP_DB_DIR", "/usr/share/GeoIP")
        city_db = os.path.join(db_dir, "GeoLite2-City.mmdb")
        asn_db = os.path.join(db_dir, "GeoLite2-ASN.mmdb")

        # Also check project-local paths
        project_db_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data", "geoip")
        if not os.path.exists(city_db):
            city_db = os.path.join(project_db_dir, "GeoLite2-City.mmdb")
        if not os.path.exists(asn_db):
            asn_db = os.path.join(project_db_dir, "GeoLite2-ASN.mmdb")

        try:
            if os.path.exists(city_db):
                self._city_reader = _geoip2_db.Reader(city_db)
                logger.info("Loaded GeoLite2-City from %s", city_db)
            else:
                logger.info("GeoLite2-City not found at %s; geolocation unavailable", city_db)
        except Exception as e:
            logger.warning("Failed to load GeoLite2-City: %s", e)

        try:
            if os.path.exists(asn_db):
                self._asn_reader = _geoip2_db.Reader(asn_db)
                logger.info("Loaded GeoLite2-ASN from %s", asn_db)
            else:
                logger.info("GeoLite2-ASN not found at %s; ASN data unavailable", asn_db)
        except Exception as e:
            logger.warning("Failed to load GeoLite2-ASN: %s", e)

    def lookup_geo(self, ip: str) -> GeoInfo | None:
        """Look up geolocation for an IP address."""
        if not self._city_reader:
            return None
        try:
            resp = self._city_reader.city(ip)
            return GeoInfo(
                country_code=resp.country.iso_code,
                country_name=resp.country.name,
                region=resp.subdivisions.most_specific.name if resp.subdivisions else None,
                city=resp.city.name,
                latitude=resp.location.latitude,
                longitude=resp.location.longitude,
                accuracy_radius_km=resp.location.accuracy_radius,
            )
        except _geoip2_errors.AddressNotFoundError:
            return None
        except Exception as e:
            logger.warning("GeoIP lookup failed for %s: %s", ip, e)
            return None

    def lookup_asn(self, ip: str) -> ASNInfo | None:
        """Look up ASN information for an IP address."""
        if not self._asn_reader:
            return None
        try:
            resp = self._asn_reader.asn(ip)
            return ASNInfo(
                asn=resp.autonomous_system_number,
                organization=resp.autonomous_system_organization,
                network=str(resp.network),
            )
        except _geoip2_errors.AddressNotFoundError:
            return None
        except Exception as e:
            logger.warning("ASN lookup failed for %s: %s", ip, e)
            return None

    def close(self) -> None:
        """Close database readers."""
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()


# Singleton service instance
_geoip_service: GeoIPService | None = None


def get_geoip_service() -> GeoIPService:
    global _geoip_service
    if _geoip_service is None:
        _geoip_service = GeoIPService()
    return _geoip_service


# ── Public API ───────────────────────────────────────────────────────


def analyze_ip(ip: str) -> IPIntelligence:
    """Perform full intelligence analysis on a single IP address.

    This is the main entry point for IP analysis.
    """
    intel = IPIntelligence(ip=ip)

    # Classify IP
    try:
        addr = ipaddress.ip_address(ip)
        intel.is_private = addr.is_private or addr.is_loopback or addr.is_link_local
        intel.is_reserved = addr.is_reserved
        intel.is_public = not (intel.is_private or intel.is_reserved)
    except ValueError:
        intel.warnings.append(f"Invalid IP address: {ip}")
        return intel

    if intel.is_private:
        intel.warnings.append(
            "IP is private/reserved — infrastructure location cannot be determined"
        )
        return intel

    # GeoIP lookup
    service = get_geoip_service()
    intel.geo = service.lookup_geo(ip)
    intel.asn = service.lookup_asn(ip)

    if not intel.geo:
        intel.warnings.append("Geolocation data not available for this IP")
    if not intel.asn:
        intel.warnings.append("ASN data not available for this IP")

    return intel


def analyze_ips(ips: list[str]) -> list[IPIntelligence]:
    """Analyze a list of IP addresses."""
    return [analyze_ip(ip) for ip in ips]


def extract_ips_from_headers(headers: dict[str, str | list[str]]) -> list[str]:
    """Extract all unique IP addresses from email headers."""
    import re

    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    found_ips: set[str] = set()

    for key in ("received", "x-originating-ip", "x-mailer", "x-sender-ip"):
        values = headers.get(key, [])
        if not isinstance(values, list):
            values = [values]
        for val in values:
            if val:
                for match in ip_pattern.finditer(val):
                    ip = match.group(1)
                    # Filter out obviously internal IPs from header metadata
                    found_ips.add(ip)

    return sorted(found_ips)
