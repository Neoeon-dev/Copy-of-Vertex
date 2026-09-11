"""Tests for IP intelligence analysis.

Verifies:
- IP classification (public/private/reserved)
- GeoIP lookup (stubbed)
- ASN lookup (stubbed)
- IP extraction from headers
- API endpoint integration
"""
from __future__ import annotations

import io
from unittest.mock import patch, MagicMock

from app.forensics.ip_intelligence import (
    GeoInfo,
    ASNInfo,
    IPIntelligence,
    analyze_ip,
    extract_ips_from_headers,
)
from tests.conftest import SAMPLE_EML, SAMPLE_EML_HEADERS_ONLY


class TestIPClassification:
    """IP address classification tests."""

    def test_public_ip(self):
        intel = analyze_ip("8.8.8.8")
        assert intel.is_public is True
        assert intel.is_private is False

    def test_private_ip(self):
        intel = analyze_ip("192.168.1.1")
        assert intel.is_private is True
        assert intel.is_public is False
        assert "private" in intel.warnings[0].lower()

    def test_loopback(self):
        intel = analyze_ip("127.0.0.1")
        assert intel.is_private is True

    def test_invalid_ip(self):
        intel = analyze_ip("not-an-ip")
        assert "Invalid IP" in intel.warnings[0]

    def test_reserved_ip(self):
        intel = analyze_ip("240.0.0.1")
        assert intel.is_reserved is True


class TestGeoIPLookup:
    """GeoIP analysis with mocked databases."""

    def test_geoip_lookup_public_ip(self):
        mock_city = MagicMock()
        mock_city.country.iso_code = "US"
        mock_city.country.name = "United States"
        mock_city.subdivisions.most_specific.name = "California"
        mock_city.city.name = "Mountain View"
        mock_city.location.latitude = 37.386
        mock_city.location.longitude = -122.0838
        mock_city.location.accuracy_radius = 1000

        mock_asn = MagicMock()
        mock_asn.autonomous_system_number = 15169
        mock_asn.autonomous_system_organization = "Google LLC"
        mock_asn.network = "8.8.8.0/24"

        with patch("app.forensics.ip_intelligence.get_geoip_service") as mock_svc:
            service = MagicMock()
            service.lookup_geo.return_value = GeoInfo(
                country_code="US",
                country_name="United States",
                region="California",
                city="Mountain View",
                latitude=37.386,
                longitude=-122.0838,
            )
            service.lookup_asn.return_value = ASNInfo(
                asn=15169,
                organization="Google LLC",
                network="8.8.8.0/24",
            )
            mock_svc.return_value = service

            intel = analyze_ip("8.8.8.8")

        assert intel.geo is not None
        assert intel.geo.country_code == "US"
        assert intel.geo.city == "Mountain View"
        assert intel.asn is not None
        assert intel.asn.asn == 15169
        assert intel.asn.organization == "Google LLC"

    def test_geoip_private_ip_skipped(self):
        intel = analyze_ip("192.168.1.1")
        assert intel.geo is None
        assert intel.asn is None


class TestIPExtraction:
    """IP extraction from email headers."""

    def test_extract_from_received(self):
        headers = {
            "received": "from mail.example.com [203.0.113.1] by mx.target.com [10.0.0.1]",
        }
        ips = extract_ips_from_headers(headers)
        assert "203.0.113.1" in ips
        assert "10.0.0.1" in ips

    def test_extract_from_multiple_received(self):
        headers = {
            "received": [
                "from mail.example.com [1.2.3.4] by mx.target.com",
                "from mx.target.com [5.6.7.8] by localhost",
            ],
        }
        ips = extract_ips_from_headers(headers)
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_no_ips(self):
        headers = {"from": "sender@example.com"}
        ips = extract_ips_from_headers(headers)
        assert ips == []

    def test_deduplication(self):
        headers = {
            "received": [
                "from host [1.2.3.4] by mx",
                "from mx [1.2.3.4] by localhost",
            ],
        }
        ips = extract_ips_from_headers(headers)
        assert ips.count("1.2.3.4") == 1


class TestIPIntelEndpoint:
    """Integration tests for POST /api/emails/{id}/ip-intel."""

    def _upload_email(self, client) -> int:
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML_HEADERS_ONLY), "message/rfc822")},
        )
        assert resp.status_code == 201
        return resp.json()["id"]

    def test_ip_intel_endpoint_works(self, client):
        eid = self._upload_email(client)
        resp = client.post(f"/api/emails/{eid}/ip-intel")
        assert resp.status_code == 200
        data = resp.json()
        assert "ips" in data
        assert data["total_ips"] == 2
        assert data["private_ips"] == 2  # 192.168.1.1 and 10.0.0.1 are private

    def test_get_ip_intel(self, client):
        eid = self._upload_email(client)
        resp = client.get(f"/api/emails/{eid}/ip-intel")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_ips"] == 2

    def test_ip_intel_nonexistent(self, client):
        resp = client.post("/api/emails/99999/ip-intel")
        assert resp.status_code == 404
