"""Tests for Received-header forensic reconstruction.

Verifies:
- Hop parsing from Received headers
- Chronological ordering
- Public/private IP identification
- Anomaly detection
- Integration with API endpoint
"""
from __future__ import annotations

import io

from app.forensics.received_analyzer import (
    ReceivedChainAnalysis,
    _extract_ip,
    _extract_hostname,
    _is_private_ip,
    parse_received_headers,
)
from tests.conftest import SAMPLE_EML, SAMPLE_EML_HEADERS_ONLY


class TestReceivedParser:
    """Unit tests for the Received header parser."""

    def test_no_received_headers(self):
        headers = {"from": "sender@example.com"}
        analysis = parse_received_headers(headers)
        assert analysis.total_hops == 0
        assert "no_received_headers" in analysis.anomalies

    def test_single_hop(self):
        headers = {
            "received": "from mail.example.com [192.168.1.1] by mx.target.com with ESMTP id abc; Mon, 01 Jan 2024 12:00:00 +0000",
        }
        analysis = parse_received_headers(headers)
        assert analysis.total_hops == 1
        assert "only_one_hop" in analysis.anomalies
        assert len(analysis.hops) == 1
        hop = analysis.hops[0]
        assert hop.source_hostname == "mail.example.com"
        assert hop.source_ip == "192.168.1.1"
        assert hop.source_is_public is False  # private IP
        assert hop.protocol == "ESMTP"
        assert hop.timestamp is not None

    def test_multiple_hops_ordering(self):
        headers = {
            "received": [
                "from mx.target.com [10.0.0.1] by localhost with ESMTP; Mon, 01 Jan 2024 12:01:00 +0000",
                "from mail.example.com [203.0.113.1] by mx.target.com with ESMTPS; Mon, 01 Jan 2024 12:00:00 +0000",
            ],
        }
        analysis = parse_received_headers(headers)
        assert analysis.total_hops == 2

        # Raw order: hop 0 is closest to recipient
        assert analysis.hops[0].source_hostname == "mx.target.com"
        assert analysis.hops[1].source_hostname == "mail.example.com"

        # Chronological: reversed (oldest first)
        assert analysis.chronological_hops[0].source_hostname == "mail.example.com"
        assert analysis.chronological_hops[1].source_hostname == "mx.target.com"

    def test_public_ip_identification(self):
        headers = {
            "received": [
                "from mail.example.com [203.0.113.10] by mx.target.com with ESMTP; Mon, 01 Jan 2024 12:00:00 +0000",
                "from internal [192.168.1.1] by mail.example.com with ESMTP; Mon, 01 Jan 2024 11:59:00 +0000",
            ],
        }
        analysis = parse_received_headers(headers)
        assert "203.0.113.10" in analysis.public_ips
        assert "192.168.1.1" in analysis.private_ips

    def test_anomaly_detection_missing_ip(self):
        headers = {
            "received": "from mail.example.com by mx.target.com with ESMTP; Mon, 01 Jan 2024 12:00:00 +0000",
        }
        analysis = parse_received_headers(headers)
        assert "missing_source_ip" in analysis.hops[0].anomaly_indicators

    def test_anomaly_detection_missing_timestamp(self):
        headers = {
            "received": "from mail.example.com [203.0.113.1] by mx.target.com with ESMTP",
        }
        analysis = parse_received_headers(headers)
        assert "missing_timestamp" in analysis.hops[0].anomaly_indicators

    def test_extract_ip_from_brackets(self):
        assert _extract_ip("from host [1.2.3.4] by mx") == "1.2.3.4"

    def test_extract_ip_from_parens(self):
        assert _extract_ip("from host (1.2.3.4) by mx") == "1.2.3.4"

    def test_extract_ip_none(self):
        assert _extract_ip("from host by mx") is None

    def test_extract_hostname(self):
        assert _extract_hostname("from mail.example.com by mx.target.com", "from") == "mail.example.com"
        assert _extract_hostname("from mail.example.com by mx.target.com", "by") == "mx.target.com"
        assert _extract_hostname("from [1.2.3.4] by mx.target.com", "from") is None  # IP, not hostname

    def test_is_private_ip(self):
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("203.0.113.1") is False
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("not-an-ip") is None

    def test_timestamp_extraction(self):
        headers = {
            "received": "from mail.example.com [203.0.113.1] by mx.target.com; Mon, 01 Jan 2024 12:00:00 +0000",
        }
        analysis = parse_received_headers(headers)
        assert analysis.hops[0].timestamp is not None
        assert analysis.earliest_timestamp is not None
        assert analysis.latest_timestamp is not None


class TestReceivedEndpoint:
    """Integration tests for POST /api/emails/{id}/received."""

    def _upload_email(self, client) -> int:
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML_HEADERS_ONLY), "message/rfc822")},
        )
        assert resp.status_code == 201
        return resp.json()["id"]

    def test_received_endpoint_works(self, client):
        eid = self._upload_email(client)
        resp = client.post(f"/api/emails/{eid}/received")
        assert resp.status_code == 200
        data = resp.json()
        assert "hops" in data
        assert "chronological_hops" in data
        assert data["total_hops"] == 2
        assert "192.168.1.1" in data["private_ips"]
        assert "10.0.0.1" in data["private_ips"]

    def test_get_received(self, client):
        eid = self._upload_email(client)
        resp = client.get(f"/api/emails/{eid}/received")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_hops"] == 2

    def test_received_nonexistent_email(self, client):
        resp = client.post("/api/emails/99999/received")
        assert resp.status_code == 404

    def test_received_simple_email(self, client):
        """Email with no Received headers should return empty analysis."""
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
        )
        eid = resp.json()["id"]
        resp = client.get(f"/api/emails/{eid}/received")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_hops"] == 0
