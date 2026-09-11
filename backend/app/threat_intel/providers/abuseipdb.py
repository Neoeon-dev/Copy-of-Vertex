"""
VERTEX Phase D6 — AbuseIPDB Provider.

AbuseIPDB provides IP reputation data.
- API v2: https://docs.abuseipdb.com/
- Free tier: 1,000 requests/day
- Supports IPv4 and IPv6
- Reports: abuse confidence score, categories, country, ISP, last reported
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ..ioc import IOC, IOCType
from .base import ProviderConfig, ThreatIntelProvider
from ..schemas import (
    ProviderName,
    ThreatIntelFinding,
    Verdict,
    CacheStatus,
    TimeoutError,
    AuthError,
    RateLimitError,
)

logger = logging.getLogger(__name__)


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    AbuseIPDB API v2 provider.
    
    Requires API key (free tier available).
    Supports IP address reputation lookups only.
    """
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    # AbuseIPDB category mapping
    CATEGORY_MAP = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH Brute-Force",
        23: "IoT Targeted",
        24: "Malware",
        25: "Ransomware",
        26: "Botnet",
    }
    
    def __init__(self, config: ProviderConfig, cache: Any = None, circuit_breaker: Any = None, rate_limiter: Any = None):
        if not config.api_key:
            raise ValueError("AbuseIPDB requires API key")
        super().__init__(config, cache, circuit_breaker, rate_limiter)
        self.config.base_url = self.BASE_URL
        # Free tier: 1000/day = ~0.7/minute, be conservative
        self.config.rate_limit_per_minute = min(config.rate_limit_per_minute, 30)
    
    def _default_headers(self) -> dict[str, str]:
        headers = super()._default_headers()
        headers["Key"] = self.config.api_key
        headers["Accept"] = "application/json"
        return headers
    
    def supported_ioc_types(self) -> list[IOCType]:
        return [IOCType.IPV4, IOCType.IPV6]
    
    async def _lookup_raw(self, ioc: IOC) -> Any:
        """Look up IP reputation from AbuseIPDB."""
        if ioc.ioc_type not in (IOCType.IPV4, IOCType.IPV6):
            from app.threat_intel.schemas import ThreatIntelFinding, Verdict
            return ThreatIntelFinding(
                provider=ProviderName.ABUSEIPDB,
                provider_version="v2",
                ioc_type=ioc.ioc_type.value,
                ioc_value=ioc.normalized_value,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                error="AbuseIPDB only supports IP address lookups",
            )
        
        client = await self._get_client()
        
        try:
            # AbuseIPDB check endpoint
            # maxAgeInDays: how far back to check reports (default 30, max 365)
            # verbose: include reports details
            params = {
                "ipAddress": ioc.normalized_value,
                "maxAgeInDays": 30,
                "verbose": "true",
            }
            
            response = await client.get(
                "/check",
                params=params,
                timeout=self.config.timeout_read,
            )
            response.raise_for_status()
            data = response.json()
            
            return self._parse_response(data, ioc)
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthError(ProviderName.ABUSEIPDB)
            if e.response.status_code == 422:
                # Invalid IP
                from app.threat_intel.schemas import ThreatIntelFinding, Verdict
                return ThreatIntelFinding(
                    provider=ProviderName.ABUSEIPDB,
                    provider_version="v2",
                    ioc_type=ioc.ioc_type.value,
                    ioc_value=ioc.normalized_value,
                    verdict=Verdict.UNKNOWN,
                    confidence=0.0,
                    error="Invalid IP address format",
                )
            if e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 60))
                raise RateLimitError(ProviderName.ABUSEIPDB, retry_after)
            raise
        except httpx.TimeoutException:
            raise TimeoutError(ProviderName.ABUSEIPDB, "read")
        except Exception as e:
            logger.error("AbuseIPDB lookup failed: %s", e)
            raise
    
    def _parse_response(self, data: dict[str, Any], ioc: IOC) -> Any:
        """Parse AbuseIPDB check response."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict, CacheStatus
        from datetime import datetime, timezone
        
        ip_data = data.get("data", {})
        
        abuse_confidence = ip_data.get("abuseConfidenceScore", 0)
        total_reports = ip_data.get("totalReports", 0)
        country_code = ip_data.get("countryCode")
        country_name = ip_data.get("countryName")
        isp = ip_data.get("isp")
        domain = ip_data.get("domain")
        hostnames = ip_data.get("hostnames", [])
        is_tor = ip_data.get("isTor", False)
        is_whitelisted = ip_data.get("isWhitelisted", False)
        last_reported_at = ip_data.get("lastReportedAt")
        
        # Parse categories
        raw_categories = ip_data.get("reports", [])
        categories = []
        for report in raw_categories:
            cat_ids = report.get("categories", [])
            for cat_id in cat_ids:
                cat_name = self.CATEGORY_MAP.get(cat_id, f"Category_{cat_id}")
                if cat_name not in categories:
                    categories.append(cat_name)
        
        # Determine verdict based on abuse confidence
        if is_whitelisted:
            verdict = Verdict.BENIGN
            confidence = 0.8
        elif abuse_confidence >= 75:
            verdict = Verdict.MALICIOUS
            confidence = min(0.95, 0.5 + (abuse_confidence / 100) * 0.5)
        elif abuse_confidence >= 25:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.5 + (abuse_confidence / 100) * 0.3
        elif total_reports > 0:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.4
        else:
            verdict = Verdict.UNKNOWN
            confidence = 0.0
        
        # Boost confidence for TOR
        if is_tor:
            if verdict == Verdict.UNKNOWN:
                verdict = Verdict.SUSPICIOUS
            confidence = min(0.9, confidence + 0.2)
            if "TOR" not in categories:
                categories.append("TOR")
        
        return {
            "provider": "abuseipdb",
            "provider_version": "v2",
            "ioc_type": ioc.ioc_type.value,
            "ioc_value": ioc.normalized_value,
            "verdict": verdict.value,
            "confidence": round(confidence, 2),
            "categories": categories,
            "detections": total_reports,
            "total_engines": 1,
            "first_seen": None,
            "last_seen": last_reported_at,
            "ttl": 86400,  # 24 hours
            "provider_reference": str(ip_data.get("ipAddress")),
            "raw_available": True,
            "provenance": {
                "abuse_confidence_score": abuse_confidence,
                "total_reports": total_reports,
                "country_code": country_code,
                "country_name": country_name,
                "isp": isp,
                "domain": domain,
                "hostnames": hostnames,
                "is_tor": is_tor,
                "is_whitelisted": is_whitelisted,
                "raw_categories": [r.get("categories", []) for r in raw_categories],
            },
        }
    
    def _normalize_response(self, raw_response: dict[str, Any], ioc: IOC) -> Any:
        """Convert raw dict to ThreatIntelFinding."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict, CacheStatus
        from datetime import datetime, timezone
        
        return ThreatIntelFinding(
            provider=ProviderName.ABUSEIPDB,
            provider_version=raw_response.get("provider_version", "v2"),
            ioc_type=raw_response["ioc_type"],
            ioc_value=raw_response["ioc_value"],
            verdict=Verdict(raw_response["verdict"]),
            confidence=raw_response["confidence"],
            categories=raw_response.get("categories", []),
            detections=raw_response.get("detections", 0),
            total_engines=raw_response.get("total_engines", 1),
            first_seen=raw_response.get("first_seen"),
            last_seen=raw_response.get("last_seen"),
            ttl=raw_response.get("ttl", 86400),
            queried_at=datetime.now(timezone.utc),
            expires_at=None,
            cache_status=CacheStatus.LIVE,
            provider_reference=raw_response.get("provider_reference"),
            raw_available=raw_response.get("raw_available", False),
            error=raw_response.get("error"),
            provenance=raw_response.get("provenance", {}),
        )