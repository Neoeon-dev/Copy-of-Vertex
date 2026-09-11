"""
VERTEX Phase D6 — VirusTotal Provider.

VirusTotal v3 API supports:
- URL lookup (GET /urls/{id})
- Domain lookup (GET /domains/{domain})
- IP address lookup (GET /ip_addresses/{ip})
- File hash lookup (GET /files/{hash})

IMPORTANT: This provider does NOT upload files or URLs.
Only performs reputation lookups using indicators.
"""

from __future__ import annotations

import base64
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


class VirusTotalProvider(ThreatIntelProvider):
    """
    VirusTotal v3 API provider.
    
    Requires API key (free tier: 4 requests/minute, 500/day).
    Supports URL, domain, IP, and file hash lookups.
    
    Does NOT upload files or URLs - only reputation lookups.
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, config: ProviderConfig, cache: Any = None, circuit_breaker: Any = None, rate_limiter: Any = None):
        if not config.api_key:
            raise ValueError("VirusTotal requires API key")
        super().__init__(config, cache, circuit_breaker, rate_limiter)
        self.config.base_url = self.BASE_URL
        # Rate limit: 4 requests/minute on free tier
        self.config.rate_limit_per_minute = min(config.rate_limit_per_minute, 4)
    
    def _default_headers(self) -> dict[str, str]:
        headers = super()._default_headers()
        headers["x-apikey"] = self.config.api_key
        return headers
    
    def supported_ioc_types(self) -> list[IOCType]:
        return [IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6, IOCType.FILE_HASH]
    
    def _get_url_id(self, url: str) -> str:
        """Generate VirusTotal URL ID (base64 encoded, no padding)."""
        # VT URL ID is base64(url) without padding
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    
    async def _lookup_raw(self, ioc: IOC) -> Any:
        """Route to appropriate lookup method based on IOC type."""
        if ioc.ioc_type == IOCType.URL:
            return await self._lookup_url(ioc)
        elif ioc.ioc_type == IOCType.DOMAIN:
            return await self._lookup_domain(ioc)
        elif ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return await self._lookup_ip(ioc)
        elif ioc.ioc_type == IOCType.FILE_HASH:
            return await self._lookup_hash(ioc)
        else:
            from app.threat_intel.schemas import ThreatIntelFinding, Verdict
            return ThreatIntelFinding(
                provider=ProviderName.VIRUSTOTAL,
                provider_version="v3",
                ioc_type=ioc.ioc_type.value,
                ioc_value=ioc.normalized_value,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                error=f"Unsupported IOC type: {ioc.ioc_type}",
            )
    
    async def _lookup_url(self, ioc: IOC) -> Any:
        """Look up URL reputation."""
        client = await self._get_client()
        url_id = self._get_url_id(ioc.normalized_value)
        
        try:
            response = await client.get(
                f"/urls/{url_id}",
                timeout=self.config.timeout_read,
            )
            response.raise_for_status()
            data = response.json()
            
            return self._parse_url_response(data, ioc)
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                # URL not in VT database - not necessarily benign
                return self._not_found_response(ioc)
            if e.response.status_code == 401:
                raise AuthError(ProviderName.VIRUSTOTAL)
            if e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 60))
                raise RateLimitError(ProviderName.VIRUSTOTAL, retry_after)
            raise
    
    async def _lookup_domain(self, ioc: IOC) -> Any:
        """Look up domain reputation."""
        client = await self._get_client()
        
        try:
            response = await client.get(
                f"/domains/{ioc.normalized_value}",
                timeout=self.config.timeout_read,
            )
            response.raise_for_status()
            data = response.json()
            
            return self._parse_domain_response(data, ioc)
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return self._not_found_response(ioc)
            if e.response.status_code == 401:
                raise AuthError(ProviderName.VIRUSTOTAL)
            if e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 60))
                raise RateLimitError(ProviderName.VIRUSTOTAL, retry_after)
            raise
    
    async def _lookup_ip(self, ioc: IOC) -> Any:
        """Look up IP address reputation."""
        client = await self._get_client()
        
        try:
            response = await client.get(
                f"/ip_addresses/{ioc.normalized_value}",
                timeout=self.config.timeout_read,
            )
            response.raise_for_status()
            data = response.json()
            
            return self._parse_ip_response(data, ioc)
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return self._not_found_response(ioc)
            if e.response.status_code == 401:
                raise AuthError(ProviderName.VIRUSTOTAL)
            if e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 60))
                raise RateLimitError(ProviderName.VIRUSTOTAL, retry_after)
            raise
    
    async def _lookup_hash(self, ioc: IOC) -> Any:
        """Look up file hash reputation."""
        client = await self._get_client()
        
        try:
            response = await client.get(
                f"/files/{ioc.normalized_value}",
                timeout=self.config.timeout_read,
            )
            response.raise_for_status()
            data = response.json()
            
            return self._parse_file_response(data, ioc)
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return self._not_found_response(ioc)
            if e.response.status_code == 401:
                raise AuthError(ProviderName.VIRUSTOTAL)
            if e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 60))
                raise RateLimitError(ProviderName.VIRUSTOTAL, retry_after)
            raise
    
    def _parse_url_response(self, data: dict[str, Any], ioc: IOC) -> Any:
        """Parse VirusTotal URL analysis response."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict, CacheStatus
        from datetime import datetime, timezone
        
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values())
        
        # Determine verdict
        if malicious > 0:
            verdict = Verdict.MALICIOUS
            confidence = min(0.95, 0.5 + (malicious / max(total, 1)) * 0.5)
        elif suspicious > 0:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.6
        elif harmless > 0 and malicious == 0:
            verdict = Verdict.BENIGN
            confidence = 0.7
        else:
            verdict = Verdict.UNKNOWN
            confidence = 0.0
        
        # Extract categories
        categories = attrs.get("categories", [])
        if isinstance(categories, dict):
            categories = list(categories.values())
        
        return {
            "provider": "virustotal",
            "provider_version": "v3",
            "ioc_type": "URL",
            "ioc_value": ioc.normalized_value,
            "verdict": verdict.value,
            "confidence": round(confidence, 2),
            "categories": categories,
            "detections": malicious,
            "total_engines": total,
            "first_seen": None,
            "last_seen": attrs.get("last_analysis_date"),
            "ttl": 3600,
            "provider_reference": data.get("data", {}).get("id"),
            "raw_available": True,
            "provenance": {
                "stats": stats,
                "categories": categories,
                "reputation": attrs.get("reputation"),
                "times_submitted": attrs.get("times_submitted"),
            },
        }
    
    def _parse_domain_response(self, data: dict[str, Any], ioc: IOC) -> Any:
        """Parse VirusTotal domain response."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict, CacheStatus
        from datetime import datetime, timezone
        
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        
        if malicious > 0:
            verdict = Verdict.MALICIOUS
            confidence = min(0.95, 0.5 + (malicious / max(total, 1)) * 0.5)
        elif suspicious > 0:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.6
        else:
            verdict = Verdict.UNKNOWN
            confidence = 0.0
        
        categories = attrs.get("categories", [])
        if isinstance(categories, dict):
            categories = list(categories.values())
        
        return {
            "provider": "virustotal",
            "provider_version": "v3",
            "ioc_type": "DOMAIN",
            "ioc_value": ioc.normalized_value,
            "verdict": verdict.value,
            "confidence": round(confidence, 2),
            "categories": categories,
            "detections": malicious,
            "total_engines": total,
            "first_seen": attrs.get("creation_date"),
            "last_seen": attrs.get("last_analysis_date"),
            "ttl": 86400,  # 24 hours for domain
            "provider_reference": data.get("data", {}).get("id"),
            "raw_available": True,
            "provenance": {
                "stats": stats,
                "categories": categories,
                "reputation": attrs.get("reputation"),
                "registrar": attrs.get("registrar"),
                "whois": attrs.get("whois"),
            },
        }
    
    def _parse_ip_response(self, data: dict[str, Any], ioc: IOC) -> Any:
        """Parse VirusTotal IP address response."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict
        
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        
        if malicious > 0:
            verdict = Verdict.MALICIOUS
            confidence = min(0.95, 0.5 + (malicious / max(total, 1)) * 0.5)
        elif suspicious > 0:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.6
        else:
            verdict = Verdict.UNKNOWN
            confidence = 0.0
        
        # Network info
        asn = attrs.get("asn")
        as_owner = attrs.get("as_owner")
        country = attrs.get("country")
        network = attrs.get("network")
        
        return {
            "provider": "virustotal",
            "provider_version": "v3",
            "ioc_type": ioc.ioc_type.value,
            "ioc_value": ioc.normalized_value,
            "verdict": verdict.value,
            "confidence": round(confidence, 2),
            "categories": [],
            "detections": malicious,
            "total_engines": total,
            "first_seen": None,
            "last_seen": attrs.get("last_analysis_date"),
            "ttl": 3600,
            "provider_reference": data.get("data", {}).get("id"),
            "raw_available": True,
            "provenance": {
                "stats": stats,
                "asn": asn,
                "as_owner": as_owner,
                "country": country,
                "network": network,
                "reputation": attrs.get("reputation"),
            },
        }
    
    def _parse_file_response(self, data: dict[str, Any], ioc: IOC) -> Any:
        """Parse VirusTotal file hash response."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict
        
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        
        if malicious > 0:
            verdict = Verdict.MALICIOUS
            confidence = min(0.98, 0.6 + (malicious / max(total, 1)) * 0.4)
        elif suspicious > 0:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.7
        else:
            verdict = Verdict.UNKNOWN
            confidence = 0.0
        
        # Extract meaningful info
        names = attrs.get("names", [])
        type_desc = attrs.get("type_description", "")
        size = attrs.get("size", 0)
        magic = attrs.get("magic", "")
        
        return {
            "provider": "virustotal",
            "provider_version": "v3",
            "ioc_type": "FILE_HASH",
            "ioc_value": ioc.normalized_value,
            "verdict": verdict.value,
            "confidence": round(confidence, 2),
            "categories": [],
            "detections": malicious,
            "total_engines": total,
            "first_seen": attrs.get("creation_date"),
            "last_seen": attrs.get("last_analysis_date"),
            "ttl": 86400,
            "provider_reference": data.get("data", {}).get("id"),
            "raw_available": True,
            "provenance": {
                "stats": stats,
                "names": names[:10],  # Limit
                "type_description": type_desc,
                "size": size,
                "magic": magic,
                "sha256": attrs.get("sha256"),
                "md5": attrs.get("md5"),
                "sha1": attrs.get("sha1"),
                "reputation": attrs.get("reputation"),
            },
        }
    
    def _not_found_response(self, ioc: IOC) -> Any:
        """Response when IOC not found in VirusTotal database."""
        from app.threat_intel.schemas import Verdict
        
        # NOT FOUND != BENIGN
        return {
            "provider": "virustotal",
            "provider_version": "v3",
            "ioc_type": ioc.ioc_type.value,
            "ioc_value": ioc.normalized_value,
            "verdict": Verdict.UNKNOWN.value,
            "confidence": 0.0,
            "categories": [],
            "detections": 0,
            "total_engines": 0,
            "ttl": 3600,
            "error": "Not found in VirusTotal database",
            "provenance": {"status": "not_found"},
        }
    
    def _normalize_response(self, raw_response: dict[str, Any], ioc: IOC) -> Any:
        """Convert raw dict to ThreatIntelFinding."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict, CacheStatus
        from datetime import datetime, timezone
        
        return ThreatIntelFinding(
            provider=ProviderName.VIRUSTOTAL,
            provider_version=raw_response.get("provider_version", "v3"),
            ioc_type=raw_response["ioc_type"],
            ioc_value=raw_response["ioc_value"],
            verdict=Verdict(raw_response["verdict"]),
            confidence=raw_response["confidence"],
            categories=raw_response.get("categories", []),
            detections=raw_response.get("detections", 0),
            total_engines=raw_response.get("total_engines", 0),
            first_seen=raw_response.get("first_seen"),
            last_seen=raw_response.get("last_seen"),
            ttl=raw_response.get("ttl", 3600),
            queried_at=datetime.now(timezone.utc),
            expires_at=None,
            cache_status=CacheStatus.LIVE,
            provider_reference=raw_response.get("provider_reference"),
            raw_available=raw_response.get("raw_available", False),
            error=raw_response.get("error"),
            provenance=raw_response.get("provenance", {}),
        )