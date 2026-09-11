"""
VERTEX Phase D6 — OpenPhish Provider.

OpenPhish provides a phishing URL feed.
- Community feed: https://openphish.com/feed.txt (free, updated every 12h)
- Enterprise API: Requires subscription

This implementation supports:
- URL lookups against the community feed
- Caching of the feed
- No API key required for community feed
"""

from __future__ import annotations

import logging
import time
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
)

logger = logging.getLogger(__name__)


class OpenPhishProvider(ThreatIntelProvider):
    """
    OpenPhish threat intelligence provider.
    
    Uses the community feed (no API key needed).
    Feed format: one URL per line.
    Updated every 12 hours.
    """
    
    COMMUNITY_FEED_URL = "https://openphish.com/feed.txt"
    ENTERPRISE_API_URL = "https://api.openphish.com/v1"  # Requires subscription
    
    def __init__(self, config: ProviderConfig, cache: Any = None, circuit_breaker: Any = None, rate_limiter: Any = None):
        super().__init__(config, cache, circuit_breaker, rate_limiter)
        self._feed_cache: set[str] | None = None
        self._feed_fetched_at: float = 0
        self._feed_ttl = config.cache_ttl_seconds or 43200  # 12 hours default
    
    def supported_ioc_types(self) -> list[IOCType]:
        return [IOCType.URL]
    
    def _default_headers(self) -> dict[str, str]:
        headers = super()._default_headers()
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
    
    async def _fetch_feed(self) -> set[str]:
        """Fetch and parse the OpenPhish community feed."""
        now = time.time()
        
        # Return cached feed if still valid
        if self._feed_cache is not None and (now - self._feed_fetched_at) < self._feed_ttl:
            return self._feed_cache
        
        client = await self._get_client()
        
        try:
            # Use community feed (no API key required)
            url = self.COMMUNITY_FEED_URL
            response = await client.get(url, timeout=self.config.timeout_read)
            response.raise_for_status()
            
            # Parse feed: one URL per line
            urls = set()
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if line and line.startswith('http'):
                    urls.add(line)
            
            self._feed_cache = urls
            self._feed_fetched_at = now
            logger.info("Fetched OpenPhish feed: %d URLs", len(urls))
            
            return urls
            
        except httpx.TimeoutException:
            raise TimeoutError(ProviderName.OPENSHPHISH, "read")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthError(ProviderName.OPENSHPHISH)
            if e.response.status_code == 429:
                from app.threat_intel.schemas import RateLimitError
                retry_after = int(e.response.headers.get("Retry-After", 60))
                raise RateLimitError(ProviderName.OPENSHPHISH, retry_after)
            raise
        except Exception as e:
            logger.error("OpenPhish feed fetch failed: %s", e)
            # Return stale cache if available
            if self._feed_cache is not None:
                logger.warning("Returning stale OpenPhish feed (%d URLs)", len(self._feed_cache))
                return self._feed_cache
            raise
    
    async def _lookup_raw(self, ioc: IOC) -> Any:
        """Check if URL is in OpenPhish feed."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict, CacheStatus
        
        if ioc.ioc_type != "URL":
            return ThreatIntelFinding(
                provider=ProviderName.OPENSHPHISH,
                provider_version="community_feed",
                ioc_type=ioc.ioc_type.value,
                ioc_value=ioc.normalized_value,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                error="OpenPhish only supports URL lookups",
            )
        
        feed = await self._fetch_feed()
        
        # Check for exact match
        # Also check without trailing slash variations
        search_urls = {ioc.normalized_value}
        if ioc.normalized_value.endswith('/'):
            search_urls.add(ioc.normalized_value.rstrip('/'))
        else:
            search_urls.add(ioc.normalized_value + '/')
        
        found = any(url in self._feed_cache for url in search_urls)
        
        return {
            "provider": "openphish",
            "provider_version": "community_feed",
            "ioc_type": "URL",
            "ioc_value": ioc.normalized_value,
            "verdict": Verdict.MALICIOUS.value if found else Verdict.UNKNOWN.value,
            "confidence": 0.9 if found else 0.0,
            "categories": ["phishing"] if found else [],
            "detections": 1 if found else 0,
            "total_engines": 1,
            "first_seen": None,
            "last_seen": None,
            "ttl": 43200,  # 12 hours
            "queried_at": None,  # Will be set by base class
            "expires_at": None,
            "cache_status": CacheStatus.LIVE,
            "provider_reference": "community_feed",
            "raw_available": False,
            "error": None,
            "provenance": {
                "feed_size": len(self._feed_cache) if self._feed_cache else 0,
                "feed_age_hours": (time.time() - self._feed_fetched_at) / 3600 if self._feed_fetched_at else None,
            },
        }
    
    def _normalize_response(self, raw_response: dict[str, Any], ioc: IOC) -> Any:
        """Convert raw dict to ThreatIntelFinding."""
        from app.threat_intel.schemas import ThreatIntelFinding, Verdict, CacheStatus
        from datetime import datetime, timezone
        
        return ThreatIntelFinding(
            provider=ProviderName.OPENSHPHISH,
            provider_version=raw_response.get("provider_version", "community_feed"),
            ioc_type=raw_response["ioc_type"],
            ioc_value=raw_response["ioc_value"],
            verdict=Verdict(raw_response["verdict"]),
            confidence=raw_response["confidence"],
            categories=raw_response.get("categories", []),
            detections=raw_response.get("detections", 0),
            total_engines=raw_response.get("total_engines", 1),
            first_seen=None,
            last_seen=None,
            ttl=raw_response.get("ttl", 43200),
            queried_at=datetime.now(timezone.utc),
            expires_at=None,
            cache_status=CacheStatus.LIVE,
            provider_reference=raw_response.get("provider_reference"),
            raw_available=False,
            error=raw_response.get("error"),
            provenance=raw_response.get("provenance", {}),
        )


# Enterprise API support (placeholder for future)
class OpenPhishEnterpriseProvider(OpenPhishProvider):
    """
    OpenPhish Enterprise API provider.
    
    Requires API key and subscription.
    Supports real-time URL lookup API.
    """
    
    def __init__(self, config: ProviderConfig, cache: Any = None, circuit_breaker: Any = None, rate_limiter: Any = None):
        if not config.api_key:
            raise ValueError("OpenPhish Enterprise requires API key")
        super().__init__(config, cache, circuit_breaker, rate_limiter)
        self.config.base_url = "https://api.openphish.com/v1"
    
    async def _lookup_raw(self, ioc: IOC) -> Any:
        if ioc.ioc_type != "URL":
            from app.threat_intel.schemas import ThreatIntelFinding, Verdict
            return ThreatIntelFinding(
                provider=ProviderName.OPENSHPHISH,
                provider_version="enterprise_api",
                ioc_type=ioc.ioc_type.value,
                ioc_value=ioc.normalized_value,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                error="OpenPhish Enterprise only supports URL lookups",
            )
        
        client = await self._get_client()
        
        try:
            # Enterprise API: POST /url with JSON body
            response = await client.post(
                "/url",
                json={"url": ioc.normalized_value},
                timeout=self.config.timeout_read,
            )
            response.raise_for_status()
            data = response.json()
            
            # Parse enterprise response
            # Expected format: {"status": "phishing|clean|unknown", "details": {...}}
            status = data.get("status", "unknown").lower()
            
            verdict_map = {
                "phishing": "MALICIOUS",
                "clean": "BENIGN",
                "unknown": "UNKNOWN",
            }
            
            return {
                "provider": "openphish",
                "provider_version": "enterprise_api",
                "ioc_type": "URL",
                "ioc_value": ioc.normalized_value,
                "verdict": verdict_map.get(status, "UNKNOWN"),
                "confidence": 0.95 if status == "phishing" else (0.8 if status == "clean" else 0.0),
                "categories": ["phishing"] if status == "phishing" else [],
                "detections": 1 if status == "phishing" else 0,
                "total_engines": 1,
                "ttl": 3600,
                "provider_reference": data.get("id"),
                "raw_available": True,
                "provenance": data,
            }
            
        except httpx.TimeoutException:
            raise TimeoutError("openphish", "read")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthError("openphish")
            if e.response.status_code == 429:
                from app.threat_intel.schemas import RateLimitError
                retry_after = int(e.response.headers.get("Retry-After", 60))
                raise RateLimitError(ProviderName.OPENSHPHISH, retry_after)
            raise
        except Exception as e:
            logger.error("OpenPhish Enterprise lookup failed: %s", e)
            raise