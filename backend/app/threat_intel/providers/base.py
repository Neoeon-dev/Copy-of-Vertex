"""
VERTEX Phase D6 — Provider Abstraction Layer.

Abstract base class for threat intelligence providers.
All providers implement this interface.
"""

from __future__ import annotations

import abc
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from ..ioc import IOC, IOCType, is_private_or_reserved_ip
from ..schemas import (
    ProviderName,
    ThreatIntelFinding,
    Verdict,
    CacheStatus,
    ProviderError,
    RateLimitError,
    AuthError,
    TimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    """Configuration for a threat intelligence provider."""
    name: ProviderName
    api_key: str | None = None
    base_url: str = ""
    timeout_connect: float = 5.0
    timeout_read: float = 15.0
    timeout_total: float = 30.0
    max_retries: int = 3
    retry_backoff_factor: float = 0.5
    retry_jitter: float = 0.1
    rate_limit_per_minute: int = 60
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: float = 60.0
    cache_ttl_seconds: int = 3600  # 1 hour default
    enabled: bool = True


class ThreatIntelProvider(abc.ABC):
    """
    Abstract base class for threat intelligence providers.
    
    All providers must implement:
    - supported_ioc_types(): Which IOC types this provider supports
    - lookup_ioc(): Single IOC lookup
    - lookup_iocs(): Batch lookup with deduplication
    
    The base class provides:
    - HTTP client with timeouts/retries
    - Circuit breaker
    - Rate limiting
    - SSRF protection
    - Error handling
    """
    
    def __init__(self, config: ProviderConfig, cache: Any = None, circuit_breaker: Any = None, rate_limiter: Any = None):
        self.config = config
        self.cache = cache
        self.circuit_breaker = circuit_breaker
        self.rate_limiter = rate_limiter
        self._client: httpx.AsyncClient | None = None
        self._health = {
            "total_queries": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "rate_limited": 0,
            "consecutive_failures": 0,
            "last_success": None,
            "last_failure": None,
            "circuit_open": False,
            "circuit_open_since": None,
            "total_latency_ms": 0.0,
        }
    
    @abc.abstractmethod
    def supported_ioc_types(self) -> list[IOCType]:
        """Return list of IOC types this provider supports."""
        pass
    
    @abc.abstractmethod
    async def _lookup_raw(self, ioc: IOC) -> ThreatIntelFinding:
        """
        Perform the actual provider API call.
        
        This method should NOT handle caching, circuit breaking, or rate limiting.
        Those are handled by the public lookup_ioc method.
        """
        pass
    
    @abc.abstractmethod
    def _normalize_response(self, raw_response: dict[str, Any], ioc: IOC) -> ThreatIntelFinding:
        """
        Normalize provider-specific response into ThreatIntelFinding.
        
        This is where provider-specific JSON parsing happens.
        """
        pass
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=httpx.Timeout(
                    connect=self.config.timeout_connect,
                    read=self.config.timeout_read,
                    write=10.0,
                    pool=5.0,
                ),
                limits=limits,
                headers=self._default_headers(),
            )
        return self._client
    
    def _default_headers(self) -> dict[str, str]:
        """Default headers for API requests."""
        return {
            "User-Agent": "VERTEX/6.0 ThreatIntel",
            "Accept": "application/json",
        }
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
    
    # ─── SSRF Protection ──────────────────────────────────────────────
    
    def _validate_ioc_for_query(self, ioc: IOC) -> None:
        """
        Validate IOC before querying provider.
        
        Blocks private/internal IPs to prevent SSRF.
        """
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            if is_private_or_reserved_ip(ioc.normalized_value):
                raise ProviderError(
                    f"Blocked query to private/reserved IP: {ioc.normalized_value}",
                    "SSRF_BLOCKED",
                    self.config.name,
                    retryable=False,
                )
        
        # For URLs, check if hostname resolves to private IP
        if ioc.ioc_type == IOCType.URL:
            # The URL normalization already extracts and validates the hostname
            # Additional check could be added here if needed
            pass
    
    # ─── Circuit Breaker ──────────────────────────────────────────────
    
    def _check_circuit_breaker(self) -> None:
        """Check if circuit breaker is open."""
        if self.circuit_breaker:
            if not self.circuit_breaker.can_execute(self.config.name):
                from app.threat_intel.schemas import CircuitOpenError
                raise CircuitOpenError(self.config.name)
        else:
            # Simple built-in circuit breaker
            if self._health["circuit_open"]:
                if self._health["circuit_open_since"]:
                    import time
                    if time.time() - self._health["circuit_open_since"] > self.config.circuit_breaker_timeout:
                        # Try half-open
                        self._health["circuit_open"] = False
                        self._health["consecutive_failures"] = 0
                        logger.info("Circuit breaker half-open for %s", self.config.name.value)
                    else:
                        from app.threat_intel.schemas import CircuitOpenError
                        raise CircuitOpenError(self.config.name)
    
    def _record_success(self, latency_ms: float) -> None:
        """Record successful query for circuit breaker/health."""
        self._health["total_queries"] += 1
        self._health["successful_queries"] += 1
        self._health["consecutive_failures"] = 0
        self._health["last_success"] = time.time()
        self._health["total_latency_ms"] += latency_ms
        
        if self.circuit_breaker:
            self.circuit_breaker.record_success(self.config.name)
    
    def _record_failure(self, error: Exception) -> None:
        """Record failed query for circuit breaker/health."""
        self._health["total_queries"] += 1
        self._health["failed_queries"] += 1
        self._health["consecutive_failures"] += 1
        self._health["last_failure"] = time.time()
        
        if isinstance(error, RateLimitError):
            self._health["rate_limited"] += 1
        
        # Check circuit breaker threshold
        if self._health["consecutive_failures"] >= self.config.circuit_breaker_threshold:
            self._health["circuit_open"] = True
            self._health["circuit_open_since"] = time.time()
            logger.warning("Circuit breaker opened for %s after %d failures", 
                          self.config.name.value, self._health["consecutive_failures"])
        
        if self.circuit_breaker:
            self.circuit_breaker.record_failure(self.config.name)
    
    # ─── Rate Limiting ────────────────────────────────────────────────
    
    async def _check_rate_limit(self) -> None:
        """Check rate limit before query."""
        if self.rate_limiter:
            await self.rate_limiter.acquire(self.config.name)
        else:
            # Simple in-memory rate limiting
            pass  # Could implement token bucket here if needed
    
    # ─── Public API ───────────────────────────────────────────────────
    
    async def lookup_ioc(self, ioc: IOC) -> ThreatIntelFinding:
        """
        Look up a single IOC with caching, circuit breaker, rate limiting.
        
        Flow:
        1. Check cache
        2. Check circuit breaker
        3. Check rate limit
        3. Validate IOC (SSRF protection)
        4. Query provider with retries
        5. Cache result
        6. Return finding
        """
        # Check cache first
        if self.cache:
            cached = await self.cache.get(self.config.name, ioc.cache_key())
            if cached:
                cached.cache_status = CacheStatus.CACHED
                return cached
        
        # Check circuit breaker
        self._check_circuit_breaker()
        
        # Rate limit
        await self._check_rate_limit()
        
        # SSRF protection
        self._validate_ioc_for_query(ioc)
        
        # Query with retries
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                start = time.perf_counter()
                finding = await self._lookup_raw(ioc)
                latency_ms = (time.perf_counter() - start) * 1000
                
                finding.queried_at = finding.queried_at
                finding.cache_status = CacheStatus.LIVE
                
                # Set expiry based on TTL
                if finding.ttl:
                    from datetime import datetime, timedelta, timezone
                    finding.expires_at = datetime.now(timezone.utc) + timedelta(seconds=finding.ttl)
                
                # Cache result
                if self.cache:
                    await self.cache.set(
                        self.config.name,
                        ioc.cache_key(),
                        finding,
                        ttl=self.config.cache_ttl_seconds,
                    )
                
                self._record_success(latency_ms)
                return finding
                
            except RateLimitError as e:
                last_error = e
                self._health["rate_limited"] += 1
                if attempt < self.config.max_retries and e.retry_after:
                    wait = e.retry_after + (attempt * self.config.retry_backoff_factor)
                    logger.warning("Rate limited by %s, waiting %.1fs (attempt %d/%d)",
                                  self.config.name.value, wait, attempt + 1, self.config.max_retries + 1)
                    import asyncio
                    await asyncio.sleep(wait)
                    continue
                raise
                
            except (TimeoutError, httpx.TimeoutException) as e:
                last_error = TimeoutError(self.config.name, "read" if isinstance(e, httpx.ReadTimeout) else "connect")
                if attempt < self.config.max_retries:
                    wait = self.config.retry_backoff_factor * (2 ** attempt)
                    import asyncio
                    await asyncio.sleep(wait)
                    continue
                raise
                
            except AuthError:
                raise  # Don't retry auth errors
                
            except httpx.HTTPStatusError as e:
                last_error = ProviderError(
                    f"HTTP {e.response.status_code}: {e.response.text[:200]}",
                    f"HTTP_{e.response.status_code}",
                    self.config.name,
                    retryable=e.response.status_code >= 500,
                )
                if attempt < self.config.max_retries and e.response.status_code >= 500:
                    wait = self.config.retry_backoff_factor * (2 ** attempt)
                    import asyncio
                    await asyncio.sleep(wait)
                    continue
                raise
                
            except Exception as e:
                last_error = ProviderError(
                    f"Provider error: {type(e).__name__}: {e}",
                    "PROVIDER_ERROR",
                    self.config.name,
                    retryable=True,
                )
                if attempt < self.config.max_retries:
                    wait = self.config.retry_backoff_factor * (2 ** attempt)
                    import asyncio
                    await asyncio.sleep(wait)
                    continue
                raise
        
        # All retries exhausted
        self._record_failure(last_error or Exception("Unknown error"))
        
        # Return UNKNOWN finding with error info
        return ThreatIntelFinding(
            provider=self.config.name,
            provider_version="unknown",
            ioc_type=ioc.ioc_type.value,
            ioc_value=ioc.normalized_value,
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            error=str(last_error),
            cache_status=CacheStatus.UNAVAILABLE,
            provenance={"attempts": self.config.max_retries + 1},
        )
    
    async def lookup_iocs(self, iocs: list[IOC]) -> list[ThreatIntelFinding]:
        """
        Look up multiple IOCs with deduplication and budget awareness.
        
        Deduplicates by cache_key before querying.
        """
        # Deduplicate
        seen: set[str] = set()
        unique_iocs: list[IOC] = []
        for ioc in iocs:
            key = ioc.cache_key()
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        # Query in parallel with semaphore to limit concurrency
        import asyncio
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent per provider
        
        async def bounded_lookup(ioc: IOC) -> ThreatIntelFinding:
            async with semaphore:
                return await self.lookup_ioc(ioc)
        
        tasks = [bounded_lookup(ioc) for ioc in unique_iocs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        findings: list[ThreatIntelFinding] = []
        for ioc, result in zip(unique_iocs, results):
            if isinstance(result, Exception):
                findings.append(ThreatIntelFinding(
                    provider=self.config.name,
                    provider_version="unknown",
                    ioc_type=ioc.ioc_type.value,
                    ioc_value=ioc.normalized_value,
                    verdict=Verdict.UNKNOWN,
                    confidence=0.0,
                    error=f"Exception: {type(result).__name__}: {result}",
                    cache_status=CacheStatus.UNAVAILABLE,
                ))
            else:
                findings.append(result)
        
        return findings
    
    def get_health(self) -> dict[str, Any]:
        """Get provider health status."""
        avg_latency = 0.0
        if self._health["successful_queries"] > 0:
            avg_latency = self._health["total_latency_ms"] / self._health["successful_queries"]
        
        return {
            "provider": self.config.name.value,
            "enabled": self.config.enabled,
            "total_queries": self._health["total_queries"],
            "successful_queries": self._health["successful_queries"],
            "failed_queries": self._health["failed_queries"],
            "rate_limited": self._health["rate_limited"],
            "consecutive_failures": self._health["consecutive_failures"],
            "circuit_open": self._health["circuit_open"],
            "circuit_open_since": self._health["circuit_open_since"],
            "average_latency_ms": round(avg_latency, 2),
            "success_rate": (
                self._health["successful_queries"] / self._health["total_queries"]
                if self._health["total_queries"] > 0 else 1.0
            ),
        }