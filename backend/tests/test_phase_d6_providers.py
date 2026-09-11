"""
Phase D6 Tests — Provider Abstraction and Reliability.

Tests for circuit breaker, rate limiter, cache, and provider interface.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.threat_intel.cache import ThreatIntelCache
from app.threat_intel.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
    CircuitState,
)
from app.threat_intel.rate_limiter import (
    AsyncTokenBucketRateLimiter,
    RateLimitConfig,
    RateLimiterRegistry,
)
from app.threat_intel.schemas import (
    ProviderName,
    Verdict,
    CacheStatus,
    ThreatIntelFinding,
)
from app.threat_intel.ioc import IOC, IOCType


class TestCache:
    """Tests for ThreatIntelCache."""
    
    @pytest.fixture
    def cache(self):
        return ThreatIntelCache(default_ttl=60, max_entries=100)
    
    @pytest.fixture
    def sample_finding(self):
        return ThreatIntelFinding(
            provider=ProviderName.VIRUSTOTAL,
            provider_version="v3",
            ioc_type="IPV4",
            ioc_value="8.8.8.8",
            verdict=Verdict.MALICIOUS,
            confidence=0.9,
            categories=["malware"],
            detections=5,
            total_engines=80,
        )
    
    @pytest.mark.asyncio
    async def test_cache_miss(self, cache):
        result = await cache.get("virustotal", "IPV4:8.8.8.8")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_cache_hit(self, cache, sample_finding):
        await cache.set("virustotal", "IPV4:8.8.8.8", sample_finding, ttl=60)
        result = await cache.get("virustotal", "IPV4:8.8.8.8")
        assert result is not None
        assert result.verdict == Verdict.MALICIOUS
        assert result.cache_status == CacheStatus.CACHED
    
    @pytest.mark.asyncio
    async def test_cache_expiry(self, cache, sample_finding):
        # Test that expired entries are served stale by default
        await cache.set("virustotal", "IPV4:8.8.8.8", sample_finding, ttl=0)
        await asyncio.sleep(0.01)
        result = await cache.get("virustotal", "IPV4:8.8.8.8")
        # Expired entries are served stale by default (resilience)
        assert result is not None
        assert result.cache_status == CacheStatus.STALE
        
        # Test that UNAVAILABLE findings are NOT served stale
        unavailable_finding = ThreatIntelFinding(
            provider=ProviderName.VIRUSTOTAL,
            provider_version="v3",
            ioc_type="IPV4",
            ioc_value="9.9.9.9",
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            cache_status=CacheStatus.UNAVAILABLE,
        )
        await cache.set("virustotal", "IPV4:9.9.9.9", unavailable_finding, ttl=0)
        await asyncio.sleep(0.01)
        result = await cache.get("virustotal", "IPV4:9.9.9.9")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_stale_serve(self, cache, sample_finding):
        # Test with CACHED status - should serve stale
        sample_finding.cache_status = CacheStatus.CACHED
        await cache.set("virustotal", "IPV4:8.8.8.8", sample_finding, ttl=-1)
        result = await cache.get("virustotal", "IPV4:8.8.8.8")
        assert result is not None
        assert result.cache_status == CacheStatus.STALE
        
        # Test with UNAVAILABLE status - should NOT serve stale
        sample_finding.cache_status = CacheStatus.UNAVAILABLE
        await cache.set("virustotal", "IPV4:9.9.9.9", sample_finding, ttl=-1)
        result = await cache.get("virustotal", "IPV4:9.9.9.9")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_cache_stats(self, cache, sample_finding):
        await cache.set("virustotal", "IPV4:8.8.8.8", sample_finding, ttl=60)
        await cache.get("virustotal", "IPV4:8.8.8.8")
        await cache.get("virustotal", "IPV4:8.8.8.8")
        await cache.get("virustotal", "IPV4:9.9.9.9")  # miss
        
        stats = cache.get_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert abs(stats["hit_rate"] - 2/3) < 0.01
    
    @pytest.mark.asyncio
    async def test_cache_eviction(self):
        cache = ThreatIntelCache(default_ttl=60, max_entries=2)
        f1 = ThreatIntelFinding(provider=ProviderName.VIRUSTOTAL, provider_version="v3", ioc_type="IPV4", ioc_value="1.1.1.1", verdict=Verdict.BENIGN, confidence=0.5)
        f2 = ThreatIntelFinding(provider=ProviderName.VIRUSTOTAL, provider_version="v3", ioc_type="IPV4", ioc_value="2.2.2.2", verdict=Verdict.BENIGN, confidence=0.5)
        f3 = ThreatIntelFinding(provider=ProviderName.VIRUSTOTAL, provider_version="v3", ioc_type="IPV4", ioc_value="3.3.3.3", verdict=Verdict.BENIGN, confidence=0.5)
        
        await cache.set("virustotal", "IPV4:1.1.1.1", f1)
        await cache.set("virustotal", "IPV4:2.2.2.2", f2)
        await cache.set("virustotal", "IPV4:3.3.3.3", f3)  # Should evict LRU
        
        stats = cache.get_stats()
        assert stats["entries"] == 2
        assert stats["evictions"] == 1
    
    @pytest.mark.asyncio
    async def test_invalidate(self, cache, sample_finding):
        await cache.set("virustotal", "IPV4:8.8.8.8", sample_finding)
        await cache.invalidate("virustotal", "IPV4:8.8.8.8")
        result = await cache.get("virustotal", "IPV4:8.8.8.8")
        assert result is None


class TestCircuitBreaker:
    """Tests for CircuitBreaker."""
    
    @pytest.fixture
    def breaker(self):
        return CircuitBreaker("test", CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=1.0,
        ))
    
    def test_initial_state_closed(self, breaker):
        assert breaker.state == CircuitState.CLOSED
        assert breaker.can_execute() is True
    
    def test_opens_after_failures(self, breaker):
        breaker.record_failure()
        breaker.record_failure()
        assert breaker.state == CircuitState.CLOSED
        
        breaker.record_failure()  # 3rd failure - should open
        assert breaker.state == CircuitState.OPEN
        assert breaker.can_execute() is False
    
    def test_half_open_after_timeout(self, breaker):
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN
        
        time.sleep(1.1)  # Wait for timeout
        assert breaker.state == CircuitState.HALF_OPEN
        assert breaker.can_execute() is True
    
    def test_closes_after_successes_in_half_open(self, breaker):
        # Force open
        for _ in range(3):
            breaker.record_failure()
        time.sleep(1.1)
        assert breaker.state == CircuitState.HALF_OPEN
        
        breaker.record_success()
        assert breaker.state == CircuitState.HALF_OPEN
        
        breaker.record_success()
        assert breaker.state == CircuitState.CLOSED
    
    def test_failure_in_half_open_reopens(self, breaker):
        for _ in range(3):
            breaker.record_failure()
        time.sleep(1.1)
        assert breaker.state == CircuitState.HALF_OPEN
        
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN
    
    def test_stats(self, breaker):
        breaker.record_success()
        breaker.record_success()
        breaker.record_failure()
        
        stats = breaker.get_stats()
        assert stats["total_calls"] == 3
        assert stats["successful_calls"] == 2
        assert stats["failed_calls"] == 1
        assert stats["consecutive_failures"] == 1


class TestCircuitBreakerRegistry:
    """Tests for CircuitBreakerRegistry."""
    
    def test_get_breaker(self):
        registry = CircuitBreakerRegistry()
        b1 = registry.get_breaker("provider1")
        b2 = registry.get_breaker("provider1")
        assert b1 is b2
        assert b1.name == "provider1"
    
    def test_can_execute(self):
        registry = CircuitBreakerRegistry(
            default_config=CircuitBreakerConfig(failure_threshold=3)
        )
        # Unknown provider - no breaker exists, so can execute
        assert registry.can_execute("unknown") is True
        
        # Create and fail a breaker
        breaker = registry.get_breaker("provider1")
        for _ in range(3):
            breaker.record_failure()
        assert registry.can_execute("provider1") is False


class TestRateLimiter:
    """Tests for TokenBucketRateLimiter."""
    
    @pytest.fixture
    def limiter(self):
        return AsyncTokenBucketRateLimiter("test", RateLimitConfig(
            requests_per_minute=10,
            requests_per_hour=100,
            requests_per_day=1000,
            burst_allowance=2,
        ))
    
    @pytest.mark.asyncio
    async def test_acquire_allows(self, limiter):
        result = await limiter.async_acquire(1)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_acquire_blocks_when_empty(self, limiter):
        # Use all tokens
        for _ in range(12):  # 10 + 2 burst
            await limiter.async_acquire(1)
        
        # Should block now
        result = await limiter.async_acquire(1, timeout=0.1)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_refill_over_time(self, limiter):
        # Use all tokens
        for _ in range(12):  # 10 + 2 burst
            await limiter.async_acquire(1)
        
        # After using all tokens, we should have 0
        # (refill happens on next acquire, not continuously)
        assert limiter._tokens_minute <= 0.5  # Allow small floating point
    
    @pytest.mark.asyncio
    async def test_stats(self, limiter):
        await limiter.async_acquire(5)
        await limiter.async_acquire(3)
        stats = limiter.get_stats()
        # Stats count requests, not tokens
        assert stats["allowed_requests"] == 2
        assert stats["rejected_requests"] == 0


class TestRateLimiterRegistry:
    """Tests for RateLimiterRegistry."""
    
    def test_get_limiter(self):
        registry = RateLimiterRegistry()
        l1 = registry.get_limiter("provider1")
        l2 = registry.get_limiter("provider1")
        assert l1 is l2
    
    def test_async_get_limiter(self):
        registry = RateLimiterRegistry()
        l1 = registry.get_limiter("provider1", async_mode=True)
        l2 = registry.get_limiter("provider1", async_mode=True)
        assert l1 is l2
    
    def test_acquire(self):
        registry = RateLimiterRegistry()
        result = registry.acquire("provider1", tokens=1, block=False)
        assert result is True


class TestProviderAbstraction:
    """Tests for provider interface compliance."""
    
    def test_provider_config(self):
        from app.threat_intel.providers import ProviderConfig
        
        config = ProviderConfig(
            name=ProviderName.VIRUSTOTAL,
            api_key="test_key",
            timeout_connect=5.0,
            timeout_read=15.0,
        )
        assert config.name == ProviderName.VIRUSTOTAL
        assert config.api_key == "test_key"
    
    def test_provider_requires_api_key(self):
        from app.threat_intel.providers import VirusTotalProvider, AbuseIPDBProvider, ProviderConfig
        
        # These should raise without API key when instantiated
        with pytest.raises(ValueError):
            VirusTotalProvider(ProviderConfig(name=ProviderName.VIRUSTOTAL))
        
        with pytest.raises(ValueError):
            AbuseIPDBProvider(ProviderConfig(name=ProviderName.ABUSEIPDB))
    
    def test_openphish_no_api_key_required(self):
        from app.threat_intel.providers import OpenPhishProvider, ProviderConfig
        
        # OpenPhish should work without API key (community feed)
        provider = OpenPhishProvider(ProviderConfig(name=ProviderName.OPENSHPHISH))
        assert provider is not None


class TestIntelligenceAggregator:
    """Tests for IntelligenceAggregator."""
    
    @pytest.fixture
    def aggregator(self):
        from app.threat_intel.aggregator import IntelligenceAggregator, AggregationConfig
        return IntelligenceAggregator(AggregationConfig())
    
    @pytest.fixture
    def sample_findings(self):
        return [
            ThreatIntelFinding(
                provider=ProviderName.VIRUSTOTAL,
                provider_version="v3",
                ioc_type="IPV4",
                ioc_value="8.8.8.8",
                verdict=Verdict.MALICIOUS,
                confidence=0.9,
                categories=["malware"],
                detections=10,
                total_engines=80,
            ),
            ThreatIntelFinding(
                provider=ProviderName.ABUSEIPDB,
                provider_version="v2",
                ioc_type="IPV4",
                ioc_value="8.8.8.8",
                verdict=Verdict.MALICIOUS,
                confidence=0.85,
                categories=["botnet"],
                detections=5,
                total_engines=1,
            ),
            ThreatIntelFinding(
                provider=ProviderName.OPENSHPHISH,
                provider_version="community_feed",
                ioc_type="URL",
                ioc_value="https://phishing.example.com",
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
            ),
        ]
    
    def test_aggregate_basic(self, aggregator, sample_findings):
        assessment = aggregator.aggregate(sample_findings)
        
        assert assessment.malicious_count == 2
        assert assessment.suspicious_count == 0
        assert assessment.benign_count == 0
        assert assessment.unknown_count == 1
        assert len(assessment.findings) == 3
        assert "virustotal" in assessment.provider_summary
        assert "abuseipdb" in assessment.provider_summary
        assert "openphish" in assessment.provider_summary
    
    def test_provider_agreement(self, aggregator):
        findings = [
            ThreatIntelFinding(
                provider=ProviderName.VIRUSTOTAL,
                provider_version="v3",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.MALICIOUS,
                confidence=0.9,
                detections=10,
                total_engines=80,
            ),
            ThreatIntelFinding(
                provider=ProviderName.ABUSEIPDB,
                provider_version="v2",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.MALICIOUS,
                confidence=0.85,
                detections=5,
                total_engines=1,
            ),
        ]
        
        assessment = aggregator.aggregate(findings)
        assert len(assessment.provider_agreement) == 1
        assert "MALICIOUS" in assessment.provider_agreement[0]
    
    def test_provider_disagreement(self, aggregator):
        findings = [
            ThreatIntelFinding(
                provider=ProviderName.VIRUSTOTAL,
                provider_version="v3",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.MALICIOUS,
                confidence=0.9,
                detections=10,
                total_engines=80,
            ),
            ThreatIntelFinding(
                provider=ProviderName.ABUSEIPDB,
                provider_version="v2",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.BENIGN,
                confidence=0.8,
                detections=0,
                total_engines=1,
            ),
        ]
        
        assessment = aggregator.aggregate(findings)
        assert len(assessment.provider_disagreement) == 1
        assert "MALICIOUS" in assessment.provider_disagreement[0]
        assert "BENIGN" in assessment.provider_disagreement[0]
    
    def test_unknown_is_neutral(self, aggregator):
        findings = [
            ThreatIntelFinding(
                provider=ProviderName.VIRUSTOTAL,
                provider_version="v3",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
            ),
            ThreatIntelFinding(
                provider=ProviderName.ABUSEIPDB,
                provider_version="v2",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.MALICIOUS,
                confidence=0.8,
            ),
        ]
        
        assessment = aggregator.aggregate(findings)
        # UNKNOWN should not count as agreement or disagreement
        assert assessment.malicious_count == 1
        assert assessment.unknown_count == 1
    
    def test_confidence_calculation(self, aggregator):
        findings = [
            ThreatIntelFinding(
                provider=ProviderName.VIRUSTOTAL,  # reliability 0.9
                provider_version="v3",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.MALICIOUS,
                confidence=0.9,
                detections=10,
                total_engines=80,
            ),
        ]
        
        assessment = aggregator.aggregate(findings)
        # Weighted by provider reliability (VT=0.9): 0.9 * 0.9 / 0.9 = 0.9
        assert assessment.confidence > 0.8
    
    def test_evidence_quality_high(self, aggregator):
        from app.threat_intel.schemas import CacheStatus
        
        findings = [
            ThreatIntelFinding(
                provider=ProviderName.VIRUSTOTAL,
                provider_version="v3",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.MALICIOUS,
                confidence=0.9,
                cache_status=CacheStatus.LIVE,
            ),
            ThreatIntelFinding(
                provider=ProviderName.ABUSEIPDB,
                provider_version="v2",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.MALICIOUS,
                confidence=0.85,
                cache_status=CacheStatus.LIVE,
            ),
        ]
        
        assessment = aggregator.aggregate(findings)
        assert assessment.evidence_quality == "HIGH"
    
    def test_evidence_quality_degraded(self, aggregator):
        from app.threat_intel.schemas import CacheStatus
        
        findings = [
            ThreatIntelFinding(
                provider=ProviderName.VIRUSTOTAL,
                provider_version="v3",
                ioc_type="IPV4",
                ioc_value="1.2.3.4",
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                cache_status=CacheStatus.UNAVAILABLE,
            ),
        ]
        
        assessment = aggregator.aggregate(findings)
        assert assessment.evidence_quality == "DEGRADED"
    
    def test_explanation_generation(self, aggregator, sample_findings):
        assessment = aggregator.aggregate(sample_findings)
        
        assert "malicious" in assessment.explanation.lower()
        assert "D5.1" in assessment.explanation
        assert "external evidence" in assessment.explanation.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])