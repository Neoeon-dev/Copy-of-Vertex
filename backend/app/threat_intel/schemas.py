"""
VERTEX Phase D6 — Threat Intelligence Schemas.

Common data contracts for provider responses and aggregated intelligence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ProviderName(str, Enum):
    """Supported threat intelligence providers."""
    OPENSHPHISH = "openphish"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"


class Verdict(str, Enum):
    """Standardized verdict from threat intelligence providers."""
    UNKNOWN = "UNKNOWN"       # No data / not in database
    BENIGN = "BENIGN"         # Clean / no threats found
    SUSPICIOUS = "SUSPICIOUS" # Some indicators but not confirmed malicious
    MALICIOUS = "MALICIOUS"   # Confirmed malicious


class CacheStatus(str, Enum):
    """Cache state for a provider response."""
    LIVE = "LIVE"             # Fresh from provider
    CACHED = "CACHED"         # From cache, within TTL
    STALE = "STALE"           # From cache, expired but provider unavailable
    UNAVAILABLE = "UNAVAILABLE"  # Provider error, no cache
    NOT_FOUND = "NOT_FOUND"   # Provider returned 404/no data


class ProviderError(Exception):
    """Base exception for provider errors."""
    def __init__(self, message: str, error_class: str, provider: ProviderName, retryable: bool = False):
        super().__init__(message)
        self.error_class = error_class
        self.provider = provider
        self.retryable = retryable


class RateLimitError(ProviderError):
    """Provider rate limit exceeded."""
    def __init__(self, provider: ProviderName, retry_after: int | None = None):
        super().__init__(
            f"Rate limited by {provider.value}",
            "RATE_LIMITED",
            provider,
            retryable=True,
        )
        self.retry_after = retry_after


class AuthError(ProviderError):
    """Provider authentication failed."""
    def __init__(self, provider: ProviderName):
        super().__init__(
            f"Authentication failed for {provider.value}",
            "AUTH_ERROR",
            provider,
            retryable=False,
        )


class TimeoutError(ProviderError):
    """Provider request timed out."""
    def __init__(self, provider: ProviderName, timeout_type: str):
        super().__init__(
            f"{timeout_type} timeout for {provider.value}",
            "TIMEOUT",
            provider,
            retryable=True,
        )


class CircuitOpenError(ProviderError):
    """Circuit breaker is open for this provider."""
    def __init__(self, provider: ProviderName):
        super().__init__(
            f"Circuit breaker open for {provider.value}",
            "CIRCUIT_OPEN",
            provider,
            retryable=False,
        )


@dataclass
class ThreatIntelFinding:
    """
    Normalized threat intelligence finding from a single provider.
    
    Every provider response is normalized into this schema.
    """
    provider: ProviderName
    provider_version: str              # API version queried
    ioc_type: str                      # IPV4, IPV6, DOMAIN, URL, FILE_HASH
    ioc_value: str                     # Normalized IOC value
    verdict: Verdict
    confidence: float                  # Provider's confidence 0.0-1.0 (if available)
    categories: list[str] = field(default_factory=list)  # Malware family, phishing, etc.
    detections: int = 0                # Number of engines detecting (VT)
    total_engines: int = 0             # Total engines scanned (VT)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    ttl: int | None = None             # Cache TTL in seconds
    queried_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    cache_status: CacheStatus = CacheStatus.LIVE
    provider_reference: str | None = None  # Provider-specific ID (VT analysis ID, etc.)
    raw_available: bool = False        # Whether raw response is stored
    error: str | None = None           # Error if query failed
    provenance: dict[str, Any] = field(default_factory=dict)  # Full provider response metadata
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "provider_version": self.provider_version,
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "categories": self.categories,
            "detections": self.detections,
            "total_engines": self.total_engines,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "ttl": self.ttl,
            "queried_at": self.queried_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "cache_status": self.cache_status.value,
            "provider_reference": self.provider_reference,
            "raw_available": self.raw_available,
            "error": self.error,
            "provenance": self.provenance,
        }
    
    @property
    def is_malicious(self) -> bool:
        return self.verdict == Verdict.MALICIOUS
    
    @property
    def is_suspicious(self) -> bool:
        return self.verdict == Verdict.SUSPICIOUS
    
    @property
    def is_benign(self) -> bool:
        return self.verdict == Verdict.BENIGN
    
    @property
    def is_unknown(self) -> bool:
        return self.verdict == Verdict.UNKNOWN


@dataclass
class IntelligenceAssessment:
    """
    Aggregated intelligence assessment from multiple providers.
    
    This is the primary output of D6 intelligence aggregation.
    """
    queried_iocs: list[dict[str, Any]]  # List of {type, value, source}
    findings: list[ThreatIntelFinding]
    provider_summary: dict[str, dict[str, Any]]  # Per-provider stats
    malicious_count: int = 0
    suspicious_count: int = 0
    benign_count: int = 0
    unknown_count: int = 0
    unavailable_count: int = 0
    confidence: float = 0.0            # Aggregated confidence 0.0-1.0
    freshness: float = 0.0             # How fresh is the intelligence (0.0-1.0)
    provider_agreement: list[str] = field(default_factory=list)  # IOCs where providers agree
    provider_disagreement: list[str] = field(default_factory=list)  # IOCs where providers disagree
    evidence_quality: str = "MEDIUM"   # HIGH, MEDIUM, LOW, DEGRADED
    explanation: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    engine_version: str = "6.0.0"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "queried_iocs": self.queried_iocs,
            "findings": [f.to_dict() for f in self.findings],
            "provider_summary": self.provider_summary,
            "malicious_count": self.malicious_count,
            "suspicious_count": self.suspicious_count,
            "benign_count": self.benign_count,
            "unknown_count": self.unknown_count,
            "unavailable_count": self.unavailable_count,
            "confidence": round(self.confidence, 4),
            "freshness": round(self.freshness, 4),
            "provider_agreement": self.provider_agreement,
            "provider_disagreement": self.provider_disagreement,
            "evidence_quality": self.evidence_quality,
            "explanation": self.explanation,
            "provenance": self.provenance,
            "engine_version": self.engine_version,
        }
    
    def __post_init__(self):
        # Compute counts from findings if not set
        if self.findings and not any([self.malicious_count, self.suspicious_count, self.benign_count, self.unknown_count, self.unavailable_count]):
            for f in self.findings:
                if f.verdict == Verdict.MALICIOUS:
                    self.malicious_count += 1
                elif f.verdict == Verdict.SUSPICIOUS:
                    self.suspicious_count += 1
                elif f.verdict == Verdict.BENIGN:
                    self.benign_count += 1
                elif f.verdict == Verdict.UNKNOWN:
                    self.unknown_count += 1
                if f.cache_status == CacheStatus.UNAVAILABLE:
                    self.unavailable_count += 1


@dataclass
class ProviderHealth:
    """Health status for a threat intelligence provider."""
    provider: ProviderName
    available: bool = True
    last_successful_query: datetime | None = None
    last_failure: datetime | None = None
    consecutive_failures: int = 0
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    rate_limited_count: int = 0
    average_latency_ms: float = 0.0
    circuit_open: bool = False
    circuit_open_since: datetime | None = None
    cache_hit_rate: float = 0.0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "available": self.available,
            "last_successful_query": self.last_successful_query.isoformat() if self.last_successful_query else None,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
            "consecutive_failures": self.consecutive_failures,
            "total_queries": self.total_queries,
            "successful_queries": self.successful_queries,
            "failed_queries": self.failed_queries,
            "rate_limited_count": self.rate_limited_count,
            "average_latency_ms": round(self.average_latency_ms, 2),
            "circuit_open": self.circuit_open,
            "circuit_open_since": self.circuit_open_since.isoformat() if self.circuit_open_since else None,
            "cache_hit_rate": round(self.cache_hit_rate, 4),
        }
    
    @property
    def success_rate(self) -> float:
        if self.total_queries == 0:
            return 1.0
        return self.successful_queries / self.total_queries


@dataclass
class QueryBudget:
    """Query budget for a single email analysis."""
    max_ip_queries: int = 10
    max_domain_queries: int = 20
    max_url_queries: int = 30
    max_hash_queries: int = 10
    max_total_queries: int = 50
    
    def __post_init__(self):
        self._used: dict[str, int] = {
            "IPV4": 0,
            "IPV6": 0,
            "DOMAIN": 0,
            "URL": 0,
            "FILE_HASH": 0,
        }
    
    def can_query(self, ioc_type: str) -> bool:
        type_key = ioc_type.upper()
        if type_key == "IPV4" or type_key == "IPV6":
            ip_key = "IPV4" if type_key == "IPV4" else "IPV6"
            return self._used.get(ip_key, 0) < getattr(self, f"max_{ip_key.lower()}_queries", 10)
        elif type_key == "DOMAIN":
            return self._used.get("DOMAIN", 0) < self.max_domain_queries
        elif type_key == "URL":
            return self._used.get("URL", 0) < self.max_url_queries
        elif type_key == "FILE_HASH":
            return self._used.get("FILE_HASH", 0) < self.max_hash_queries
        return True
    
    def use(self, ioc_type: str) -> bool:
        if not self.can_query(ioc_type):
            return False
        type_key = ioc_type.upper()
        if type_key in ("IPV4", "IPV6"):
            ip_key = "IPV4" if type_key == "IPV4" else "IPV6"
            self._used[ip_key] += 1
        else:
            self._used[type_key] += 1
        return True
    
    def remaining(self) -> dict[str, int]:
        return {
            "IPV4": self.max_ip_queries - self._used.get("IPV4", 0),
            "IPV6": self.max_ipv6_queries - self._used.get("IPV6", 0) if hasattr(self, 'max_ipv6_queries') else self.max_ip_queries - self._used.get("IPV6", 0),
            "DOMAIN": self.max_domain_queries - self._used.get("DOMAIN", 0),
            "URL": self.max_url_queries - self._used.get("URL", 0),
            "FILE_HASH": self.max_hash_queries - self._used.get("FILE_HASH", 0),
            "TOTAL": self.max_total_queries - sum(self._used.values()),
        }