"""
VERTEX Phase D6 — Threat Intelligence Database Models.

PostgreSQL models for IOC storage, query history, findings, provider health, and cache.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    JSON, BigInteger, DateTime, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IOCTypeEnum(str, Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE_HASH = "FILE_HASH"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"


class VerdictEnum(str, Enum):
    UNKNOWN = "UNKNOWN"
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class CacheStatusEnum(str, Enum):
    LIVE = "LIVE"
    CACHED = "CACHED"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_FOUND = "NOT_FOUND"


class ProviderNameEnum(str, Enum):
    OPENSHPHISH = "openphish"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"


class IOC(Base):
    """Normalized Indicator of Compromise."""
    
    __tablename__ = "threat_intel_iocs"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Canonical IOC
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    normalized_value: Mapped[str] = mapped_column(String(512), index=True)
    display_value: Mapped[str] = mapped_column(String(512))
    
    # Source tracking
    source_location: Mapped[str] = mapped_column(String(128))
    extraction_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Privacy
    is_private: Mapped[bool] = mapped_column(default=False)
    
    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    
    # Confidence in extraction
    confidence: Mapped[float] = mapped_column(default=1.0)
    
    # Relationships
    queries: Mapped[list["ThreatIntelQuery"]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )
    
    __table_args__ = (
        UniqueConstraint("ioc_type", "normalized_value", name="uq_ioc_type_value"),
        Index("ix_ioc_type_seen", "ioc_type", "first_seen"),
    )
    
    def __repr__(self) -> str:
        return f"<IOC {self.ioc_type}:{self.normalized_value[:50]}>"


class ThreatIntelQuery(Base):
    """Record of a threat intelligence query."""
    
    __tablename__ = "threat_intel_queries"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Link to IOC
    ioc_id: Mapped[int] = mapped_column(
        ForeignKey("threat_intel_iocs.id", ondelete="CASCADE"), index=True
    )
    
    # Provider info
    provider: Mapped[str] = mapped_column(String(64), index=True)
    
    # Query metadata
    queried_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    cache_status: Mapped[str] = mapped_column(String(32), default=CacheStatusEnum.LIVE.value)
    
    # Result
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    confidence: Mapped[float] = mapped_column(default=0.0)
    categories: Mapped[list | None] = mapped_column(JSON, nullable=True)
    detections: Mapped[int] = mapped_column(default=0)
    total_engines: Mapped[int] = mapped_column(default=0)
    
    # Provider-specific
    provider_reference: Mapped[str | None] = mapped_column(String(256), nullable=True)
    provider_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    
    # Timestamps from provider
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Cache TTL
    ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Error info
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    
    # Latency
    latency_ms: Mapped[float | None] = mapped_column(nullable=True)
    
    # Raw response (optional, for debugging)
    raw_response: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    
    # Provenance
    provenance: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    
    # Relationships
    ioc: Mapped[IOC] = relationship(back_populates="queries")
    findings: Mapped[list["ThreatIntelFinding"]] = relationship(
        back_populates="query", cascade="all, delete-orphan"
    )
    
    __table_args__ = (
        Index("ix_query_provider_time", "provider", "queried_at"),
        Index("ix_query_verdict", "verdict"),
    )


class ThreatIntelFinding(Base):
    """Aggregated finding from multiple providers for an IOC."""
    
    __tablename__ = "threat_intel_findings"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Link to query
    query_id: Mapped[int] = mapped_column(
        ForeignKey("threat_intel_queries.id", ondelete="CASCADE"), index=True
    )
    
    # IOC info (denormalized for easy querying)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    ioc_value: Mapped[str] = mapped_column(String(512), index=True)
    
    # Aggregated verdict
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    confidence: Mapped[float] = mapped_column(default=0.0)
    
    # Provider details
    providers: Mapped[list] = mapped_column(JSON, default=list)
    malicious_providers: Mapped[list] = mapped_column(JSON, default=list)
    suspicious_providers: Mapped[list] = mapped_column(JSON, default=list)
    benign_providers: Mapped[list] = mapped_column(JSON, default=list)
    
    # Agreement/disagreement
    has_agreement: Mapped[bool] = mapped_column(default=False)
    has_disagreement: Mapped[bool] = mapped_column(default=False)
    agreement_details: Mapped[str | None] = mapped_column(Text, nullable=True)
    disagreement_details: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Assessment metadata
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    evidence_quality: Mapped[str] = mapped_column(String(32), default="MEDIUM")
    
    # Relationships
    query: Mapped[ThreatIntelQuery] = relationship(back_populates="findings")


class ProviderHealth(Base):
    """Health tracking for threat intelligence providers."""
    
    __tablename__ = "threat_intel_provider_health"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    provider: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    
    # Availability
    available: Mapped[bool] = mapped_column(default=True)
    
    # Timestamps
    last_successful_query: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    
    # Counters
    consecutive_failures: Mapped[int] = mapped_column(default=0)
    total_queries: Mapped[int] = mapped_column(default=0)
    successful_queries: Mapped[int] = mapped_column(default=0)
    failed_queries: Mapped[int] = mapped_column(default=0)
    rate_limited_count: Mapped[int] = mapped_column(default=0)
    
    # Latency
    average_latency_ms: Mapped[float] = mapped_column(default=0.0)
    
    # Circuit breaker
    circuit_open: Mapped[bool] = mapped_column(default=False)
    circuit_open_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    
    # Cache
    cache_hit_rate: Mapped[float] = mapped_column(default=0.0)
    
    # Updated
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    
    @property
    def success_rate(self) -> float:
        if self.total_queries == 0:
            return 1.0
        return self.successful_queries / self.total_queries


class ThreatIntelCache(Base):
    """Persistent cache for threat intelligence responses."""
    
    __tablename__ = "threat_intel_cache"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Cache key
    provider: Mapped[str] = mapped_column(String(64), index=True)
    cache_key: Mapped[str] = mapped_column(String(512), index=True)
    
    # IOC info
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    ioc_value: Mapped[str] = mapped_column(String(512), index=True)
    
    # Cached finding
    verdict: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(default=0.0)
    categories: Mapped[list | None] = mapped_column(JSON, nullable=True)
    detections: Mapped[int] = mapped_column(default=0)
    total_engines: Mapped[int] = mapped_column(default=0)
    provider_reference: Mapped[str | None] = mapped_column(String(256), nullable=True)
    raw_available: Mapped[bool] = mapped_column(default=False)
    
    # Cache metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    hit_count: Mapped[int] = mapped_column(default=0)
    last_accessed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    
    # Cache status
    cache_status: Mapped[str] = mapped_column(
        String(32), default=CacheStatusEnum.CACHED.value
    )
    
    __table_args__ = (
        UniqueConstraint("provider", "cache_key", name="uq_cache_provider_key"),
        Index("ix_cache_expires", "expires_at"),
    )