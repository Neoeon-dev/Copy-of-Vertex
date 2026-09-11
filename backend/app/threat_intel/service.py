"""
VERTEX Phase D6 — Threat Intelligence Service.

Main entry point for threat intelligence enrichment.
Coordinates IOC extraction, provider queries, caching, and aggregation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.threat_intel.ioc import (
    IOC,
    extract_iocs_from_email,
    normalize_iocs,
)
from app.threat_intel.providers import (
    ProviderConfig,
    ThreatIntelProvider,
    OpenPhishProvider,
    VirusTotalProvider,
    AbuseIPDBProvider,
)
from app.threat_intel.aggregator import IntelligenceAggregator, AggregationConfig
from app.threat_intel.cache import ThreatIntelCache
from app.threat_intel.circuit_breaker import get_circuit_breaker_registry
from app.threat_intel.rate_limiter import get_rate_limiter_registry
from app.threat_intel.schemas import (
    IntelligenceAssessment,
    QueryBudget,
)

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelServiceConfig:
    """Configuration for the threat intelligence service."""
    # Provider configurations
    openphish_enabled: bool = True
    virustotal_enabled: bool = True
    abuseipdb_enabled: bool = True
    
    # API keys (loaded from environment)
    openphish_api_key: str | None = None
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    
    # Query budgets
    max_ip_queries: int = 10
    max_domain_queries: int = 20
    max_url_queries: int = 30
    max_hash_queries: int = 10
    max_total_queries: int = 50
    
    # Cache settings
    cache_enabled: bool = True
    cache_ttl_seconds: int = 3600
    cache_max_entries: int = 10000
    
    # Circuit breaker
    cb_failure_threshold: int = 5
    cb_timeout: float = 60.0
    
    # Rate limiting
    openphish_rpm: int = 30
    virustotal_rpm: int = 4
    abuseipdb_rpm: int = 30
    
    # Timeouts
    timeout_connect: float = 5.0
    timeout_read: float = 15.0
    timeout_total: float = 30.0
    
    # Aggregation
    min_providers_for_agreement: int = 2
    
    # Privacy
    skip_private_ips: bool = True


class ThreatIntelService:
    """
    Main threat intelligence service.
    
    Orchestrates the full pipeline:
    1. Extract IOCs from email
    2. Normalize and deduplicate IOCs
    3. Apply query budgets
    4. Query providers (with cache, circuit breaker, rate limiting)
    5. Aggregate findings
    6. Return IntelligenceAssessment
    """
    
    def __init__(self, config: ThreatIntelServiceConfig):
        self.config = config
        self._initialized = False
        
        # Initialize providers
        self._providers: dict[str, ThreatIntelProvider] = {}
        
        # Initialize cache
        self._cache = ThreatIntelCache(
            default_ttl=config.cache_ttl_seconds,
            max_entries=config.cache_max_entries,
        ) if config.cache_enabled else None
        
        # Initialize circuit breaker registry
        self._cb_registry = get_circuit_breaker_registry()
        
        # Initialize rate limiter registry
        self._rl_registry = get_rate_limiter_registry()
        
        # Initialize aggregator
        self._aggregator = IntelligenceAggregator(AggregationConfig(
            min_providers_for_agreement=config.min_providers_for_agreement,
        ))
    
    async def initialize(self) -> None:
        """Initialize providers and connections."""
        if self._initialized:
            return
        
        # OpenPhish (no API key required for community feed)
        if self.config.openphish_enabled:
            self._providers["openphish"] = OpenPhishProvider(
                ProviderConfig(
                    name="openphish",
                    api_key=self.config.openphish_api_key,
                    timeout_connect=self.config.timeout_connect,
                    timeout_read=self.config.timeout_read,
                    timeout_total=self.config.timeout_total,
                    rate_limit_per_minute=self.config.openphish_rpm,
                    cache_ttl_seconds=self.config.cache_ttl_seconds,
                ),
                cache=self._cache,
                circuit_breaker=self._cb_registry,
                rate_limiter=self._rl_registry,
            )
        
        # VirusTotal (requires API key)
        if self.config.virustotal_enabled and self.config.virustotal_api_key:
            self._providers["virustotal"] = VirusTotalProvider(
                ProviderConfig(
                    name="virustotal",
                    api_key=self.config.virustotal_api_key,
                    timeout_connect=self.config.timeout_connect,
                    timeout_read=self.config.timeout_read,
                    timeout_total=self.config.timeout_total,
                    rate_limit_per_minute=self.config.virustotal_rpm,
                    cache_ttl_seconds=self.config.cache_ttl_seconds,
                ),
                cache=self._cache,
                circuit_breaker=self._cb_registry,
                rate_limiter=self._rl_registry,
            )
        elif self.config.virustotal_enabled:
            logger.warning("VirusTotal enabled but no API key configured")
        
        # AbuseIPDB (requires API key)
        if self.config.abuseipdb_enabled and self.config.abuseipdb_api_key:
            self._providers["abuseipdb"] = AbuseIPDBProvider(
                ProviderConfig(
                    name="abuseipdb",
                    api_key=self.config.abuseipdb_api_key,
                    timeout_connect=self.config.timeout_connect,
                    timeout_read=self.config.timeout_read,
                    timeout_total=self.config.timeout_total,
                    rate_limit_per_minute=self.config.abuseipdb_rpm,
                    cache_ttl_seconds=self.config.cache_ttl_seconds,
                ),
                cache=self._cache,
                circuit_breaker=self._cb_registry,
                rate_limiter=self._rl_registry,
            )
        elif self.config.abuseipdb_enabled:
            logger.warning("AbuseIPDB enabled but no API key configured")
        
        self._initialized = True
        logger.info("ThreatIntelService initialized with providers: %s", list(self._providers.keys()))
    
    async def close(self) -> None:
        """Close all provider connections."""
        for provider in self._providers.values():
            await provider.close()
        self._initialized = False
    
    def get_query_budget(self) -> QueryBudget:
        """Get query budget for this analysis."""
        return QueryBudget(
            max_ip_queries=self.config.max_ip_queries,
            max_domain_queries=self.config.max_domain_queries,
            max_url_queries=self.config.max_url_queries,
            max_hash_queries=self.config.max_hash_queries,
            max_total_queries=self.config.max_total_queries,
        )
    
    async def analyze_email(
        self,
        headers: dict[str, Any],
        body_text: str | None = None,
        body_html: str | None = None,
        attachments: list[dict[str, Any]] | None = None,
    ) -> IntelligenceAssessment:
        """
        Analyze an email for threat intelligence.
        
        This is the main entry point for email enrichment.
        """
        if not self._initialized:
            await self.initialize()
        
        # Step 1: Extract IOCs from email
        logger.debug("Extracting IOCs from email")
        raw_iocs = extract_iocs_from_email(
            headers=headers,
            body_text=body_text,
            body_html=body_html,
            attachments=attachments,
        )
        
        logger.info("Extracted %d raw IOCs", len(raw_iocs))
        
        # Step 2: Filter by query budget and privacy
        budget = self.get_query_budget()
        filtered_iocs = self._filter_iocs_by_budget(raw_iocs, budget)
        
        logger.info("Filtered to %d IOCs within budget", len(filtered_iocs))
        
        # Step 3: Query providers
        all_findings = []
        queried_iocs = []
        
        for ioc in filtered_iocs:
            # Skip private IPs if configured
            if self.config.skip_private_ips and ioc.ioc_type.value in ("IPV4", "IPV6"):
                from app.threat_intel.ioc import is_private_or_reserved_ip
                if is_private_or_reserved_ip(ioc.normalized_value):
                    logger.debug("Skipping private IP: %s", ioc.normalized_value)
                    continue
            
            # Find providers that support this IOC type
            supporting_providers = [
                p for p in self._providers.values()
                if ioc.ioc_type in p.supported_ioc_types()
            ]
            
            if not supporting_providers:
                logger.debug("No provider supports IOC type: %s", ioc.ioc_type)
                continue
            
            # Query all supporting providers
            for provider in supporting_providers:
                if not budget.use(ioc.ioc_type.value):
                    logger.warning("Query budget exhausted for %s", ioc.ioc_type)
                    break
                
                try:
                    finding = await provider.lookup_ioc(ioc)
                    all_findings.append(finding)
                except Exception as e:
                    logger.error("Provider %s failed for %s: %s", 
                                provider.config.name.value, ioc.normalized_value, e)
            
            queried_iocs.append({
                "type": ioc.ioc_type.value,
                "value": ioc.normalized_value,
                "source": ioc.source_location,
                "context": ioc.extraction_context,
            })
        
        # Step 4: Aggregate findings
        logger.info("Aggregating %d findings from %d providers", 
                   len(all_findings), len(self._providers))
        
        assessment = self._aggregator.aggregate(
            findings=all_findings,
            queried_iocs=queried_iocs,
        )
        
        return assessment
    
    def _filter_iocs_by_budget(
        self,
        iocs: list[IOC],
        budget: QueryBudget,
    ) -> list[IOC]:
        """Filter IOCs to stay within query budget."""
        # Group by type
        by_type: dict[str, list[IOC]] = {}
        for ioc in iocs:
            type_key = ioc.ioc_type.value
            if type_key not in by_type:
                by_type[type_key] = []
            by_type[type_key].append(ioc)
        
        # Take up to budget for each type
        filtered = []
        for type_key, type_iocs in by_type.items():
            max_allowed = getattr(budget, f"max_{type_key.lower()}_queries", 10)
            filtered.extend(type_iocs[:max_allowed])
        
        return filtered
    
    async def lookup_ioc(self, ioc: IOC) -> IntelligenceAssessment:
        """Look up a single IOC across all providers."""
        if not self._initialized:
            await self.initialize()
        
        all_findings = []
        queried_iocs = [{
            "type": ioc.ioc_type.value,
            "value": ioc.normalized_value,
            "source": ioc.source_location,
            "context": ioc.extraction_context,
        }]
        
        for provider in self._providers.values():
            if ioc.ioc_type in provider.supported_ioc_types():
                try:
                    finding = await provider.lookup_ioc(ioc)
                    all_findings.append(finding)
                except Exception as e:
                    logger.error("Provider %s failed: %s", provider.config.name.value, e)
        
        return self._aggregator.aggregate(all_findings, queried_iocs)
    
    def get_provider_health(self) -> dict[str, dict[str, Any]]:
        """Get health status for all providers."""
        health = {}
        for name, provider in self._providers.items():
            health[name] = provider.get_health()
        return health
    
    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        if self._cache:
            return self._cache.get_stats()
        return {"enabled": False}
    
    def get_circuit_breaker_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        return self._cb_registry.get_all_stats()
    
    def get_rate_limiter_stats(self) -> dict[str, Any]:
        """Get rate limiter statistics."""
        return self._rl_registry.get_all_stats()


# Global service instance
_threat_intel_service: ThreatIntelService | None = None


def get_threat_intel_service(config: ThreatIntelServiceConfig | None = None) -> ThreatIntelService:
    """Get or create the global threat intelligence service."""
    global _threat_intel_service
    if _threat_intel_service is None:
        if config is None:
            config = ThreatIntelServiceConfig()
        _threat_intel_service = ThreatIntelService(config)
    return _threat_intel_service