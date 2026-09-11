"""
VERTEX Phase D6 — Cache Layer for Threat Intelligence.

Provider-aware cache with TTL, freshness tracking, and stale-if-error support.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.threat_intel.schemas import CacheStatus, ThreatIntelFinding

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Single cache entry with metadata."""
    provider: str
    cache_key: str
    finding: ThreatIntelFinding
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    hit_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    
    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at
    
    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at
    
    @property
    def ttl_remaining(self) -> float:
        return max(0.0, self.expires_at - time.time())


class ThreatIntelCache:
    """
    In-memory threat intelligence cache with TTL and stale-if-error support.
    
    Can be extended with Redis/PostgreSQL backend for persistence.
    """
    
    def __init__(self, default_ttl: int = 3600, max_entries: int = 10000):
        self.default_ttl = default_ttl
        self.max_entries = max_entries
        self._cache: dict[str, CacheEntry] = {}
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "stale_serves": 0,
            "errors": 0,
        }
    
    def _make_key(self, provider: str, cache_key: str) -> str:
        return f"{provider}:{cache_key}"
    
    async def get(self, provider: str, cache_key: str) -> Optional[ThreatIntelFinding]:
        """
        Get cached finding.
        
        Returns:
            Finding if cached and not expired, None otherwise.
            Stale entries are returned with CacheStatus.STALE.
        """
        key = self._make_key(provider, cache_key)
        entry = self._cache.get(key)
        
        if entry is None:
            self._stats["misses"] += 1
            return None
        
        now = time.time()
        
        if now > entry.expires_at:
            # Expired - check if we can serve stale
            if entry.finding.cache_status == CacheStatus.UNAVAILABLE:
                # Don't serve stale errors
                self._stats["misses"] += 1
                return None
            
            # Serve stale
            entry.finding.cache_status = CacheStatus.STALE
            entry.hit_count += 1
            entry.last_accessed = now
            self._stats["stale_serves"] += 1
            logger.debug("Serving stale cache for %s (age: %.0fs)", key, entry.age_seconds)
            return entry.finding
        
        # Fresh cache hit
        entry.finding.cache_status = CacheStatus.CACHED
        entry.hit_count += 1
        entry.last_accessed = now
        self._stats["hits"] += 1
        return entry.finding
    
    async def set(
        self,
        provider: str,
        cache_key: str,
        finding: ThreatIntelFinding,
        ttl: Optional[int] = None,
    ) -> None:
        """Store finding in cache."""
        # Evict if at capacity
        if len(self._cache) >= self.max_entries:
            await self._evict_lru()
        
        # Handle explicit TTL=0 vs None
        if ttl is None:
            ttl = self.default_ttl
        now = time.time()
        
        # Handle TTL <= 0 as immediately expired
        if ttl <= 0:
            expires_at = now - 1  # Already expired
        else:
            expires_at = now + ttl
        
        entry = CacheEntry(
            provider=provider,
            cache_key=cache_key,
            finding=finding,
            created_at=now,
            expires_at=expires_at,
        )
        
        self._cache[self._make_key(provider, cache_key)] = entry
    
    async def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self._cache:
            return
        
        # Find LRU entry
        lru_key = min(self._cache.keys(), key=lambda k: self._cache[k].last_accessed)
        del self._cache[lru_key]
        self._stats["evictions"] += 1
    
    async def invalidate(self, provider: str, cache_key: str) -> bool:
        """Manually invalidate a cache entry."""
        key = self._make_key(provider, cache_key)
        if key in self._cache:
            del self._cache[key]
            return True
        return False
    
    async def clear_provider(self, provider: str) -> int:
        """Clear all entries for a provider."""
        keys_to_delete = [k for k in self._cache.keys() if k.startswith(f"{provider}:")]
        for key in keys_to_delete:
            del self._cache[key]
        return len(keys_to_delete)
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self._stats["hits"] + self._stats["misses"]
        hit_rate = self._stats["hits"] / total if total > 0 else 0.0
        
        return {
            "entries": len(self._cache),
            "max_entries": self.max_entries,
            "hits": self._stats["hits"],
            "misses": self._stats["misses"],
            "stale_serves": self._stats["stale_serves"],
            "evictions": self._stats["evictions"],
            "hit_rate": round(hit_rate, 4),
            "errors": self._stats["errors"],
        }
    
    def get_entries_info(self) -> list[dict[str, Any]]:
        """Get info about all cache entries (for debugging)."""
        now = time.time()
        return [
            {
                "key": entry.cache_key,
                "provider": entry.provider,
                "age_seconds": round(entry.age_seconds, 1),
                "ttl_remaining": round(entry.ttl_remaining, 1),
                "hit_count": entry.hit_count,
                "is_expired": entry.is_expired,
                "cache_status": entry.finding.cache_status.value,
                "verdict": entry.finding.verdict.value,
            }
            for entry in self._cache.values()
        ]


# Redis backend (optional, for production)
class RedisThreatIntelCache(ThreatIntelCache):
    """
    Redis-backed cache for multi-instance deployments.
    
    Requires redis-py package.
    """
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        default_ttl: int = 3600,
        key_prefix: str = "vertex:threat_intel:",
    ):
        super().__init__(default_ttl)
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self._redis = None
    
    async def _get_redis(self):
        if self._redis is None:
            import redis.asyncio as redis
            self._redis = redis.from_url(self.redis_url, decode_responses=True)
        return self._redis
    
    async def get(self, provider: str, cache_key: str) -> Optional[ThreatIntelFinding]:
        redis = await self._get_redis()
        key = f"{self.key_prefix}{provider}:{cache_key}"
        
        try:
            data = await redis.get(key)
            if data:
                finding_data = json.loads(data)
                finding = ThreatIntelFinding(**finding_data)
                finding.cache_status = CacheStatus.CACHED
                self._stats["hits"] += 1
                return finding
        except Exception as e:
            logger.warning("Redis cache get failed: %s", e)
        
        self._stats["misses"] += 1
        return None
    
    async def set(
        self,
        provider: str,
        cache_key: str,
        finding: ThreatIntelFinding,
        ttl: Optional[int] = None,
    ) -> None:
        redis = await self._get_redis()
        key = f"{self.key_prefix}{provider}:{cache_key}"
        ttl = ttl or self.default_ttl
        
        try:
            finding.cache_status = CacheStatus.CACHED
            await redis.setex(key, ttl, json.dumps(finding.to_dict()))
        except Exception as e:
            logger.warning("Redis cache set failed: %s", e)
    
    async def invalidate(self, provider: str, cache_key: str) -> bool:
        redis = await self._get_redis()
        key = f"{self.key_prefix}{provider}:{cache_key}"
        result = await redis.delete(key)
        return result > 0
    
    async def clear_provider(self, provider: str) -> int:
        redis = await self._get_redis()
        pattern = f"{self.key_prefix}{provider}:*"
        keys = []
        async for key in redis.scan_iter(match=pattern):
            keys.append(key)
        if keys:
            return await redis.delete(*keys)
        return 0


# PostgreSQL backend (optional, for persistence across restarts)
class PostgresThreatIntelCache:
    """
    PostgreSQL-backed cache using the existing database.
    
    Uses a dedicated table for threat intelligence cache.
    """
    
    def __init__(self, session_factory, default_ttl: int = 3600):
        self.session_factory = session_factory
        self.default_ttl = default_ttl
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
        }
    
    async def get(self, provider: str, cache_key: str) -> Optional[ThreatIntelFinding]:
        # Would use async SQLAlchemy session
        # Placeholder for now - implement when needed
        self._stats["misses"] += 1
        return None
    
    async def set(
        self,
        provider: str,
        cache_key: str,
        finding: ThreatIntelFinding,
        ttl: Optional[int] = None,
    ) -> None:
        pass  # Implement when needed
    
    def get_stats(self) -> dict[str, Any]:
        return self._stats