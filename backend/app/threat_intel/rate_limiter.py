"""
VERTEX Phase D6 — Rate Limiter for Provider API Calls.

Implements token bucket rate limiting with per-provider quotas.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limit configuration for a provider."""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_allowance: int = 5  # Extra tokens for burst


@dataclass
class RateLimitStats:
    """Statistics for rate limiter."""
    total_requests: int = 0
    allowed_requests: int = 0
    rejected_requests: int = 0
    current_tokens_minute: float = 0.0
    current_tokens_hour: float = 0.0
    current_tokens_day: float = 0.0


class TokenBucketRateLimiter:
    """
    Token bucket rate limiter with multiple time windows.
    
    Supports per-minute, per-hour, and per-day limits.
    Thread-safe implementation.
    """
    
    def __init__(
        self,
        name: str,
        config: RateLimitConfig | None = None,
    ):
        self.name = name
        self.config = config or RateLimitConfig()
        self._tokens_minute = float(self.config.requests_per_minute)
        self._tokens_hour = float(self.config.requests_per_hour)
        self._tokens_day = float(self.config.requests_per_day)
        self._last_refill_minute = time.time()
        self._last_refill_hour = time.time()
        self._last_refill_day = time.time()
        self._stats = RateLimitStats()
        self._lock = threading.RLock()
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        
        # Refill minute bucket
        elapsed_minute = now - self._last_refill_minute
        if elapsed_minute >= 60:
            self._tokens_minute = float(self.config.requests_per_minute)
            self._last_refill_minute = now
        else:
            # Add tokens proportionally
            tokens_to_add = elapsed_minute * (self.config.requests_per_minute / 60.0)
            self._tokens_minute = min(
                float(self.config.requests_per_minute) + self.config.burst_allowance,
                self._tokens_minute + tokens_to_add,
            )
        
        # Refill hour bucket
        elapsed_hour = now - self._last_refill_hour
        if elapsed_hour >= 3600:
            self._tokens_hour = float(self.config.requests_per_hour)
            self._last_refill_hour = now
        else:
            tokens_to_add = elapsed_hour * (self.config.requests_per_hour / 3600.0)
            self._tokens_hour = min(
                float(self.config.requests_per_hour),
                self._tokens_hour + tokens_to_add,
            )
        
        # Refill day bucket
        elapsed_day = now - self._last_refill_day
        if elapsed_day >= 86400:
            self._tokens_day = float(self.config.requests_per_day)
            self._last_refill_day = now
        else:
            tokens_to_add = elapsed_day * (self.config.requests_per_day / 86400.0)
            self._tokens_day = min(
                float(self.config.requests_per_day),
                self._tokens_day + tokens_to_add,
            )
    
    def acquire(self, tokens: int = 1, block: bool = True, timeout: float | None = None) -> bool:
        """
        Acquire tokens from the bucket.
        
        Args:
            tokens: Number of tokens to acquire
            block: If True, wait until tokens available
            timeout: Maximum time to wait (seconds), None = wait forever
            
        Returns:
            True if tokens acquired, False if rejected (non-blocking)
        """
        with self._lock:
            self._refill()
            
            # Check if we have enough tokens in all buckets
            if (self._tokens_minute >= tokens and 
                self._tokens_hour >= tokens and 
                self._tokens_day >= tokens):
                
                self._tokens_minute -= tokens
                self._tokens_hour -= tokens
                self._tokens_day -= tokens
                
                self._stats.total_requests += 1
                self._stats.allowed_requests += 1
                self._stats.current_tokens_minute = self._tokens_minute
                self._stats.current_tokens_hour = self._tokens_hour
                self._stats.current_tokens_day = self._tokens_day
                
                return True
            
            self._stats.total_requests += 1
            self._stats.rejected_requests += 1
            
            if not block:
                return False
        
        # Block until tokens available
        if block:
            start_time = time.time()
            while True:
                with self._lock:
                    self._refill()
                    if (self._tokens_minute >= tokens and 
                        self._tokens_hour >= tokens and 
                        self._tokens_day >= tokens):
                        
                        self._tokens_minute -= tokens
                        self._tokens_hour -= tokens
                        self._tokens_day -= tokens
                        
                        self._stats.total_requests += 1
                        self._stats.allowed_requests += 1
                        self._stats.current_tokens_minute = self._tokens_minute
                        self._stats.current_tokens_hour = self._tokens_hour
                        self._stats.current_tokens_day = self._tokens_day
                        
                        return True
                
                # Check timeout
                if timeout is not None and (time.time() - start_time) >= timeout:
                    return False
                
                # Wait a bit before retrying
                time.sleep(0.1)
        
        return False
    
    async def async_acquire(self, tokens: int = 1, timeout: float | None = None) -> bool:
        """Async version of acquire."""
        # For async, we use a loop with sleep
        start_time = time.time()
        
        while True:
            acquired = self.acquire(tokens, block=False)
            if acquired:
                return True
            
            if timeout is not None and (time.time() - start_time) >= timeout:
                return False
            
            await asyncio.sleep(0.1)
    
    def get_stats(self) -> dict[str, Any]:
        """Get rate limiter statistics."""
        with self._lock:
            self._refill()
            return {
                "name": self.name,
                "requests_per_minute": self.config.requests_per_minute,
                "requests_per_hour": self.config.requests_per_hour,
                "requests_per_day": self.config.requests_per_day,
                "burst_allowance": self.config.burst_allowance,
                "current_tokens_minute": round(self._tokens_minute, 1),
                "current_tokens_hour": round(self._tokens_hour, 1),
                "current_tokens_day": round(self._tokens_day, 1),
                "total_requests": self._stats.total_requests,
                "allowed_requests": self._stats.allowed_requests,
                "rejected_requests": self._stats.rejected_requests,
                "utilization_minute_pct": round(
                    (1 - self._tokens_minute / (self.config.requests_per_minute + self.config.burst_allowance)) * 100, 1
                ),
            }
    
    def reset(self) -> None:
        """Reset rate limiter to full tokens."""
        with self._lock:
            self._tokens_minute = float(self.config.requests_per_minute) + self.config.burst_allowance
            self._tokens_hour = float(self.config.requests_per_hour)
            self._tokens_day = float(self.config.requests_per_day)
            self._last_refill_minute = time.time()
            self._last_refill_hour = time.time()
            self._last_refill_day = time.time()
            self._stats = RateLimitStats()


class AsyncTokenBucketRateLimiter(TokenBucketRateLimiter):
    """
    Async-compatible token bucket rate limiter.
    
    Uses asyncio locks for async contexts.
    """
    
    def __init__(self, name: str, config: RateLimitConfig | None = None):
        super().__init__(name, config)
        self._async_lock = asyncio.Lock()
    
    async def async_acquire(self, tokens: int = 1, timeout: float | None = None) -> bool:
        """Async acquire with proper async locking."""
        async with self._async_lock:
            self._refill()
            
            if (self._tokens_minute >= tokens and 
                self._tokens_hour >= tokens and 
                self._tokens_day >= tokens):
                
                self._tokens_minute -= tokens
                self._tokens_hour -= tokens
                self._tokens_day -= tokens
                
                self._stats.total_requests += 1
                self._stats.allowed_requests += 1
                self._stats.current_tokens_minute = self._tokens_minute
                self._stats.current_tokens_hour = self._tokens_hour
                self._stats.current_tokens_day = self._tokens_day
                
                return True
            
            self._stats.total_requests += 1
            self._stats.rejected_requests += 1
            
            if timeout is not None:
                # Wait with timeout
                start_time = time.time()
                while True:
                    await asyncio.sleep(0.05)
                    self._refill()
                    
                    if (self._tokens_minute >= tokens and 
                        self._tokens_hour >= tokens and 
                        self._tokens_day >= tokens):
                        
                        self._tokens_minute -= tokens
                        self._tokens_hour -= tokens
                        self._tokens_day -= tokens
                        
                        self._stats.total_requests += 1
                        self._stats.allowed_requests += 1
                        self._stats.current_tokens_minute = self._tokens_minute
                        self._stats.current_tokens_hour = self._tokens_hour
                        self._stats.current_tokens_day = self._tokens_day
                        
                        return True
                    
                    if (time.time() - start_time) >= timeout:
                        return False
            else:
                # Wait indefinitely
                while True:
                    await asyncio.sleep(0.1)
                    self._refill()
                    
                    if (self._tokens_minute >= tokens and 
                        self._tokens_hour >= tokens and 
                        self._tokens_day >= tokens):
                        
                        self._tokens_minute -= tokens
                        self._tokens_hour -= tokens
                        self._tokens_day -= tokens
                        
                        self._stats.total_requests += 1
                        self._stats.allowed_requests += 1
                        self._stats.current_tokens_minute = self._tokens_minute
                        self._stats.current_tokens_hour = self._tokens_hour
                        self._stats.current_tokens_day = self._tokens_day
                        
                        return True
    
    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return super().get_stats()


class RateLimiterRegistry:
    """
    Registry of rate limiters for all providers.
    """
    
    def __init__(self):
        self._limiters: dict[str, TokenBucketRateLimiter] = {}
        self._async_limiters: dict[str, AsyncTokenBucketRateLimiter] = {}
        self._lock = threading.RLock()
    
    def get_limiter(
        self,
        name: str,
        config: RateLimitConfig | None = None,
        async_mode: bool = False,
    ) -> TokenBucketRateLimiter | AsyncTokenBucketRateLimiter:
        """Get or create rate limiter for a provider."""
        with self._lock:
            if async_mode:
                if name not in self._async_limiters:
                    self._async_limiters[name] = AsyncTokenBucketRateLimiter(name, config)
                return self._async_limiters[name]
            else:
                if name not in self._limiters:
                    self._limiters[name] = TokenBucketRateLimiter(name, config)
                return self._limiters[name]
    
    def acquire(self, provider_name: str, tokens: int = 1, block: bool = True, timeout: float | None = None) -> bool:
        """Acquire tokens for a provider (sync)."""
        limiter = self.get_limiter(provider_name)
        return limiter.acquire(tokens, block, timeout)
    
    async def async_acquire(self, provider_name: str, tokens: int = 1, timeout: float | None = None) -> bool:
        """Acquire tokens for a provider (async)."""
        limiter = self.get_limiter(provider_name, async_mode=True)
        return await limiter.async_acquire(tokens, timeout)
    
    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        """Get stats for all rate limiters."""
        with self._lock:
            stats = {}
            for name, limiter in self._limiters.items():
                stats[name] = limiter.get_stats()
            for name, limiter in self._async_limiters.items():
                if name not in stats:
                    stats[name] = limiter.get_stats()
            return stats
    
    def reset_all(self) -> None:
        """Reset all rate limiters."""
        with self._lock:
            for limiter in self._limiters.values():
                limiter.reset()
            for limiter in self._async_limiters.values():
                limiter.reset()
    
    def get_provider_remaining(self, provider_name: str) -> dict[str, float]:
        """Get remaining tokens for a provider."""
        with self._lock:
            limiter = self._limiters.get(provider_name) or self._async_limiters.get(provider_name)
            if limiter:
                with limiter._lock:
                    limiter._refill()
                    return {
                        "minute": limiter._tokens_minute,
                        "hour": limiter._tokens_hour,
                        "day": limiter._tokens_day,
                    }
            return {"minute": 0, "hour": 0, "day": 0}


# Global registry
_rate_limiter_registry: RateLimiterRegistry | None = None


def get_rate_limiter_registry() -> RateLimiterRegistry:
    """Get global rate limiter registry."""
    global _rate_limiter_registry
    if _rate_limiter_registry is None:
        _rate_limiter_registry = RateLimiterRegistry()
    return _rate_limiter_registry