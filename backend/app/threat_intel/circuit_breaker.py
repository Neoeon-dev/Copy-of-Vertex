"""
VERTEX Phase D6 — Circuit Breaker for Provider Reliability.

Implements the circuit breaker pattern to prevent cascading failures
when a threat intelligence provider is consistently failing.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"       # Normal operation, requests go through
    OPEN = "open"           # Failing, requests blocked
    HALF_OPEN = "half_open" # Testing if provider recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5          # Failures before opening
    success_threshold: int = 2          # Successes in half-open before closing
    timeout: float = 60.0               # Seconds before half-open
    half_open_max_calls: int = 3        # Max calls in half-open state


@dataclass
class CircuitBreakerStats:
    """Statistics for a circuit breaker."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    state_changes: int = 0
    last_failure_time: float = 0
    last_success_time: float = 0
    last_state_change: float = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0


class CircuitBreaker:
    """
    Circuit breaker for a single provider.
    
    State machine:
    - CLOSED: Normal operation, track failures
    - OPEN: Too many failures, reject calls immediately
    - HALF_OPEN: Allow limited calls to test recovery
    
    Thread-safe implementation.
    """
    
    def __init__(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None,
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitBreakerStats()
        self._lock = threading.RLock()
        self._half_open_calls = 0
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            # Check if timeout expired for OPEN -> HALF_OPEN transition
            if self._state == CircuitState.OPEN:
                if time.time() - self._stats.last_failure_time >= self.config.timeout:
                    self._transition_to_half_open()
            return self._state
    
    def can_execute(self, provider_name: str = "") -> bool:
        """Check if a call should be allowed."""
        state = self.state
        
        if state == CircuitState.CLOSED:
            return True
        
        if state == CircuitState.OPEN:
            return False
        
        if state == CircuitState.HALF_OPEN:
            with self._lock:
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False
        
        return False
    
    def record_success(self, provider_name: str = "") -> None:
        """Record a successful call."""
        with self._lock:
            self._stats.total_calls += 1
            self._stats.successful_calls += 1
            self._stats.last_success_time = time.time()
            
            if self._state == CircuitState.HALF_OPEN:
                self._stats.consecutive_successes += 1
                self._stats.consecutive_failures = 0
                
                if self._stats.consecutive_successes >= self.config.success_threshold:
                    self._transition_to_closed()
            
            elif self._state == CircuitState.CLOSED:
                self._stats.consecutive_failures = 0
    
    def record_failure(self, provider_name: str = "") -> None:
        """Record a failed call."""
        with self._lock:
            self._stats.total_calls += 1
            self._stats.failed_calls += 1
            self._stats.last_failure_time = time.time()
            self._stats.consecutive_failures += 1
            self._stats.consecutive_successes = 0
            
            if self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open goes back to OPEN
                self._transition_to_open()
            
            elif self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self.config.failure_threshold:
                    self._transition_to_open()
    
    def _transition_to_open(self) -> None:
        """Transition to OPEN state."""
        if self._state != CircuitState.OPEN:
            self._state = CircuitState.OPEN
            self._stats.state_changes += 1
            self._stats.last_state_change = time.time()
            logger.warning("Circuit breaker OPEN for %s", self.name)
    
    def _transition_to_half_open(self) -> None:
        """Transition to HALF_OPEN state."""
        self._state = CircuitState.HALF_OPEN
        self._half_open_calls = 0
        self._stats.state_changes += 1
        self._stats.last_state_change = time.time()
        self._stats.consecutive_successes = 0
        logger.info("Circuit breaker HALF_OPEN for %s", self.name)
    
    def _transition_to_closed(self) -> None:
        """Transition to CLOSED state."""
        if self._state != CircuitState.CLOSED:
            self._state = CircuitState.CLOSED
            self._stats.state_changes += 1
            self._stats.last_state_change = time.time()
            self._stats.consecutive_failures = 0
            self._half_open_calls = 0
            logger.info("Circuit breaker CLOSED for %s", self.name)
    
    def reset(self) -> None:
        """Manually reset circuit breaker to CLOSED."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._stats = CircuitBreakerStats()
            self._half_open_calls = 0
    
    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "total_calls": self._stats.total_calls,
                "successful_calls": self._stats.successful_calls,
                "failed_calls": self._stats.failed_calls,
                "rejected_calls": self._stats.rejected_calls,
                "state_changes": self._stats.state_changes,
                "consecutive_failures": self._stats.consecutive_failures,
                "consecutive_successes": self._stats.consecutive_successes,
                "last_failure_time": self._stats.last_failure_time,
                "last_success_time": self._stats.last_success_time,
                "last_state_change": self._stats.last_state_change,
            }
    
    def force_open(self) -> None:
        """Manually force circuit to OPEN (for testing/maintenance)."""
        with self._lock:
            self._transition_to_open()
    
    def force_closed(self) -> None:
        """Manually force circuit to CLOSED (for testing/maintenance)."""
        with self._lock:
            self._transition_to_closed()


class CircuitBreakerRegistry:
    """
    Registry of circuit breakers for all providers.
    
    Manages lifecycle and provides aggregated health view.
    """
    
    def __init__(self, default_config: CircuitBreakerConfig | None = None):
        self.default_config = default_config or CircuitBreakerConfig()
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.RLock()
    
    def get_breaker(self, name: str, config: CircuitBreakerConfig | None = None) -> CircuitBreaker:
        """Get or create circuit breaker for a provider."""
        with self._lock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(
                    name=name,
                    config=config or self.default_config,
                )
            return self._breakers[name]
    
    def can_execute(self, provider_name: str) -> bool:
        """Check if provider can execute."""
        breaker = self._breakers.get(provider_name)
        if breaker is None:
            return True  # No breaker = allow
        return breaker.can_execute(provider_name)
    
    def record_success(self, provider_name: str) -> None:
        """Record success for provider."""
        breaker = self._breakers.get(provider_name)
        if breaker:
            breaker.record_success(provider_name)
    
    def record_failure(self, provider_name: str) -> None:
        """Record failure for provider."""
        breaker = self._breakers.get(provider_name)
        if breaker:
            breaker.record_failure(provider_name)
    
    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        """Get stats for all circuit breakers."""
        with self._lock:
            return {name: breaker.get_stats() for name, breaker in self._breakers.items()}
    
    def get_health_summary(self) -> dict[str, Any]:
        """Get overall health summary."""
        with self._lock:
            total_calls = sum(b._stats.total_calls for b in self._breakers.values())
            total_failures = sum(b._stats.failed_calls for b in self._breakers.values())
            open_count = sum(1 for b in self._breakers.values() if b.state == CircuitState.OPEN)
            half_open_count = sum(1 for b in self._breakers.values() if b.state == CircuitState.HALF_OPEN)
            
            return {
                "total_providers": len(self._breakers),
                "total_calls": total_calls,
                "total_failures": total_failures,
                "failure_rate": total_failures / total_calls if total_calls > 0 else 0.0,
                "circuits_open": open_count,
                "circuits_half_open": half_open_count,
                "circuits_closed": len(self._breakers) - open_count - half_open_count,
            }
    
    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        with self._lock:
            for breaker in self._breakers.values():
                breaker.reset()
    
    def reset_provider(self, provider_name: str) -> bool:
        """Reset circuit breaker for specific provider."""
        with self._lock:
            breaker = self._breakers.get(provider_name)
            if breaker:
                breaker.reset()
                return True
            return False


# Global registry instance
_circuit_breaker_registry: CircuitBreakerRegistry | None = None


def get_circuit_breaker_registry() -> CircuitBreakerRegistry:
    """Get global circuit breaker registry."""
    global _circuit_breaker_registry
    if _circuit_breaker_registry is None:
        _circuit_breaker_registry = CircuitBreakerRegistry()
    return _circuit_breaker_registry