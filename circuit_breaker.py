"""Circuit breaker for Bitwarden connectivity.

Detects when Bitwarden is having issues and switches to degraded mode
rather than failing every request.  When the circuit is OPEN, credential
requests check the encrypted cache first instead of hitting Bitwarden.

State transitions:
    CLOSED -> OPEN:     After ``failure_threshold`` consecutive failures
    OPEN -> HALF_OPEN:  After ``recovery_timeout`` seconds
    HALF_OPEN -> CLOSED: If the test request succeeds
    HALF_OPEN -> OPEN:  If the test request fails (reset recovery timer)

Phase 11 implementation.
"""

import logging
import threading
import time
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"        # Normal — all requests go to Bitwarden
    OPEN = "open"            # Bitwarden is down — serve from cache if available
    HALF_OPEN = "half_open"  # Testing — let one request through to check if BW is back


class BitwardenCircuitBreaker:
    """Circuit breaker pattern for Bitwarden connectivity.

    When OPEN:
    - Credential requests check the encrypted cache first
    - If cache hit + YubiKey approval -> serve from cache (logged as "offline_cached")
    - If cache miss -> return 503 with explanation
    - Proxy requests that need live credentials -> 503
    - Health endpoint reports degraded mode
    - Ntfy notification sent on state transitions
    """

    def __init__(self, config: dict, notifier=None):
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float | None = None
        self._last_state_change: float | None = None
        self._lock = threading.Lock()
        self._config = config
        self._notifier = notifier

    @property
    def state(self) -> CircuitState:
        """Current circuit state. Automatically transitions OPEN -> HALF_OPEN
        if recovery_timeout has elapsed."""
        with self._lock:
            if (
                self._state == CircuitState.OPEN
                and self._last_state_change
            ):
                cb_cfg = self._config.get("offline", {}).get("circuit_breaker", {})
                timeout = cb_cfg.get("recovery_timeout_seconds", 60)
                if time.time() - self._last_state_change > timeout:
                    logger.info("Circuit breaker: OPEN -> HALF_OPEN (recovery timeout elapsed)")
                    self._state = CircuitState.HALF_OPEN
            return self._state

    def record_success(self) -> None:
        """Record a successful Bitwarden operation. Resets failure count.
        If in HALF_OPEN, transitions to CLOSED."""
        with self._lock:
            old_state = self._state
            self._failure_count = 0

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._last_state_change = time.time()
                logger.info("Circuit breaker: HALF_OPEN -> CLOSED (Bitwarden recovered)")
                self._send_state_notification("closed")

            elif self._state == CircuitState.OPEN:
                # Shouldn't normally happen, but handle gracefully
                self._state = CircuitState.CLOSED
                self._last_state_change = time.time()
                logger.info("Circuit breaker: OPEN -> CLOSED (success recorded)")
                self._send_state_notification("closed")

    def record_failure(self, error: str) -> None:
        """Record a Bitwarden failure. Increments count.
        If threshold reached, transitions to OPEN + sends notification."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            cb_cfg = self._config.get("offline", {}).get("circuit_breaker", {})
            threshold = cb_cfg.get("failure_threshold", 3)

            if self._state == CircuitState.CLOSED and self._failure_count >= threshold:
                self._state = CircuitState.OPEN
                self._last_state_change = time.time()
                logger.warning(
                    "Circuit breaker: CLOSED -> OPEN after %d failures (last: %s)",
                    self._failure_count, error,
                )
                self._send_state_notification("open")

            elif self._state == CircuitState.HALF_OPEN:
                # Test request failed — back to OPEN
                self._state = CircuitState.OPEN
                self._last_state_change = time.time()
                logger.warning(
                    "Circuit breaker: HALF_OPEN -> OPEN (test request failed: %s)", error,
                )
                self._send_state_notification("open")

    def should_attempt_bitwarden(self) -> bool:
        """Whether to try Bitwarden or go straight to cache.

        CLOSED -> True (always try)
        OPEN -> False (skip BW, use cache)
        HALF_OPEN -> True (test request)
        """
        current = self.state  # triggers auto-transition check
        if current == CircuitState.CLOSED:
            return True
        if current == CircuitState.HALF_OPEN:
            return True
        # OPEN
        return False

    def get_status(self) -> dict:
        """Return circuit breaker status for health endpoint."""
        cb_cfg = self._config.get("offline", {}).get("circuit_breaker", {})
        return {
            "state": self.state.value,
            "failure_count": self._failure_count,
            "last_failure": self._last_failure_time,
            "last_state_change": self._last_state_change,
            "recovery_timeout_seconds": cb_cfg.get("recovery_timeout_seconds", 60),
            "failure_threshold": cb_cfg.get("failure_threshold", 3),
        }

    def check_open_too_long(self) -> bool:
        """Check if the circuit has been OPEN longer than max_open_duration.

        Called from the daemon loop to send reminder notifications.
        Returns True if a reminder should be sent.
        """
        with self._lock:
            if self._state != CircuitState.OPEN or not self._last_state_change:
                return False

            cb_cfg = self._config.get("offline", {}).get("circuit_breaker", {})
            max_duration = cb_cfg.get("max_open_duration_seconds", 300)
            return time.time() - self._last_state_change > max_duration

    def _send_state_notification(self, new_state: str) -> None:
        """Fire notification for state change (best-effort, non-blocking)."""
        if not self._notifier:
            return
        try:
            from notifications import send_circuit_breaker_notification
            send_circuit_breaker_notification(
                new_state=new_state,
                failure_count=self._failure_count,
                config=self._notifier,
            )
        except Exception as e:
            logger.warning("Failed to send circuit breaker notification: %s", e)
