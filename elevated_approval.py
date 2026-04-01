"""Elevated approval for phone-only (silver) tier.

When the security tier is 'silver' (no YubiKey), high-risk or sensitive
operations that would normally require YubiKey are instead protected by
an elevated phone approval: a six-digit confirmation code sent via Ntfy
that must be echoed back within a short window.

Flow:
  1. Gate generates a random 6-digit code.
  2. Code is sent as a push notification (no action buttons — user must
     type it manually, proving they read and understood the request).
  3. Caller (REST or MCP) submits the code to /confirm-elevated/{request_id}.
  4. If the code matches and hasn't expired, the operation proceeds.

Confirmation codes are single-use and expire after a configurable timeout
(default: 120 seconds).  The code is stored only in memory and is
cleared after use or expiry.

Phase 12 implementation.
"""

import logging
import secrets
import threading
import time

logger = logging.getLogger(__name__)


class ElevatedRequest:
    """A pending elevated-approval request."""

    __slots__ = (
        "request_id",
        "code",
        "agent_id",
        "credential_name",
        "purpose",
        "operation",
        "created_at",
        "expires_at",
        "confirmed",
        "event",
    )

    def __init__(
        self,
        request_id: str,
        code: str,
        agent_id: str,
        credential_name: str,
        purpose: str,
        operation: str,
        timeout_seconds: int,
    ):
        self.request_id = request_id
        self.code = code
        self.agent_id = agent_id
        self.credential_name = credential_name
        self.purpose = purpose
        self.operation = operation
        self.created_at = time.time()
        self.expires_at = self.created_at + timeout_seconds
        self.confirmed = False
        self.event = threading.Event()


class ElevatedApprovalManager:
    """Manages elevated phone-approval flows for silver-tier operations.

    Thread-safe.  Pending requests are stored in memory only — they do
    not survive a restart (by design: security codes should not persist).
    """

    def __init__(self, config: dict):
        self._config = config
        self._pending: dict[str, ElevatedRequest] = {}
        self._lock = threading.Lock()

        elevated_cfg = config.get("elevated_approval", {})
        self._timeout_seconds = elevated_cfg.get("timeout_seconds", 120)
        self._code_length = elevated_cfg.get("code_length", 6)

    def create_request(
        self,
        agent_id: str,
        credential_name: str,
        purpose: str,
        operation: str,
    ) -> ElevatedRequest:
        """Create a new elevated-approval request.

        Generates a cryptographically random numeric code and stores
        the pending request.  Returns the ElevatedRequest (caller should
        send the code via notification).
        """
        request_id = secrets.token_urlsafe(32)
        code = self._generate_code()

        req = ElevatedRequest(
            request_id=request_id,
            code=code,
            agent_id=agent_id,
            credential_name=credential_name,
            purpose=purpose,
            operation=operation,
            timeout_seconds=self._timeout_seconds,
        )

        with self._lock:
            self._pending[request_id] = req

        logger.info(
            "Elevated approval created: request_id=%s agent=%s op=%s (expires in %ds)",
            request_id[:12],
            agent_id,
            operation,
            self._timeout_seconds,
        )
        return req

    def confirm(self, request_id: str, code: str) -> dict:
        """Confirm an elevated-approval request with the given code.

        Returns a dict:
            {"confirmed": True} on success
            {"confirmed": False, "reason": "..."} on failure

        The request is consumed on successful confirmation (single-use).
        """
        with self._lock:
            req = self._pending.get(request_id)
            if not req:
                return {"confirmed": False, "reason": "unknown_request"}

            if time.time() > req.expires_at:
                del self._pending[request_id]
                return {"confirmed": False, "reason": "expired"}

            if not secrets.compare_digest(req.code, code.strip()):
                return {"confirmed": False, "reason": "wrong_code"}

            # Success — consume the request
            req.confirmed = True
            req.event.set()
            del self._pending[request_id]

        logger.info(
            "Elevated approval confirmed: request_id=%s agent=%s",
            request_id[:12],
            req.agent_id,
        )
        return {"confirmed": True}

    def wait_for_confirmation(
        self,
        request_id: str,
        timeout: float | None = None,
    ) -> bool:
        """Block until the elevated request is confirmed or times out.

        Returns True if confirmed, False on timeout.
        """
        with self._lock:
            req = self._pending.get(request_id)
        if not req:
            return False

        effective_timeout = timeout or self._timeout_seconds
        confirmed = req.event.wait(timeout=effective_timeout)

        # Clean up if timed out
        if not confirmed:
            with self._lock:
                self._pending.pop(request_id, None)

        return confirmed

    def get_pending(self, request_id: str) -> ElevatedRequest | None:
        """Get a pending request by ID (for status checks)."""
        with self._lock:
            return self._pending.get(request_id)

    def cleanup_expired(self) -> int:
        """Remove expired pending requests.  Returns count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            expired_ids = [
                rid for rid, req in self._pending.items()
                if now > req.expires_at
            ]
            for rid in expired_ids:
                del self._pending[rid]
                removed += 1
        if removed:
            logger.debug("Cleaned up %d expired elevated requests", removed)
        return removed

    def _generate_code(self) -> str:
        """Generate a random numeric code of configured length."""
        # Use secrets for uniform random digits
        upper = 10 ** self._code_length
        num = secrets.randbelow(upper)
        return str(num).zfill(self._code_length)
