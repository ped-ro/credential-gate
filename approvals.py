"""Pending request queue for phone-based approval flows.

When an agent requests a credential in 'phone' or 'both' mode, a
PendingRequest is created and held in the ApprovalQueue.  The agent's
HTTP request blocks on the request's threading.Event until the phone
callback fires (approve/deny) or the timeout expires.

Request IDs are cryptographically random (secrets.token_urlsafe(32))
and single-use — once resolved they cannot be replayed.
"""

import logging
import secrets
import threading
import time
from enum import Enum

logger = logging.getLogger(__name__)


class ApprovalState(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class PendingRequest:
    def __init__(self, request_id: str, agent_id: str, credential_name: str,
                 purpose: str, fields: list[str]):
        self.request_id = request_id
        self.agent_id = agent_id
        self.credential_name = credential_name
        self.purpose = purpose
        self.fields = fields
        self.state = ApprovalState.PENDING
        self.created_at = time.time()
        self.event = threading.Event()  # Blocks until approved/denied/timeout


class ApprovalQueue:
    def __init__(self):
        self._requests: dict[str, PendingRequest] = {}
        self._lock = threading.Lock()

    def create(self, agent_id: str, credential_name: str, purpose: str,
               fields: list[str]) -> PendingRequest:
        """Create a new pending request and return it."""
        request_id = secrets.token_urlsafe(32)
        req = PendingRequest(request_id, agent_id, credential_name, purpose, fields)
        with self._lock:
            self._cleanup_expired()
            self._requests[request_id] = req
        logger.info(
            "Created pending request %s for %s/%s",
            request_id[:12], agent_id, credential_name,
        )
        return req

    def approve(self, request_id: str) -> bool:
        """Approve a pending request. Returns True if it was found and pending."""
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                return False
            if req.state != ApprovalState.PENDING:
                return False
            req.state = ApprovalState.APPROVED
            req.event.set()
            logger.info("Request %s approved via phone", request_id[:12])
            return True

    def deny(self, request_id: str) -> bool:
        """Deny a pending request. Returns True if it was found and pending."""
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                return False
            if req.state != ApprovalState.PENDING:
                return False
            req.state = ApprovalState.DENIED
            req.event.set()
            logger.info("Request %s denied via phone", request_id[:12])
            return True

    def wait(self, request_id: str, timeout_seconds: int) -> ApprovalState:
        """Block until the request is approved, denied, or timeout expires."""
        req = self._requests.get(request_id)
        if not req:
            return ApprovalState.EXPIRED
        req.event.wait(timeout=timeout_seconds)
        if req.state == ApprovalState.PENDING:
            req.state = ApprovalState.EXPIRED
        return req.state

    def get(self, request_id: str) -> PendingRequest | None:
        """Look up a request by ID."""
        return self._requests.get(request_id)

    def _cleanup_expired(self) -> None:
        """Remove requests older than 5 minutes. Called under lock."""
        cutoff = time.time() - 300
        expired = [
            rid for rid, req in self._requests.items()
            if req.created_at < cutoff
        ]
        for rid in expired:
            del self._requests[rid]
        if expired:
            logger.debug("Cleaned up %d expired requests", len(expired))
