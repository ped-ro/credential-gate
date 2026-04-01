"""Emergency kill switch (panic mode) for Credential Gate.

When something goes wrong — compromised agent, suspicious activity, breach
detected — the gate can be instantly locked.  All active leases are revoked,
new credential requests are blocked, and the gate stays locked until Pete
explicitly unlocks it with YubiKey.

Lock state is persisted to data/lock.json so a service restart during an
incident does not accidentally unlock the gate.

Phase 10 implementation.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PanicManager:
    """Circuit breaker for the entire Credential Gate.

    One boolean check (``check_gate``) is inserted at the top of every
    credential-issuing path.  When locked, it raises HTTP 503 immediately
    — no policy evaluation, no Bitwarden call, nothing.
    """

    def __init__(self, lease_manager, bitwarden, notifier_config, audit, data_dir: str):
        self._lease_mgr = lease_manager
        self._bw = bitwarden
        self._notifier_config = notifier_config
        self._audit = audit
        self._credential_cache = None
        self._lock_file = Path(data_dir) / "lock.json"

        # In-memory state
        self._locked = False
        self._lock_reason: str | None = None
        self._lock_time: float | None = None

        # Cooldown tracking (prevent rapid lock/unlock cycling)
        self._last_unlock_time: float | None = None
        self._cooldown_seconds: int = 60

        # Restore persisted lock state
        self._load_lock_state()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_locked(self) -> bool:
        return self._locked

    @property
    def lock_info(self) -> dict | None:
        if not self._locked:
            return None
        return {
            "locked": True,
            "reason": self._lock_reason,
            "locked_at": _now_iso_from_ts(self._lock_time) if self._lock_time else None,
            "locked_for_seconds": int(time.time() - self._lock_time) if self._lock_time else 0,
            "message": (
                "Credential Gate is in panic lockdown. "
                "No credentials will be issued. YubiKey required to unlock."
            ),
        }

    # ------------------------------------------------------------------
    # Gate check — the circuit breaker
    # ------------------------------------------------------------------

    def check_gate(self) -> None:
        """Called at the top of every credential/proxy request.

        If locked, raises HTTP 503 with lock details.  This is the single
        point of enforcement — one boolean check that stops everything.
        """
        if not self._locked:
            return

        info = self.lock_info
        raise HTTPException(
            status_code=503,
            detail={
                "error": "gate_locked",
                "message": info["message"],
                "locked_at": info["locked_at"],
                "reason": info["reason"],
            },
        )

    # ------------------------------------------------------------------
    # Panic — lock the gate
    # ------------------------------------------------------------------

    async def panic(
        self,
        reason: str,
        rotate_credentials: bool = False,
        agent_filter: str | None = None,
    ) -> dict:
        """Execute emergency lockdown.

        Steps (in order):
        1. Set locked = True (immediately blocks all new credential requests)
        2. Revoke ALL active leases (or filtered by agent)
        3. If rotate_credentials: trigger rotation for affected credentials
        4. Send URGENT Ntfy notification
        5. Log panic event to audit with full context
        6. Persist lock state to disk
        7. Return summary of actions taken
        """
        now = time.time()

        # 1. Lock immediately
        self._locked = True
        self._lock_reason = reason
        self._lock_time = now
        logger.critical("PANIC LOCKDOWN: %s", reason)

        # 2. Revoke active leases
        leases_revoked = 0
        if self._lease_mgr:
            leases_revoked = self._lease_mgr.revoke_all(agent_id=agent_filter)
            logger.warning("Panic: revoked %d active lease(s)", leases_revoked)

        # 2b. Evict all cached credentials (Phase 11)
        cache_evicted = 0
        if self._credential_cache:
            cache_evicted = self._credential_cache.evict_all()
            if cache_evicted:
                logger.warning("Panic: evicted %d cached credential(s)", cache_evicted)

        # 3. Optional credential rotation
        credentials_rotated = 0
        if rotate_credentials and self._bw:
            try:
                from bitwarden import SessionState
                if self._bw.state == SessionState.ACTIVE:
                    # Get all credentials that had active leases
                    # For now, log the intent — rotation is done via the
                    # existing rotation module and requires per-credential
                    # type knowledge.
                    logger.warning(
                        "Panic: credential rotation requested — "
                        "use POST /rotate/{name} for individual credentials"
                    )
            except Exception as e:
                logger.error("Panic: rotation check failed: %s", e)

        # 4. Send urgent notification
        notification_sent = False
        from notifications import send_panic_notification
        notification_sent = send_panic_notification(
            reason=reason,
            leases_revoked=leases_revoked,
            config=self._notifier_config,
        )

        # 5. Audit
        if self._audit:
            self._audit.log(
                agent_id=agent_filter or "admin",
                credential_name="*",
                status="panic_locked",
                purpose=f"PANIC: {reason} (leases_revoked={leases_revoked})",
            )

        # 6. Persist to disk
        self._save_lock_state()

        locked_at_iso = _now_iso_from_ts(now)
        logger.critical(
            "Panic lockdown active. Leases revoked: %d. Unlock with YubiKey.",
            leases_revoked,
        )

        return {
            "status": "locked",
            "leases_revoked": leases_revoked,
            "cache_evicted": cache_evicted,
            "credentials_rotated": credentials_rotated,
            "notification_sent": notification_sent,
            "locked_at": locked_at_iso,
        }

    # ------------------------------------------------------------------
    # Unlock — restore normal operations
    # ------------------------------------------------------------------

    async def unlock(self, reason: str) -> dict:
        """Unlock the gate after panic.

        Can only be called via YubiKey-authenticated endpoint.

        Steps:
        1. Set locked = False
        2. Record unlock time for cooldown
        3. Send Ntfy notification (gate unlocked)
        4. Log unlock event to audit
        5. Persist unlocked state to disk
        6. Return summary
        """
        was_locked_for = 0
        if self._lock_time:
            was_locked_for = int(time.time() - self._lock_time)

        old_reason = self._lock_reason

        # 1. Unlock
        self._locked = False
        self._lock_reason = None
        self._lock_time = None

        # 2. Cooldown tracking
        self._last_unlock_time = time.time()

        logger.info(
            "Gate UNLOCKED: %s (was locked for %ds, previous reason: %s)",
            reason, was_locked_for, old_reason,
        )

        # 3. Notification
        notification_sent = False
        from notifications import send_unlock_notification
        notification_sent = send_unlock_notification(
            reason=reason,
            locked_duration_seconds=was_locked_for,
            config=self._notifier_config,
        )

        # 4. Audit
        if self._audit:
            self._audit.log(
                agent_id="admin",
                credential_name="*",
                status="panic_unlocked",
                purpose=f"UNLOCK: {reason} (was locked {was_locked_for}s)",
            )

        # 5. Persist
        self._save_lock_state()

        return {
            "status": "unlocked",
            "was_locked_for_seconds": was_locked_for,
            "notification_sent": notification_sent,
        }

    # ------------------------------------------------------------------
    # Cooldown check
    # ------------------------------------------------------------------

    def is_in_cooldown(self) -> bool:
        """Check if we're in the post-unlock cooldown period."""
        if self._last_unlock_time is None:
            return False
        elapsed = time.time() - self._last_unlock_time
        return elapsed < self._cooldown_seconds

    def set_cooldown(self, seconds: int) -> None:
        """Set the cooldown period from config."""
        self._cooldown_seconds = seconds

    def set_credential_cache(self, cache) -> None:
        """Set the credential cache (Phase 11).

        Called after the cache is initialized in the lifespan, since cache
        init may fail and happens after PanicManager creation.
        """
        self._credential_cache = cache

    # ------------------------------------------------------------------
    # Lock status (for GET /lock-status)
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return current lock state for the status endpoint."""
        if not self._locked:
            return {"locked": False}
        return {
            "locked": True,
            "reason": self._lock_reason,
            "locked_at": _now_iso_from_ts(self._lock_time) if self._lock_time else None,
            "locked_for_seconds": int(time.time() - self._lock_time) if self._lock_time else 0,
        }

    # ------------------------------------------------------------------
    # Auto-panic (called from anomaly detection)
    # ------------------------------------------------------------------

    async def auto_panic(self, reason: str) -> dict | None:
        """Trigger automatic panic lockdown from anomaly detection.

        Only fires if the gate is not already locked.
        Returns the panic result or None if already locked.
        """
        if self._locked:
            return None
        logger.critical("AUTO-PANIC triggered: %s", reason)
        return await self.panic(reason=f"AUTO-PANIC: {reason}")

    # ------------------------------------------------------------------
    # Persistence — survive service restarts
    # ------------------------------------------------------------------

    def _save_lock_state(self) -> None:
        """Write lock state to data/lock.json."""
        try:
            self._lock_file.parent.mkdir(parents=True, exist_ok=True)
            state = {
                "locked": self._locked,
                "reason": self._lock_reason,
                "locked_at": self._lock_time,
            }
            with open(self._lock_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error("Failed to persist lock state: %s", e)

    def _load_lock_state(self) -> None:
        """Restore lock state from data/lock.json on startup."""
        if not self._lock_file.exists():
            return

        try:
            with open(self._lock_file) as f:
                state = json.load(f)

            if state.get("locked", False):
                self._locked = True
                self._lock_reason = state.get("reason", "restored from disk")
                self._lock_time = state.get("locked_at", time.time())
                logger.critical(
                    "Lock state restored from disk — gate is LOCKED: %s",
                    self._lock_reason,
                )
        except Exception as e:
            logger.error("Failed to load lock state from %s: %s", self._lock_file, e)


def _now_iso_from_ts(ts: float | None) -> str | None:
    """Convert a Unix timestamp to ISO 8601 UTC string."""
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
