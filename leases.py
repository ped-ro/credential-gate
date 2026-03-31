"""Credential lease tracking for Credential Gate.

Every approved credential access creates a lease with a TTL.  The service
tracks active leases and can revoke them.  Optionally, when a lease expires,
the credential can be auto-rotated in Bitwarden.

Phase 5 implementation.
"""

import json
import logging
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class LeaseState(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Lease:
    """A single credential lease."""

    __slots__ = (
        "lease_id",
        "agent_id",
        "credential_name",
        "fields",
        "purpose",
        "created_at",
        "expires_at",
        "state",
        "approval_method",
        "revoked_at",
        "revoke_reason",
    )

    def __init__(
        self,
        lease_id: str,
        agent_id: str,
        credential_name: str,
        fields: list[str],
        purpose: str,
        created_at: float,
        expires_at: float,
        state: LeaseState,
        approval_method: str,
        revoked_at: float | None = None,
        revoke_reason: str | None = None,
    ):
        self.lease_id = lease_id
        self.agent_id = agent_id
        self.credential_name = credential_name
        self.fields = fields
        self.purpose = purpose
        self.created_at = created_at
        self.expires_at = expires_at
        self.state = state
        self.approval_method = approval_method
        self.revoked_at = revoked_at
        self.revoke_reason = revoke_reason

    def to_dict(self) -> dict:
        return {
            "lease_id": self.lease_id,
            "agent_id": self.agent_id,
            "credential_name": self.credential_name,
            "fields": self.fields,
            "purpose": self.purpose,
            "created_at": _ts_to_iso(self.created_at),
            "expires_at": _ts_to_iso(self.expires_at),
            "ttl_seconds": max(0, int(self.expires_at - time.time())),
            "state": self.state.value,
            "approval_method": self.approval_method,
            "revoked_at": _ts_to_iso(self.revoked_at) if self.revoked_at else None,
            "revoke_reason": self.revoke_reason,
        }


def _ts_to_iso(ts: float) -> str:
    """Convert a Unix timestamp to ISO 8601 UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS leases (
    lease_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    credential_name TEXT NOT NULL,
    fields TEXT,
    purpose TEXT,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    approval_method TEXT,
    revoked_at REAL,
    revoke_reason TEXT
);
"""

_CREATE_INDEX_STATE = """\
CREATE INDEX IF NOT EXISTS idx_leases_state ON leases(state);
"""

_CREATE_INDEX_AGENT = """\
CREATE INDEX IF NOT EXISTS idx_leases_agent ON leases(agent_id, state);
"""


# ---------------------------------------------------------------------------
# LeaseManager
# ---------------------------------------------------------------------------

class LeaseManager:
    """SQLite-backed lease tracking."""

    def __init__(self, db_path: str):
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CREATE_TABLE)
        self._conn.execute(_CREATE_INDEX_STATE)
        self._conn.execute(_CREATE_INDEX_AGENT)
        self._conn.commit()

    # -- helpers --------------------------------------------------------

    def _row_to_lease(self, row: sqlite3.Row) -> Lease:
        fields_raw = row["fields"]
        fields = json.loads(fields_raw) if fields_raw else []
        return Lease(
            lease_id=row["lease_id"],
            agent_id=row["agent_id"],
            credential_name=row["credential_name"],
            fields=fields,
            purpose=row["purpose"] or "",
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            state=LeaseState(row["state"]),
            approval_method=row["approval_method"] or "",
            revoked_at=row["revoked_at"],
            revoke_reason=row["revoke_reason"],
        )

    # -- public API -----------------------------------------------------

    def create_lease(
        self,
        agent_id: str,
        credential_name: str,
        fields: list[str],
        purpose: str,
        ttl_seconds: int,
        approval_method: str,
    ) -> Lease:
        """Create a new active lease."""
        lease_id = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + ttl_seconds

        self._conn.execute(
            """\
            INSERT INTO leases
                (lease_id, agent_id, credential_name, fields, purpose,
                 created_at, expires_at, state, approval_method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                lease_id,
                agent_id,
                credential_name,
                json.dumps(fields),
                purpose,
                now,
                expires_at,
                LeaseState.ACTIVE.value,
                approval_method,
            ),
        )
        self._conn.commit()

        logger.info(
            "Lease created: %s for %s/%s (TTL %ds)",
            lease_id[:12], agent_id, credential_name, ttl_seconds,
        )

        return Lease(
            lease_id=lease_id,
            agent_id=agent_id,
            credential_name=credential_name,
            fields=fields,
            purpose=purpose,
            created_at=now,
            expires_at=expires_at,
            state=LeaseState.ACTIVE,
            approval_method=approval_method,
        )

    def get_lease(self, lease_id: str) -> Lease | None:
        """Get a single lease by ID."""
        row = self._conn.execute(
            "SELECT * FROM leases WHERE lease_id = ?", (lease_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_lease(row)

    def get_active_leases(
        self,
        agent_id: str | None = None,
        credential_name: str | None = None,
    ) -> list[Lease]:
        """List all active (non-expired, non-revoked) leases."""
        query = "SELECT * FROM leases WHERE state = ?"
        params: list = [LeaseState.ACTIVE.value]

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if credential_name:
            query += " AND credential_name = ?"
            params.append(credential_name)

        query += " ORDER BY created_at DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_lease(r) for r in rows]

    def revoke_lease(self, lease_id: str, reason: str = "manual") -> bool:
        """Immediately revoke a lease. Returns True if found and was active."""
        now = time.time()
        cur = self._conn.execute(
            """\
            UPDATE leases SET state = ?, revoked_at = ?, revoke_reason = ?
            WHERE lease_id = ? AND state = ?
            """,
            (LeaseState.REVOKED.value, now, reason, lease_id, LeaseState.ACTIVE.value),
        )
        self._conn.commit()
        if cur.rowcount > 0:
            logger.info("Lease revoked: %s (reason: %s)", lease_id[:12], reason)
            return True
        return False

    def revoke_all(self, agent_id: str | None = None) -> int:
        """Revoke all active leases. Optional filter by agent. Returns count."""
        now = time.time()
        if agent_id:
            cur = self._conn.execute(
                """\
                UPDATE leases SET state = ?, revoked_at = ?, revoke_reason = ?
                WHERE state = ? AND agent_id = ?
                """,
                (LeaseState.REVOKED.value, now, "revoke-all", LeaseState.ACTIVE.value, agent_id),
            )
        else:
            cur = self._conn.execute(
                """\
                UPDATE leases SET state = ?, revoked_at = ?, revoke_reason = ?
                WHERE state = ?
                """,
                (LeaseState.REVOKED.value, now, "revoke-all", LeaseState.ACTIVE.value),
            )
        self._conn.commit()
        count = cur.rowcount
        if count:
            logger.info("Revoked %d active lease(s) (agent_id=%s)", count, agent_id or "all")
        return count

    def renew_lease(self, lease_id: str, additional_seconds: int) -> Lease | None:
        """Extend an active lease's TTL. Returns updated lease or None."""
        lease = self.get_lease(lease_id)
        if not lease or lease.state != LeaseState.ACTIVE:
            return None

        new_expires = lease.expires_at + additional_seconds
        self._conn.execute(
            "UPDATE leases SET expires_at = ? WHERE lease_id = ? AND state = ?",
            (new_expires, lease_id, LeaseState.ACTIVE.value),
        )
        self._conn.commit()

        lease.expires_at = new_expires
        logger.info(
            "Lease renewed: %s (+%ds, new expiry %s)",
            lease_id[:12], additional_seconds, _ts_to_iso(new_expires),
        )
        return lease

    def check_expired(self) -> list[Lease]:
        """Find and mark expired leases. Returns the newly expired leases."""
        now = time.time()

        # Find leases that are active but past their expiry
        rows = self._conn.execute(
            "SELECT * FROM leases WHERE state = ? AND expires_at < ?",
            (LeaseState.ACTIVE.value, now),
        ).fetchall()

        if not rows:
            return []

        expired_leases = [self._row_to_lease(r) for r in rows]
        lease_ids = [l.lease_id for l in expired_leases]

        # Mark them as expired
        placeholders = ",".join("?" * len(lease_ids))
        self._conn.execute(
            f"UPDATE leases SET state = ? WHERE lease_id IN ({placeholders})",
            [LeaseState.EXPIRED.value, *lease_ids],
        )
        self._conn.commit()

        for l in expired_leases:
            l.state = LeaseState.EXPIRED
            logger.info(
                "Lease expired: %s (%s/%s)",
                l.lease_id[:12], l.agent_id, l.credential_name,
            )

        return expired_leases

    def count_active(self, agent_id: str) -> int:
        """Count active leases for an agent (for limit enforcement)."""
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM leases WHERE state = ? AND agent_id = ?",
            (LeaseState.ACTIVE.value, agent_id),
        ).fetchone()
        return row[0] if row else 0

    def count_active_for_credential(self, credential_name: str) -> int:
        """Count active leases for a specific credential (for per-credential limits)."""
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM leases WHERE state = ? AND credential_name = ?",
            (LeaseState.ACTIVE.value, credential_name),
        ).fetchone()
        return row[0] if row else 0

    def stats_today(self) -> dict:
        """Get lease statistics for today (UTC)."""
        today_start = time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime())
        # Convert to epoch for comparison with REAL columns
        import calendar
        today_epoch = calendar.timegm(time.strptime(today_start, "%Y-%m-%dT%H:%M:%SZ"))

        active = self._conn.execute(
            "SELECT COUNT(*) FROM leases WHERE state = ?",
            (LeaseState.ACTIVE.value,),
        ).fetchone()[0]

        expired_today = self._conn.execute(
            "SELECT COUNT(*) FROM leases WHERE state = ? AND expires_at >= ?",
            (LeaseState.EXPIRED.value, today_epoch),
        ).fetchone()[0]

        revoked_today = self._conn.execute(
            "SELECT COUNT(*) FROM leases WHERE state = ? AND revoked_at >= ?",
            (LeaseState.REVOKED.value, today_epoch),
        ).fetchone()[0]

        return {
            "active": active,
            "expired_today": expired_today,
            "revoked_today": revoked_today,
        }

    def close(self):
        self._conn.close()
