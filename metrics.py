"""Metrics collection for Credential Gate.

Queries existing audit.db and leases.db to compute aggregate statistics,
per-agent breakdowns, and anomaly detection.  Does NOT add any new database
files — all data comes from the existing Phase 4/5 tables.

Phase 8 implementation.
"""

import calendar
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Read-only metrics from existing audit and lease databases."""

    def __init__(self, audit_db_path: str, lease_db_path: str):
        self._audit_conn = sqlite3.connect(
            f"file:{audit_db_path}?mode=ro", uri=True, check_same_thread=False,
        )
        self._audit_conn.row_factory = sqlite3.Row

        self._lease_conn = sqlite3.connect(
            f"file:{lease_db_path}?mode=ro", uri=True, check_same_thread=False,
        )
        self._lease_conn.row_factory = sqlite3.Row

    # ------------------------------------------------------------------
    # Aggregate stats
    # ------------------------------------------------------------------

    def get_stats(self, hours: int = 24) -> dict:
        """Aggregate stats for the given time window."""
        cutoff = self._cutoff_iso(hours)
        today_epoch = self._today_epoch()

        # --- Request stats from audit_log ---
        ac = self._audit_conn

        total = self._count(ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?", (cutoff,))
        approved = self._count(ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND status = 'approved'", (cutoff,))
        denied = self._count(ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND status = 'denied'", (cutoff,))
        timed_out = self._count(ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND status = 'timeout'", (cutoff,))

        approval_rate = round(approved / total, 3) if total > 0 else 0.0

        # Average response time
        row = ac.execute(
            "SELECT AVG(response_time_ms) FROM audit_log WHERE timestamp >= ? AND response_time_ms IS NOT NULL",
            (cutoff,),
        ).fetchone()
        avg_response_time_ms = int(row[0]) if row[0] is not None else 0

        # By agent
        by_agent = {}
        rows = ac.execute(
            "SELECT agent_id, status, COUNT(*) as cnt FROM audit_log "
            "WHERE timestamp >= ? GROUP BY agent_id, status",
            (cutoff,),
        ).fetchall()
        for r in rows:
            aid = r["agent_id"]
            if aid not in by_agent:
                by_agent[aid] = {"total": 0, "approved": 0, "denied": 0}
            by_agent[aid]["total"] += r["cnt"]
            if r["status"] == "approved":
                by_agent[aid]["approved"] += r["cnt"]
            elif r["status"] == "denied":
                by_agent[aid]["denied"] += r["cnt"]

        # By credential
        by_credential = {}
        rows = ac.execute(
            "SELECT credential_name, status, COUNT(*) as cnt FROM audit_log "
            "WHERE timestamp >= ? GROUP BY credential_name, status",
            (cutoff,),
        ).fetchall()
        for r in rows:
            cname = r["credential_name"]
            if cname not in by_credential:
                by_credential[cname] = {"total": 0, "approved": 0}
            by_credential[cname]["total"] += r["cnt"]
            if r["status"] == "approved":
                by_credential[cname]["approved"] += r["cnt"]

        # By hour histogram
        by_hour = []
        rows = ac.execute(
            "SELECT substr(timestamp, 1, 13) as hour_key, COUNT(*) as cnt "
            "FROM audit_log WHERE timestamp >= ? "
            "GROUP BY hour_key ORDER BY hour_key",
            (cutoff,),
        ).fetchall()
        for r in rows:
            by_hour.append({"hour": r["hour_key"] + ":00", "count": r["cnt"]})

        # --- Lease stats ---
        lc = self._lease_conn

        active_leases = self._count(lc, "SELECT COUNT(*) FROM leases WHERE state = 'active'")
        expired_today = self._count(
            lc, "SELECT COUNT(*) FROM leases WHERE state = 'expired' AND expires_at >= ?",
            (today_epoch,),
        )
        revoked_today = self._count(
            lc, "SELECT COUNT(*) FROM leases WHERE state = 'revoked' AND revoked_at >= ?",
            (today_epoch,),
        )

        # Average lease duration (completed leases today)
        row = lc.execute(
            "SELECT AVG(expires_at - created_at) FROM leases "
            "WHERE state IN ('expired', 'revoked') AND created_at >= ?",
            (today_epoch,),
        ).fetchone()
        avg_duration_minutes = round(row[0] / 60, 1) if row[0] else 0.0

        # Renewals today (from audit log)
        renewals_today = self._count(
            ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND status = 'lease_renewed'",
            (self._cutoff_iso_from_epoch(today_epoch),),
        )

        # --- Proxy stats ---
        proxy_executed = self._count(
            ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND status = 'proxy_executed'",
            (cutoff,),
        )
        proxy_failed = self._count(
            ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND status = 'proxy_failed'",
            (cutoff,),
        )
        proxy_total = proxy_executed + proxy_failed
        proxy_success_rate = round(proxy_executed / proxy_total, 2) if proxy_total > 0 else 0.0

        # Proxy by action
        by_action = {}
        rows = ac.execute(
            "SELECT purpose, COUNT(*) as cnt FROM audit_log "
            "WHERE timestamp >= ? AND status IN ('proxy_executed', 'proxy_failed') "
            "AND purpose LIKE 'proxy:%' GROUP BY purpose",
            (cutoff,),
        ).fetchall()
        for r in rows:
            # purpose format: "proxy:action_name purpose_text"
            purpose = r["purpose"] or ""
            action_name = purpose.replace("proxy:", "").split(" ")[0] if purpose.startswith("proxy:") else purpose
            if action_name:
                by_action[action_name] = by_action.get(action_name, 0) + r["cnt"]

        # --- Policy stats ---
        denials_today = self._count(
            ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND status = 'denied'",
            (self._cutoff_iso_from_epoch(today_epoch),),
        )

        # Denial reasons from policy_checks
        denial_reasons = {}
        rows = ac.execute(
            "SELECT policy_checks FROM audit_log "
            "WHERE timestamp >= ? AND status = 'denied' AND policy_checks IS NOT NULL",
            (self._cutoff_iso_from_epoch(today_epoch),),
        ).fetchall()
        for r in rows:
            try:
                checks = json.loads(r["policy_checks"])
                for check in checks:
                    if not check.get("allowed", True):
                        reason_key = check.get("check", "unknown")
                        denial_reasons[reason_key] = denial_reasons.get(reason_key, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass

        # Auto-approvals today
        auto_approvals_today = self._count(
            ac,
            "SELECT COUNT(*) FROM audit_log "
            "WHERE timestamp >= ? AND status = 'approved' AND purpose LIKE '%auto-approve%'",
            (self._cutoff_iso_from_epoch(today_epoch),),
        )

        return {
            "window_hours": hours,
            "requests": {
                "total": total,
                "approved": approved,
                "denied": denied,
                "timed_out": timed_out,
                "approval_rate": approval_rate,
                "avg_response_time_ms": avg_response_time_ms,
                "by_agent": by_agent,
                "by_credential": by_credential,
                "by_hour": by_hour,
            },
            "leases": {
                "active": active_leases,
                "expired_today": expired_today,
                "revoked_today": revoked_today,
                "avg_duration_minutes": avg_duration_minutes,
                "renewals_today": renewals_today,
            },
            "proxy": {
                "executions_today": proxy_total,
                "success_rate": proxy_success_rate,
                "by_action": by_action,
            },
            "policy": {
                "denials_today": denials_today,
                "denial_reasons": denial_reasons,
                "auto_approvals_today": auto_approvals_today,
            },
        }

    # ------------------------------------------------------------------
    # Agent-specific activity
    # ------------------------------------------------------------------

    def get_agent_activity(self, agent_id: str, hours: int = 24) -> dict:
        """Detailed activity for a specific agent."""
        cutoff = self._cutoff_iso(hours)
        ac = self._audit_conn
        lc = self._lease_conn

        total = self._count(ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND agent_id = ?", (cutoff, agent_id))
        approved = self._count(ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND agent_id = ? AND status = 'approved'", (cutoff, agent_id))
        denied = self._count(ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND agent_id = ? AND status = 'denied'", (cutoff, agent_id))
        timed_out = self._count(ac, "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND agent_id = ? AND status = 'timeout'", (cutoff, agent_id))

        approval_rate = round(approved / total, 3) if total > 0 else 0.0

        # Last seen
        row = ac.execute(
            "SELECT timestamp FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        last_seen = row["timestamp"] if row else None

        # Credentials accessed
        credentials = {}
        rows = ac.execute(
            "SELECT credential_name, COUNT(*) as cnt FROM audit_log "
            "WHERE timestamp >= ? AND agent_id = ? AND status = 'approved' "
            "GROUP BY credential_name ORDER BY cnt DESC",
            (cutoff, agent_id),
        ).fetchall()
        for r in rows:
            credentials[r["credential_name"]] = r["cnt"]

        # Active leases
        active_leases = self._count(lc, "SELECT COUNT(*) FROM leases WHERE state = 'active' AND agent_id = ?", (agent_id,))

        # Recent events
        events = []
        rows = ac.execute(
            "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT 20",
            (agent_id,),
        ).fetchall()
        for r in rows:
            events.append(self._row_to_event(r))

        return {
            "agent_id": agent_id,
            "window_hours": hours,
            "total": total,
            "approved": approved,
            "denied": denied,
            "timed_out": timed_out,
            "approval_rate": approval_rate,
            "last_seen": last_seen,
            "credentials": credentials,
            "active_leases": active_leases,
            "recent_events": events,
        }

    # ------------------------------------------------------------------
    # Recent events
    # ------------------------------------------------------------------

    def get_recent_events(self, limit: int = 50, agent_id: str | None = None) -> list[dict]:
        """Most recent audit entries, formatted for display."""
        ac = self._audit_conn
        if agent_id:
            rows = ac.execute(
                "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        else:
            rows = ac.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def check_anomalies(self, config: dict) -> list[dict]:
        """Check for anomalous behavior based on threshold config.

        Config format:
        {
            "default": {"max_requests_per_hour": 30, ...},
            "monina": {"max_requests_per_hour": 20, ...}
        }
        """
        anomalies = []
        ac = self._audit_conn

        # Get all agents active in the last hour
        one_hour_ago = self._cutoff_iso(1)
        one_day_ago = self._cutoff_iso(24)

        agent_rows = ac.execute(
            "SELECT DISTINCT agent_id FROM audit_log WHERE timestamp >= ?",
            (one_day_ago,),
        ).fetchall()

        for row in agent_rows:
            agent_id = row["agent_id"]
            thresholds = config.get(agent_id, config.get("default", {}))

            if not thresholds:
                continue

            # Requests per hour
            max_rph = thresholds.get("max_requests_per_hour")
            if max_rph:
                count = self._count(
                    ac,
                    "SELECT COUNT(*) FROM audit_log WHERE agent_id = ? AND timestamp >= ?",
                    (agent_id, one_hour_ago),
                )
                if count > max_rph:
                    anomalies.append({
                        "type": "rate_spike",
                        "agent_id": agent_id,
                        "metric": "requests_per_hour",
                        "value": count,
                        "threshold": max_rph,
                        "severity": "critical" if count > max_rph * 2 else "warning",
                        "timestamp": self._now_iso(),
                    })

            # Requests per day
            max_rpd = thresholds.get("max_requests_per_day")
            if max_rpd:
                count = self._count(
                    ac,
                    "SELECT COUNT(*) FROM audit_log WHERE agent_id = ? AND timestamp >= ?",
                    (agent_id, one_day_ago),
                )
                if count > max_rpd:
                    anomalies.append({
                        "type": "rate_spike",
                        "agent_id": agent_id,
                        "metric": "requests_per_day",
                        "value": count,
                        "threshold": max_rpd,
                        "severity": "critical" if count > max_rpd * 2 else "warning",
                        "timestamp": self._now_iso(),
                    })

            # Unique credentials per hour
            max_creds = thresholds.get("max_unique_credentials_per_hour")
            if max_creds:
                cred_row = ac.execute(
                    "SELECT COUNT(DISTINCT credential_name) as cnt FROM audit_log "
                    "WHERE agent_id = ? AND timestamp >= ?",
                    (agent_id, one_hour_ago),
                ).fetchone()
                count = cred_row["cnt"] if cred_row else 0
                if count > max_creds:
                    anomalies.append({
                        "type": "credential_sprawl",
                        "agent_id": agent_id,
                        "metric": "unique_credentials_per_hour",
                        "value": count,
                        "threshold": max_creds,
                        "severity": "warning",
                        "timestamp": self._now_iso(),
                    })

            # Denials per hour
            max_denials = thresholds.get("max_denials_per_hour")
            if max_denials:
                count = self._count(
                    ac,
                    "SELECT COUNT(*) FROM audit_log WHERE agent_id = ? AND timestamp >= ? AND status = 'denied'",
                    (agent_id, one_hour_ago),
                )
                if count > max_denials:
                    anomalies.append({
                        "type": "denial_spike",
                        "agent_id": agent_id,
                        "metric": "denials_per_hour",
                        "value": count,
                        "threshold": max_denials,
                        "severity": "critical" if count > max_denials * 2 else "warning",
                        "timestamp": self._now_iso(),
                    })

        return anomalies

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _count(conn: sqlite3.Connection, query: str, params: tuple = ()) -> int:
        row = conn.execute(query, params).fetchone()
        return row[0] if row else 0

    @staticmethod
    def _cutoff_iso(hours: int) -> str:
        """ISO 8601 UTC timestamp for `hours` ago."""
        return time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - hours * 3600),
        )

    @staticmethod
    def _cutoff_iso_from_epoch(epoch: float) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))

    @staticmethod
    def _today_epoch() -> float:
        today_start = time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime())
        return calendar.timegm(time.strptime(today_start, "%Y-%m-%dT%H:%M:%SZ"))

    @staticmethod
    def _now_iso() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict:
        """Convert an audit row to a display-friendly event dict."""
        d = dict(row)
        # Parse policy_checks JSON
        if d.get("policy_checks"):
            try:
                d["policy_checks"] = json.loads(d["policy_checks"])
            except (json.JSONDecodeError, TypeError):
                pass
        # Parse fields_requested JSON
        if d.get("fields_requested"):
            try:
                d["fields_requested"] = json.loads(d["fields_requested"])
            except (json.JSONDecodeError, TypeError):
                pass
        return d

    def close(self):
        self._audit_conn.close()
        self._lease_conn.close()
