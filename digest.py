"""Daily digest generator for Credential Gate.

Generates a text summary of the last 24 hours and sends it via Ntfy.
Designed to be called once per day by the background scheduler.

Phase 8 implementation.
"""

import logging

from metrics import MetricsCollector

logger = logging.getLogger(__name__)


class DigestGenerator:
    """Generate and send daily usage digests."""

    def __init__(self, metrics: MetricsCollector, config: dict):
        self._metrics = metrics
        self._config = config

    async def generate_daily_digest(self) -> str:
        """Generate a text summary of the last 24 hours.

        Returns a plain-text string suitable for Ntfy notification body.
        """
        stats = self._metrics.get_stats(hours=24)

        rq = stats.get("requests", {})
        ls = stats.get("leases", {})
        px = stats.get("proxy", {})
        pol = stats.get("policy", {})

        lines = [
            "Credential Gate — Daily Digest",
            "",
        ]

        # Requests summary
        total = rq.get("total", 0)
        approved = rq.get("approved", 0)
        denied = rq.get("denied", 0)
        timed_out = rq.get("timed_out", 0)
        approval_rate = rq.get("approval_rate", 0)

        lines.append(f"Requests: {total} total ({approved} approved, {denied} denied, {timed_out} timed out)")
        lines.append(f"Approval rate: {approval_rate * 100:.1f}%")
        lines.append("")

        # Leases
        lines.append(f"Active leases: {ls.get('active', 0)}")
        lines.append(f"Lease renewals: {ls.get('renewals_today', 0)}")
        lines.append("")

        # Proxy
        px_total = px.get("executions_today", 0)
        px_rate = px.get("success_rate", 0)
        if px_total > 0:
            lines.append(f"Proxy executions: {px_total} ({px_rate * 100:.0f}% success)")
        else:
            lines.append("Proxy executions: 0")
        lines.append("")

        # Top agents
        by_agent = rq.get("by_agent", {})
        if by_agent:
            lines.append("Top agents:")
            # Sort by total desc
            sorted_agents = sorted(by_agent.items(), key=lambda x: x[1].get("total", 0), reverse=True)
            for agent_id, data in sorted_agents[:5]:
                a_total = data.get("total", 0)
                a_approved = data.get("approved", 0)
                a_rate = f"{a_approved / a_total * 100:.0f}%" if a_total > 0 else "—"
                lines.append(f"  - {agent_id}: {a_total} requests ({a_rate} approved)")
            lines.append("")

        # Top credentials
        by_cred = rq.get("by_credential", {})
        if by_cred:
            lines.append("Top credentials:")
            sorted_creds = sorted(by_cred.items(), key=lambda x: x[1].get("total", 0), reverse=True)
            for cred_name, data in sorted_creds[:5]:
                lines.append(f"  - {cred_name}: {data.get('total', 0)} requests")
            lines.append("")

        # Anomalies
        obs_cfg = self._config.get("observability", {})
        thresholds = obs_cfg.get("anomaly_thresholds", {})
        if thresholds:
            anomalies = self._metrics.check_anomalies(thresholds)
            if anomalies:
                lines.append(f"Anomalies: {len(anomalies)} detected")
                for a in anomalies:
                    lines.append(f"  - {a['severity'].upper()}: {a['agent_id']} {a['metric']} = {a['value']} (threshold: {a['threshold']})")
            else:
                lines.append("Anomalies: none")
        else:
            lines.append("Anomalies: none")

        return "\n".join(lines)

    async def send_digest(self):
        """Generate and send daily digest via Ntfy."""
        from notifications import send_daily_digest_notification

        try:
            digest_text = await self.generate_daily_digest()
            send_daily_digest_notification(digest_text, self._config)
            logger.info("Daily digest sent successfully")
        except Exception as e:
            logger.error("Failed to send daily digest: %s", e)
