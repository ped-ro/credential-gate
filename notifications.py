"""Push notifications via Ntfy.sh for Credential Gate.

Sends push notifications to the Ntfy app when credential requests
arrive.  Supports three notification types:

  - Approval request (with Approve/Deny action buttons for phone mode)
  - Touch-only (informational, no buttons — for yubikey mode)
  - Timeout / approved status updates

Notifications are best-effort — failures are logged but never block
credential requests.
"""

import logging
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)


def send_approval_notification(
    config: dict,
    request_id: str,
    agent_id: str,
    credential_name: str,
    purpose: str,
) -> bool:
    """Send Ntfy notification with Approve/Deny action buttons.

    Used in 'phone' and 'both' modes. Returns True if sent.
    Never raises — all errors are logged and swallowed.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]
        callback_base = config["notifications"]["callback_base_url"]

        approve_url = f"{callback_base}/approve/{request_id}"
        deny_url = f"{callback_base}/deny/{request_id}"

        purpose_text = f"\nPurpose: {purpose}" if purpose else ""
        message = f"{agent_id} requests '{credential_name}'{purpose_text}"

        headers = {
            "Title": "Credential Gate — Approval Required",
            "Priority": "urgent",
            "Tags": "key",
            "Actions": (
                f"http, Approve, {approve_url}, method=POST, clear=true; "
                f"http, Deny, {deny_url}, method=POST, clear=true"
            ),
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Approval notification sent for '%s'", credential_name)
                return True
            else:
                logger.warning("Ntfy returned status %d", resp.status)
                return False

    except urllib.error.URLError as e:
        logger.warning("Failed to send approval notification (ntfy unreachable): %s", e)
        return False
    except Exception as e:
        logger.warning("Failed to send approval notification: %s", e)
        return False


def send_touch_notification(
    config: dict,
    agent_id: str,
    credential_name: str,
    purpose: str,
) -> bool:
    """Send informational Ntfy notification (no action buttons).

    Used in 'yubikey' mode to notify that a YubiKey touch is waiting.
    Returns True if sent. Never raises.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        purpose_text = f" for '{purpose}'" if purpose else ""
        message = f"{agent_id} needs '{credential_name}'{purpose_text}\nTouch your YubiKey to approve"

        headers = {
            "Title": "Credential Gate — Touch Required",
            "Priority": "urgent",
            "Tags": "key",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Touch notification sent for '%s'", credential_name)
                return True
            else:
                logger.warning("Ntfy returned status %d", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send touch notification: %s", e)
        return False


def send_auto_approve_notification(
    config: dict,
    request_id: str,
    agent_id: str,
    credential_name: str,
    purpose: str,
    seconds: int,
) -> bool:
    """Send Ntfy notification for auto-approve countdown with Deny button.

    Used for low-risk credentials with auto_approve_seconds. The user can
    tap Deny to cancel the auto-approval. Returns True if sent. Never raises.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]
        callback_base = config["notifications"]["callback_base_url"]

        deny_url = f"{callback_base}/deny/{request_id}"

        purpose_text = f"\nPurpose: {purpose}" if purpose else ""
        message = (
            f"Auto-approving '{credential_name}' for {agent_id} in {seconds}s"
            f"{purpose_text}\nTap Deny to block"
        )

        headers = {
            "Title": "Credential Gate — Auto-Approve",
            "Priority": "default",
            "Tags": "timer_clock",
            "Actions": f"http, Deny, {deny_url}, method=POST, clear=true",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Auto-approve notification sent for '%s'", credential_name)
                return True
            else:
                logger.warning("Ntfy returned status %d", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send auto-approve notification: %s", e)
        return False


def send_timeout_notification(
    config: dict,
    agent_id: str,
    credential_name: str,
) -> bool:
    """Notify that a request timed out. Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        message = f"Request from {agent_id} for '{credential_name}' expired (no approval received)"

        headers = {
            "Title": "Credential Gate — Request Timed Out",
            "Priority": "default",
            "Tags": "hourglass",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status < 300

    except Exception:
        return False


def send_approved_notification(
    config: dict,
    agent_id: str,
    credential_name: str,
    method: str,
) -> bool:
    """Notify that a request was approved (and how). Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        message = f"'{credential_name}' released to {agent_id} via {method}"

        headers = {
            "Title": "Credential Gate — Approved",
            "Priority": "low",
            "Tags": "white_check_mark",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status < 300

    except Exception:
        return False


def send_lease_expired_notification(
    config: dict,
    agent_id: str,
    credential_name: str,
    lease_id: str,
    rotated: bool = False,
) -> bool:
    """Notify that a lease has expired. Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        rotation_note = " — credential rotated in Bitwarden" if rotated else ""
        message = (
            f"Lease expired: '{credential_name}' ({agent_id})"
            f"\nLease: {lease_id[:12]}…{rotation_note}"
        )

        headers = {
            "Title": "Credential Gate — Lease Expired",
            "Priority": "default",
            "Tags": "hourglass",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status < 300

    except Exception:
        return False


def send_lease_revoked_notification(
    config: dict,
    agent_id: str,
    credential_name: str,
    lease_id: str,
    reason: str = "",
) -> bool:
    """Notify that a lease was revoked. Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        reason_text = f" ({reason})" if reason else ""
        message = (
            f"Lease revoked: '{credential_name}' ({agent_id}){reason_text}"
            f"\nLease: {lease_id[:12]}…"
        )

        headers = {
            "Title": "Credential Gate — Lease Revoked",
            "Priority": "default",
            "Tags": "x",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status < 300

    except Exception:
        return False


def send_revoke_all_notification(
    config: dict,
    count: int,
    agent_id: str | None = None,
) -> bool:
    """Notify that all leases were revoked (emergency). Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        scope = f" for {agent_id}" if agent_id else ""
        message = f"All active leases revoked{scope} ({count} lease(s))"

        headers = {
            "Title": "Credential Gate — All Leases Revoked",
            "Priority": "urgent",
            "Tags": "rotating_light",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status < 300

    except Exception:
        return False


def send_rotation_failed_notification(
    config: dict,
    credential_name: str,
    error: str,
) -> bool:
    """Notify that credential rotation failed. Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        message = f"Credential rotation failed for '{credential_name}'\nError: {error}"

        headers = {
            "Title": "Credential Gate — Rotation Failed",
            "Priority": "urgent",
            "Tags": "warning",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status < 300

    except Exception:
        return False


def send_anomaly_notification(anomalies: list[dict], config: dict) -> bool:
    """Send high-priority Ntfy notification for detected anomalies.

    Priority: urgent (5). Tags: warning, rotating_light.
    Never raises — all errors are logged and swallowed.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        lines = [f"{len(anomalies)} anomaly(s) detected:"]
        for a in anomalies:
            lines.append(
                f"  {a['severity'].upper()}: {a['agent_id']} — "
                f"{a['metric']} = {a['value']} (threshold: {a['threshold']})"
            )
        message = "\n".join(lines)

        headers = {
            "Title": "Credential Gate — Anomaly Alert",
            "Priority": "urgent",
            "Tags": "warning,rotating_light",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Anomaly notification sent (%d anomalies)", len(anomalies))
                return True
            else:
                logger.warning("Ntfy returned status %d for anomaly notification", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send anomaly notification: %s", e)
        return False


def send_daily_digest_notification(digest_text: str, config: dict) -> bool:
    """Send daily digest via Ntfy.

    Priority: default (3). Tags: bar_chart.
    Never raises — all errors are logged and swallowed.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        headers = {
            "Title": "Credential Gate — Daily Digest",
            "Priority": "default",
            "Tags": "bar_chart",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = digest_text.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status < 300:
                logger.info("Daily digest notification sent")
                return True
            else:
                logger.warning("Ntfy returned status %d for digest", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send daily digest notification: %s", e)
        return False


def send_scan_complete_notification(
    config: dict,
    scan_path: str,
    total_findings: int,
    by_severity: dict,
) -> bool:
    """Notify that a secret scan completed. Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        severity_text = ", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items()))
        message = (
            f"Secret scan completed: {scan_path}\n"
            f"Findings: {total_findings} ({severity_text})"
        )

        priority = "urgent" if by_severity.get("critical", 0) > 0 else "default"
        headers = {
            "Title": "Credential Gate — Secret Scan Complete",
            "Priority": priority,
            "Tags": "mag",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Scan complete notification sent (%d findings)", total_findings)
                return True
            else:
                logger.warning("Ntfy returned status %d for scan notification", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send scan notification: %s", e)
        return False


def send_rotation_complete_notification(
    config: dict,
    credential_name: str,
    rotation_type: str,
    success: bool,
    message_text: str,
) -> bool:
    """Notify that a credential rotation completed (or failed). Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        status = "succeeded" if success else "failed"
        message = (
            f"Credential rotation {status}: '{credential_name}'\n"
            f"Type: {rotation_type}\n"
            f"{message_text}"
        )

        priority = "default" if success else "urgent"
        tag = "white_check_mark" if success else "warning"
        headers = {
            "Title": f"Credential Gate — Rotation {'Complete' if success else 'Failed'}",
            "Priority": priority,
            "Tags": tag,
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Rotation notification sent for '%s'", credential_name)
                return True
            else:
                logger.warning("Ntfy returned status %d for rotation notification", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send rotation notification: %s", e)
        return False


def send_vault_complete_notification(
    config: dict,
    created: int,
    skipped: int,
    failed: int,
) -> bool:
    """Notify that auto-vaulting completed. Never raises."""
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        message = (
            f"Auto-vaulting complete:\n"
            f"  Created: {created}\n"
            f"  Skipped: {skipped}\n"
            f"  Failed: {failed}"
        )

        headers = {
            "Title": "Credential Gate — Secrets Vaulted",
            "Priority": "default",
            "Tags": "lock",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Vault complete notification sent")
                return True
            else:
                logger.warning("Ntfy returned status %d for vault notification", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send vault notification: %s", e)
        return False


def send_panic_notification(
    reason: str,
    leases_revoked: int,
    config: dict,
) -> bool:
    """URGENT panic notification. Priority: max (5). Tags: rotating_light, lock, warning.

    Title: 'CREDENTIAL GATE LOCKED'
    Body: Reason, leases revoked, instructions to unlock.
    Never raises.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        message = (
            f"EMERGENCY LOCKDOWN\n"
            f"Reason: {reason}\n"
            f"Leases revoked: {leases_revoked}\n"
            f"\nAll credential requests are blocked.\n"
            f"Touch YubiKey + POST /unlock to restore access."
        )

        headers = {
            "Title": "CREDENTIAL GATE LOCKED",
            "Priority": "max",
            "Tags": "rotating_light,lock,warning",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Panic notification sent")
                return True
            else:
                logger.warning("Ntfy returned status %d for panic notification", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send panic notification: %s", e)
        return False


def send_unlock_notification(
    reason: str,
    locked_duration_seconds: int,
    config: dict,
) -> bool:
    """Gate unlocked notification. Priority: high (4). Tags: unlock, white_check_mark.

    Title: 'Credential Gate Unlocked'
    Body: Reason, how long it was locked.
    Never raises.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        minutes = locked_duration_seconds // 60
        seconds = locked_duration_seconds % 60
        duration = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

        message = (
            f"Gate unlocked after {duration}\n"
            f"Reason: {reason}\n"
            f"\nNormal operations resumed."
        )

        headers = {
            "Title": "Credential Gate Unlocked",
            "Priority": "high",
            "Tags": "unlock,white_check_mark",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Unlock notification sent")
                return True
            else:
                logger.warning("Ntfy returned status %d for unlock notification", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send unlock notification: %s", e)
        return False


def send_identity_violation_notification(
    agent_id: str,
    violation: str,
    source_ip: str,
    config: dict,
) -> bool:
    """Identity violation alert. Priority: urgent (5). Tags: warning, detective.

    Title: 'Identity Violation -- {agent_id}'
    Body: What happened, source IP, action taken.
    Never raises.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        message = (
            f"Agent: {agent_id}\n"
            f"Violation: {violation}\n"
            f"Source IP: {source_ip}\n"
            f"\nRequest was DENIED."
        )

        headers = {
            "Title": f"Identity Violation \u2014 {agent_id}",
            "Priority": "urgent",
            "Tags": "warning,detective",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Identity violation notification sent for '%s'", agent_id)
                return True
            else:
                logger.warning("Ntfy returned status %d for identity violation", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send identity violation notification: %s", e)
        return False


def test_ntfy(config: dict) -> bool:
    """Send a test notification to verify Ntfy connectivity.

    Returns True if the notification was sent successfully.
    """
    try:
        ntfy_server = config["notifications"]["ntfy_server"]
        ntfy_topic = config["notifications"]["ntfy_topic"]

        message = "Credential Gate test notification — Ntfy is working!"

        headers = {
            "Title": "Credential Gate — Test",
            "Priority": "default",
            "Tags": "test_tube",
        }

        ntfy_token = config["notifications"].get("ntfy_token")
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
        data = message.encode()

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status < 300

    except Exception as e:
        logger.error("Ntfy test failed: %s", e)
        return False
