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
