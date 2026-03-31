"""Push notifications via Home Assistant for Credential Gate.

Sends time-sensitive push notifications to Pete's iPhone when a YubiKey
touch is required or when a request times out. Notifications are
best-effort — failures are logged but never block credential requests.
"""

import logging
import urllib.error
import urllib.request
import json

from bitwarden import keychain_retrieve

logger = logging.getLogger(__name__)


def _get_ha_token(keychain_service: str, keychain_account: str) -> str | None:
    """Retrieve the Home Assistant long-lived access token from Keychain."""
    return keychain_retrieve(keychain_service, keychain_account)


def send_touch_notification(
    agent_id: str,
    credential_name: str,
    purpose: str,
    ha_url: str,
    keychain_service: str = "credential-gate",
    keychain_account: str = "home-assistant",
) -> bool:
    """Send a push notification that a YubiKey touch is waiting.

    Returns True if the notification was sent, False otherwise.
    Never raises — all errors are logged and swallowed.
    """
    try:
        token = _get_ha_token(keychain_service, keychain_account)
        if not token:
            logger.warning(
                "No HA token in Keychain — cannot send notification. "
                "Run: python setup.py store-ha-token"
            )
            return False

        purpose_text = f" for '{purpose}'" if purpose else ""
        message = f"{agent_id} needs '{credential_name}'{purpose_text}"

        payload = {
            "message": message,
            "title": "Credential Gate — Touch Required",
            "data": {
                "push": {
                    "sound": "default",
                    "interruption-level": "time-sensitive",
                },
            },
        }

        url = f"{ha_url.rstrip('/')}/api/services/notify/mobile_app_petes_iphone"
        data = json.dumps(payload).encode()

        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Touch notification sent for '%s'", credential_name)
                return True
            else:
                logger.warning("HA notification returned status %d", resp.status)
                return False

    except urllib.error.URLError as e:
        logger.warning("Failed to send touch notification (HA unreachable): %s", e)
        return False
    except Exception as e:
        logger.warning("Failed to send touch notification: %s", e)
        return False


def send_timeout_notification(
    agent_id: str,
    credential_name: str,
    ha_url: str,
    keychain_service: str = "credential-gate",
    keychain_account: str = "home-assistant",
) -> bool:
    """Send a push notification that a touch request timed out.

    Returns True if sent, False otherwise. Never raises.
    """
    try:
        token = _get_ha_token(keychain_service, keychain_account)
        if not token:
            return False

        payload = {
            "message": f"Touch timed out for '{credential_name}' — request denied",
            "title": "Credential Gate — Timeout",
            "data": {
                "push": {
                    "sound": "default",
                    "interruption-level": "active",
                },
            },
        }

        url = f"{ha_url.rstrip('/')}/api/services/notify/mobile_app_petes_iphone"
        data = json.dumps(payload).encode()

        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 300:
                logger.info("Timeout notification sent for '%s'", credential_name)
                return True
            else:
                logger.warning("HA timeout notification returned status %d", resp.status)
                return False

    except Exception as e:
        logger.warning("Failed to send timeout notification: %s", e)
        return False
