"""Credential rotation — track age and rotate supported services.

Phase 9: One-click rotation for services with API support, age tracking
via Bitwarden revisionDate, and semi-manual rotation with instructions
for services without API rotation.

Uses httpx (already a dependency from Phase 7) for service API calls.
No new pip dependencies.
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("credential-gate.rotation")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RotationResult:
    success: bool
    credential_name: str
    rotation_type: str          # "automatic", "semi-manual", "manual_required"
    message: str                # human-readable result
    old_invalidated: bool       # was the old credential revoked?
    bw_updated: bool            # was Bitwarden updated?
    instructions: str | None    # if manual steps needed
    error: str | None = None


# ---------------------------------------------------------------------------
# Rotator
# ---------------------------------------------------------------------------

class CredentialRotator:
    """Handles credential rotation for supported services."""

    ROTATORS = {
        "github_pat": "_rotate_github_pat",
        "cloudflare_api_token": "_rotate_cloudflare_token",
    }

    def __init__(self, bitwarden, config: dict):
        self._bw = bitwarden
        self._config = config
        self._rotation_cfg = config.get("rotation", {})
        self._stale_days = self._rotation_cfg.get("stale_threshold_days", 30)
        self._overdue_days = self._rotation_cfg.get("overdue_threshold_days", 90)

    async def rotate(self, credential_name: str, credential_type: str) -> RotationResult:
        """Rotate a credential.

        1. Look up the rotator method for the credential type
        2. If automatic rotation is supported, execute it
        3. Otherwise return semi-manual instructions
        """
        method_name = self.ROTATORS.get(credential_type)
        if not method_name:
            return RotationResult(
                success=False,
                credential_name=credential_name,
                rotation_type="manual_required",
                message=f"No automatic rotator for type '{credential_type}'",
                old_invalidated=False,
                bw_updated=False,
                instructions=(
                    f"Manual rotation required for '{credential_name}':\n"
                    f"1. Generate a new credential at the service provider\n"
                    f"2. Update the Bitwarden item '{credential_name}' with the new value\n"
                    f"3. Verify the new credential works"
                ),
            )

        method = getattr(self, method_name)
        return await method(credential_name)

    async def _rotate_github_pat(self, bw_item_name: str) -> RotationResult:
        """Rotate a GitHub fine-grained PAT.

        GitHub fine-grained PATs can't be rotated via API (no create-via-API yet).
        Instead:
        - Check token validity via GET /user (with current token)
        - Report token age, expiry, and permissions
        - Return instructions with link to create new token
        """
        services_cfg = self._rotation_cfg.get("services", {}).get("github", {})
        token_url = services_cfg.get(
            "token_settings_url",
            "https://github.com/settings/tokens?type=beta",
        )

        # Fetch current token from Bitwarden
        try:
            item = self._bw.get_item(bw_item_name)
            current_token = self._bw.extract_fields(item, ["password"]).get("password")
            if not current_token:
                return RotationResult(
                    success=False,
                    credential_name=bw_item_name,
                    rotation_type="semi-manual",
                    message="No password found in Bitwarden item",
                    old_invalidated=False,
                    bw_updated=False,
                    instructions=None,
                    error="Bitwarden item has no password field",
                )
        except Exception as e:
            return RotationResult(
                success=False,
                credential_name=bw_item_name,
                rotation_type="semi-manual",
                message=f"Failed to read credential from Bitwarden: {e}",
                old_invalidated=False,
                bw_updated=False,
                instructions=None,
                error=str(e),
            )

        # Check token validity
        token_info = ""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"Bearer {current_token}",
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "credential-gate",
                    },
                )
                if resp.status_code == 200:
                    user_data = resp.json()
                    token_info = f"Token is valid (user: {user_data.get('login', 'unknown')})"
                elif resp.status_code == 401:
                    token_info = "Token is INVALID or expired"
                else:
                    token_info = f"Token check returned HTTP {resp.status_code}"
        except Exception as e:
            token_info = f"Could not verify token: {e}"

        # Get credential age
        age_info = self.get_credential_age(bw_item_name)
        age_text = f"Age: {age_info.get('age_days', '?')} days ({age_info.get('status', 'unknown')})"

        instructions = (
            f"GitHub PAT rotation (semi-manual):\n"
            f"  Current status: {token_info}\n"
            f"  {age_text}\n\n"
            f"Steps:\n"
            f"  1. Go to: {token_url}\n"
            f"  2. Create a new fine-grained token with the same permissions\n"
            f"  3. Update the Bitwarden item '{bw_item_name}' with the new token\n"
            f"  4. Delete the old token from GitHub settings\n"
            f"  5. Verify the new token works"
        )

        return RotationResult(
            success=True,
            credential_name=bw_item_name,
            rotation_type="semi-manual",
            message=f"GitHub PAT rotation instructions generated. {token_info}. {age_text}",
            old_invalidated=False,
            bw_updated=False,
            instructions=instructions,
        )

    async def _rotate_cloudflare_token(self, bw_item_name: str) -> RotationResult:
        """Rotate a Cloudflare API token.

        Cloudflare supports full API-based rotation:
        1. Verify current token
        2. List tokens to find the matching one
        3. Create new token with same policies
        4. Update Bitwarden
        5. Verify new token
        6. Delete old token
        """
        services_cfg = self._rotation_cfg.get("services", {}).get("cloudflare", {})
        api_url = services_cfg.get("api_url", "https://api.cloudflare.com/client/v4")

        # Fetch current token from Bitwarden
        try:
            item = self._bw.get_item(bw_item_name)
            current_token = self._bw.extract_fields(item, ["password"]).get("password")
            if not current_token:
                return RotationResult(
                    success=False,
                    credential_name=bw_item_name,
                    rotation_type="automatic",
                    message="No password found in Bitwarden item",
                    old_invalidated=False,
                    bw_updated=False,
                    instructions=None,
                    error="Bitwarden item has no password field",
                )
        except Exception as e:
            return RotationResult(
                success=False,
                credential_name=bw_item_name,
                rotation_type="automatic",
                message=f"Failed to read credential from Bitwarden: {e}",
                old_invalidated=False,
                bw_updated=False,
                instructions=None,
                error=str(e),
            )

        headers = {
            "Authorization": f"Bearer {current_token}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Step 1: Verify current token
                verify_resp = await client.get(
                    f"{api_url}/user/tokens/verify",
                    headers=headers,
                )
                if verify_resp.status_code != 200:
                    return RotationResult(
                        success=False,
                        credential_name=bw_item_name,
                        rotation_type="automatic",
                        message="Current token verification failed",
                        old_invalidated=False,
                        bw_updated=False,
                        instructions=None,
                        error=f"Token verify returned HTTP {verify_resp.status_code}: {verify_resp.text}",
                    )

                verify_data = verify_resp.json()
                token_id = verify_data.get("result", {}).get("id")

                # Step 2: Get current token details (including policies)
                tokens_resp = await client.get(
                    f"{api_url}/user/tokens",
                    headers=headers,
                )
                if tokens_resp.status_code != 200:
                    return RotationResult(
                        success=False,
                        credential_name=bw_item_name,
                        rotation_type="automatic",
                        message="Failed to list tokens",
                        old_invalidated=False,
                        bw_updated=False,
                        instructions=None,
                        error=f"List tokens returned HTTP {tokens_resp.status_code}",
                    )

                # Find the matching token
                tokens = tokens_resp.json().get("result", [])
                current_token_data = None
                for t in tokens:
                    if t.get("id") == token_id:
                        current_token_data = t
                        break

                if not current_token_data:
                    return RotationResult(
                        success=False,
                        credential_name=bw_item_name,
                        rotation_type="automatic",
                        message="Could not find current token in token list",
                        old_invalidated=False,
                        bw_updated=False,
                        instructions=None,
                        error=f"Token ID {token_id} not found in list",
                    )

                # Step 3: Create new token with same policies
                new_token_payload = {
                    "name": f"{current_token_data.get('name', bw_item_name)}-rotated-{int(time.time())}",
                    "policies": current_token_data.get("policies", []),
                }
                # Include condition if present
                if current_token_data.get("condition"):
                    new_token_payload["condition"] = current_token_data["condition"]

                create_resp = await client.post(
                    f"{api_url}/user/tokens",
                    headers=headers,
                    json=new_token_payload,
                )
                if create_resp.status_code != 200:
                    return RotationResult(
                        success=False,
                        credential_name=bw_item_name,
                        rotation_type="automatic",
                        message="Failed to create new token",
                        old_invalidated=False,
                        bw_updated=False,
                        instructions=(
                            "Token creation failed. The current token may lack "
                            "'API Tokens: Edit' permission. Add this permission "
                            "and try again."
                        ),
                        error=f"Create token returned HTTP {create_resp.status_code}: {create_resp.text}",
                    )

                new_token_data = create_resp.json().get("result", {})
                new_token_value = new_token_data.get("value")
                if not new_token_value:
                    return RotationResult(
                        success=False,
                        credential_name=bw_item_name,
                        rotation_type="automatic",
                        message="New token created but no value returned",
                        old_invalidated=False,
                        bw_updated=False,
                        instructions=None,
                        error="Cloudflare API did not return the new token value",
                    )

                # Step 4: Update Bitwarden with new token
                bw_updated = False
                try:
                    import base64
                    import json

                    bw_item = self._bw.get_item(bw_item_name)
                    item_id = bw_item.get("id")
                    login = bw_item.get("login", {}) or {}
                    login["password"] = new_token_value
                    bw_item["login"] = login

                    item_json = json.dumps(bw_item).encode()
                    item_b64 = base64.b64encode(item_json).decode()
                    self._bw.client._run("edit", "item", item_id, item_b64)
                    bw_updated = True
                    logger.info("Updated Bitwarden item '%s' with new Cloudflare token", bw_item_name)
                except Exception as e:
                    logger.error("Failed to update Bitwarden: %s", e)
                    # Continue — we have the new token but Bitwarden update failed
                    # This is recoverable: the old token still works

                # Step 5: Verify new token works
                new_headers = {
                    "Authorization": f"Bearer {new_token_value}",
                    "Content-Type": "application/json",
                }
                verify_new = await client.get(
                    f"{api_url}/user/tokens/verify",
                    headers=new_headers,
                )
                new_token_valid = verify_new.status_code == 200

                if not new_token_valid:
                    return RotationResult(
                        success=False,
                        credential_name=bw_item_name,
                        rotation_type="automatic",
                        message="New token created but verification failed",
                        old_invalidated=False,
                        bw_updated=bw_updated,
                        instructions="New token failed verification. Old token is still active.",
                        error=f"New token verify returned HTTP {verify_new.status_code}",
                    )

                # Step 6: Delete old token
                old_invalidated = False
                delete_resp = await client.delete(
                    f"{api_url}/user/tokens/{token_id}",
                    headers=new_headers,  # use new token to delete old
                )
                if delete_resp.status_code == 200:
                    old_invalidated = True
                    logger.info("Deleted old Cloudflare token %s", token_id)
                else:
                    logger.warning(
                        "Failed to delete old Cloudflare token: HTTP %d",
                        delete_resp.status_code,
                    )

                return RotationResult(
                    success=True,
                    credential_name=bw_item_name,
                    rotation_type="automatic",
                    message=(
                        f"Cloudflare token rotated successfully. "
                        f"Old token {'revoked' if old_invalidated else 'NOT revoked (delete manually)'}. "
                        f"Bitwarden {'updated' if bw_updated else 'NOT updated (update manually)'}."
                    ),
                    old_invalidated=old_invalidated,
                    bw_updated=bw_updated,
                    instructions=None,
                )

        except httpx.TimeoutException:
            return RotationResult(
                success=False,
                credential_name=bw_item_name,
                rotation_type="automatic",
                message="Cloudflare API request timed out",
                old_invalidated=False,
                bw_updated=False,
                instructions=None,
                error="HTTP timeout communicating with Cloudflare API",
            )
        except Exception as e:
            return RotationResult(
                success=False,
                credential_name=bw_item_name,
                rotation_type="automatic",
                message=f"Cloudflare rotation failed: {e}",
                old_invalidated=False,
                bw_updated=False,
                instructions=None,
                error=str(e),
            )

    def get_credential_age(self, bw_item_name: str) -> dict:
        """Check when a credential was last rotated.

        Uses Bitwarden item's revisionDate field.
        """
        try:
            item = self._bw.get_item(bw_item_name)
            revision_date_str = item.get("revisionDate")
            if not revision_date_str:
                return {
                    "name": bw_item_name,
                    "last_rotated": None,
                    "age_days": None,
                    "status": "unknown",
                }

            # Parse ISO date (Bitwarden uses "2026-03-31T12:00:00.000Z")
            revision_date = datetime.fromisoformat(
                revision_date_str.replace("Z", "+00:00")
            )
            now = datetime.now(timezone.utc)
            age_days = (now - revision_date).days

            if age_days > self._overdue_days:
                status = "overdue"
            elif age_days > self._stale_days:
                status = "stale"
            else:
                status = "ok"

            return {
                "name": bw_item_name,
                "last_rotated": revision_date_str,
                "age_days": age_days,
                "status": status,
            }
        except Exception as e:
            logger.warning("Failed to check age of '%s': %s", bw_item_name, e)
            return {
                "name": bw_item_name,
                "last_rotated": None,
                "age_days": None,
                "status": "error",
                "error": str(e),
            }

    def get_all_credential_ages(self) -> list[dict]:
        """Check age of all managed credentials.

        Uses the agent config to find all unique credential names.
        """
        # Collect unique credential names from agent configs
        credential_names: set[str] = set()
        agents = self._config.get("agents", {})
        for agent_cfg in agents.values():
            allowed = agent_cfg.get("allowed_credentials", [])
            for name in allowed:
                if name != "*":
                    credential_names.add(name)

        # Also check proxy actions
        proxy_cfg = self._config.get("proxy", {})
        if proxy_cfg.get("enabled", False):
            for action_cfg in proxy_cfg.get("actions", {}).values():
                cred_name = action_cfg.get("credential_name")
                if cred_name:
                    credential_names.add(cred_name)

        results = []
        for name in sorted(credential_names):
            results.append(self.get_credential_age(name))

        return results
