"""Auto-vaulting — move discovered secrets into Bitwarden.

Phase 9: Takes scan findings from SecretScanner and creates Bitwarden
vault items.  Generates replacement instructions for the original files.

No external dependencies — uses the existing Bitwarden session manager.
"""

import base64
import json
import logging

from discovery import SecretFinding

logger = logging.getLogger("credential-gate.vaulting")


class AutoVaulter:
    """Create Bitwarden items from scan findings."""

    def __init__(self, bitwarden):
        self._bw = bitwarden

    async def vault_finding(
        self,
        finding: SecretFinding,
        collection_id: str | None = None,
        custom_name: str | None = None,
    ) -> dict:
        """Create a Bitwarden item from a scan finding.

        1. Check if an item with the suggested name already exists (skip if so)
        2. Create a new Secure Note with the secret value
        3. Return metadata (not the secret)
        """
        item_name = custom_name or finding.suggested_bw_name

        # Check if item already exists
        try:
            existing = self._bw.get_item(item_name)
            if existing:
                return {
                    "status": "skipped",
                    "reason": f"Item '{item_name}' already exists in Bitwarden",
                    "item_name": item_name,
                }
        except Exception:
            # Item doesn't exist — good, we'll create it
            pass

        # Build the Bitwarden item JSON
        # Type 2 = Secure Note
        bw_item = {
            "type": 2,
            "secureNote": {"type": 0},
            "name": item_name,
            "notes": (
                f"Discovered by Credential Gate secret scanner\n"
                f"File: {finding.file_path}:{finding.line_number}\n"
                f"Pattern: {finding.pattern_name}\n"
                f"Severity: {finding.severity}\n"
                f"Value: {finding.raw_value}"
            ),
        }

        if collection_id:
            bw_item["collectionIds"] = [collection_id]

        try:
            item_json = json.dumps(bw_item).encode()
            item_b64 = base64.b64encode(item_json).decode()

            # Use bw create item
            result_raw = self._bw.client._run("create", "item", item_b64)
            created = json.loads(result_raw)
            logger.info("Vaulted secret '%s' from %s:%d", item_name, finding.file_path, finding.line_number)

            return {
                "status": "created",
                "item_name": item_name,
                "item_id": created.get("id"),
                "source_file": finding.file_path,
                "source_line": finding.line_number,
                "pattern": finding.pattern_name,
            }
        except Exception as e:
            logger.error("Failed to vault '%s': %s", item_name, e)
            return {
                "status": "failed",
                "item_name": item_name,
                "error": str(e),
            }

    async def vault_batch(
        self,
        findings: list[SecretFinding],
        collection_id: str | None = None,
    ) -> dict:
        """Vault multiple findings. Returns summary of created/skipped/failed."""
        created = 0
        skipped = 0
        failed = 0
        results = []

        for finding in findings:
            result = await self.vault_finding(finding, collection_id=collection_id)
            results.append(result)
            status = result.get("status")
            if status == "created":
                created += 1
            elif status == "skipped":
                skipped += 1
            else:
                failed += 1

        return {
            "total": len(findings),
            "created": created,
            "skipped": skipped,
            "failed": failed,
            "results": results,
        }

    @staticmethod
    def generate_replacement_instructions(finding: SecretFinding, bw_item_name: str) -> str:
        """Generate instructions for replacing the hardcoded secret with a reference.

        Returns file-type-appropriate instructions.
        """
        file_path = finding.file_path
        line = finding.line_number

        if file_path.endswith((".env", ".env.local", ".env.production")) or "/.env" in file_path:
            return (
                f"In {file_path}:{line}\n"
                f"Replace the hardcoded value with a comment:\n"
                f"  # Secret moved to Bitwarden: {bw_item_name}\n"
                f"  # Retrieve via: credential-gate API or `bw get notes {bw_item_name}`"
            )

        if file_path.endswith(".py"):
            return (
                f"In {file_path}:{line}\n"
                f"Replace the hardcoded value with:\n"
                f"  import os\n"
                f"  value = os.environ.get('{finding.pattern_name.upper()}')\n"
                f"  # Or use credential gate:\n"
                f"  # POST /credential with credential_name='{bw_item_name}'"
            )

        if file_path.endswith((".yaml", ".yml")):
            return (
                f"In {file_path}:{line}\n"
                f"Replace the hardcoded value with an environment variable reference:\n"
                f"  ${{ENV_VAR_NAME}}  # or use envsubst\n"
                f"  # Secret stored in Bitwarden: {bw_item_name}"
            )

        if file_path.endswith((".sh", ".bash", ".zsh", ".bashrc", ".zshrc")):
            return (
                f"In {file_path}:{line}\n"
                f"Replace the hardcoded value with:\n"
                f"  value=$(bw get notes '{bw_item_name}')\n"
                f"  # Or via credential gate API"
            )

        if file_path.endswith((".json", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties")):
            return (
                f"In {file_path}:{line}\n"
                f"Replace the hardcoded value with an environment variable\n"
                f"or configuration reference.\n"
                f"  # Secret stored in Bitwarden: {bw_item_name}"
            )

        return (
            f"In {file_path}:{line}\n"
            f"Replace the hardcoded secret with a reference to Bitwarden item '{bw_item_name}'\n"
            f"Retrieve via: credential-gate API or `bw get notes {bw_item_name}`"
        )
