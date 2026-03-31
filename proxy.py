"""Execution proxy for Credential Gate.

The most secure credential model: the agent never sees the raw credential.
Instead, the agent describes an action ("push to GitHub", "call Slack API"),
the gate approves it, executes the action with the credential injected, and
returns only the result.

This is how AWS IAM instance roles work — the application never touches
the raw key.

Phase 7 implementation.
"""

import asyncio
import base64
import logging
import os
import re
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# Shell metacharacters that must never appear in command args
_SHELL_METACHAR_RE = re.compile(r"[;|&$`><\n]")


@dataclass
class ProxyAction:
    """Definition of a proxy action loaded from config."""

    name: str
    type: str  # "http" or "command"
    credential_name: str
    credential_field: str = "password"
    # HTTP-specific
    method: str | None = None
    url_template: str | None = None
    auth_header_template: str | None = None
    extra_headers: dict | None = None
    # Command-specific
    command_template: str | None = None
    credential_env_var: str | None = None
    env_inject: dict | None = None
    allowed_args_pattern: str | None = None
    # Common
    timeout_seconds: int = 30
    max_response_bytes: int = 1_048_576  # 1 MB


@dataclass
class ProxyResult:
    """Result of a proxy action execution."""

    success: bool
    action_name: str
    # HTTP results
    status_code: int | None = None
    response_body: str | None = None
    response_headers: dict | None = None
    # Command results
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    # Common
    execution_time_ms: int = 0
    truncated: bool = False
    error: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "success": self.success,
            "action_name": self.action_name,
            "execution_time_ms": self.execution_time_ms,
            "truncated": self.truncated,
        }
        if self.status_code is not None:
            d["status_code"] = self.status_code
        if self.response_body is not None:
            d["output"] = self.response_body
        if self.response_headers is not None:
            d["response_headers"] = self.response_headers
        if self.exit_code is not None:
            d["exit_code"] = self.exit_code
        if self.stdout is not None:
            d["output"] = self.stdout
        if self.stderr is not None:
            d["stderr"] = self.stderr
        if self.error is not None:
            d["error"] = self.error
        return d


# ---------------------------------------------------------------------------
# ProxyExecutor
# ---------------------------------------------------------------------------

class ProxyExecutor:
    """Loads proxy action definitions and executes them with credential injection."""

    def __init__(self, config: dict):
        proxy_cfg = config.get("proxy", {})
        self._actions: dict[str, ProxyAction] = {}
        self._enabled = proxy_cfg.get("enabled", False)

        if not self._enabled:
            return

        raw_actions = proxy_cfg.get("actions", {})
        for name, acfg in raw_actions.items():
            action = ProxyAction(
                name=name,
                type=acfg.get("type", "http"),
                credential_name=acfg.get("credential_name", ""),
                credential_field=acfg.get("credential_field", "password"),
                method=acfg.get("method"),
                url_template=acfg.get("url_template"),
                auth_header_template=acfg.get("auth_header_template"),
                extra_headers=acfg.get("extra_headers"),
                command_template=acfg.get("command_template"),
                credential_env_var=acfg.get("credential_env_var"),
                env_inject=acfg.get("env_inject"),
                allowed_args_pattern=acfg.get("allowed_args_pattern"),
                timeout_seconds=acfg.get("timeout_seconds", 30),
                max_response_bytes=acfg.get("max_response_bytes", 1_048_576),
            )
            self._actions[name] = action
            logger.info(
                "Proxy action loaded: %s (type=%s, credential=%s)",
                name, action.type, action.credential_name,
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def get_action(self, name: str) -> ProxyAction | None:
        return self._actions.get(name)

    def list_actions(self) -> list[dict]:
        """List all configured proxy actions (metadata only)."""
        result = []
        for action in self._actions.values():
            entry: dict = {
                "name": action.name,
                "type": action.type,
                "credential_name": action.credential_name,
            }
            if action.type == "http":
                entry["url_template"] = action.url_template
            elif action.type == "command":
                entry["command_template"] = action.command_template
                if action.allowed_args_pattern:
                    entry["allowed_args_pattern"] = action.allowed_args_pattern
            entry["timeout_seconds"] = action.timeout_seconds
            result.append(entry)
        return result

    def get_actions_for_credential(self, credential_name: str) -> list[str]:
        """Return proxy action names that use a given credential."""
        return [
            a.name for a in self._actions.values()
            if a.credential_name == credential_name
        ]

    # -- execution ---------------------------------------------------------

    async def execute(
        self, action: ProxyAction, credential: str, params: dict,
    ) -> ProxyResult:
        """Dispatch to the appropriate executor based on action type."""
        if action.type == "http":
            return await self.execute_http(action, credential, params)
        elif action.type == "command":
            return await self.execute_command(action, credential, params)
        else:
            return ProxyResult(
                success=False,
                action_name=action.name,
                error=f"Unknown action type: {action.type}",
            )

    async def execute_http(
        self, action: ProxyAction, credential: str, params: dict,
    ) -> ProxyResult:
        """Execute an HTTP request with credential injected."""
        start = time.monotonic()
        truncated = False

        # Resolve method — action default or agent-specified
        method = (params.get("method") or action.method or "GET").upper()

        # Expand URL template
        path = params.get("path", "")
        if not action.url_template:
            return ProxyResult(
                success=False, action_name=action.name,
                error="No url_template configured for this action",
                execution_time_ms=_elapsed_ms(start),
            )
        url = action.url_template.replace("{path}", path)

        # SSRF prevention — validate expanded URL domain matches template
        if not _validate_url_domain(url, action.url_template):
            return ProxyResult(
                success=False, action_name=action.name,
                error="URL domain does not match action template (SSRF blocked)",
                execution_time_ms=_elapsed_ms(start),
            )

        # Build headers
        headers: dict[str, str] = {}
        if action.extra_headers:
            headers.update(action.extra_headers)

        # Agent-provided extra headers (cannot override auth)
        agent_headers = params.get("extra_headers")
        if isinstance(agent_headers, dict):
            for k, v in agent_headers.items():
                if k.lower() != "authorization":
                    headers[k] = v

        # Inject auth header
        if action.auth_header_template:
            auth_value = action.auth_header_template.replace("{credential}", credential)
            headers["Authorization"] = auth_value

        # Body
        body = params.get("body")

        # Query params
        query_params = params.get("query_params")

        try:
            async with httpx.AsyncClient(timeout=action.timeout_seconds) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=body if isinstance(body, (dict, list)) else None,
                    content=body if isinstance(body, str) else None,
                    params=query_params,
                )

                # Read response with size limit
                raw_body = resp.text
                if len(raw_body) > action.max_response_bytes:
                    raw_body = raw_body[:action.max_response_bytes]
                    truncated = True

                # Sanitize credential from response
                sanitized_body = sanitize_output(raw_body, credential)

                # Sanitize response headers (remove sensitive ones)
                safe_headers = {}
                for k, v in resp.headers.items():
                    lower_k = k.lower()
                    if lower_k not in ("set-cookie", "authorization"):
                        safe_headers[k] = sanitize_output(v, credential)

                success = 200 <= resp.status_code < 400

                return ProxyResult(
                    success=success,
                    action_name=action.name,
                    status_code=resp.status_code,
                    response_body=sanitized_body,
                    response_headers=safe_headers,
                    execution_time_ms=_elapsed_ms(start),
                    truncated=truncated,
                )

        except httpx.TimeoutException:
            return ProxyResult(
                success=False, action_name=action.name,
                error=f"HTTP request timed out after {action.timeout_seconds}s",
                execution_time_ms=_elapsed_ms(start),
            )
        except Exception as e:
            return ProxyResult(
                success=False, action_name=action.name,
                error=f"HTTP request failed: {e}",
                execution_time_ms=_elapsed_ms(start),
            )

    async def execute_command(
        self, action: ProxyAction, credential: str, params: dict,
    ) -> ProxyResult:
        """Execute a shell command with credential injected via env var or temp file."""
        start = time.monotonic()

        args_str = params.get("args", "")

        # Validate args against allowed pattern
        if action.allowed_args_pattern:
            if not re.match(action.allowed_args_pattern, args_str):
                return ProxyResult(
                    success=False, action_name=action.name,
                    error=f"Args do not match allowed pattern: {action.allowed_args_pattern}",
                    execution_time_ms=_elapsed_ms(start),
                )

        # Reject shell metacharacters
        if _SHELL_METACHAR_RE.search(args_str):
            return ProxyResult(
                success=False, action_name=action.name,
                error="Args contain forbidden shell metacharacters",
                execution_time_ms=_elapsed_ms(start),
            )

        if not action.command_template:
            return ProxyResult(
                success=False, action_name=action.name,
                error="No command_template configured for this action",
                execution_time_ms=_elapsed_ms(start),
            )

        # Build command parts
        # Expand {args} in template
        cmd_str = action.command_template.replace("{args}", args_str)

        # Check if temp file injection is needed
        credential_file_path: str | None = None
        try:
            if "{credential_file}" in cmd_str:
                # Write credential to a temp file (mode 0600)
                fd, credential_file_path = tempfile.mkstemp(
                    prefix="cg_cred_", suffix=".tmp",
                )
                os.write(fd, credential.encode())
                os.close(fd)
                os.chmod(credential_file_path, 0o600)
                cmd_str = cmd_str.replace("{credential_file}", credential_file_path)

            # Split command into args for exec (no shell=True)
            cmd_parts = cmd_str.split()

            # Build environment
            env = os.environ.copy()
            if action.env_inject:
                env.update(action.env_inject)
            if action.credential_env_var:
                env[action.credential_env_var] = credential

            # Execute
            proc = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=action.timeout_seconds,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ProxyResult(
                    success=False, action_name=action.name,
                    error=f"Command timed out after {action.timeout_seconds}s (killed)",
                    execution_time_ms=_elapsed_ms(start),
                )

            # Decode and truncate output
            truncated = False
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            if len(stdout_str) > action.max_response_bytes:
                stdout_str = stdout_str[:action.max_response_bytes]
                truncated = True
            if len(stderr_str) > action.max_response_bytes:
                stderr_str = stderr_str[:action.max_response_bytes]
                truncated = True

            # Sanitize credential from output
            stdout_str = sanitize_output(stdout_str, credential)
            stderr_str = sanitize_output(stderr_str, credential)

            return ProxyResult(
                success=proc.returncode == 0,
                action_name=action.name,
                exit_code=proc.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                execution_time_ms=_elapsed_ms(start),
                truncated=truncated,
            )

        except Exception as e:
            return ProxyResult(
                success=False, action_name=action.name,
                error=f"Command execution failed: {e}",
                execution_time_ms=_elapsed_ms(start),
            )
        finally:
            # Always clean up credential temp file
            if credential_file_path:
                try:
                    os.unlink(credential_file_path)
                except OSError:
                    logger.warning(
                        "Failed to delete credential temp file: %s",
                        credential_file_path,
                    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def sanitize_output(output: str, credential: str) -> str:
    """Remove any occurrence of the credential from output.

    Also scrubs base64-encoded and URL-encoded versions.
    """
    if not credential or not output:
        return output

    # Raw credential
    output = output.replace(credential, "[REDACTED]")

    # Base64-encoded
    try:
        b64 = base64.b64encode(credential.encode()).decode()
        if b64 in output:
            output = output.replace(b64, "[REDACTED]")
    except Exception:
        pass

    # URL-encoded
    try:
        url_encoded = urllib.parse.quote(credential, safe="")
        if url_encoded != credential and url_encoded in output:
            output = output.replace(url_encoded, "[REDACTED]")
    except Exception:
        pass

    return output


def _validate_url_domain(expanded_url: str, template: str) -> bool:
    """Validate that the expanded URL's domain matches the template's domain.

    Prevents SSRF by ensuring the agent cannot redirect requests to arbitrary
    hosts through path traversal or template manipulation.
    """
    try:
        from urllib.parse import urlparse

        # Extract domain from template (strip template variables)
        # Replace {path} and similar with empty string for parsing
        clean_template = re.sub(r"\{[^}]+\}", "", template)
        template_parsed = urlparse(clean_template)
        expanded_parsed = urlparse(expanded_url)

        if not template_parsed.hostname or not expanded_parsed.hostname:
            return False

        # Scheme must match
        if template_parsed.scheme != expanded_parsed.scheme:
            return False

        # Host must match exactly
        if template_parsed.hostname != expanded_parsed.hostname:
            return False

        # Port must match (or both be default)
        if template_parsed.port != expanded_parsed.port:
            return False

        return True
    except Exception:
        return False
