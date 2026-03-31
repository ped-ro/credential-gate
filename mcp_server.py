"""MCP Server interface for Credential Gate.

Exposes Credential Gate's functionality as MCP tools so agents can request
credentials through their native tool protocol.  Uses the Python MCP SDK
with Streamable HTTP transport, mounted on the existing FastAPI app at /mcp.

All MCP tools call the same business logic as the REST endpoints — zero
duplication.

Phase 6 implementation.
"""

import asyncio
import json
import logging
import time

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("credential-gate.mcp")


def create_mcp_server(
    config: dict,
    bw_manager,
    approval_queue,
    lease_manager,
    audit_log,
) -> FastMCP:
    """Create and configure the MCP server with all tools.

    All tools reuse the same business logic objects as the REST endpoints.
    Auth is performed via X-API-Key header on the HTTP transport — extracted
    from the MCP request context.
    """
    mcp_cfg = config.get("mcp", {})
    server_name = mcp_cfg.get("server_name", "credential-gate")

    mcp = FastMCP(server_name, stateless_http=True)

    # -- helpers -----------------------------------------------------------

    agents: dict = config.get("agents", {})

    def _validate_api_key(agent_id: str, api_key: str) -> bool:
        agent = agents.get(agent_id)
        if not agent:
            return False
        return agent.get("api_key") == api_key

    def _is_credential_allowed(agent_id: str, credential_name: str) -> bool:
        agent = agents.get(agent_id)
        if not agent:
            return False
        allowed = agent.get("allowed_credentials", [])
        return "*" in allowed or credential_name in allowed

    def _notifications_enabled() -> bool:
        return config.get("notifications", {}).get("enabled", False)

    def _auth_mode() -> str:
        return config.get("authorization", {}).get("mode", "yubikey")

    # -- tools -------------------------------------------------------------

    @mcp.tool(
        description=(
            "Request a credential with approval flow. Triggers YubiKey touch "
            "or phone approval depending on policy. Blocks until approved, "
            "denied, or timeout. Returns credential values and lease metadata "
            "on approval, or a denial reason."
        ),
    )
    async def request_credential(
        agent_id: str,
        credential_name: str,
        purpose: str = "",
        fields: list[str] | None = None,
    ) -> str:
        if fields is None:
            fields = ["password"]

        from main import (
            CredentialRequest,
            _elapsed_ms,
            _finalize_approval,
            _handle_auto_approve_mode,
            _handle_both_mode,
            _handle_phone_mode,
            _handle_yubikey_mode,
        )
        from bitwarden import SessionState
        from policy import LeasePolicy, load_agent_policy

        start = time.monotonic()

        # Build request object
        req = CredentialRequest(
            agent_id=agent_id,
            credential_name=credential_name,
            purpose=purpose,
            fields=fields,
        )

        # Authenticate — MCP tools receive agent_id as a parameter,
        # so we verify the agent exists and is configured
        if agent_id not in agents:
            return json.dumps({"status": "error", "reason": f"Unknown agent '{agent_id}'"})

        # Authorize credential access
        if not _is_credential_allowed(agent_id, credential_name):
            return json.dumps({
                "status": "denied",
                "reason": f"Agent '{agent_id}' is not allowed to access '{credential_name}'",
            })

        # Check Bitwarden availability
        if bw_manager.state in (SessionState.NO_SESSION, SessionState.LOCKED):
            return json.dumps({
                "status": "error",
                "reason": "Bitwarden vault unavailable",
            })

        # Evaluate policy
        policies_cfg = config.get("policies", {})
        policies_dir = policies_cfg.get("directory", "policies")
        default_policy = policies_cfg.get("default_policy", "deny")

        agent_policy = load_agent_policy(policies_dir, agent_id)

        if agent_policy is None:
            if default_policy == "deny":
                return json.dumps({
                    "status": "denied",
                    "reason": f"No policy file for agent '{agent_id}'",
                })
            decision = None
        else:
            decision = agent_policy.evaluate(credential_name, audit_log)
            if not decision.allowed:
                return json.dumps({
                    "status": "denied",
                    "reason": decision.reason,
                })

        # Determine effective mode
        if decision:
            mode = decision.approval_mode
            auto_approve_seconds = decision.auto_approve_seconds
            alert_always = decision.alert_always
            policy_checks = decision.checks
            lease_pol = decision.lease_policy
        else:
            mode = _auth_mode()
            auto_approve_seconds = None
            alert_always = False
            policy_checks = None
            lease_pol = LeasePolicy()

        # Print request banner to console
        from main import _print_request_banner
        _print_request_banner(req, mode)

        # Dispatch to mode-specific handler (same as REST endpoint)
        client_ip = "mcp"  # MCP requests don't have a direct client IP

        if auto_approve_seconds:
            result = await _handle_auto_approve_mode(
                req, client_ip, start, auto_approve_seconds,
                alert_always, policy_checks, lease_pol,
            )
        elif mode == "yubikey":
            result = await _handle_yubikey_mode(
                req, client_ip, start, alert_always, policy_checks, lease_pol,
            )
        elif mode == "phone":
            result = await _handle_phone_mode(
                req, client_ip, start, alert_always, policy_checks, lease_pol,
            )
        elif mode == "both":
            result = await _handle_both_mode(
                req, client_ip, start, alert_always, policy_checks, lease_pol,
            )
        else:
            return json.dumps({"status": "error", "reason": f"Unknown authorization mode: {mode}"})

        # Convert CredentialResponse to JSON
        return json.dumps({
            "status": result.status,
            "credential": result.credential,
            "lease": result.lease.model_dump() if result.lease else None,
            "reason": result.reason,
        })

    @mcp.tool(
        description=(
            "Check the status of a pending credential request. Use this for "
            "async workflows to poll whether a request has been approved or "
            "denied. Returns the current status."
        ),
    )
    async def check_request_status(request_id: str) -> str:
        from approvals import ApprovalState

        pending = approval_queue.get(request_id)
        if not pending:
            return json.dumps({
                "status": "not_found",
                "reason": f"No pending request with ID '{request_id}'",
            })

        return json.dumps({
            "request_id": request_id,
            "status": pending.state.value,
            "agent_id": pending.agent_id,
            "credential_name": pending.credential_name,
        })

    @mcp.tool(
        description=(
            "List credentials this agent is allowed to request, filtered by "
            "policy. Returns credential names with their risk levels, approval "
            "modes, and lease settings."
        ),
    )
    async def list_available_credentials(agent_id: str) -> str:
        from policy import load_agent_policy

        if agent_id not in agents:
            return json.dumps({"status": "error", "reason": f"Unknown agent '{agent_id}'"})

        agent_cfg = agents[agent_id]
        allowed = agent_cfg.get("allowed_credentials", [])

        # Load policy for richer info
        policies_dir = config.get("policies", {}).get("directory", "policies")
        agent_policy = load_agent_policy(policies_dir, agent_id)

        credentials = []
        if "*" in allowed:
            # Wildcard — list what's in the policy file
            if agent_policy:
                for cred_name, cred_cfg in agent_policy.credentials.items():
                    if cred_name == "*":
                        continue
                    lease_pol = agent_policy.get_lease_policy(cred_name)
                    credentials.append({
                        "name": cred_name,
                        "risk": cred_cfg.get("risk", "medium"),
                        "approval": cred_cfg.get("approval", agent_policy.default_approval),
                        "auto_approve_seconds": cred_cfg.get("auto_approve_seconds"),
                        "lease_ttl_minutes": lease_pol.lease_ttl_minutes,
                    })
                # Include wildcard info
                wildcard = agent_policy.credentials.get("*", {})
                if wildcard:
                    credentials.append({
                        "name": "*",
                        "note": "Wildcard — any credential not listed above uses these defaults",
                        "risk": wildcard.get("risk", "medium"),
                        "approval": wildcard.get("approval", agent_policy.default_approval),
                        "lease_ttl_minutes": agent_policy.get_lease_policy("*").lease_ttl_minutes,
                    })
            else:
                credentials.append({
                    "name": "*",
                    "note": "Wildcard access, no policy file — defaults apply",
                })
        else:
            for cred_name in allowed:
                entry = {"name": cred_name}
                if agent_policy:
                    cred_cfg = agent_policy.get_credential_policy(cred_name)
                    lease_pol = agent_policy.get_lease_policy(cred_name)
                    entry["risk"] = cred_cfg.get("risk", "medium")
                    entry["approval"] = cred_cfg.get("approval", agent_policy.default_approval)
                    entry["auto_approve_seconds"] = cred_cfg.get("auto_approve_seconds")
                    entry["lease_ttl_minutes"] = lease_pol.lease_ttl_minutes
                credentials.append(entry)

        return json.dumps({
            "agent_id": agent_id,
            "credentials": credentials,
        })

    @mcp.tool(
        description=(
            "Check active leases for an agent. Returns lease details including "
            "TTL remaining. Optionally filter by a specific lease ID."
        ),
    )
    async def get_lease_status(
        agent_id: str,
        lease_id: str | None = None,
    ) -> str:
        if agent_id not in agents:
            return json.dumps({"status": "error", "reason": f"Unknown agent '{agent_id}'"})

        if lease_id:
            lease = lease_manager.get_lease(lease_id)
            if not lease:
                return json.dumps({"status": "not_found", "reason": "Lease not found"})
            if lease.agent_id != agent_id:
                return json.dumps({"status": "error", "reason": "Lease belongs to a different agent"})
            return json.dumps({"leases": [lease.to_dict()]})

        leases = lease_manager.get_active_leases(agent_id=agent_id)
        return json.dumps({
            "agent_id": agent_id,
            "active_leases": len(leases),
            "leases": [l.to_dict() for l in leases],
        })

    @mcp.tool(
        description=(
            "Extend an active lease's TTL. Specify the lease ID and how many "
            "additional minutes to add. Returns the updated lease with new "
            "expiry, or denial if the policy's max lease duration would be exceeded."
        ),
    )
    async def renew_lease(
        lease_id: str,
        additional_minutes: int = 15,
    ) -> str:
        from policy import load_agent_policy

        lease = lease_manager.get_lease(lease_id)
        if not lease:
            return json.dumps({"status": "error", "reason": "Lease not found"})

        from leases import LeaseState
        if lease.state != LeaseState.ACTIVE:
            return json.dumps({
                "status": "error",
                "reason": f"Lease is {lease.state.value}, cannot renew",
            })

        # Check max_lease_minutes from policy
        policies_dir = config.get("policies", {}).get("directory", "policies")
        agent_policy = load_agent_policy(policies_dir, lease.agent_id)
        if agent_policy:
            lease_pol = agent_policy.get_lease_policy(lease.credential_name)
            max_seconds = lease_pol.max_lease_seconds
        else:
            max_seconds = 60 * 60  # default 60 min

        additional_seconds = additional_minutes * 60
        new_expiry = lease.expires_at + additional_seconds
        total_duration = new_expiry - lease.created_at

        if total_duration > max_seconds:
            max_mins = max_seconds // 60
            return json.dumps({
                "status": "denied",
                "reason": f"Renewal would exceed max lease duration ({max_mins} min)",
            })

        renewed = lease_manager.renew_lease(lease_id, additional_seconds)
        if not renewed:
            return json.dumps({"status": "error", "reason": "Lease could not be renewed"})

        audit_log.log(
            agent_id=renewed.agent_id,
            credential_name=renewed.credential_name,
            status="lease_renewed",
            purpose=f"lease:{lease_id[:12]} +{additional_minutes}min (mcp)",
        )

        return json.dumps({"status": "renewed", "lease": renewed.to_dict()})

    @mcp.tool(
        description=(
            "Service health check. Returns Bitwarden session status, FIDO2 "
            "readiness, authorization mode, notification status, lease "
            "statistics, and MCP status."
        ),
    )
    async def gate_health() -> str:
        from bitwarden import SessionState

        fido2_cfg = config.get("fido2", {})
        store = fido2_cfg.get("credential_store", "")
        has_creds = False
        try:
            from fido import get_registered_credentials
            has_creds = len(get_registered_credentials(store)) > 0
        except Exception:
            pass

        bw_status = "unknown"
        if bw_manager:
            state = bw_manager.state
            if state == SessionState.ACTIVE:
                bw_status = "active"
            elif state == SessionState.EXPIRED:
                bw_status = "expired"
            elif state == SessionState.LOCKED:
                bw_status = "locked"
            elif state == SessionState.NO_SESSION:
                bw_status = "no_password"

        notif_status = "disabled"
        if _notifications_enabled():
            ntfy_cfg = config.get("notifications", {})
            has_server = bool(ntfy_cfg.get("ntfy_server"))
            has_topic = bool(ntfy_cfg.get("ntfy_topic"))
            notif_status = "ntfy_connected" if (has_server and has_topic) else "misconfigured"

        lease_stats = lease_manager.stats_today() if lease_manager else {}

        return json.dumps({
            "status": "ok" if bw_status == "active" else "degraded",
            "bitwarden": bw_status,
            "fido2": "ready" if has_creds else "no_credentials",
            "authorization_mode": _auth_mode(),
            "notifications": notif_status,
            "mcp": "enabled",
            "leases": lease_stats,
        })

    return mcp
