"""Credential Gate Service — FastAPI application.

Physical authorization gate: AI agents request credentials, and a
YubiKey touch, phone approval, or either-first-wins authorizes access.
The credential is fetched fresh from Bitwarden on every approved request.

Phase 5: Credential leases — every approved request creates a lease with
TTL, tracked in SQLite.  Leases can be renewed, revoked, and auto-expire.
Credentials with rotate_on_expire get new passwords in Bitwarden.

Phase 6: MCP server interface — agents can request credentials through
their native MCP tool protocol via Streamable HTTP at /mcp.

Phase 7: Execution proxy — agents describe actions and the gate executes
them with credentials injected.  The agent never sees raw credentials.

Phase 8: Observability — metrics collection, web dashboard, anomaly
detection, and daily digest notifications.

Phase 9: Secret discovery — scan codebases for hardcoded secrets,
vault them in Bitwarden, track credential ages, and one-click rotation.
"""

import logging
import threading
import time
from contextlib import asynccontextmanager
from fnmatch import fnmatch
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel

from approvals import ApprovalQueue, ApprovalState
from audit import AuditLog
from bitwarden import BitwardenError, BitwardenSessionManager, SessionState
from config import load_config
from fido import AssertionResult, assert_touch
from leases import LeaseManager, LeaseState, _ts_to_iso
from panic import PanicManager
from proxy import ProxyExecutor, ProxyResult, sanitize_output
from notifications import (
    send_anomaly_notification,
    send_approval_notification,
    send_approved_notification,
    send_auto_approve_notification,
    send_daily_digest_notification,
    send_identity_violation_notification,
    send_lease_expired_notification,
    send_lease_revoked_notification,
    send_revoke_all_notification,
    send_rotation_complete_notification,
    send_rotation_failed_notification,
    send_scan_complete_notification,
    send_timeout_notification,
    send_touch_notification,
    send_vault_complete_notification,
)
from policy import LeasePolicy, load_agent_policy

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("credential-gate")

# ---------------------------------------------------------------------------
# Config & shared state
# ---------------------------------------------------------------------------

cfg = load_config()
audit_log: AuditLog | None = None
bw: BitwardenSessionManager | None = None
approval_queue = ApprovalQueue()
lease_mgr: LeaseManager | None = None
proxy_exec: ProxyExecutor | None = None
_expiry_stop = threading.Event()  # signal the expiry daemon to stop
_start_time = time.time()  # service start time for uptime tracking

# Phase 8: Observability
metrics_collector = None  # type: ignore
digest_gen = None  # type: ignore
_last_anomalies: list[dict] = []  # most recent anomaly check results

# Phase 9: Discovery & Rotation
secret_scanner = None  # type: ignore
credential_rotator = None  # type: ignore
auto_vaulter = None  # type: ignore
_last_scan_findings: list = []  # in-memory only, cleared after 10 min
_last_scan_time: float = 0  # monotonic timestamp of last scan
_SCAN_CACHE_TTL = 600  # 10 minutes

# Phase 10: Emergency Kill + Hardened Identity
panic_mgr: PanicManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global audit_log, bw, lease_mgr
    audit_log = AuditLog(cfg["audit"]["db_path"])

    # Lease manager — store leases alongside audit DB
    lease_db_path = str(Path(cfg["audit"]["db_path"]).parent / "leases.db")
    lease_mgr = LeaseManager(lease_db_path)

    bw_cfg = cfg.get("bitwarden", {})
    bw = BitwardenSessionManager(
        cli_path=bw_cfg.get("cli_path"),
        session_timeout=bw_cfg.get("session_timeout_seconds", 300),
        refresh_minutes=bw_cfg.get("session_refresh_minutes", 10),
        keychain_service=bw_cfg.get("keychain_service", "credential-gate"),
        keychain_account=bw_cfg.get("keychain_account", "bitwarden"),
    )

    # Attempt to unlock via Keychain on startup
    state = bw.startup()
    if state == SessionState.ACTIVE:
        logger.info("Bitwarden session active (via Keychain)")
    elif state == SessionState.NO_SESSION:
        logger.warning(
            "No Bitwarden password in Keychain — running in degraded mode. "
            "Run: python setup.py store-password"
        )
    else:
        logger.warning("Bitwarden session state: %s", state.value)

    # Start the lease expiry daemon
    _expiry_stop.clear()
    expiry_thread = threading.Thread(target=_lease_expiry_daemon, daemon=True)
    expiry_thread.start()

    # Initialize proxy executor
    global proxy_exec
    proxy_exec = ProxyExecutor(cfg)
    if proxy_exec.enabled:
        logger.info("Proxy executor enabled with %d action(s)", len(proxy_exec.list_actions()))

    # Initialize observability (Phase 8)
    global metrics_collector, digest_gen
    obs_cfg = cfg.get("observability", {})
    if obs_cfg.get("enabled", False):
        from metrics import MetricsCollector
        from digest import DigestGenerator

        metrics_collector = MetricsCollector(
            audit_db_path=cfg["audit"]["db_path"],
            lease_db_path=str(Path(cfg["audit"]["db_path"]).parent / "leases.db"),
        )

        digest_gen = DigestGenerator(metrics_collector, cfg)
        logger.info("Observability enabled (metrics, dashboard, anomaly detection)")

        # Start daily digest scheduler
        digest_cfg = obs_cfg.get("daily_digest", {})
        if digest_cfg.get("enabled", False):
            _start_digest_scheduler(digest_cfg.get("time", "23:00"))
    else:
        logger.info("Observability disabled (set observability.enabled: true to enable)")

    # Initialize panic manager (Phase 10)
    global panic_mgr
    data_dir = str(Path(cfg["audit"]["db_path"]).parent)
    panic_mgr = PanicManager(
        lease_manager=lease_mgr,
        bitwarden=bw,
        notifier_config=cfg,
        audit=audit_log,
        data_dir=data_dir,
    )
    panic_cfg = cfg.get("panic", {})
    cooldown = panic_cfg.get("cooldown_after_unlock_seconds", 60)
    panic_mgr.set_cooldown(cooldown)
    if panic_mgr.is_locked:
        logger.critical("SERVICE STARTING IN LOCKED MODE — gate is LOCKED")

    # Initialize discovery & rotation (Phase 9)
    global secret_scanner, credential_rotator, auto_vaulter
    disc_cfg = cfg.get("discovery", {})
    rot_cfg = cfg.get("rotation", {})
    if disc_cfg.get("enabled", False):
        from discovery import SecretScanner
        secret_scanner = SecretScanner(cfg)
        logger.info("Secret scanner enabled")
    if rot_cfg.get("enabled", False):
        from rotation import CredentialRotator
        credential_rotator = CredentialRotator(bw, cfg)
        logger.info("Credential rotator enabled")
    if disc_cfg.get("enabled", False) or rot_cfg.get("enabled", False):
        from vaulting import AutoVaulter
        auto_vaulter = AutoVaulter(bw)
        logger.info("Auto-vaulter enabled")

    # Mount MCP server if enabled
    mcp_cfg = cfg.get("mcp", {})
    if mcp_cfg.get("enabled", False):
        from mcp_server import create_mcp_server

        mcp_srv = create_mcp_server(
            config=cfg,
            bw_manager=bw,
            approval_queue=approval_queue,
            lease_manager=lease_mgr,
            audit_log=audit_log,
            proxy_executor=proxy_exec,
            metrics_collector=metrics_collector,
            secret_scanner=secret_scanner,
            credential_rotator=credential_rotator,
            auto_vaulter=auto_vaulter,
            panic_manager=panic_mgr,
        )
        mcp_app = mcp_srv.streamable_http_app()
        mcp_path = mcp_cfg.get("path", "/mcp")
        app.mount(mcp_path, mcp_app)

        # Start the MCP session manager
        _mcp_session_ctx = mcp_srv.session_manager.run()
        await _mcp_session_ctx.__aenter__()
        app.state.mcp_session_ctx = _mcp_session_ctx

        logger.info("MCP server mounted at %s", mcp_path)

    mode = cfg.get("authorization", {}).get("mode", "yubikey")
    logger.info(
        "Credential Gate started on %s:%s (mode=%s)",
        cfg["server"]["host"],
        cfg["server"]["port"],
        mode,
    )
    yield

    # Shutdown MCP session manager
    if hasattr(app.state, "mcp_session_ctx"):
        await app.state.mcp_session_ctx.__aexit__(None, None, None)

    _expiry_stop.set()
    if metrics_collector:
        metrics_collector.close()
    bw.shutdown()
    lease_mgr.close()
    audit_log.close()
    logger.info("Credential Gate stopped")


app = FastAPI(title="Credential Gate", lifespan=lifespan)

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

_agents: dict = cfg.get("agents", {})


def _validate_api_key(agent_id: str, api_key: str) -> bool:
    agent = _agents.get(agent_id)
    if not agent:
        return False
    return agent.get("api_key") == api_key


def _is_credential_allowed(agent_id: str, credential_name: str) -> bool:
    agent = _agents.get(agent_id)
    if not agent:
        return False
    allowed = agent.get("allowed_credentials", [])
    return "*" in allowed or credential_name in allowed


def _notifications_enabled() -> bool:
    return cfg.get("notifications", {}).get("enabled", False)


def _auth_mode() -> str:
    return cfg.get("authorization", {}).get("mode", "yubikey")


def _validate_agent_identity(request: Request, agent_id: str) -> None:
    """Additional identity checks beyond API key (Phase 10).

    Checks source IP against allowed_source_ips in the agent's policy file.
    Logs a warning if User-Agent doesn't match allowed_user_agents.

    Raises HTTPException(403) if source IP is not in the allowlist.
    """
    policies_dir = cfg.get("policies", {}).get("directory", "policies")
    agent_policy = load_agent_policy(policies_dir, agent_id)
    if not agent_policy:
        return

    # Read identity config from the raw policy data
    policy_path = Path(policies_dir) / f"{agent_id}.yaml"
    identity = {}
    if policy_path.exists():
        import yaml
        try:
            with open(policy_path) as f:
                raw = yaml.safe_load(f) or {}
            identity = raw.get("identity", {})
        except Exception:
            pass

    if not identity:
        return

    client_ip = request.client.host if request.client else "unknown"

    # Check source IP
    allowed_ips = identity.get("allowed_source_ips")
    if allowed_ips:
        if client_ip not in allowed_ips:
            violation = f"Request from unauthorized IP {client_ip}"
            logger.warning("Identity violation for %s: %s", agent_id, violation)

            if _notifications_enabled():
                send_identity_violation_notification(
                    agent_id=agent_id,
                    violation=violation,
                    source_ip=client_ip,
                    config=cfg,
                )

            audit_log.log(
                agent_id=agent_id,
                credential_name="identity_check",
                status="denied",
                purpose=f"identity_violation: {violation}",
                ip_address=client_ip,
            )

            raise HTTPException(
                status_code=403,
                detail=f"Request from unauthorized IP {client_ip} for agent {agent_id}",
            )

    # Check User-Agent (non-blocking — log warning only)
    allowed_uas = identity.get("allowed_user_agents")
    if allowed_uas:
        ua = request.headers.get("user-agent", "")
        if not any(fnmatch(ua, pattern) for pattern in allowed_uas):
            logger.warning(
                "Unexpected User-Agent for %s: %s (expected one of %s)",
                agent_id, ua, allowed_uas,
            )


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class CredentialRequest(BaseModel):
    agent_id: str
    credential_name: str
    purpose: str = ""
    fields: list[str] = ["password"]


class LeaseInfo(BaseModel):
    lease_id: str
    expires_at: str
    ttl_seconds: int
    renewable: bool

class CredentialResponse(BaseModel):
    status: str
    credential: dict | None = None
    lease: LeaseInfo | None = None
    reason: str | None = None


# ---------------------------------------------------------------------------
# /approve and /deny callback endpoints (unauthenticated — security from
# unguessable request_id tokens)
# ---------------------------------------------------------------------------

@app.post("/approve/{request_id}")
async def approve_request(request_id: str):
    """Called by Ntfy action button when the user taps Approve."""
    found = approval_queue.approve(request_id)
    if found:
        logger.info("Phone approval callback for %s", request_id[:12])
        return {"status": "Approved"}
    # Don't error — Ntfy retries on errors
    logger.warning("Approve callback for unknown/handled request %s", request_id[:12])
    return {"status": "Already handled"}


@app.post("/deny/{request_id}")
async def deny_request(request_id: str):
    """Called by Ntfy action button when the user taps Deny."""
    found = approval_queue.deny(request_id)
    if found:
        logger.info("Phone denial callback for %s", request_id[:12])
        return {"status": "Denied"}
    logger.warning("Deny callback for unknown/handled request %s", request_id[:12])
    return {"status": "Already handled"}


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    fido2_cfg = cfg.get("fido2", {})
    store = fido2_cfg.get("credential_store", "")
    has_creds = False
    try:
        from fido import get_registered_credentials
        has_creds = len(get_registered_credentials(store)) > 0
    except Exception:
        pass

    # Bitwarden session status
    bw_status = "unknown"
    if bw:
        state = bw.state
        if state == SessionState.ACTIVE:
            bw_status = "active"
        elif state == SessionState.EXPIRED:
            bw_status = "expired"
        elif state == SessionState.LOCKED:
            bw_status = "locked"
        elif state == SessionState.NO_SESSION:
            bw_status = "no_password"

    # Notifications / Ntfy status
    notif_status = "disabled"
    if _notifications_enabled():
        ntfy_cfg = cfg.get("notifications", {})
        has_server = bool(ntfy_cfg.get("ntfy_server"))
        has_topic = bool(ntfy_cfg.get("ntfy_topic"))
        notif_status = "ntfy_connected" if (has_server and has_topic) else "misconfigured"

    # Lease stats
    lease_stats = lease_mgr.stats_today() if lease_mgr else {}

    # MCP status
    mcp_cfg = cfg.get("mcp", {})
    mcp_status = "enabled" if mcp_cfg.get("enabled", False) else "disabled"

    # Proxy status
    proxy_status = "disabled"
    proxy_action_count = 0
    if proxy_exec and proxy_exec.enabled:
        proxy_status = "enabled"
        proxy_action_count = len(proxy_exec.list_actions())

    # Observability status
    obs_cfg = cfg.get("observability", {})
    obs_status = "enabled" if obs_cfg.get("enabled", False) and metrics_collector else "disabled"

    # Discovery & Rotation status (Phase 9)
    disc_cfg = cfg.get("discovery", {})
    rot_cfg = cfg.get("rotation", {})
    discovery_status = "enabled" if disc_cfg.get("enabled", False) and secret_scanner else "disabled"
    rotation_status = "enabled" if rot_cfg.get("enabled", False) and credential_rotator else "disabled"

    # Panic / lock status (Phase 10)
    lock_status = panic_mgr.get_status() if panic_mgr else {"locked": False}
    is_locked = lock_status.get("locked", False)

    # Overall status: locked overrides everything
    if is_locked:
        overall_status = "locked"
    elif bw_status == "active":
        overall_status = "ok"
    else:
        overall_status = "degraded"

    return {
        "status": overall_status,
        "bitwarden": bw_status,
        "fido2": "ready" if has_creds else "no_credentials",
        "authorization_mode": _auth_mode(),
        "notifications": notif_status,
        "mcp": mcp_status,
        "proxy": proxy_status,
        "proxy_actions": proxy_action_count,
        "leases": lease_stats,
        "observability": obs_status,
        "discovery": discovery_status,
        "rotation": rotation_status,
        "panic": lock_status,
    }


# ---------------------------------------------------------------------------
# Audit endpoint
# ---------------------------------------------------------------------------

@app.get("/audit")
async def get_audit(
    x_api_key: str = Header(..., alias="X-API-Key"),
    limit: int = 50,
):
    # Any valid agent key can read audit log
    valid = any(
        agent.get("api_key") == x_api_key for agent in _agents.values()
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return audit_log.recent(limit)


# ---------------------------------------------------------------------------
# Observability endpoints (Phase 8)
# ---------------------------------------------------------------------------

@app.get("/stats")
async def get_stats(hours: int = Query(24, ge=1, le=720)):
    """Return aggregate metrics for the given time window."""
    if not metrics_collector:
        raise HTTPException(status_code=404, detail="Observability not enabled")

    stats = metrics_collector.get_stats(hours=hours)

    # Include current anomalies
    obs_cfg = cfg.get("observability", {})
    thresholds = obs_cfg.get("anomaly_thresholds", {})
    if thresholds:
        stats["anomalies"] = metrics_collector.check_anomalies(thresholds)
    else:
        stats["anomalies"] = []

    return stats


@app.get("/stats/{agent_id}")
async def get_agent_stats(agent_id: str, hours: int = Query(24, ge=1, le=720)):
    """Return agent-specific activity metrics."""
    if not metrics_collector:
        raise HTTPException(status_code=404, detail="Observability not enabled")
    return metrics_collector.get_agent_activity(agent_id, hours=hours)


@app.get("/dashboard")
async def get_dashboard():
    """Serve the observability dashboard HTML page."""
    obs_cfg = cfg.get("observability", {})
    if not obs_cfg.get("enabled", False):
        raise HTTPException(status_code=404, detail="Dashboard not enabled")

    from dashboard import get_dashboard_html
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=get_dashboard_html())


@app.get("/events")
async def get_events(
    limit: int = Query(50, ge=1, le=500),
    agent_id: str | None = Query(None),
):
    """Return recent audit events for dashboard polling."""
    if not metrics_collector:
        raise HTTPException(status_code=404, detail="Observability not enabled")
    return metrics_collector.get_recent_events(limit=limit, agent_id=agent_id)


@app.get("/leases/active")
async def get_active_leases_unauthenticated():
    """Return active leases for the dashboard (localhost-only, no auth).

    This is safe because the service only binds to 127.0.0.1.
    """
    if not lease_mgr:
        return []
    leases = lease_mgr.get_active_leases()
    return [l.to_dict() for l in leases]


class DashboardRevokeRequest(BaseModel):
    reason: str = "dashboard revoke"


@app.post("/dashboard/revoke/{lease_id}")
async def dashboard_revoke_lease(lease_id: str, body: DashboardRevokeRequest | None = None):
    """Revoke a lease from the dashboard (localhost-only, no API key).

    This is safe because the service only binds to 127.0.0.1.
    Similar to /approve and /deny callbacks which are also unauthenticated.
    """
    if not lease_mgr:
        raise HTTPException(status_code=503, detail="Lease manager not available")

    lease = lease_mgr.get_lease(lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail="Lease not found")

    reason = body.reason if body else "dashboard revoke"
    revoked = lease_mgr.revoke_lease(lease_id, reason=reason)
    if not revoked:
        raise HTTPException(status_code=409, detail=f"Lease is not active (state: {lease.state.value})")

    audit_log.log(
        agent_id=lease.agent_id,
        credential_name=lease.credential_name,
        status="lease_revoked",
        purpose=f"lease:{lease_id[:12]} reason:{reason}",
    )

    if _notifications_enabled():
        send_lease_revoked_notification(
            config=cfg,
            agent_id=lease.agent_id,
            credential_name=lease.credential_name,
            lease_id=lease.lease_id,
            reason=reason,
        )

    return {"status": "revoked", "lease_id": lease_id}


# ---------------------------------------------------------------------------
# Panic / Lock endpoints (Phase 10)
# ---------------------------------------------------------------------------

class PanicRequest(BaseModel):
    reason: str
    rotate_credentials: bool = False
    agent_filter: str | None = None


@app.post("/panic")
async def trigger_panic(req: PanicRequest, request: Request):
    """Emergency lockdown. Revokes all leases and blocks all credential access.

    Requires YubiKey ONLY — no phone approval for panic (phone could be
    compromised). Overrides any policy — panic always works regardless of
    schedule, rate limits, etc.
    """
    if not panic_mgr:
        raise HTTPException(status_code=503, detail="Panic manager not initialized")

    logger.critical("PANIC requested: %s", req.reason)
    print(
        f"\n{'='*60}\n"
        f"  EMERGENCY LOCKDOWN REQUEST\n"
        f"  Reason:           {req.reason}\n"
        f"  Rotate creds:     {req.rotate_credentials}\n"
        f"  Agent filter:     {req.agent_filter or 'ALL'}\n"
        f"{'='*60}\n"
        f"  >>> Touch your YubiKey to LOCK THE GATE\n"
    )

    result = _run_fido2_assertion()
    if not result.success:
        audit_log.log(
            agent_id="admin",
            credential_name="*",
            status="denied",
            purpose=f"panic_attempt: {req.reason}",
        )
        raise HTTPException(status_code=403, detail=f"YubiKey assertion failed: {result.error}")

    summary = await panic_mgr.panic(
        reason=req.reason,
        rotate_credentials=req.rotate_credentials,
        agent_filter=req.agent_filter,
    )
    return summary


class UnlockRequest(BaseModel):
    reason: str


@app.post("/unlock")
async def unlock_gate(req: UnlockRequest, request: Request):
    """Unlock the gate after a panic lockdown.

    Requires YubiKey ONLY. Cannot be done via phone.
    """
    if not panic_mgr:
        raise HTTPException(status_code=503, detail="Panic manager not initialized")

    if not panic_mgr.is_locked:
        return {"status": "already_unlocked", "message": "Gate is not locked"}

    logger.info("Unlock requested: %s", req.reason)
    print(
        f"\n{'='*60}\n"
        f"  GATE UNLOCK REQUEST\n"
        f"  Reason: {req.reason}\n"
        f"{'='*60}\n"
        f"  >>> Touch your YubiKey to UNLOCK\n"
    )

    result = _run_fido2_assertion()
    if not result.success:
        audit_log.log(
            agent_id="admin",
            credential_name="*",
            status="denied",
            purpose=f"unlock_attempt: {req.reason}",
        )
        raise HTTPException(status_code=403, detail=f"YubiKey assertion failed: {result.error}")

    summary = await panic_mgr.unlock(reason=req.reason)
    return summary


@app.get("/lock-status")
async def get_lock_status():
    """Return current lock state. No auth required.

    Agents need to know why they're being rejected.
    """
    if not panic_mgr:
        return {"locked": False}
    return panic_mgr.get_status()


# ---------------------------------------------------------------------------
# Discovery & Rotation endpoints (Phase 9)
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    path: str
    recursive: bool = True
    severity_filter: str = "medium"


class ScanResponse(BaseModel):
    files_scanned: int
    findings_count: int
    by_severity: dict
    findings: list[dict]


@app.post("/scan", response_model=ScanResponse)
async def scan_for_secrets(req: ScanRequest, request: Request):
    """Scan a directory for hardcoded secrets.

    Requires YubiKey approval (scan results are sensitive).
    The response NEVER includes raw secret values — only masked versions.
    """
    global _last_scan_findings, _last_scan_time

    if not secret_scanner:
        raise HTTPException(status_code=404, detail="Discovery not enabled")

    # Always require YubiKey for scans
    logger.info("Secret scan requested for '%s' — awaiting YubiKey touch", req.path)
    print(
        f"\n{'='*60}\n"
        f"  SECRET SCAN REQUEST\n"
        f"  Path:      {req.path}\n"
        f"  Recursive: {req.recursive}\n"
        f"{'='*60}\n"
        f"  >>> Touch your YubiKey to approve\n"
    )

    result = _run_fido2_assertion()
    if not result.success:
        audit_log.log(
            agent_id="admin",
            credential_name="secret_scan",
            status="denied",
            purpose=f"scan:{req.path}",
        )
        raise HTTPException(status_code=403, detail=f"YubiKey assertion failed: {result.error}")

    # Run the scan
    findings, files_scanned = secret_scanner.scan_directory(
        req.path,
        recursive=req.recursive,
        severity_filter=req.severity_filter,
    )

    # Cache findings in memory (for vault-finding/vault-batch)
    _last_scan_findings = findings
    _last_scan_time = time.monotonic()

    report = secret_scanner.generate_report(findings, req.path, files_scanned)

    # Audit
    audit_log.log(
        agent_id="admin",
        credential_name="secret_scan",
        status="scan_completed",
        purpose=f"scan:{req.path} findings:{len(findings)}",
    )

    if _notifications_enabled():
        send_scan_complete_notification(
            config=cfg,
            scan_path=req.path,
            total_findings=len(findings),
            by_severity=report.get("by_severity", {}),
        )

    logger.info("Scan complete: %d files scanned, %d findings", files_scanned, len(findings))

    return ScanResponse(
        files_scanned=files_scanned,
        findings_count=len(findings),
        by_severity=report.get("by_severity", {}),
        findings=report.get("findings", []),
    )


class VaultRequest(BaseModel):
    finding_index: int
    collection_id: str | None = None
    custom_name: str | None = None


@app.post("/vault-finding")
async def vault_finding(req: VaultRequest, request: Request):
    """Vault a specific finding from the most recent scan.

    Requires YubiKey or phone approval.
    """
    if not auto_vaulter:
        raise HTTPException(status_code=404, detail="Discovery not enabled")

    # Check scan cache validity
    if not _last_scan_findings or (time.monotonic() - _last_scan_time > _SCAN_CACHE_TTL):
        raise HTTPException(
            status_code=409,
            detail="No recent scan results. Run POST /scan first.",
        )

    if req.finding_index < 0 or req.finding_index >= len(_last_scan_findings):
        raise HTTPException(
            status_code=400,
            detail=f"finding_index {req.finding_index} out of range (0-{len(_last_scan_findings) - 1})",
        )

    # Require approval
    mode = _auth_mode()
    logger.info("Vault-finding requested — awaiting approval (mode=%s)", mode)
    print(
        f"\n{'='*60}\n"
        f"  VAULT FINDING\n"
        f"  Finding:   #{req.finding_index}\n"
        f"  Mode:      {mode}\n"
        f"{'='*60}\n"
        f"  >>> Touch your YubiKey to approve\n"
    )

    result = _run_fido2_assertion()
    if not result.success:
        raise HTTPException(status_code=403, detail=f"YubiKey assertion failed: {result.error}")

    finding = _last_scan_findings[req.finding_index]
    vault_result = await auto_vaulter.vault_finding(
        finding,
        collection_id=req.collection_id,
        custom_name=req.custom_name,
    )

    # Generate replacement instructions
    item_name = req.custom_name or finding.suggested_bw_name
    from vaulting import AutoVaulter
    vault_result["replacement_instructions"] = AutoVaulter.generate_replacement_instructions(
        finding, item_name,
    )

    audit_log.log(
        agent_id="admin",
        credential_name="vault_finding",
        status="vault_" + vault_result.get("status", "unknown"),
        purpose=f"vault:{item_name} from {finding.file_path}:{finding.line_number}",
    )

    return vault_result


class VaultBatchRequest(BaseModel):
    severity_filter: str = "high"
    collection_id: str | None = None


@app.post("/vault-batch")
async def vault_batch(req: VaultBatchRequest, request: Request):
    """Vault all findings from the last scan above a severity threshold.

    Requires YubiKey approval (batch operation on secrets).
    """
    if not auto_vaulter:
        raise HTTPException(status_code=404, detail="Discovery not enabled")

    # Check scan cache
    if not _last_scan_findings or (time.monotonic() - _last_scan_time > _SCAN_CACHE_TTL):
        raise HTTPException(
            status_code=409,
            detail="No recent scan results. Run POST /scan first.",
        )

    severity_order = {"critical": 3, "high": 2, "medium": 1}
    min_severity = severity_order.get(req.severity_filter, 2)
    eligible = [
        f for f in _last_scan_findings
        if severity_order.get(f.severity, 0) >= min_severity
    ]

    if not eligible:
        return {"total": 0, "created": 0, "skipped": 0, "failed": 0, "results": []}

    # YubiKey required for batch operations
    logger.info("Vault-batch requested (%d findings) — awaiting YubiKey touch", len(eligible))
    print(
        f"\n{'='*60}\n"
        f"  VAULT BATCH\n"
        f"  Findings:  {len(eligible)} (>= {req.severity_filter})\n"
        f"{'='*60}\n"
        f"  >>> Touch your YubiKey to approve\n"
    )

    result = _run_fido2_assertion()
    if not result.success:
        raise HTTPException(status_code=403, detail=f"YubiKey assertion failed: {result.error}")

    batch_result = await auto_vaulter.vault_batch(eligible, collection_id=req.collection_id)

    audit_log.log(
        agent_id="admin",
        credential_name="vault_batch",
        status="vault_batch_completed",
        purpose=f"vault_batch: {batch_result['created']} created, {batch_result['skipped']} skipped, {batch_result['failed']} failed",
    )

    if _notifications_enabled():
        from notifications import send_vault_complete_notification
        send_vault_complete_notification(
            config=cfg,
            created=batch_result["created"],
            skipped=batch_result["skipped"],
            failed=batch_result["failed"],
        )

    return batch_result


@app.get("/credential-ages")
async def get_credential_ages():
    """Return age information for all managed credentials.

    No approval needed — no secrets are exposed.
    """
    if not credential_rotator:
        raise HTTPException(status_code=404, detail="Rotation not enabled")

    return credential_rotator.get_all_credential_ages()


@app.post("/rotate/{credential_name}")
async def rotate_credential(credential_name: str, request: Request):
    """Trigger rotation for a specific credential.

    Requires YubiKey approval.
    """
    if not credential_rotator:
        raise HTTPException(status_code=404, detail="Rotation not enabled")

    # Determine credential type from pattern (best guess from name)
    credential_type = _guess_credential_type(credential_name)

    logger.info("Rotation requested for '%s' (type=%s) — awaiting YubiKey touch", credential_name, credential_type)
    print(
        f"\n{'='*60}\n"
        f"  CREDENTIAL ROTATION\n"
        f"  Credential: {credential_name}\n"
        f"  Type:       {credential_type}\n"
        f"{'='*60}\n"
        f"  >>> Touch your YubiKey to approve\n"
    )

    result = _run_fido2_assertion()
    if not result.success:
        audit_log.log(
            agent_id="admin",
            credential_name=credential_name,
            status="denied",
            purpose=f"rotate:{credential_name}",
        )
        raise HTTPException(status_code=403, detail=f"YubiKey assertion failed: {result.error}")

    rotation_result = await credential_rotator.rotate(credential_name, credential_type)

    audit_log.log(
        agent_id="admin",
        credential_name=credential_name,
        status="rotation_completed" if rotation_result.success else "rotation_failed",
        purpose=f"rotate:{credential_name} type:{rotation_result.rotation_type}",
    )

    if _notifications_enabled():
        send_rotation_complete_notification(
            config=cfg,
            credential_name=credential_name,
            rotation_type=rotation_result.rotation_type,
            success=rotation_result.success,
            message_text=rotation_result.message,
        )

    return {
        "success": rotation_result.success,
        "credential_name": rotation_result.credential_name,
        "rotation_type": rotation_result.rotation_type,
        "message": rotation_result.message,
        "old_invalidated": rotation_result.old_invalidated,
        "bw_updated": rotation_result.bw_updated,
        "instructions": rotation_result.instructions,
        "error": rotation_result.error,
    }


def _guess_credential_type(credential_name: str) -> str:
    """Guess the credential type from its name for rotation dispatch."""
    name_lower = credential_name.lower()
    if "github" in name_lower:
        return "github_pat"
    if "cloudflare" in name_lower or "cf-" in name_lower:
        return "cloudflare_api_token"
    if "slack" in name_lower:
        return "slack_token"
    if "aws" in name_lower:
        return "aws_access_key"
    return "unknown"


# ---------------------------------------------------------------------------
# Lease expiry daemon (background thread, runs every 30s)
# ---------------------------------------------------------------------------

def _lease_expiry_daemon():
    """Background thread that checks for expired leases every 30 seconds.

    For leases with rotate_on_expire, rotates the credential in Bitwarden.
    """
    logger.info("Lease expiry daemon started")
    while not _expiry_stop.is_set():
        try:
            expired = lease_mgr.check_expired()
            for lease in expired:
                rotated = False
                # Check if this credential has rotate_on_expire
                should_rotate = _should_rotate(lease.agent_id, lease.credential_name)

                if should_rotate and bw and bw.state == SessionState.ACTIVE:
                    try:
                        bw.rotate_credential(lease.credential_name)
                        rotated = True
                        logger.info(
                            "Rotated credential '%s' after lease %s expired",
                            lease.credential_name, lease.lease_id[:12],
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to rotate '%s' after lease expiry: %s",
                            lease.credential_name, e,
                        )
                        if _notifications_enabled():
                            send_rotation_failed_notification(
                                config=cfg,
                                credential_name=lease.credential_name,
                                error=str(e),
                            )

                if _notifications_enabled():
                    send_lease_expired_notification(
                        config=cfg,
                        agent_id=lease.agent_id,
                        credential_name=lease.credential_name,
                        lease_id=lease.lease_id,
                        rotated=rotated,
                    )

                # Log lease expiry to audit
                audit_log.log(
                    agent_id=lease.agent_id,
                    credential_name=lease.credential_name,
                    status="lease_expired",
                    fields_requested=lease.fields,
                    purpose=f"lease:{lease.lease_id[:12]}"
                           + (" (rotated)" if rotated else ""),
                )
        except Exception as e:
            logger.error("Lease expiry daemon error: %s", e)

        # Phase 8: Anomaly detection (piggybacks on expiry daemon cycle)
        try:
            _run_anomaly_check()
        except Exception as e:
            logger.error("Anomaly check error: %s", e)

        _expiry_stop.wait(30)
    logger.info("Lease expiry daemon stopped")


def _should_rotate(agent_id: str, credential_name: str) -> bool:
    """Check if the credential policy has rotate_on_expire enabled."""
    policies_dir = cfg.get("policies", {}).get("directory", "policies")
    agent_policy = load_agent_policy(policies_dir, agent_id)
    if not agent_policy:
        return False
    lease_policy = agent_policy.get_lease_policy(credential_name)
    return lease_policy.rotate_on_expire


def _run_anomaly_check():
    """Check for anomalies using the metrics collector.

    Called from the expiry daemon loop. Sends Ntfy notification if new
    anomalies are detected.

    Phase 10: Also checks auto-panic triggers and locks the gate if
    critical thresholds are exceeded.
    """
    global _last_anomalies

    if not metrics_collector:
        return

    obs_cfg = cfg.get("observability", {})
    if not obs_cfg.get("enabled", False):
        return

    thresholds = obs_cfg.get("anomaly_thresholds", {})
    if not thresholds:
        return

    anomalies = metrics_collector.check_anomalies(thresholds)

    if anomalies and anomalies != _last_anomalies:
        logger.warning("Anomalies detected: %d", len(anomalies))
        for a in anomalies:
            logger.warning(
                "  %s: %s %s = %s (threshold: %s)",
                a["severity"], a["agent_id"], a["metric"],
                a["value"], a["threshold"],
            )
        if _notifications_enabled():
            send_anomaly_notification(anomalies, cfg)

    _last_anomalies = anomalies

    # Phase 10: Auto-panic triggers
    _check_auto_panic_triggers(anomalies)


def _check_auto_panic_triggers(anomalies: list[dict]):
    """Evaluate auto-panic triggers from config. Locks the gate if critical
    thresholds are exceeded.

    Called from the anomaly check loop (background thread).
    """
    if not panic_mgr or panic_mgr.is_locked:
        return

    panic_cfg = cfg.get("panic", {})
    if not panic_cfg.get("enabled", True):
        return

    auto_triggers = panic_cfg.get("auto_triggers", {})
    if not auto_triggers:
        return

    # Check requests_per_minute_critical
    rpm_critical = auto_triggers.get("requests_per_minute_critical")
    if rpm_critical and metrics_collector:
        one_min_ago = metrics_collector._cutoff_iso_from_epoch(time.time() - 60)
        total = metrics_collector._count(
            metrics_collector._audit_conn,
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?",
            (one_min_ago,),
        )
        if total >= rpm_critical:
            import asyncio
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(
                    panic_mgr.auto_panic(
                        f"Request rate critical: {total} requests/min (threshold: {rpm_critical})"
                    )
                )
                loop.close()
            except Exception as e:
                logger.error("Auto-panic (rpm) failed: %s", e)
            return  # already locked

    # Check denials_per_minute_critical
    dpm_critical = auto_triggers.get("denials_per_minute_critical")
    if dpm_critical and metrics_collector:
        one_min_ago = metrics_collector._cutoff_iso_from_epoch(time.time() - 60)
        denials = metrics_collector._count(
            metrics_collector._audit_conn,
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND status = 'denied'",
            (one_min_ago,),
        )
        if denials >= dpm_critical:
            import asyncio
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(
                    panic_mgr.auto_panic(
                        f"Denial rate critical: {denials} denials/min (threshold: {dpm_critical})"
                    )
                )
                loop.close()
            except Exception as e:
                logger.error("Auto-panic (dpm) failed: %s", e)
            return

    # Check unknown_agent_lockdown
    if auto_triggers.get("unknown_agent_lockdown", False) and metrics_collector:
        one_min_ago = metrics_collector._cutoff_iso_from_epoch(time.time() - 60)
        rows = metrics_collector._audit_conn.execute(
            "SELECT DISTINCT agent_id FROM audit_log WHERE timestamp >= ?",
            (one_min_ago,),
        ).fetchall()
        known_agents = set(_agents.keys())
        for row in rows:
            agent_id = row[0]
            if agent_id not in known_agents and agent_id != "admin":
                import asyncio
                try:
                    loop = asyncio.new_event_loop()
                    loop.run_until_complete(
                        panic_mgr.auto_panic(
                            f"Unknown agent detected: '{agent_id}'"
                        )
                    )
                    loop.close()
                except Exception as e:
                    logger.error("Auto-panic (unknown agent) failed: %s", e)
                return


# ---------------------------------------------------------------------------
# Daily digest scheduler (Phase 8)
# ---------------------------------------------------------------------------

_digest_timer: threading.Timer | None = None


def _start_digest_scheduler(time_str: str):
    """Schedule the daily digest to run at the configured time.

    Uses a threading.Timer that reschedules itself after each run.
    """
    global _digest_timer

    try:
        hour, minute = map(int, time_str.split(":"))
    except (ValueError, AttributeError):
        logger.warning("Invalid digest time '%s', defaulting to 23:00", time_str)
        hour, minute = 23, 0

    def _schedule_next():
        import datetime as dt

        now = dt.datetime.now()
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= now:
            target += dt.timedelta(days=1)
        delay = (target - now).total_seconds()

        global _digest_timer
        _digest_timer = threading.Timer(delay, _run_digest)
        _digest_timer.daemon = True
        _digest_timer.start()
        logger.info("Daily digest scheduled for %s (in %.0f seconds)", target.strftime("%H:%M"), delay)

    def _run_digest():
        if digest_gen:
            import asyncio
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(digest_gen.send_digest())
                loop.close()
            except Exception as e:
                logger.error("Daily digest failed: %s", e)
        # Reschedule for tomorrow
        if not _expiry_stop.is_set():
            _schedule_next()

    _schedule_next()


# ---------------------------------------------------------------------------
# Lease endpoints
# ---------------------------------------------------------------------------

@app.get("/leases")
async def list_leases(
    agent_id: str | None = Query(None),
    credential_name: str | None = Query(None),
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """List active leases. Requires a valid agent API key."""
    valid = any(
        agent.get("api_key") == x_api_key for agent in _agents.values()
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid API key")

    leases = lease_mgr.get_active_leases(agent_id=agent_id, credential_name=credential_name)
    return [l.to_dict() for l in leases]


class RenewRequest(BaseModel):
    additional_minutes: int = 15


@app.post("/renew/{lease_id}")
async def renew_lease(
    lease_id: str,
    body: RenewRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """Extend an active lease's TTL. Must be the owning agent."""
    # Find the lease
    lease = lease_mgr.get_lease(lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail="Lease not found")

    if lease.state != LeaseState.ACTIVE:
        raise HTTPException(status_code=409, detail=f"Lease is {lease.state.value}, cannot renew")

    # Validate that the caller owns the lease
    if not _validate_api_key(lease.agent_id, x_api_key):
        raise HTTPException(status_code=403, detail="Not the lease owner")

    # Check max_lease_minutes from policy
    policies_dir = cfg.get("policies", {}).get("directory", "policies")
    agent_policy = load_agent_policy(policies_dir, lease.agent_id)
    if agent_policy:
        lease_policy = agent_policy.get_lease_policy(lease.credential_name)
        max_seconds = lease_policy.max_lease_seconds
    else:
        max_seconds = 60 * 60  # default 60 min

    additional_seconds = body.additional_minutes * 60
    new_expiry = lease.expires_at + additional_seconds
    total_duration = new_expiry - lease.created_at

    if total_duration > max_seconds:
        max_mins = max_seconds // 60
        raise HTTPException(
            status_code=403,
            detail=f"Renewal would exceed max lease duration ({max_mins} min)",
        )

    renewed = lease_mgr.renew_lease(lease_id, additional_seconds)
    if not renewed:
        raise HTTPException(status_code=409, detail="Lease could not be renewed")

    audit_log.log(
        agent_id=renewed.agent_id,
        credential_name=renewed.credential_name,
        status="lease_renewed",
        purpose=f"lease:{lease_id[:12]} +{body.additional_minutes}min",
    )

    return renewed.to_dict()


class RevokeRequest(BaseModel):
    reason: str = "no longer needed"


@app.post("/revoke/{lease_id}")
async def revoke_lease(
    lease_id: str,
    body: RevokeRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """Revoke a specific lease. Must be the owning agent or any valid key."""
    lease = lease_mgr.get_lease(lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail="Lease not found")

    # Owner or any valid agent can revoke
    is_owner = _validate_api_key(lease.agent_id, x_api_key)
    is_valid = any(
        agent.get("api_key") == x_api_key for agent in _agents.values()
    )
    if not is_owner and not is_valid:
        raise HTTPException(status_code=401, detail="Invalid API key")

    revoked = lease_mgr.revoke_lease(lease_id, reason=body.reason)
    if not revoked:
        raise HTTPException(status_code=409, detail=f"Lease is not active (state: {lease.state.value})")

    audit_log.log(
        agent_id=lease.agent_id,
        credential_name=lease.credential_name,
        status="lease_revoked",
        purpose=f"lease:{lease_id[:12]} reason:{body.reason}",
    )

    if _notifications_enabled():
        send_lease_revoked_notification(
            config=cfg,
            agent_id=lease.agent_id,
            credential_name=lease.credential_name,
            lease_id=lease.lease_id,
            reason=body.reason,
        )

    return {"status": "revoked", "lease_id": lease_id}


class RevokeAllRequest(BaseModel):
    agent_id: str | None = None


@app.post("/revoke-all")
async def revoke_all_leases(
    body: RevokeAllRequest,
    request: Request,
):
    """Revoke all active leases. Requires YubiKey touch (safety-critical)."""
    # This is a dangerous operation — require YubiKey
    logger.warning("Revoke-all requested — awaiting YubiKey touch")
    print(
        f"\n{'='*60}\n"
        f"  REVOKE ALL LEASES\n"
        f"  Scope: {body.agent_id or 'ALL AGENTS'}\n"
        f"{'='*60}\n"
        f"  >>> Touch your YubiKey to confirm\n"
    )

    result = _run_fido2_assertion()
    if not result.success:
        raise HTTPException(status_code=403, detail=f"YubiKey assertion failed: {result.error}")

    count = lease_mgr.revoke_all(agent_id=body.agent_id)

    audit_log.log(
        agent_id=body.agent_id or "admin",
        credential_name="*",
        status="lease_revoke_all",
        purpose=f"revoked {count} lease(s)",
    )

    if _notifications_enabled():
        send_revoke_all_notification(
            config=cfg,
            count=count,
            agent_id=body.agent_id,
        )

    return {"status": "revoked", "count": count}


# ---------------------------------------------------------------------------
# Proxy endpoints — execute actions without exposing credentials
# ---------------------------------------------------------------------------

class ProxyRequest(BaseModel):
    agent_id: str
    action_name: str
    purpose: str = ""
    params: dict = {}


class ProxyResponse(BaseModel):
    action_name: str
    success: bool
    status_code: int | None = None
    exit_code: int | None = None
    output: str | None = None
    stderr: str | None = None
    error: str | None = None
    execution_time_ms: int = 0
    truncated: bool = False
    lease_id: str | None = None


@app.get("/proxy/actions")
async def list_proxy_actions(
    agent_id: str | None = Query(None),
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """List available proxy actions. Optionally filter by agent policy."""
    # Validate API key
    valid = any(
        agent.get("api_key") == x_api_key for agent in _agents.values()
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not proxy_exec or not proxy_exec.enabled:
        return {"actions": [], "proxy_enabled": False}

    all_actions = proxy_exec.list_actions()

    # If agent_id provided, filter by what the agent can access
    if agent_id:
        if not _validate_api_key(agent_id, x_api_key):
            raise HTTPException(status_code=403, detail="API key does not match agent_id")

        filtered = []
        for action in all_actions:
            cred_name = action.get("credential_name", "")
            if _is_credential_allowed(agent_id, cred_name):
                # Enrich with policy info
                policies_dir = cfg.get("policies", {}).get("directory", "policies")
                agent_policy = load_agent_policy(policies_dir, agent_id)
                if agent_policy:
                    cred_policy = agent_policy.get_credential_policy(cred_name)
                    action["risk"] = cred_policy.get("risk", "medium")
                    action["approval"] = cred_policy.get("approval", agent_policy.default_approval)
                    action["auto_approve_seconds"] = cred_policy.get("auto_approve_seconds")
                filtered.append(action)
        return {"actions": filtered, "proxy_enabled": True}

    return {"actions": all_actions, "proxy_enabled": True}


@app.post("/proxy", response_model=ProxyResponse)
async def execute_proxy(
    req: ProxyRequest,
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """Execute an action through the proxy. The credential is injected by the
    gate — the agent never sees it."""
    start = time.monotonic()
    client_ip = request.client.host if request.client else "unknown"

    # --- Phase 10: Gate lock check (FIRST — before anything else) ---
    if panic_mgr:
        panic_mgr.check_gate()

    # --- Check proxy is enabled ---
    if not proxy_exec or not proxy_exec.enabled:
        raise HTTPException(status_code=404, detail="Proxy is not enabled")

    # --- Authenticate agent ---
    if not _validate_api_key(req.agent_id, x_api_key):
        audit_log.log(
            agent_id=req.agent_id,
            credential_name=f"proxy:{req.action_name}",
            status="error",
            purpose=req.purpose,
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
        )
        raise HTTPException(status_code=401, detail="Invalid API key")

    # --- Phase 10: Agent identity hardening ---
    _validate_agent_identity(request, req.agent_id)

    # --- Look up proxy action ---
    action = proxy_exec.get_action(req.action_name)
    if not action:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown proxy action: '{req.action_name}'",
        )

    # --- Authorize credential access ---
    if not _is_credential_allowed(req.agent_id, action.credential_name):
        audit_log.log(
            agent_id=req.agent_id,
            credential_name=action.credential_name,
            status="denied",
            purpose=f"proxy:{req.action_name} {req.purpose}",
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
        )
        raise HTTPException(
            status_code=403,
            detail=f"Agent '{req.agent_id}' is not allowed to access credential '{action.credential_name}'",
        )

    # --- Check Bitwarden availability ---
    if bw.state in (SessionState.NO_SESSION, SessionState.LOCKED):
        raise HTTPException(status_code=503, detail="Bitwarden vault unavailable")

    # --- Evaluate policy for the underlying credential ---
    policies_cfg = cfg.get("policies", {})
    policies_dir = policies_cfg.get("directory", "policies")
    default_policy = policies_cfg.get("default_policy", "deny")

    agent_policy = load_agent_policy(policies_dir, req.agent_id)

    if agent_policy is None:
        if default_policy == "deny":
            audit_log.log(
                agent_id=req.agent_id,
                credential_name=action.credential_name,
                status="denied",
                purpose=f"proxy:{req.action_name} {req.purpose}",
                ip_address=client_ip,
                response_time_ms=_elapsed_ms(start),
                policy_checks=[{"check": "policy_file", "allowed": False,
                                "reason": "No policy file for agent"}],
            )
            raise HTTPException(
                status_code=403,
                detail=f"No policy file for agent '{req.agent_id}'",
            )
        decision = None
    else:
        decision = agent_policy.evaluate(action.credential_name, audit_log)
        if not decision.allowed:
            logger.warning(
                "Policy denied proxy %s/%s: %s",
                req.agent_id, action.credential_name, decision.reason,
            )
            audit_log.log(
                agent_id=req.agent_id,
                credential_name=action.credential_name,
                status="denied",
                purpose=f"proxy:{req.action_name} {req.purpose}",
                ip_address=client_ip,
                response_time_ms=_elapsed_ms(start),
                policy_checks=decision.checks,
            )
            raise HTTPException(status_code=403, detail=decision.reason)

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

    # --- Build a CredentialRequest for the approval flow ---
    cred_req = CredentialRequest(
        agent_id=req.agent_id,
        credential_name=action.credential_name,
        purpose=f"proxy:{req.action_name} {req.purpose}",
        fields=[action.credential_field],
    )

    logger.info(
        "Proxy request [mode=%s]: %s action '%s' (credential '%s') for '%s'",
        mode, req.agent_id, req.action_name, action.credential_name, req.purpose,
    )
    _print_request_banner(cred_req, mode)

    # --- Run approval flow (same as credential requests) ---
    if auto_approve_seconds:
        approval = await _handle_auto_approve_mode(
            cred_req, client_ip, start, auto_approve_seconds,
            alert_always, policy_checks, lease_pol,
        )
    elif mode == "yubikey":
        approval = await _handle_yubikey_mode(
            cred_req, client_ip, start, alert_always, policy_checks, lease_pol,
        )
    elif mode == "phone":
        approval = await _handle_phone_mode(
            cred_req, client_ip, start, alert_always, policy_checks, lease_pol,
        )
    elif mode == "both":
        approval = await _handle_both_mode(
            cred_req, client_ip, start, alert_always, policy_checks, lease_pol,
        )
    else:
        raise HTTPException(status_code=500, detail=f"Unknown authorization mode: {mode}")

    # --- If not approved, return the denial ---
    if approval.status != "approved":
        return ProxyResponse(
            action_name=req.action_name,
            success=False,
            error=approval.reason or approval.status,
            execution_time_ms=_elapsed_ms(start),
        )

    # --- Extract credential for proxy use ---
    credential_value = approval.credential.get(action.credential_field) if approval.credential else None
    if not credential_value:
        return ProxyResponse(
            action_name=req.action_name,
            success=False,
            error=f"Credential field '{action.credential_field}' is empty",
            execution_time_ms=_elapsed_ms(start),
        )

    # --- Execute the proxy action ---
    result: ProxyResult = await proxy_exec.execute(action, credential_value, req.params)

    # --- Audit the proxy execution ---
    audit_log.log(
        agent_id=req.agent_id,
        credential_name=action.credential_name,
        status="proxy_executed" if result.success else "proxy_failed",
        purpose=f"proxy:{req.action_name} {req.purpose}",
        ip_address=client_ip,
        response_time_ms=_elapsed_ms(start),
        policy_checks=policy_checks,
    )

    logger.info(
        "Proxy action '%s' %s for %s (%dms)",
        req.action_name,
        "succeeded" if result.success else "failed",
        req.agent_id,
        result.execution_time_ms,
    )

    return ProxyResponse(
        action_name=result.action_name,
        success=result.success,
        status_code=result.status_code,
        exit_code=result.exit_code,
        output=result.response_body or result.stdout,
        stderr=result.stderr,
        error=result.error,
        execution_time_ms=result.execution_time_ms,
        truncated=result.truncated,
        lease_id=approval.lease.lease_id if approval.lease else None,
    )


# ---------------------------------------------------------------------------
# Credential endpoint — three authorization modes
# ---------------------------------------------------------------------------

def _print_request_banner(req: CredentialRequest, mode: str):
    """Print a human-readable banner to the console."""
    mode_hint = {
        "yubikey": "Touch your YubiKey to approve",
        "phone": "Approve on your phone",
        "both": "Touch YubiKey OR approve on phone",
    }
    print(
        f"\n{'='*60}\n"
        f"  CREDENTIAL REQUEST\n"
        f"  Agent:      {req.agent_id}\n"
        f"  Credential: {req.credential_name}\n"
        f"  Purpose:    {req.purpose}\n"
        f"  Fields:     {', '.join(req.fields)}\n"
        f"  Mode:       {mode}\n"
        f"{'='*60}\n"
        f"  >>> {mode_hint.get(mode, '')}\n"
    )


def _run_fido2_assertion() -> AssertionResult:
    """Run FIDO2 assertion (blocking). Designed to run in a thread."""
    fido2_cfg = cfg.get("fido2", {})
    timeout = cfg.get("timeouts", {}).get("touch_timeout_seconds", 60)
    return assert_touch(
        rp_id=fido2_cfg.get("rp_id", "credential-gate.local"),
        rp_name=fido2_cfg.get("rp_name", "Credential Gate"),
        store_path=fido2_cfg.get("credential_store"),
        timeout_seconds=timeout,
    )


def _fetch_credential(req: CredentialRequest) -> dict:
    """Fetch the credential from Bitwarden. Raises BitwardenError."""
    item = bw.get_item(req.credential_name)
    extracted = bw.extract_fields(item, req.fields)

    if "totp" in req.fields:
        try:
            extracted["totp"] = bw.get_totp(req.credential_name)
        except BitwardenError:
            extracted["totp"] = None

    return extracted


@app.post("/credential", response_model=CredentialResponse)
async def request_credential(
    req: CredentialRequest,
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    start = time.monotonic()
    client_ip = request.client.host if request.client else "unknown"

    # --- Phase 10: Gate lock check (FIRST — before anything else) ---
    if panic_mgr:
        panic_mgr.check_gate()

    # --- Authenticate agent ---
    if not _validate_api_key(req.agent_id, x_api_key):
        audit_log.log(
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            status="error",
            fields_requested=req.fields,
            purpose=req.purpose,
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
        )
        raise HTTPException(status_code=401, detail="Invalid API key")

    # --- Phase 10: Agent identity hardening ---
    _validate_agent_identity(request, req.agent_id)

    # --- Authorize credential access ---
    if not _is_credential_allowed(req.agent_id, req.credential_name):
        audit_log.log(
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            status="denied",
            fields_requested=req.fields,
            purpose=req.purpose,
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
        )
        raise HTTPException(
            status_code=403,
            detail=f"Agent '{req.agent_id}' is not allowed to access '{req.credential_name}'",
        )

    # --- Check Bitwarden availability before prompting ---
    if bw.state in (SessionState.NO_SESSION, SessionState.LOCKED):
        audit_log.log(
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            status="error",
            fields_requested=req.fields,
            purpose=req.purpose,
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
        )
        detail = (
            "Bitwarden vault unavailable. "
            "Run: python setup.py store-password"
            if bw.state == SessionState.NO_SESSION
            else "Bitwarden vault is locked. Check master password in Keychain."
        )
        raise HTTPException(status_code=503, detail=detail)

    # --- Evaluate policy ---
    policies_cfg = cfg.get("policies", {})
    policies_dir = policies_cfg.get("directory", "policies")
    default_policy = policies_cfg.get("default_policy", "deny")

    agent_policy = load_agent_policy(policies_dir, req.agent_id)

    if agent_policy is None:
        if default_policy == "deny":
            audit_log.log(
                agent_id=req.agent_id,
                credential_name=req.credential_name,
                status="denied",
                fields_requested=req.fields,
                purpose=req.purpose,
                ip_address=client_ip,
                response_time_ms=_elapsed_ms(start),
                policy_checks=[{"check": "policy_file", "allowed": False,
                                "reason": "No policy file for agent"}],
            )
            raise HTTPException(
                status_code=403,
                detail=f"No policy file for agent '{req.agent_id}'",
            )
        # default_policy == "allow_all": skip policy checks, use config-level mode
        decision = None
    else:
        decision = agent_policy.evaluate(req.credential_name, audit_log)
        if not decision.allowed:
            logger.warning(
                "Policy denied %s/%s: %s",
                req.agent_id, req.credential_name, decision.reason,
            )
            audit_log.log(
                agent_id=req.agent_id,
                credential_name=req.credential_name,
                status="denied",
                fields_requested=req.fields,
                purpose=req.purpose,
                ip_address=client_ip,
                response_time_ms=_elapsed_ms(start),
                policy_checks=decision.checks,
            )
            # Send alert if flagged
            if decision.alert_always and _notifications_enabled():
                send_touch_notification(
                    config=cfg,
                    agent_id=req.agent_id,
                    credential_name=req.credential_name,
                    purpose=f"DENIED: {decision.reason}",
                )
            raise HTTPException(status_code=403, detail=decision.reason)

    # Determine effective mode: policy overrides config
    if decision:
        mode = decision.approval_mode
        auto_approve_seconds = decision.auto_approve_seconds
        alert_always = decision.alert_always
        policy_checks = decision.checks
    else:
        mode = _auth_mode()
        auto_approve_seconds = None
        alert_always = False
        policy_checks = None

    logger.info(
        "Credential request [mode=%s]: %s requests '%s' for '%s'",
        mode, req.agent_id, req.credential_name, req.purpose,
    )
    _print_request_banner(req, mode)

    # Resolve lease policy
    if decision:
        lease_pol = decision.lease_policy
    else:
        lease_pol = LeasePolicy()  # defaults

    # --- Dispatch to mode-specific handler ---
    if auto_approve_seconds:
        return await _handle_auto_approve_mode(
            req, client_ip, start, auto_approve_seconds,
            alert_always, policy_checks, lease_pol,
        )
    elif mode == "yubikey":
        return await _handle_yubikey_mode(req, client_ip, start, alert_always, policy_checks, lease_pol)
    elif mode == "phone":
        return await _handle_phone_mode(req, client_ip, start, alert_always, policy_checks, lease_pol)
    elif mode == "both":
        return await _handle_both_mode(req, client_ip, start, alert_always, policy_checks, lease_pol)
    else:
        logger.error("Unknown authorization mode: %s", mode)
        raise HTTPException(status_code=500, detail=f"Unknown authorization mode: {mode}")


# ---------------------------------------------------------------------------
# Mode: yubikey (existing Phase 1/2 behavior)
# ---------------------------------------------------------------------------

async def _handle_yubikey_mode(
    req: CredentialRequest, client_ip: str, start: float,
    alert_always: bool = False, policy_checks: list[dict] | None = None,
    lease_policy: LeasePolicy | None = None,
) -> CredentialResponse:
    """YubiKey-only authorization."""
    # Send informational notification (no action buttons)
    if _notifications_enabled():
        send_touch_notification(
            config=cfg,
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            purpose=req.purpose,
        )

    # FIDO2 assertion — blocks until touch or timeout
    result: AssertionResult = _run_fido2_assertion()

    if not result.success:
        status = "timeout" if result.error == "timeout" else "denied"
        logger.warning("FIDO2 assertion failed: %s", result.error)

        if status == "timeout" and _notifications_enabled():
            send_timeout_notification(
                config=cfg,
                agent_id=req.agent_id,
                credential_name=req.credential_name,
            )

        audit_log.log(
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            status=status,
            fields_requested=req.fields,
            purpose=req.purpose,
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
            policy_checks=policy_checks,
        )
        return CredentialResponse(status=status, reason=result.error)

    # Approved — fetch credential
    return _finalize_approval(
        req, client_ip, start, method="yubikey",
        alert_always=alert_always, policy_checks=policy_checks,
        lease_policy=lease_policy,
    )


# ---------------------------------------------------------------------------
# Mode: phone
# ---------------------------------------------------------------------------

async def _handle_phone_mode(
    req: CredentialRequest, client_ip: str, start: float,
    alert_always: bool = False, policy_checks: list[dict] | None = None,
    lease_policy: LeasePolicy | None = None,
) -> CredentialResponse:
    """Phone-only authorization via Ntfy action buttons."""
    timeout = cfg.get("timeouts", {}).get("touch_timeout_seconds", 60)

    # Create pending request
    pending = approval_queue.create(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        purpose=req.purpose,
        fields=req.fields,
    )

    # Send Ntfy notification with Approve/Deny buttons
    if _notifications_enabled():
        send_approval_notification(
            config=cfg,
            request_id=pending.request_id,
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            purpose=req.purpose,
        )

    # Block until phone callback or timeout
    state = approval_queue.wait(pending.request_id, timeout)

    if state == ApprovalState.APPROVED:
        return _finalize_approval(
            req, client_ip, start, method="phone",
            alert_always=alert_always, policy_checks=policy_checks,
            lease_policy=lease_policy,
        )

    # Denied or expired
    status = "denied" if state == ApprovalState.DENIED else "timeout"
    reason = "Denied via phone" if state == ApprovalState.DENIED else "timeout"
    logger.warning("Phone approval failed: %s", status)

    if status == "timeout" and _notifications_enabled():
        send_timeout_notification(
            config=cfg,
            agent_id=req.agent_id,
            credential_name=req.credential_name,
        )

    audit_log.log(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        status=status,
        fields_requested=req.fields,
        purpose=req.purpose,
        ip_address=client_ip,
        response_time_ms=_elapsed_ms(start),
        policy_checks=policy_checks,
    )
    return CredentialResponse(status=status, reason=reason)


# ---------------------------------------------------------------------------
# Mode: both (race FIDO2 touch vs phone approval)
# ---------------------------------------------------------------------------

async def _handle_both_mode(
    req: CredentialRequest, client_ip: str, start: float,
    alert_always: bool = False, policy_checks: list[dict] | None = None,
    lease_policy: LeasePolicy | None = None,
) -> CredentialResponse:
    """Race FIDO2 touch and phone approval — first one wins."""
    timeout = cfg.get("timeouts", {}).get("touch_timeout_seconds", 60)

    # Create pending request for phone path
    pending = approval_queue.create(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        purpose=req.purpose,
        fields=req.fields,
    )

    # Send Ntfy notification with Approve/Deny buttons
    if _notifications_enabled():
        send_approval_notification(
            config=cfg,
            request_id=pending.request_id,
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            purpose=req.purpose,
        )

    # Race: run FIDO2 in a thread, phone waits on the approval event
    race_resolved = threading.Event()
    winner = {"method": None}  # mutable container for closure
    fido_result_holder: list[AssertionResult] = []

    def fido2_racer():
        """Run FIDO2 assertion; if it finishes first, mark winner."""
        result = _run_fido2_assertion()
        fido_result_holder.append(result)
        if result.success and winner["method"] is None:
            winner["method"] = "yubikey"
            # Cancel the phone wait by approving the pending request
            # (so the phone waiter unblocks)
            approval_queue.approve(pending.request_id)
            race_resolved.set()
        elif not result.success:
            # FIDO2 failed/timed out — only set resolved if phone hasn't won
            race_resolved.set()

    def phone_racer():
        """Wait for phone approval; if it fires first, mark winner."""
        state = approval_queue.wait(pending.request_id, timeout)
        if state == ApprovalState.APPROVED and winner["method"] is None:
            winner["method"] = "phone"
            race_resolved.set()
        elif state == ApprovalState.DENIED:
            winner["method"] = "denied"
            race_resolved.set()
        else:
            race_resolved.set()

    fido_thread = threading.Thread(target=fido2_racer, daemon=True)
    phone_thread = threading.Thread(target=phone_racer, daemon=True)
    fido_thread.start()
    phone_thread.start()

    # Wait for either to finish
    race_resolved.wait(timeout=timeout + 5)

    # Determine outcome
    method = winner["method"]

    if method == "yubikey":
        logger.info("Race won by YubiKey touch")
        return _finalize_approval(
            req, client_ip, start, method="yubikey",
            alert_always=alert_always, policy_checks=policy_checks,
            lease_policy=lease_policy,
        )

    if method == "phone":
        logger.info("Race won by phone approval")
        return _finalize_approval(
            req, client_ip, start, method="phone",
            alert_always=alert_always, policy_checks=policy_checks,
            lease_policy=lease_policy,
        )

    if method == "denied":
        logger.warning("Request denied via phone")
        audit_log.log(
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            status="denied",
            fields_requested=req.fields,
            purpose=req.purpose,
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
            policy_checks=policy_checks,
        )
        return CredentialResponse(status="denied", reason="Denied via phone")

    # Neither won — timeout
    logger.warning("Both mode timed out — no approval received")

    if _notifications_enabled():
        send_timeout_notification(
            config=cfg,
            agent_id=req.agent_id,
            credential_name=req.credential_name,
        )

    audit_log.log(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        status="timeout",
        fields_requested=req.fields,
        purpose=req.purpose,
        ip_address=client_ip,
        response_time_ms=_elapsed_ms(start),
        policy_checks=policy_checks,
    )
    return CredentialResponse(status="timeout", reason="timeout")


# ---------------------------------------------------------------------------
# Mode: auto-approve (low-risk credentials with auto_approve_seconds)
# ---------------------------------------------------------------------------

async def _handle_auto_approve_mode(
    req: CredentialRequest, client_ip: str, start: float,
    auto_approve_seconds: int, alert_always: bool = False,
    policy_checks: list[dict] | None = None,
    lease_policy: LeasePolicy | None = None,
) -> CredentialResponse:
    """Auto-approve after a timer unless denied via phone.

    Flow:
    1. Send informational Ntfy with Deny button and countdown
    2. Wait for auto_approve_seconds
    3. If deny callback arrives → deny
    4. If timer expires with no deny → auto-approve
    """
    # Create pending request so deny callback can cancel
    pending = approval_queue.create(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        purpose=req.purpose,
        fields=req.fields,
    )

    # Send notification with Deny button and auto-approve countdown
    if _notifications_enabled():
        send_auto_approve_notification(
            config=cfg,
            request_id=pending.request_id,
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            purpose=req.purpose,
            seconds=auto_approve_seconds,
        )

    logger.info(
        "Auto-approve timer started for '%s' (%ds)",
        req.credential_name, auto_approve_seconds,
    )

    # Wait for deny or timeout (auto-approve on expiry)
    state = approval_queue.wait(pending.request_id, auto_approve_seconds)

    if state == ApprovalState.DENIED:
        logger.warning("Auto-approve denied via phone for '%s'", req.credential_name)
        audit_log.log(
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            status="denied",
            fields_requested=req.fields,
            purpose=req.purpose,
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
            policy_checks=policy_checks,
        )
        return CredentialResponse(status="denied", reason="Denied via phone (auto-approve cancelled)")

    # Timer expired with no deny → auto-approve
    logger.info("Auto-approved '%s' for %s (no deny received)", req.credential_name, req.agent_id)
    return _finalize_approval(
        req, client_ip, start, method="auto-approve",
        alert_always=alert_always, policy_checks=policy_checks,
        lease_policy=lease_policy,
    )


# ---------------------------------------------------------------------------
# Shared: finalize an approved request (fetch from Bitwarden)
# ---------------------------------------------------------------------------

def _finalize_approval(
    req: CredentialRequest, client_ip: str, start: float, method: str,
    alert_always: bool = False, policy_checks: list[dict] | None = None,
    lease_policy: LeasePolicy | None = None,
) -> CredentialResponse:
    """Fetch credential from Bitwarden, create a lease, and return response."""
    try:
        extracted = _fetch_credential(req)
    except BitwardenError as e:
        logger.error("Bitwarden error: %s", e)
        audit_log.log(
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            status="error",
            fields_requested=req.fields,
            purpose=req.purpose,
            ip_address=client_ip,
            response_time_ms=_elapsed_ms(start),
            policy_checks=policy_checks,
        )
        return CredentialResponse(status="denied", reason=f"Bitwarden error: {e}")

    # --- Check concurrent lease limit ---
    if lease_policy:
        max_concurrent = lease_policy.max_concurrent_leases
        current_count = lease_mgr.count_active_for_credential(req.credential_name)
        if current_count >= max_concurrent:
            audit_log.log(
                agent_id=req.agent_id,
                credential_name=req.credential_name,
                status="denied",
                fields_requested=req.fields,
                purpose=req.purpose,
                ip_address=client_ip,
                response_time_ms=_elapsed_ms(start),
                policy_checks=policy_checks,
            )
            return CredentialResponse(
                status="denied",
                reason=f"Max concurrent leases reached ({max_concurrent}) for '{req.credential_name}'",
            )

    # --- Create lease ---
    ttl = lease_policy.ttl_seconds if lease_policy else 15 * 60
    lease = lease_mgr.create_lease(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        fields=req.fields,
        purpose=req.purpose,
        ttl_seconds=ttl,
        approval_method=method,
    )

    audit_log.log(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        status="approved",
        fields_requested=req.fields,
        purpose=req.purpose,
        ip_address=client_ip,
        response_time_ms=_elapsed_ms(start),
        policy_checks=policy_checks,
    )

    logger.info(
        "Credential '%s' approved for %s via %s (lease %s, TTL %ds)",
        req.credential_name, req.agent_id, method,
        lease.lease_id[:12], ttl,
    )

    if _notifications_enabled():
        send_approved_notification(
            config=cfg,
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            method=method,
        )

    # Build lease info for response
    max_lease_seconds = lease_policy.max_lease_seconds if lease_policy else 60 * 60
    renewable = (lease.expires_at - lease.created_at) < max_lease_seconds

    lease_info = LeaseInfo(
        lease_id=lease.lease_id,
        expires_at=_ts_to_iso(lease.expires_at),
        ttl_seconds=ttl,
        renewable=renewable,
    )

    return CredentialResponse(
        status="approved",
        credential=extracted,
        lease=lease_info,
    )


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=cfg["server"]["host"],
        port=cfg["server"]["port"],
        log_level="info",
    )
