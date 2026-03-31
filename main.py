"""Credential Gate Service — FastAPI application.

Physical authorization gate: AI agents request credentials, and a
YubiKey touch, phone approval, or either-first-wins authorizes access.
The credential is fetched fresh from Bitwarden on every approved request.

Phase 3: Ntfy.sh notifications, phone approval, three authorization
modes (yubikey / phone / both), pending request queue.
"""

import logging
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from approvals import ApprovalQueue, ApprovalState
from audit import AuditLog
from bitwarden import BitwardenError, BitwardenSessionManager, SessionState
from config import load_config
from fido import AssertionResult, assert_touch
from notifications import (
    send_approval_notification,
    send_approved_notification,
    send_timeout_notification,
    send_touch_notification,
)

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    global audit_log, bw
    audit_log = AuditLog(cfg["audit"]["db_path"])

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

    mode = cfg.get("authorization", {}).get("mode", "yubikey")
    logger.info(
        "Credential Gate started on %s:%s (mode=%s)",
        cfg["server"]["host"],
        cfg["server"]["port"],
        mode,
    )
    yield
    bw.shutdown()
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


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class CredentialRequest(BaseModel):
    agent_id: str
    credential_name: str
    purpose: str = ""
    fields: list[str] = ["password"]


class CredentialResponse(BaseModel):
    status: str
    credential: dict | None = None
    expires_at: None = None
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

    return {
        "status": "ok" if bw_status == "active" else "degraded",
        "bitwarden": bw_status,
        "fido2": "ready" if has_creds else "no_credentials",
        "authorization_mode": _auth_mode(),
        "notifications": notif_status,
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
    mode = _auth_mode()

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

    logger.info(
        "Credential request [mode=%s]: %s requests '%s' for '%s'",
        mode, req.agent_id, req.credential_name, req.purpose,
    )
    _print_request_banner(req, mode)

    # --- Dispatch to mode-specific handler ---
    if mode == "yubikey":
        return await _handle_yubikey_mode(req, client_ip, start)
    elif mode == "phone":
        return await _handle_phone_mode(req, client_ip, start)
    elif mode == "both":
        return await _handle_both_mode(req, client_ip, start)
    else:
        logger.error("Unknown authorization mode: %s", mode)
        raise HTTPException(status_code=500, detail=f"Unknown authorization mode: {mode}")


# ---------------------------------------------------------------------------
# Mode: yubikey (existing Phase 1/2 behavior)
# ---------------------------------------------------------------------------

async def _handle_yubikey_mode(
    req: CredentialRequest, client_ip: str, start: float,
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
        )
        return CredentialResponse(status=status, reason=result.error)

    # Approved — fetch credential
    return _finalize_approval(req, client_ip, start, method="yubikey")


# ---------------------------------------------------------------------------
# Mode: phone
# ---------------------------------------------------------------------------

async def _handle_phone_mode(
    req: CredentialRequest, client_ip: str, start: float,
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
        return _finalize_approval(req, client_ip, start, method="phone")

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
    )
    return CredentialResponse(status=status, reason=reason)


# ---------------------------------------------------------------------------
# Mode: both (race FIDO2 touch vs phone approval)
# ---------------------------------------------------------------------------

async def _handle_both_mode(
    req: CredentialRequest, client_ip: str, start: float,
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
        return _finalize_approval(req, client_ip, start, method="yubikey")

    if method == "phone":
        logger.info("Race won by phone approval")
        return _finalize_approval(req, client_ip, start, method="phone")

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
    )
    return CredentialResponse(status="timeout", reason="timeout")


# ---------------------------------------------------------------------------
# Shared: finalize an approved request (fetch from Bitwarden)
# ---------------------------------------------------------------------------

def _finalize_approval(
    req: CredentialRequest, client_ip: str, start: float, method: str,
) -> CredentialResponse:
    """Fetch credential from Bitwarden and return success response."""
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
        )
        return CredentialResponse(status="denied", reason=f"Bitwarden error: {e}")

    audit_log.log(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        status="approved",
        fields_requested=req.fields,
        purpose=req.purpose,
        ip_address=client_ip,
        response_time_ms=_elapsed_ms(start),
    )

    logger.info(
        "Credential '%s' approved for %s via %s",
        req.credential_name, req.agent_id, method,
    )

    if _notifications_enabled():
        send_approved_notification(
            config=cfg,
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            method=method,
        )

    return CredentialResponse(status="approved", credential=extracted)


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
