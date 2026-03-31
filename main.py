"""Credential Gate Service — FastAPI application.

Physical authorization gate: AI agents request credentials, a YubiKey touch
approves (or denies) access, and the credential is fetched fresh from
Bitwarden on every approved request.

Phase 2: Bitwarden session management via Keychain, push notifications
via Home Assistant, enhanced health reporting.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from audit import AuditLog
from bitwarden import BitwardenError, BitwardenSessionManager, SessionState
from config import load_config
from fido import AssertionResult, assert_touch
from notifications import send_timeout_notification, send_touch_notification

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

    logger.info(
        "Credential Gate started on %s:%s",
        cfg["server"]["host"],
        cfg["server"]["port"],
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


# ---------------------------------------------------------------------------
# Notification helpers
# ---------------------------------------------------------------------------

def _notif_params() -> dict:
    """Return common notification parameters from config."""
    notif_cfg = cfg.get("notifications", {})
    bw_cfg = cfg.get("bitwarden", {})
    return {
        "ha_url": notif_cfg.get("ha_url", ""),
        "keychain_service": bw_cfg.get("keychain_service", "credential-gate"),
        "keychain_account": notif_cfg.get("ha_keychain_account", "home-assistant"),
    }


def _notifications_enabled() -> bool:
    return cfg.get("notifications", {}).get("enabled", False)


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
# Endpoints
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

    # Notifications status
    notif_status = "disabled"
    if _notifications_enabled():
        from bitwarden import keychain_retrieve
        params = _notif_params()
        has_token = keychain_retrieve(
            params["keychain_service"], params["keychain_account"]
        ) is not None
        notif_status = "enabled" if has_token else "no_token"

    return {
        "status": "ok" if bw_status == "active" else "degraded",
        "bitwarden": bw_status,
        "fido2": "ready" if has_creds else "no_credentials",
        "notifications": notif_status,
    }


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


@app.post("/credential", response_model=CredentialResponse)
async def request_credential(
    req: CredentialRequest,
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    start = time.monotonic()
    client_ip = request.client.host if request.client else "unknown"

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

    # --- Check Bitwarden availability before prompting for touch ---
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

    # --- Send push notification (before YubiKey prompt) ---
    if _notifications_enabled():
        params = _notif_params()
        send_touch_notification(
            agent_id=req.agent_id,
            credential_name=req.credential_name,
            purpose=req.purpose,
            **params,
        )

    # --- Prompt for YubiKey touch ---
    fido2_cfg = cfg.get("fido2", {})
    timeout = cfg.get("timeouts", {}).get("touch_timeout_seconds", 60)

    logger.info(
        "FIDO2 challenge: %s requests '%s' for '%s'",
        req.agent_id,
        req.credential_name,
        req.purpose,
    )
    print(
        f"\n{'='*60}\n"
        f"  CREDENTIAL REQUEST\n"
        f"  Agent:      {req.agent_id}\n"
        f"  Credential: {req.credential_name}\n"
        f"  Purpose:    {req.purpose}\n"
        f"  Fields:     {', '.join(req.fields)}\n"
        f"{'='*60}\n"
        f"  >>> Touch your YubiKey to approve …\n"
    )

    result: AssertionResult = assert_touch(
        rp_id=fido2_cfg.get("rp_id", "credential-gate.local"),
        rp_name=fido2_cfg.get("rp_name", "Credential Gate"),
        store_path=fido2_cfg.get("credential_store"),
        timeout_seconds=timeout,
    )

    if not result.success:
        status = "timeout" if result.error == "timeout" else "denied"
        logger.warning("FIDO2 assertion failed: %s", result.error)

        # Send timeout notification
        if status == "timeout" and _notifications_enabled():
            params = _notif_params()
            send_timeout_notification(
                agent_id=req.agent_id,
                credential_name=req.credential_name,
                **params,
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

    # --- Fetch credential from Bitwarden (with session management) ---
    try:
        item = bw.get_item(req.credential_name)
        extracted = bw.extract_fields(item, req.fields)

        # Handle TOTP separately if requested
        if "totp" in req.fields:
            try:
                extracted["totp"] = bw.get_totp(req.credential_name)
            except BitwardenError:
                extracted["totp"] = None

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

    # --- Success ---
    audit_log.log(
        agent_id=req.agent_id,
        credential_name=req.credential_name,
        status="approved",
        fields_requested=req.fields,
        purpose=req.purpose,
        ip_address=client_ip,
        response_time_ms=_elapsed_ms(start),
    )

    logger.info("Credential '%s' approved for %s", req.credential_name, req.agent_id)
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
