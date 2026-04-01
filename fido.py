"""FIDO2 registration and assertion for headless YubiKey flows.

Uses python-fido2's CTAP2 HID transport directly — no browser involved.
The Fido2Server handles challenge generation and response verification;
the Ctap2 client talks to the physical key over USB HID.

Phase 12: All fido2 imports are conditional — when python-fido2 is not
installed (silver tier / phone-only mode), this module still loads but
all functions raise RuntimeError with a clear message.
"""

import json
import hashlib
import logging
import os
import secrets
import threading
import time
from pathlib import Path

try:
    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin
    from fido2.hid import CtapHidDevice
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        AttestedCredentialData,
        AuthenticatorData,
        CollectedClientData,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
    )
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False

logger = logging.getLogger(__name__)


def _require_fido2():
    """Raise if python-fido2 is not installed."""
    if not FIDO2_AVAILABLE:
        raise RuntimeError(
            "python-fido2 is not installed. YubiKey features require: "
            "pip install fido2\n"
            "For phone-only operation (silver tier), set security_tier: silver "
            "in config.yaml."
        )

# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------

def list_devices() -> list:
    """Return all connected FIDO2 HID devices."""
    if not FIDO2_AVAILABLE:
        return []
    try:
        return list(CtapHidDevice.list_devices())
    except Exception as exc:
        logger.error("Failed to enumerate HID devices: %s", exc)
        return []


def get_device():
    """Return the first connected FIDO2 device or raise."""
    _require_fido2()
    devices = list_devices()
    if not devices:
        raise RuntimeError(
            "No FIDO2 device found. Is your YubiKey plugged in?"
        )
    dev = devices[0]
    logger.info(
        "Using device: %s (serial=%s)",
        dev.descriptor.product_name,
        dev.descriptor.serial_number,
    )
    return dev


# ---------------------------------------------------------------------------
# Credential persistence
# ---------------------------------------------------------------------------

def _load_credentials(path: str) -> list[dict]:
    """Load stored credentials from JSON file."""
    p = Path(path)
    if not p.exists():
        return []
    with open(p) as f:
        return json.load(f)


def _save_credentials(path: str, creds: list[dict]) -> None:
    """Save credentials to JSON file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(creds, f, indent=2)


def get_registered_credentials(store_path: str) -> list:
    """Load AttestedCredentialData objects from the credential store."""
    _require_fido2()
    entries = _load_credentials(store_path)
    result = []
    for entry in entries:
        raw = bytes.fromhex(entry["attested_credential_data"])
        acd, _ = AttestedCredentialData.unpack_from(raw)
        result.append(acd)
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_server(rp_id: str, rp_name: str):
    rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    return Fido2Server(rp)


def _make_client_data(typ: str, challenge: bytes, origin: str):
    """Build a CollectedClientData object for headless use.

    The fido2 library's Fido2Server.register_complete / authenticate_complete
    expects a proper CollectedClientData.  We construct one manually since
    there is no browser.
    """
    return CollectedClientData.create(
        type=typ,
        challenge=challenge,
        origin=origin,
    )


def _origin_for_rp(rp_id: str) -> str:
    """Synthesise an origin string for a non-browser RP.

    WebAuthn origins are normally https URLs but the fido2 library lets us
    pass a custom verify_origin to the server, or we can just build a
    consistent origin string and supply a permissive verifier.
    """
    return f"https://{rp_id}"


def _get_pin_if_needed(ctap2: Ctap2) -> tuple[bytes | None, int | None]:
    """Prompt for PIN and return (pin_uv_param, pin_uv_protocol) or (None, None).

    If the device requires a PIN we must authenticate first to get a
    pinUvAuthToken.  Returns the raw token (caller computes HMAC for each
    command using the ClientPin helper).
    """
    info = ctap2.info
    options = info.options if info.options else {}

    # clientPin option present and set to True means a PIN is configured
    if not options.get("clientPin", False):
        return None, None

    pin = os.environ.get("CREDENTIAL_GATE_FIDO2_PIN")
    if not pin:
        import getpass
        pin = getpass.getpass("YubiKey PIN: ")

    client_pin = ClientPin(ctap2)
    return client_pin, pin


# ---------------------------------------------------------------------------
# Registration  (one-time setup)
# ---------------------------------------------------------------------------

def register(
    rp_id: str,
    rp_name: str,
    store_path: str,
    user_name: str = "credential-gate-admin",
):
    """Register a new FIDO2 credential on the connected YubiKey.

    This is the one-time setup step.  The resulting AttestedCredentialData
    (containing the public key and credential ID) is persisted to
    *store_path* so that future assertion challenges can reference it.

    Returns the AttestedCredentialData for the new credential.
    """
    _require_fido2()
    device = get_device()
    ctap2 = Ctap2(device)

    server = _build_server(rp_id, rp_name)
    origin = _origin_for_rp(rp_id)

    user = PublicKeyCredentialUserEntity(
        id=secrets.token_bytes(32),
        name=user_name,
        display_name=user_name,
    )

    # Exclude already-registered credentials to avoid duplicates
    existing = get_registered_credentials(store_path)

    # --- Generate challenge ---
    creation_options, state = server.register_begin(
        user=user,
        credentials=existing,
        user_verification="discouraged",
    )

    options = creation_options.public_key
    challenge = options.challenge

    # --- Build client data ---
    client_data = _make_client_data("webauthn.create", challenge, origin)
    client_data_hash = hashlib.sha256(client_data).digest()

    # --- PIN handling ---
    pin_uv_param = None
    pin_uv_protocol = None
    pin_helper, pin = None, None
    cp_result = _get_pin_if_needed(ctap2)
    if cp_result[0] is not None:
        pin_helper, pin = cp_result
        pin_token = pin_helper.get_pin_token(
            pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp_id
        )
        pin_uv_param = pin_helper.protocol.authenticate(pin_token, client_data_hash)
        pin_uv_protocol = pin_helper.protocol.VERSION

    # --- Build CTAP2 parameters ---
    key_params = [{"type": "public-key", "alg": alg.alg} for alg in options.pub_key_cred_params]
    rp_dict = {"id": rp_id, "name": rp_name}
    user_dict = {"id": user.id, "name": user.name, "displayName": user.display_name}

    exclude = None
    if options.exclude_credentials:
        exclude = [
            {"type": "public-key", "id": c.id}
            for c in options.exclude_credentials
        ]

    print("\n>>> Touch your YubiKey to complete registration …\n")

    # --- Call authenticator ---
    try:
        att_resp = ctap2.make_credential(
            client_data_hash=client_data_hash,
            rp=rp_dict,
            user=user_dict,
            key_params=key_params,
            exclude_list=exclude,
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_uv_protocol,
        )
    except CtapError as e:
        if e.code == CtapError.ERR.CREDENTIAL_EXCLUDED:
            raise RuntimeError(
                "This YubiKey already has a credential registered for this RP. "
                "Remove it first or use a different key."
            ) from e
        raise

    auth_data: AuthenticatorData = att_resp.auth_data
    credential_data: AttestedCredentialData = auth_data.credential_data

    if credential_data is None:
        raise RuntimeError("Authenticator did not return credential data")

    # --- Verify with server ---
    # We need to build a RegistrationResponse-like dict that the server can verify
    from fido2.webauthn import AttestationObject, AuthenticatorAttestationResponse
    att_obj = AttestationObject.create(att_resp.fmt, att_resp.auth_data, att_resp.att_stmt)

    result = server.register_complete(
        state,
        response={
            "id": credential_data.credential_id,
            "rawId": credential_data.credential_id,
            "response": AuthenticatorAttestationResponse(
                client_data=client_data,
                attestation_object=att_obj,
            ),
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
        },
    )

    # --- Persist ---
    entries = _load_credentials(store_path)
    entries.append({
        "credential_id": credential_data.credential_id.hex(),
        "attested_credential_data": credential_data.hex(),
        "user_name": user_name,
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    _save_credentials(store_path, entries)

    print(f"✓ Registration complete. Credential ID: {credential_data.credential_id.hex()[:16]}…")
    return credential_data


# ---------------------------------------------------------------------------
# Assertion  (per-request touch verification)
# ---------------------------------------------------------------------------

class AssertionResult:
    """Result of a FIDO2 assertion (touch verification)."""

    def __init__(self, success: bool, credential_id: bytes | None = None,
                 error: str | None = None):
        self.success = success
        self.credential_id = credential_id
        self.error = error


def assert_touch(
    rp_id: str,
    rp_name: str,
    store_path: str,
    timeout_seconds: int = 60,
) -> AssertionResult:
    """Run a FIDO2 assertion to verify physical presence (YubiKey touch).

    This is called on every credential request.  It:
    1. Generates a challenge via Fido2Server
    2. Sends it to the YubiKey over HID
    3. Waits for the user to touch the key (up to timeout_seconds)
    4. Verifies the signed response

    Returns an AssertionResult indicating success or failure.
    """
    _require_fido2()
    # --- Load registered credentials ---
    credentials = get_registered_credentials(store_path)
    if not credentials:
        return AssertionResult(
            success=False,
            error="No registered credentials. Run setup first.",
        )

    # --- Get device ---
    try:
        device = get_device()
    except RuntimeError as e:
        return AssertionResult(success=False, error=str(e))

    ctap2 = Ctap2(device)
    server = _build_server(rp_id, rp_name)
    origin = _origin_for_rp(rp_id)

    # --- Generate challenge ---
    request_options, state = server.authenticate_begin(
        credentials=credentials,
        user_verification="discouraged",
    )

    options = request_options.public_key
    challenge = options.challenge

    # --- Build client data ---
    client_data = _make_client_data("webauthn.get", challenge, origin)
    client_data_hash = hashlib.sha256(client_data).digest()

    # --- PIN handling ---
    pin_uv_param = None
    pin_uv_protocol = None
    cp_result = _get_pin_if_needed(ctap2)
    if cp_result[0] is not None:
        pin_helper, pin = cp_result
        pin_token = pin_helper.get_pin_token(
            pin, ClientPin.PERMISSION.GET_ASSERTION, rp_id
        )
        pin_uv_param = pin_helper.protocol.authenticate(pin_token, client_data_hash)
        pin_uv_protocol = pin_helper.protocol.VERSION

    # --- Build allow list ---
    allow_list = [
        {"type": "public-key", "id": cred.credential_id}
        for cred in credentials
    ]

    # --- Call authenticator with timeout ---
    timeout_event = threading.Event()
    timer = threading.Timer(timeout_seconds, timeout_event.set)
    timer.daemon = True
    timer.start()

    try:
        assertions = ctap2.get_assertions(
            rp_id=rp_id,
            client_data_hash=client_data_hash,
            allow_list=allow_list,
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_uv_protocol,
            event=timeout_event,
        )
    except CtapError as e:
        timer.cancel()
        if e.code == CtapError.ERR.KEEPALIVE_CANCEL:
            return AssertionResult(success=False, error="timeout")
        if e.code == CtapError.ERR.NO_CREDENTIALS:
            return AssertionResult(
                success=False,
                error="YubiKey has no matching credentials. Re-register.",
            )
        if e.code == CtapError.ERR.OPERATION_DENIED:
            return AssertionResult(success=False, error="denied")
        return AssertionResult(success=False, error=f"CTAP error: {e.code.name}")
    except Exception as e:
        timer.cancel()
        return AssertionResult(success=False, error=f"Unexpected error: {e}")
    finally:
        timer.cancel()

    if not assertions:
        return AssertionResult(success=False, error="No assertion returned")

    assertion = assertions[0]

    # --- Verify with server ---
    try:
        from fido2.webauthn import AuthenticatorAssertionResponse

        assertion_response = {
            "id": assertion.credential["id"],
            "rawId": assertion.credential["id"],
            "response": AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=assertion.auth_data,
                signature=assertion.signature,
            ),
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
        }

        server.authenticate_complete(
            state,
            credentials=credentials,
            response=assertion_response,
        )
    except Exception as e:
        return AssertionResult(
            success=False,
            error=f"Assertion verification failed: {e}",
        )

    cred_id = assertion.credential["id"]
    logger.info("Assertion verified for credential %s", cred_id.hex()[:16])
    return AssertionResult(success=True, credential_id=cred_id)
