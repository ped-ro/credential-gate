"""Bitwarden CLI integration for Credential Gate.

Wraps the `bw` CLI to unlock the vault and fetch individual items.
Session tokens are cached in memory with a configurable timeout.

Phase 2 adds BitwardenSessionManager which handles the full session
lifecycle: Keychain password retrieval, proactive refresh, error
detection with automatic retry, and degraded-mode reporting.
"""

import enum
import json
import logging
import shutil
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

ALLOWED_FIELDS = {"password", "username", "uri", "notes", "totp"}

# Auth/session error substrings from `bw` CLI stderr
_SESSION_ERROR_INDICATORS = [
    "session key is invalid",
    "you are not logged in",
    "vault is locked",
    "not logged in",
    "invalid session",
    "session expired",
]


class BitwardenError(Exception):
    pass


class BitwardenUnavailableError(BitwardenError):
    """Raised when the circuit breaker is open or Bitwarden failed.

    Distinct from other BW errors — signals that the caller should
    check the offline cache for a cached credential.
    """
    pass


class SessionState(enum.Enum):
    """Bitwarden session lifecycle states."""
    NO_SESSION = "no_session"
    ACTIVE = "active"
    EXPIRED = "expired"
    LOCKED = "locked"


class BitwardenClient:
    def __init__(self, cli_path: str | None = None, session_timeout: int = 300):
        self._cli = cli_path or shutil.which("bw") or "bw"
        self._session: str | None = None
        self._session_expires: float = 0
        self._session_timeout = session_timeout

    def _run(self, *args: str, session: bool = True) -> str:
        """Run a bw CLI command and return stdout."""
        cmd = [self._cli, *args, "--nointeraction", "--raw"]
        if session and self._session:
            cmd.extend(["--session", self._session])

        logger.debug("Running: bw %s", " ".join(args))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            raise BitwardenError(
                f"Bitwarden CLI not found at '{self._cli}'. "
                "Install with: brew install bitwarden-cli"
            )
        except subprocess.TimeoutExpired:
            raise BitwardenError("Bitwarden CLI timed out")

        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise BitwardenError(f"bw {args[0]} failed: {stderr or result.stdout.strip()}")

        return result.stdout.strip()

    def status(self) -> dict:
        """Get vault status."""
        raw = self._run("status", session=False)
        return json.loads(raw)

    def is_unlocked(self) -> bool:
        """Check if the vault is currently unlocked with a valid session."""
        if not self._session or time.monotonic() > self._session_expires:
            return False
        try:
            st = self.status()
            return st.get("status") == "unlocked"
        except BitwardenError:
            return False

    def unlock(self, password: str | None = None) -> str:
        """Unlock the vault and cache the session token.

        If *password* is None, prompts interactively (only works for setup,
        not during API requests — for headless use set BW_PASSWORD env var
        or unlock manually and pass the session).
        """
        if self.is_unlocked():
            return self._session

        if password:
            session = self._run("unlock", password, session=False)
        else:
            # Try to unlock with env var or manual prompt
            import os
            pw = os.environ.get("BW_PASSWORD")
            if pw:
                session = self._run("unlock", pw, session=False)
            else:
                import getpass
                pw = getpass.getpass("Bitwarden master password: ")
                session = self._run("unlock", pw, session=False)

        self._session = session
        self._session_expires = time.monotonic() + self._session_timeout
        logger.info("Bitwarden vault unlocked")
        return session

    def set_session(self, session: str) -> None:
        """Set an externally-obtained session token (e.g. from `bw unlock`)."""
        self._session = session
        self._session_expires = time.monotonic() + self._session_timeout

    def get_item(self, name: str) -> dict:
        """Fetch a vault item by name or ID. Returns the parsed JSON item."""
        if not self._session:
            raise BitwardenError("Vault is locked. Unlock first.")

        raw = self._run("get", "item", name)
        return json.loads(raw)

    def get_totp(self, name: str) -> str:
        """Fetch the current TOTP code for an item."""
        if not self._session:
            raise BitwardenError("Vault is locked. Unlock first.")

        return self._run("get", "totp", name)

    def extract_fields(self, item: dict, requested: list[str]) -> dict:
        """Extract only the requested fields from a Bitwarden item.

        Supports: password, username, uri, notes, totp, and custom field names.
        """
        result = {}
        login = item.get("login", {}) or {}

        for field_name in requested:
            if field_name == "password":
                result["password"] = login.get("password")
            elif field_name == "username":
                result["username"] = login.get("username")
            elif field_name == "uri":
                uris = login.get("uris")
                if uris:
                    result["uri"] = uris[0].get("uri") if uris else None
                else:
                    result["uri"] = None
            elif field_name == "notes":
                result["notes"] = item.get("notes")
            elif field_name == "totp":
                # TOTP is handled separately via `bw get totp`
                result["totp"] = None  # caller should use get_totp()
            else:
                # Custom field
                fields = item.get("fields") or []
                match = next(
                    (f for f in fields if f.get("name") == field_name), None
                )
                result[field_name] = match.get("value") if match else None

        return result

    def sync(self) -> None:
        """Force a vault sync."""
        self._run("sync")
        logger.info("Bitwarden vault synced")

    def generate_password(self, length: int = 32) -> str:
        """Generate a random password using the Bitwarden CLI."""
        return self._run("generate", "-ulns", f"--length={length}", session=False)

    def rotate_credential(self, item_name: str, field: str = "password") -> str:
        """Generate a new password and update a Bitwarden vault item.

        Returns the new password. Only supports the login password field.
        Raises BitwardenError on failure.
        """
        import base64

        # 1. Generate new password
        new_password = self.generate_password()

        # 2. Get the full item
        item = self.get_item(item_name)
        item_id = item.get("id")
        if not item_id:
            raise BitwardenError(f"Cannot find item ID for '{item_name}'")

        # 3. Update the password in the item JSON
        if field == "password":
            login = item.get("login", {})
            if login is None:
                login = {}
            login["password"] = new_password
            item["login"] = login
        else:
            raise BitwardenError(f"Rotation of field '{field}' is not supported (only 'password')")

        # 4. Encode updated item as base64 and push to Bitwarden
        item_json = json.dumps(item).encode()
        item_b64 = base64.b64encode(item_json).decode()

        self._run("edit", "item", item_id, item_b64)
        logger.info("Rotated credential '%s' (field=%s)", item_name, field)

        return new_password


# ---------------------------------------------------------------------------
# Keychain helpers (macOS `security` CLI)
# ---------------------------------------------------------------------------

def keychain_store(service: str, account: str, password: str) -> None:
    """Store a password in macOS Keychain.

    Uses `security add-generic-password` with -U to update if it already exists.
    """
    try:
        subprocess.run(
            [
                "security", "add-generic-password",
                "-s", service,
                "-a", account,
                "-w", password,
                "-U",  # update if exists
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise BitwardenError(f"Failed to store in Keychain: {e.stderr.strip()}")


def keychain_retrieve(service: str, account: str) -> str | None:
    """Retrieve a password from macOS Keychain.

    Returns None if the entry doesn't exist.
    """
    try:
        result = subprocess.run(
            [
                "security", "find-generic-password",
                "-s", service,
                "-a", account,
                "-w",  # output password only
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def keychain_delete(service: str, account: str) -> bool:
    """Delete a password from macOS Keychain. Returns True if deleted."""
    try:
        subprocess.run(
            [
                "security", "delete-generic-password",
                "-s", service,
                "-a", account,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


# ---------------------------------------------------------------------------
# Session Manager (Phase 2)
# ---------------------------------------------------------------------------

def _is_session_error(error_msg: str) -> bool:
    """Check if a BitwardenError message indicates a session/auth problem."""
    lower = error_msg.lower()
    return any(indicator in lower for indicator in _SESSION_ERROR_INDICATORS)


class BitwardenSessionManager:
    """Manages the full Bitwarden session lifecycle.

    State machine:
        NO_SESSION → (unlock with Keychain password) → ACTIVE
        ACTIVE → (token expires or auth error) → EXPIRED
        EXPIRED → (re-unlock) → ACTIVE
        EXPIRED → (re-unlock fails) → LOCKED (notify, queue requests)

    Features:
        - Reads master password from macOS Keychain (never stored on disk)
        - Caches session token in memory only
        - Proactive refresh before expiry
        - Automatic retry on session errors
        - Degraded mode reporting when locked
    """

    def __init__(
        self,
        cli_path: str | None = None,
        session_timeout: int = 300,
        refresh_minutes: int = 10,
        keychain_service: str = "credential-gate",
        keychain_account: str = "bitwarden",
    ):
        self._client = BitwardenClient(
            cli_path=cli_path,
            session_timeout=session_timeout,
        )
        self._state = SessionState.NO_SESSION
        self._lock = threading.Lock()
        self._refresh_minutes = refresh_minutes
        self._keychain_service = keychain_service
        self._keychain_account = keychain_account
        self._session_obtained_at: float = 0
        self._last_activity: float = 0
        self._refresh_timer: threading.Timer | None = None

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def client(self) -> BitwardenClient:
        return self._client

    def _get_password_from_keychain(self) -> str | None:
        """Retrieve the Bitwarden master password from macOS Keychain."""
        return keychain_retrieve(self._keychain_service, self._keychain_account)

    def get_master_password_from_keychain(self) -> str | None:
        """Public accessor for the Keychain password (Phase 12: silver tier cache key)."""
        return self._get_password_from_keychain()

    def _do_unlock(self) -> bool:
        """Attempt to unlock using the Keychain-stored password.

        Returns True on success, False on failure.
        """
        password = self._get_password_from_keychain()
        if not password:
            logger.error(
                "No Bitwarden master password found in Keychain "
                "(service=%s, account=%s). Run: python setup.py store-password",
                self._keychain_service,
                self._keychain_account,
            )
            self._state = SessionState.NO_SESSION
            return False

        try:
            self._client.unlock(password=password)
            self._state = SessionState.ACTIVE
            self._session_obtained_at = time.monotonic()
            self._last_activity = time.monotonic()
            logger.info("Bitwarden session established via Keychain")
            self._schedule_refresh()
            return True
        except BitwardenError as e:
            logger.error("Failed to unlock Bitwarden: %s", e)
            self._state = SessionState.LOCKED
            return False

    def _schedule_refresh(self) -> None:
        """Schedule a proactive session refresh."""
        if self._refresh_timer is not None:
            self._refresh_timer.cancel()

        interval = self._refresh_minutes * 60
        self._refresh_timer = threading.Timer(interval, self._proactive_refresh)
        self._refresh_timer.daemon = True
        self._refresh_timer.start()

    def _proactive_refresh(self) -> None:
        """Proactively re-unlock before the session expires.

        Only refreshes if there has been activity since the last refresh.
        """
        with self._lock:
            if self._state != SessionState.ACTIVE:
                return

            # Only refresh if there's been activity in the refresh window
            time_since_activity = time.monotonic() - self._last_activity
            if time_since_activity > self._refresh_minutes * 60:
                logger.debug(
                    "No activity in last %d minutes, skipping proactive refresh",
                    self._refresh_minutes,
                )
                # Still schedule the next one in case activity resumes
                self._schedule_refresh()
                return

            logger.info("Proactive session refresh")
            # Force re-unlock by clearing the current session
            self._client._session = None
            self._client._session_expires = 0
            if not self._do_unlock():
                logger.error("Proactive refresh failed — session now LOCKED")

    def startup(self) -> SessionState:
        """Initialize session on service startup.

        Attempts to unlock using Keychain password. Returns the resulting state.
        """
        with self._lock:
            password = self._get_password_from_keychain()
            if not password:
                logger.warning(
                    "No Bitwarden password in Keychain. "
                    "Service starting in degraded mode. "
                    "Run: python setup.py store-password"
                )
                self._state = SessionState.NO_SESSION
                return self._state

            if self._do_unlock():
                return self._state

            # Unlock failed — start in locked state
            return self._state

    def ensure_unlocked(self) -> None:
        """Ensure the vault is unlocked, re-unlocking if needed.

        Call this before any vault operation. Raises BitwardenError if
        the vault cannot be unlocked.
        """
        with self._lock:
            self._last_activity = time.monotonic()

            if self._state == SessionState.ACTIVE and self._client.is_unlocked():
                return

            # Session expired or invalid — try to re-unlock
            if self._state in (SessionState.ACTIVE, SessionState.EXPIRED):
                logger.info("Session expired or invalid, re-unlocking")
                self._state = SessionState.EXPIRED
                self._client._session = None
                self._client._session_expires = 0
                if self._do_unlock():
                    return

            # No session or locked — try to unlock from Keychain
            if self._state in (SessionState.NO_SESSION, SessionState.LOCKED):
                if self._do_unlock():
                    return

            # All attempts failed
            if self._state == SessionState.NO_SESSION:
                raise BitwardenError(
                    "No Bitwarden password in Keychain. "
                    "Run: python setup.py store-password"
                )
            raise BitwardenError(
                "Bitwarden vault is locked and cannot be unlocked. "
                "Check master password in Keychain."
            )

    def get_item(self, name: str) -> dict:
        """Fetch a vault item with automatic session management.

        If the first attempt fails with a session error, re-unlocks and
        retries once.
        """
        self.ensure_unlocked()

        try:
            return self._client.get_item(name)
        except BitwardenError as e:
            if not _is_session_error(str(e)):
                raise

            # Session error — re-unlock and retry once
            logger.warning("Session error fetching item, re-unlocking: %s", e)
            with self._lock:
                self._state = SessionState.EXPIRED
                self._client._session = None
                self._client._session_expires = 0
                if not self._do_unlock():
                    raise BitwardenError(
                        "Failed to re-unlock Bitwarden after session error"
                    )

            return self._client.get_item(name)

    def get_totp(self, name: str) -> str:
        """Fetch TOTP with automatic session management."""
        self.ensure_unlocked()

        try:
            return self._client.get_totp(name)
        except BitwardenError as e:
            if not _is_session_error(str(e)):
                raise

            logger.warning("Session error fetching TOTP, re-unlocking: %s", e)
            with self._lock:
                self._state = SessionState.EXPIRED
                self._client._session = None
                self._client._session_expires = 0
                if not self._do_unlock():
                    raise BitwardenError(
                        "Failed to re-unlock Bitwarden after session error"
                    )

            return self._client.get_totp(name)

    def extract_fields(self, item: dict, requested: list[str]) -> dict:
        """Delegate to the underlying client."""
        return self._client.extract_fields(item, requested)

    def rotate_credential(self, item_name: str, field: str = "password") -> str:
        """Rotate a credential with automatic session management.

        Returns the new password. Best-effort — errors are raised, caller
        should catch and log.
        """
        self.ensure_unlocked()

        try:
            return self._client.rotate_credential(item_name, field)
        except BitwardenError as e:
            if not _is_session_error(str(e)):
                raise

            logger.warning("Session error during rotation, re-unlocking: %s", e)
            with self._lock:
                self._state = SessionState.EXPIRED
                self._client._session = None
                self._client._session_expires = 0
                if not self._do_unlock():
                    raise BitwardenError(
                        "Failed to re-unlock Bitwarden after session error"
                    )

            return self._client.rotate_credential(item_name, field)

    def shutdown(self) -> None:
        """Clean up resources (cancel timers)."""
        if self._refresh_timer is not None:
            self._refresh_timer.cancel()
            self._refresh_timer = None
