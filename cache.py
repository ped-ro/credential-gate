"""Encrypted credential cache for offline operation.

When Bitwarden is unreachable, the gate can serve recently-approved
credentials from an encrypted local cache — but only with explicit
YubiKey approval (higher bar than normal operation).

Encryption: AES-256-GCM with a key derived from a FIDO2 assertion via
HKDF.  The encryption key is derived at service startup when the YubiKey
is present.  If the YubiKey is removed, the cache file is unreadable.

Phase 12 addition: silver tier (phone-only) can derive the cache key
from a passphrase stored in macOS Keychain instead of a FIDO2 assertion.
Uses PBKDF2-HMAC-SHA256 with a high iteration count.

Cache entries expire independently of Bitwarden — a cached credential
has its own TTL (default: 4 hours, configurable per risk level).

Critical credentials are NEVER cached — this is hardcoded and
non-configurable.

Phase 11 implementation, extended in Phase 12.
"""

import json
import logging
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

# Cache TTL by risk level (hours).  Critical is ALWAYS 0 — never cached.
DEFAULT_CACHE_TTLS = {
    "low": 8.0,
    "standard": 4.0,
    "high": 1.0,
    "critical": 0.0,
}


class EncryptedCredentialCache:
    """Encrypted at-rest credential cache for offline operation.

    Encryption: AES-256-GCM with a key derived from a YubiKey FIDO2 assertion.
    The encryption key is derived at service startup when the YubiKey is present.
    If the YubiKey is removed, the cache becomes unreadable.

    Cache entries expire independently of Bitwarden — a cached credential
    has its own TTL (default: 4 hours, configurable per risk level).
    """

    def __init__(self, cache_path: str, config: dict):
        self._cache_path = Path(cache_path)
        self._encryption_key: bytes | None = None
        self._cache: dict = {}  # decrypted in-memory copy
        self._config = config

    def derive_key(self, fido_assertion_result: bytes) -> None:
        """Derive the cache encryption key from a FIDO2 assertion.

        Called once at startup with YubiKey present.
        Uses HKDF to derive a 256-bit AES key from the FIDO2 signature.
        The key is held in memory only — never written to disk.

        Args:
            fido_assertion_result: Raw bytes from a FIDO2 assertion
                (authenticator data + signature).
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"credential-gate-cache-v1",
            info=b"cache-encryption-key",
        )
        self._encryption_key = hkdf.derive(fido_assertion_result)
        logger.info("Cache encryption key derived from FIDO2 assertion")

        # Try to load existing cache from disk
        self._read_and_decrypt()

    def derive_key_from_passphrase(self, passphrase: str) -> None:
        """Derive the cache encryption key from a passphrase (silver tier).

        Used when no YubiKey is present.  The passphrase is the Bitwarden
        master password retrieved from macOS Keychain — it never leaves
        memory.

        Uses PBKDF2-HMAC-SHA256 with 600,000 iterations and a fixed salt
        (the salt is not secret — it just ensures the derived key differs
        from the Bitwarden key derivation).

        Args:
            passphrase: The Bitwarden master password from Keychain.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"credential-gate-cache-silver-v1",
            iterations=600_000,
        )
        self._encryption_key = kdf.derive(passphrase.encode("utf-8"))
        logger.info("Cache encryption key derived from passphrase (silver tier)")

        # Try to load existing cache from disk
        self._read_and_decrypt()

    def is_initialized(self) -> bool:
        """Whether the encryption key has been derived (YubiKey was present at startup)."""
        return self._encryption_key is not None

    def store(self, credential_name: str, fields: dict, risk_level: str = "standard") -> None:
        """Cache a credential after a successful Bitwarden fetch.

        Called automatically after every approved credential request.
        The credential is encrypted and written to disk.

        Critical credentials are NEVER cached — this is hardcoded.

        Args:
            credential_name: Bitwarden item name
            fields: Dict of field_name -> field_value
            risk_level: Risk level from policy (determines TTL)
        """
        if not self._encryption_key:
            return

        # Critical credentials are NEVER cached — hardcoded, non-configurable
        if risk_level == "critical":
            logger.debug("Skipping cache for critical credential '%s'", credential_name)
            return

        # Determine TTL
        ttl_config = self._config.get("offline", {}).get("cache", {}).get("ttl_by_risk", {})
        # Always enforce critical = 0 regardless of config
        ttl_hours = ttl_config.get(risk_level, DEFAULT_CACHE_TTLS.get(risk_level, 4.0))
        if risk_level == "critical":
            ttl_hours = 0.0
        if ttl_hours <= 0:
            return

        # Check max entries
        max_entries = self._config.get("offline", {}).get("cache", {}).get("max_entries", 50)
        if len(self._cache) >= max_entries and credential_name not in self._cache:
            # Evict oldest entry to make room
            self._evict_oldest()

        self._cache[credential_name] = {
            "fields": fields,
            "cached_at": time.time(),
            "expires_at": time.time() + (ttl_hours * 3600),
            "risk_level": risk_level,
        }

        self._encrypt_and_write()
        logger.info(
            "Cached credential '%s' (risk=%s, TTL=%.1fh)",
            credential_name, risk_level, ttl_hours,
        )

    def get(self, credential_name: str) -> dict | None:
        """Retrieve a cached credential if it exists and hasn't expired.

        Returns None if:
        - Cache not initialized (no encryption key)
        - Credential not in cache
        - Credential has expired
        - Decryption fails (cache corrupted or key changed)
        """
        if not self._encryption_key:
            return None

        entry = self._cache.get(credential_name)
        if not entry:
            return None

        # Check expiry
        if time.time() > entry["expires_at"]:
            logger.info("Cache entry for '%s' has expired, removing", credential_name)
            del self._cache[credential_name]
            self._encrypt_and_write()
            return None

        return entry["fields"]

    def evict(self, credential_name: str) -> bool:
        """Remove a specific credential from cache (e.g. after rotation)."""
        if credential_name in self._cache:
            del self._cache[credential_name]
            if self._encryption_key:
                self._encrypt_and_write()
            logger.info("Evicted '%s' from cache", credential_name)
            return True
        return False

    def evict_all(self) -> int:
        """Clear the entire cache. Called during panic. Returns count evicted."""
        count = len(self._cache)
        self._cache.clear()
        if self._encryption_key:
            self._encrypt_and_write()
        if count:
            logger.warning("Evicted all %d entries from credential cache", count)
        return count

    def evict_expired(self) -> int:
        """Remove all expired entries. Called periodically by the daemon."""
        now = time.time()
        expired_keys = [
            k for k, v in self._cache.items()
            if now > v["expires_at"]
        ]
        for k in expired_keys:
            del self._cache[k]

        if expired_keys and self._encryption_key:
            self._encrypt_and_write()
            logger.info("Evicted %d expired cache entries", len(expired_keys))

        return len(expired_keys)

    def stats(self) -> dict:
        """Return cache statistics without exposing credential values.

        Returns:
            {
                "initialized": true,
                "entries": 5,
                "expired": 1,
                "oldest_entry_age_hours": 3.2,
                "total_size_bytes": 2048,
            }
        """
        now = time.time()
        expired_count = sum(
            1 for v in self._cache.values()
            if now > v["expires_at"]
        )

        oldest_age_hours = 0.0
        if self._cache:
            oldest_cached_at = min(v["cached_at"] for v in self._cache.values())
            oldest_age_hours = round((now - oldest_cached_at) / 3600, 2)

        total_size = 0
        if self._cache_path.exists():
            try:
                total_size = self._cache_path.stat().st_size
            except OSError:
                pass

        return {
            "initialized": self.is_initialized(),
            "entries": len(self._cache),
            "expired": expired_count,
            "oldest_entry_age_hours": oldest_age_hours,
            "total_size_bytes": total_size,
        }

    def _evict_oldest(self) -> None:
        """Evict the oldest cache entry to make room for a new one."""
        if not self._cache:
            return
        oldest_key = min(self._cache, key=lambda k: self._cache[k]["cached_at"])
        del self._cache[oldest_key]
        logger.debug("Evicted oldest cache entry '%s' (max entries reached)", oldest_key)

    def _encrypt_and_write(self) -> None:
        """Encrypt the in-memory cache and write to disk.

        Format: 12-byte nonce + ciphertext (AES-256-GCM)
        The entire cache is serialized as JSON and encrypted as one blob.
        """
        if not self._encryption_key:
            return

        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)

            plaintext = json.dumps(self._cache).encode("utf-8")
            aesgcm = AESGCM(self._encryption_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            with open(self._cache_path, "wb") as f:
                f.write(nonce + ciphertext)

        except Exception as e:
            logger.error("Failed to write encrypted cache: %s", e)

    def _read_and_decrypt(self) -> None:
        """Read from disk and decrypt into memory.

        If decryption fails (wrong key, corrupted file), start with empty cache.
        Log the failure but don't crash.
        """
        if not self._encryption_key:
            return

        if not self._cache_path.exists():
            logger.info("No existing cache file at %s — starting empty", self._cache_path)
            return

        try:
            with open(self._cache_path, "rb") as f:
                data = f.read()

            if len(data) < 13:  # 12-byte nonce + at least 1 byte
                logger.warning("Cache file too small, starting empty")
                self._cache = {}
                return

            nonce = data[:12]
            ciphertext = data[12:]

            aesgcm = AESGCM(self._encryption_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self._cache = json.loads(plaintext.decode("utf-8"))

            logger.info(
                "Loaded %d entries from encrypted cache", len(self._cache),
            )

        except Exception as e:
            logger.warning(
                "Failed to decrypt cache (wrong key or corrupted): %s — starting empty", e,
            )
            self._cache = {}
