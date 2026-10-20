"""Key Registry and Key Lifecycle Management for AI Firewall.

Manages Ed25519 public keys, key ownership validation, active validity windows,
key rotation, and revocation registries.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


class KeyRegistryError(Exception):
    """Base exception for Key Registry operations."""


class KeyNotFoundError(KeyRegistryError):
    """Raised when a queried key ID does not exist in the registry."""


class KeyRevokedError(KeyRegistryError):
    """Raised when a key is marked as revoked in the registry."""


class KeyExpiredError(KeyRegistryError):
    """Raised when a key is used outside its active validity window."""


class KeyOwnershipError(KeyRegistryError):
    """Raised when the key owner does not match the claimed principal."""


_KEY_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{4,64}$")
_HEX_64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


def _parse_iso_utc(ts_str: str) -> datetime:
    """Parses ISO 8601 UTC timestamp ending in 'Z'."""
    if not ts_str.endswith("Z"):
        raise ValueError(f"Timestamp must end with 'Z' (UTC): {ts_str}")
    # Remove 'Z' and parse as UTC
    clean = ts_str[:-1]
    dt = datetime.fromisoformat(clean)
    return dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class KeyRecord:
    """Immutable public key registration record."""

    key_id: str
    owner_user_id: str
    public_key_hex: str
    not_before_utc: str
    not_after_utc: str
    is_revoked: bool = False
    revoked_at_utc: Optional[str] = None
    revocation_reason: Optional[str] = None

    def __post_init__(self) -> None:
        if not _KEY_ID_REGEX.match(self.key_id):
            raise KeyRegistryError(f"Invalid key_id format: {self.key_id!r}")
        if not self.owner_user_id:
            raise KeyRegistryError("owner_user_id cannot be empty")
        if not _HEX_64_REGEX.match(self.public_key_hex):
            raise KeyRegistryError(
                f"public_key_hex must be exactly 64 hexadecimal characters (32 raw bytes), got: {len(self.public_key_hex)}"
            )
        # Validate timestamp formats
        _parse_iso_utc(self.not_before_utc)
        _parse_iso_utc(self.not_after_utc)
        if self.is_revoked and self.revoked_at_utc is not None:
            _parse_iso_utc(self.revoked_at_utc)


class KeyRegistry:
    """In-memory key registry managing public keys, rotation, and revocation."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyRecord] = {}

    def register_key(self, record: KeyRecord) -> None:
        """Registers a public key record."""
        if record.key_id in self._keys:
            raise KeyRegistryError(f"Key ID {record.key_id!r} already registered")
        self._keys[record.key_id] = record

    def revoke_key(self, key_id: str, revoked_at_utc: str, reason: str = "Key compromised/rotated") -> None:
        """Marks an existing key as revoked."""
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Cannot revoke nonexistent key: {key_id}")
        existing = self._keys[key_id]
        _parse_iso_utc(revoked_at_utc)
        revoked_record = KeyRecord(
            key_id=existing.key_id,
            owner_user_id=existing.owner_user_id,
            public_key_hex=existing.public_key_hex,
            not_before_utc=existing.not_before_utc,
            not_after_utc=existing.not_after_utc,
            is_revoked=True,
            revoked_at_utc=revoked_at_utc,
            revocation_reason=reason,
        )
        self._keys[key_id] = revoked_record

    def get_key(self, key_id: str) -> KeyRecord:
        """Retrieves raw key record without evaluation."""
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Key {key_id!r} not found in registry")
        return self._keys[key_id]

    def validate_and_get_public_key(
        self,
        key_id: str,
        expected_owner: str,
        verification_time_utc: Optional[str] = None,
    ) -> ed25519.Ed25519PublicKey:
        """Validates key status, ownership, revocation, and validity window.

        Args:
            key_id: Public key identifier.
            expected_owner: Claimed reviewer or system user identity.
            verification_time_utc: Evaluation timestamp (ISO 8601 with 'Z'). Defaults to current UTC.

        Returns:
            The loaded Ed25519PublicKey instance ready for signature verification.

        Raises:
            KeyNotFoundError: If key does not exist.
            KeyOwnershipError: If key is not owned by expected_owner.
            KeyRevokedError: If key has been revoked.
            KeyExpiredError: If verification time is outside [not_before, not_after].
        """
        record = self.get_key(key_id)

        # 1. Ownership check
        if record.owner_user_id != expected_owner:
            raise KeyOwnershipError(
                f"Key ownership mismatch: key {key_id!r} is owned by {record.owner_user_id!r}, "
                f"not claimed owner {expected_owner!r}"
            )

        # 2. Revocation check
        if record.is_revoked:
            raise KeyRevokedError(
                f"Key {key_id!r} was revoked at {record.revoked_at_utc} (Reason: {record.revocation_reason})"
            )

        # 3. Temporal validity check
        if verification_time_utc is None:
            v_time = datetime.now(timezone.utc)
        else:
            v_time = _parse_iso_utc(verification_time_utc)

        not_before = _parse_iso_utc(record.not_before_utc)
        not_after = _parse_iso_utc(record.not_after_utc)

        if v_time < not_before:
            raise KeyExpiredError(f"Key {key_id!r} is not yet valid (valid from {record.not_before_utc})")
        if v_time > not_after:
            raise KeyExpiredError(f"Key {key_id!r} expired at {record.not_after_utc}")

        # 4. Load raw Ed25519 public key bytes
        pub_bytes = bytes.fromhex(record.public_key_hex)
        return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)


def generate_dev_ed25519_keypair(
    key_id: str,
    owner_user_id: str,
    not_before_utc: str = "2026-01-01T00:00:00.000000Z",
    not_after_utc: str = "2027-01-01T00:00:00.000000Z",
) -> tuple[ed25519.Ed25519PrivateKey, KeyRecord]:
    """Helper for tests and development to generate keypair without hardcoding secrets."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes_raw()
    record = KeyRecord(
        key_id=key_id,
        owner_user_id=owner_user_id,
        public_key_hex=pub_bytes.hex(),
        not_before_utc=not_before_utc,
        not_after_utc=not_after_utc,
    )
    return private_key, record
