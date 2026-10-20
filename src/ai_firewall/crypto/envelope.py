"""Authoritative Signed Approval Envelope Implementation for AI Firewall.

Implements the Phase 3.3 authoritative 13-field signing contract:
1. Strict domain-separated signing payload.
2. Ed25519 signature generation and verification.
3. Verification of reviewer identity, key status, expiration, and policy epoch.
4. Fail-closed rejection: signed REJECTED decisions cannot authorize execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ai_firewall.crypto.keys import KeyRegistry, KeyRegistryError


DOMAIN_TAG = "AI-FIREWALL-APPROVAL-V1"
SUPPORTED_ENVELOPE_VERSION = "1.0.0"

_APPROVAL_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{16,64}$")
_HEX_64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_32_NONCE_REGEX = re.compile(r"^[0-9a-fA-F]{32}$")
_HEX_128_SIG_REGEX = re.compile(r"^[0-9a-fA-F]{128}$")

_VALID_STATUSES = {"APPROVED", "REJECTED"}
_VALID_AUTH_LEVELS = {"STANDARD_PASSWORD", "MFA_TOTP", "MFA_HARDWARE_TOKEN"}

# Explicit allowed top-level keys for the envelope
_ENVELOPE_TOP_KEYS = {"envelope_version", "approval_id", "action_digest", "approval_status", "decision_claims", "cryptographic_proof"}
_DECISION_CLAIMS_KEYS = {
    "reviewer_user_id",
    "key_id",
    "auth_level",
    "issued_at_utc",
    "expires_at_utc",
    "policy_version",
    "policy_epoch",
    "single_use_nonce",
}
_CRYPTO_PROOF_KEYS = {"signature_algorithm", "signature_value"}


class ApprovalEnvelopeError(ValueError):
    """Base error for approval envelope validation and verification failures."""


class EnvelopeSchemaError(ApprovalEnvelopeError):
    """Raised when the envelope violates the formal schema or contains unknown fields."""


class EnvelopeVerificationError(ApprovalEnvelopeError):
    """Raised when signature verification or security constraints fail."""


class ExecutionNotAuthorizedError(ApprovalEnvelopeError):
    """Raised when attempting to authorize an action with an envelope that is not APPROVED."""


def _parse_iso_utc(ts_str: str) -> datetime:
    """Parses ISO 8601 UTC timestamp ending in 'Z'."""
    if not isinstance(ts_str, str) or not ts_str.endswith("Z"):
        raise EnvelopeSchemaError(f"Timestamp must be ISO 8601 string ending in 'Z': {ts_str!r}")
    clean = ts_str[:-1]
    try:
        dt = datetime.fromisoformat(clean)
        return dt.replace(tzinfo=timezone.utc)
    except Exception as exc:
        raise EnvelopeSchemaError(f"Invalid timestamp format {ts_str!r}: {exc}") from exc


def construct_signing_payload(
    envelope_version: str,
    approval_id: str,
    action_digest: str,
    approval_status: str,
    reviewer_user_id: str,
    key_id: str,
    auth_level: str,
    policy_version: str,
    policy_epoch: int,
    issued_at_utc: str,
    expires_at_utc: str,
    single_use_nonce: str,
) -> bytes:
    """Authoritative, single function that constructs the 13-field signing byte stream.

    The sequence contains exactly 13 newline-delimited (\\n), UTF-8 encoded text fields
    with no trailing newline.
    """
    if envelope_version != SUPPORTED_ENVELOPE_VERSION:
        raise EnvelopeSchemaError(f"Unsupported envelope_version: {envelope_version!r}")
    if not _APPROVAL_ID_REGEX.match(approval_id):
        raise EnvelopeSchemaError(f"Invalid approval_id format: {approval_id!r}")
    if not _HEX_64_REGEX.match(action_digest):
        raise EnvelopeSchemaError(f"action_digest must be 64 hexadecimal characters: {action_digest!r}")
    if approval_status not in _VALID_STATUSES:
        raise EnvelopeSchemaError(f"approval_status must be 'APPROVED' or 'REJECTED': {approval_status!r}")
    if not reviewer_user_id:
        raise EnvelopeSchemaError("reviewer_user_id cannot be empty")
    if not key_id:
        raise EnvelopeSchemaError("key_id cannot be empty")
    if auth_level not in _VALID_AUTH_LEVELS:
        raise EnvelopeSchemaError(f"Invalid auth_level: {auth_level!r}")
    if not policy_version:
        raise EnvelopeSchemaError("policy_version cannot be empty")
    if not isinstance(policy_epoch, int) or policy_epoch < 0:
        raise EnvelopeSchemaError(f"policy_epoch must be non-negative integer: {policy_epoch!r}")
    if not _HEX_32_NONCE_REGEX.match(single_use_nonce):
        raise EnvelopeSchemaError(f"single_use_nonce must be 32 hexadecimal characters: {single_use_nonce!r}")

    # Validate timestamps
    _parse_iso_utc(issued_at_utc)
    _parse_iso_utc(expires_at_utc)

    fields = [
        DOMAIN_TAG,
        envelope_version,
        approval_id,
        action_digest.lower(),
        approval_status,
        reviewer_user_id,
        key_id,
        auth_level,
        policy_version,
        str(policy_epoch),
        issued_at_utc,
        expires_at_utc,
        single_use_nonce.lower(),
    ]

    # Guard against delimiter injection
    for f in fields:
        if "\n" in f:
            raise EnvelopeSchemaError(f"Field contains newline character: {f!r}")

    return "\n".join(fields).encode("utf-8")


def sign_approval_envelope(
    approval_id: str,
    action_digest: str,
    approval_status: str,
    reviewer_user_id: str,
    key_id: str,
    auth_level: str,
    policy_version: str,
    policy_epoch: int,
    issued_at_utc: str,
    expires_at_utc: str,
    single_use_nonce: str,
    private_key: ed25519.Ed25519PrivateKey,
    envelope_version: str = SUPPORTED_ENVELOPE_VERSION,
) -> dict[str, Any]:
    """Constructs and signs a full Approval Envelope using an Ed25519 private key."""
    signing_bytes = construct_signing_payload(
        envelope_version=envelope_version,
        approval_id=approval_id,
        action_digest=action_digest,
        approval_status=approval_status,
        reviewer_user_id=reviewer_user_id,
        key_id=key_id,
        auth_level=auth_level,
        policy_version=policy_version,
        policy_epoch=policy_epoch,
        issued_at_utc=issued_at_utc,
        expires_at_utc=expires_at_utc,
        single_use_nonce=single_use_nonce,
    )

    signature_raw = private_key.sign(signing_bytes)
    signature_hex = signature_raw.hex()

    return {
        "envelope_version": envelope_version,
        "approval_id": approval_id,
        "action_digest": action_digest.lower(),
        "approval_status": approval_status,
        "decision_claims": {
            "reviewer_user_id": reviewer_user_id,
            "key_id": key_id,
            "auth_level": auth_level,
            "issued_at_utc": issued_at_utc,
            "expires_at_utc": expires_at_utc,
            "policy_version": policy_version,
            "policy_epoch": policy_epoch,
            "single_use_nonce": single_use_nonce.lower(),
        },
        "cryptographic_proof": {
            "signature_algorithm": "ED25519",
            "signature_value": signature_hex,
        },
    }


def verify_approval_envelope(
    envelope: dict[str, Any],
    key_registry: KeyRegistry,
    expected_action_digest: str,
    current_policy_epoch: int,
    current_time_utc: Optional[str] = None,
    enforce_execution_allowed: bool = True,
) -> bool:
    """Strictly validates and verifies an Approval Envelope against key registry and invariants.

    Args:
        envelope: Dictionary representing the approval envelope.
        key_registry: Registry containing public keys and revocation status.
        expected_action_digest: The SHA-256 digest of the proposed action identity.
        current_policy_epoch: Active gateway policy epoch integer.
        current_time_utc: Verification time (defaults to system UTC).
        enforce_execution_allowed: If True (default), raises ExecutionNotAuthorizedError
            if approval_status != 'APPROVED'.

    Returns:
        True if all cryptographic and authorization checks pass.

    Raises:
        EnvelopeSchemaError: If schema is violated or unknown fields exist.
        EnvelopeVerificationError: If signature, digest, timestamps, or epoch fail.
        ExecutionNotAuthorizedError: If approval_status is REJECTED when authorizing execution.
    """
    if not isinstance(envelope, dict):
        raise EnvelopeSchemaError("Approval envelope must be a dictionary")

    # 1. Strict schema key validation (reject unknown fields)
    extra_top = set(envelope.keys()) - _ENVELOPE_TOP_KEYS
    if extra_top:
        raise EnvelopeSchemaError(f"Unknown top-level fields in envelope: {sorted(extra_top)}")

    envelope_version = envelope.get("envelope_version")
    if envelope_version != SUPPORTED_ENVELOPE_VERSION:
        raise EnvelopeSchemaError(f"Unsupported envelope_version: {envelope_version!r}")

    approval_id = envelope.get("approval_id")
    action_digest = envelope.get("action_digest")
    approval_status = envelope.get("approval_status")
    claims = envelope.get("decision_claims")
    proof = envelope.get("cryptographic_proof")

    if not isinstance(claims, dict):
        raise EnvelopeSchemaError("decision_claims must be an object/dict")
    extra_claims = set(claims.keys()) - _DECISION_CLAIMS_KEYS
    if extra_claims:
        raise EnvelopeSchemaError(f"Unknown fields in decision_claims: {sorted(extra_claims)}")

    if not isinstance(proof, dict):
        raise EnvelopeSchemaError("cryptographic_proof must be an object/dict")
    extra_proof = set(proof.keys()) - _CRYPTO_PROOF_KEYS
    if extra_proof:
        raise EnvelopeSchemaError(f"Unknown fields in cryptographic_proof: {sorted(extra_proof)}")

    # 2. Status verification
    if approval_status not in _VALID_STATUSES:
        raise EnvelopeSchemaError(f"Invalid approval_status: {approval_status!r}")

    if enforce_execution_allowed and approval_status != "APPROVED":
        raise ExecutionNotAuthorizedError(
            f"Execution rejected: approval status is {approval_status!r}, must be 'APPROVED'"
        )

    # 3. Action digest match
    if str(action_digest).lower() != str(expected_action_digest).lower():
        raise EnvelopeVerificationError(
            f"Action digest mismatch! Envelope binds: {action_digest}, Target action is: {expected_action_digest}"
        )

    # 4. Extract claims and construct authoritative signing payload
    reviewer_user_id = claims.get("reviewer_user_id")
    key_id = claims.get("key_id")
    auth_level = claims.get("auth_level")
    policy_version = claims.get("policy_version")
    policy_epoch = claims.get("policy_epoch")
    issued_at_utc = claims.get("issued_at_utc")
    expires_at_utc = claims.get("expires_at_utc")
    single_use_nonce = claims.get("single_use_nonce")

    signing_bytes = construct_signing_payload(
        envelope_version=envelope_version,
        approval_id=approval_id,
        action_digest=action_digest,
        approval_status=approval_status,
        reviewer_user_id=reviewer_user_id,
        key_id=key_id,
        auth_level=auth_level,
        policy_version=policy_version,
        policy_epoch=policy_epoch,
        issued_at_utc=issued_at_utc,
        expires_at_utc=expires_at_utc,
        single_use_nonce=single_use_nonce,
    )

    # 5. Proof validation
    sig_alg = proof.get("signature_algorithm")
    if sig_alg != "ED25519":
        raise EnvelopeSchemaError(f"Unsupported signature_algorithm: {sig_alg!r}")

    sig_hex = proof.get("signature_value")
    if not isinstance(sig_hex, str) or not _HEX_128_SIG_REGEX.match(sig_hex):
        raise EnvelopeVerificationError(
            f"signature_value must be exactly 128 hex chars (64 bytes), got length {len(sig_hex) if isinstance(sig_hex, str) else type(sig_hex)}"
        )
    signature_raw = bytes.fromhex(sig_hex)

    # 6. Retrieve and validate key from KeyRegistry
    if current_time_utc is None:
        eval_time = datetime.now(timezone.utc)
    else:
        eval_time = _parse_iso_utc(current_time_utc)

    try:
        public_key = key_registry.validate_and_get_public_key(
            key_id=key_id,
            expected_owner=reviewer_user_id,
            verification_time_utc=eval_time.isoformat().replace("+00:00", "Z"),
        )
    except KeyRegistryError as exc:
        raise EnvelopeVerificationError(f"Key verification failed: {exc}") from exc

    # 7. Cryptographic Ed25519 verification
    try:
        public_key.verify(signature_raw, signing_bytes)
    except InvalidSignature as exc:
        raise EnvelopeVerificationError("Cryptographic signature verification failed (invalid signature)") from exc

    # 8. Envelope temporal validity check
    expires_dt = _parse_iso_utc(expires_at_utc)
    if eval_time > expires_dt:
        raise EnvelopeVerificationError(f"Approval envelope has expired: current {eval_time} > expires {expires_dt}")

    # 9. Policy epoch validity check
    if policy_epoch != current_policy_epoch:
        raise EnvelopeVerificationError(
            f"Stale policy epoch: envelope policy_epoch={policy_epoch} != gateway current_epoch={current_policy_epoch}"
        )

    return True

