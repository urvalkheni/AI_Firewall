"""Signed Authorization Decision Record for AI Firewall.

Cryptographically binds policy evaluations, risk scoring, context taint, and
required authentication levels into an immutable gateway-issued record.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ai_firewall.crypto.keys import KeyRegistry, KeyRegistryError


RECORD_DOMAIN_TAG = "AI-FIREWALL-DECISION-V1"
SUPPORTED_RECORD_VERSION = "1.0.0"

_DECISION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{16,64}$")
_HEX_64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_128_SIG_REGEX = re.compile(r"^[0-9a-fA-F]{128}$")

_VALID_VERDICTS = {"ALLOW", "DENY", "APPROVAL_REQUIRED", "RETRY_REQUIRED"}
_VALID_RISK_TIERS = {"LOW_RISK", "MODERATE_RISK", "HIGH_CONSEQUENCE"}
_VALID_TAINT_LEVELS = {"CLEAN", "SUSPICIOUS_EXTERNAL", "UNTRUSTED_INDIRECT_INPUT"}
_VALID_AUTH_LEVELS = {"NONE", "STANDARD_PASSWORD", "MFA_TOTP", "MFA_HARDWARE_TOKEN"}

_RECORD_TOP_KEYS = {
    "record_version",
    "decision_id",
    "action_digest",
    "verdict",
    "policy_binding",
    "evaluated_risk",
    "gateway_signature",
}
_POLICY_BINDING_KEYS = {"policy_version", "policy_epoch", "issued_at_utc"}
_EVALUATED_RISK_KEYS = {"score", "risk_tier", "provenance_taint", "required_auth_level"}
_GATEWAY_SIG_KEYS = {"signer_key_id", "signature_algorithm", "signature_value"}


class DecisionRecordError(ValueError):
    """Base error for Authorization Decision Record operations."""


class DecisionRecordSchemaError(DecisionRecordError):
    """Raised when record violates formal schema or contains unknown fields."""


class DecisionRecordVerificationError(DecisionRecordError):
    """Raised when record cryptographic verification or consistency checks fail."""


def _parse_iso_utc(ts_str: str) -> datetime:
    """Parses ISO 8601 UTC timestamp ending in 'Z'."""
    if not isinstance(ts_str, str) or not ts_str.endswith("Z"):
        raise DecisionRecordSchemaError(f"Timestamp must be ISO 8601 string ending in 'Z': {ts_str!r}")
    clean = ts_str[:-1]
    try:
        dt = datetime.fromisoformat(clean)
        return dt.replace(tzinfo=timezone.utc)
    except Exception as exc:
        raise DecisionRecordSchemaError(f"Invalid timestamp format {ts_str!r}: {exc}") from exc


def construct_record_signing_payload(
    record_version: str,
    decision_id: str,
    action_digest: str,
    verdict: str,
    policy_version: str,
    policy_epoch: int,
    issued_at_utc: str,
    score: float | int,
    risk_tier: str,
    provenance_taint: str,
    required_auth_level: str,
    signer_key_id: str,
) -> bytes:
    """Constructs the deterministic 12-field signing payload for an Authorization Decision Record.

    Format: Newline-delimited (\\n), UTF-8 encoded text fields with no trailing newline.
    """
    if record_version != SUPPORTED_RECORD_VERSION:
        raise DecisionRecordSchemaError(f"Unsupported record_version: {record_version!r}")
    if not _DECISION_ID_REGEX.match(decision_id):
        raise DecisionRecordSchemaError(f"Invalid decision_id format: {decision_id!r}")
    if not _HEX_64_REGEX.match(action_digest):
        raise DecisionRecordSchemaError(f"action_digest must be 64 hex chars: {action_digest!r}")
    if verdict not in _VALID_VERDICTS:
        raise DecisionRecordSchemaError(f"Invalid verdict: {verdict!r}")
    if not policy_version:
        raise DecisionRecordSchemaError("policy_version cannot be empty")
    if not isinstance(policy_epoch, int) or policy_epoch < 0:
        raise DecisionRecordSchemaError(f"policy_epoch must be non-negative integer: {policy_epoch!r}")
    _parse_iso_utc(issued_at_utc)

    # Score validation: must be within [0.0, 100.0]
    if isinstance(score, (int, float)):
        score_val = float(score)
        if score_val < 0.0 or score_val > 100.0:
            raise DecisionRecordSchemaError(f"Risk score must be in range [0.0, 100.0], got {score_val}")
    else:
        raise DecisionRecordSchemaError(f"score must be numeric, got {type(score).__name__}")

    if risk_tier not in _VALID_RISK_TIERS:
        raise DecisionRecordSchemaError(f"Invalid risk_tier: {risk_tier!r}")
    if provenance_taint not in _VALID_TAINT_LEVELS:
        raise DecisionRecordSchemaError(f"Invalid provenance_taint: {provenance_taint!r}")
    if required_auth_level not in _VALID_AUTH_LEVELS:
        raise DecisionRecordSchemaError(f"Invalid required_auth_level: {required_auth_level!r}")
    if not signer_key_id:
        raise DecisionRecordSchemaError("signer_key_id cannot be empty")

    # Format score with 2 decimal places deterministically
    score_str = f"{score_val:.2f}"

    fields = [
        RECORD_DOMAIN_TAG,
        record_version,
        decision_id,
        action_digest.lower(),
        verdict,
        policy_version,
        str(policy_epoch),
        issued_at_utc,
        score_str,
        risk_tier,
        provenance_taint,
        required_auth_level,
        signer_key_id,
    ]

    for f in fields:
        if "\n" in f:
            raise DecisionRecordSchemaError(f"Field contains newline: {f!r}")

    return "\n".join(fields).encode("utf-8")


def sign_authorization_decision_record(
    decision_id: str,
    action_digest: str,
    verdict: str,
    policy_version: str,
    policy_epoch: int,
    issued_at_utc: str,
    score: float | int,
    risk_tier: str,
    provenance_taint: str,
    required_auth_level: str,
    signer_key_id: str,
    private_key: ed25519.Ed25519PrivateKey,
    record_version: str = SUPPORTED_RECORD_VERSION,
) -> dict[str, Any]:
    """Constructs and signs an Authorization Decision Record using a gateway private key."""
    signing_bytes = construct_record_signing_payload(
        record_version=record_version,
        decision_id=decision_id,
        action_digest=action_digest,
        verdict=verdict,
        policy_version=policy_version,
        policy_epoch=policy_epoch,
        issued_at_utc=issued_at_utc,
        score=score,
        risk_tier=risk_tier,
        provenance_taint=provenance_taint,
        required_auth_level=required_auth_level,
        signer_key_id=signer_key_id,
    )

    sig_hex = private_key.sign(signing_bytes).hex()

    return {
        "record_version": record_version,
        "decision_id": decision_id,
        "action_digest": action_digest.lower(),
        "verdict": verdict,
        "policy_binding": {
            "policy_version": policy_version,
            "policy_epoch": policy_epoch,
            "issued_at_utc": issued_at_utc,
        },
        "evaluated_risk": {
            "score": float(score),
            "risk_tier": risk_tier,
            "provenance_taint": provenance_taint,
            "required_auth_level": required_auth_level,
        },
        "gateway_signature": {
            "signer_key_id": signer_key_id,
            "signature_algorithm": "ED25519",
            "signature_value": sig_hex,
        },
    }


def verify_authorization_decision_record(
    record: dict[str, Any],
    key_registry: KeyRegistry,
    expected_action_digest: str,
    current_policy_epoch: int,
    gateway_principal_id: str,
    verification_time_utc: Optional[str] = None,
) -> bool:
    """Validates and verifies an Authorization Decision Record.

    Ensures:
    1. Schema conformity without unknown fields.
    2. Action digest binding matches expected_action_digest.
    3. Policy epoch matches current_policy_epoch (not stale).
    4. Gateway cryptographic signature is valid.
    """
    if not isinstance(record, dict):
        raise DecisionRecordSchemaError("Record must be a dictionary")

    extra_top = set(record.keys()) - _RECORD_TOP_KEYS
    if extra_top:
        raise DecisionRecordSchemaError(f"Unknown fields in record: {sorted(extra_top)}")

    if record.get("record_version") != SUPPORTED_RECORD_VERSION:
        raise DecisionRecordSchemaError(f"Unsupported record_version: {record.get('record_version')!r}")

    decision_id = record.get("decision_id")
    action_digest = record.get("action_digest")
    verdict = record.get("verdict")
    policy_binding = record.get("policy_binding")
    evaluated_risk = record.get("evaluated_risk")
    gateway_sig = record.get("gateway_signature")

    if not isinstance(policy_binding, dict):
        raise DecisionRecordSchemaError("policy_binding must be a dictionary")
    extra_pb = set(policy_binding.keys()) - _POLICY_BINDING_KEYS
    if extra_pb:
        raise DecisionRecordSchemaError(f"Unknown fields in policy_binding: {sorted(extra_pb)}")

    if not isinstance(evaluated_risk, dict):
        raise DecisionRecordSchemaError("evaluated_risk must be a dictionary")
    extra_er = set(evaluated_risk.keys()) - _EVALUATED_RISK_KEYS
    if extra_er:
        raise DecisionRecordSchemaError(f"Unknown fields in evaluated_risk: {sorted(extra_er)}")

    if not isinstance(gateway_sig, dict):
        raise DecisionRecordSchemaError("gateway_signature must be a dictionary")
    extra_gs = set(gateway_sig.keys()) - _GATEWAY_SIG_KEYS
    if extra_gs:
        raise DecisionRecordSchemaError(f"Unknown fields in gateway_signature: {sorted(extra_gs)}")

    # 1. Action digest match
    if str(action_digest).lower() != str(expected_action_digest).lower():
        raise DecisionRecordVerificationError(
            f"Action digest mismatch! Record binds: {action_digest}, Target is: {expected_action_digest}"
        )

    # 2. Policy epoch freshness check
    epoch = policy_binding.get("policy_epoch")
    if epoch != current_policy_epoch:
        raise DecisionRecordVerificationError(
            f"Stale policy epoch in decision record: record epoch {epoch} != gateway current epoch {current_policy_epoch}"
        )

    # 3. Construct signing bytes
    signer_key_id = gateway_sig.get("signer_key_id")
    signing_bytes = construct_record_signing_payload(
        record_version=record["record_version"],
        decision_id=decision_id,
        action_digest=action_digest,
        verdict=verdict,
        policy_version=policy_binding.get("policy_version"),
        policy_epoch=epoch,
        issued_at_utc=policy_binding.get("issued_at_utc"),
        score=evaluated_risk.get("score"),
        risk_tier=evaluated_risk.get("risk_tier"),
        provenance_taint=evaluated_risk.get("provenance_taint"),
        required_auth_level=evaluated_risk.get("required_auth_level"),
        signer_key_id=signer_key_id,
    )

    # 4. Signature validation
    sig_hex = gateway_sig.get("signature_value")
    if not isinstance(sig_hex, str) or not _HEX_128_SIG_REGEX.match(sig_hex):
        raise DecisionRecordVerificationError("Invalid signature length or format")
    sig_raw = bytes.fromhex(sig_hex)

    try:
        public_key = key_registry.validate_and_get_public_key(
            key_id=signer_key_id,
            expected_owner=gateway_principal_id,
            verification_time_utc=verification_time_utc,
        )
    except KeyRegistryError as exc:
        raise DecisionRecordVerificationError(f"Gateway key verification failed: {exc}") from exc

    try:
        public_key.verify(sig_raw, signing_bytes)
    except InvalidSignature as exc:
        raise DecisionRecordVerificationError("Cryptographic signature invalid on decision record") from exc

    return True

