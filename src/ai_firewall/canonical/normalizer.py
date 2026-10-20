"""Selective Unicode Normalization and Canonical Action Schema Validation.

Rules:
1. Strict schema validation of Canonical Action objects.
2. Rejection of unknown properties (fail-closed).
3. Selective Unicode NFC normalization applied only to declared textual fields.
4. Detection and rejection of key collisions post-normalization.
5. Preservation of verbatim parameters (raw code, binary base64, SQL queries).
"""

from __future__ import annotations

import unicodedata
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when an action proposal violates the Canonical Action Schema."""


class NormalizationCollisionError(ValueError):
    """Raised when distinct object keys normalize to identical Unicode NFC sequences."""


# Required top-level fields for action_identity
_ACTION_IDENTITY_FIELDS = {
    "principal",
    "invocation",
    "target_resource",
    "authorization_binding",
}

_PRINCIPAL_FIELDS = {"user_id", "agent_id", "session_id"}
_INVOCATION_FIELDS = {"tool_server_id", "tool_name", "operation_type", "canonical_params"}
_TARGET_RESOURCE_FIELDS = {"resource_uri", "preconditions"}
_PRECONDITION_FIELDS = {"expected_etag", "expected_sha256", "precondition_mode"}
_AUTH_BINDING_FIELDS = {"policy_version", "policy_epoch", "idempotency_key", "expires_at_utc"}

# Fields in canonical_params where parameters are strictly verbatim and must NOT be NFC normalized
_VERBATIM_PARAM_KEYS = {
    "content",        # File contents or patches
    "code",           # Source code strings
    "raw_query",      # SQL or query strings
    "binary_base64",  # Base64 encoded blobs
    "expected_sha256",# Hashes
    "expected_etag",  # ETags
}


def _validate_dict_keys(d: dict[str, Any], allowed_keys: set[str], context: str) -> None:
    """Ensures dictionary contains exactly the required/allowed keys without unknown extras."""
    if not isinstance(d, dict):
        raise SchemaValidationError(f"{context} must be an object/dict, got {type(d).__name__}")
    extra_keys = set(d.keys()) - allowed_keys
    if extra_keys:
        raise SchemaValidationError(f"Unknown fields rejected in {context}: {sorted(extra_keys)}")


def _normalize_string_nfc(s: str) -> str:
    """Normalizes string to Unicode Normalization Form C (NFC)."""
    return unicodedata.normalize("NFC", s)


def _normalize_params_recursive(params: Any, parent_key: str | None = None) -> Any:
    """Recursively processes tool parameters with selective NFC normalization."""
    if isinstance(params, dict):
        normalized_dict: dict[str, Any] = {}
        seen_keys_map: dict[str, str] = {}
        for k, v in params.items():
            if not isinstance(k, str):
                raise SchemaValidationError(f"Parameter key must be string, got {type(k).__name__}: {k!r}")

            norm_k = _normalize_string_nfc(k)
            if norm_k in seen_keys_map and seen_keys_map[norm_k] != k:
                raise NormalizationCollisionError(
                    f"Parameter key collision detected after NFC normalization: {k!r} and {seen_keys_map[norm_k]!r} -> {norm_k!r}"
                )
            seen_keys_map[norm_k] = k

            # Check if this parameter is verbatim
            if norm_k in _VERBATIM_PARAM_KEYS:
                # Verbatim preservation: do not alter string contents
                normalized_dict[norm_k] = v
            else:
                normalized_dict[norm_k] = _normalize_params_recursive(v, parent_key=norm_k)
        return normalized_dict
    elif isinstance(params, list):
        return [_normalize_params_recursive(item, parent_key=parent_key) for item in params]
    elif isinstance(params, str):
        if parent_key in _VERBATIM_PARAM_KEYS:
            return params
        return _normalize_string_nfc(params)
    else:
        return params


def normalize_canonical_action(action_payload: dict[str, Any]) -> dict[str, Any]:
    """Validates schema conformance and applies selective NFC normalization.

    Args:
        action_payload: Dictionary containing the proposed action. Must contain
            either 'action_identity' or top-level fields matching action_identity.

    Returns:
        The validated and normalized action_identity dictionary, ready for JCS
        canonicalization, reviewer UI rendering, and downstream dispatch.

    Raises:
        SchemaValidationError: If required fields are missing or unknown fields exist.
        NormalizationCollisionError: If object keys collide after NFC normalization.
    """
    if not isinstance(action_payload, dict):
        raise SchemaValidationError(f"Action payload must be an object, got {type(action_payload).__name__}")

    # Extract action_identity if wrapped
    if "action_identity" in action_payload:
        identity = action_payload["action_identity"]
    else:
        identity = action_payload

    _validate_dict_keys(identity, _ACTION_IDENTITY_FIELDS, "action_identity")

    # 1. Principal Validation & Normalization
    principal = identity.get("principal")
    _validate_dict_keys(principal, _PRINCIPAL_FIELDS, "principal")
    norm_principal = {
        "user_id": _normalize_string_nfc(str(principal["user_id"])),
        "agent_id": _normalize_string_nfc(str(principal["agent_id"])),
        "session_id": _normalize_string_nfc(str(principal["session_id"])),
    }

    # 2. Invocation Validation & Normalization
    invocation = identity.get("invocation")
    _validate_dict_keys(invocation, _INVOCATION_FIELDS, "invocation")
    norm_invocation = {
        "tool_server_id": _normalize_string_nfc(str(invocation["tool_server_id"])),
        "tool_name": _normalize_string_nfc(str(invocation["tool_name"])),
        "operation_type": str(invocation["operation_type"]),
        "canonical_params": _normalize_params_recursive(invocation.get("canonical_params", {})),
    }

    # 3. Target Resource Validation & Normalization
    target_res = identity.get("target_resource")
    _validate_dict_keys(target_res, _TARGET_RESOURCE_FIELDS, "target_resource")
    preconditions = target_res.get("preconditions")
    if preconditions is not None:
        _validate_dict_keys(preconditions, _PRECONDITION_FIELDS, "preconditions")
        norm_preconditions = {
            "expected_etag": preconditions.get("expected_etag"),
            "expected_sha256": preconditions.get("expected_sha256"),
            "precondition_mode": str(preconditions.get("precondition_mode", "EXACT_HASH_MATCH")),
        }
    else:
        norm_preconditions = None

    norm_target_res = {
        "resource_uri": _normalize_string_nfc(str(target_res["resource_uri"])),
        "preconditions": norm_preconditions,
    }

    # 4. Authorization Binding Validation & Normalization
    auth_binding = identity.get("authorization_binding")
    _validate_dict_keys(auth_binding, _AUTH_BINDING_FIELDS, "authorization_binding")
    norm_auth_binding = {
        "policy_version": _normalize_string_nfc(str(auth_binding["policy_version"])),
        "policy_epoch": int(auth_binding["policy_epoch"]),
        "idempotency_key": str(auth_binding["idempotency_key"]),
        "expires_at_utc": str(auth_binding["expires_at_utc"]),
    }

    return {
        "principal": norm_principal,
        "invocation": norm_invocation,
        "target_resource": norm_target_res,
        "authorization_binding": norm_auth_binding,
    }
