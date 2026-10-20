"""Cryptographic Action Digest Generation and Validation.

Implements SHA-256 digest computation over the RFC 8785 serialized bytes of the
normalized action_identity.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ai_firewall.canonical.jcs import canonicalize_jcs
from ai_firewall.canonical.normalizer import normalize_canonical_action


class ActionDigestMismatchError(ValueError):
    """Raised when an action digest does not match the computed hash of the action."""


def compute_action_digest(action_payload: dict[str, Any]) -> tuple[str, bytes, dict[str, Any]]:
    """Normalizes, canonicalizes, and computes the SHA-256 action digest.

    Args:
        action_payload: Dictionary representing the proposed action.

    Returns:
        A tuple of (action_digest_hex, canonical_bytes, normalized_action_dict).
    """
    normalized_action = normalize_canonical_action(action_payload)
    canonical_bytes = canonicalize_jcs(normalized_action)
    action_digest = hashlib.sha256(canonical_bytes).hexdigest()
    return action_digest, canonical_bytes, normalized_action


def validate_action_digest(action_payload: dict[str, Any], expected_digest: str) -> bool:
    """Verifies that an action payload strictly matches an expected digest.

    Args:
        action_payload: Action dictionary to verify.
        expected_digest: 64-character lowercase hexadecimal SHA-256 digest.

    Returns:
        True if the digest matches.

    Raises:
        ActionDigestMismatchError: If the digest differs (indicating parameter tampering).
    """
    computed_digest, _, _ = compute_action_digest(action_payload)
    if computed_digest.lower() != expected_digest.lower():
        raise ActionDigestMismatchError(
            f"Action digest mismatch! Expected: {expected_digest}, Computed: {computed_digest}"
        )
    return True

