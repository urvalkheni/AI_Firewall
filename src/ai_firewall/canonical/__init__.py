"""Canonicalization subpackage for the AI Firewall.

Implements strict JSON parsing, selective NFC normalization, RFC 8785 (JCS)
serialization, and SHA-256 action digest generation.
"""

from ai_firewall.canonical.parser import (
    StrictJSONError,
    DuplicateKeyError,
    NumericPrecisionError,
    strict_json_loads,
)
from ai_firewall.canonical.normalizer import (
    NormalizationCollisionError,
    normalize_canonical_action,
)
from ai_firewall.canonical.jcs import (
    JCSCanonicalizationError,
    canonicalize_jcs,
)
from ai_firewall.canonical.hasher import (
    ActionDigestMismatchError,
    compute_action_digest,
    validate_action_digest,
)

__all__ = [
    "StrictJSONError",
    "DuplicateKeyError",
    "NumericPrecisionError",
    "strict_json_loads",
    "NormalizationCollisionError",
    "normalize_canonical_action",
    "JCSCanonicalizationError",
    "canonicalize_jcs",
    "ActionDigestMismatchError",
    "compute_action_digest",
    "validate_action_digest",
]

