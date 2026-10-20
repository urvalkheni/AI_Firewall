"""Strict JSON Parser for AI Firewall.

Enforces:
1. Rejection of duplicate object keys (RFC 7493 I-JSON conformance).
2. Verification of IEEE 754 safe integer limits [-2^53 + 1, 2^53 - 1].
3. Rejection of NaN, Infinity, and non-conforming numbers.
4. Valid UTF-8 string decoding.
"""

from __future__ import annotations

import json
import math
from typing import Any

# IEEE 754 safe integer range: [-9007199254740991, 9007199254740991]
SAFE_INT_MIN = -9007199254740991
SAFE_INT_MAX = 9007199254740991


class StrictJSONError(ValueError):
    """Base error for strict JSON parsing failures."""


class DuplicateKeyError(StrictJSONError):
    """Raised when an object contains duplicate keys."""

    def __init__(self, key: str) -> None:
        super().__init__(f"Duplicate object key rejected: {key!r}")
        self.key = key


class NumericPrecisionError(StrictJSONError):
    """Raised when a number exceeds safe integer precision limits."""

    def __init__(self, val: Any) -> None:
        super().__init__(
            f"Integer value {val!r} exceeds IEEE 754 safe integer limits "
            f"[{SAFE_INT_MIN}, {SAFE_INT_MAX}]. Encode large values as strings."
        )
        self.val = val


def _strict_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Object hook that raises DuplicateKeyError if any key is repeated."""
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateKeyError(key)
        obj[key] = value
    return obj


def _validate_numbers(node: Any) -> None:
    """Recursively validates numeric boundaries and finite representations."""
    if isinstance(node, dict):
        for v in node.values():
            _validate_numbers(v)
    elif isinstance(node, list):
        for item in node:
            _validate_numbers(item)
    elif isinstance(node, bool):
        # In Python, bool is a subclass of int, so check bool before int
        return
    elif isinstance(node, int):
        if node < SAFE_INT_MIN or node > SAFE_INT_MAX:
            raise NumericPrecisionError(node)
    elif isinstance(node, float):
        if math.isnan(node) or math.isinf(node):
            raise StrictJSONError(f"Non-finite float value rejected: {node!r}")


def strict_json_loads(data: str | bytes) -> Any:
    """Parses JSON with strict duplicate-key rejection and numeric validation.

    Args:
        data: JSON string or UTF-8 bytes to parse.

    Returns:
        The deserialized Python object hierarchy.

    Raises:
        StrictJSONError: If syntax is invalid, duplicate keys exist, or numbers
            exceed safe limits.
    """
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StrictJSONError(f"Invalid UTF-8 byte sequence: {exc}") from exc

    try:
        parsed = json.loads(
            data,
            object_pairs_hook=_strict_object_pairs_hook,
            parse_constant=None,  # Rejects NaN, Infinity, -Infinity
        )
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"JSON syntax error: {exc.msg} at line {exc.lineno} col {exc.colno}") from exc

    _validate_numbers(parsed)
    return parsed

