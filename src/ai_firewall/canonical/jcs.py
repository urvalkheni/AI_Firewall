"""RFC 8785 JSON Canonicalization Scheme (JCS) Implementation.

Pure Python, zero-dependency canonical serialization according to RFC 8785:
- UTF-16 code unit lexicographic key ordering.
- ECMAScript-compliant number serialization (ECMA-262 Section 7.1.12.1).
- Compact formatting with no whitespace.
- Standard JSON character escaping (quotes, backslashes, control characters 0x00-0x1F).
- Outputs UTF-8 encoded bytes.
"""

from __future__ import annotations

import math
from typing import Any


class JCSCanonicalizationError(ValueError):
    """Raised when an object cannot be canonicalized under RFC 8785."""


# Precomputed ASCII control character escapes
_CONTROL_ESCAPES = {
    '"': '\\"',
    '\\': '\\\\',
    '\b': '\\b',
    '\f': '\\f',
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
}
for i in range(0x20):
    char = chr(i)
    if char not in _CONTROL_ESCAPES:
        _CONTROL_ESCAPES[char] = f"\\u{i:04x}"


def _escape_string(s: str) -> str:
    """Escapes string according to RFC 8785 Section 3.2.2.2."""
    out = ['"']
    for char in s:
        if char in _CONTROL_ESCAPES:
            out.append(_CONTROL_ESCAPES[char])
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _format_ecma_number(val: float | int) -> str:
    """Serializes a number adhering strictly to ECMA-262 / RFC 8785 Section 3.2.2.3."""
    if isinstance(val, bool):
        raise JCSCanonicalizationError("Boolean passed as number")

    if isinstance(val, int):
        # Integers in Python serialize directly to standard decimal string
        return str(val)

    if math.isnan(val) or math.isinf(val):
        raise JCSCanonicalizationError(f"Non-finite float value rejected: {val!r}")

    if val == 0.0:
        return "0"

    # Python float repr() implements David Gay's dtoa (shortest round-trippable representation).
    s = repr(val)
    sign = ""
    if s.startswith("-"):
        sign = "-"
        s = s[1:]

    if "e" in s or "E" in s:
        mantissa_str, exp_str = s.lower().split("e")
        exp = int(exp_str)
        if "." in mantissa_str:
            m_int, m_frac = mantissa_str.split(".")
            m_frac = m_frac.rstrip("0")
            digits = m_int + m_frac
            k = exp + len(m_int)
        else:
            digits = mantissa_str
            k = exp + len(digits)
    else:
        if "." in s:
            m_int, m_frac = s.split(".")
            m_frac = m_frac.rstrip("0")
            if int(m_int) == 0:
                frac_trimmed = m_frac.lstrip("0")
                leading_zeros = len(m_frac) - len(frac_trimmed)
                digits = frac_trimmed
                k = -leading_zeros
            else:
                digits = m_int + m_frac
                k = len(m_int)
        else:
            digits = s
            k = len(s)

    n = len(digits)
    if 0 < k <= 21:
        if n <= k:
            out = digits + "0" * (k - n)
        else:
            out = digits[:k] + "." + digits[k:]
    elif -6 < k <= 0:
        out = "0." + "0" * (-k) + digits
    else:
        exp_val = k - 1
        exp_sign = "+" if exp_val >= 0 else "-"
        if n > 1:
            out = digits[0] + "." + digits[1:] + "e" + exp_sign + str(abs(exp_val))
        else:
            out = digits[0] + "e" + exp_sign + str(abs(exp_val))

    return sign + out


def _utf16_sort_key(s: str) -> list[int]:
    """Generates the UTF-16 code units sort key required by RFC 8785 Section 3.2.3."""
    res = []
    for c in s:
        code = ord(c)
        if code < 0x10000:
            res.append(code)
        else:
            # Surrogate pair representation
            code -= 0x10000
            res.append(0xD800 + (code >> 10))
            res.append(0xDC00 + (code & 0x3FF))
    return res


def _serialize(obj: Any, buffer: list[str]) -> None:
    """Recursively serializes Python data objects to canonical JSON strings."""
    if obj is None:
        buffer.append("null")
    elif isinstance(obj, bool):
        buffer.append("true" if obj else "false")
    elif isinstance(obj, (int, float)):
        buffer.append(_format_ecma_number(obj))
    elif isinstance(obj, str):
        buffer.append(_escape_string(obj))
    elif isinstance(obj, list):
        buffer.append("[")
        for i, item in enumerate(obj):
            if i > 0:
                buffer.append(",")
            _serialize(item, buffer)
        buffer.append("]")
    elif isinstance(obj, dict):
        buffer.append("{")
        # Validate that all keys are strings and sort by UTF-16 code units
        for k in obj:
            if not isinstance(k, str):
                raise JCSCanonicalizationError(f"Dictionary key must be str, got {type(k).__name__}: {k!r}")

        sorted_keys = sorted(obj.keys(), key=_utf16_sort_key)
        for i, k in enumerate(sorted_keys):
            if i > 0:
                buffer.append(",")
            buffer.append(_escape_string(k))
            buffer.append(":")
            _serialize(obj[k], buffer)
        buffer.append("}")
    else:
        raise JCSCanonicalizationError(f"Unsupported data type for canonicalization: {type(obj).__name__}")


def canonicalize_jcs(obj: Any) -> bytes:
    """Serializes a Python object structure into RFC 8785 canonical UTF-8 bytes.

    Args:
        obj: The data structure (dict, list, primitive) to serialize.

    Returns:
        The deterministic UTF-8 bytes representation.

    Raises:
        JCSCanonicalizationError: If unencodable types or non-finite numbers exist.
    """
    buffer: list[str] = []
    _serialize(obj, buffer)
    return "".join(buffer).encode("utf-8")

