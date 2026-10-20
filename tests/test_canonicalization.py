"""Deterministic test suite for AI Firewall Canonicalization Core.

Tests:
1. Strict JSON parsing: duplicate-key rejection, malformed syntax, safe integer boundaries.
2. Selective Unicode NFC normalization & collision detection.
3. Preservation of verbatim parameters (code, SQL, binary).
4. RFC 8785 (JCS) official conformance vectors (arrays, structures, values, unicode).
5. Deterministic key sorting across permuted dictionaries.
6. SHA-256 action digest generation and tamper detection.
7. Cross-adapter digest parity fixtures (MCP vs LangChain format equivalence).
"""

from __future__ import annotations

import json
import pytest

from ai_firewall.canonical.parser import (
    DuplicateKeyError,
    NumericPrecisionError,
    StrictJSONError,
    strict_json_loads,
)
from ai_firewall.canonical.jcs import (
    JCSCanonicalizationError,
    canonicalize_jcs,
)
from ai_firewall.canonical.normalizer import (
    NormalizationCollisionError,
    SchemaValidationError,
    normalize_canonical_action,
)
from ai_firewall.canonical.hasher import (
    ActionDigestMismatchError,
    compute_action_digest,
    validate_action_digest,
)


# ==============================================================================
# 1. Strict Parser Tests
# ==============================================================================

def test_strict_json_loads_rejects_duplicate_keys():
    payload = '{"path": "/safe", "path": "/etc/passwd"}'
    with pytest.raises(DuplicateKeyError) as exc:
        strict_json_loads(payload)
    assert "Duplicate object key rejected: 'path'" in str(exc.value)


def test_strict_json_loads_rejects_nested_duplicate_keys():
    payload = '{"parent": {"child": 1, "child": 2}}'
    with pytest.raises(DuplicateKeyError) as exc:
        strict_json_loads(payload)
    assert "Duplicate object key rejected: 'child'" in str(exc.value)


def test_strict_json_loads_rejects_malformed_syntax():
    with pytest.raises(StrictJSONError):
        strict_json_loads('{"unclosed": "string')


def test_strict_json_loads_rejects_nan_and_infinity():
    with pytest.raises(StrictJSONError):
        strict_json_loads('{"val": NaN}')
    with pytest.raises(StrictJSONError):
        strict_json_loads('{"val": Infinity}')


def test_strict_json_loads_integer_boundaries():
    # Safe integers within [-2^53 + 1, 2^53 - 1]
    safe_max = 9007199254740991
    safe_min = -9007199254740991
    assert strict_json_loads(f'{{"val": {safe_max}}}') == {"val": safe_max}
    assert strict_json_loads(f'{{"val": {safe_min}}}') == {"val": safe_min}

    # Out of bounds integers must be rejected
    with pytest.raises(NumericPrecisionError):
        strict_json_loads(f'{{"val": {safe_max + 1}}}')
    with pytest.raises(NumericPrecisionError):
        strict_json_loads(f'{{"val": {safe_min - 1}}}')


# ==============================================================================
# 2. RFC 8785 Official Conformance Test Vectors
# ==============================================================================

def test_rfc8785_arrays_vector():
    """Matches Anders Rundgren / RFC 8785 arrays.json test vector."""
    inp = [56, {"d": True, "10": None, "1": []}]
    expected = b'[56,{"1":[],"10":null,"d":true}]'
    assert canonicalize_jcs(inp) == expected


def test_rfc8785_structures_vector():
    """Matches Anders Rundgren / RFC 8785 structures.json test vector."""
    inp = {
        "1": {"f": {"f": "hi", "F": 5}, "\n": 56.0},
        "10": {},
        "": "empty",
        "a": {},
        "111": [{"e": "yes", "E": "no"}],
        "A": {},
    }
    expected = b'{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}'
    assert canonicalize_jcs(inp) == expected


def test_rfc8785_values_vector():
    """Matches Anders Rundgren / RFC 8785 values.json test vector."""
    inp = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "string": "\u20ac$\u000f\nA'B\"\\\"/",
        "literals": [None, True, False],
    }
    # JCS does not escape forward slash; escapes control chars and quotes
    expected = (
        b'{"literals":[null,true,false],'
        b'"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\"/"}'
    )
    assert canonicalize_jcs(inp) == expected


def test_rfc8785_unicode_vector():
    """Matches Anders Rundgren / RFC 8785 unicode.json test vector.

    RFC 8785 leaves unnormalized string codepoints intact in raw JCS serialization.
    """
    inp = {"Unnormalized Unicode": "A\u030a"}
    expected = b'{"Unnormalized Unicode":"A\xcc\x8a"}'
    assert canonicalize_jcs(inp) == expected


# ==============================================================================
# 3. Selective Normalization and Schema Validation Tests
# ==============================================================================

def sample_action_fixture():
    return {
        "principal": {
            "user_id": "usr_99",
            "agent_id": "agt_01",
            "session_id": "ses_01",
        },
        "invocation": {
            "tool_server_id": "mcp_fs",
            "tool_name": "write_file",
            "operation_type": "MUTATION",
            "canonical_params": {
                "path": "/tmp/test.txt",
                "content": "Line 1\nLine 2\r\n",
                "code": "def foo(): pass",
            },
        },
        "target_resource": {
            "resource_uri": "file:///tmp/test.txt",
            "preconditions": {
                "expected_etag": 'W/"abc"',
                "expected_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "precondition_mode": "EXACT_HASH_MATCH",
            },
        },
        "authorization_binding": {
            "policy_version": "v1.0",
            "policy_epoch": 1,
            "idempotency_key": "idemp_123",
            "expires_at_utc": "2026-10-12T10:00:00Z",
        },
    }


def test_schema_rejects_unknown_fields():
    bad_payload = sample_action_fixture()
    bad_payload["unknown_exploit_field"] = "malicious"
    with pytest.raises(SchemaValidationError):
        normalize_canonical_action(bad_payload)


def test_nfc_normalization_applies_to_identifiers():
    payload = sample_action_fixture()
    # Decomposed 'e' + combining acute accent (\u0065\u0301)
    decomposed = "re\u0301sume\u0301.txt"
    # Precomposed 'é' (\u00e9)
    precomposed = "r\u00e9sum\u00e9.txt"

    payload["invocation"]["canonical_params"]["path"] = f"/data/{decomposed}"
    normalized = normalize_canonical_action(payload)
    assert normalized["invocation"]["canonical_params"]["path"] == f"/data/{precomposed}"


def test_verbatim_fields_are_preserved_without_alteration():
    payload = sample_action_fixture()
    # Content has combining characters that must NOT be modified
    decomposed_code = "name = 'A\u030a'"
    payload["invocation"]["canonical_params"]["content"] = decomposed_code
    normalized = normalize_canonical_action(payload)
    # The content must retain exact decomposed characters
    assert normalized["invocation"]["canonical_params"]["content"] == decomposed_code


def test_normalization_key_collision_rejected():
    payload = sample_action_fixture()
    # If parameters contain two keys that collide upon NFC normalization
    payload["invocation"]["canonical_params"] = {
        "cafe\u0301": 1,
        "caf\u00e9": 2,
    }
    with pytest.raises(NormalizationCollisionError):
        normalize_canonical_action(payload)


# ==============================================================================
# 4. Action Digest & Tamper Detection Tests
# ==============================================================================

def test_identical_semantic_actions_with_permuted_keys_produce_identical_digest():
    action_1 = sample_action_fixture()

    # Create action_2 with reversed / permuted dictionary key order
    action_2 = {
        "authorization_binding": {
            "expires_at_utc": "2026-10-12T10:00:00Z",
            "idempotency_key": "idemp_123",
            "policy_epoch": 1,
            "policy_version": "v1.0",
        },
        "target_resource": {
            "preconditions": {
                "precondition_mode": "EXACT_HASH_MATCH",
                "expected_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "expected_etag": 'W/"abc"',
            },
            "resource_uri": "file:///tmp/test.txt",
        },
        "invocation": {
            "canonical_params": {
                "code": "def foo(): pass",
                "content": "Line 1\nLine 2\r\n",
                "path": "/tmp/test.txt",
            },
            "operation_type": "MUTATION",
            "tool_name": "write_file",
            "tool_server_id": "mcp_fs",
        },
        "principal": {
            "session_id": "ses_01",
            "agent_id": "agt_01",
            "user_id": "usr_99",
        },
    }

    digest_1, bytes_1, _ = compute_action_digest(action_1)
    digest_2, bytes_2, _ = compute_action_digest(action_2)

    assert bytes_1 == bytes_2
    assert digest_1 == digest_2
    assert validate_action_digest(action_1, digest_2) is True


def test_parameter_tampering_triggers_digest_mismatch():
    action = sample_action_fixture()
    digest, _, _ = compute_action_digest(action)

    # Tamper with target path from /tmp to /etc
    tampered_action = sample_action_fixture()
    tampered_action["invocation"]["canonical_params"]["path"] = "/etc/shadow"

    with pytest.raises(ActionDigestMismatchError):
        validate_action_digest(tampered_action, digest)


def test_epoch_change_triggers_digest_mismatch():
    action = sample_action_fixture()
    digest, _, _ = compute_action_digest(action)

    # Policy epoch bumped from 1 to 2
    updated_epoch_action = sample_action_fixture()
    updated_epoch_action["authorization_binding"]["policy_epoch"] = 2

    with pytest.raises(ActionDigestMismatchError):
        validate_action_digest(updated_epoch_action, digest)


# ==============================================================================
# 5. Cross-Adapter Equivalence Fixture Test
# ==============================================================================

def test_cross_adapter_digest_parity():
    """Verifies that normalized representations arriving from MCP vs LangChain

    yield byte-for-byte identical action digests when semantics are identical.
    """
    # Simulated MCP translated payload
    mcp_action = {
        "principal": {"user_id": "usr_bob", "agent_id": "agent_alpha", "session_id": "session_mcp_01"},
        "invocation": {
            "tool_server_id": "filesystem_server",
            "tool_name": "edit_file",
            "operation_type": "MUTATION",
            "canonical_params": {"target": "/var/log/app.log", "append": True},
        },
        "target_resource": {"resource_uri": "file:///var/log/app.log", "preconditions": None},
        "authorization_binding": {
            "policy_version": "v2.0",
            "policy_epoch": 10,
            "idempotency_key": "idemp_parity_test_001",
            "expires_at_utc": "2026-10-12T12:00:00Z",
        },
    }

    # Simulated LangChain translated payload (identical semantic values, different dict ordering)
    langchain_action = {
        "authorization_binding": {
            "policy_version": "v2.0",
            "expires_at_utc": "2026-10-12T12:00:00Z",
            "policy_epoch": 10,
            "idempotency_key": "idemp_parity_test_001",
        },
        "invocation": {
            "operation_type": "MUTATION",
            "canonical_params": {"append": True, "target": "/var/log/app.log"},
            "tool_name": "edit_file",
            "tool_server_id": "filesystem_server",
        },
        "target_resource": {"preconditions": None, "resource_uri": "file:///var/log/app.log"},
        "principal": {"session_id": "session_mcp_01", "agent_id": "agent_alpha", "user_id": "usr_bob"},
    }

    mcp_digest, mcp_bytes, _ = compute_action_digest(mcp_action)
    lc_digest, lc_bytes, _ = compute_action_digest(langchain_action)

    assert mcp_bytes == lc_bytes
    assert mcp_digest == lc_digest
