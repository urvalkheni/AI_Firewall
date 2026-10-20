"""Deterministic unit tests for Target Resource Precondition Verifier.

Tests:
1. Exact ETag match succeeds.
2. ETag mismatch raises StateDriftError.
3. Exact SHA-256 hash match succeeds.
4. SHA-256 hash mismatch raises StateDriftError.
5. Unchecked mode when preconditions are None.
"""

from __future__ import annotations

import pytest

from ai_firewall.broker.preconditions import (
    PreconditionMode,
    StateDriftError,
    verify_resource_preconditions,
)


def test_etag_match_succeeds():
    preconditions = {
        "expected_etag": 'W/"4f-189a"',
        "precondition_mode": "EXACT_ETAG_MATCH",
    }
    inspector = lambda uri: {"etag": 'W/"4f-189a"', "sha256": "abc"}

    res = verify_resource_preconditions("file:///data.txt", preconditions, inspector)
    assert res.passed is True
    assert res.mode == PreconditionMode.EXACT_ETAG_MATCH


def test_etag_mismatch_raises_state_drift():
    preconditions = {
        "expected_etag": 'W/"4f-189a"',
        "precondition_mode": "EXACT_ETAG_MATCH",
    }
    # Live resource changed to W/"50-9999"
    inspector = lambda uri: {"etag": 'W/"50-9999"', "sha256": "abc"}

    with pytest.raises(StateDriftError) as exc:
        verify_resource_preconditions("file:///data.txt", preconditions, inspector)
    assert "State drift detected" in str(exc.value)


def test_hash_match_succeeds():
    preconditions = {
        "expected_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "precondition_mode": "EXACT_HASH_MATCH",
    }
    inspector = lambda uri: {"etag": None, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}

    res = verify_resource_preconditions("file:///empty.txt", preconditions, inspector)
    assert res.passed is True
    assert res.mode == PreconditionMode.EXACT_HASH_MATCH


def test_hash_mismatch_raises_state_drift():
    preconditions = {
        "expected_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "precondition_mode": "EXACT_HASH_MATCH",
    }
    # Live resource has different content
    inspector = lambda uri: {"etag": None, "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}

    with pytest.raises(StateDriftError) as exc:
        verify_resource_preconditions("file:///empty.txt", preconditions, inspector)
    assert "State drift detected" in str(exc.value)


def test_none_preconditions_passes_unchecked():
    res = verify_resource_preconditions("file:///any.txt", preconditions=None)
    assert res.passed is True
    assert res.mode == PreconditionMode.MODE_UNCHECKED

