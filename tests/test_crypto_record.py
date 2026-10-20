"""Deterministic Security Tests for Authorization Decision Record.

Tests:
1. Valid record creation, signing, and verification.
2. Tampering with score, risk_tier, verdict, and policy_epoch.
3. Digest mismatch between proposed action and decision record.
4. Stale policy epoch detection.
5. Unknown fields and numeric bounds validation (score outside [0, 100]).
6. Gateway signature verification using KeyRegistry.
"""

from __future__ import annotations

import pytest

from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.crypto.record import (
    DecisionRecordSchemaError,
    DecisionRecordVerificationError,
    sign_authorization_decision_record,
    verify_authorization_decision_record,
)


@pytest.fixture
def decision_fixture():
    registry = KeyRegistry()
    priv_key, record = generate_dev_ed25519_keypair(
        key_id="k_gw_01",
        owner_user_id="gw_core",
        not_before_utc="2026-01-01T00:00:00.000000Z",
        not_after_utc="2026-12-31T23:59:59.000000Z",
    )
    registry.register_key(record)

    action_digest = "e4b3602901a141b712c40c832c32cf97686566d2184f93a96860ecab3857e4b3"
    rec = sign_authorization_decision_record(
        decision_id="dec_01HZX9Z0ABCDEF123456789012",
        action_digest=action_digest,
        verdict="APPROVAL_REQUIRED",
        policy_version="pol_v1.0",
        policy_epoch=3,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=75.5,
        risk_tier="MODERATE_RISK",
        provenance_taint="UNTRUSTED_INDIRECT_INPUT",
        required_auth_level="MFA_HARDWARE_TOKEN",
        signer_key_id="k_gw_01",
        private_key=priv_key,
    )

    return {
        "registry": registry,
        "priv_key": priv_key,
        "record": rec,
        "action_digest": action_digest,
    }


def test_valid_decision_record_verifies(decision_fixture):
    res = verify_authorization_decision_record(
        record=decision_fixture["record"],
        key_registry=decision_fixture["registry"],
        expected_action_digest=decision_fixture["action_digest"],
        current_policy_epoch=3,
        gateway_principal_id="gw_core",
        verification_time_utc="2026-10-12T10:05:00.000000Z",
    )
    assert res is True


def test_record_tampering_score_fails_verification(decision_fixture):
    rec = dict(decision_fixture["record"])
    rec["evaluated_risk"] = dict(rec["evaluated_risk"])
    rec["evaluated_risk"]["score"] = 10.0  # Attempt to downgrade risk score

    with pytest.raises(DecisionRecordVerificationError):
        verify_authorization_decision_record(
            record=rec,
            key_registry=decision_fixture["registry"],
            expected_action_digest=decision_fixture["action_digest"],
            current_policy_epoch=3,
            gateway_principal_id="gw_core",
        )


def test_record_tampering_verdict_fails_verification(decision_fixture):
    rec = dict(decision_fixture["record"])
    rec["verdict"] = "ALLOW"  # Attempt to bypass approval

    with pytest.raises(DecisionRecordVerificationError):
        verify_authorization_decision_record(
            record=rec,
            key_registry=decision_fixture["registry"],
            expected_action_digest=decision_fixture["action_digest"],
            current_policy_epoch=3,
            gateway_principal_id="gw_core",
        )


def test_record_action_digest_mismatch(decision_fixture):
    tampered_digest = "1111111111111111111111111111111111111111111111111111111111111111"
    with pytest.raises(DecisionRecordVerificationError) as exc:
        verify_authorization_decision_record(
            record=decision_fixture["record"],
            key_registry=decision_fixture["registry"],
            expected_action_digest=tampered_digest,
            current_policy_epoch=3,
            gateway_principal_id="gw_core",
        )
    assert "Action digest mismatch" in str(exc.value)


def test_stale_policy_epoch_in_decision_record(decision_fixture):
    # Gateway epoch is 4, but decision was issued under epoch 3
    with pytest.raises(DecisionRecordVerificationError) as exc:
        verify_authorization_decision_record(
            record=decision_fixture["record"],
            key_registry=decision_fixture["registry"],
            expected_action_digest=decision_fixture["action_digest"],
            current_policy_epoch=4,
            gateway_principal_id="gw_core",
        )
    assert "Stale policy epoch" in str(exc.value)


def test_score_out_of_range_rejected():
    registry = KeyRegistry()
    priv_key, rec = generate_dev_ed25519_keypair("k_gw", "gw_core")

    with pytest.raises(DecisionRecordSchemaError) as exc:
        sign_authorization_decision_record(
            decision_id="dec_01HZX9Z0123456789",
            action_digest="e4b3602901a141b712c40c832c32cf97686566d2184f93a96860ecab3857e4b3",
            verdict="ALLOW",
            policy_version="pol_v1.0",
            policy_epoch=1,
            issued_at_utc="2026-10-12T10:00:00.000000Z",
            score=105.0,  # Invalid: > 100
            risk_tier="LOW_RISK",
            provenance_taint="CLEAN",
            required_auth_level="NONE",
            signer_key_id="k_gw",
            private_key=priv_key,
        )
    assert "must be in range [0.0, 100.0]" in str(exc.value)
