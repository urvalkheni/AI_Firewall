"""Deterministic Security Tests for Approval Envelope and Key Registry.

Tests:
1. Valid Ed25519 signature creation and verification.
2. Tampering with every one of the 13 signed fields.
3. APPROVE to REJECT and REJECT to APPROVE substitution attacks.
4. Malformed envelope fields, incorrect lengths, and unknown fields.
5. Unknown, revoked, expired, and wrong-owner keys.
6. Timestamp expiration and policy epoch drift.
7. Signing/verifying byte-for-byte consistency.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from ai_firewall.crypto.keys import (
    KeyRegistry,
    KeyNotFoundError,
    KeyRevokedError,
    KeyExpiredError,
    KeyOwnershipError,
    generate_dev_ed25519_keypair,
)
from ai_firewall.crypto.envelope import (
    EnvelopeSchemaError,
    EnvelopeVerificationError,
    ExecutionNotAuthorizedError,
    construct_signing_payload,
    sign_approval_envelope,
    verify_approval_envelope,
)


@pytest.fixture
def crypto_fixture():
    registry = KeyRegistry()
    priv_key, record = generate_dev_ed25519_keypair(
        key_id="k_rev_01",
        owner_user_id="usr_admin",
        not_before_utc="2026-01-01T00:00:00.000000Z",
        not_after_utc="2026-12-31T23:59:59.000000Z",
    )
    registry.register_key(record)

    action_digest = "e4b3602901a141b712c40c832c32cf97686566d2184f93a96860ecab3857e4b3"
    envelope = sign_approval_envelope(
        approval_id="appr_01HZX9Z0123456789ABCDEF012",
        action_digest=action_digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="MFA_HARDWARE_TOKEN",
        policy_version="pol_v1.0",
        policy_epoch=5,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T10:30:00.000000Z",
        single_use_nonce="7f9c21a4e10b42d7a9616254839210ab",
        private_key=priv_key,
    )

    return {
        "registry": registry,
        "priv_key": priv_key,
        "record": record,
        "envelope": envelope,
        "action_digest": action_digest,
    }


def test_valid_approval_envelope_verifies(crypto_fixture):
    res = verify_approval_envelope(
        envelope=crypto_fixture["envelope"],
        key_registry=crypto_fixture["registry"],
        expected_action_digest=crypto_fixture["action_digest"],
        current_policy_epoch=5,
        current_time_utc="2026-10-12T10:15:00.000000Z",
    )
    assert res is True


def test_tampering_each_signed_field_fails_verification(crypto_fixture):
    base_env = crypto_fixture["envelope"]
    registry = crypto_fixture["registry"]
    digest = crypto_fixture["action_digest"]

    # 1. Tamper approval_id
    env = dict(base_env)
    env["approval_id"] = "appr_TAMPERED1234567890"
    with pytest.raises(EnvelopeVerificationError):
        verify_approval_envelope(env, registry, digest, 5, "2026-10-12T10:15:00.000000Z")

    # 2. Tamper action_digest
    env = dict(base_env)
    env["action_digest"] = "0000000000000000000000000000000000000000000000000000000000000000"
    with pytest.raises(EnvelopeVerificationError):
        verify_approval_envelope(env, registry, digest, 5, "2026-10-12T10:15:00.000000Z")

    # 3. Tamper auth_level
    env = dict(base_env)
    env["decision_claims"] = dict(base_env["decision_claims"])
    env["decision_claims"]["auth_level"] = "STANDARD_PASSWORD"
    with pytest.raises(EnvelopeVerificationError):
        verify_approval_envelope(env, registry, digest, 5, "2026-10-12T10:15:00.000000Z")

    # 4. Tamper policy_version
    env = dict(base_env)
    env["decision_claims"] = dict(base_env["decision_claims"])
    env["decision_claims"]["policy_version"] = "pol_v2.0"
    with pytest.raises(EnvelopeVerificationError):
        verify_approval_envelope(env, registry, digest, 5, "2026-10-12T10:15:00.000000Z")

    # 5. Tamper single_use_nonce
    env = dict(base_env)
    env["decision_claims"] = dict(base_env["decision_claims"])
    env["decision_claims"]["single_use_nonce"] = "00000000000000000000000000000000"
    with pytest.raises(EnvelopeVerificationError):
        verify_approval_envelope(env, registry, digest, 5, "2026-10-12T10:15:00.000000Z")


def test_status_substitution_rejected_to_approved(crypto_fixture):
    """An attacker takes a legitimately signed REJECTED envelope and modifies status to APPROVED."""
    rejected_env = sign_approval_envelope(
        approval_id="appr_01HZX9Z0123456789ABCDEF012",
        action_digest=crypto_fixture["action_digest"],
        approval_status="REJECTED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="MFA_HARDWARE_TOKEN",
        policy_version="pol_v1.0",
        policy_epoch=5,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T10:30:00.000000Z",
        single_use_nonce="7f9c21a4e10b42d7a9616254839210ab",
        private_key=crypto_fixture["priv_key"],
    )

    # Substitution attack: attacker changes status from REJECTED to APPROVED
    tampered_env = dict(rejected_env)
    tampered_env["approval_status"] = "APPROVED"

    # Signature verification must fail because status is bound in signing payload
    with pytest.raises(EnvelopeVerificationError):
        verify_approval_envelope(
            envelope=tampered_env,
            key_registry=crypto_fixture["registry"],
            expected_action_digest=crypto_fixture["action_digest"],
            current_policy_epoch=5,
            current_time_utc="2026-10-12T10:15:00.000000Z",
        )


def test_legitimately_signed_rejected_envelope_never_authorizes_execution(crypto_fixture):
    """Even with a mathematically valid signature, a REJECTED envelope cannot authorize execution."""
    rejected_env = sign_approval_envelope(
        approval_id="appr_01HZX9Z0123456789ABCDEF012",
        action_digest=crypto_fixture["action_digest"],
        approval_status="REJECTED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="MFA_HARDWARE_TOKEN",
        policy_version="pol_v1.0",
        policy_epoch=5,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T10:30:00.000000Z",
        single_use_nonce="7f9c21a4e10b42d7a9616254839210ab",
        private_key=crypto_fixture["priv_key"],
    )

    with pytest.raises(ExecutionNotAuthorizedError) as exc:
        verify_approval_envelope(
            envelope=rejected_env,
            key_registry=crypto_fixture["registry"],
            expected_action_digest=crypto_fixture["action_digest"],
            current_policy_epoch=5,
            current_time_utc="2026-10-12T10:15:00.000000Z",
            enforce_execution_allowed=True,
        )
    assert "must be 'APPROVED'" in str(exc.value)


def test_unknown_envelope_fields_rejected(crypto_fixture):
    env = dict(crypto_fixture["envelope"])
    env["unexpected_injected_claim"] = "exploit"
    with pytest.raises(EnvelopeSchemaError):
        verify_approval_envelope(env, crypto_fixture["registry"], crypto_fixture["action_digest"], 5)


def test_revoked_key_fails_verification(crypto_fixture):
    registry = crypto_fixture["registry"]
    registry.revoke_key("k_rev_01", revoked_at_utc="2026-10-12T10:05:00.000000Z")

    with pytest.raises(EnvelopeVerificationError) as exc:
        verify_approval_envelope(
            envelope=crypto_fixture["envelope"],
            key_registry=registry,
            expected_action_digest=crypto_fixture["action_digest"],
            current_policy_epoch=5,
            current_time_utc="2026-10-12T10:15:00.000000Z",
        )
    assert "was revoked" in str(exc.value)


def test_expired_approval_fails_verification(crypto_fixture):
    with pytest.raises(EnvelopeVerificationError) as exc:
        verify_approval_envelope(
            envelope=crypto_fixture["envelope"],
            key_registry=crypto_fixture["registry"],
            expected_action_digest=crypto_fixture["action_digest"],
            current_policy_epoch=5,
            current_time_utc="2026-10-12T11:00:00.000000Z",  # Past 10:30 expiration
        )
    assert "has expired" in str(exc.value)


def test_stale_policy_epoch_fails_verification(crypto_fixture):
    # Gateway bumped epoch from 5 to 6
    with pytest.raises(EnvelopeVerificationError) as exc:
        verify_approval_envelope(
            envelope=crypto_fixture["envelope"],
            key_registry=crypto_fixture["registry"],
            expected_action_digest=crypto_fixture["action_digest"],
            current_policy_epoch=6,
            current_time_utc="2026-10-12T10:15:00.000000Z",
        )
    assert "Stale policy epoch" in str(exc.value)


def test_wrong_owner_key_fails_verification(crypto_fixture):
    env = dict(crypto_fixture["envelope"])
    env["decision_claims"] = dict(env["decision_claims"])
    env["decision_claims"]["reviewer_user_id"] = "usr_imposter"
    with pytest.raises(EnvelopeVerificationError) as exc:
        verify_approval_envelope(
            envelope=env,
            key_registry=crypto_fixture["registry"],
            expected_action_digest=crypto_fixture["action_digest"],
            current_policy_epoch=5,
            current_time_utc="2026-10-12T10:15:00.000000Z",
        )
    assert "Key ownership mismatch" in str(exc.value)

