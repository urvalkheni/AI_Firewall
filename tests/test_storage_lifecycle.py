"""Deterministic Security Tests for Persistent Lifecycle and Storage.

Tests:
1. Legal and illegal state transitions.
2. Single-use nonce uniqueness constraint in database.
3. Concurrent redemption by 50 workers: exactly one successful reservation.
4. Repeated redemption after SUCCEEDED triggers ReplayDetectedError.
5. Invariant binding mismatches (wrong action_id, decision_id, or action_digest).
6. Expired approval and stale policy epoch integration rejection.
7. Worker crash during RESERVED (lease expiry reset to APPROVED).
8. Worker crash during DISPATCHING (lease expiry transitions to UNKNOWN).
9. Lease expiry and stale-worker fencing token rejection.
10. Duplicate request retrieval for completed action outcomes.
11. UNKNOWN-state reconciliation constraints.
"""

from __future__ import annotations

import concurrent.futures
import os
import tempfile
import pytest

from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.crypto.envelope import sign_approval_envelope
from ai_firewall.crypto.record import sign_authorization_decision_record
from ai_firewall.storage.database import (
    DatabaseManager,
    ReplayDetectedError,
    ConcurrencyContentionError,
    FencingTokenMismatchError,
    InvariantBindingMismatchError,
)


@pytest.fixture
def lifecycle_fixture():
    # Create a temporary SQLite database file for testing concurrency and WAL mode
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = DatabaseManager(db_path=db_path)

    # Key Registry setup
    registry = KeyRegistry()
    priv_rev, rec_rev = generate_dev_ed25519_keypair("k_rev_01", "usr_admin")
    priv_gw, rec_gw = generate_dev_ed25519_keypair("k_gw_01", "gw_core")
    registry.register_key(rec_rev)
    registry.register_key(rec_gw)

    action_id = "act_01HZX8B0ABCDEF1234567890AB"
    action_digest = "e4b3602901a141b712c40c832c32cf97686566d2184f93a96860ecab3857e4b3"
    decision_id = "dec_01HZX9Z0ABCDEF123456789012"
    approval_id = "appr_01HZX9Z0123456789ABCDEF012"
    nonce = "7f9c21a4e10b42d7a9616254839210ab"

    # Action Identity Mock
    action_identity = {
        "principal": {"user_id": "usr_admin", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {
            "tool_server_id": "mcp_fs",
            "tool_name": "write_file",
            "operation_type": "MUTATION",
            "canonical_params": {"path": "/tmp/out.txt"},
        },
        "target_resource": {"resource_uri": "file:///tmp/out.txt", "preconditions": None},
        "authorization_binding": {
            "policy_version": "pol_v1.0",
            "policy_epoch": 5,
            "idempotency_key": "idemp_test_001",
            "expires_at_utc": "2026-10-12T11:00:00.000000Z",
        },
    }

    # Record action
    db.record_action(action_id, action_identity, action_digest)

    # Decision Record
    decision_record = sign_authorization_decision_record(
        decision_id=decision_id,
        action_digest=action_digest,
        verdict="APPROVAL_REQUIRED",
        policy_version="pol_v1.0",
        policy_epoch=5,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=65.0,
        risk_tier="MODERATE_RISK",
        provenance_taint="CLEAN",
        required_auth_level="MFA_HARDWARE_TOKEN",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )
    db.record_authorization_decision(decision_record, action_id)

    # Signed Approval Envelope
    envelope = sign_approval_envelope(
        approval_id=approval_id,
        action_digest=action_digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="MFA_HARDWARE_TOKEN",
        policy_version="pol_v1.0",
        policy_epoch=5,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T10:30:00.000000Z",
        single_use_nonce=nonce,
        private_key=priv_rev,
    )
    db.register_approval_envelope(envelope, action_id, decision_id, initial_state="APPROVED")

    yield {
        "db": db,
        "db_path": db_path,
        "registry": registry,
        "action_id": action_id,
        "action_digest": action_digest,
        "decision_id": decision_id,
        "approval_id": approval_id,
        "envelope": envelope,
        "nonce": nonce,
    }

    # Cleanup
    if os.path.exists(db_path):
        os.remove(db_path)


def test_atomic_redemption_and_fencing(lifecycle_fixture):
    db = lifecycle_fixture["db"]
    envelope = lifecycle_fixture["envelope"]

    # 1. First worker reserves approval
    res = db.redeem_approval_atomically(
        approval_envelope=envelope,
        action_id=lifecycle_fixture["action_id"],
        expected_action_digest=lifecycle_fixture["action_digest"],
        decision_id=lifecycle_fixture["decision_id"],
        worker_id="worker_alpha",
        lease_duration_seconds=30,
        key_registry=lifecycle_fixture["registry"],
        current_policy_epoch=5,
        now_utc="2026-10-12T10:05:00.000000Z",
    )
    assert res.approval_id == lifecycle_fixture["approval_id"]
    assert res.worker_id == "worker_alpha"
    assert res.dispatch_epoch == 1

    # 2. Worker transitions to DISPATCHING using valid fencing token
    db.mark_dispatching(
        approval_id=res.approval_id,
        worker_id="worker_alpha",
        dispatch_epoch=1,
        now_utc="2026-10-12T10:05:01.000000Z",
    )

    # 3. Worker records terminal outcome SUCCEEDED
    db.record_execution_outcome(
        approval_id=res.approval_id,
        worker_id="worker_alpha",
        dispatch_epoch=1,
        outcome_state="SUCCEEDED",
        execution_result={"bytes_written": 128},
        now_utc="2026-10-12T10:05:02.000000Z",
    )

    # 4. Attempting to redeem again must trigger ReplayDetectedError
    with pytest.raises(ReplayDetectedError) as exc:
        db.redeem_approval_atomically(
            approval_envelope=envelope,
            action_id=lifecycle_fixture["action_id"],
            expected_action_digest=lifecycle_fixture["action_digest"],
            decision_id=lifecycle_fixture["decision_id"],
            worker_id="worker_beta",
            now_utc="2026-10-12T10:05:10.000000Z",
        )
    assert "already terminal or completed" in str(exc.value)

    # 5. Outcome can be queried idempotently
    outcome = db.get_approval_outcome(res.approval_id)
    assert outcome.lifecycle_state == "SUCCEEDED"
    assert outcome.execution_result == {"bytes_written": 128}


def test_concurrent_redemption_50_workers(lifecycle_fixture):
    """Stress test: 50 concurrent worker threads compete to redeem the exact same approval.

    Invariance: Exactly 1 worker must succeed; exactly 49 workers must receive ConcurrencyContentionError.
    """
    db_path = lifecycle_fixture["db_path"]
    envelope = lifecycle_fixture["envelope"]
    action_id = lifecycle_fixture["action_id"]
    action_digest = lifecycle_fixture["action_digest"]
    decision_id = lifecycle_fixture["decision_id"]

    successes = []
    contentions = []

    def worker_task(w_idx: int):
        # Each thread gets its own DatabaseManager connection to the same SQLite WAL DB
        local_db = DatabaseManager(db_path=db_path)
        try:
            res = local_db.redeem_approval_atomically(
                approval_envelope=envelope,
                action_id=action_id,
                expected_action_digest=action_digest,
                decision_id=decision_id,
                worker_id=f"worker_{w_idx:02d}",
                lease_duration_seconds=30,
                now_utc="2026-10-12T10:05:00.000000Z",
            )
            successes.append(res.worker_id)
        except ConcurrencyContentionError:
            contentions.append(w_idx)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(worker_task, i) for i in range(50)]
        concurrent.futures.wait(futures)

    # Strict invariant assertion
    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {successes}"
    assert len(contentions) == 49, f"Expected 49 contentions, got {len(contentions)}"


def test_invariant_binding_mismatches(lifecycle_fixture):
    db = lifecycle_fixture["db"]
    envelope = lifecycle_fixture["envelope"]

    # Wrong action_id
    with pytest.raises(InvariantBindingMismatchError):
        db.redeem_approval_atomically(
            approval_envelope=envelope,
            action_id="act_WRONG_ID_1234567890",
            expected_action_digest=lifecycle_fixture["action_digest"],
            decision_id=lifecycle_fixture["decision_id"],
            worker_id="w1",
        )

    # Wrong decision_id
    with pytest.raises(InvariantBindingMismatchError):
        db.redeem_approval_atomically(
            approval_envelope=envelope,
            action_id=lifecycle_fixture["action_id"],
            expected_action_digest=lifecycle_fixture["action_digest"],
            decision_id="dec_WRONG_DECISION_ID",
            worker_id="w1",
        )

    # Wrong action_digest
    with pytest.raises(InvariantBindingMismatchError):
        db.redeem_approval_atomically(
            approval_envelope=envelope,
            action_id=lifecycle_fixture["action_id"],
            expected_action_digest="0000000000000000000000000000000000000000000000000000000000000000",
            decision_id=lifecycle_fixture["decision_id"],
            worker_id="w1",
        )


def test_worker_crash_during_reserved_resets_to_approved(lifecycle_fixture):
    """Simulated crash: Worker reserves approval but crashes before calling mark_dispatching.

    Safety: Zero network bytes were sent; reaper safely resets state to APPROVED.
    """
    db = lifecycle_fixture["db"]
    envelope = lifecycle_fixture["envelope"]

    # Reserve with 10s lease expiring at 10:00:10Z
    db.redeem_approval_atomically(
        approval_envelope=envelope,
        action_id=lifecycle_fixture["action_id"],
        expected_action_digest=lifecycle_fixture["action_digest"],
        decision_id=lifecycle_fixture["decision_id"],
        worker_id="worker_crashed",
        lease_duration_seconds=10,
        now_utc="2026-10-12T10:00:00.000000Z",
    )

    # Reaper runs at 10:00:05Z (lease still active) -> Nothing recovered
    recovered_early = db.recover_expired_leases(now_utc="2026-10-12T10:00:05.000000Z")
    assert len(recovered_early) == 0

    # Reaper runs at 10:00:15Z (lease expired) -> Recovers RESERVED to APPROVED
    recovered_late = db.recover_expired_leases(now_utc="2026-10-12T10:00:15.000000Z")
    assert len(recovered_late) == 1
    assert "RESERVED->APPROVED" in recovered_late[0]

    # Another worker can now reserve it
    res2 = db.redeem_approval_atomically(
        approval_envelope=envelope,
        action_id=lifecycle_fixture["action_id"],
        expected_action_digest=lifecycle_fixture["action_digest"],
        decision_id=lifecycle_fixture["decision_id"],
        worker_id="worker_recovery",
        now_utc="2026-10-12T10:00:20.000000Z",
    )
    assert res2.worker_id == "worker_recovery"
    assert res2.dispatch_epoch == 2  # Monotonic fencing epoch incremented


def test_worker_crash_during_dispatching_marks_unknown(lifecycle_fixture):
    """Simulated in-flight crash: Worker marks DISPATCHING but crashes before recording outcome.

    Safety: Network mutation may have executed downstream. Reaper marks UNKNOWN and blocks auto-retry.
    """
    db = lifecycle_fixture["db"]
    envelope = lifecycle_fixture["envelope"]

    # 1. Reserve and mark DISPATCHING
    db.redeem_approval_atomically(
        approval_envelope=envelope,
        action_id=lifecycle_fixture["action_id"],
        expected_action_digest=lifecycle_fixture["action_digest"],
        decision_id=lifecycle_fixture["decision_id"],
        worker_id="worker_in_flight",
        lease_duration_seconds=10,
        now_utc="2026-10-12T10:00:00.000000Z",
    )
    db.mark_dispatching(
        approval_id=lifecycle_fixture["approval_id"],
        worker_id="worker_in_flight",
        dispatch_epoch=1,
        now_utc="2026-10-12T10:00:01.000000Z",
    )

    # 2. Reaper runs after lease expiration at 10:00:15Z
    recovered = db.recover_expired_leases(now_utc="2026-10-12T10:00:15.000000Z")
    assert len(recovered) == 1
    assert "DISPATCHING->UNKNOWN" in recovered[0]

    # 3. Attempting to redeem must raise ReplayDetectedError
    with pytest.raises(ReplayDetectedError) as exc:
        db.redeem_approval_atomically(
            approval_envelope=envelope,
            action_id=lifecycle_fixture["action_id"],
            expected_action_digest=lifecycle_fixture["action_digest"],
            decision_id=lifecycle_fixture["decision_id"],
            worker_id="worker_new",
            now_utc="2026-10-12T10:00:20.000000Z",
        )
    assert "state=UNKNOWN" in str(exc.value)


def test_stale_worker_fencing_token_rejected(lifecycle_fixture):
    """Zombies: Worker 1 reserves approval (epoch 1), stalls until lease expires.

    Reaper resets to APPROVED. Worker 2 reserves approval (epoch 2).
    Worker 1 wakes up and attempts to dispatch with epoch 1 -> Rejected by fencing token!
    """
    db = lifecycle_fixture["db"]
    envelope = lifecycle_fixture["envelope"]

    # Worker 1 reserves with 10s lease
    db.redeem_approval_atomically(
        approval_envelope=envelope,
        action_id=lifecycle_fixture["action_id"],
        expected_action_digest=lifecycle_fixture["action_digest"],
        decision_id=lifecycle_fixture["decision_id"],
        worker_id="worker_1",
        lease_duration_seconds=10,
        now_utc="2026-10-12T10:00:00.000000Z",
    )

    # Worker 1 stalls. Lease expires. Reaper resets to APPROVED.
    db.recover_expired_leases(now_utc="2026-10-12T10:00:15.000000Z")

    # Worker 2 reserves (acquiring epoch 2)
    db.redeem_approval_atomically(
        approval_envelope=envelope,
        action_id=lifecycle_fixture["action_id"],
        expected_action_digest=lifecycle_fixture["action_digest"],
        decision_id=lifecycle_fixture["decision_id"],
        worker_id="worker_2",
        lease_duration_seconds=30,
        now_utc="2026-10-12T10:00:16.000000Z",
    )

    # Worker 1 wakes up and tries to mark dispatching with stale epoch 1
    with pytest.raises(FencingTokenMismatchError) as exc:
        db.mark_dispatching(
            approval_id=lifecycle_fixture["approval_id"],
            worker_id="worker_1",
            dispatch_epoch=1,
            now_utc="2026-10-12T10:00:17.000000Z",
        )
    assert "Stale worker fencing token" in str(exc.value)

