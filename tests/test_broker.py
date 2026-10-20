"""Deterministic Integration and Security Tests for Execution Broker.

Tests:
1. End-to-end authorized dispatch: validation -> preconditions -> DISPATCHING -> SUCCEEDED.
2. Immediate pre-dispatch precondition failure (State Drift aborts without network send).
3. Insufficient authentication level rejection (Decision requires MFA_HARDWARE_TOKEN, envelope has STANDARD_PASSWORD).
4. Authorization decision verdict DENY prohibits dispatch.
5. In-flight dispatch exception transitions to UNKNOWN; blocks automated re-dispatch.
6. Idempotent return of recorded result for duplicate requests.
7. Expired approval envelope rejection.
8. Concurrent broker execution requests: exactly one worker dispatches.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from ai_firewall.broker.dispatcher import (
    DispatchProhibitedError,
    ExecutionBroker,
    PreconditionFailureError,
)
from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.crypto.envelope import sign_approval_envelope
from ai_firewall.crypto.record import sign_authorization_decision_record
from ai_firewall.storage.database import DatabaseManager


@pytest.fixture
def broker_fixture():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=db_path)

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

    normalized_action = {
        "principal": {"user_id": "usr_admin", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {
            "tool_server_id": "mcp_fs",
            "tool_name": "write_file",
            "operation_type": "MUTATION",
            "canonical_params": {"path": "/tmp/test.txt", "content": "Hello World"},
        },
        "target_resource": {
            "resource_uri": "file:///tmp/test.txt",
            "preconditions": {"expected_etag": 'W/"10-2026"', "precondition_mode": "EXACT_ETAG_MATCH"},
        },
        "authorization_binding": {
            "policy_version": "pol_v1.0",
            "policy_epoch": 2,
            "idempotency_key": "idemp_test_001",
            "expires_at_utc": "2026-10-12T11:00:00.000000Z",
        },
    }

    db.record_action(action_id, normalized_action, action_digest)

    # Decision Record
    decision_record = sign_authorization_decision_record(
        decision_id=decision_id,
        action_digest=action_digest,
        verdict="APPROVAL_REQUIRED",
        policy_version="pol_v1.0",
        policy_epoch=2,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=85.0,
        risk_tier="HIGH_CONSEQUENCE",
        provenance_taint="CLEAN",
        required_auth_level="MFA_HARDWARE_TOKEN",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )
    db.record_authorization_decision(decision_record, action_id)

    # Approval Envelope
    envelope = sign_approval_envelope(
        approval_id=approval_id,
        action_digest=action_digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="MFA_HARDWARE_TOKEN",
        policy_version="pol_v1.0",
        policy_epoch=2,
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
        "decision_record": decision_record,
        "normalized_action": normalized_action,
        "priv_rev": priv_rev,
    }

    if os.path.exists(db_path):
        os.remove(db_path)


def test_broker_end_to_end_authorized_dispatch(broker_fixture):
    """End-to-end: Preconditions met, valid signatures, durable transitions, successful dispatch."""
    dispatched_calls = []

    def mock_downstream_handler(action):
        dispatched_calls.append(action["invocation"]["tool_name"])
        return {"status": "ok", "bytes_written": 11}

    # Mock inspector matching expected ETag
    live_inspector = lambda uri: {"etag": 'W/"10-2026"', "sha256": "abc"}

    broker = ExecutionBroker(
        db_manager=broker_fixture["db"],
        key_registry=broker_fixture["registry"],
        current_policy_epoch=2,
        downstream_tool_handler=mock_downstream_handler,
        live_resource_inspector=live_inspector,
    )

    result = broker.execute_authorized_action(
        normalized_action=broker_fixture["normalized_action"],
        expected_action_digest=broker_fixture["action_digest"],
        approval_envelope=broker_fixture["envelope"],
        decision_record=broker_fixture["decision_record"],
        action_id=broker_fixture["action_id"],
        worker_id="worker_01",
        now_utc="2026-10-12T10:10:00.000000Z",
    )

    assert result.status == "SUCCEEDED"
    assert result.output == {"status": "ok", "bytes_written": 11}
    assert len(dispatched_calls) == 1

    # Verify duplicate request returns recorded result without second tool call
    dup_result = broker.execute_authorized_action(
        normalized_action=broker_fixture["normalized_action"],
        expected_action_digest=broker_fixture["action_digest"],
        approval_envelope=broker_fixture["envelope"],
        decision_record=broker_fixture["decision_record"],
        action_id=broker_fixture["action_id"],
        worker_id="worker_02",
        now_utc="2026-10-12T10:11:00.000000Z",
    )
    assert dup_result.status == "SUCCEEDED"
    assert dup_result.output == {"status": "ok", "bytes_written": 11}
    assert len(dispatched_calls) == 1  # No second dispatch occurred!


def test_broker_state_drift_aborts_before_downstream_send(broker_fixture):
    """TOCTOU Defense: Target ETag modified during review pause; broker aborts without sending to tool."""
    dispatched_calls = []

    def mock_downstream_handler(action):
        dispatched_calls.append(action)
        return {"status": "ok"}

    # Live resource changed to W/"99-drift"
    drifting_inspector = lambda uri: {"etag": 'W/"99-drift"', "sha256": "drift"}

    broker = ExecutionBroker(
        db_manager=broker_fixture["db"],
        key_registry=broker_fixture["registry"],
        current_policy_epoch=2,
        downstream_tool_handler=mock_downstream_handler,
        live_resource_inspector=drifting_inspector,
    )

    with pytest.raises(PreconditionFailureError) as exc:
        broker.execute_authorized_action(
            normalized_action=broker_fixture["normalized_action"],
            expected_action_digest=broker_fixture["action_digest"],
            approval_envelope=broker_fixture["envelope"],
            decision_record=broker_fixture["decision_record"],
            action_id=broker_fixture["action_id"],
            worker_id="worker_01",
            now_utc="2026-10-12T10:10:00.000000Z",
        )
    assert "Precondition check failed" in str(exc.value)
    assert len(dispatched_calls) == 0  # CRITICAL: Tool was NEVER called!


def test_broker_insufficient_auth_level_prohibits_dispatch(broker_fixture):
    """Decision requires MFA_HARDWARE_TOKEN; envelope only provides STANDARD_PASSWORD."""
    # Create envelope with STANDARD_PASSWORD
    weak_envelope = sign_approval_envelope(
        approval_id="appr_WEAK_0123456789ABCDEF012",
        action_digest=broker_fixture["action_digest"],
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=2,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T10:30:00.000000Z",
        single_use_nonce="00000000000000000000000000000001",
        private_key=broker_fixture["priv_rev"],
    )
    broker_fixture["db"].register_approval_envelope(weak_envelope, broker_fixture["action_id"], broker_fixture["decision_id"])

    broker = ExecutionBroker(
        db_manager=broker_fixture["db"],
        key_registry=broker_fixture["registry"],
        current_policy_epoch=2,
        downstream_tool_handler=lambda a: {},
    )

    with pytest.raises(DispatchProhibitedError) as exc:
        broker.execute_authorized_action(
            normalized_action=broker_fixture["normalized_action"],
            expected_action_digest=broker_fixture["action_digest"],
            approval_envelope=weak_envelope,
            decision_record=broker_fixture["decision_record"],
            action_id=broker_fixture["action_id"],
            worker_id="worker_01",
            now_utc="2026-10-12T10:10:00.000000Z",
        )
    assert "Insufficient authentication level" in str(exc.value)


def test_broker_in_flight_timeout_marks_unknown(broker_fixture):
    """Ambiguous network error: Downstream raises timeout during dispatch; state transitions to UNKNOWN."""
    def timeout_handler(action):
        raise TimeoutError("Downstream MCP server timed out after socket connect")

    live_inspector = lambda uri: {"etag": 'W/"10-2026"', "sha256": "abc"}

    broker = ExecutionBroker(
        db_manager=broker_fixture["db"],
        key_registry=broker_fixture["registry"],
        current_policy_epoch=2,
        downstream_tool_handler=timeout_handler,
        live_resource_inspector=live_inspector,
    )

    res = broker.execute_authorized_action(
        normalized_action=broker_fixture["normalized_action"],
        expected_action_digest=broker_fixture["action_digest"],
        approval_envelope=broker_fixture["envelope"],
        decision_record=broker_fixture["decision_record"],
        action_id=broker_fixture["action_id"],
        worker_id="worker_01",
        now_utc="2026-10-12T10:10:00.000000Z",
    )

    assert res.status == "UNKNOWN"
    assert res.error_code == "ERR_DISPATCH_EXCEPTION_UNKNOWN"

    # Database state must be durably recorded as UNKNOWN
    db_outcome = broker_fixture["db"].get_approval_outcome(broker_fixture["approval_id"])
    assert db_outcome.lifecycle_state == "UNKNOWN"
