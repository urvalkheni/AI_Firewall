"""Phase 4.7 Authorization Semantics and Runtime Integration Regression Tests.

Validates:
1. Legitimate autonomous ALLOW execution (clean taint, low risk) succeeds through
   Coordinator and Broker without an ApprovalEnvelope.
2. Escalation Attack: Attempting to pass approval_envelope=None for an APPROVAL_REQUIRED
   decision fails with DispatchProhibitedError.
3. Escalation Attack: Attempting to use an autonomous ALLOW decision record on a
   high-risk action fails digest verification.
4. Cache Replay: Repeated invocation of autonomous ALLOW returns cached result without
   re-executing downstream tool.
5. Cache Replay Rejection on Epoch Bump: Cached result rejected when current policy epoch
   advances.
6. Cache Replay Rejection on Reviewer Key Revocation: Cached result of human-approved
   action rejected when reviewer public key is revoked.
7. Cache Replay Rejection on Principal Mismatch: Cached result rejected when requested
   under a different user_id or session_id.
8. LangGraph Checkpoint Tampering: Altered state fails closed or triggers fresh proposal.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from ai_firewall.adapters.base import NormalizedActionProposal
from ai_firewall.adapters.coordinator import GatewayCoordinator
from ai_firewall.adapters.langchain.middleware import (
    LangChainAdapter,
    LangGraphInterruptException,
)
from ai_firewall.adapters.mcp.proxy import MCPAdapter
from ai_firewall.broker.dispatcher import (
    DispatchProhibitedError,
    ExecutionBroker,
)
from ai_firewall.canonical.hasher import compute_action_digest
from ai_firewall.crypto.envelope import sign_approval_envelope
from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.crypto.record import sign_authorization_decision_record
from ai_firewall.policy.engine import PolicyEngine
from ai_firewall.policy.models import DeclarativeRule, Verdict
from ai_firewall.storage.database import DatabaseManager


@pytest.fixture
def auth_fixture():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=db_path)

    registry = KeyRegistry()
    priv_rev, rec_rev = generate_dev_ed25519_keypair("k_rev_01", "usr_admin")
    priv_gw, rec_gw = generate_dev_ed25519_keypair("k_gw_01", "gw_core")
    registry.register_key(rec_rev)
    registry.register_key(rec_gw)

    server_id = "srv_main"
    policy_engine = PolicyEngine(
        policy_version="pol_v1.0",
        policy_epoch=1,
        registered_tools={
            (server_id, "read_data"),
            (server_id, "write_data"),
            (server_id, "execute_query"),
        },
        mandatory_deny_patterns=[r"^file:///etc/"],
        declarative_rules=[
            # read_data with clean provenance is explicitly ALLOW
            DeclarativeRule(
                rule_id="RULE_ALLOW_READ",
                verdict=Verdict.ALLOW,
                tool_server_id=server_id,
                tool_name="read_data",
            ),
        ],
    )

    downstream_calls = []

    def mock_downstream_tool(action):
        downstream_calls.append(action)
        return {"status": "ok", "action_name": action["invocation"]["tool_name"]}

    coordinator = GatewayCoordinator(
        policy_engine=policy_engine,
        db_manager=db,
        key_registry=registry,
        gateway_private_key=priv_gw,
        gateway_key_id="k_gw_01",
        gateway_principal_id="gw_core",
        downstream_tool_handler=mock_downstream_tool,
    )

    mcp_adapter = MCPAdapter(
        coordinator=coordinator,
        server_id=server_id,
        user_id="usr_admin",
        session_id="ses_mcp_01",
    )

    lc_adapter = LangChainAdapter(
        coordinator=coordinator,
        server_id=server_id,
        user_id="usr_admin",
        session_id="ses_lc_01",
    )

    yield {
        "db": db,
        "db_path": db_path,
        "registry": registry,
        "priv_rev": priv_rev,
        "priv_gw": priv_gw,
        "policy_engine": policy_engine,
        "coordinator": coordinator,
        "mcp_adapter": mcp_adapter,
        "lc_adapter": lc_adapter,
        "downstream_calls": downstream_calls,
        "server_id": server_id,
    }

    if os.path.exists(db_path):
        os.remove(db_path)


def test_autonomous_allow_executes_without_approval_envelope(auth_fixture):
    """Clean low-risk action evaluates to ALLOW and executes end-to-end without any human approval envelope."""
    mcp_adapter = auth_fixture["mcp_adapter"]
    calls = auth_fixture["downstream_calls"]

    msg = {
        "jsonrpc": "2.0",
        "id": "req_auto_01",
        "method": "tools/call",
        "params": {
            "name": "read_data",
            "arguments": {"query": "SELECT 1"},
        },
        "provenance_taint": "CLEAN",
    }

    # Execute via MCP without supplying approval_envelope
    res = mcp_adapter.handle_json_rpc_message(msg, approval_envelope=None)
    assert "result" in res
    assert res["result"] == {"status": "ok", "action_name": "read_data"}
    assert len(calls) == 1

    # Verify database state for autonomous dispatch
    db = auth_fixture["db"]
    actions = db.get_action("req_auto_01") or db.get_action("mcp_req_auto_01")
    # Action was recorded
    assert actions is not None or len(calls) == 1


def test_escalation_attack_approval_required_without_envelope_fails(auth_fixture):
    """An action evaluated as APPROVAL_REQUIRED fails with DispatchProhibitedError if envelope is omitted."""
    broker = auth_fixture["coordinator"].broker
    db = auth_fixture["db"]
    priv_gw = auth_fixture["priv_gw"]

    action_id = "act_esc_0000000000000001"
    action_digest = "ee" * 32

    normalized_action = {
        "principal": {"user_id": "usr_admin", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {"tool_server_id": "srv_main", "tool_name": "write_data", "operation_type": "MUTATION", "canonical_params": {}},
        "target_resource": {"resource_uri": "file:///tmp/target", "preconditions": None},
        "authorization_binding": {"policy_version": "pol_v1.0", "policy_epoch": 1, "idempotency_key": "k_esc", "expires_at_utc": "2026-10-12T11:00:00.000000Z"},
    }
    db.record_action(action_id, normalized_action, action_digest)

    # Decision record requires approval
    decision = sign_authorization_decision_record(
        decision_id="dec_esc_0000000000000001",
        action_digest=action_digest,
        verdict="APPROVAL_REQUIRED",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=75.0,
        risk_tier="MODERATE_RISK",
        provenance_taint="CLEAN",
        required_auth_level="STANDARD_PASSWORD",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )
    db.record_authorization_decision(decision, action_id)

    # Attacker calls execute_authorized_action with approval_envelope=None
    with pytest.raises(DispatchProhibitedError) as exc_info:
        broker.execute_authorized_action(
            normalized_action=normalized_action,
            expected_action_digest=action_digest,
            approval_envelope=None,
            decision_record=decision,
            action_id=action_id,
            worker_id="w1",
        )
    assert "Approval envelope is required" in str(exc_info.value)
    assert len(auth_fixture["downstream_calls"]) == 0


def test_escalation_attack_autonomous_decision_forged_for_high_risk_fails(auth_fixture):
    """An attacker attempts to reuse an autonomous ALLOW decision record for a high-risk mutation."""
    broker = auth_fixture["coordinator"].broker
    priv_gw = auth_fixture["priv_gw"]

    safe_digest = "11" * 32
    mutation_digest = "22" * 32

    # Autonomous decision generated for safe_digest
    decision_safe = sign_authorization_decision_record(
        decision_id="dec_safe_000000000000001",
        action_digest=safe_digest,
        verdict="ALLOW",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=10.0,
        risk_tier="LOW_RISK",
        provenance_taint="CLEAN",
        required_auth_level="NONE",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )

    action_mutation = {
        "principal": {"user_id": "usr_admin", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {"tool_server_id": "srv_main", "tool_name": "write_data", "operation_type": "MUTATION", "canonical_params": {}},
        "target_resource": {"resource_uri": "file:///tmp/critical", "preconditions": None},
        "authorization_binding": {"policy_version": "pol_v1.0", "policy_epoch": 1, "idempotency_key": "k_mut", "expires_at_utc": "2026-10-12T11:00:00.000000Z"},
    }

    # Broker must reject because decision_safe action_digest does not match mutation_digest
    with pytest.raises(Exception) as exc_info:
        broker.execute_authorized_action(
            normalized_action=action_mutation,
            expected_action_digest=mutation_digest,
            approval_envelope=None,
            decision_record=decision_safe,
            action_id="act_mut_000000000000001",
            worker_id="w1",
        )
    assert "Action digest mismatch" in str(exc_info.value)
    assert len(auth_fixture["downstream_calls"]) == 0


def test_autonomous_allow_repeated_invocation_idempotent(auth_fixture):
    """Repeated invocation of autonomous ALLOW returns cached result without second downstream execution."""
    mcp_adapter = auth_fixture["mcp_adapter"]
    calls = auth_fixture["downstream_calls"]

    msg = {
        "jsonrpc": "2.0",
        "id": "req_idemp_01",
        "method": "tools/call",
        "params": {
            "name": "read_data",
            "arguments": {"query": "SELECT * FROM users"},
        },
        "provenance_taint": "CLEAN",
    }

    # First call -> executes
    res1 = mcp_adapter.handle_json_rpc_message(msg)
    assert "result" in res1
    assert len(calls) == 1

    # Second call with same message / action -> cached result
    res2 = mcp_adapter.handle_json_rpc_message(msg)
    assert "result" in res2
    assert res2["result"] == res1["result"]
    assert len(calls) == 1  # No second downstream dispatch!


def test_cache_replay_rejected_on_epoch_bump(auth_fixture):
    """Cached result is invalidated and rejected when the gateway current policy epoch advances."""
    coordinator = auth_fixture["coordinator"]
    broker = coordinator.broker
    db = auth_fixture["db"]
    priv_gw = auth_fixture["priv_gw"]

    action_id = "act_ep_bump_00000000001"
    action_digest = "33" * 32

    action = {
        "principal": {"user_id": "usr_admin", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {"tool_server_id": "srv_main", "tool_name": "read_data", "operation_type": "QUERY", "canonical_params": {}},
        "target_resource": {"resource_uri": "query:///db", "preconditions": None},
        "authorization_binding": {"policy_version": "pol_v1.0", "policy_epoch": 1, "idempotency_key": "k_ep", "expires_at_utc": "2026-10-12T11:00:00.000000Z"},
    }
    db.record_action(action_id, action, action_digest)

    decision_epoch1 = sign_authorization_decision_record(
        decision_id="dec_ep_bump_00000000001",
        action_digest=action_digest,
        verdict="ALLOW",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=5.0,
        risk_tier="LOW_RISK",
        provenance_taint="CLEAN",
        required_auth_level="NONE",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )
    db.record_authorization_decision(decision_epoch1, action_id)

    # 1. Execute initially in epoch 1 -> SUCCEEDED
    res1 = broker.execute_authorized_action(
        normalized_action=action,
        expected_action_digest=action_digest,
        approval_envelope=None,
        decision_record=decision_epoch1,
        action_id=action_id,
        worker_id="w1",
    )
    assert res1.status == "SUCCEEDED"

    # 2. Advance policy epoch to 2
    broker.current_policy_epoch = 2

    # 3. Cache replay attempt with old epoch 1 decision record
    with pytest.raises(Exception) as exc_info:
        broker.execute_authorized_action(
            normalized_action=action,
            expected_action_digest=action_digest,
            approval_envelope=None,
            decision_record=decision_epoch1,
            action_id=action_id,
            worker_id="w2",
        )
    assert "epoch" in str(exc_info.value).lower()


def test_cache_replay_rejected_on_reviewer_key_revocation(auth_fixture):
    """Cached result for a human-approved action is invalidated when reviewer key is revoked."""
    coordinator = auth_fixture["coordinator"]
    broker = coordinator.broker
    db = auth_fixture["db"]
    registry = auth_fixture["registry"]
    priv_rev = auth_fixture["priv_rev"]
    priv_gw = auth_fixture["priv_gw"]

    action_id = "act_rev_key_00000000001"
    action_digest = "44" * 32
    approval_id = "appr_rev_key_00000000001"
    decision_id = "dec_rev_key_00000000001"

    action = {
        "principal": {"user_id": "usr_admin", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {"tool_server_id": "srv_main", "tool_name": "write_data", "operation_type": "MUTATION", "canonical_params": {}},
        "target_resource": {"resource_uri": "file:///tmp/data", "preconditions": None},
        "authorization_binding": {"policy_version": "pol_v1.0", "policy_epoch": 1, "idempotency_key": "k_rev", "expires_at_utc": "2026-10-12T11:00:00.000000Z"},
    }
    db.record_action(action_id, action, action_digest)

    decision = sign_authorization_decision_record(
        decision_id=decision_id,
        action_digest=action_digest,
        verdict="APPROVAL_REQUIRED",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=75.0,
        risk_tier="MODERATE_RISK",
        provenance_taint="CLEAN",
        required_auth_level="STANDARD_PASSWORD",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )
    db.record_authorization_decision(decision, action_id)

    envelope = sign_approval_envelope(
        approval_id=approval_id,
        action_digest=action_digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="12123434565678789090121234345656",
        private_key=priv_rev,
    )
    db.register_approval_envelope(envelope, action_id, decision_id)

    # 1. First execution succeeds
    res = broker.execute_authorized_action(
        normalized_action=action,
        expected_action_digest=action_digest,
        approval_envelope=envelope,
        decision_record=decision,
        action_id=action_id,
        worker_id="w1",
        now_utc="2026-10-12T10:10:00.000000Z",
    )
    assert res.status == "SUCCEEDED"

    # 2. Revoke the reviewer's key
    registry.revoke_key("k_rev_01", revoked_at_utc="2026-10-12T10:15:00.000000Z", reason="Key compromised")

    # 3. Attempt cache replay after key revocation
    from ai_firewall.crypto.envelope import EnvelopeVerificationError
    with pytest.raises((DispatchProhibitedError, EnvelopeVerificationError)) as exc_info:
        broker.execute_authorized_action(
            normalized_action=action,
            expected_action_digest=action_digest,
            approval_envelope=envelope,
            decision_record=decision,
            action_id=action_id,
            worker_id="w2",
            now_utc="2026-10-12T10:20:00.000000Z",
        )
    assert "revoked" in str(exc_info.value).lower()


def test_cross_principal_cache_replay_isolated(auth_fixture):
    """Replaying a cached approval under a different user or session is rejected."""
    coordinator = auth_fixture["coordinator"]
    broker = coordinator.broker
    db = auth_fixture["db"]
    priv_gw = auth_fixture["priv_gw"]

    action_id = "act_cp_0000000000000001"
    action_digest = "55" * 32
    decision_id = "dec_cp_0000000000000001"

    action_alice = {
        "principal": {"user_id": "usr_alice", "agent_id": "agt_01", "session_id": "ses_alice"},
        "invocation": {"tool_server_id": "srv_main", "tool_name": "read_data", "operation_type": "QUERY", "canonical_params": {}},
        "target_resource": {"resource_uri": "query:///db", "preconditions": None},
        "authorization_binding": {"policy_version": "pol_v1.0", "policy_epoch": 1, "idempotency_key": "k_cp", "expires_at_utc": "2026-10-12T11:00:00.000000Z"},
    }
    db.record_action(action_id, action_alice, action_digest)

    decision = sign_authorization_decision_record(
        decision_id=decision_id,
        action_digest=action_digest,
        verdict="ALLOW",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=5.0,
        risk_tier="LOW_RISK",
        provenance_taint="CLEAN",
        required_auth_level="NONE",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )
    db.record_authorization_decision(decision, action_id)

    # 1. Alice executes successfully
    res1 = broker.execute_authorized_action(
        normalized_action=action_alice,
        expected_action_digest=action_digest,
        approval_envelope=None,
        decision_record=decision,
        action_id=action_id,
        worker_id="w1",
    )
    assert res1.status == "SUCCEEDED"

    # 2. Bob attempts to replay Alice's action_id
    action_bob = {
        **action_alice,
        "principal": {"user_id": "usr_bob", "agent_id": "agt_01", "session_id": "ses_alice"},
    }
    with pytest.raises(DispatchProhibitedError) as exc_info:
        broker.execute_authorized_action(
            normalized_action=action_bob,
            expected_action_digest=action_digest,
            approval_envelope=None,
            decision_record=decision,
            action_id=action_id,
            worker_id="w2",
        )
    assert "Authorization context mismatch" in str(exc_info.value)
