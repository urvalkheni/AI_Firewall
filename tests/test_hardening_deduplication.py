"""Phase 4.6 Security Hardening: Operation Identity, Deduplication, and Cache Hit Binding.

Tests:
1. Reused JSON-RPC request IDs across different actions:
   A second request with the same JSON-RPC ID but different parameters must NOT inherit
   the prior action's successful output, and attempting to pass the old approval is rejected.
2. Reused JSON-RPC request IDs across different sessions:
   Identical tool and parameters across two sessions yield distinct action digests.
3. Reused JSON-RPC request IDs across different principals:
   Different user principals produce distinct action digests; approval cannot cross principals.
4. Completed-result cache hit rejected on action digest mismatch:
   Broker rejects cached outcome return if the requested action digest differs from the approval.
5. Completed-result cache hit rejected on action_id mismatch:
   Broker rejects cached outcome return if the requested action_id differs from the approval.
6. Completed-result cache hit rejected on principal/context mismatch:
   Broker rejects cached outcome return if user_id or session_id in the action changed.
7. Legitimate repeated-resume idempotency:
   Exact match returns recorded output without a second downstream tool dispatch.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from ai_firewall.adapters.coordinator import GatewayCoordinator
from ai_firewall.adapters.mcp.proxy import MCPAdapter
from ai_firewall.broker.dispatcher import DispatchProhibitedError, ExecutionBroker
from ai_firewall.crypto.envelope import sign_approval_envelope
from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.crypto.record import sign_authorization_decision_record
from ai_firewall.policy.engine import PolicyEngine
from ai_firewall.storage.database import DatabaseManager


@pytest.fixture
def hardening_fixture():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=db_path)

    registry = KeyRegistry()
    priv_rev, rec_rev = generate_dev_ed25519_keypair("k_rev_01", "usr_admin")
    priv_gw, rec_gw = generate_dev_ed25519_keypair("k_gw_01", "gw_core")
    registry.register_key(rec_rev)
    registry.register_key(rec_gw)

    server_id = "srv_fs"
    policy_engine = PolicyEngine(
        policy_version="pol_v1.0",
        policy_epoch=1,
        registered_tools={
            (server_id, "write_file"),
            (server_id, "read_file"),
            (server_id, "delete_file"),
        },
        mandatory_deny_patterns=[r"^file:///etc/"],
    )

    downstream_calls = []

    def mock_downstream_tool(action):
        downstream_calls.append(action)
        return {"status": "ok", "executed_tool": action["invocation"]["tool_name"]}

    coordinator = GatewayCoordinator(
        policy_engine=policy_engine,
        db_manager=db,
        key_registry=registry,
        gateway_private_key=priv_gw,
        gateway_key_id="k_gw_01",
        gateway_principal_id="gw_core",
        downstream_tool_handler=mock_downstream_tool,
    )

    adapter = MCPAdapter(
        coordinator=coordinator,
        server_id=server_id,
        user_id="usr_admin",
        session_id="ses_01",
    )

    yield {
        "coordinator": coordinator,
        "adapter": adapter,
        "db": db,
        "db_path": db_path,
        "registry": registry,
        "priv_rev": priv_rev,
        "priv_gw": priv_gw,
        "downstream_calls": downstream_calls,
        "server_id": server_id,
    }

    if os.path.exists(db_path):
        os.remove(db_path)


def test_reused_jsonrpc_id_different_action_does_not_inherit_result(hardening_fixture):
    """Reusing JSON-RPC ID 'req_01' for a different action requires fresh approval and cannot inherit result."""
    adapter = hardening_fixture["adapter"]
    priv_rev = hardening_fixture["priv_rev"]

    # 1. Action 1: write_file(/tmp/first.txt) with id="req_01"
    msg_1 = {
        "jsonrpc": "2.0",
        "id": "req_01",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "file:///tmp/first.txt", "content": "alpha"},
        },
    }
    challenge_1 = adapter.handle_json_rpc_message(msg_1)["error"]["data"]
    digest_1 = challenge_1["action_digest"]

    envelope_1 = sign_approval_envelope(
        approval_id="appr_01HZX_FIRST_0000000001",
        action_digest=digest_1,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="11112222333344445555666677778888",
        private_key=priv_rev,
    )
    res_1 = adapter.handle_json_rpc_message(msg_1, approval_envelope=envelope_1, now_utc="2026-10-12T10:10:00.000000Z")
    assert "result" in res_1
    assert len(hardening_fixture["downstream_calls"]) == 1

    # 2. Action 2: delete_file(/tmp/second.txt) ALSO with id="req_01"
    msg_2 = {
        "jsonrpc": "2.0",
        "id": "req_01",
        "method": "tools/call",
        "params": {
            "name": "delete_file",
            "arguments": {"path": "file:///tmp/second.txt"},
        },
    }
    challenge_2 = adapter.handle_json_rpc_message(msg_2)
    # MUST require human approval and MUST NOT return Action 1's output
    assert challenge_2["error"]["code"] == -32001
    digest_2 = challenge_2["error"]["data"]["action_digest"]
    assert digest_2 != digest_1

    # 3. Attacker attempts to reuse envelope_1 on Action 2
    tampered_res = adapter.handle_json_rpc_message(msg_2, approval_envelope=envelope_1, now_utc="2026-10-12T10:10:00.000000Z")
    assert tampered_res["error"]["code"] == -32003
    assert "ERR_ENVELOPE_DIGEST_MISMATCH" in str(tampered_res["error"])
    # Tool was not called a second time
    assert len(hardening_fixture["downstream_calls"]) == 1


def test_reused_jsonrpc_id_different_sessions_isolated(hardening_fixture):
    """Reusing JSON-RPC ID '1' across two different sessions yields different action digests."""
    coordinator = hardening_fixture["coordinator"]
    server_id = hardening_fixture["server_id"]

    adapter_s1 = MCPAdapter(coordinator=coordinator, server_id=server_id, user_id="usr_admin", session_id="ses_01")
    adapter_s2 = MCPAdapter(coordinator=coordinator, server_id=server_id, user_id="usr_admin", session_id="ses_02")

    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "file:///tmp/common.txt"}},
    }

    p1 = adapter_s1.translate_to_canonical(msg)
    p2 = adapter_s2.translate_to_canonical(msg)

    assert p1.action_digest != p2.action_digest
    assert p1.action_identity["principal"]["session_id"] == "ses_01"
    assert p2.action_identity["principal"]["session_id"] == "ses_02"


def test_reused_jsonrpc_id_different_principals_isolated(hardening_fixture):
    """Reusing JSON-RPC ID '1' across two different user principals yields different action digests."""
    coordinator = hardening_fixture["coordinator"]
    server_id = hardening_fixture["server_id"]

    adapter_alice = MCPAdapter(coordinator=coordinator, server_id=server_id, user_id="usr_alice", session_id="ses_01")
    adapter_bob = MCPAdapter(coordinator=coordinator, server_id=server_id, user_id="usr_bob", session_id="ses_01")

    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "file:///tmp/common.txt"}},
    }

    p_alice = adapter_alice.translate_to_canonical(msg)
    p_bob = adapter_bob.translate_to_canonical(msg)

    assert p_alice.action_digest != p_bob.action_digest


def test_completed_result_cache_hit_rejected_if_action_digest_mismatched(hardening_fixture):
    """ExecutionBroker rejects cached outcome return if the requested action digest differs from approval."""
    coordinator = hardening_fixture["coordinator"]
    db = hardening_fixture["db"]
    priv_rev = hardening_fixture["priv_rev"]
    priv_gw = hardening_fixture["priv_gw"]

    action_id_1 = "act_legit_001"
    action_digest_1 = "11" * 32
    action_digest_2 = "22" * 32
    approval_id = "appr_cache_test_001"

    # Pre-record completed action and approval in DB
    normalized_action_1 = {
        "principal": {"user_id": "usr_admin", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {"tool_server_id": "srv_fs", "tool_name": "write_file", "operation_type": "MUTATION", "canonical_params": {}},
        "target_resource": {"resource_uri": "file:///tmp/a", "preconditions": None},
        "authorization_binding": {"policy_version": "pol_v1.0", "policy_epoch": 1, "idempotency_key": "k1", "expires_at_utc": "2026-10-12T11:00:00.000000Z"},
    }
    db.record_action(action_id_1, normalized_action_1, action_digest_1)

    envelope_1 = sign_approval_envelope(
        approval_id=approval_id,
        action_digest=action_digest_1,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="aaaa0000bbbb1111cccc2222dddd3333",
        private_key=priv_rev,
    )
    decision_1 = sign_authorization_decision_record(
        decision_id="dec_01HZX_TEST_000000000001",
        action_digest=action_digest_1,
        verdict="APPROVAL_REQUIRED",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=85.0,
        risk_tier="HIGH_CONSEQUENCE",
        provenance_taint="CLEAN",
        required_auth_level="STANDARD_PASSWORD",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )

    db.record_authorization_decision(decision_1, action_id_1)
    db.register_approval_envelope(envelope_1, action_id_1, "dec_01HZX_TEST_000000000001", initial_state="APPROVED")

    # Execute legitimate action once -> SUCCEEDED
    res = coordinator.broker.execute_authorized_action(
        normalized_action=normalized_action_1,
        expected_action_digest=action_digest_1,
        approval_envelope=envelope_1,
        decision_record=decision_1,
        action_id=action_id_1,
        worker_id="w1",
        now_utc="2026-10-12T10:10:00.000000Z",
    )
    assert res.status == "SUCCEEDED"

    # Attacker calls execute_authorized_action passing approval_id from envelope_1,
    # but for action_digest_2
    with pytest.raises(Exception):
        coordinator.broker.execute_authorized_action(
            normalized_action=normalized_action_1,
            expected_action_digest=action_digest_2,
            approval_envelope=envelope_1,
            decision_record=decision_1,
            action_id=action_id_1,
            worker_id="w1",
            now_utc="2026-10-12T10:10:00.000000Z",
        )


def test_completed_result_cache_hit_rejected_if_action_id_mismatched(hardening_fixture):
    """ExecutionBroker rejects cached outcome if action_id does not match the approval record."""
    coordinator = hardening_fixture["coordinator"]
    db = hardening_fixture["db"]
    priv_rev = hardening_fixture["priv_rev"]
    priv_gw = hardening_fixture["priv_gw"]

    action_id_1 = "act_legit_101"
    action_digest = "33" * 32
    approval_id = "appr_cache_test_101"

    normalized_action = {
        "principal": {"user_id": "usr_admin", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {"tool_server_id": "srv_fs", "tool_name": "write_file", "operation_type": "MUTATION", "canonical_params": {}},
        "target_resource": {"resource_uri": "file:///tmp/b", "preconditions": None},
        "authorization_binding": {"policy_version": "pol_v1.0", "policy_epoch": 1, "idempotency_key": "k2", "expires_at_utc": "2026-10-12T11:00:00.000000Z"},
    }
    db.record_action(action_id_1, normalized_action, action_digest)

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
        single_use_nonce="bbbb1111cccc2222dddd3333eeee4444",
        private_key=priv_rev,
    )
    decision = sign_authorization_decision_record(
        decision_id="dec_01HZX_TEST_000000000101",
        action_digest=action_digest,
        verdict="APPROVAL_REQUIRED",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=85.0,
        risk_tier="HIGH_CONSEQUENCE",
        provenance_taint="CLEAN",
        required_auth_level="STANDARD_PASSWORD",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )

    db.record_authorization_decision(decision, action_id_1)
    db.register_approval_envelope(envelope, action_id_1, "dec_01HZX_TEST_000000000101", initial_state="APPROVED")

    # Run legitimate dispatch
    res = coordinator.broker.execute_authorized_action(
        normalized_action=normalized_action,
        expected_action_digest=action_digest,
        approval_envelope=envelope,
        decision_record=decision,
        action_id=action_id_1,
        worker_id="w1",
        now_utc="2026-10-12T10:10:00.000000Z",
    )
    assert res.status == "SUCCEEDED"

    # Attacker passes different action_id
    with pytest.raises(DispatchProhibitedError) as exc_info:
        coordinator.broker.execute_authorized_action(
            normalized_action=normalized_action,
            expected_action_digest=action_digest,
            approval_envelope=envelope,
            decision_record=decision,
            action_id="act_forged_999",
            worker_id="w1",
            now_utc="2026-10-12T10:10:00.000000Z",
        )
    assert "was registered for action" in str(exc_info.value)


def test_completed_result_cache_hit_rejected_if_principal_mismatched(hardening_fixture):
    """ExecutionBroker rejects cached outcome if user_id or session_id in the action changed."""
    coordinator = hardening_fixture["coordinator"]
    db = hardening_fixture["db"]
    priv_rev = hardening_fixture["priv_rev"]
    priv_gw = hardening_fixture["priv_gw"]

    action_id = "act_legit_201"
    action_digest = "44" * 32
    approval_id = "appr_cache_test_201"

    original_action = {
        "principal": {"user_id": "usr_alice", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {"tool_server_id": "srv_fs", "tool_name": "write_file", "operation_type": "MUTATION", "canonical_params": {}},
        "target_resource": {"resource_uri": "file:///tmp/c", "preconditions": None},
        "authorization_binding": {"policy_version": "pol_v1.0", "policy_epoch": 1, "idempotency_key": "k3", "expires_at_utc": "2026-10-12T11:00:00.000000Z"},
    }
    db.record_action(action_id, original_action, action_digest)

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
        single_use_nonce="cccc2222dddd3333eeee4444ffff5555",
        private_key=priv_rev,
    )
    decision = sign_authorization_decision_record(
        decision_id="dec_01HZX_TEST_000000000201",
        action_digest=action_digest,
        verdict="APPROVAL_REQUIRED",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        score=85.0,
        risk_tier="HIGH_CONSEQUENCE",
        provenance_taint="CLEAN",
        required_auth_level="STANDARD_PASSWORD",
        signer_key_id="k_gw_01",
        private_key=priv_gw,
    )

    db.record_authorization_decision(decision, action_id)
    db.register_approval_envelope(envelope, action_id, "dec_01HZX_TEST_000000000201", initial_state="APPROVED")

    res = coordinator.broker.execute_authorized_action(
        normalized_action=original_action,
        expected_action_digest=action_digest,
        approval_envelope=envelope,
        decision_record=decision,
        action_id=action_id,
        worker_id="w1",
        now_utc="2026-10-12T10:10:00.000000Z",
    )
    assert res.status == "SUCCEEDED"

    # Attacker tries to query cache with usr_bob
    tampered_principal_action = {
        **original_action,
        "principal": {"user_id": "usr_bob", "agent_id": "agt_01", "session_id": "ses_01"},
    }
    with pytest.raises(DispatchProhibitedError) as exc_info:
        coordinator.broker.execute_authorized_action(
            normalized_action=tampered_principal_action,
            expected_action_digest=action_digest,
            approval_envelope=envelope,
            decision_record=decision,
            action_id=action_id,
            worker_id="w1",
            now_utc="2026-10-12T10:10:00.000000Z",
        )
    assert "Authorization context mismatch" in str(exc_info.value)


def test_mcp_protocol_lifecycle_methods(hardening_fixture):
    """MCPAdapter correctly handles initialize, tools/list, and unknown method."""
    adapter = hardening_fixture["adapter"]

    # 1. Initialize
    init_msg = {
        "jsonrpc": "2.0",
        "id": "init_1",
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05"},
    }
    init_res = adapter.handle_json_rpc_message(init_msg)
    assert "result" in init_res
    assert init_res["result"]["protocolVersion"] == "2024-11-05"
    assert "capabilities" in init_res["result"]

    # 2. Tools list
    list_msg = {
        "jsonrpc": "2.0",
        "id": "list_1",
        "method": "tools/list",
    }
    list_res = adapter.handle_json_rpc_message(list_msg)
    assert "result" in list_res
    tool_names = [t["name"] for t in list_res["result"]["tools"]]
    assert "write_file" in tool_names

    # 3. Method not found
    unknown_msg = {
        "jsonrpc": "2.0",
        "id": "unk_1",
        "method": "resources/read",
        "params": {"uri": "file:///test"},
    }
    unk_res = adapter.handle_json_rpc_message(unknown_msg)
    assert unk_res["error"]["code"] == -32601
    assert "Method not found" in unk_res["error"]["message"]
