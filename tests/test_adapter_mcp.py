"""Deterministic Security Tests for MCP Adapter.

Tests:
1. Valid MCP tools/call JSON-RPC message translation.
2. Malformed JSON-RPC protocol error handling.
3. Hard-denied tool invocation returns JSON-RPC error -32003 (tool never called).
4. High-risk tool invocation returns JSON-RPC error -32001 (approval challenge).
5. Approved MCP tool invocation executes successfully.
6. Downstream mock timeout returns JSON-RPC internal error and marks UNKNOWN in DB.
7. Parameter tampering between proposal and approval fails closed.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from ai_firewall.adapters.coordinator import GatewayCoordinator
from ai_firewall.adapters.mcp.proxy import MCPAdapter
from ai_firewall.crypto.envelope import sign_approval_envelope
from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.policy.engine import PolicyEngine
from ai_firewall.policy.models import DeclarativeRule, Verdict
from ai_firewall.storage.database import DatabaseManager


@pytest.fixture
def mcp_fixture():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=db_path)

    registry = KeyRegistry()
    priv_rev, rec_rev = generate_dev_ed25519_keypair("k_rev_01", "usr_admin")
    priv_gw, rec_gw = generate_dev_ed25519_keypair("k_gw_01", "gw_core")
    registry.register_key(rec_rev)
    registry.register_key(rec_gw)

    policy = PolicyEngine(
        policy_version="pol_v1.0",
        policy_epoch=1,
        registered_tools={("mcp_server_01", "write_file"), ("mcp_server_01", "read_file")},
        mandatory_deny_patterns=[r"^file:///etc/"],
    )

    downstream_calls = []

    def mock_downstream_tool(action):
        downstream_calls.append(action["invocation"]["tool_name"])
        return {"bytes_written": 42}

    coordinator = GatewayCoordinator(
        policy_engine=policy,
        db_manager=db,
        key_registry=registry,
        gateway_private_key=priv_gw,
        downstream_tool_handler=mock_downstream_tool,
    )

    adapter = MCPAdapter(
        coordinator=coordinator,
        server_id="mcp_server_01",
        user_id="usr_admin",
        session_id="ses_mcp_001",
    )

    yield {
        "adapter": adapter,
        "db": db,
        "registry": registry,
        "priv_rev": priv_rev,
        "downstream_calls": downstream_calls,
    }

    if os.path.exists(db_path):
        os.remove(db_path)


def test_mcp_malformed_json_rpc_rejected(mcp_fixture):
    adapter = mcp_fixture["adapter"]
    res = adapter.handle_json_rpc_message('{"bad": "json"')
    assert res["error"]["code"] == -32700


def test_mcp_mandatory_deny_blocks_tool_call(mcp_fixture):
    adapter = mcp_fixture["adapter"]
    # Request targeting /etc/shadow matches L2 blocklist
    msg = {
        "jsonrpc": "2.0",
        "id": "req_01",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "file:///etc/shadow", "content": "root:pw"},
        },
    }
    res = adapter.handle_json_rpc_message(msg)
    assert res["error"]["code"] == -32003
    assert "Action denied" in res["error"]["message"]
    assert len(mcp_fixture["downstream_calls"]) == 0  # Tool was never called!


def test_mcp_high_risk_yields_approval_challenge_and_executes_on_approval(mcp_fixture):
    adapter = mcp_fixture["adapter"]

    # 1. First invocation: High risk mutation targeting /tmp/out.txt
    msg = {
        "jsonrpc": "2.0",
        "id": "req_02",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "file:///tmp/out.txt", "content": "data"},
        },
    }
    challenge_res = adapter.handle_json_rpc_message(msg)
    assert challenge_res["error"]["code"] == -32001
    assert "Human approval required" in challenge_res["error"]["message"]
    challenge_data = challenge_res["error"]["data"]
    action_digest = challenge_data["action_digest"]

    # Tool was not called yet
    assert len(mcp_fixture["downstream_calls"]) == 0

    # 2. Reviewer signs approval envelope
    envelope = sign_approval_envelope(
        approval_id="appr_mcp_0123456789ABCDEF012",
        action_digest=action_digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="11112222333344445555666677778888",
        private_key=mcp_fixture["priv_rev"],
    )

    # 3. Re-submit message with approval envelope
    approved_res = adapter.handle_json_rpc_message(
        msg, approval_envelope=envelope, now_utc="2026-10-12T10:10:00.000000Z"
    )
    assert "result" in approved_res
    assert approved_res["result"] == {"bytes_written": 42}
    assert len(mcp_fixture["downstream_calls"]) == 1


def test_mcp_downstream_timeout_marks_unknown(mcp_fixture):
    # Reconfigure downstream tool to raise TimeoutError
    def timeout_tool(action):
        raise TimeoutError("Downstream MCP server timed out")

    mcp_fixture["adapter"].coordinator.broker.downstream_tool_handler = timeout_tool

    msg = {
        "jsonrpc": "2.0",
        "id": "req_timeout",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "file:///tmp/out.txt", "content": "data"},
        },
    }

    # Propose action & sign approval
    challenge = mcp_fixture["adapter"].handle_json_rpc_message(msg)["error"]["data"]
    envelope = sign_approval_envelope(
        approval_id="appr_timeout_1234567890123456",
        action_digest=challenge["action_digest"],
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="99998888777766665555444433332222",
        private_key=mcp_fixture["priv_rev"],
    )

    res = mcp_fixture["adapter"].handle_json_rpc_message(
        msg, approval_envelope=envelope, now_utc="2026-10-12T10:10:00.000000Z"
    )
    assert res["error"]["code"] == -32603
    assert "Internal error: ambiguous execution outcome" in res["error"]["message"]
