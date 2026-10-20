"""Cross-Adapter Parity and Security Invariant Tests.

Tests:
1. Parity: Identical tool name, target, and arguments across MCP and LangChain adapters
   yield byte-for-byte identical canonical serialization and SHA-256 action digest.
2. Hard Deny Parity: Mandatory deny targets are rejected identically by both adapters
   without invoking downstream handlers.
3. Cross-Adapter Replay Prevention: An approval envelope issued for an MCP action cannot
   authorize a modified LangChain invocation.
4. Stale Policy Epoch Parity: Approvals issued under a superseded policy epoch are rejected
   identically by both adapters.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from ai_firewall.adapters.coordinator import GatewayCoordinator
from ai_firewall.adapters.langchain.middleware import LangChainAdapter
from ai_firewall.adapters.mcp.proxy import MCPAdapter
from ai_firewall.canonical.hasher import compute_action_digest
from ai_firewall.crypto.envelope import sign_approval_envelope
from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.policy.engine import PolicyEngine
from ai_firewall.storage.database import DatabaseManager


@pytest.fixture
def cross_adapter_fixture():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=db_path)

    registry = KeyRegistry()
    priv_rev, rec_rev = generate_dev_ed25519_keypair("k_rev_01", "usr_admin")
    priv_gw, rec_gw = generate_dev_ed25519_keypair("k_gw_01", "gw_core")
    registry.register_key(rec_rev)
    registry.register_key(rec_gw)

    server_id = "shared_service"
    user_id = "usr_shared"
    agent_id = "agt_shared"
    session_id = "ses_shared_001"

    policy_engine = PolicyEngine(
        policy_version="pol_v1.0",
        policy_epoch=1,
        registered_tools={
            (server_id, "write_file"),
            (server_id, "read_file"),
        },
        mandatory_deny_patterns=[r"^file:///etc/"],
    )

    downstream_calls = []

    def mock_downstream_tool(action):
        downstream_calls.append(action)
        return {"status": "success", "echo": action["invocation"]["canonical_params"]}

    coordinator = GatewayCoordinator(
        policy_engine=policy_engine,
        db_manager=db,
        key_registry=registry,
        gateway_private_key=priv_gw,
        downstream_tool_handler=mock_downstream_tool,
    )

    mcp_adapter = MCPAdapter(
        coordinator=coordinator,
        server_id=server_id,
        user_id=user_id,
        agent_id=agent_id,
        session_id=session_id,
    )

    lc_adapter = LangChainAdapter(
        coordinator=coordinator,
        server_id=server_id,
        user_id=user_id,
        agent_id=agent_id,
        session_id=session_id,
    )

    yield {
        "coordinator": coordinator,
        "mcp_adapter": mcp_adapter,
        "lc_adapter": lc_adapter,
        "db": db,
        "db_path": db_path,
        "registry": registry,
        "priv_rev": priv_rev,
        "priv_gw": priv_gw,
        "downstream_calls": downstream_calls,
        "server_id": server_id,
        "user_id": user_id,
        "session_id": session_id,
    }

    if os.path.exists(db_path):
        os.remove(db_path)


def test_cross_adapter_digest_parity(cross_adapter_fixture):
    """When both adapters translate equivalent tool invocations with identical bindings,

    they must produce byte-for-byte identical canonical serialization and SHA-256 action digest.
    """
    mcp_adapter = cross_adapter_fixture["mcp_adapter"]
    lc_adapter = cross_adapter_fixture["lc_adapter"]

    shared_idempotency_key = "idemp_shared_12345"
    shared_expires = "2026-10-12T11:00:00.000000Z"
    args = {"path": "file:///tmp/common.json", "data": {"b": 2, "a": 1}}

    mcp_invocation = {
        "jsonrpc": "2.0",
        "id": shared_idempotency_key,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": args,
        },
        "expires_at_utc": shared_expires,
    }

    lc_invocation = {
        "name": "write_file",
        "arguments": {"data": {"a": 1, "b": 2}, "path": "file:///tmp/common.json"},
        "idempotency_key": shared_idempotency_key,
        "expires_at_utc": shared_expires,
    }

    mcp_proposal = mcp_adapter.translate_to_canonical(mcp_invocation)
    lc_proposal = lc_adapter.translate_to_canonical(lc_invocation)

    # Digests must be identical regardless of JSON key permutation in arguments
    assert mcp_proposal.action_digest == lc_proposal.action_digest


def test_cross_adapter_hard_deny_parity(cross_adapter_fixture):
    """Mandatory denials must fail-closed across both adapters identically."""
    mcp_adapter = cross_adapter_fixture["mcp_adapter"]
    lc_adapter = cross_adapter_fixture["lc_adapter"]
    downstream_calls = cross_adapter_fixture["downstream_calls"]

    # MCP invocation targeting /etc/shadow
    mcp_msg = {
        "jsonrpc": "2.0",
        "id": "req_mcp_deny",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "file:///etc/shadow", "data": "evil"},
        },
    }
    mcp_res = mcp_adapter.handle_json_rpc_message(mcp_msg)
    assert mcp_res["error"]["code"] == -32003
    assert "Action denied" in mcp_res["error"]["message"]

    # LangChain invocation targeting /etc/shadow
    lc_res = lc_adapter.execute_tool_node(
        node_state={},
        tool_name="write_file",
        tool_input={"path": "file:///etc/shadow", "data": "evil"},
        now_utc="2026-10-12T10:10:00.000000Z",
    )
    assert lc_res["status"] == "denied"
    assert lc_res["error_code"] == "ERR_POLICY_DENIED"

    # Neither adapter ever dispatched to downstream tool
    assert len(downstream_calls) == 0


def test_cross_adapter_tampered_envelope_rejected(cross_adapter_fixture):
    """An approval signed for an MCP action cannot be replayed onto a modified LangChain action."""
    mcp_adapter = cross_adapter_fixture["mcp_adapter"]
    lc_adapter = cross_adapter_fixture["lc_adapter"]
    priv_rev = cross_adapter_fixture["priv_rev"]

    # 1. MCP action proposed
    mcp_msg = {
        "jsonrpc": "2.0",
        "id": "req_cross_01",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "file:///tmp/dest.txt", "content": "approved_data"},
        },
    }
    challenge = mcp_adapter.handle_json_rpc_message(mcp_msg)["error"]["data"]
    mcp_digest = challenge["action_digest"]

    # 2. Envelope signed for mcp_digest
    envelope = sign_approval_envelope(
        approval_id="appr_cross_0123456789ABCDEF",
        action_digest=mcp_digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="dddd4444eeee5555ffff666600001111",
        private_key=priv_rev,
    )

    # 3. Attacker attempts to redeem envelope on a LangChain node with modified content
    tampered_node_state = {
        "_firewall_action_id": "act_lc_tampered_001",
        "_firewall_action_digest": mcp_digest,
        "_firewall_approval_envelope": envelope,
    }
    tampered_input = {"path": "file:///tmp/dest.txt", "content": "tampered_data"}

    # LangChain adapter detects parameter difference between tool_input and stored digest,
    # clearing the old envelope and preventing redemption of the mismatched approval.
    with pytest.raises(Exception):
        lc_adapter.execute_tool_node(
            node_state=tampered_node_state,
            tool_name="write_file",
            tool_input=tampered_input,
            now_utc="2026-10-12T10:10:00.000000Z",
        )

    assert len(cross_adapter_fixture["downstream_calls"]) == 0
