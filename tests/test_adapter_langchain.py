"""Integration and Security Tests for LangChain/LangGraph Adapter.

Tests:
1. Tool call translation to Canonical Action Proposal.
2. Pre-interrupt: High risk mutation triggers LangGraphInterruptException and checkpoints state.
3. Post-interrupt: Resuming node with valid signed envelope executes downstream tool and succeeds.
4. Parameter editing detection: Modifying tool arguments during review invalidates digest, clears checkpoint, and proposes freshly.
5. Repeated resume idempotency: Resuming an already-executed action returns recorded result without second tool dispatch.
6. Mandatory deny blocks LangChain tool invocation immediately without calling downstream tool.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from ai_firewall.adapters.coordinator import GatewayCoordinator
from ai_firewall.adapters.langchain.middleware import (
    LangChainAdapter,
    LangGraphInterruptException,
)
from ai_firewall.crypto.envelope import sign_approval_envelope
from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.policy.engine import PolicyEngine
from ai_firewall.storage.database import DatabaseManager


@pytest.fixture
def langchain_fixture():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=db_path)

    registry = KeyRegistry()
    priv_rev, rec_rev = generate_dev_ed25519_keypair("k_rev_01", "usr_admin")
    priv_gw, rec_gw = generate_dev_ed25519_keypair("k_gw_01", "gw_core")
    registry.register_key(rec_rev)
    registry.register_key(rec_gw)

    policy_engine = PolicyEngine(
        policy_version="pol_v1.0",
        policy_epoch=1,
        registered_tools={
            ("langchain_runtime", "write_file"),
            ("langchain_runtime", "read_file"),
            ("langchain_runtime", "search_web"),
        },
        mandatory_deny_patterns=[r"^file:///etc/"],
    )

    downstream_calls = []

    def mock_downstream_handler(action):
        downstream_calls.append(action)
        return {"status": "ok", "items_written": 100}

    coordinator = GatewayCoordinator(
        policy_engine=policy_engine,
        db_manager=db,
        key_registry=registry,
        gateway_private_key=priv_gw,
        gateway_key_id="k_gw_01",
        gateway_principal_id="gw_core",
        downstream_tool_handler=mock_downstream_handler,
    )

    adapter = LangChainAdapter(
        coordinator=coordinator,
        server_id="langchain_runtime",
        user_id="usr_admin",
        session_id="ses_lc_001",
    )

    yield {
        "adapter": adapter,
        "coordinator": coordinator,
        "db": db,
        "db_path": db_path,
        "registry": registry,
        "priv_rev": priv_rev,
        "priv_gw": priv_gw,
        "downstream_calls": downstream_calls,
    }

    if os.path.exists(db_path):
        os.remove(db_path)


def test_langchain_mandatory_deny_blocks_tool(langchain_fixture):
    adapter = langchain_fixture["adapter"]
    node_state = {}

    res = adapter.execute_tool_node(
        node_state=node_state,
        tool_name="write_file",
        tool_input={"path": "file:///etc/shadow", "content": "malicious"},
        now_utc="2026-10-12T10:10:00.000000Z",
    )

    assert res["status"] == "denied"
    assert res["error_code"] == "ERR_POLICY_DENIED"
    assert len(langchain_fixture["downstream_calls"]) == 0


def test_langchain_interrupt_and_resume_cycle(langchain_fixture):
    adapter = langchain_fixture["adapter"]
    priv_rev = langchain_fixture["priv_rev"]

    node_state = {}
    tool_input = {"path": "file:///tmp/app.conf", "content": "debug=true"}

    # 1. First execution of the node: should raise LangGraphInterruptException
    with pytest.raises(LangGraphInterruptException) as exc_info:
        adapter.execute_tool_node(
            node_state=node_state,
            tool_name="write_file",
            tool_input=tool_input,
            now_utc="2026-10-12T10:10:00.000000Z",
        )

    # Assert node_state contains checkpointed action metadata
    assert node_state.get("_firewall_action_id") is not None
    action_digest = node_state.get("_firewall_action_digest")
    assert action_digest is not None
    assert len(langchain_fixture["downstream_calls"]) == 0

    challenge = exc_info.value.challenge_data
    assert challenge["action_digest"] == action_digest

    # 2. Human reviewer reviews challenge and signs approval envelope
    envelope = sign_approval_envelope(
        approval_id="appr_lc_0123456789ABCDEF0123",
        action_digest=action_digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="aaaa1111bbbb2222cccc3333dddd4444",
        private_key=priv_rev,
    )

    # 3. Simulate LangGraph resume: Command(resume=envelope) restarts node from line 1
    node_state["_firewall_approval_envelope"] = envelope

    res = adapter.execute_tool_node(
        node_state=node_state,
        tool_name="write_file",
        tool_input=tool_input,
        now_utc="2026-10-12T10:10:00.000000Z",
    )

    assert res["status"] == "success"
    assert res["output"] == {"status": "ok", "items_written": 100}
    assert len(langchain_fixture["downstream_calls"]) == 1

    # Checkpoint markers in node_state cleared upon success
    assert node_state.get("_firewall_action_id") is None
    assert node_state.get("_firewall_approval_envelope") is None


def test_langchain_parameter_editing_triggers_fresh_proposal(langchain_fixture):
    adapter = langchain_fixture["adapter"]
    priv_rev = langchain_fixture["priv_rev"]

    node_state = {}
    original_input = {"path": "file:///tmp/app.conf", "content": "port=80"}

    # 1. First execution raises interrupt
    with pytest.raises(LangGraphInterruptException):
        adapter.execute_tool_node(
            node_state=node_state,
            tool_name="write_file",
            tool_input=original_input,
            now_utc="2026-10-12T10:10:00.000000Z",
        )

    original_digest = node_state["_firewall_action_digest"]

    # 2. Human reviews and EDITS parameters (e.g., changes port to 8080)
    edited_input = {"path": "file:///tmp/app.conf", "content": "port=8080"}

    # Attempting to resume with the old envelope for original input
    old_envelope = sign_approval_envelope(
        approval_id="appr_lc_edited_0123456789ABCDE",
        action_digest=original_digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="bbbb2222cccc3333dddd4444eeee5555",
        private_key=priv_rev,
    )
    node_state["_firewall_approval_envelope"] = old_envelope

    # Adapter detects that current input hash does not match stored _firewall_action_digest,
    # clears stored action_id/digest, and triggers a fresh proposal cycle (raising a new InterruptException).
    with pytest.raises(LangGraphInterruptException) as exc_info_2:
        adapter.execute_tool_node(
            node_state=node_state,
            tool_name="write_file",
            tool_input=edited_input,
            now_utc="2026-10-12T10:10:00.000000Z",
        )

    # Confirm fresh action digest was created for the new parameters
    new_digest = exc_info_2.value.challenge_data["action_digest"]
    assert new_digest != original_digest
    assert len(langchain_fixture["downstream_calls"]) == 0


def test_langchain_repeated_resume_idempotency(langchain_fixture):
    adapter = langchain_fixture["adapter"]
    priv_rev = langchain_fixture["priv_rev"]

    node_state = {}
    tool_input = {"path": "file:///tmp/audit.log", "content": "entry_1"}

    # Pre-interrupt
    with pytest.raises(LangGraphInterruptException):
        adapter.execute_tool_node(
            node_state=node_state,
            tool_name="write_file",
            tool_input=tool_input,
            now_utc="2026-10-12T10:10:00.000000Z",
        )

    digest = node_state["_firewall_action_digest"]
    action_id = node_state["_firewall_action_id"]

    envelope = sign_approval_envelope(
        approval_id="appr_lc_idemp_0123456789ABCDE",
        action_digest=digest,
        approval_status="APPROVED",
        reviewer_user_id="usr_admin",
        key_id="k_rev_01",
        auth_level="STANDARD_PASSWORD",
        policy_version="pol_v1.0",
        policy_epoch=1,
        issued_at_utc="2026-10-12T10:00:00.000000Z",
        expires_at_utc="2026-10-12T11:00:00.000000Z",
        single_use_nonce="cccc3333dddd4444eeee5555ffff6666",
        private_key=priv_rev,
    )

    # 1. First resume execution -> Success, tool called once
    node_state["_firewall_approval_envelope"] = envelope
    node_state["_firewall_action_id"] = action_id
    res1 = adapter.execute_tool_node(
        node_state=node_state,
        tool_name="write_file",
        tool_input=tool_input,
        now_utc="2026-10-12T10:10:00.000000Z",
    )
    assert res1["status"] == "success"
    assert len(langchain_fixture["downstream_calls"]) == 1

    # 2. Duplicate retry / replay with same approval envelope
    # Node re-invoked with the same approval envelope
    duplicate_state = {
        "_firewall_action_id": action_id,
        "_firewall_action_digest": digest,
        "_firewall_approval_envelope": envelope,
    }
    res2 = adapter.execute_tool_node(
        node_state=duplicate_state,
        tool_name="write_file",
        tool_input=tool_input,
        now_utc="2026-10-12T10:10:00.000000Z",
    )

    assert res2["status"] == "success"
    assert res2["output"] == {"status": "ok", "items_written": 100}
    # Downstream tool was NOT called a second time
    assert len(langchain_fixture["downstream_calls"]) == 1
