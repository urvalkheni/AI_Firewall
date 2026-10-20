"""LangChain and LangGraph Tool Interception Middleware for AI Firewall.

Enforces:
1. Translation of LangChain tool call invocations into Canonical Action representations.
2. Stable action/proposal identity tracking across interrupt and resume cycles.
3. Node re-execution replay guard: when LangGraph restarts a node from line 1 upon resume,
   prevents creating duplicate action proposals and prevents duplicate dispatch.
4. Parameter edit detection: modified arguments trigger fresh proposal creation.
5. Authoritative gateway verification: checkpoint data is treated as untrusted input.
"""

from __future__ import annotations

from typing import Any, Callable, Optional
import uuid

from ai_firewall.adapters.base import (
    BaseToolAdapter,
    GatewayInvocationResponse,
    NormalizedActionProposal,
)
from ai_firewall.adapters.coordinator import GatewayCoordinator
from ai_firewall.canonical.hasher import compute_action_digest


class LangChainAdapterError(Exception):
    """Base error for LangChain adapter processing."""


class LangGraphInterruptException(Exception):
    """Simulates LangGraph interrupt() signaling when human approval is required."""

    def __init__(self, challenge_data: dict[str, Any]) -> None:
        super().__init__(f"LangGraph Interrupt: approval required ({challenge_data.get('action_digest')})")
        self.challenge_data = challenge_data


class LangChainAdapter(BaseToolAdapter):
    """Adapter intercepting LangChain / LangGraph tool invocations."""

    def __init__(
        self,
        coordinator: GatewayCoordinator,
        server_id: str = "langchain_runtime",
        user_id: str = "usr_langchain_agent",
        agent_id: str = "agt_langchain_agent",
        session_id: str = "ses_langchain_001",
    ) -> None:
        self.coordinator = coordinator
        self.server_id = server_id
        self.user_id = user_id
        self.agent_id = agent_id
        self.session_id = session_id

    def translate_to_canonical(self, raw_invocation: dict[str, Any]) -> NormalizedActionProposal:
        """Translates a LangChain tool invocation dictionary into a Canonical Action Proposal."""
        tool_name = raw_invocation.get("name")
        if not tool_name or not isinstance(tool_name, str):
            raise LangChainAdapterError("Missing or invalid tool name in LangChain invocation")

        tool_input = raw_invocation.get("arguments", {})
        if not isinstance(tool_input, dict):
            raise LangChainAdapterError("LangChain tool arguments must be a dictionary")

        resource_uri = tool_input.get("path") or tool_input.get("uri") or f"langchain://{self.server_id}/{tool_name}"

        action_id = raw_invocation.get("action_id") or f"act_lc_{uuid.uuid4().hex[:20]}"
        idemp_key = (
            raw_invocation.get("tool_call_id")
            or raw_invocation.get("idempotency_key")
            or f"idemp_{action_id}"
        )
        op_type = raw_invocation.get("operation_type") or ("READ_ONLY" if tool_name.startswith(("read_", "get_", "query_")) else "MUTATION")
        action_identity = {
            "principal": {
                "user_id": self.user_id,
                "agent_id": self.agent_id,
                "session_id": self.session_id,
            },
            "invocation": {
                "tool_server_id": self.server_id,
                "tool_name": tool_name,
                "operation_type": op_type,
                "canonical_params": tool_input,
            },
            "target_resource": {
                "resource_uri": resource_uri,
                "preconditions": tool_input.get("preconditions"),
            },
            "authorization_binding": {
                "policy_version": self.coordinator.policy_engine.policy_version,
                "policy_epoch": self.coordinator.policy_engine.policy_epoch,
                "idempotency_key": str(idemp_key),
                "expires_at_utc": raw_invocation.get("expires_at_utc", "2026-10-12T11:00:00.000000Z"),
            },
        }

        action_digest, _, normalized_dict = compute_action_digest(action_identity)

        provenance_taint = raw_invocation.get("provenance_taint")

        return NormalizedActionProposal(
            action_id=action_id,
            action_identity=normalized_dict,
            action_digest=action_digest,
            provenance_taint=provenance_taint,
        )

    def handle_tool_call(
        self,
        raw_invocation: dict[str, Any],
        approval_envelope: Optional[dict[str, Any]] = None,
        now_utc: Optional[str] = None,
    ) -> GatewayInvocationResponse:
        """Processes a LangChain tool invocation through the gateway core."""
        proposal = self.translate_to_canonical(raw_invocation)
        return self.coordinator.process_invocation(proposal, approval_envelope, now_utc=now_utc)

    def execute_tool_node(
        self,
        node_state: dict[str, Any],
        tool_name: str,
        tool_input: dict[str, Any],
        provenance_taint: Optional[str] = None,
        now_utc: Optional[str] = None,
    ) -> dict[str, Any]:
        """LangGraph tool node wrapper implementing the node re-execution replay guard.

        Lifecycle across LangGraph interrupt/resume:
        1. Pre-Interrupt (First invocation of the node):
           - No `_firewall_action_id` exists in `node_state`.
           - Adapter proposes action to Gateway.
           - If APPROVAL_REQUIRED, sets `_firewall_action_id` and raises `LangGraphInterruptException`.
        2. Post-Interrupt (Node re-executes from line 1 upon resume):
           - `node_state` contains `_firewall_action_id` and `_firewall_approval_envelope`.
           - Node checks if tool_input changed (parameter editing). If changed, clears ID and proposes fresh.
           - Otherwise, redeems the approval envelope via gateway core.
        """
        existing_action_id = node_state.get("_firewall_action_id")
        existing_digest = node_state.get("_firewall_action_digest")

        raw_invocation = {
            "name": tool_name,
            "arguments": tool_input,
            "action_id": existing_action_id,
            "provenance_taint": provenance_taint,
        }

        # Check parameter tampering / editing
        proposal = self.translate_to_canonical(raw_invocation)
        if existing_digest and proposal.action_digest != existing_digest:
            # Arguments were edited in human-in-the-loop review!
            # Old action proposal is invalid; clear and propose fresh
            existing_action_id = None
            node_state["_firewall_action_id"] = None
            node_state["_firewall_action_digest"] = None
            node_state["_firewall_approval_envelope"] = None
            raw_invocation["action_id"] = None
            proposal = self.translate_to_canonical(raw_invocation)

        # Check if an approval envelope was provided upon resume
        approval_envelope = node_state.get("_firewall_approval_envelope")

        gateway_res = self.coordinator.process_invocation(proposal, approval_envelope, now_utc=now_utc)

        if gateway_res.status == "APPROVAL_REQUIRED":
            # State checkpointing before interrupt
            node_state["_firewall_action_id"] = gateway_res.action_id
            node_state["_firewall_action_digest"] = gateway_res.action_digest
            raise LangGraphInterruptException(gateway_res.approval_challenge or {})

        elif gateway_res.status in ("ALLOW_EXECUTED", "SUCCEEDED"):
            # Clear state flags upon completion
            node_state["_firewall_action_id"] = None
            node_state["_firewall_action_digest"] = None
            node_state["_firewall_approval_envelope"] = None
            return {
                "status": "success",
                "output": gateway_res.output,
                "action_id": gateway_res.action_id,
                "action_digest": gateway_res.action_digest,
            }

        elif gateway_res.status == "DENIED":
            return {
                "status": "denied",
                "error_code": gateway_res.error_code,
                "error_message": gateway_res.error_message,
            }

        elif gateway_res.status == "RETRY_REQUIRED":
            return {
                "status": "retry_required",
                "error_code": gateway_res.error_code,
                "error_message": gateway_res.error_message,
            }

        else:
            return {
                "status": "unknown",
                "error_code": gateway_res.error_code or "ERR_UNKNOWN_STATE",
                "error_message": gateway_res.error_message,
            }
