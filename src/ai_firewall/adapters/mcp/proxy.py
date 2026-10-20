"""Model Context Protocol (MCP) Reverse Proxy and Adapter for AI Firewall.

Intercepts MCP JSON-RPC 2.0 tool invocation frames (`tools/call`), performs
strict JSON-RPC schema validation, translates arguments into Canonical Action
representations, and delegates authorization exclusively to the Gateway Core.
"""

from __future__ import annotations

import json
from typing import Any, Optional
import uuid

from ai_firewall.adapters.base import (
    BaseToolAdapter,
    GatewayInvocationResponse,
    NormalizedActionProposal,
)
from ai_firewall.adapters.coordinator import GatewayCoordinator
from ai_firewall.canonical.hasher import compute_action_digest
from ai_firewall.canonical.parser import strict_json_loads


class MCPAdapterError(Exception):
    """Base error for MCP adapter processing."""


class MCPJSONRPCError(MCPAdapterError):
    """Raised when an incoming MCP message violates JSON-RPC 2.0 specification."""


class MCPAdapter(BaseToolAdapter):
    """Adapter intercepting and translating Model Context Protocol (MCP) tool invocations."""

    def __init__(
        self,
        coordinator: GatewayCoordinator,
        server_id: str = "mcp_server_default",
        user_id: str = "usr_mcp_client",
        agent_id: str = "agt_mcp_client",
        session_id: str = "ses_mcp_default",
    ) -> None:
        self.coordinator = coordinator
        self.server_id = server_id
        self.user_id = user_id
        self.agent_id = agent_id
        self.session_id = session_id

    def translate_to_canonical(self, raw_invocation: dict[str, Any]) -> NormalizedActionProposal:
        """Translates an MCP `tools/call` JSON-RPC message into a Canonical Action Proposal."""
        # 1. Validate JSON-RPC structure
        if raw_invocation.get("jsonrpc") != "2.0":
            raise MCPJSONRPCError("Invalid or missing jsonrpc version, must be '2.0'")

        method = raw_invocation.get("method")
        if method != "tools/call":
            raise MCPJSONRPCError(f"Unsupported MCP method {method!r}, expected 'tools/call'")

        params = raw_invocation.get("params")
        if not isinstance(params, dict):
            raise MCPJSONRPCError("MCP params must be an object/dict")

        tool_name = params.get("name")
        if not tool_name or not isinstance(tool_name, str):
            raise MCPJSONRPCError("Missing or invalid tool name in MCP params")

        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise MCPJSONRPCError("MCP tool arguments must be an object/dict")

        # 2. Extract target resource URI heuristic
        resource_uri = arguments.get("path") or arguments.get("uri") or f"mcp://{self.server_id}/{tool_name}"

        # 3. Construct Canonical Action Identity
        explicit_idemp = (
            raw_invocation.get("idempotency_key")
            or (params.get("idempotency_key") if isinstance(params, dict) else None)
            or (arguments.get("idempotency_key") if isinstance(arguments, dict) else None)
        )
        msg_id_val = raw_invocation.get("id")
        action_id = (
            raw_invocation.get("action_id")
            or (params.get("action_id") if isinstance(params, dict) else None)
            or (arguments.get("_firewall_action_id") if isinstance(arguments, dict) else None)
            or (f"act_mcp_{msg_id_val}_{tool_name}" if msg_id_val is not None else f"act_mcp_{uuid.uuid4().hex[:20]}")
        )

        if explicit_idemp is not None:
            idempotency_key = str(explicit_idemp)
        elif raw_invocation.get("action_id") or (params.get("action_id") if isinstance(params, dict) else None):
            idempotency_key = f"idemp_{action_id}"
        elif raw_invocation.get("id") is not None:
            idempotency_key = str(raw_invocation.get("id"))
        else:
            idempotency_key = f"idemp_{uuid.uuid4().hex[:16]}"

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
                "canonical_params": arguments,
            },
            "target_resource": {
                "resource_uri": resource_uri,
                "preconditions": arguments.get("preconditions"),
            },
            "authorization_binding": {
                "policy_version": self.coordinator.policy_engine.policy_version,
                "policy_epoch": self.coordinator.policy_engine.policy_epoch,
                "idempotency_key": idempotency_key,
                "expires_at_utc": raw_invocation.get("expires_at_utc", "2026-10-12T11:00:00.000000Z"),
            },
        }

        # 4. Canonicalize and compute digest
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
        """Processes an MCP tool invocation through the gateway core."""
        proposal = self.translate_to_canonical(raw_invocation)
        return self.coordinator.process_invocation(proposal, approval_envelope, now_utc=now_utc)

    def handle_json_rpc_message(
        self,
        message: str | bytes | dict[str, Any],
        approval_envelope: Optional[dict[str, Any]] = None,
        now_utc: Optional[str] = None,
    ) -> dict[str, Any]:
        """High-level JSON-RPC handler returning standard JSON-RPC 2.0 response objects."""
        try:
            if isinstance(message, dict):
                parsed = message
            elif isinstance(message, (str, bytes)):
                parsed = strict_json_loads(message)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request: not a JSON object or string"},
                }

            if not isinstance(parsed, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request: not a JSON object"},
                }

            msg_id = parsed.get("id")
            method = parsed.get("method")

            # Handle MCP Protocol Lifecycle messages
            if method == "initialize":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "ai-firewall-mcp-proxy", "version": "1.0.0"},
                    },
                }
            elif method == "notifications/initialized":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            elif method == "tools/list":
                reg_tools = getattr(self.coordinator.policy_engine, "registered_tools", set())
                tool_list = [
                    {"name": t_name, "description": f"Tool {t_name} on server {s_id}"}
                    for (s_id, t_name) in reg_tools
                    if s_id == self.server_id
                ]
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"tools": tool_list},
                }
            elif method != "tools/call":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Method not found: {method!r}"},
                }

            gateway_res = self.handle_tool_call(parsed, approval_envelope, now_utc=now_utc)

            if gateway_res.status == "ALLOW_EXECUTED":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": gateway_res.output or {"status": "success"},
                }
            elif gateway_res.status == "APPROVAL_REQUIRED":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32001,
                        "message": "Human approval required before tool execution",
                        "data": gateway_res.approval_challenge,
                    },
                }
            elif gateway_res.status == "DENIED":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32003,
                        "message": f"Action denied: {gateway_res.error_message}",
                        "data": {"error_code": gateway_res.error_code},
                    },
                }
            elif gateway_res.status == "RETRY_REQUIRED":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32002,
                        "message": "State drift detected; retry required with fresh perception",
                        "data": {"error_code": gateway_res.error_code},
                    },
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": "Internal error: ambiguous execution outcome",
                        "data": {"status": gateway_res.status},
                    },
                }

        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error or invalid message: {exc}"},
            }
