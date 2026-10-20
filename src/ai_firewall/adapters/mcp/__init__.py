"""MCP subpackage initialization for AI Firewall."""

from ai_firewall.adapters.mcp.proxy import (
    MCPAdapter,
    MCPAdapterError,
    MCPJSONRPCError,
)

__all__ = [
    "MCPAdapter",
    "MCPAdapterError",
    "MCPJSONRPCError",
]

