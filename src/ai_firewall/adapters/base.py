"""Shared Adapter Interface and Contracts for AI Firewall.

Every protocol or framework adapter (MCP, LangChain, etc.) must implement this
contract to translate incoming tool requests into the Canonical Action model and
delegate all authorization, risk, and execution handling to the shared core.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class NormalizedActionProposal:
    """Standardized representation produced by an adapter from incoming framework requests."""

    action_id: str
    action_identity: dict[str, Any]
    action_digest: str
    provenance_taint: Optional[str] = None


@dataclass(frozen=True)
class GatewayInvocationResponse:
    """Standardized response from the gateway back to the adapter."""

    status: str  # 'ALLOW_EXECUTED', 'APPROVAL_REQUIRED', 'DENIED', 'RETRY_REQUIRED', 'UNKNOWN'
    action_id: str
    action_digest: str
    output: Optional[dict[str, Any]] = None
    approval_challenge: Optional[dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class BaseToolAdapter(ABC):
    """Abstract base class for AI Firewall tool invocation adapters."""

    @abstractmethod
    def translate_to_canonical(self, raw_invocation: dict[str, Any]) -> NormalizedActionProposal:
        """Translates a framework-specific tool invocation into a canonical action proposal."""

    @abstractmethod
    def handle_tool_call(
        self,
        raw_invocation: dict[str, Any],
        approval_envelope: Optional[dict[str, Any]] = None,
    ) -> GatewayInvocationResponse:
        """Processes a tool invocation through the gateway authorization core."""

