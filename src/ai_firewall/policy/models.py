"""Data models and risk factors for the AI Firewall Policy Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    """Authorization verdicts emitted by the policy engine."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    RETRY_REQUIRED = "RETRY_REQUIRED"


class RiskTier(str, Enum):
    """Risk tiers derived from the calibrated risk score [0, 100]."""

    LOW_RISK = "LOW_RISK"
    MODERATE_RISK = "MODERATE_RISK"
    HIGH_CONSEQUENCE = "HIGH_CONSEQUENCE"


class ProvenanceTaint(str, Enum):
    """Context taint classifications for untrusted inputs."""

    CLEAN = "CLEAN"
    SUSPICIOUS_EXTERNAL = "SUSPICIOUS_EXTERNAL"
    UNTRUSTED_INDIRECT_INPUT = "UNTRUSTED_INDIRECT_INPUT"


class AuthLevel(str, Enum):
    """Authentication strength required for authorization."""

    NONE = "NONE"
    STANDARD_PASSWORD = "STANDARD_PASSWORD"
    MFA_TOTP = "MFA_TOTP"
    MFA_HARDWARE_TOKEN = "MFA_HARDWARE_TOKEN"


@dataclass(frozen=True)
class RiskFactors:
    """Individual integer factor scores s_i in [0, 10]."""

    mutability: int = 0
    reversibility: int = 0
    sensitivity: int = 0
    externalities: int = 0
    privilege: int = 0
    provenance: int = 0
    financial: int = 0
    blast_radius: int = 0

    def __post_init__(self) -> None:
        for factor_name in (
            "mutability",
            "reversibility",
            "sensitivity",
            "externalities",
            "privilege",
            "provenance",
            "financial",
            "blast_radius",
        ):
            val = getattr(self, factor_name)
            if not isinstance(val, int) or val < 0 or val > 10:
                raise ValueError(f"Factor {factor_name} must be integer in [0, 10], got {val!r}")


@dataclass(frozen=True)
class PolicyEvaluationResult:
    """Immutable result of a deterministic policy evaluation."""

    verdict: Verdict
    risk_score: float
    risk_tier: RiskTier
    provenance_taint: ProvenanceTaint
    required_auth_level: AuthLevel
    policy_version: str
    policy_epoch: int
    matched_rule: str
    reason: str


@dataclass(frozen=True)
class DeclarativeRule:
    """A declarative policy rule with matching criteria."""

    rule_id: str
    verdict: Verdict
    tool_server_id: Optional[str] = None  # None = wildcard
    tool_name: Optional[str] = None        # None = wildcard
    resource_uri_prefix: Optional[str] = None
    required_auth_level: Optional[AuthLevel] = None
    description: str = ""

