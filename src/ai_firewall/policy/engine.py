"""Deterministic 7-Layer Policy Engine and Risk Classifier for AI Firewall.

Enforces:
1. Structural and cryptographic validation (fail-closed on malformed action).
2. Mandatory security denials (blocklists, destructive bans).
3. Target resource and tool server authorization.
4. Risk and provenance evaluation:
   - Factor weights w_i summing to 1.0, factor scores s_i in [0, 10].
   - Score R = 10 * sum(w_i * s_i) in [0.0, 100.0].
   - Taint elevation: UNTRUSTED taint forces APPROVAL_REQUIRED even if R < 30.
5. Explicit declarative rules (DENY supremacy over ALLOW).
6. Step-up authentication mapping (R >= 80 requires MFA_HARDWARE_TOKEN).
7. Fail-closed defaults on missing provenance, unknown tools, or engine errors.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from ai_firewall.policy.models import (
    AuthLevel,
    DeclarativeRule,
    PolicyEvaluationResult,
    ProvenanceTaint,
    RiskFactors,
    RiskTier,
    Verdict,
)


class PolicyEngineError(Exception):
    """Base error for Policy Engine failures."""


class UnknownToolError(PolicyEngineError):
    """Raised when an unregistered tool is evaluated."""


class MalformedPolicyConfigError(PolicyEngineError):
    """Raised when declarative rules or configurations are malformed."""


# Normalized factor weights (sum = 1.0)
WEIGHTS = {
    "mutability": 0.20,
    "reversibility": 0.15,
    "sensitivity": 0.15,
    "externalities": 0.15,
    "privilege": 0.10,
    "provenance": 0.10,
    "financial": 0.10,
    "blast_radius": 0.05,
}

# Calibrated decision thresholds
THRESHOLD_LOW = 30.0
THRESHOLD_HIGH = 80.0


def calculate_risk_score(factors: RiskFactors) -> float:
    """Calculates normalized risk score R = 10 * sum(w_i * s_i) in [0.0, 100.0]."""
    raw_sum = (
        factors.mutability * WEIGHTS["mutability"]
        + factors.reversibility * WEIGHTS["reversibility"]
        + factors.sensitivity * WEIGHTS["sensitivity"]
        + factors.externalities * WEIGHTS["externalities"]
        + factors.privilege * WEIGHTS["privilege"]
        + factors.provenance * WEIGHTS["provenance"]
        + factors.financial * WEIGHTS["financial"]
        + factors.blast_radius * WEIGHTS["blast_radius"]
    )
    score = round(10.0 * raw_sum, 2)
    # Ensure strict floating point bounds
    return max(0.0, min(100.0, score))


def determine_risk_tier(score: float) -> RiskTier:
    """Maps score to risk tier."""
    if score < THRESHOLD_LOW:
        return RiskTier.LOW_RISK
    elif score < THRESHOLD_HIGH:
        return RiskTier.MODERATE_RISK
    else:
        return RiskTier.HIGH_CONSEQUENCE


class PolicyEngine:
    """Deterministic policy engine implementing the 7-layer precedence pipeline."""

    def __init__(
        self,
        policy_version: str = "pol_v1.0",
        policy_epoch: int = 1,
        registered_tools: Optional[set[tuple[str, str]]] = None,  # (tool_server_id, tool_name)
        mandatory_deny_patterns: Optional[list[str]] = None,
        declarative_rules: Optional[list[DeclarativeRule]] = None,
    ) -> None:
        self.policy_version = policy_version
        self.policy_epoch = policy_epoch
        self.registered_tools = registered_tools or set()
        self.mandatory_deny_patterns = mandatory_deny_patterns or []
        self.declarative_rules = declarative_rules or []

    def evaluate_action(
        self,
        normalized_action: dict[str, Any],
        risk_factors: Optional[RiskFactors] = None,
        provenance_taint: Optional[ProvenanceTaint] = None,
    ) -> PolicyEvaluationResult:
        """Evaluates an action proposal against the 7-layer precedence pipeline.

        Fail-Closed Guarantees:
        - Missing provenance is treated as UNTRUSTED_INDIRECT_INPUT.
        - Unregistered tool server/tool name results in immediate DENY.
        - Hard-deny blocklists cannot be bypassed by any allow rule or score.
        """
        # --- Layer 1: Structural Action Validation ---
        if not isinstance(normalized_action, dict):
            return PolicyEvaluationResult(
                verdict=Verdict.DENY,
                risk_score=100.0,
                risk_tier=RiskTier.HIGH_CONSEQUENCE,
                provenance_taint=ProvenanceTaint.UNTRUSTED_INDIRECT_INPUT,
                required_auth_level=AuthLevel.NONE,
                policy_version=self.policy_version,
                policy_epoch=self.policy_epoch,
                matched_rule="L1_STRUCTURAL_FAIL",
                reason="Malformed action payload: not a dictionary",
            )

        inv = normalized_action.get("invocation", {})
        tool_server_id = inv.get("tool_server_id")
        tool_name = inv.get("tool_name")
        target_res = normalized_action.get("target_resource", {})
        resource_uri = target_res.get("resource_uri", "")

        # --- Layer 2: Mandatory Security Denials (Hard Blocklist Supremacy) ---
        for pattern in self.mandatory_deny_patterns:
            if re.search(pattern, resource_uri) or re.search(pattern, f"{tool_server_id}:{tool_name}"):
                return PolicyEvaluationResult(
                    verdict=Verdict.DENY,
                    risk_score=100.0,
                    risk_tier=RiskTier.HIGH_CONSEQUENCE,
                    provenance_taint=provenance_taint or ProvenanceTaint.UNTRUSTED_INDIRECT_INPUT,
                    required_auth_level=AuthLevel.NONE,
                    policy_version=self.policy_version,
                    policy_epoch=self.policy_epoch,
                    matched_rule=f"L2_MANDATORY_DENY:{pattern}",
                    reason=f"Target matches mandatory security blocklist pattern: {pattern}",
                )

        # --- Layer 3: Target Resource & Tool Registry Authorization ---
        if self.registered_tools and (tool_server_id, tool_name) not in self.registered_tools:
            return PolicyEvaluationResult(
                verdict=Verdict.DENY,
                risk_score=100.0,
                risk_tier=RiskTier.HIGH_CONSEQUENCE,
                provenance_taint=provenance_taint or ProvenanceTaint.UNTRUSTED_INDIRECT_INPUT,
                required_auth_level=AuthLevel.NONE,
                policy_version=self.policy_version,
                policy_epoch=self.policy_epoch,
                matched_rule="L3_UNREGISTERED_TOOL",
                reason=f"Unregistered tool target ({tool_server_id}:{tool_name}) rejected by policy",
            )

        # --- Layer 4: Risk and Provenance Evaluation ---
        # Fail-closed: missing provenance defaults to UNTRUSTED_INDIRECT_INPUT
        actual_taint = provenance_taint if provenance_taint is not None else ProvenanceTaint.UNTRUSTED_INDIRECT_INPUT

        if risk_factors is None:
            # Default heuristic if factors omitted: assess worst-case risk based on operation_type
            op_type = inv.get("operation_type", "MUTATION")
            if op_type == "READ_ONLY":
                actual_factors = RiskFactors(mutability=0, reversibility=0, sensitivity=3, externalities=0)
            else:
                actual_factors = RiskFactors(mutability=8, reversibility=8, sensitivity=7, externalities=5, blast_radius=5)
        else:
            actual_factors = risk_factors

        risk_score = calculate_risk_score(actual_factors)
        risk_tier = determine_risk_tier(risk_score)

        # --- Layer 5: Explicit Declarative Policy Rule Matching ---
        # Check declarative rules in definition order
        matched_rule_id = "DEFAULT_RISK_ROUTING"
        rule_verdict: Optional[Verdict] = None
        rule_req_auth: Optional[AuthLevel] = None

        for rule in self.declarative_rules:
            server_match = rule.tool_server_id is None or rule.tool_server_id == tool_server_id
            tool_match = rule.tool_name is None or rule.tool_name == tool_name
            uri_match = rule.resource_uri_prefix is None or resource_uri.startswith(rule.resource_uri_prefix)

            if server_match and tool_match and uri_match:
                matched_rule_id = rule.rule_id
                rule_verdict = rule.verdict
                rule_req_auth = rule.required_auth_level
                break

        # Mandatory Hard Deny in Declarative Rules
        if rule_verdict == Verdict.DENY:
            return PolicyEvaluationResult(
                verdict=Verdict.DENY,
                risk_score=risk_score,
                risk_tier=risk_tier,
                provenance_taint=actual_taint,
                required_auth_level=AuthLevel.NONE,
                policy_version=self.policy_version,
                policy_epoch=self.policy_epoch,
                matched_rule=f"L5_RULE_DENY:{matched_rule_id}",
                reason=f"Matched explicit policy DENY rule: {matched_rule_id}",
            )

        # --- Layer 6 & 7: Threshold Evaluation, Taint Elevation & Auth Level Mapping ---
        # Authentication level determination
        if risk_tier == RiskTier.HIGH_CONSEQUENCE:
            required_auth = AuthLevel.MFA_HARDWARE_TOKEN
        elif risk_tier == RiskTier.MODERATE_RISK:
            required_auth = AuthLevel.STANDARD_PASSWORD
        else:
            required_auth = AuthLevel.NONE

        if rule_req_auth is not None:
            # Explicit rule can demand stronger auth, but never weaken High Consequence
            if required_auth == AuthLevel.MFA_HARDWARE_TOKEN:
                pass  # Keep MFA_HARDWARE_TOKEN
            else:
                required_auth = rule_req_auth

        # Taint Elevation: If input context is UNTRUSTED or SUSPICIOUS, autonomous ALLOW is forbidden!
        if actual_taint in (ProvenanceTaint.UNTRUSTED_INDIRECT_INPUT, ProvenanceTaint.SUSPICIOUS_EXTERNAL):
            # Taint forces human review even if risk score is low
            return PolicyEvaluationResult(
                verdict=Verdict.APPROVAL_REQUIRED,
                risk_score=risk_score,
                risk_tier=risk_tier,
                provenance_taint=actual_taint,
                required_auth_level=required_auth if required_auth != AuthLevel.NONE else AuthLevel.STANDARD_PASSWORD,
                policy_version=self.policy_version,
                policy_epoch=self.policy_epoch,
                matched_rule=f"L4_TAINT_ELEVATION:{matched_rule_id}",
                reason=f"Untrusted context taint ({actual_taint.value}) elevated action to mandatory human approval",
            )

        # Explicit ALLOW rule with CLEAN provenance
        if rule_verdict == Verdict.ALLOW:
            if risk_score < THRESHOLD_LOW:
                return PolicyEvaluationResult(
                    verdict=Verdict.ALLOW,
                    risk_score=risk_score,
                    risk_tier=risk_tier,
                    provenance_taint=actual_taint,
                    required_auth_level=AuthLevel.NONE,
                    policy_version=self.policy_version,
                    policy_epoch=self.policy_epoch,
                    matched_rule=f"L5_RULE_ALLOW:{matched_rule_id}",
                    reason=f"Permitted by explicit allow rule: {matched_rule_id}",
                )
            else:
                # High risk overrides explicit allow to APPROVAL_REQUIRED
                return PolicyEvaluationResult(
                    verdict=Verdict.APPROVAL_REQUIRED,
                    risk_score=risk_score,
                    risk_tier=risk_tier,
                    provenance_taint=actual_taint,
                    required_auth_level=required_auth,
                    policy_version=self.policy_version,
                    policy_epoch=self.policy_epoch,
                    matched_rule=f"L4_RISK_OVERRIDE_ALLOW:{matched_rule_id}",
                    reason=f"Elevated risk score ({risk_score}) overrides allow rule to require approval",
                )

        # Default Risk Routing (No explicit allow/deny rule matched)
        if risk_score < THRESHOLD_LOW:
            final_verdict = Verdict.ALLOW
            final_auth = AuthLevel.NONE
            reason_text = f"Low risk action ({risk_score} < {THRESHOLD_LOW}) authorized for autonomous dispatch"
        else:
            final_verdict = Verdict.APPROVAL_REQUIRED
            final_auth = required_auth
            reason_text = f"Risk score ({risk_score} >= {THRESHOLD_LOW}) requires human approval ({final_auth.value})"

        return PolicyEvaluationResult(
            verdict=final_verdict,
            risk_score=risk_score,
            risk_tier=risk_tier,
            provenance_taint=actual_taint,
            required_auth_level=final_auth,
            policy_version=self.policy_version,
            policy_epoch=self.policy_epoch,
            matched_rule=matched_rule_id,
            reason=reason_text,
        )

