"""Deterministic unit tests for AI Firewall Policy Engine and Risk Classifier.

Tests:
1. Hard-deny supremacy over allow rules, low risk scores, and approvals.
2. Mandatory blocklist matching on resource URI and tool names.
3. Unregistered tool rejection (fail-closed).
4. Missing provenance fails closed to UNTRUSTED_INDIRECT_INPUT.
5. Taint elevation: untrusted taint prevents autonomous ALLOW even if risk score is zero.
6. Calibrated risk scoring formula: R in [0, 100], correct threshold mapping.
7. Step-up authentication mapping (R >= 80 forces MFA_HARDWARE_TOKEN).
8. Allow rule override by high risk scores.
"""

from __future__ import annotations

import pytest

from ai_firewall.policy.models import (
    AuthLevel,
    DeclarativeRule,
    ProvenanceTaint,
    RiskFactors,
    RiskTier,
    Verdict,
)
from ai_firewall.policy.engine import (
    PolicyEngine,
    calculate_risk_score,
    determine_risk_tier,
)


@pytest.fixture
def sample_action():
    return {
        "principal": {"user_id": "usr_bob", "agent_id": "agt_01", "session_id": "ses_01"},
        "invocation": {
            "tool_server_id": "mcp_fs",
            "tool_name": "write_file",
            "operation_type": "MUTATION",
            "canonical_params": {"path": "/tmp/test.txt"},
        },
        "target_resource": {"resource_uri": "file:///tmp/test.txt", "preconditions": None},
        "authorization_binding": {
            "policy_version": "pol_v1.0",
            "policy_epoch": 1,
            "idempotency_key": "idemp_01",
            "expires_at_utc": "2026-10-12T12:00:00Z",
        },
    }


def test_calculate_risk_score_bounds_and_weights():
    # Zero risk
    factors_zero = RiskFactors()
    assert calculate_risk_score(factors_zero) == 0.0

    # Max risk
    factors_max = RiskFactors(10, 10, 10, 10, 10, 10, 10, 10)
    assert calculate_risk_score(factors_max) == 100.0

    # Intermediate risk
    factors_mid = RiskFactors(mutability=5, reversibility=5, sensitivity=5, externalities=5, privilege=5, provenance=5, financial=5, blast_radius=5)
    assert calculate_risk_score(factors_mid) == 50.0
    assert determine_risk_tier(50.0) == RiskTier.MODERATE_RISK


def test_mandatory_deny_blocklist_supremacy(sample_action):
    """L2 blocklist must immediately deny regardless of risk factors or allow rules."""
    engine = PolicyEngine(
        mandatory_deny_patterns=[r"^file:///etc/", r"/passwd$"],
        declarative_rules=[DeclarativeRule("ALLOW_ALL", verdict=Verdict.ALLOW)],
    )

    action = dict(sample_action)
    action["target_resource"] = {"resource_uri": "file:///etc/shadow", "preconditions": None}

    res = engine.evaluate_action(action, RiskFactors(0, 0, 0, 0, 0, 0, 0, 0), ProvenanceTaint.CLEAN)
    assert res.verdict == Verdict.DENY
    assert "L2_MANDATORY_DENY" in res.matched_rule


def test_unregistered_tool_fails_closed(sample_action):
    """L3 rejects any tool not explicitly registered in the catalog."""
    engine = PolicyEngine(
        registered_tools={("mcp_fs", "read_file")},  # only read_file registered
    )

    # sample_action has write_file
    res = engine.evaluate_action(sample_action, RiskFactors(0, 0, 0, 0, 0, 0, 0, 0), ProvenanceTaint.CLEAN)
    assert res.verdict == Verdict.DENY
    assert res.matched_rule == "L3_UNREGISTERED_TOOL"


def test_missing_provenance_fails_closed_to_untrusted_taint(sample_action):
    """If provenance is omitted, engine assumes worst-case taint and elevates to APPROVAL_REQUIRED."""
    engine = PolicyEngine(
        registered_tools={("mcp_fs", "write_file")},
    )

    # Risk score is zero, but provenance is omitted (None)
    res = engine.evaluate_action(sample_action, RiskFactors(0, 0, 0, 0, 0, 0, 0, 0), provenance_taint=None)
    assert res.verdict == Verdict.APPROVAL_REQUIRED
    assert res.provenance_taint == ProvenanceTaint.UNTRUSTED_INDIRECT_INPUT
    assert "L4_TAINT_ELEVATION" in res.matched_rule


def test_taint_elevation_overrides_autonomous_allow(sample_action):
    """Untrusted context taint elevates an action to APPROVAL_REQUIRED even if score < 30."""
    engine = PolicyEngine(
        registered_tools={("mcp_fs", "write_file")},
    )

    # Score is 0.0, but provenance is UNTRUSTED_INDIRECT_INPUT
    res = engine.evaluate_action(
        sample_action,
        RiskFactors(0, 0, 0, 0, 0, 0, 0, 0),
        provenance_taint=ProvenanceTaint.UNTRUSTED_INDIRECT_INPUT,
    )
    assert res.verdict == Verdict.APPROVAL_REQUIRED
    assert res.required_auth_level == AuthLevel.STANDARD_PASSWORD


def test_clean_low_risk_permits_autonomous_allow(sample_action):
    """When provenance is CLEAN and score < 30, action qualifies for autonomous ALLOW."""
    engine = PolicyEngine(
        registered_tools={("mcp_fs", "write_file")},
    )

    factors_low = RiskFactors(mutability=2, reversibility=0, sensitivity=1, externalities=0)  # score ~ 5.5
    res = engine.evaluate_action(sample_action, factors_low, ProvenanceTaint.CLEAN)
    assert res.verdict == Verdict.ALLOW
    assert res.risk_score < 30.0
    assert res.required_auth_level == AuthLevel.NONE


def test_high_consequence_requires_step_up_mfa(sample_action):
    """When score >= 80, required authentication step-up must be MFA_HARDWARE_TOKEN."""
    engine = PolicyEngine(
        registered_tools={("mcp_fs", "write_file")},
    )

    factors_high = RiskFactors(mutability=10, reversibility=10, sensitivity=10, externalities=10, privilege=10, provenance=0, financial=10, blast_radius=10)  # score = 90
    res = engine.evaluate_action(sample_action, factors_high, ProvenanceTaint.CLEAN)
    assert res.verdict == Verdict.APPROVAL_REQUIRED
    assert res.risk_score >= 80.0
    assert res.risk_tier == RiskTier.HIGH_CONSEQUENCE
    assert res.required_auth_level == AuthLevel.MFA_HARDWARE_TOKEN


def test_declarative_deny_overrides_allow(sample_action):
    """Explicit declarative DENY rule rejects action regardless of low risk score."""
    engine = PolicyEngine(
        registered_tools={("mcp_fs", "write_file")},
        declarative_rules=[
            DeclarativeRule(rule_id="RULE_DENY_TMP", verdict=Verdict.DENY, resource_uri_prefix="file:///tmp/"),
            DeclarativeRule(rule_id="RULE_ALLOW_ALL", verdict=Verdict.ALLOW),
        ],
    )

    res = engine.evaluate_action(sample_action, RiskFactors(0, 0, 0, 0, 0, 0, 0, 0), ProvenanceTaint.CLEAN)
    assert res.verdict == Verdict.DENY
    assert "L5_RULE_DENY:RULE_DENY_TMP" in res.matched_rule
