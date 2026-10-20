"""Shared Gateway Coordinator for Tool Interception Adapters.

Encapsulates the unified pipeline across Policy Engine, Crypto Registry, Storage,
and Execution Broker so adapters never implement independent security semantics.
"""

from __future__ import annotations

from typing import Any, Callable, Optional
import uuid

from ai_firewall.adapters.base import GatewayInvocationResponse, NormalizedActionProposal
from ai_firewall.broker.dispatcher import (
    DispatchProhibitedError,
    ExecutionBroker,
    PreconditionFailureError,
)
from ai_firewall.canonical.hasher import compute_action_digest
from ai_firewall.crypto.keys import KeyRegistry
from ai_firewall.crypto.record import sign_authorization_decision_record
from ai_firewall.policy.engine import PolicyEngine
from ai_firewall.policy.models import AuthLevel, ProvenanceTaint, RiskFactors, Verdict
from ai_firewall.storage.database import DatabaseManager, ReplayDetectedError


class GatewayCoordinator:
    """Coordinates policy evaluation, persistence, and execution dispatch for adapters."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        db_manager: DatabaseManager,
        key_registry: KeyRegistry,
        gateway_private_key: Any,
        gateway_key_id: str = "k_gw_01",
        gateway_principal_id: str = "gw_core",
        downstream_tool_handler: Optional[Callable[[dict[str, Any]], dict[str, Any]]] = None,
        live_resource_inspector: Optional[Callable[[str], dict[str, Any]]] = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.db = db_manager
        self.key_registry = key_registry
        self.gateway_private_key = gateway_private_key
        self.gateway_key_id = gateway_key_id
        self.gateway_principal_id = gateway_principal_id

        self.broker = ExecutionBroker(
            db_manager=self.db,
            key_registry=self.key_registry,
            current_policy_epoch=self.policy_engine.policy_epoch,
            gateway_principal_id=self.gateway_principal_id,
            downstream_tool_handler=downstream_tool_handler,
            live_resource_inspector=live_resource_inspector,
        )

    def process_invocation(
        self,
        proposal: NormalizedActionProposal,
        approval_envelope: Optional[dict[str, Any]] = None,
        worker_id: str = "worker_adapter",
        now_utc: Optional[str] = None,
    ) -> GatewayInvocationResponse:
        """Processes a normalized proposal through the full gateway authorization core."""
        action_id = proposal.action_id
        action_identity = proposal.action_identity
        action_digest = proposal.action_digest

        # 1. Record action identity in database
        try:
            self.db.record_action(action_id, action_identity, action_digest)
        except Exception:
            # Action may already be recorded on resume/repeat
            existing = self.db.get_action(action_id)
            if existing and existing["action_digest"].lower() != action_digest.lower():
                return GatewayInvocationResponse(
                    status="DENIED",
                    action_id=action_id,
                    action_digest=action_digest,
                    error_code="ERR_ACTION_IDENTITY_CONFLICT",
                    error_message=f"Action ID {action_id} already exists with a different action digest",
                )

        # 2. Map provenance taint
        taint = None
        if proposal.provenance_taint:
            try:
                taint = ProvenanceTaint(proposal.provenance_taint)
            except ValueError:
                taint = ProvenanceTaint.UNTRUSTED_INDIRECT_INPUT

        # 3. Evaluate Policy Engine
        eval_result = self.policy_engine.evaluate_action(
            normalized_action={"action_identity": action_identity, **action_identity},
            provenance_taint=taint,
        )

        # 4. Handle Policy DENY immediately
        if eval_result.verdict == Verdict.DENY:
            return GatewayInvocationResponse(
                status="DENIED",
                action_id=action_id,
                action_digest=action_digest,
                error_code="ERR_POLICY_DENIED",
                error_message=f"Action denied by policy: {eval_result.reason}",
            )

        # 5. Fetch existing or generate and sign new AuthorizationDecisionRecord
        existing_decision = self.db.get_decision_by_action_id(action_id)
        if existing_decision and existing_decision.get("action_digest", "").lower() == action_digest.lower():
            decision_record = existing_decision
            decision_id = decision_record["decision_id"]
        else:
            decision_id = f"dec_{uuid.uuid4().hex[:24]}"
            issued_ts = action_identity["authorization_binding"]["expires_at_utc"]
            decision_record = sign_authorization_decision_record(
                decision_id=decision_id,
                action_digest=action_digest,
                verdict=eval_result.verdict.value,
                policy_version=eval_result.policy_version,
                policy_epoch=eval_result.policy_epoch,
                issued_at_utc="2026-10-12T10:00:00.000000Z",
                score=eval_result.risk_score,
                risk_tier=eval_result.risk_tier.value,
                provenance_taint=eval_result.provenance_taint.value,
                required_auth_level=eval_result.required_auth_level.value,
                signer_key_id=self.gateway_key_id,
                private_key=self.gateway_private_key,
            )
            self.db.record_authorization_decision(decision_record, action_id)

        # 6. Check if Human Approval is Required
        if eval_result.verdict == Verdict.APPROVAL_REQUIRED:
            if approval_envelope is None:
                # Return approval challenge to adapter
                return GatewayInvocationResponse(
                    status="APPROVAL_REQUIRED",
                    action_id=action_id,
                    action_digest=action_digest,
                    approval_challenge={
                        "action_id": action_id,
                        "action_digest": action_digest,
                        "decision_id": decision_id,
                        "risk_score": eval_result.risk_score,
                        "risk_tier": eval_result.risk_tier.value,
                        "required_auth_level": eval_result.required_auth_level.value,
                        "reason": eval_result.reason,
                    },
                )
            else:
                # Assert approval envelope action digest matches proposed action digest
                env_digest = approval_envelope.get("action_digest", "").lower()
                if env_digest != action_digest.lower():
                    return GatewayInvocationResponse(
                        status="DENIED",
                        action_id=action_id,
                        action_digest=action_digest,
                        error_code="ERR_ENVELOPE_DIGEST_MISMATCH",
                        error_message=(
                            f"Approval envelope action digest ({env_digest}) "
                            f"does not match proposed action ({action_digest.lower()})"
                        ),
                    )
                # Register the approval envelope in database if not already present
                try:
                    self.db.register_approval_envelope(approval_envelope, action_id, decision_id)
                except Exception:
                    pass

        # 7. Execute via Controlled Execution Broker
        # If ALLOW (autonomous), no human approval envelope is required or manufactured.
        # The gateway-signed decision_record is the authoritative authorization grant.
        if eval_result.verdict == Verdict.ALLOW:
            active_envelope = None
        else:
            active_envelope = approval_envelope

        try:
            dispatch_res = self.broker.execute_authorized_action(
                normalized_action=action_identity,
                expected_action_digest=action_digest,
                approval_envelope=active_envelope,
                decision_record=decision_record,
                action_id=action_id,
                worker_id=worker_id,
                now_utc=now_utc,
            )
            return GatewayInvocationResponse(
                status="ALLOW_EXECUTED" if dispatch_res.status == "SUCCEEDED" else dispatch_res.status,
                action_id=action_id,
                action_digest=action_digest,
                output=dispatch_res.output,
                error_code=dispatch_res.error_code,
                error_message=dispatch_res.error_message,
            )
        except PreconditionFailureError as pre_exc:
            return GatewayInvocationResponse(
                status="RETRY_REQUIRED",
                action_id=action_id,
                action_digest=action_digest,
                error_code="ERR_STATE_DRIFT",
                error_message=str(pre_exc),
            )
        except (DispatchProhibitedError, ReplayDetectedError) as disp_exc:
            return GatewayInvocationResponse(
                status="DENIED",
                action_id=action_id,
                action_digest=action_digest,
                error_code="ERR_DISPATCH_PROHIBITED",
                error_message=str(disp_exc),
            )
        except Exception as general_exc:
            return GatewayInvocationResponse(
                status="UNKNOWN",
                action_id=action_id,
                action_digest=action_digest,
                error_code="ERR_BROKER_EXCEPTION",
                error_message=str(general_exc),
            )

