"""Controlled Execution Broker for AI Firewall.

Enforces:
1. Revalidation of cryptographic envelope, authorization decision, policy epoch, and auth level.
2. Immediate pre-dispatch resource precondition inspection (TOCTOU defense).
3. Mandatory durable transition to DISPATCHING before any downstream network dispatch.
4. Worker lease fencing token validation on all state transitions.
5. Injected downstream tool dispatcher execution.
6. Ambiguous outcomes (timeouts/exceptions) transitioned durably to UNKNOWN with no auto-retry.
7. Idempotent return of recorded outcomes for duplicate requests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from ai_firewall.broker.preconditions import (
    StateDriftError,
    verify_resource_preconditions,
)
from ai_firewall.crypto.keys import KeyRegistry
from ai_firewall.crypto.envelope import verify_approval_envelope, ExecutionNotAuthorizedError
from ai_firewall.crypto.record import verify_authorization_decision_record
from ai_firewall.storage.database import (
    ApprovalNotFoundError,
    DatabaseManager,
    FencingTokenMismatchError,
    ReplayDetectedError,
    ReservationResult,
)


class BrokerError(Exception):
    """Base error for Execution Broker failures."""


class PreconditionFailureError(BrokerError):
    """Raised when resource precondition inspection fails prior to dispatch."""


class DispatchProhibitedError(BrokerError):
    """Raised when an action cannot be dispatched due to policy, epoch, or status denial."""


@dataclass(frozen=True)
class ExecutionDispatchResult:
    """Outcome returned to the agent runtime following broker dispatch."""

    status: str  # 'SUCCEEDED', 'FAILED', or 'UNKNOWN'
    approval_id: str
    action_id: str
    dispatch_epoch: int
    output: Optional[dict[str, Any]]
    error_code: Optional[str]
    error_message: Optional[str]


class ExecutionBroker:
    """Coordinates atomic verification, precondition checking, and controlled dispatch."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        key_registry: KeyRegistry,
        current_policy_epoch: int,
        gateway_principal_id: str = "gw_core",
        downstream_tool_handler: Optional[Callable[[dict[str, Any]], dict[str, Any]]] = None,
        live_resource_inspector: Optional[Callable[[str], dict[str, Any]]] = None,
    ) -> None:
        self.db = db_manager
        self.key_registry = key_registry
        self.current_policy_epoch = current_policy_epoch
        self.gateway_principal_id = gateway_principal_id
        self.downstream_tool_handler = downstream_tool_handler
        self.live_resource_inspector = live_resource_inspector

    def execute_authorized_action(
        self,
        normalized_action: dict[str, Any],
        expected_action_digest: str,
        approval_envelope: dict[str, Any],
        decision_record: dict[str, Any],
        action_id: str,
        worker_id: str,
        lease_duration_seconds: int = 30,
        now_utc: Optional[str] = None,
    ) -> ExecutionDispatchResult:
        """Executes the complete security-critical authorization and dispatch pipeline.

        Pipeline:
        1. Query if approval has already completed (idempotent result return).
        2. Validate Authorization Decision Record signature and policy epoch.
        3. Assert decision record verdict allows dispatch (not DENY or RETRY_REQUIRED).
        4. Validate Approval Envelope signature, status (must be APPROVED), and claims.
        5. Assert required_auth_level satisfied by envelope auth_level.
        6. Atomically reserve approval lease via DatabaseManager (single-use CAS).
        7. Inspect live resource preconditions (TOCTOU check).
        8. Atomically transition state to DISPATCHING.
        9. Dispatch tool invocation to downstream tool handler.
        10. Record definitive outcome (SUCCEEDED/FAILED) or UNKNOWN on ambiguous exception.
        """
        # Step 1: Validate Authorization Decision Record
        verify_authorization_decision_record(
            record=decision_record,
            key_registry=self.key_registry,
            expected_action_digest=expected_action_digest,
            current_policy_epoch=self.current_policy_epoch,
            gateway_principal_id=self.gateway_principal_id,
            verification_time_utc=now_utc,
        )

        # Step 2: Assert Decision Record allows execution
        verdict = decision_record.get("verdict")
        if verdict in ("DENY", "RETRY_REQUIRED"):
            raise DispatchProhibitedError(f"Dispatch prohibited by authorization decision verdict: {verdict}")

        req_auth = decision_record.get("evaluated_risk", {}).get("required_auth_level", "NONE")

        # Step 3: Branch between Autonomous ALLOW and Human Approval
        if approval_envelope is None:
            # Autonomous execution path
            if verdict != "ALLOW" or req_auth != "NONE":
                raise DispatchProhibitedError(
                    f"Approval envelope is required for verdict {verdict!r} with required auth level {req_auth!r}"
                )
            approval_id = f"auto_{decision_record['decision_id']}"
            is_autonomous = True
        else:
            # Human approval path
            approval_id = approval_envelope.get("approval_id")
            if not approval_id:
                raise DispatchProhibitedError("Missing approval_id in approval envelope")
            is_autonomous = False

            # Validate Approval Envelope Cryptography and Status
            verify_approval_envelope(
                envelope=approval_envelope,
                key_registry=self.key_registry,
                expected_action_digest=expected_action_digest,
                current_policy_epoch=self.current_policy_epoch,
                current_time_utc=now_utc,
                enforce_execution_allowed=True,  # Rejects REJECTED
            )

            # Assert Required Authentication Level
            envelope_auth = approval_envelope.get("decision_claims", {}).get("auth_level")
            auth_hierarchy = {"NONE": 0, "STANDARD_PASSWORD": 1, "MFA_TOTP": 2, "MFA_HARDWARE_TOKEN": 3}
            if auth_hierarchy.get(envelope_auth, 0) < auth_hierarchy.get(req_auth, 0):
                raise DispatchProhibitedError(
                    f"Insufficient authentication level! Required: {req_auth}, Provided in envelope: {envelope_auth}"
                )

        # Step 4: Check for duplicate / completed requests (Cache hit / Idempotency)
        try:
            prior_outcome = self.db.get_approval_outcome(approval_id)

            # Invariant binding verification on prior outcome
            if prior_outcome.action_digest.lower() != expected_action_digest.lower():
                raise DispatchProhibitedError(
                    f"Approval ID {approval_id!r} is bound to action digest {prior_outcome.action_digest!r}, "
                    f"not requested {expected_action_digest.lower()!r}"
                )
            if prior_outcome.action_id != action_id:
                raise DispatchProhibitedError(
                    f"Approval ID {approval_id!r} was registered for action {prior_outcome.action_id!r}, "
                    f"not requested {action_id!r}"
                )

            # Verify authorization context against recorded action
            recorded_action = self.db.get_action(action_id)
            if recorded_action:
                req_principal = normalized_action.get("principal", {})
                req_binding = normalized_action.get("authorization_binding", {})
                if (
                    recorded_action["user_id"] != req_principal.get("user_id")
                    or recorded_action["agent_id"] != req_principal.get("agent_id")
                    or recorded_action["session_id"] != req_principal.get("session_id")
                    or recorded_action["idempotency_key"] != req_binding.get("idempotency_key")
                ):
                    raise DispatchProhibitedError(
                        f"Authorization context mismatch for action {action_id!r}: principal or idempotency key changed"
                    )

            # Policy epoch check on recorded outcome / decision record
            if decision_record.get("policy_binding", {}).get("policy_epoch") != self.current_policy_epoch:
                raise DispatchProhibitedError(
                    f"Cached result invalidated by policy epoch bump: record epoch "
                    f"{decision_record.get('policy_binding', {}).get('policy_epoch')} != current epoch {self.current_policy_epoch}"
                )

            # Key revocation check for human approval envelope on cache hit
            if not is_autonomous and approval_envelope is not None:
                rev_claims = approval_envelope.get("decision_claims", {})
                rev_key_id = rev_claims.get("key_id")
                rev_user = rev_claims.get("reviewer_user_id")
                try:
                    self.key_registry.validate_and_get_public_key(
                        key_id=rev_key_id,
                        expected_owner=rev_user,
                        verification_time_utc=now_utc,
                    )
                except Exception as k_exc:
                    raise DispatchProhibitedError(
                        f"Cached result invalidated because reviewer key is invalid/revoked: {k_exc}"
                    ) from k_exc

            if prior_outcome.lifecycle_state in ("SUCCEEDED", "FAILED"):
                return ExecutionDispatchResult(
                    status=prior_outcome.lifecycle_state,
                    approval_id=approval_id,
                    action_id=action_id,
                    dispatch_epoch=prior_outcome.dispatch_epoch,
                    output=prior_outcome.execution_result,
                    error_code=prior_outcome.error_code,
                    error_message=prior_outcome.error_message,
                )
            elif prior_outcome.lifecycle_state == "UNKNOWN":
                return ExecutionDispatchResult(
                    status="UNKNOWN",
                    approval_id=approval_id,
                    action_id=action_id,
                    dispatch_epoch=prior_outcome.dispatch_epoch,
                    output=None,
                    error_code="ERR_UNKNOWN_DOWNSTREAM_STATE",
                    error_message="Action outcome is unknown; automatic re-dispatch is prohibited",
                )
            elif prior_outcome.lifecycle_state in ("REJECTED", "EXPIRED", "CANCELLED"):
                raise DispatchProhibitedError(
                    f"Approval {approval_id!r} is in terminal non-executable state: {prior_outcome.lifecycle_state}"
                )
        except ApprovalNotFoundError:
            pass  # New approval registration, proceed to reserve and execute

        # Step 5: Atomic Reservation (Single-Use Token Claim)
        if is_autonomous:
            reservation = self.db.register_and_reserve_autonomous_action(
                action_id=action_id,
                action_digest=expected_action_digest,
                decision_id=decision_record["decision_id"],
                worker_id=worker_id,
                lease_duration_seconds=lease_duration_seconds,
                now_utc=now_utc,
            )
        else:
            reservation = self.db.redeem_approval_atomically(
                approval_envelope=approval_envelope,
                action_id=action_id,
                expected_action_digest=expected_action_digest,
                decision_id=decision_record["decision_id"],
                worker_id=worker_id,
                lease_duration_seconds=lease_duration_seconds,
                key_registry=self.key_registry,
                current_policy_epoch=self.current_policy_epoch,
                now_utc=now_utc,
            )

        # Step 7: Precondition Inspection (Immediate Pre-Dispatch TOCTOU Check)
        target_res = normalized_action.get("target_resource", {})
        resource_uri = target_res.get("resource_uri", "")
        preconditions = target_res.get("preconditions")

        try:
            verify_resource_preconditions(
                resource_uri=resource_uri,
                preconditions=preconditions,
                live_state_inspector=self.live_resource_inspector,
            )
        except StateDriftError as drift_exc:
            # Precondition failed: reset or record failure
            self.db.record_execution_outcome(
                approval_id=approval_id,
                worker_id=worker_id,
                dispatch_epoch=reservation.dispatch_epoch,
                outcome_state="FAILED",
                error_code="ERR_STATE_DRIFT",
                error_message=str(drift_exc),
                now_utc=now_utc,
            )
            raise PreconditionFailureError(f"Precondition check failed prior to dispatch: {drift_exc}") from drift_exc

        # Step 8: Mandatory Durable Transition to DISPATCHING
        self.db.mark_dispatching(
            approval_id=approval_id,
            worker_id=worker_id,
            dispatch_epoch=reservation.dispatch_epoch,
            now_utc=now_utc,
        )

        # Step 9: Downstream Network Execution
        if self.downstream_tool_handler is None:
            raise BrokerError("No downstream tool handler configured in broker")

        try:
            tool_output = self.downstream_tool_handler(normalized_action)
            # Step 10A: Record Definitive SUCCEEDED
            self.db.record_execution_outcome(
                approval_id=approval_id,
                worker_id=worker_id,
                dispatch_epoch=reservation.dispatch_epoch,
                outcome_state="SUCCEEDED",
                execution_result=tool_output,
                now_utc=now_utc,
            )
            return ExecutionDispatchResult(
                status="SUCCEEDED",
                approval_id=approval_id,
                action_id=action_id,
                dispatch_epoch=reservation.dispatch_epoch,
                output=tool_output,
                error_code=None,
                error_message=None,
            )
        except Exception as dispatch_exc:
            # Step 10B: Ambiguous outcome handling
            # If downstream raised a known non-retryable execution error (e.g., ToolExecutionError with definite failure):
            # For general exceptions during network I/O, mark UNKNOWN to block uncoordinated retries!
            err_msg = str(dispatch_exc)
            self.db.record_execution_outcome(
                approval_id=approval_id,
                worker_id=worker_id,
                dispatch_epoch=reservation.dispatch_epoch,
                outcome_state="UNKNOWN",
                error_code="ERR_DISPATCH_EXCEPTION_UNKNOWN",
                error_message=err_msg,
                now_utc=now_utc,
            )
            return ExecutionDispatchResult(
                status="UNKNOWN",
                approval_id=approval_id,
                action_id=action_id,
                dispatch_epoch=reservation.dispatch_epoch,
                output=None,
                error_code="ERR_DISPATCH_EXCEPTION_UNKNOWN",
                error_message=err_msg,
            )

