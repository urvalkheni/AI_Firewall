"""Persistent Lifecycle Storage, Atomic Redemption, and Worker Fencing.

Implements the AI Firewall state machine on SQLite:
- Single-use nonce uniqueness constraints.
- Atomic worker lease reservation with monotonic fencing counters (dispatch_epoch).
- Verification of cryptographic envelope and authorization decision bindings.
- Crash recovery: transitions unfulfilled RESERVED leases, and marks in-flight
  DISPATCHING timeouts as UNKNOWN.
- Idempotent queries for completed actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import sqlite3
import threading
from typing import Any, Optional

from ai_firewall.crypto.keys import KeyRegistry
from ai_firewall.crypto.envelope import verify_approval_envelope, ApprovalEnvelopeError
from ai_firewall.crypto.record import verify_authorization_decision_record, DecisionRecordError


class StorageError(Exception):
    """Base error for storage and lifecycle state machine failures."""


class ActionNotFoundError(StorageError):
    """Raised when an action is not found."""


class DecisionNotFoundError(StorageError):
    """Raised when an authorization decision is not found."""


class ApprovalNotFoundError(StorageError):
    """Raised when an approval is not found."""


class InvalidStateTransitionError(StorageError):
    """Raised when an illegal lifecycle state transition is requested."""


class ReplayDetectedError(StorageError):
    """Raised when an approval has already been redeemed, consumed, or is currently in-flight."""


class ConcurrencyContentionError(StorageError):
    """Raised when a concurrent worker won the race to reserve the approval."""


class FencingTokenMismatchError(StorageError):
    """Raised when a worker attempts an operation with a stale dispatch_epoch."""


class InvariantBindingMismatchError(StorageError):
    """Raised when an approval does not bind to the claimed action or decision."""


# Legal state transitions map
LEGAL_TRANSITIONS: dict[str, set[str]] = {
    "PROPOSED": {"PENDING_APPROVAL", "APPROVED", "FAILED", "CANCELLED"},
    "PENDING_APPROVAL": {"APPROVED", "REJECTED", "EXPIRED", "CANCELLED"},
    "APPROVED": {"RESERVED", "EXPIRED", "CANCELLED"},
    "RESERVED": {"DISPATCHING", "APPROVED", "FAILED", "CANCELLED"},  # APPROVED on lease recovery
    "DISPATCHING": {"SUCCEEDED", "FAILED", "UNKNOWN"},
    "UNKNOWN": {"SUCCEEDED", "FAILED"},  # Operator/idempotent reconciliation only
    # Terminal states
    "SUCCEEDED": set(),
    "FAILED": set(),
    "REJECTED": set(),
    "EXPIRED": set(),
    "CANCELLED": set(),
}


def _parse_iso_utc(ts_str: str) -> datetime:
    """Parses ISO 8601 UTC timestamp ending in 'Z'."""
    if not isinstance(ts_str, str) or not ts_str.endswith("Z"):
        raise ValueError(f"Timestamp must be ISO 8601 string ending in 'Z': {ts_str!r}")
    clean = ts_str[:-1]
    return datetime.fromisoformat(clean).replace(tzinfo=timezone.utc)


def _now_utc_str() -> str:
    """Returns current UTC timestamp formatted with microsecond precision and 'Z'."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ReservationResult:
    """Result returned upon successful atomic reservation."""

    approval_id: str
    action_id: str
    action_digest: str
    decision_id: str
    worker_id: str
    dispatch_epoch: int
    lease_expires_at_utc: str


@dataclass(frozen=True)
class RedemptionOutcome:
    """Outcome returned for duplicate requests or completed actions."""

    approval_id: str
    lifecycle_state: str
    dispatch_epoch: int
    execution_result: Optional[dict[str, Any]]
    error_code: Optional[str]
    error_message: Optional[str]
    action_id: str = ""
    action_digest: str = ""
    decision_id: str = ""


class DatabaseManager:
    """Manages transactional SQLite storage for the AI Firewall authorization lifecycle."""

    def __init__(
        self,
        db_path: str = ":memory:",
        timeout_seconds: float = 30.0,
        reuse_connections: bool = False,
    ) -> None:
        if db_path == ":memory:" and not reuse_connections:
            raise ValueError(
                "Unsupported configuration: ':memory:' database cannot be used with reuse_connections=False "
                "because each non-reused connection creates an isolated, empty in-memory database where schema "
                "and tables are not retained across calls. Use a file-backed path or set reuse_connections=True."
            )
        self.db_path = db_path
        self.timeout_seconds = timeout_seconds
        self.reuse_connections = reuse_connections
        self._conns_lock = threading.Lock()
        self._thread_conns: dict[int, sqlite3.Connection] = {}
        self._is_closed = False
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        with self._conns_lock:
            if self._is_closed:
                raise StorageError("DatabaseManager has been closed")

            if self.reuse_connections:
                tid = threading.get_ident()
                conn = self._thread_conns.get(tid)
                if conn is None:
                    # check_same_thread=False allows deterministic cleanup from manager thread
                    # while our dictionary mapping strictly enforces thread-to-connection binding
                    conn = sqlite3.connect(
                        self.db_path,
                        timeout=self.timeout_seconds,
                        check_same_thread=False,
                    )
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys = ON;")
                    conn.execute("PRAGMA journal_mode = WAL;")
                    self._thread_conns[tid] = conn
                return conn

        # On-demand connection creation path
        conn = sqlite3.connect(self.db_path, timeout=self.timeout_seconds)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def close(self) -> None:
        """Closes all tracked thread connections and marks manager as closed."""
        with self._conns_lock:
            self._is_closed = True
            for tid, conn in list(self._thread_conns.items()):
                try:
                    conn.close()
                except Exception:
                    pass
            self._thread_conns.clear()

    def _init_db(self) -> None:
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        with self._get_connection() as conn:
            conn.executescript(schema_sql)

    # --------------------------------------------------------------------------
    # 1. Action & Decision Persistence
    # --------------------------------------------------------------------------

    def record_action(self, action_id: str, action_identity: dict[str, Any], action_digest: str) -> None:
        """Stores a proposed action identity."""
        principal = action_identity["principal"]
        invocation = action_identity["invocation"]
        target_res = action_identity["target_resource"]
        auth_binding = action_identity["authorization_binding"]

        preconds_json = json.dumps(target_res.get("preconditions")) if target_res.get("preconditions") else None

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO actions (
                    action_id, action_digest, user_id, agent_id, session_id,
                    tool_server_id, tool_name, operation_type, resource_uri,
                    preconditions_json, policy_version, policy_epoch,
                    idempotency_key, expires_at_utc, created_at_utc, raw_normalized_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    action_id,
                    action_digest.lower(),
                    principal["user_id"],
                    principal["agent_id"],
                    principal["session_id"],
                    invocation["tool_server_id"],
                    invocation["tool_name"],
                    invocation["operation_type"],
                    target_res["resource_uri"],
                    preconds_json,
                    auth_binding["policy_version"],
                    auth_binding["policy_epoch"],
                    auth_binding["idempotency_key"],
                    auth_binding["expires_at_utc"],
                    _now_utc_str(),
                    json.dumps(action_identity),
                ),
            )

    def record_authorization_decision(self, decision_record: dict[str, Any], action_id: str) -> None:
        """Stores an authorized gateway decision record."""
        pb = decision_record["policy_binding"]
        er = decision_record["evaluated_risk"]
        gs = decision_record["gateway_signature"]

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO authorization_decisions (
                    decision_id, action_id, action_digest, verdict,
                    policy_version, policy_epoch, risk_score, risk_tier,
                    provenance_taint, required_auth_level, signer_key_id,
                    issued_at_utc, raw_record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    decision_record["decision_id"],
                    action_id,
                    decision_record["action_digest"].lower(),
                    decision_record["verdict"],
                    pb["policy_version"],
                    pb["policy_epoch"],
                    er["score"],
                    er["risk_tier"],
                    er["provenance_taint"],
                    er["required_auth_level"],
                    gs["signer_key_id"],
                    pb["issued_at_utc"],
                    json.dumps(decision_record),
                ),
            )

    def register_approval_envelope(
        self,
        envelope: dict[str, Any],
        action_id: str,
        decision_id: str,
        initial_state: str = "APPROVED",
    ) -> None:
        """Registers a signed approval envelope in the database."""
        claims = envelope["decision_claims"]
        now_ts = _now_utc_str()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO approvals (
                    approval_id, action_id, action_digest, decision_id,
                    single_use_nonce, approval_status, auth_level,
                    reviewer_user_id, key_id, policy_version, policy_epoch,
                    issued_at_utc, expires_at_utc, lifecycle_state,
                    raw_envelope_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    envelope["approval_id"],
                    action_id,
                    envelope["action_digest"].lower(),
                    decision_id,
                    claims["single_use_nonce"].lower(),
                    envelope["approval_status"],
                    claims["auth_level"],
                    claims["reviewer_user_id"],
                    claims["key_id"],
                    claims["policy_version"],
                    claims["policy_epoch"],
                    claims["issued_at_utc"],
                    claims["expires_at_utc"],
                    initial_state,
                    json.dumps(envelope),
                ),
            )

            # Audit record
            conn.execute(
                """
                INSERT INTO audit_log (
                    approval_id, action_id, action_digest, from_state,
                    to_state, dispatch_epoch, worker_id, transition_timestamp_utc, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    envelope["approval_id"],
                    action_id,
                    envelope["action_digest"].lower(),
                    "INITIAL_REGISTRATION",
                    initial_state,
                    0,
                    None,
                    now_ts,
                    f"Registered approval with status {envelope['approval_status']}",
                ),
            )

    def register_and_reserve_autonomous_action(
        self,
        action_id: str,
        action_digest: str,
        decision_id: str,
        worker_id: str,
        lease_duration_seconds: int = 30,
        now_utc: Optional[str] = None,
    ) -> ReservationResult:
        """Atomically registers and reserves an autonomous ALLOW action for execution.

        Autonomous execution does not involve human approval; instead it is authorized
        solely by a gateway-signed AuthorizationDecisionRecord (verdict=ALLOW, auth_level=NONE).
        Creates a synthetic approval record with auth_level='NONE' and transitions directly
        from APPROVED to RESERVED in a single exclusive transaction.
        """
        eval_time = now_utc or _now_utc_str()
        from datetime import timedelta
        lease_exp_dt = _parse_iso_utc(eval_time) + timedelta(seconds=lease_duration_seconds)
        lease_exp_str = lease_exp_dt.isoformat().replace("+00:00", "Z")

        approval_id = f"auto_{decision_id}"
        nonce = f"autononce_{decision_id}_{action_id}"

        # Fetch action details for metadata binding
        action_row = self.get_action(action_id)
        if not action_row:
            raise ActionNotFoundError(f"Action {action_id!r} not found in database")

        user_id = action_row["user_id"]
        pol_ver = action_row["policy_version"]
        pol_epoch = action_row["policy_epoch"]
        exp_utc = action_row["expires_at_utc"]

        with self._get_connection() as conn:
            conn.execute("BEGIN EXCLUSIVE TRANSACTION;")

            # Check if this autonomous approval already exists
            cur = conn.execute("SELECT * FROM approvals WHERE approval_id = ?;", (approval_id,))
            row = cur.fetchone()
            if row:
                st = row["lifecycle_state"]
                if st in ("SUCCEEDED", "FAILED", "REJECTED", "EXPIRED", "CANCELLED", "UNKNOWN"):
                    raise ReplayDetectedError(f"Autonomous action {approval_id} already executed or terminal: state={st}")
                if st in ("RESERVED", "DISPATCHING"):
                    lease_exp = row["lease_expires_at_utc"]
                    if lease_exp and _parse_iso_utc(eval_time) <= _parse_iso_utc(lease_exp):
                        raise ConcurrencyContentionError(f"Autonomous action {approval_id} locked by {row['worker_id']}")
                    raise ConcurrencyContentionError(f"Autonomous action {approval_id} has expired lease, awaiting recovery")
                # If in APPROVED state, reserve it
                new_epoch = row["dispatch_epoch"] + 1
                upd = conn.execute(
                    """
                    UPDATE approvals
                    SET lifecycle_state = 'RESERVED',
                        worker_id = ?,
                        dispatch_epoch = ?,
                        lease_expires_at_utc = ?
                    WHERE approval_id = ? AND lifecycle_state = 'APPROVED';
                    """,
                    (worker_id, new_epoch, lease_exp_str, approval_id),
                )
                if upd.rowcount != 1:
                    raise ConcurrencyContentionError(f"Race won by concurrent worker on {approval_id}")
            else:
                # Insert directly in RESERVED state with epoch 1
                new_epoch = 1
                raw_auto_record = json.dumps({
                    "type": "AUTONOMOUS_ALLOW_GRANT",
                    "decision_id": decision_id,
                    "action_id": action_id,
                    "action_digest": action_digest.lower(),
                })
                conn.execute(
                    """
                    INSERT INTO approvals (
                        approval_id, action_id, action_digest, decision_id,
                        single_use_nonce, approval_status, auth_level,
                        reviewer_user_id, key_id, policy_version, policy_epoch,
                        issued_at_utc, expires_at_utc, lifecycle_state,
                        worker_id, dispatch_epoch, lease_expires_at_utc,
                        raw_envelope_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        approval_id,
                        action_id,
                        action_digest.lower(),
                        decision_id,
                        nonce,
                        "APPROVED",
                        "NONE",
                        user_id,
                        "gateway_policy_engine",
                        pol_ver,
                        pol_epoch,
                        eval_time,
                        exp_utc,
                        "RESERVED",
                        worker_id,
                        new_epoch,
                        lease_exp_str,
                        raw_auto_record,
                    ),
                )

            # Audit record
            conn.execute(
                """
                INSERT INTO audit_log (
                    approval_id, action_id, action_digest, from_state,
                    to_state, dispatch_epoch, worker_id, transition_timestamp_utc, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    approval_id,
                    action_id,
                    action_digest.lower(),
                    "INITIAL_REGISTRATION",
                    "RESERVED",
                    new_epoch,
                    worker_id,
                    eval_time,
                    "Autonomous policy ALLOW dispatched by worker",
                ),
            )

            return ReservationResult(
                approval_id=approval_id,
                action_id=action_id,
                action_digest=action_digest.lower(),
                decision_id=decision_id,
                worker_id=worker_id,
                dispatch_epoch=new_epoch,
                lease_expires_at_utc=lease_exp_str,
            )

    # --------------------------------------------------------------------------
    # 2. Atomic Single-Use Redemption
    # --------------------------------------------------------------------------

    def redeem_approval_atomically(
        self,
        approval_envelope: dict[str, Any],
        action_id: str,
        expected_action_digest: str,
        decision_id: str,
        worker_id: str,
        lease_duration_seconds: int = 30,
        key_registry: Optional[KeyRegistry] = None,
        current_policy_epoch: Optional[int] = None,
        now_utc: Optional[str] = None,
    ) -> ReservationResult:
        """Atomically validates, claims, and reserves an approval for dispatch.

        Guarantees:
        - Cryptographic envelope validity (via Phase 4.2 module if registry provided).
        - Invariant binding: approval binds to action_id, decision_id, and digest.
        - Single-use exclusivity: exactly ONE worker can successfully transition
          state from APPROVED to RESERVED.
        - Monotonic increment of dispatch_epoch (worker fencing counter).
        - Duplicate requests or previously completed actions raise ReplayDetectedError.
        """
        eval_time = now_utc or _now_utc_str()

        # Step A: Cryptographic check if KeyRegistry is provided
        if key_registry is not None and current_policy_epoch is not None:
            verify_approval_envelope(
                envelope=approval_envelope,
                key_registry=key_registry,
                expected_action_digest=expected_action_digest,
                current_policy_epoch=current_policy_epoch,
                current_time_utc=eval_time,
                enforce_execution_allowed=True,
            )

        approval_id = approval_envelope["approval_id"]
        nonce = approval_envelope["decision_claims"]["single_use_nonce"].lower()
        envelope_digest = approval_envelope["action_digest"].lower()

        # Step B: Database Atomic Check and Update inside an EXCLUSIVE transaction
        with self._get_connection() as conn:
            conn.execute("BEGIN EXCLUSIVE TRANSACTION;")

            # 1. Fetch current approval row
            cur = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?;",
                (approval_id,),
            )
            row = cur.fetchone()

            if not row:
                raise ApprovalNotFoundError(f"Approval {approval_id!r} not found in database")

            # 2. Invariant binding assertions
            if row["action_id"] != action_id:
                raise InvariantBindingMismatchError(
                    f"Approval bound to action_id {row['action_id']!r}, not claimed {action_id!r}"
                )
            if row["decision_id"] != decision_id:
                raise InvariantBindingMismatchError(
                    f"Approval bound to decision_id {row['decision_id']!r}, not claimed {decision_id!r}"
                )
            if row["action_digest"] != expected_action_digest.lower():
                raise InvariantBindingMismatchError(
                    f"Approval bound to digest {row['action_digest']!r}, not expected {expected_action_digest.lower()!r}"
                )
            if row["single_use_nonce"] != nonce:
                raise InvariantBindingMismatchError("Single-use nonce mismatch")

            current_state = row["lifecycle_state"]

            # 3. Handle duplicate/replay terminal states
            if current_state in ("SUCCEEDED", "FAILED", "REJECTED", "EXPIRED", "CANCELLED", "UNKNOWN"):
                raise ReplayDetectedError(
                    f"Approval {approval_id} is already terminal or completed: state={current_state}"
                )

            # 4. Handle active in-flight states
            if current_state in ("RESERVED", "DISPATCHING"):
                # Check if lease expired
                lease_exp = row["lease_expires_at_utc"]
                if lease_exp and _parse_iso_utc(eval_time) <= _parse_iso_utc(lease_exp):
                    raise ConcurrencyContentionError(
                        f"Approval {approval_id} is currently locked by worker {row['worker_id']} (state={current_state})"
                    )
                # If lease expired, recovery must happen via reaper or explicit reclaim
                raise ConcurrencyContentionError(
                    f"Approval {approval_id} has expired lease in state {current_state}, awaiting recovery"
                )

            if current_state != "APPROVED":
                raise InvalidStateTransitionError(
                    f"Cannot reserve approval in state {current_state}, must be 'APPROVED'"
                )

            # 5. Atomic conditional reservation
            from datetime import timedelta
            lease_exp_dt = _parse_iso_utc(eval_time) + timedelta(seconds=lease_duration_seconds)
            lease_exp_str = lease_exp_dt.isoformat().replace("+00:00", "Z")
            new_epoch = row["dispatch_epoch"] + 1

            update_cur = conn.execute(
                """
                UPDATE approvals
                SET lifecycle_state = 'RESERVED',
                    worker_id = ?,
                    dispatch_epoch = ?,
                    lease_expires_at_utc = ?
                WHERE approval_id = ? AND lifecycle_state = 'APPROVED';
                """,
                (worker_id, new_epoch, lease_exp_str, approval_id),
            )

            if update_cur.rowcount != 1:
                # Concurrent worker won the race
                raise ConcurrencyContentionError(
                    f"Failed to atomically reserve approval {approval_id}: race won by another worker"
                )

            # 6. Record audit transition
            conn.execute(
                """
                INSERT INTO audit_log (
                    approval_id, action_id, action_digest, from_state,
                    to_state, dispatch_epoch, worker_id, transition_timestamp_utc, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    approval_id,
                    action_id,
                    expected_action_digest.lower(),
                    "APPROVED",
                    "RESERVED",
                    new_epoch,
                    worker_id,
                    eval_time,
                    f"Reserved by worker {worker_id}",
                ),
            )

            return ReservationResult(
                approval_id=approval_id,
                action_id=action_id,
                action_digest=expected_action_digest.lower(),
                decision_id=decision_id,
                worker_id=worker_id,
                dispatch_epoch=new_epoch,
                lease_expires_at_utc=lease_exp_str,
            )

    # --------------------------------------------------------------------------
    # 3. Transition to DISPATCHING & Fencing Token Assertion
    # --------------------------------------------------------------------------

    def mark_dispatching(
        self,
        approval_id: str,
        worker_id: str,
        dispatch_epoch: int,
        now_utc: Optional[str] = None,
    ) -> None:
        """Transitions state from RESERVED to DISPATCHING.

        Fencing Assertion:
        Validates that worker_id and dispatch_epoch match the active lease.
        If a zombie worker woke up after its lease expired and was replaced,
        dispatch_epoch has incremented, causing immediate failure.
        """
        eval_time = now_utc or _now_utc_str()

        with self._get_connection() as conn:
            conn.execute("BEGIN EXCLUSIVE TRANSACTION;")

            cur = conn.execute("SELECT * FROM approvals WHERE approval_id = ?;", (approval_id,))
            row = cur.fetchone()
            if not row:
                raise ApprovalNotFoundError(f"Approval {approval_id!r} not found")

            if row["lifecycle_state"] != "RESERVED":
                raise InvalidStateTransitionError(
                    f"Cannot transition to DISPATCHING from state {row['lifecycle_state']}"
                )

            if row["worker_id"] != worker_id or row["dispatch_epoch"] != dispatch_epoch:
                raise FencingTokenMismatchError(
                    f"Stale worker fencing token! Claimed (worker={worker_id}, epoch={dispatch_epoch}), "
                    f"Database has (worker={row['worker_id']}, epoch={row['dispatch_epoch']})"
                )

            # Check lease expiry
            if _parse_iso_utc(eval_time) > _parse_iso_utc(row["lease_expires_at_utc"]):
                raise FencingTokenMismatchError(f"Worker lease expired at {row['lease_expires_at_utc']}")

            conn.execute(
                """
                UPDATE approvals
                SET lifecycle_state = 'DISPATCHING'
                WHERE approval_id = ? AND dispatch_epoch = ?;
                """,
                (approval_id, dispatch_epoch),
            )

            conn.execute(
                """
                INSERT INTO audit_log (
                    approval_id, action_id, action_digest, from_state,
                    to_state, dispatch_epoch, worker_id, transition_timestamp_utc, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    approval_id,
                    row["action_id"],
                    row["action_digest"],
                    "RESERVED",
                    "DISPATCHING",
                    dispatch_epoch,
                    worker_id,
                    eval_time,
                    "Preconditions passed; in-flight network dispatch started",
                ),
            )

    # --------------------------------------------------------------------------
    # 4. Terminal Outcome Recording
    # --------------------------------------------------------------------------

    def record_execution_outcome(
        self,
        approval_id: str,
        worker_id: str,
        dispatch_epoch: int,
        outcome_state: str,  # 'SUCCEEDED', 'FAILED', or 'UNKNOWN'
        execution_result: Optional[dict[str, Any]] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        now_utc: Optional[str] = None,
    ) -> None:
        """Records the terminal execution outcome (SUCCEEDED or FAILED) or UNKNOWN.

        Validates worker lease fencing token before updating.
        """
        if outcome_state not in ("SUCCEEDED", "FAILED", "UNKNOWN"):
            raise InvalidStateTransitionError(f"Invalid outcome state: {outcome_state}")

        eval_time = now_utc or _now_utc_str()

        with self._get_connection() as conn:
            conn.execute("BEGIN EXCLUSIVE TRANSACTION;")

            cur = conn.execute("SELECT * FROM approvals WHERE approval_id = ?;", (approval_id,))
            row = cur.fetchone()
            if not row:
                raise ApprovalNotFoundError(f"Approval {approval_id!r} not found")

            allowed_prior_states = ("DISPATCHING", "UNKNOWN")
            if outcome_state == "FAILED":
                allowed_prior_states = ("DISPATCHING", "UNKNOWN", "RESERVED")

            if row["lifecycle_state"] not in allowed_prior_states:
                raise InvalidStateTransitionError(
                    f"Cannot record outcome {outcome_state} from state {row['lifecycle_state']}"
                )

            if row["worker_id"] != worker_id or row["dispatch_epoch"] != dispatch_epoch:
                raise FencingTokenMismatchError(
                    f"Fencing token mismatch recording outcome: worker={worker_id}, epoch={dispatch_epoch}"
                )

            res_json = json.dumps(execution_result) if execution_result is not None else None

            conn.execute(
                """
                UPDATE approvals
                SET lifecycle_state = ?,
                    consumed_at_utc = ?,
                    execution_result_json = ?,
                    error_code = ?,
                    error_message = ?,
                    lease_expires_at_utc = NULL
                WHERE approval_id = ? AND dispatch_epoch = ?;
                """,
                (
                    outcome_state,
                    eval_time if outcome_state == "SUCCEEDED" else None,
                    res_json,
                    error_code,
                    error_message,
                    approval_id,
                    dispatch_epoch,
                ),
            )

            conn.execute(
                """
                INSERT INTO audit_log (
                    approval_id, action_id, action_digest, from_state,
                    to_state, dispatch_epoch, worker_id, transition_timestamp_utc, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    approval_id,
                    row["action_id"],
                    row["action_digest"],
                    row["lifecycle_state"],
                    outcome_state,
                    dispatch_epoch,
                    worker_id,
                    eval_time,
                    f"Execution finished with {outcome_state}: {error_code or 'OK'}",
                ),
            )

    # --------------------------------------------------------------------------
    # 5. Crash Recovery & Lease Reaper
    # --------------------------------------------------------------------------

    def recover_expired_leases(self, now_utc: Optional[str] = None) -> list[str]:
        """Reaps expired worker leases and enforces safety recovery rules.

        Rules:
        1. If a worker crashed while in RESERVED (before dispatch):
           Zero network side effects occurred. Safe to reset to APPROVED so
           another worker can process it.
        2. If a worker crashed or timed out while in DISPATCHING:
           Network call may have executed downstream. To prevent duplicate executions
           on non-idempotent endpoints, transitions state to UNKNOWN.
           Automatic re-dispatch is prohibited.
        """
        eval_time = now_utc or _now_utc_str()
        recovered_ids: list[str] = []

        with self._get_connection() as conn:
            conn.execute("BEGIN EXCLUSIVE TRANSACTION;")

            # Query all active leases where lease_expires_at_utc < eval_time
            cur = conn.execute(
                """
                SELECT approval_id, lifecycle_state, dispatch_epoch, action_id, action_digest
                FROM approvals
                WHERE lifecycle_state IN ('RESERVED', 'DISPATCHING')
                  AND lease_expires_at_utc IS NOT NULL
                  AND lease_expires_at_utc < ?;
                """,
                (eval_time,),
            )
            expired_rows = cur.fetchall()

            for row in expired_rows:
                appr_id = row["approval_id"]
                st = row["lifecycle_state"]
                epoch = row["dispatch_epoch"]

                if st == "RESERVED":
                    # Safe to reset to APPROVED
                    conn.execute(
                        """
                        UPDATE approvals
                        SET lifecycle_state = 'APPROVED',
                            worker_id = NULL,
                            lease_expires_at_utc = NULL
                        WHERE approval_id = ?;
                        """,
                        (appr_id,),
                    )
                    conn.execute(
                        """
                        INSERT INTO audit_log (
                            approval_id, action_id, action_digest, from_state,
                            to_state, dispatch_epoch, worker_id, transition_timestamp_utc, reason
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            appr_id,
                            row["action_id"],
                            row["action_digest"],
                            "RESERVED",
                            "APPROVED",
                            epoch,
                            "REAPER",
                            eval_time,
                            "Lease expired before dispatch; reset to APPROVED",
                        ),
                    )
                    recovered_ids.append(f"{appr_id}:RESERVED->APPROVED")

                elif st == "DISPATCHING":
                    # Ambiguous! May have executed. Mark UNKNOWN.
                    conn.execute(
                        """
                        UPDATE approvals
                        SET lifecycle_state = 'UNKNOWN',
                            lease_expires_at_utc = NULL,
                            error_code = 'ERR_DISPATCH_TIMEOUT_UNKNOWN_OUTCOME',
                            error_message = 'Worker timed out during network dispatch; outcome unknown'
                        WHERE approval_id = ?;
                        """,
                        (appr_id,),
                    )
                    conn.execute(
                        """
                        INSERT INTO audit_log (
                            approval_id, action_id, action_digest, from_state,
                            to_state, dispatch_epoch, worker_id, transition_timestamp_utc, reason
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            appr_id,
                            row["action_id"],
                            row["action_digest"],
                            "DISPATCHING",
                            "UNKNOWN",
                            epoch,
                            "REAPER",
                            eval_time,
                            "In-flight timeout during dispatch; marked UNKNOWN",
                        ),
                    )
                    recovered_ids.append(f"{appr_id}:DISPATCHING->UNKNOWN")

        return recovered_ids

    def get_approval_outcome(self, approval_id: str) -> RedemptionOutcome:
        """Queries the recorded outcome of an approval for duplicate request handling."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM approvals WHERE approval_id = ?;", (approval_id,))
            row = cur.fetchone()
            if not row:
                raise ApprovalNotFoundError(f"Approval {approval_id!r} not found")

            res_json = json.loads(row["execution_result_json"]) if row["execution_result_json"] else None

            return RedemptionOutcome(
                approval_id=row["approval_id"],
                lifecycle_state=row["lifecycle_state"],
                dispatch_epoch=row["dispatch_epoch"],
                execution_result=res_json,
                error_code=row["error_code"],
                error_message=row["error_message"],
                action_id=row["action_id"],
                action_digest=row["action_digest"],
                decision_id=row["decision_id"],
            )

    def get_action(self, action_id: str) -> Optional[dict[str, Any]]:
        """Queries the recorded action by action_id."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM actions WHERE action_id = ?;", (action_id,))
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def get_decision_by_action_id(self, action_id: str) -> Optional[dict[str, Any]]:
        """Queries the recorded authorization decision by action_id."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT raw_record_json FROM authorization_decisions WHERE action_id = ? ORDER BY issued_at_utc DESC LIMIT 1;", (action_id,))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row["raw_record_json"])

