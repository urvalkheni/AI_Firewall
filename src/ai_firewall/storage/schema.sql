-- AI Firewall Persistent Lifecycle Schema (SQLite)
-- Enforces:
-- 1. Uniqueness of action_id, approval_id, and single_use_nonce.
-- 2. Foreign-key relationships between actions, decisions, and approvals.
-- 3. Fencing tokens (dispatch_epoch) and worker lease tracking.
-- 4. Audit trail of all state transitions and execution outcomes.

PRAGMA foreign_keys = ON;

-- 1. Proposed Actions
CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    action_digest TEXT NOT NULL,
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tool_server_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    resource_uri TEXT NOT NULL,
    preconditions_json TEXT,
    policy_version TEXT NOT NULL,
    policy_epoch INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    raw_normalized_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_actions_digest ON actions(action_digest);
CREATE INDEX IF NOT EXISTS idx_actions_session ON actions(session_id);

-- 2. Authorization Decision Records (Gateway-Signed)
CREATE TABLE IF NOT EXISTS authorization_decisions (
    decision_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK(verdict IN ('ALLOW', 'DENY', 'APPROVAL_REQUIRED', 'RETRY_REQUIRED')),
    policy_version TEXT NOT NULL,
    policy_epoch INTEGER NOT NULL,
    risk_score REAL NOT NULL,
    risk_tier TEXT NOT NULL CHECK(risk_tier IN ('LOW_RISK', 'MODERATE_RISK', 'HIGH_CONSEQUENCE')),
    provenance_taint TEXT NOT NULL CHECK(provenance_taint IN ('CLEAN', 'SUSPICIOUS_EXTERNAL', 'UNTRUSTED_INDIRECT_INPUT')),
    required_auth_level TEXT NOT NULL CHECK(required_auth_level IN ('NONE', 'STANDARD_PASSWORD', 'MFA_TOTP', 'MFA_HARDWARE_TOKEN')),
    signer_key_id TEXT NOT NULL,
    issued_at_utc TEXT NOT NULL,
    raw_record_json TEXT NOT NULL,
    FOREIGN KEY(action_id) REFERENCES actions(action_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_decisions_action ON authorization_decisions(action_id);
CREATE INDEX IF NOT EXISTS idx_decisions_digest ON authorization_decisions(action_digest);

-- 3. Persistent Approval Lifecycle
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    single_use_nonce TEXT NOT NULL UNIQUE,
    approval_status TEXT NOT NULL CHECK(approval_status IN ('APPROVED', 'REJECTED')),
    auth_level TEXT NOT NULL,
    reviewer_user_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_epoch INTEGER NOT NULL,
    issued_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    
    -- Lifecycle state machine
    -- Terminal states: SUCCEEDED, FAILED, REJECTED, EXPIRED, CANCELLED
    -- Transient states: PROPOSED, PENDING_APPROVAL, APPROVED, RESERVED, DISPATCHING
    -- Ambiguous / Operator state: UNKNOWN
    lifecycle_state TEXT NOT NULL CHECK(lifecycle_state IN (
        'PROPOSED',
        'PENDING_APPROVAL',
        'APPROVED',
        'RESERVED',
        'DISPATCHING',
        'SUCCEEDED',
        'FAILED',
        'UNKNOWN',
        'REJECTED',
        'EXPIRED',
        'CANCELLED'
    )),
    
    -- Worker lease and fencing token
    worker_id TEXT,
    dispatch_epoch INTEGER NOT NULL DEFAULT 0,
    lease_expires_at_utc TEXT,
    
    -- Execution outcome metadata
    consumed_at_utc TEXT,
    execution_result_json TEXT,
    error_code TEXT,
    error_message TEXT,
    
    -- Raw signed envelope
    raw_envelope_json TEXT NOT NULL,
    
    FOREIGN KEY(action_id) REFERENCES actions(action_id) ON DELETE RESTRICT,
    FOREIGN KEY(decision_id) REFERENCES authorization_decisions(decision_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_approvals_action ON approvals(action_id);
CREATE INDEX IF NOT EXISTS idx_approvals_digest ON approvals(action_digest);
CREATE INDEX IF NOT EXISTS idx_approvals_nonce ON approvals(single_use_nonce);
CREATE INDEX IF NOT EXISTS idx_approvals_state ON approvals(lifecycle_state);

-- 4. Audit Trail (Immutable log of all transitions)
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    dispatch_epoch INTEGER NOT NULL,
    worker_id TEXT,
    transition_timestamp_utc TEXT NOT NULL,
    reason TEXT,
    FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_audit_approval ON audit_log(approval_id);

