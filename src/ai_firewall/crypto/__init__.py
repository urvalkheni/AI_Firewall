"""Crypto subpackage initialization for AI Firewall.

Exports Key Registry, Approval Envelope, and Authorization Decision Record implementations.
"""

from ai_firewall.crypto.keys import (
    KeyRegistry,
    KeyRecord,
    KeyRegistryError,
    KeyNotFoundError,
    KeyRevokedError,
    KeyExpiredError,
    KeyOwnershipError,
    generate_dev_ed25519_keypair,
)
from ai_firewall.crypto.envelope import (
    ApprovalEnvelopeError,
    EnvelopeSchemaError,
    EnvelopeVerificationError,
    ExecutionNotAuthorizedError,
    construct_signing_payload,
    sign_approval_envelope,
    verify_approval_envelope,
)
from ai_firewall.crypto.record import (
    DecisionRecordError,
    DecisionRecordSchemaError,
    DecisionRecordVerificationError,
    construct_record_signing_payload,
    sign_authorization_decision_record,
    verify_authorization_decision_record,
)

__all__ = [
    "KeyRegistry",
    "KeyRecord",
    "KeyRegistryError",
    "KeyNotFoundError",
    "KeyRevokedError",
    "KeyExpiredError",
    "KeyOwnershipError",
    "generate_dev_ed25519_keypair",
    "ApprovalEnvelopeError",
    "EnvelopeSchemaError",
    "EnvelopeVerificationError",
    "ExecutionNotAuthorizedError",
    "construct_signing_payload",
    "sign_approval_envelope",
    "verify_approval_envelope",
    "DecisionRecordError",
    "DecisionRecordSchemaError",
    "DecisionRecordVerificationError",
    "construct_record_signing_payload",
    "sign_authorization_decision_record",
    "verify_authorization_decision_record",
]

