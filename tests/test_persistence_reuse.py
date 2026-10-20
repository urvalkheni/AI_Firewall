"""Tests for Safe SQLite Connection Reuse and Concurrency Boundaries."""

from __future__ import annotations

import os
import tempfile
import threading
from typing import Any

import pytest

from ai_firewall.storage.database import (
    DatabaseManager,
    ReplayDetectedError,
)


def test_connection_reuse_same_thread():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        conn1 = db._get_connection()
        conn2 = db._get_connection()
        # In the same thread, connection object identity is preserved
        assert conn1 is conn2
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_connection_isolation_across_threads():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        main_conn = db._get_connection()

        worker_conns = []

        def worker():
            w_conn = db._get_connection()
            worker_conns.append(w_conn)

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        assert len(worker_conns) == 1
        # Worker thread must NOT share the main thread's connection!
        assert worker_conns[0] is not main_conn
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_lifecycle_and_replay_protection_under_reuse():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)

        action = {
            "principal": {"user_id": "u1", "agent_id": "a1", "session_id": "s1"},
            "invocation": {"tool_server_id": "srv", "tool_name": "t1", "operation_type": "READ_ONLY", "canonical_params": {}},
            "target_resource": {"resource_uri": "uri://res", "preconditions": None},
            "authorization_binding": {"policy_version": "v1", "policy_epoch": 1, "idempotency_key": "k1", "expires_at_utc": "2029-10-12T11:00:00.000000Z"},
        }
        digest = "a" * 64
        db.record_action("act_01", action, digest)

        # Record authorization decision record first (required by foreign key)
        from ai_firewall.crypto.keys import generate_dev_ed25519_keypair
        from ai_firewall.crypto.record import sign_authorization_decision_record
        priv_gw, _ = generate_dev_ed25519_keypair("k_gw", "gw")
        dec_id = "dec_0000000000000001"
        dec = sign_authorization_decision_record(
            decision_id=dec_id,
            action_digest=digest,
            verdict="ALLOW",
            policy_version="v1",
            policy_epoch=1,
            issued_at_utc="2026-10-12T10:00:00.000000Z",
            score=5.0,
            risk_tier="LOW_RISK",
            provenance_taint="CLEAN",
            required_auth_level="NONE",
            signer_key_id="k_gw",
            private_key=priv_gw,
        )
        db.record_authorization_decision(dec, "act_01")

        # Reserve autonomous action
        res = db.register_and_reserve_autonomous_action(
            action_id="act_01",
            action_digest=digest,
            decision_id=dec_id,
            worker_id="w_01",
        )
        assert res.dispatch_epoch == 1

        # Mark dispatching and outcome
        approval_id = f"auto_{dec_id}"
        db.mark_dispatching(approval_id, "w_01", 1)
        db.record_execution_outcome(
            approval_id=approval_id,
            worker_id="w_01",
            dispatch_epoch=1,
            outcome_state="SUCCEEDED",
            execution_result={"ok": True},
        )

        # Attempting to re-reserve must raise ReplayDetectedError
        with pytest.raises(ReplayDetectedError):
            db.register_and_reserve_autonomous_action(
                action_id="act_01",
                action_digest=digest,
                decision_id=dec_id,
                worker_id="w_02",
            )

        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)
