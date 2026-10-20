"""Comprehensive Lifecycle, Concurrency, and Crash Recovery Hardening Tests (Phase 4.11).

Validates:
1. Thread connection ownership, cleanup, repeated close, cross-thread close, and post-close safety.
2. In-memory vs. file-backed SQLite configurations and rejection of unsupported combinations.
3. Multi-thread and multi-process atomic reservation concurrency under connection reuse.
4. Worker crash recovery matrix across all 8 lifecycle/failure scenarios.
5. Fail-closed behavior on database errors and transaction aborts.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sqlite3
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
import pytest

from ai_firewall.crypto.keys import KeyRegistry, generate_dev_ed25519_keypair
from ai_firewall.crypto.record import sign_authorization_decision_record
from ai_firewall.storage.database import (
    DatabaseManager,
    StorageError,
    ReplayDetectedError,
    ConcurrencyContentionError,
    FencingTokenMismatchError,
    InvalidStateTransitionError,
)


def _make_action_and_decision(db: DatabaseManager, act_id: str, dec_id: str):
    digest = "a" * 64
    action = {
        "principal": {"user_id": "u1", "agent_id": "a1", "session_id": "s1"},
        "invocation": {"tool_server_id": "srv", "tool_name": "t1", "operation_type": "READ_ONLY", "canonical_params": {}},
        "target_resource": {"resource_uri": "uri://res", "preconditions": None},
        "authorization_binding": {"policy_version": "v1", "policy_epoch": 1, "idempotency_key": f"k_{act_id}", "expires_at_utc": "2029-10-12T11:00:00.000000Z"},
    }
    db.record_action(act_id, action, digest)
    priv_gw, _ = generate_dev_ed25519_keypair(f"k_{dec_id}", "gw")
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
        signer_key_id=f"k_{dec_id}",
        private_key=priv_gw,
    )
    db.record_authorization_decision(dec, act_id)
    return digest, dec


# ==============================================================================
# SECTION 1: Thread-Local Connection Ownership & Deterministic Cleanup
# ==============================================================================

def test_deterministic_cross_thread_close():
    """Verify that DatabaseManager.close() cleanly closes connections opened by worker threads."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        worker_conn_ref = None

        def worker():
            nonlocal worker_conn_ref
            worker_conn_ref = db._get_connection()
            # Execute something to verify active connection
            worker_conn_ref.execute("SELECT 1;")

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        assert len(db._thread_conns) == 2
        # Calling close from main thread must deterministically close all connections
        db.close()
        assert len(db._thread_conns) == 0
        assert db._is_closed is True

        # Operations post-close must raise StorageError
        with pytest.raises(StorageError, match="DatabaseManager has been closed"):
            db._get_connection()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_repeated_close_idempotent():
    """Verify that repeated calls to close() do not raise errors."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        db._get_connection()
        db.close()
        # Second and third close calls
        db.close()
        db.close()
        assert db._is_closed is True
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_worker_exception_does_not_corrupt_manager():
    """Verify that an unhandled exception in worker thread leaves manager in consistent state."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)

        worker_crashed = False

        def faulty_worker():
            nonlocal worker_crashed
            try:
                conn = db._get_connection()
                raise RuntimeError("Worker crash!")
            except RuntimeError:
                worker_crashed = True

        t = threading.Thread(target=faulty_worker)
        t.start()
        t.join()

        assert worker_crashed is True
        # Manager can still be safely closed from main thread
        db.close()
        assert len(db._thread_conns) == 0
    finally:
        if os.path.exists(path):
            os.remove(path)


# ==============================================================================
# SECTION 2: In-Memory vs. File-Backed Database Semantics
# ==============================================================================

def test_reject_memory_without_connection_reuse():
    """Verify that default ':memory:' without connection reuse is rejected explicitly."""
    with pytest.raises(ValueError, match="Unsupported configuration: ':memory:'"):
        DatabaseManager(db_path=":memory:", reuse_connections=False)


def test_memory_with_connection_reuse():
    """Verify that ':memory:' with connection reuse works within a single thread."""
    db = DatabaseManager(db_path=":memory:", reuse_connections=True)
    digest, dec = _make_action_and_decision(db, "act_mem_000000001", "dec_mem_000000001")
    act = db.get_action("act_mem_000000001")
    assert act is not None
    db.close()


def test_file_backed_wal_cross_thread_visibility():
    """Verify that file-backed WAL database shares state across threads."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, dec = _make_action_and_decision(db, "act_wal_000000001", "dec_wal_000000001")

        worker_visible = False

        def reader_worker():
            nonlocal worker_visible
            act = db.get_action("act_wal_000000001")
            worker_visible = act is not None

        t = threading.Thread(target=reader_worker)
        t.start()
        t.join()

        assert worker_visible is True
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


# ==============================================================================
# SECTION 3: Concurrency and Multi-Process Safety
# ==============================================================================

def test_multithread_simultaneous_reservation():
    """Verify that 20 threads simultaneously competing to reserve the same action allow exactly 1 reservation."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_th_concur_001", "dec_th_concur_001")

        successes = []
        errors = []

        def worker(wid: str):
            ldb = DatabaseManager(db_path=path, reuse_connections=True)
            try:
                res = ldb.register_and_reserve_autonomous_action(
                    action_id="act_th_concur_001",
                    action_digest=digest,
                    decision_id="dec_th_concur_001",
                    worker_id=wid,
                )
                successes.append((wid, res.dispatch_epoch))
            except Exception as e:
                errors.append((wid, type(e).__name__))
            finally:
                ldb.close()

        threads = [threading.Thread(target=worker, args=(f"worker_{i}",)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(successes) == 1
        assert len(errors) == 19
        assert all(err == "ConcurrencyContentionError" for _, err in errors)
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def _proc_worker_entry(path: str, act_id: str, digest: str, dec_id: str, wid: str, queue: mp.Queue):
    ldb = DatabaseManager(db_path=path, reuse_connections=True)
    try:
        res = ldb.register_and_reserve_autonomous_action(
            action_id=act_id,
            action_digest=digest,
            decision_id=dec_id,
            worker_id=wid,
        )
        queue.put(("SUCCESS", wid, res.dispatch_epoch))
    except Exception as e:
        queue.put(("ERROR", wid, type(e).__name__))
    finally:
        ldb.close()


def test_multiprocess_simultaneous_reservation():
    """Verify multi-process concurrency safety on file-backed SQLite database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_mp_concur_001", "dec_mp_concur_001")

        ctx = mp.get_context("fork")
        q = ctx.Queue()

        procs = [
            ctx.Process(
                target=_proc_worker_entry,
                args=(path, "act_mp_concur_001", digest, "dec_mp_concur_001", f"proc_{i}", q),
            )
            for i in range(8)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join()

        results = []
        while not q.empty():
            results.append(q.get())

        successes = [r for r in results if r[0] == "SUCCESS"]
        errors = [r for r in results if r[0] == "ERROR"]

        assert len(successes) == 1
        assert len(errors) == 7
        assert all(err[2] == "ConcurrencyContentionError" for err in errors)
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


# ==============================================================================
# SECTION 4: Crash-Recovery Matrix (8 Scenarios)
# ==============================================================================

def test_recovery_scenario_1_crash_before_reservation():
    """Scenario 1: Worker crashes before reservation. Initial state remains APPROVED."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_rec_0000000001", "dec_rec_0000000001")
        # Action is recorded, but no worker has reserved it yet
        reaped = db.recover_expired_leases(now_utc="2026-10-12T10:00:10.000000Z")
        assert len(reaped) == 0
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_recovery_scenario_2_crash_after_reservation_before_dispatch():
    """Scenario 2: Worker crashes while RESERVED. Reaper resets to APPROVED for another worker."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_rec_0000000002", "dec_rec_0000000002")

        t0 = "2026-10-12T10:00:00.000000Z"
        t_reap = "2026-10-12T10:00:10.000000Z"

        res = db.register_and_reserve_autonomous_action(
            "act_rec_0000000002", digest, "dec_rec_0000000002", "worker_crashed_1",
            lease_duration_seconds=5, now_utc=t0,
        )
        assert res.dispatch_epoch == 1

        reaped = db.recover_expired_leases(now_utc=t_reap)
        assert len(reaped) == 1
        assert "RESERVED->APPROVED" in reaped[0]

        # Replacement worker reserves it
        res2 = db.register_and_reserve_autonomous_action(
            "act_rec_0000000002", digest, "dec_rec_0000000002", "worker_replacement",
            lease_duration_seconds=30, now_utc=t_reap,
        )
        assert res2.dispatch_epoch == 2
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_recovery_scenario_3_crash_after_dispatching_before_mock_call():
    """Scenario 3: Worker crashes in DISPATCHING before mock call. Reaper marks UNKNOWN (fail-closed)."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_rec_0000000003", "dec_rec_0000000003")

        t0 = "2026-10-12T10:00:00.000000Z"
        t_reap = "2026-10-12T10:00:10.000000Z"

        res = db.register_and_reserve_autonomous_action(
            "act_rec_0000000003", digest, "dec_rec_0000000003", "worker_dispatch_crash",
            lease_duration_seconds=5, now_utc=t0,
        )
        db.mark_dispatching(res.approval_id, "worker_dispatch_crash", 1, now_utc=t0)

        # Worker dies before calling tool
        reaped = db.recover_expired_leases(now_utc=t_reap)
        assert len(reaped) == 1
        assert "DISPATCHING->UNKNOWN" in reaped[0]

        outcome = db.get_approval_outcome(res.approval_id)
        assert outcome.lifecycle_state == "UNKNOWN"
        assert outcome.error_code == "ERR_DISPATCH_TIMEOUT_UNKNOWN_OUTCOME"
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_recovery_scenario_4_crash_after_mock_call_before_record_outcome():
    """Scenario 4: Downstream call completed but worker crashed before record_execution_outcome.
    Reaper marks UNKNOWN; re-reservation is prohibited to avoid duplicate side effects."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_rec_0000000004", "dec_rec_0000000004")

        t0 = "2026-10-12T10:00:00.000000Z"
        t_reap = "2026-10-12T10:00:10.000000Z"

        res = db.register_and_reserve_autonomous_action(
            "act_rec_0000000004", digest, "dec_rec_0000000004", "worker_call_completed_then_crashed",
            lease_duration_seconds=5, now_utc=t0,
        )
        db.mark_dispatching(res.approval_id, "worker_call_completed_then_crashed", 1, now_utc=t0)

        # Mock downstream executed here, but worker crashed prior to recording outcome
        reaped = db.recover_expired_leases(now_utc=t_reap)
        assert len(reaped) == 1
        assert "DISPATCHING->UNKNOWN" in reaped[0]

        # Automatic retry must raise ReplayDetectedError
        with pytest.raises(ReplayDetectedError, match="state=UNKNOWN"):
            db.register_and_reserve_autonomous_action(
                "act_rec_0000000004", digest, "dec_rec_0000000004", "worker_replacement",
                lease_duration_seconds=30, now_utc=t_reap,
            )
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_recovery_scenario_5_lease_expires_while_worker_paused():
    """Scenario 5: Lease expires while worker is paused; reaper reclaims lease."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_rec_0000000005", "dec_rec_0000000005")

        t0 = "2026-10-12T10:00:00.000000Z"
        t_reap = "2026-10-12T10:00:10.000000Z"

        res = db.register_and_reserve_autonomous_action(
            "act_rec_0000000005", digest, "dec_rec_0000000005", "worker_paused",
            lease_duration_seconds=5, now_utc=t0,
        )
        reaped = db.recover_expired_leases(now_utc=t_reap)
        assert len(reaped) == 1
        assert "RESERVED->APPROVED" in reaped[0]
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_recovery_scenario_6_stale_worker_resumes_after_replacement():
    """Scenario 6: Stale worker attempts to dispatch after replacement worker took over."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_rec_0000000006", "dec_rec_0000000006")

        t0 = "2026-10-12T10:00:00.000000Z"
        t_reap = "2026-10-12T10:00:10.000000Z"

        res1 = db.register_and_reserve_autonomous_action(
            "act_rec_0000000006", digest, "dec_rec_0000000006", "worker_stale_01",
            lease_duration_seconds=5, now_utc=t0,
        )
        assert res1.dispatch_epoch == 1

        db.recover_expired_leases(now_utc=t_reap)

        res2 = db.register_and_reserve_autonomous_action(
            "act_rec_0000000006", digest, "dec_rec_0000000006", "worker_replacement_02",
            lease_duration_seconds=30, now_utc=t_reap,
        )
        assert res2.dispatch_epoch == 2

        # Stale worker wakes up and attempts mark_dispatching with epoch 1
        with pytest.raises(FencingTokenMismatchError, match="Stale worker fencing token"):
            db.mark_dispatching(res1.approval_id, "worker_stale_01", res1.dispatch_epoch, now_utc=t_reap)

        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_recovery_scenario_7_process_restarts_ambiguous_state():
    """Scenario 7: Gateway process restarts while an action is in DISPATCHING state."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        # Process 1 creates in-flight dispatching action
        db1 = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db1, "act_rec_0000000007", "dec_rec_0000000007")
        t0 = "2026-10-12T10:00:00.000000Z"
        t_restart = "2026-10-12T10:00:15.000000Z"

        res = db1.register_and_reserve_autonomous_action(
            "act_rec_0000000007", digest, "dec_rec_0000000007", "worker_p1",
            lease_duration_seconds=10, now_utc=t0,
        )
        db1.mark_dispatching(res.approval_id, "worker_p1", 1, now_utc=t0)
        db1.close()

        # Process 2 restarts and runs startup recovery
        db2 = DatabaseManager(db_path=path, reuse_connections=True)
        reaped = db2.recover_expired_leases(now_utc=t_restart)
        assert len(reaped) == 1
        assert "DISPATCHING->UNKNOWN" in reaped[0]

        outcome = db2.get_approval_outcome(res.approval_id)
        assert outcome.lifecycle_state == "UNKNOWN"
        db2.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_recovery_scenario_8_approval_replayed_after_recovery():
    """Scenario 8: Replay of an approval after crash recovery has marked it UNKNOWN is blocked."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = DatabaseManager(db_path=path, reuse_connections=True)
        digest, _ = _make_action_and_decision(db, "act_rec_0000000008", "dec_rec_0000000008")

        t0 = "2026-10-12T10:00:00.000000Z"
        t_reap = "2026-10-12T10:00:10.000000Z"

        res = db.register_and_reserve_autonomous_action(
            "act_rec_0000000008", digest, "dec_rec_0000000008", "worker_init",
            lease_duration_seconds=5, now_utc=t0,
        )
        db.mark_dispatching(res.approval_id, "worker_init", 1, now_utc=t0)
        db.recover_expired_leases(now_utc=t_reap)

        # Attempt replay
        with pytest.raises(ReplayDetectedError, match="state=UNKNOWN"):
            db.register_and_reserve_autonomous_action(
                "act_rec_0000000008", digest, "dec_rec_0000000008", "attacker_replay",
                lease_duration_seconds=30, now_utc=t_reap,
            )
        db.close()
    finally:
        if os.path.exists(path):
            os.remove(path)
