# Phase 5.0 Claim-Evidence Matrix

This document provides a line-item trace from every major scientific and empirical claim in the research paper to its supporting implementation file, unit test, raw benchmark JSON record, or literature reference.

---

## 1. Security & Protection Claims

| Claim ID | Paper Claim Statement | Supporting Evidence (Test / File / Raw Data) | Tested Population & Scope | Documented Boundary / Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Mandatory policy evaluation blocks unauthorized tool proposals before dispatch. | `tests/test_policy_engine.py`<br>`tests/test_broker.py::test_denied_action_zero_dispatch` | 15 unit tests covering explicit `DENY`, unlisted tools, and taint propagation. | Evaluated against declarative rules; not a generic prompt-injection filter. |
| **SEC-02** | Cryptographic envelope binding prevents parameter tampering between approval and execution. | `tests/test_hardening_invariants.py::test_action_digest_mismatch_rejected`<br>`tests/test_crypto_envelope.py` | 18 tests evaluating altered arguments, tool names, and resource URIs. | Requires human reviewer to inspect canonicalized parameters before signing. |
| **SEC-03** | Stale approval replay is prevented across concurrent workers. | `tests/test_hardening_deduplication.py`<br>`tests/test_storage_lifecycle.py` | 5 deduplication and replay tests; 50-worker concurrent redemption test. | Prevents duplicate reservation at the database layer; see NET-01 for wire drops. |
| **SEC-04** | Policy epoch increment invalidates previously issued approval envelopes. | `tests/test_hardening_invariants.py::test_stale_policy_epoch_rejected` | Tests evaluating epoch mismatches between envelope claims and policy state. | Requires gateway coordinator to maintain monotonic policy epoch counter. |
| **SEC-05** | Revoked reviewer or gateway signing keys are immediately rejected fail-closed. | `tests/test_hardening_invariants.py::test_revoked_key_blocked` | KeyRegistry revocation tests with Ed25519 signatures. | Key revocation list must be distributed or accessible to the gateway broker. |
| **SEC-06** | Preconditions on target resource URIs prevent TOCTOU exploitation prior to dispatch. | `tests/test_broker_preconditions.py` | 5 precondition evaluation tests inspecting state hash and resource tags. | Precondition check depends on resource provider reporting accurate state. |
| **SEC-07** | Gateway fails closed to `UNKNOWN` state upon in-flight network dispatch timeout. | `tests/test_connection_lifecycle_and_recovery.py::test_recovery_scenario_3_crash_after_dispatching_before_mock_call` | 8-scenario crash-recovery matrix; lease expiration reaper. | Prevents automated re-dispatch; requires manual reconciliation for ambiguous mutations. |

---

## 2. Integration & Cross-Adapter Claims

| Claim ID | Paper Claim Statement | Supporting Evidence (Test / File / Raw Data) | Tested Population & Scope | Documented Boundary / Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **INT-01** | Tool calls from MCP and LangChain adapters produce identical action identities and policy outcomes. | `tests/test_cross_adapter.py`<br>`src/ai_firewall/adapters/` | 5 paired cross-adapter test suites across read, write, and parameter edge cases. | Tested on adapter schemas; official SDK runtimes were not installed in the test environment. |
| **INT-02** | Gateway mediates real OS child-process stdio communications using MCP JSON-RPC 2.0 protocol. | `scratch/mcp_server_subprocess.py`<br>`tests/test_mcp_subprocess_integration.py` | 9 real subprocess tests executing over OS pipes with JSON-RPC framing. | Evaluated over stdio transport; remote HTTP/SSE transports were not tested. |
| **INT-03** | Gateway supports state checkpointing and interrupt/resume cycles in agent graphs. | `tests/test_langgraph_checkpoint_integration.py` | 7 simulated LangGraph checkpoint tests across process restarts. | Labeled as simulated integration due to the absence of the official `langgraph` package. |

---

## 3. Performance & Optimization Claims

| Claim ID | Paper Claim Statement | Supporting Evidence (Test / File / Raw Data) | Tested Population & Scope | Documented Boundary / Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **PERF-01** | Thread-local connection reuse reduces median authorization latency by 81.29% (from 3.0153 ms to 0.5643 ms). | `phase_4_11_raw_benchmark_results.json`<br>`phase_4_12_raw_verification_results.json` | 100 timed trials, 20 warmup, Autonomous ALLOW pipeline on Linux x86_64. | Measured with SQLite WAL mode; latency varies with disk sync speed and storage backend. |
| **PERF-02** | P99 tail latency is reduced by 95.97% (from 24.0348 ms to 0.9679 ms). | `phase_4_11_raw_benchmark_results.json` (nearest-rank $P_{99}$) | 100 timed trials, nearest-rank quantile ($n=100$). | Tail latency spikes under heavy concurrent write lock contention. |
| **PERF-03** | Batch throughput increases by +331.58% (from 397.7 to 1716.4 ops/sec). | `phase_4_11_raw_benchmark_results.json` | 200 operations batch execution interval. | Throughput measured sequentially on a single core; multi-core scaling limited by SQLite lock serialization. |
| **PERF-04** | Concurrent multithreaded (10 threads) and multiprocess (4 procs) throughput reaches 1167.1 and 1265.9 ops/sec. | `phase_4_11_raw_benchmark_results.json` | 300 ops multithreaded; 200 ops multiprocess. | P95 and P99 latency increase under concurrency due to `BEGIN EXCLUSIVE TRANSACTION` serialization. |

---

## 4. Architectural & Safety Boundaries

| Boundary ID | Architecture Boundary | Theoretical Guarantee | Practical Enforcement Limit |
| :--- | :--- | :--- | :--- |
| **NET-01** | Downstream Wire Dispatch Boundary | Fencing counter (`dispatch_epoch`) prevents stale database updates. | Gateway cannot recall packets sent over the wire; downstream tools must support idempotency keys for true exactly-once execution. |
| **ENV-01** | Third-Party Package Environment | Protocol framing conforms to JSON-RPC 2.0 specifications. | Official `mcp` and `langgraph` pip packages are missing from system Python; tested via child-process stdio pipes and in-process simulations. |
| **MEM-01** | In-Memory Database Isolation | `:memory:` SQLite connections are isolated per thread. | Non-reused `:memory:` databases lose schema immediately; explicit `ValueError` blocks unsupported configuration. |

