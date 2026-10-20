# Phase 5.3 Evidence Traceability Matrix

This matrix establishes the definitive scientific traceability mapping each major empirical, security, architectural, and performance claim in `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` to its underlying source-code implementation, unit regression test, raw benchmark JSON record, or external bibliographic source.

---

## 1. Traceability Table

| Claim ID | Claim Area | Statement in Corrected Manuscript | Evidence Category | Exact Evidence Source & Identifier | Verification Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TRC-01** | Empirical Benchmark Scope | 46 total benchmark scenarios: 31 consequential attacks and 15 legitimate tasks. | Benchmark Harness & Raw Data | `phase_4_8_2_corrective_report.md` §5.1, `scratch/corrective_benchmark_harness.py` | **VERIFIED** |
| **TRC-02** | Attack Blocking (System C) | 31 of 31 consequential attacks blocked (100.0% observed, Clopper-Pearson 95% CI [88.8%, 100.0%]). | Benchmark Harness & Raw Data | `phase_4_8_2_corrective_report.md` §5.1 (Cats 3–8), `phase_4_8_2_raw_benchmark_results.json` | **VERIFIED** |
| **TRC-03** | Attack Blocking (Baseline B) | 15 of 31 attacks blocked by policy engine without approval binding (48.4% observed, 95% CI [30.2%, 66.9%]). | Benchmark Harness & Raw Data | `phase_4_8_2_corrective_report.md` §5.1 (Cats 3–5 blocked; Cats 6–8 vulnerable) | **VERIFIED** |
| **TRC-04** | Attack Blocking (Baseline A) | 0 of 31 attacks blocked by direct unmediated execution (0.0% observed, 95% CI [0.0%, 11.2%]). | Benchmark Harness & Raw Data | `phase_4_8_2_corrective_report.md` §5.1 (All attacks executed directly) | **VERIFIED** |
| **TRC-05** | Legitimate Task Completion | 15 of 15 legitimate tasks dispatched without false denials (100.0% observed, 95% CI [78.2%, 100.0%]). | Benchmark Harness & Raw Data | `phase_4_8_2_corrective_report.md` §5.1 (Cats 1, 2, 9) | **VERIFIED** |
| **TRC-06** | Approval-Bypass Resistance | 11 approval-bypass and parameter-tampering attacks blocked (Cats 6 & 7: 6 tampering + 5 replay/revocation). | Benchmark Harness & Tests | `phase_4_8_2_corrective_report.md` §5.1, `tests/test_hardening_invariants.py` | **VERIFIED** |
| **TRC-07** | Dual-Boundary Downgrade | Separation of client schema failure (`CORR_CAT6_03A`) from runtime broker hierarchy rejection (`CORR_CAT6_03B`). | Implementation & Benchmark | `src/ai_firewall/broker/execution.py`, `phase_4_8_2_corrective_report.md` §2.2 | **VERIFIED** |
| **TRC-08** | Unit Regression Suite | 107 passing tests in 0.55–0.61 seconds with zero failures. | Test Suite (Pytest) | `tests/` (16 test files), `phase_4_12_final_evaluation_report.md` §2 | **VERIFIED** |
| **TRC-09** | Median Latency Optimization | Median latency reduced from 3.0153 ms to 0.5643 ms (-81.29%, -2.4510 ms). | Microbenchmark Raw JSON | `phase_4_11_raw_benchmark_results.json`, `phase_4_12_raw_verification_results.json` | **VERIFIED** |
| **TRC-10** | Tail Latency Optimization | P99 latency reduced from 24.0348 ms to 0.9679 ms (-95.97%, -23.0669 ms). | Microbenchmark Raw JSON | `phase_4_11_raw_benchmark_results.json`, nearest-rank index $S[99]$ ($n=100$) | **VERIFIED** |
| **TRC-11** | Throughput Scaling | Sequential single-core throughput increased from 397.7 to 1,716.4 ops/sec (+331.58%). | Microbenchmark Raw JSON | `phase_4_11_raw_benchmark_results.json` (200 ops batch interval) | **VERIFIED** |
| **TRC-12** | Concurrency Latency | Multithreaded (10 threads, 300 ops): 0.7075 ms median, 1,167.1 ops/sec. Multiprocess (4 procs, 200 ops): 0.6165 ms median, 1,265.9 ops/sec. | Concurrency Raw JSON | `phase_4_11_raw_benchmark_results.json`, `tests/test_connection_lifecycle_and_recovery.py` | **VERIFIED** |
| **TRC-13** | Quantile Indexing Convention | Quantile algorithm defined as nearest-rank: $P_k = S[\lfloor n \cdot k \rfloor]$ on zero-indexed array $S$ of size $n$. | Microbenchmark Script | `scratch/revalidate_benchmark_4_11.py`, `phase_4_11_raw_benchmark_results.json` | **VERIFIED** |
| **TRC-14** | Manager Connection Registry | Connections cached in `self._thread_conns: dict[int, sqlite3.Connection]` guarded by `self._conns_lock`. | Source Code | `src/ai_firewall/storage/database.py` lines 139–163 | **VERIFIED** |
| **TRC-15** | Cross-Thread Shutdown Safety | `check_same_thread=False` allows orchestrator close; `threading.get_ident()` enforces caller isolation. | Source Code & Unit Tests | `src/ai_firewall/storage/database.py`, `tests/test_connection_lifecycle_and_recovery.py` | **VERIFIED** |
| **TRC-16** | Fencing & Replay Defense | Monotonic `dispatch_epoch` counter inside `BEGIN EXCLUSIVE TRANSACTION`; unique nonces. | Source Code & Schema | `src/ai_firewall/storage/database.py`, `src/ai_firewall/storage/schema.sql` | **VERIFIED** |
| **TRC-17** | Crash Recovery to UNKNOWN | In-flight crash in `DISPATCHING` transitions to `UNKNOWN`; automatic retry blocked. | Source Code & Unit Tests | `src/ai_firewall/storage/database.py` lines 841–874, 8 recovery scenarios | **VERIFIED** |
| **TRC-18** | Downstream Wire Boundary | Gateway fencing does not equal end-to-end exactly-once without downstream idempotency keys. | Theoretical / Systems Limit | Section 7.2 of corrected manuscript, formal boundary disclosure | **VERIFIED** |
| **TRC-19** | MCP Subprocess Transport | Mediates real OS child-process stdio pipes with JSON-RPC 2.0 framing. | Unit Tests & Subprocess | `scratch/mcp_server_subprocess.py`, `tests/test_mcp_subprocess_integration.py` | **VERIFIED** |
| **TRC-20** | LangGraph Simulation | Simulated interrupt and state reload; official packages not installed in system. | Unit Tests & Disclosure | `tests/test_langgraph_checkpoint_integration.py`, Section 8 Limitation 2 | **VERIFIED** |
| **TRC-21** | Literature Verification | CaMeL (arXiv:2503.18813), AgentDojo (NeurIPS 2024), DataSentinel (arXiv:2504.11358), IsolateGPT (NDSS 2025), Progent (arXiv:2504.11703). | Bibliographic Records & PDFs | `phase_5_0_literature_verification.md`, local PDFs, arXiv metadata | **VERIFIED** |
| **TRC-22** | Progent PDF Disclosure | Local `Progent.pdf` contains CaMeL text + unindexed trailer; cited against verified external arXiv. | Literature Audit | `phase_5_0_literature_verification.md`, binary PDF analysis | **VERIFIED** |

---

## 2. Summary by Evidence Category

- **Source Code Verification:** 100% of architectural claims (`database.py`, `execution.py`, `engine.py`, `envelope.py`) verified against implementation.
- **Unit & Concurrency Tests:** 100% of invariant and recovery claims verified across 107 unit tests.
- **Microbenchmarks & Concurrency:** 100% of reported latency, throughput, and quantile numbers verified against raw JSON vectors.
- **Literature & Citations:** 100% of external bibliographic entries verified against authoritative metadata records.

