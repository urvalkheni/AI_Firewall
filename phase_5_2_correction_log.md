# Phase 5.2 Manuscript Correction Log

This log documents the disposition of each finding and claim audited in Phase 5.1, detailing the original passage, the exact correction applied in `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md`, the scientific rationale, and supporting evidence.

---

### Finding 1 (CLM-01 & Finding 1 from Phase 5.1): Conflation of Regression Suite (107 Tests) with Empirical Attack Benchmark (46 Scenarios)
- **Claim ID:** CLM-01
- **Original Passage (Draft v1.0):**
  - Abstract: *"We evaluate AI Firewall through an empirical evaluation across 107 regression tests and controlled concurrency benchmarks. The gateway demonstrates 100% defense against parameter tampering..."*
  - Section 6.1, Figure 5: *"SECURITY EVALUATION SUMMARY... across 107 test cases... Unauthorized Tool Proposal (Policy Deny) 100% Blocked (0/22)..."*
- **Correction Applied in Phase 5.2:**
  - In Abstract: Replaced with *"We evaluate AI Firewall through an empirical evaluation across a formal 46-scenario security benchmark (31 consequential attacks and 15 legitimate tasks), supported by a comprehensive 107-test regression suite. In the evaluated benchmark suite, AI Firewall successfully blocked 31 of 31 consequential attacks (100.0% observed, Clopper-Pearson 95% exact binomial confidence interval [88.8%, 100.0%]) while executing 15 of 15 legitimate tasks without false denials (100.0% observed utility, 95% CI [78.2%, 100.0%])."*
  - In Section 6: Split into **Section 6.1: Empirical Security Benchmark Evaluation (46 Scenarios)** and **Section 6.2: Regression and Invariant Test Suite (107 Tests)**.
  - Figure 5 replaced with the formal 46-scenario comparative table from Phase 4.8.2, delineating Baseline A, Baseline B, and System C across Categories 1–9.
- **Reason:** 107 tests constitute the software unit/regression suite, whereas the empirical benchmark established in Phase 4.8.2 comprises 46 scenarios (31 attacks + 15 benign tasks). Presenting unit tests as empirical attack trials was inaccurate.
- **Supporting Evidence:** `phase_4_8_2_corrective_report.md` §5, `phase_4_12_final_evaluation_report.md` §2.
- **Status:** **RESOLVED**

---

### Finding 2 (CLM-06 & Finding 2 from Phase 5.1): Imprecise Architecture Description of Connection Reuse
- **Claim ID:** CLM-06
- **Original Passage (Draft v1.0):**
  - Section 5.2: *"Thread-Local Connection Reuse... we designed an explicit thread-to-connection mapping registry in DatabaseManager... Connections are created on demand per calling thread with check_same_thread=False..."*
- **Correction Applied in Phase 5.2:**
  - Renamed Section 5.2 heading and prose to **"Manager-Owned Thread Connection Registry"**.
  - Documented exact structure: `self._thread_conns: dict[int, sqlite3.Connection]` guarded by `self._conns_lock`.
  - Clarified dual-safety model: `check_same_thread=False` allows the orchestrator thread to safely invoke `.close()` across worker connections during shutdown without `ProgrammingError`, while query execution remains strictly isolated by keying on `threading.get_ident()`.
  - Described the `_is_closed = True` sentinel that raises `StorageError` on subsequent requests.
- **Reason:** In Python, "thread-local" implies `threading.local()`, which was specifically audited and removed in Phase 4.11 because it prevented cross-thread cleanup. The actual implementation is a manager-owned dictionary registry.
- **Supporting Evidence:** `src/ai_firewall/storage/database.py` lines 139–163, `tests/test_connection_lifecycle_and_recovery.py`.
- **Status:** **RESOLVED**

---

### Finding 3 (CLM-13 & Finding 3 from Phase 5.1): Unqualified Statistical Generalizability
- **Claim ID:** CLM-13
- **Original Passage (Draft v1.0):**
  - Section 6.1: *"The gateway demonstrates 100% defense against parameter tampering, approval substitution, replay, and epoch invalidation... zero unauthorized or altered tool invocations reached the downstream mock execution handler."*
- **Correction Applied in Phase 5.2:**
  - Added exact Clopper-Pearson 95% confidence intervals to all benchmark results:
    - Attacks blocked: 31 / 31 (100.0% observed, 95% CI [88.8%, 100.0%]).
    - Baseline B attacks blocked: 15 / 31 (48.4% observed, 95% CI [30.2%, 66.9%]).
    - Baseline A attacks blocked: 0 / 31 (0.0% observed, 95% CI [0.0%, 11.2%]).
    - Legitimate tasks completed: 15 / 15 (100.0% observed utility, 95% CI [78.2%, 100.0%]).
  - Added explicit limitation in Section 6.1 and Section 8: *"We note that this observed 100% rate describes the evaluated synthetic scenario suite and does not establish a universal zero-failure probability against arbitrary real-world LLM attacks."*
- **Reason:** Reporting 100% defense without confidence bounds or synthetic suite qualifications represents statistical overselling.
- **Supporting Evidence:** `phase_4_8_2_corrective_report.md` §6.1, exact Clopper-Pearson binomial interval calculations.
- **Status:** **RESOLVED**

---

### Finding 4 (CLM-05 & Finding 4 from Phase 5.1): Unreconciled Ratio Attribution in Section 5.1
- **Claim ID:** CLM-05
- **Original Passage (Draft v1.0):**
  - Section 5.1: *"pure canonicalization and policy computation accounted for only 1.28% of latency, while SQLite persistence accounted for 98.72%."*
- **Correction Applied in Phase 5.2:**
  - Section 5.1 clarified to specify that the 1.28% compute vs. 98.72% persistence split describes the **un-optimized baseline profile** where 8 connections were opened and closed per request.
  - Section 5.2 updated with the re-profiled ratio under connection reuse: compute (~0.133 ms) accounts for **23.6%** of the pipeline, while transactional database persistence accounts for **76.4%** (~0.431 ms).
- **Reason:** Readers would otherwise infer that persistence still accounts for 98.72% in the optimized gateway.
- **Supporting Evidence:** `phase_4_10_runtime_integration_report.md` §4, `scratch/profile_sqlite_persistence.py`.
- **Status:** **RESOLVED**

---

### Finding 5 (CLM-10 & Finding 6 from Phase 5.1): Downstream Fencing Boundary Formalization
- **Claim ID:** CLM-10
- **Original Passage (Draft v1.0):**
  - Abstract: *"formalize the downstream execution boundary where tool idempotency is required to guarantee end-to-end execution safety."*
- **Correction Applied in Phase 5.2:**
  - Strengthened Abstract to explicitly state: *"formalize the downstream execution boundary where tool idempotency is required to guarantee end-to-end execution safety upon network timeouts."*
  - Reaffirmed in Section 7.2 with equation: $\text{Gateway Fencing} \neq \text{End-to-End Exactly-Once}$.
- **Reason:** Accurately communicates that database fencing cannot physically cancel packets in-flight over the wire if a worker stalls during network dispatch.
- **Supporting Evidence:** `phase_4_11_hardening_report.md` §6, `tests/test_connection_lifecycle_and_recovery.py`.
- **Status:** **RESOLVED**

---

### Finding 6 (CLM-02 & Finding 7 from Phase 5.1): Explicit Quantile Convention in Table Captions
- **Claim ID:** CLM-02
- **Original Passage (Draft v1.0):**
  - Section 6.3, Figure 6 caption: *"Figure 6: Performance comparison between on-demand and connection-reuse configurations."*
- **Correction Applied in Phase 5.2:**
  - Updated Figure 6 caption to: *"Figure 6: Microbenchmark performance comparison between on-demand and connection-registry configurations (nearest-rank quantile convention over 100 timed trials)."*
- **Reason:** Ensures exact algorithmic reproducibility of reported percentile figures ($P_{95}$, $P_{99}$).
- **Supporting Evidence:** `phase_4_8_3_1_audit_closure.md` §2, `phase_4_11_raw_benchmark_results.json`.
- **Status:** **RESOLVED**

---

### Finding 7 (CLM-08, CLM-09, CLM-11): Framework Integration Classification
- **Claim IDs:** CLM-08, CLM-09, CLM-11
- **Original Passage (Draft v1.0):**
  - Section 6.4: Described MCP stdio child process and simulated LangGraph.
- **Correction Applied in Phase 5.2:**
  - In Abstract, Contributions, and Section 6.4: Maintained explicit, precise labeling: MCP is evaluated over *real OS child-process stdio pipes with JSON-RPC 2.0 framing*, while LangGraph is evaluated in *simulation via dictionary checkpoint reloads*.
  - Section 8 explicitly discloses that official `mcp` and `langgraph` pip packages were unavailable in the environment.
- **Reason:** Prevents any ambiguity or claim of official third-party SDK certification.
- **Supporting Evidence:** `phase_4_12_final_evaluation_report.md` §7, environment inventory.
- **Status:** **RESOLVED**

