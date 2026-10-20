# Phase 5.1 Manuscript Correction Plan

This document establishes the ordered, prioritized correction plan for refining `AI_Firewall_Research_Paper_Draft.md` in Phase 5.2 prior to conference submission.

---

## 1. Mandatory Corrections (Pre-Submission Blockers)

### Correction 1: Disentangle 107 Regression Tests from 46 Benchmark Scenarios
- **Target Sections:** Abstract (lines 14–16), Section 6.1 (lines 275–296), Figure 5.
- **Problem:** Abstract and Section 6 currently describe the evaluation as being conducted over "107 regression tests", conflating unit regression tests with empirical security benchmark scenarios.
- **Action Required:**
  1. Update Abstract to state: *"We evaluate AI Firewall through an empirical evaluation across a 46-scenario security benchmark (31 consequential attacks and 15 legitimate tasks), supported by a comprehensive 107-test regression suite."*
  2. Rewrite Section 6 into two distinct parts:
     - **Section 6.1: Empirical Benchmark Evaluation (46 Scenarios):** Report the Phase 4.8.2 results (31 attacks blocked: 5 Cat 3, 5 Cat 4, 5 Cat 5, 6 Cat 6, 5 Cat 7, 5 Cat 8; 15 benign tasks executed: 5 Cat 1, 5 Cat 2, 5 Cat 9).
     - **Section 6.2: Regression Suite and Invariant Verification (107 Tests):** Report the unit test categories verifying canonicalization (22), cryptography (18), policy (15), lifecycle (10), preconditions (5), broker (5), hardening (12), adapters (11), subprocess MCP (9), simulated LangGraph (7), persistence reuse (3), and recovery/concurrency (16).
  3. Replace Figure 5 with the formal 46-scenario comparative table from Phase 4.8.2.

### Correction 2: Clarify Connection Management Architecture
- **Target Section:** Section 5.2 (lines 262–267).
- **Problem:** Text refers to "thread-local connection reuse" and could be misread as using `threading.local()`, which was audited and removed in Phase 4.11.
- **Action Required:**
  - Update terminology to: *"Manager-Owned Thread Connection Registry"*.
  - Explicitly explain that connections are mapped in `self._thread_conns: dict[int, sqlite3.Connection]` guarded by `threading.Lock()`.
  - Explain the dual-safety mechanism: `check_same_thread=False` allows the orchestrator thread to deterministically close worker connections during shutdown, while query execution remains strictly isolated by asserting `threading.get_ident()`.

### Correction 3: Add Exact Statistical Confidence Intervals
- **Target Sections:** Abstract, Section 6.1, Section 8.
- **Problem:** Unqualified claims of "100% defense" and "0% failure probability" without confidence intervals read as marketing claims.
- **Action Required:**
  - Add Clopper-Pearson 95% confidence intervals to all benchmark results: *"System C successfully blocked 31 of 31 evaluated consequential attacks (100.0% observed, 95% CI [88.8%, 100.0%]) while completing 15 of 15 legitimate tasks (100.0% observed utility, 95% CI [78.2%, 100.0%])."*
  - Explicitly state that these bounds describe the evaluated synthetic scenario suite and do not guarantee zero failure rates against unmodeled open-world LLM attacks.

### Correction 4: Re-Balance Persistence Profiling Ratios
- **Target Section:** Section 5.1 (lines 259–261).
- **Problem:** Stating that persistence accounts for 98.72% of latency without qualification misleads readers into thinking that persistence still takes 98.72% under the optimized gateway.
- **Action Required:**
  - Clarify that the 1.28% compute vs. 98.72% persistence split reflects the *un-optimized baseline* where 8 separate connections were opened per request.
  - State the re-profiled ratio under connection reuse: compute (~0.133 ms) accounts for ~23.6% of latency, while persistence accounts for ~76.4% (0.431 ms).

---

## 2. Recommended Improvements (Post-Review Polish)

### Improvement 1: Clarify Downstream Fencing Boundary in Abstract
- **Target Section:** Abstract (lines 24–27).
- **Action Required:** Strengthen the abstract summary of the wire boundary: *"We formalize the downstream execution boundary, demonstrating that while database fencing prevents stale worker state commits, downstream tools must support server-side idempotency keys to guarantee end-to-end exactly-once side effects upon network timeouts."*

### Improvement 2: Add Quantile Algorithm Note to Performance Tables
- **Target Section:** Section 6.3, Figure 6 and Figure 7 captions.
- **Action Required:** Add a note to table captions: *"All percentiles are calculated using the nearest-rank quantile convention ($P_k = S[\lfloor n \cdot k \rfloor]$) over 100 timed trials following 20 untimed warmup iterations."*

### Improvement 3: Distinguish Integration Tiers in Architecture
- **Target Section:** Section 4 & Section 6.4.
- **Action Required:** Emphasize the distinct tiers of integration: Tier 1 (Unit adapter schemas), Tier 2 (Simulated in-memory graph checkpoints), Tier 3 (Actual OS child-process stdio pipes with JSON-RPC framing), Tier 4 (Official SDK runtimes — marked as unavailable).

---

## 3. Implementation Plan & Scope

| Task ID | Task Description | Type | Impacted File(s) | Dependencies |
| :--- | :--- | :---: | :--- | :--- |
| **PLAN-01** | Disentangle 107-test suite from 46-scenario benchmark in Abstract & Section 6 | Wording / Table | `AI_Firewall_Research_Paper_Draft.md` | None (Data in Phase 4.8.2 & 4.12 reports) |
| **PLAN-02** | Correct connection registry architecture description | Wording | `AI_Firewall_Research_Paper_Draft.md` | None (Code in `database.py`) |
| **PLAN-03** | Insert Clopper-Pearson 95% confidence intervals into Section 6.1 | Wording / Stats | `AI_Firewall_Research_Paper_Draft.md` | None (Exact binomial math) |
| **PLAN-04** | Update Section 5.1 persistence profiling ratios (baseline vs optimized) | Wording / Stats | `AI_Firewall_Research_Paper_Draft.md` | None (Profiling data in Phase 4.10) |
| **PLAN-05** | Add quantile convention footnote to Figure 6 and 7 | Caption Polish | `AI_Firewall_Research_Paper_Draft.md` | None |

*Note: All corrections are strictly textual, statistical, and architectural wording refinements. No new experiments or code modifications are required.*

