# Phase 5.3 Final Independent Verification and Submission-Readiness Audit Report

**Audit Role:** Independent Academic Reviewer, AI-Agent Security Researcher, Statistical-Methodology Auditor, and Reproducibility Specialist  
**Target Manuscript:** `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` (Version 2.0, Phase 5.2)  
**Authoritative Evidence Baseline:** Phase 4.11 and Phase 4.12 Frozen Verification Artifacts (`phase_4_11_raw_benchmark_results.json`, `phase_4_12_raw_verification_results.json`)  
**Audit Date:** 2026-10-12  

---

## 1. Executive Verdict: **READY FOR TYPESETTING (Submission Pending LaTeX Formatting & Anonymization)**

### Summary of Verdict
An exhaustive, independent verification of `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` against source code, unit regression suites, microbenchmark raw JSON data, and audited literature confirms that **all critical and major defects identified in Phase 5.1 have been resolved**.

The corrected manuscript is:
1. **Scientifically Defensible:** The paper rigorously disentangles the 46-scenario empirical benchmark from the 107-test unit regression suite, avoiding population conflation.
2. **Statistically Sound:** Headline security and utility findings include exact Clopper-Pearson 95% confidence intervals, and limitations regarding finite synthetic scenario suites are clearly disclosed.
3. **Architecturally Accurate:** Connection management is documented as a manager-owned thread connection registry (`self._thread_conns`) rather than an inaccurate "thread-local variable".
4. **Empirically Exact:** All performance metrics (0.5643 ms median latency, 81.29% reduction; 0.9679 ms P99 tail latency, 95.97% reduction; 1,716.4 ops/s throughput, +331.58% increase) match the raw 100-sample JSON vectors with zero discrepancy, and the quantile indexing convention ($P_k = S[\lfloor n \cdot k \rfloor]$) reproduces the reported percentiles.
5. **Boundary-Aware:** The downstream wire-dispatch boundary ($\text{Gateway Fencing} \neq \text{End-to-End Exactly-Once}$) is formalized in the Abstract and Section 7.2.

**Typesetting Readiness:** **READY FOR TYPESETTING.** The manuscript text is complete, coherent, and ready for translation into an ACM `acmart` or IEEE conference template.  
**Formal Conference Submission Readiness:** **PENDING ANONYMIZATION & PACKAGING.** Before uploading to a double-blind conference submission portal (e.g., ACM CCS, NDSS, or IEEE S&P), author names must be anonymized, and basic package scaffolding (`pyproject.toml`) should be added to the repository.

---

## 2. Independent Verification of Claims CLM-01 through CLM-13

Each claim was independently inspected in the corrected manuscript and verified against its underlying evidence source:

| Claim ID | Claim Scope & Target | Finding in Phase 5.1 | Status in Phase 5.2 Corrected Paper | Independent Verification Finding | Audit Disposition |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **CLM-01** | Evaluation Population | Conflated 107 tests with benchmark scenarios. | Abstract & Section 6 clearly separate 46-scenario benchmark from 107 regression tests. Figure 5 presents 46 scenarios. | Verified against `phase_4_8_2_corrective_report.md` §5.1 and pytest suite. | **VERIFIED** |
| **CLM-02** | Latency & Throughput Deltas | Median -81.29%, P99 -95.97%, Throughput +331.58%. | Stated in Abstract, Section 5, and Figure 6 with nearest-rank quantile note. | Independently recalculated from raw 100-sample arrays; exact mathematical match. | **VERIFIED** |
| **CLM-03** | Microbenchmark Latencies | Baseline 3.0153 ms, 3.7991 ms, 24.0348 ms vs Reuse 0.5643 ms, 0.8325 ms, 0.9679 ms. | Reconciled in Figure 6. | Recomputed from sorted raw vectors; matches to 4 decimal places. | **VERIFIED** |
| **CLM-04** | Concurrent Latency / Throughput | Multithreaded (0.7075 ms / 1,167.1 ops/s); Multiprocess (0.6165 ms / 1,265.9 ops/s). | Figure 7 displays exact figures; lock contention noted. | Recomputed from raw 300-sample and 200-sample JSON arrays. | **VERIFIED** |
| **CLM-05** | Persistence Profiling Ratio | Baseline 1.28% compute vs 98.72% persistence. | Section 5.1 specifies baseline un-reused profile; Section 5.2 adds optimized 23.6% / 76.4% ratio. | Factually describes both un-optimized and optimized profiles. | **VERIFIED** |
| **CLM-06** | Connection Registry Architecture | Erroneously called "thread-local". | Standardized to "Manager-Owned Thread Connection Registry" in Abstract and Section 5.2. | Verified against `src/ai_firewall/storage/database.py` lines 139–163. | **VERIFIED** |
| **CLM-07** | Category Denominators | Denominators in Figure 5 mixed arbitrary test counts. | Figure 5 displays formal 46-scenario breakdown: Cats 1 (5), 2 (5), 3 (5), 4 (5), 5 (5), 6 (6), 7 (5), 8 (5), 9 (5). | Matches Phase 4.8.2 corrective benchmark matrix exactly. | **VERIFIED** |
| **CLM-08** | MCP Subprocess Transport | Mediates child-process stdio with JSON-RPC framing. | Section 6.4 clearly describes OS child-process stdio framing; 9 tests passing. | Verified against `tests/test_mcp_subprocess_integration.py`. | **VERIFIED** |
| **CLM-09** | LangGraph Integration | Graph interrupt and state checkpoint reload. | Section 6.4 and Abstract explicitly label as "simulated LangGraph-style workflows". | Verified against `tests/test_langgraph_checkpoint_integration.py`. | **VERIFIED** |
| **CLM-10** | Wire Dispatch Boundary | Claimed or implied end-to-end exactly-once. | Formalized in Abstract and Section 7.2: $\text{Gateway Fencing} \neq \text{End-to-End Exactly-Once}$. | Correctly documents downstream idempotency requirement. | **VERIFIED** |
| **CLM-11** | Third-Party Package Absences | Missing `mcp` and `langgraph` packages. | Section 8 Limitation 2 explicitly discloses uninstalled pip packages. | Verified via environment inventory (`ModuleNotFoundError`). | **VERIFIED** |
| **CLM-12** | Bibliographic Accuracy | Literature comparisons and author names. | Section 2, Figure 1, and References cite verified external publications; Progent cited via arXiv:2504.11703. | Verified against `phase_5_0_literature_verification.md`. | **VERIFIED** |
| **CLM-13** | Generalizability Qualification | Unqualified 100% defense claim. | Abstract and Section 6.1 include Clopper-Pearson 95% CIs ([88.8%, 100.0%]) and synthetic limitations. | Exact binomial confidence intervals verified; scope bounded. | **VERIFIED** |

---

## 3. Independent Statistical and Quantile Verification

### 3.1 Clopper-Pearson Exact Binomial Confidence Intervals
We recalculated exact two-sided 95% confidence intervals using the Beta distribution quantiles ($\alpha = 0.05$):
- **System C Consequential Attack Blocking ($k=31, n=31$):**
  $$\text{Lower} = \text{Beta}^{-1}(0.025, 31, 1) = 0.8878 \rightarrow \mathbf{88.8\%}, \quad \text{Upper} = \mathbf{100.0\%}$$
  *Reported in paper:* **[88.8%, 100.0%]** $\rightarrow$ **MATCH (Exact)**
- **Baseline B Attack Blocking ($k=15, n=31$):**
  $$\text{Lower} = \text{Beta}^{-1}(0.025, 15, 17) = 0.3018 \rightarrow \mathbf{30.2\%}, \quad \text{Upper} = \text{Beta}^{-1}(0.975, 16, 16) = 0.6693 \rightarrow \mathbf{66.9\%}$$
  *Reported in paper:* **[30.2%, 66.9%]** $\rightarrow$ **MATCH (Exact)**
- **Baseline A Attack Blocking ($k=0, n=31$):**
  $$\text{Lower} = \mathbf{0.0\%}, \quad \text{Upper} = \text{Beta}^{-1}(0.975, 1, 31) = 0.1116 \rightarrow \mathbf{11.2\%}$$
  *Reported in paper:* **[0.0%, 11.2%]** $\rightarrow$ **MATCH (Exact)**
- **Legitimate Task Completion ($k=15, n=15$):**
  $$\text{Lower} = \text{Beta}^{-1}(0.025, 15, 1) = 0.7820 \rightarrow \mathbf{78.2\%}, \quad \text{Upper} = \mathbf{100.0\%}$$
  *Reported in paper:* **[78.2%, 100.0%]** $\rightarrow$ **MATCH (Exact)**

### 3.2 Quantile Indexing Convention Verification
The manuscript specifies the nearest-rank quantile convention:
$$P_k = S[\lfloor n \cdot k \rfloor]$$
where $S$ is the sorted zero-indexed array of length $n$.
We audited the actual benchmark code in `scratch/revalidate_benchmark_4_11.py` lines 70–80:
```python
def calc_stats(samples: List[float]) -> Dict[str, float]:
    s = sorted(samples)
    n = len(s)
    return {
        "median": round(s[n // 2], 4),
        "p95": round(s[int(n * 0.95)], 4),
        "p99": round(s[int(n * 0.99)], 4),
    }
```
For $n=100$:
- $\text{Median}: s[100 // 2] = s[50]$. Baseline: **3.0153 ms**; Registry: **0.5643 ms**.
- $P_{95}: s[\lfloor 100 \times 0.95 \rfloor] = s[95]$. Baseline: **3.7991 ms**; Registry: **0.8325 ms**.
- $P_{99}: s[\lfloor 100 \times 0.99 \rfloor] = s[99]$. Baseline: **24.0348 ms**; Registry: **0.9679 ms**.

The formula stated in the manuscript ($P_k = S[\lfloor n \cdot k \rfloor]$) **exactly reproduces** the reported percentiles across all sample vectors.

---

## 4. Architecture and Security Boundary Audit

1. **Connection Registry Implementation:** `src/ai_firewall/storage/database.py` lines 139–163 strictly validates that connections are cached in `_thread_conns: dict[int, sqlite3.Connection]` guarded by `_conns_lock`. `check_same_thread=False` allows the orchestrator thread to close worker connections during `close()`, while `threading.get_ident()` prevents cross-thread connection sharing during query execution.
2. **Dispatch Fencing & Replay Defense:** Monotonic `dispatch_epoch` counter increment occurs inside `BEGIN EXCLUSIVE TRANSACTION` in `database.py` line 350. Unique single-use nonces are enforced by SQLite table constraints in `schema.sql`.
3. **Crash Recovery & UNKNOWN State:** Stalled in-flight operations in `DISPATCHING` transition to `UNKNOWN` (`ERR_DISPATCH_TIMEOUT_UNKNOWN_OUTCOME`) in `database.py` lines 841–874, prohibiting automated retries.
4. **Wire Boundary:** The manuscript honestly acknowledges that gateway database state cannot cancel packets already transmitted over the network, establishing that end-to-end exactly-once execution requires tool-side idempotency.

---

## 5. Literature and Novelty Verification

1. **Audited Literature:** References [1] (CaMeL), [2] (AgentDojo), [3] (DataSentinel), [4] (IsolateGPT), and [5] (Progent) cite verified external publication venues (NeurIPS 2024, NDSS 2025, arXiv 2025).
2. **Progent File Integrity:** The corruption of local file `Progent.pdf` is fully disclosed in `phase_5_0_literature_verification.md`, and the paper's comparison is grounded in Shi et al. (2025), `arXiv:2504.11703`.
3. **Novelty Grounding:** The paper distinguishes itself from prior work (Figure 1) by focusing on external protocol mediation, exact-action cryptographic approval binding, and monotonic SQLite dispatch fencing, rather than claiming novelty for general access control or prompt filtering.

---

## 6. Pre-Submission Blocker Analysis

### 6.1 Typesetting Readiness: **ZERO BLOCKERS**
The Markdown manuscript in `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` is complete, internally consistent, and ready to be translated into LaTeX.

### 6.2 Formal Conference Submission Blockers:
1. **Anonymization (Mandatory for Double-Blind Review):** Author name ("Urval Kheni"), roll number ("24CE055"), and affiliation ("CHARUSAT / CSPIT") must be suppressed in the camera-ready LaTeX preamble.
2. **Vector Graphics (Mandatory for Typesetting):** The 7 ASCII figures/tables should be rendered into LaTeX tables (`booktabs`) and vector figures (TikZ or SVG/PDF).
3. **Package Manifest (Recommended):** Add a minimal `pyproject.toml` so peer reviewers can install the repository via standard `pip install -e .`.

---

## 7. Audit Conclusion and Sign-off

`AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` satisfies all criteria for academic integrity, statistical correctness, and empirical traceability. The paper is approved as **READY FOR TYPESETTING**.

