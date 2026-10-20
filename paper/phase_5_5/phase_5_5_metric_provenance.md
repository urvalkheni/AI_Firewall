# Phase 5.5: Benchmark Provenance and Metric Traceability Matrix

**Audit Date:** October 13, 2026  
**Auditor:** Statistical Methodology & Reproducibility Specialist  
**Repository:** `/home/shadow777/Github/AI_Firewall`  
**Authoritative Raw Artifacts:**
- `~/.gemini/antigravity/brain/.../phase_4_11_raw_benchmark_results.json`
- `~/.gemini/antigravity/brain/.../phase_4_10_raw_benchmark_results.json`
- `~/.gemini/antigravity/brain/.../phase_4_8_2_raw_benchmark_results.json`
- `tests/` (107 unit and regression tests)

---

## 1. Metric Traceability Matrix

This matrix traces every numerical claim and metric reported across the AI Firewall research documents to its exact empirical origin, test execution run, and system configuration.

| Metric / Assertion | Value in `paper/phase_5_4/main.tex` | Source Run / Artifact File | Exact Configuration | Verification Status | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Total Test Scenarios** | 46 Discrete Scenarios | `phase_4_8_2_raw_benchmark_results.json` | 9 Categories across 3 system baselines | **VERIFIED** | Synthetic scenario benchmark. |
| **Consequential Attacks** | 31 Attacks (Cats 3--8) | `phase_4_8_2_raw_benchmark_results.json` | Tool injection, privilege elevation, replay, TOCTOU | **VERIFIED** | Baseline A: 0/31 blocked; B: 15/31; C: 31/31. |
| **System C Attack Block Rate** | 31 / 31 (100.0%) | `phase_4_8_2_raw_benchmark_results.json` | AI Firewall (Canonical + Policy + Envelope + SQLite) | **VERIFIED** | Evaluated on synthetic test suite. |
| **Attack Block Clopper-Pearson 95% CI** | [88.8%, 100.0%] | Re-computed via `scipy.stats.beta(0.025, 31, 1)` | Exact Clopper-Pearson binomial interval | **VERIFIED** | Exact formula: $[(0.025)^{1/31}, 1.0] = [0.8876, 1.0]$. |
| **Legitimate Tasks Completed** | 15 / 15 (100.0%) | `phase_4_8_2_raw_benchmark_results.json` | Benign tool execution (Cats 1, 2, 9) | **VERIFIED** | 0 false denials observed. |
| **Legitimate Clopper-Pearson 95% CI** | [78.2%, 100.0%] | Re-computed via `scipy.stats.beta(0.025, 15, 1)` | Exact Clopper-Pearson binomial interval | **VERIFIED** | Exact formula: $[(0.025)^{1/15}, 1.0] = [0.7816, 1.0]$. |
| **Baseline A Unauthorized Dispatches** | 31 / 31 (100.0%) | `phase_4_8_2_raw_benchmark_results.json` | Direct Tool Execution (No mediation) | **VERIFIED** | Clopper-Pearson CI: [0.0%, 11.2%]. |
| **Baseline B Unauthorized Dispatches** | 16 / 31 (51.6%) | `phase_4_8_2_raw_benchmark_results.json` | Policy Engine only (No cryptographic binding) | **VERIFIED** | Vulnerable to Cats 6, 7, 8; CI: [30.2%, 66.9%]. |
| **Regression Test Suite Count** | 107 Tests | `pytest -o pythonpath=src -q` | Full test suite across 17 test modules | **VERIFIED** | 107 collected and passed in 0.61s. |
| **Baseline Median Latency** | 3.0153 ms | `phase_4_11_raw_benchmark_results.json` | Baseline on-demand connections ($n=100$) | **VERIFIED** | 8 connections per request without pooling. |
| **Optimized Median Latency** | 0.5643 ms | `phase_4_11_raw_benchmark_results.json` | Optimized registry connection reuse ($n=100$) | **VERIFIED** | Thread-bounded connection registry. |
| **Median Latency Delta** | -81.29% (-2.451 ms) | `phase_4_11_raw_benchmark_results.json` | $(0.5643 - 3.0153) / 3.0153$ | **VERIFIED** | Exact match. |
| **Baseline P95 Latency** | 3.7991 ms | `phase_4_11_raw_benchmark_results.json` | Baseline on-demand ($n=100, S[95]$) | **VERIFIED** | Matches implementation formula. |
| **Optimized P95 Latency** | 0.8325 ms | `phase_4_11_raw_benchmark_results.json` | Optimized connection registry ($n=100, S[95]$) | **VERIFIED** | Matches implementation formula. |
| **P95 Latency Delta** | -78.09% (-2.967 ms) | `phase_4_11_raw_benchmark_results.json` | $(0.8325 - 3.7991) / 3.7991$ | **VERIFIED** | Exact match. |
| **Baseline P99 Latency** | 24.0348 ms | `phase_4_11_raw_benchmark_results.json` | Baseline on-demand ($n=100, S[99]$) | **VERIFIED** | Evaluates to sample maximum. |
| **Optimized P99 Latency** | 0.9679 ms | `phase_4_11_raw_benchmark_results.json` | Optimized connection registry ($n=100, S[99]$) | **VERIFIED** | Evaluates to sample maximum. |
| **P99 Latency Delta** | -95.97% (-23.067 ms) | `phase_4_11_raw_benchmark_results.json` | $(0.9679 - 24.0348) / 24.0348$ | **VERIFIED** | Elimination of tail allocation stalls. |
| **Baseline Mean Latency** | 3.0986 ms | `phase_4_11_raw_benchmark_results.json` | Baseline on-demand ($n=100$) | **VERIFIED** | Exact match. |
| **Optimized Mean Latency** | 0.5909 ms | `phase_4_11_raw_benchmark_results.json` | Optimized connection registry ($n=100$) | **VERIFIED** | Exact match. |
| **Baseline Min Latency** | 2.0183 ms | `phase_4_11_raw_benchmark_results.json` | Baseline on-demand ($n=100, S[0]$) | **VERIFIED** | Exact match. |
| **Optimized Min Latency** | 0.5180 ms | `phase_4_11_raw_benchmark_results.json` | Optimized connection registry ($n=100, S[0]$) | **VERIFIED** | Exact match. |
| **Baseline Batch Throughput** | 397.7 ops/s | `phase_4_11_raw_benchmark_results.json` | Baseline on-demand (200 ops batch) | **VERIFIED** | Exact match. |
| **Optimized Batch Throughput** | 1,716.4 ops/s | `phase_4_11_raw_benchmark_results.json` | Optimized connection registry (200 ops batch) | **VERIFIED** | +331.58% throughput gain. |
| **Multithreaded Concurrent (10 thd)** | 0.7075 ms / 1,167.1 ops/s | `phase_4_11_raw_benchmark_results.json` | 10 threads, 300 total ops | **VERIFIED** | Table 4 in `main.tex`. |
| **Multiprocess Concurrent (4 proc)** | 0.6165 ms / 1,265.9 ops/s | `phase_4_11_raw_benchmark_results.json` | 4 worker processes, 200 total ops | **VERIFIED** | Table 4 in `main.tex`. |

---

## 2. Investigation of Phase 5.4 Report Metrics

The audit investigated a cluster of metrics reported in Section 4 of `phase_5_4_typesetting_report.md` that appeared inconsistent with prior baselines.

| Investigated Metric | Value in Report | Actual Source Run Found | Presence in `main.tex` | Provenance Status | Reconciliation / Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Median Gateway Latency** | 0.5411 ms | Phase 4.10 unhardened run (`phase_4_10_raw_benchmark_results.json`) | **NO** (Table 3 reports 0.5643 ms) | **UNVERIFIED FOR MAIN.TEX** | 0.5411 ms was an unhardened preliminary measurement in Phase 4.10. `main.tex` correctly used the hardened Phase 4.11 value (0.5643 ms). |
| **P95 Latency** | 0.8325 ms | Phase 4.11 hardened run | **YES** (Table 3 reports 0.8325 ms) | **VERIFIED** | Accurately corresponds to $S[95]$ of Phase 4.11. |
| **P99 Latency** | 0.9679 ms | Phase 4.11 hardened run | **YES** (Table 3 reports 0.9679 ms) | **VERIFIED** | Accurately corresponds to $S[99]$ of Phase 4.11. |
| **Mean Gateway Latency** | 0.5735 ms | None (Fabrication in report) | **NO** (Table 3 reports 0.5909 ms) | **DISPROVEN / UNVERIFIED** | The value in `main.tex` is 0.5909 ms (verified in Phase 4.11). 0.5735 ms is a report hallucination. |
| **Gateway Overhead** | 14.86% | None (Fabrication in report) | **NO** (Not in `main.tex` Table 3) | **DISPROVEN / UNVERIFIED** | In `main.tex` Section 5.2, pure compute is 23.6% (0.133 ms) and persistence is 76.4% (0.43 ms). 14.86% is a report hallucination. |
| **Autonomous Throughput** | 1,732 ops/sec | None (Fabrication in report) | **NO** (Table 3 reports 1,716.4 ops/s; line 493 says 1,716 ops/sec) | **DISPROVEN / UNVERIFIED** | Real throughput is 1,716.4 ops/s. 1,732 ops/sec is an unverified hallucination in `phase_5_4_typesetting_report.md`. |
| **Direct SQLite Ops** | 28,103 ops/sec | None (Fabrication in report) | **NO** (Not in `main.tex`) | **DISPROVEN / UNVERIFIED** | Report hallucination. |
| **16-Worker Scaling** | 1,385.92 ops/sec | None (Fabrication in report) | **NO** (Table 4 reports 10 threads and 4 processes) | **DISPROVEN / UNVERIFIED** | Report hallucination. Real concurrency benchmark tested 10 threads and 4 processes. |

### Summary of Investigation:
**Crucial Finding:** The LaTeX paper source (`paper/phase_5_4/main.tex`) is completely free of these hallucinated numbers. The author of `phase_5_4_typesetting_report.md` hallucinated a comparison table in that report, but the LaTeX source correctly imported the true, verified figures from `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` and `phase_4_11_raw_benchmark_results.json`.

---

## 3. Quantile Indexing Formula Analysis

### Implementation Inspection
In `scratch/revalidate_benchmark_4_11.py` and `scratch/benchmark_harness.py`:
```python
"median": round(s[n // 2], 4),
"p95": round(s[int(n * 0.95)], 4),
"p99": round(s[int(n * 0.99)], 4),
```

### Mathematical Formulation
Let $S$ be a zero-indexed sorted vector of length $n = 100$:
- **Implementation formula:** $i = \lfloor n \cdot k \rfloor$
  - For $k = 0.50$: $i = \lfloor 100 \cdot 0.50 \rfloor = 50 \rightarrow S[50]$ (51st element).
  - For $k = 0.95$: $i = \lfloor 100 \cdot 0.95 \rfloor = 95 \rightarrow S[95]$ (96th element).
  - For $k = 0.99$: $i = \lfloor 100 \cdot 0.99 \rfloor = 99 \rightarrow S[99]$ (100th element, i.e., sample maximum).
- **Conventional NIST / Nearest-Rank formula:** $i = \lceil n \cdot k \rceil - 1$
  - For $k = 0.50$: $i = \lceil 50.0 \rceil - 1 = 49 \rightarrow S[49]$ (or average with $S[50]$).
  - For $k = 0.95$: $i = \lceil 95.0 \rceil - 1 = 94 \rightarrow S[94]$ (95th element).
  - For $k = 0.99$: $i = \lceil 99.0 \rceil - 1 = 98 \rightarrow S[98]$ (99th element).

### Empirical Comparison on Frozen Phase 4.11 Samples ($n=100$)

| Benchmark Mode | Percentile | Implementation $S[\lfloor n \cdot k \rfloor]$ | Conventional Nearest-Rank $S[\lceil n \cdot k \rceil - 1]$ | Sample Max $S[99]$ |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline On-Demand** | P95 | **3.7991 ms** ($S[95]$) | **3.5837 ms** ($S[94]$) | 24.0348 ms |
| **Baseline On-Demand** | P99 | **24.0348 ms** ($S[99]$) | **9.7160 ms** ($S[98]$) | 24.0348 ms |
| **Optimized Registry** | P95 | **0.8325 ms** ($S[95]$) | **0.7942 ms** ($S[94]$) | 0.9679 ms |
| **Optimized Registry** | P99 | **0.9679 ms** ($S[99]$) | **0.8924 ms** ($S[98]$) | 0.9679 ms |

### Consequence:
- Because the implementation evaluates $S[99]$ for P99 on $n=100$, the reported P99 coincides exactly with the sample maximum ($S[99]$).
- In `paper/phase_5_4/main.tex` Table 3 caption, this convention is explicitly and truthfully disclosed:
  $$\text{calculated ... using } P_k = S[\lfloor n \cdot k \rfloor] \text{ on a zero-indexed array } S$$
- Under conventional nearest-rank, baseline P99 is 9.7160 ms and optimized P99 is 0.8924 ms, yielding a 90.81% reduction. Under the disclosed formula $S[\lfloor n \cdot k \rfloor]$, the reduction is 95.97%. Both interpretations confirm massive tail-latency reduction.

---

## 4. Distinct Test Artifact Clarification

1. **107 Unit & Regression Tests vs. 46 Security Scenarios:**
   - The 107 tests (`pytest -o pythonpath=src`) represent structural unit and integration tests across 17 files covering schema parsing, RFC 8785 compliance, Ed25519 signature checks, SQLite transaction handling, and OS subprocess framing.
   - The 46 scenarios (`scratch/corrective_benchmark_harness.py`) represent a discrete synthetic testbed evaluating 31 attack injection vectors and 15 benign tool execution workflows against 3 system architectures.
   - These suites are distinct and must not be conflated.

2. **Baseline On-Demand vs. Connection Registry:**
   - Baseline on-demand executes the authorization pipeline opening and closing 8 SQLite database handles per tool proposal, with WAL mode and foreign key PRAGMA initialization per connection.
   - Connection registry uses a manager-owned thread registry where connections are persistent per thread, eliminating redundant filesystem stats, locks, and WAL index re-reads.

