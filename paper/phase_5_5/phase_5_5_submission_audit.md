# Phase 5.5: Independent Submission Package and Evidence Reconciliation Audit

**Audit Date:** October 13, 2026  
**Auditor:** Independent Academic Reviewer, AI-Security Methodology Auditor  
**Repository:** `/home/shadow777/Github/AI_Firewall`  
**Target Submission Artifacts:** `paper/phase_5_4/main.tex`, `paper/phase_5_4/references.bib`  
**Reference Manuscript:** `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md`  
**Overall Verdict:** **PASS WITH NOTED QUALIFICATIONS** (Source Code & LaTeX Validated; Typesetting Report Discrepancy Reconciled; Local Compilation Not Run)

---

## 1. Executive Summary and Audit Scope

Phase 5.5 conducted an independent, evidence-driven verification of the Phase 5.4 ACM LaTeX submission package. The audit examined:
1. **Manuscript Fidelity:** Structural, textual, mathematical, and claim-level preservation from the corrected Phase 5.2 Markdown manuscript into LaTeX.
2. **Benchmark Provenance & Statistical Accuracy:** Re-derivation of all empirical numbers from raw JSON benchmark records, reconciliation of conflicting metrics in reporting artifacts, and mathematical evaluation of quantile formulas.
3. **Double-Blind Anonymization:** Rigorous inspection of author identity, institutional markers, metadata, acknowledgments, repository URLs, and supplementary repository artifacts.
4. **Bibliographic Integrity:** Verification of primary vs. inferred metadata for all BibTeX entries, citation usage in the manuscript, and identification of unused or unverified keys.
5. **LaTeX Source Validation:** Static analysis of syntax, balanced braces, environment matching, TikZ graph topology, and compiler availability check.

---

## 2. File Location and Discovery Log

| Expected File Path | Actual Discovered Location | Discovery Status | Notes |
| :--- | :--- | :--- | :--- |
| `paper/phase_5_4/main.tex` | `/home/shadow777/Github/AI_Firewall/paper/phase_5_4/main.tex` | **FOUND** | Complete ACM `sigconf` LaTeX source (497 lines). |
| `paper/phase_5_4/references.bib` | `/home/shadow777/Github/AI_Firewall/paper/phase_5_4/references.bib` | **FOUND** | BibTeX database with 10 entries (84 lines). |
| `paper/phase_5_4/phase_5_4_typesetting_report.md` | `/home/shadow777/Github/AI_Firewall/phase_5_4_typesetting_report.md` | **RELOCATED** | Found in workspace root and artifact storage, not inside `paper/phase_5_4/`. |
| `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` | `/home/shadow777/Github/AI_Firewall/AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` | **FOUND** | Authoritative corrected Phase 5.2 baseline manuscript (432 lines). |
| `phase_5_2_validation_report.md` | `/home/shadow777/Github/AI_Firewall/phase_5_2_validation_report.md` | **FOUND** | Phase 5.2 validation report. |
| `phase_5_3_final_independent_audit.md` | `/home/shadow777/Github/AI_Firewall/phase_5_3_final_independent_audit.md` | **FOUND** | Phase 5.3 audit report. |
| `phase_4_11_raw_benchmark_results.json` | `~/.gemini/antigravity/brain/.../phase_4_11_raw_benchmark_results.json` | **FOUND** | Raw Phase 4.11 benchmark data (778 lines). |
| `phase_4_10_raw_benchmark_results.json` | `~/.gemini/antigravity/brain/.../phase_4_10_raw_benchmark_results.json` | **FOUND** | Raw Phase 4.10 benchmark data. |
| `phase_4_8_2_raw_benchmark_results.json` | `~/.gemini/antigravity/brain/.../phase_4_8_2_raw_benchmark_results.json` | **FOUND** | Raw 46-scenario security evaluation data. |

---

## 3. Findings by Task and Severity

### Finding 1: Manuscript Structural & Textual Fidelity (Task 1)
- **Severity:** Informational
- **Location:** `paper/phase_5_4/main.tex` vs `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md`
- **Observation:** 
  - All 10 major sections and their corresponding subsections from the Phase 5.2 Markdown are preserved in `main.tex`.
  - Section 6 is titled `\section{Experimental Methodology and Results}` in LaTeX compared to `## 6. Experimental Evaluation` in Markdown; this is a standard stylistic improvement for ACM papers and introduces no substantive change.
  - All 6 display mathematical equations match 1-to-1 without alteration.
  - The vital wire boundary formulation ($\text{Gateway Fencing} \neq \text{End-to-End Exactly-Once}$) is fully preserved in Section 7.2.
  - The security claim qualification ("*We note that this observed 100% rate describes the evaluated synthetic scenario suite and does not establish a universal zero-failure probability against arbitrary real-world LLM attacks*") is preserved verbatim in Section 6.1.
  - **Verdict:** **PASS**.

### Finding 2: Narrative Discrepancy in `phase_5_4_typesetting_report.md` (Task 2)
- **Severity:** **MAJOR**
- **Location:** `phase_5_4_typesetting_report.md` Section 4
- **Observation:**
  - In `phase_5_4_typesetting_report.md`, Section 4 presents a comparative table claiming that `paper/phase_5_4/main.tex` has:
    - Median Gateway Latency: 0.5411 ms
    - Mean Gateway Latency: 0.5735 ms
    - Relative Gateway Overhead: 14.86%
    - Autonomous Throughput: 1,732 ops/sec
    - Direct SQLite Ops: 28,103 ops/sec
    - 16-Worker Throughput: 1,385.92 ops/sec
  - **Evidence Audit:** Inspection of the actual LaTeX source `paper/phase_5_4/main.tex` reveals that **these numbers are NOT in the LaTeX paper**. Instead, `main.tex` Table 3 contains the real, verified Phase 4.11 figures:
    - Median Latency: 0.5643 ms
    - P95 Latency: 0.8325 ms
    - P99 Tail Latency: 0.9679 ms
    - Mean Latency: 0.5909 ms
    - Throughput: 1,716.4 ops/s
  - The figure `0.5411 ms` originated from preliminary unhardened Phase 4.10 testing (`phase_4_10_raw_benchmark_results.json`). The other figures (`0.5735 ms`, `14.86%`, `1,732 ops/sec`, `28,103 ops/sec`, `1,385.92 ops/sec`) were narrative hallucinations generated solely within `phase_5_4_typesetting_report.md`.
  - **Impact:** The LaTeX manuscript itself (`paper/phase_5_4/main.tex`) is scientifically sound and accurate to the raw Phase 4.11 benchmark. However, `phase_5_4_typesetting_report.md` contains erroneous claims about what the paper contains.
  - **Verdict:** **RECONCILED** (Paper source is accurate; reporting artifact flagged as inaccurate in Section 4).

### Finding 3: Quantile Indexing Implementation Analysis (Task 2)
- **Severity:** Minor / Methodological Disclosure
- **Location:** `paper/phase_5_4/main.tex` Table 3 caption; `scratch/revalidate_benchmark_4_11.py`
- **Observation:**
  - The benchmark code uses `s[int(n * k)]` on a zero-indexed sorted array of size $n=100$.
  - For $k=0.95$, this accesses index $95$ (the 96th value).
  - For $k=0.99$, this accesses index $99$ (the 100th value, i.e., sample maximum).
  - Standard NIST nearest-rank uses $S[\lceil n \cdot k \rceil - 1]$, which accesses index $94$ for P95 and index $98$ for P99.
  - The caption in `paper/phase_5_4/main.tex` Table 3 correctly discloses:
    $$\text{calculated ... using } P_k = S[\lfloor n \cdot k \rfloor] \text{ on a zero-indexed array } S$$
  - Under this formula, P99 evaluates to $S[99] = \text{Max}$. If standard nearest-rank were evaluated, baseline P99 would be $S[98] = 9.7160\text{ ms}$ and optimized P99 would be $S[98] = 0.8924\text{ ms}$ (a 90.81% reduction).
  - **Verdict:** **PASS WITH DISCLOSURE**.

### Finding 4: Unused BibTeX Entry `wang2026agentspec` (Task 4)
- **Severity:** Moderate
- **Location:** `paper/phase_5_4/references.bib` line 50; `paper/phase_5_4/main.tex`
- **Observation:**
  - `references.bib` defines 10 entries.
  - `main.tex` explicitly cites 9 entries via `\cite{...}`.
  - The entry `wang2026agentspec` (AgentSpec, ICSE 2026) is never cited in `main.tex`. Under standard BibTeX processing, it will not be rendered in the references section of the compiled paper.
  - In `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md`, AgentSpec was listed in Section 11 (References) item 7, but was never cited in the body text.
  - **Recommendation:** If the authors intend AgentSpec to appear in the printed bibliography, add `\nocite{wang2026agentspec}` or cite it in Section 2.2 alongside Progent.
  - **Verdict:** **FLAGGED / ADVISORY**.

### Finding 5: Double-Blind Anonymity in Submission vs. Workspace (Task 3)
- **Severity:** Major (Operational Risk for Submission Bundling)
- **Location:** `paper/phase_5_4/` vs Workspace Root
- **Observation:**
  - Inside `paper/phase_5_4/main.tex` and `paper/phase_5_4/references.bib`, double-blind anonymity is 100% clean. An automated regex scan for author name (`Urval`, `Kheni`), roll number (`24CE055`), and institution (`CHARUSAT`, `CSPIT`) returned 0 matches.
  - Document class specifies `\documentclass[sigconf,anonymous,review]{acmart}`, and author block is anonymized.
  - **Residual Risk:** In the workspace root, several files exist containing the student's name and roll number (`24CE055_AI_Agent_Security_Gateway_Presentation.pptx`, `24CE055_Practical_*.docx`, `AI_Agent_Security_Gateway_Literature_Review.md.pdf`).
  - **Enforcement:** Authors must NOT bundle the root repository directory when submitting supplementary material; only sanitized source directories (`src/`, `tests/`) must be included.
  - **Verdict:** **PASS FOR paper/phase_5_4/; EXCLUSION RULE REQUIRED FOR SUPPLEMENTARY MATERIAL**.

### Finding 6: Local LaTeX Compilation Status (Task 5)
- **Severity:** Informational / Host Limitation
- **Location:** Host Environment PATH
- **Observation:**
  - Local diagnostic: `which pdflatex latex xelatex lualatex tectonic kpsewhich` returned no compiler installed.
  - In accordance with phase rules, no packages were installed.
  - Compilation is reported as **NOT RUN**.
  - Static syntax validation confirmed:
    - Braces: 481 opening `{`, 481 closing `}` (perfect balance).
    - Environments: 38 `\begin{...}` / `\end{...}` pairs (0 errors, 0 mismatches).
    - Labels / Refs: 7 labels defined, all 7 referenced, 0 missing references.
    - External Graphics: 0 external files (all 3 diagrams implemented natively via TikZ).
  - **Verdict:** **NOT RUN (Host Compiler Absent); STATIC SYNTAX PASS**.

---

## 4. Summary Table of Audit Findings

| Item / Dimension | Requirement | Audit Finding | Severity | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Manuscript Fidelity** | Exact preservation of Phase 5.2 text, sections, equations | 10/10 sections preserved; 6/6 equations match | Informational | **PASS** |
| **Microbenchmark Provenance** | Table 3 metrics match raw benchmark data | Table 3 in `main.tex` matches `phase_4_11_raw_benchmark_results.json` | Informational | **PASS** |
| **Reporting Consistency** | `phase_5_4_typesetting_report.md` matches `main.tex` | Narrative table in report had hallucinated metrics; paper itself is clean | Major | **RECONCILED** |
| **Quantile Convention** | Disclosure of $S[\lfloor n \cdot k \rfloor]$ | Accurately disclosed in Table 3 caption | Minor | **PASS** |
| **46-Scenario Testbed** | 31 attacks, 15 benign, CIs verified | Matches Phase 4.8.2; Clopper-Pearson CIs independently verified | Informational | **PASS** |
| **107 Regression Tests** | Pytest test suite matches claim | 107 tests collected and passed in 0.61s | Informational | **PASS** |
| **Double-Blind Anonymity** | Anonymized author, institution, no leaked tokens | 0 identifying tokens in `paper/phase_5_4/` | Informational | **PASS** |
| **Supplementary Anonymity** | No student identity in repo artifacts | Root contains `24CE055_*` coursework files; must exclude from upload | Major | **ACTION REQUIRED** |
| **BibTeX Citations** | Valid keys, no missing cites, accurate metadata | 9/10 keys cited; 1 unused key (`wang2026agentspec`) | Moderate | **PASS (ADVISORY)** |
| **Static LaTeX Syntax** | Balanced braces, environments, labels, refs | 481 braces balanced; 38 env pairs matched; 0 label errors | Informational | **PASS** |
| **LaTeX Compilation** | Successful PDF generation | No TeX distribution on host; compilation NOT RUN | Informational | **NOT RUN** |

