# Phase 5.7: PDF Visual and Layout Audit

**Audit Date:** October 13, 2026  
**Auditor:** Document Formatting & Visual Quality Auditor  
**Repository:** `/home/shadow777/Github/AI_Firewall`  
**Candidate Source:** `paper/phase_5_7/main.tex`  
**Generated PDF Status:** **PENDING EXTERNAL USER COMPILATION**  
**Audit Scope:** **STATIC SOURCE LAYOUT AUDIT COMPLETED; RENDERED PIXEL AUDIT PENDING**

---

## 1. Methodological Disclosure

Per Task 4 requirements:
> *"State which inspection methods were actually used. Never describe a source-level layout check as a PDF visual inspection."*

Because no TeX distribution is installed on the research machine and no remote CI runner is directly accessible to the automated agent, the compilation must be completed externally (via Overleaf or an isolated Docker container). Therefore:
- **Source-Level Typography and Layout Inspection:** **COMPLETED**.
- **Page-by-Page Visual Inspection of Rendered PDF Pixels/Glyphs:** **PENDING EXTERNAL COMPILATION**.

---

## 2. Source-Level Layout and Formatting Verification

### 2.1 Document Architecture and ACM Review Mode
- **Class Configuration:** `\documentclass[sigconf,anonymous,review]{acmart}`.
  - `sigconf`: Standard ACM two-column conference layout.
  - `anonymous`: Blinds author and affiliation macros to preserve double-blind integrity.
  - `review`: Generates continuous line numbers in the outer margins to facilitate reviewer commentary.
- **Header Blocks:** Abstract, CCSXML concepts, and keywords are encapsulated within standard ACM macro environments before `\maketitle`.

### 2.2 Table Sizing, Alignment, and Rules
- **Table 1 (`tab:related_work`):**
  - Environment: `\begin{table*}[t]` (spans both columns at the top of the page).
  - Formatting: `\small`, `booktabs` (`\toprule`, `\midrule`, `\bottomrule`).
  - Columns: Explicit column wrap specifications prevent text overflow past the margins.
- **Table 2 (`tab:security_benchmark`):**
  - Environment: `\begin{table*}[t]` (full-width span).
  - Content: 9 benchmark categories, 3 baseline architectures, Clopper-Pearson 95% confidence intervals.
- **Table 3 (`tab:performance`):**
  - Environment: `\begin{table}[t]` (single column, fits standard 3.33-inch column width).
  - Content: Microbenchmark comparison (on-demand vs. connection registry) with explicit quantile convention disclosure in the caption.
- **Table 4 (`tab:concurrency`):**
  - Environment: `\begin{table}[t]` (single column).
  - Content: Multithreaded (10 threads) and multiprocess (4 worker processes) scaling metrics.

### 2.3 Vector TikZ Graphics Topology
All 3 figures are written in native vector TikZ, avoiding raster image artifacts, blurriness, or broken file paths:
- **Figure 1 (`fig:threat_model`):**
  - Single-column width (`\begin{figure}[t]`).
  - Node hierarchy: Untrusted data (red), untrusted agent core (yellow), gateway TCB boundary (blue), fenced tool (green).
  - Connectors: Directed thick arrows (`-Latex, thick`) with legible labels.
- **Figure 2 (`fig:pipeline`):**
  - Full-width span (`\begin{figure*}[t]`).
  - Pipeline topology: 6 sequential stages with dual-branch path for Autonomous `ALLOW` vs. Human `APPROVAL_REQUIRED`.
- **Figure 3 (`fig:lifecycle`):**
  - Single-column width (`\begin{figure}[t]`).
  - State machine: Complete graph showing transitions between `PROPOSED`, `PENDING_APPROVAL`, `APPROVED`, `RESERVED`, `DISPATCHING`, `SUCCEEDED`, `FAILED`, and `UNKNOWN`. Includes red dashed loop for lease expiration reset.

### 2.4 Mathematical Expressions
- 6 display equations (`\begin{equation}...\end{equation}`) format:
  1. Action proposal tuple $\langle P, I, R, B \rangle$
  2. Canonical digest $d_{\text{act}} = \text{SHA-256}(\text{JCS}(\dots))$
  3. Risk score summation and clipping $S = \min(100.0, \dots)$
  4. Cryptographic approval envelope $\langle \text{approval\_id}, d_{\text{act}}, \text{claims}, \sigma_{\text{Ed25519}} \rangle$
  5. Claims tuple $\langle \text{nonce}, \text{auth\_level}, \text{reviewer\_id}, \dots \rangle$
  6. Wire boundary principle: $\text{Gateway Fencing} \neq \text{End-to-End Exactly-Once}$

---

## 3. Post-Compilation Visual Inspection Checklist for the User

Once `main.pdf` is compiled via Overleaf or Docker, verify the following visual layout criteria:

1. [ ] **Margin Fit:** Verify that neither Table 1 nor Table 2 extends beyond the outer page margins.
2. [ ] **Line Numbering:** Confirm that line numbers run continuously down the left margin of both columns.
3. [ ] **TikZ Vector Clarity:** Zoom into Figures 1, 2, and 3 at 400% in a PDF viewer to confirm vector sharpness without pixelation.
4. [ ] **Equation Alignment:** Verify that all equation numbers `(1)` through `(6)` align cleanly to the right margin.
5. [ ] **Page Breaks & Float Placement:** Verify that tables and figures appear at the tops of pages without generating orphaned single lines or large blank spaces.
6. [ ] **Bibliography Rendering:** Confirm that the References section contains all 10 entries (including AgentSpec) and that bracketed citations `[1]--[10]` resolve properly.
7. [ ] **Metadata Anonymity:** Check Document Properties in Acrobat Reader or `pdfinfo main.pdf` to ensure the Author, Title, and Creator fields contain no personal username or university details.

