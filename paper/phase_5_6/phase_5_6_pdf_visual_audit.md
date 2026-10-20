# Phase 5.6: PDF Visual and Layout Audit

**Audit Date:** October 13, 2026  
**Auditor:** Document Formatting & Visual Quality Auditor  
**Repository:** `/home/shadow777/Github/AI_Firewall`  
**Target Manuscript:** `paper/phase_5_4/main.tex`  
**Generated PDF Location:** None (`pdflatex` compilation blocked on host)  
**PDF SHA-256 Hash:** N/A (Compilation blocked)  
**Audit Status:** **STATIC LAYOUT AUDIT COMPLETED; RENDERED VISUAL INSPECTION BLOCKED**

---

## 1. Scope and Methodological Disclosure

Per the strict instructions of Phase 5.6:
> *"Do not claim visual inspection if only text extraction was performed. Do not claim success based on static syntax checks. The PDF must actually be generated."*

Because no TeX distribution exists on the research host and installing packages was prohibited, a compiled PDF could not be generated locally. Consequently:
- **Actual rendered page-by-page pixel/glyph visual inspection:** **BLOCKED / NOT PERFORMED**.
- **Static structural and layout inspection of LaTeX source code:** **PERFORMED**.

This report documents the structural formatting audits completed on the LaTeX sources and details the visual checks that must be verified once compiled on Overleaf or an external build runner.

---

## 2. Static Layout and Typography Audit of Source Code

### 2.1 Title, Abstract, and Metadata Structure
- **ACM Template Class:** `\documentclass[sigconf,anonymous,review]{acmart}`.
  - Standard two-column ACM format specified.
  - `review` mode enables line numbering and 1-inch margins required for review.
  - `anonymous` mode enforces blinding of author and affiliation fields.
- **Title:** `\title{AI Firewall: A Shared, Risk-Based Authorization Gateway with Exact-Action Human Approval Binding for Autonomous AI Agents}`.
- **Abstract:** Encapsulated in `\begin{abstract}...\end{abstract}` before `\maketitle` (required by ACM class).
- **CCS Concepts & Keywords:**
  - `\begin{CCSXML}...\end{CCSXML}` provides formal ACM computing classification: Security and privacy $\rightarrow$ Access control, Distributed systems security, Software and application security.
  - `\keywords{AI Agents, Runtime Authorization, Tool Use Security...}` properly defined.

### 2.2 Table Sizing and Formatting
The source employs formal `booktabs` styling throughout:
- **Table 1 (`tab:related_work`):** Typeset as a two-column wide table (`\begin{table*}[t]`). Contains 5 comparative dimensions across 5 systems with wrapped `p{...}` column specifications and `\small` font to prevent column margin overflow.
- **Table 2 (`tab:security_benchmark`):** Typeset as a two-column wide table (`\begin{table*}[t]`). Contains comparative results across all 9 benchmark categories and 3 system configurations, with Clopper-Pearson 95% confidence intervals.
- **Table 3 (`tab:performance`):** Typeset as a single-column table (`\begin{table}[t]`). Compares 7 microbenchmark metrics (Median, P95, P99, Mean, Min, Max, Throughput) between on-demand baseline and connection registry. Fits cleanly within a standard 3.33-inch ACM column.
- **Table 4 (`tab:concurrency`):** Typeset as a single-column table (`\begin{table}[t]`). Displays multithreaded and multiprocess scaling metrics across 5 columns.

### 2.3 TikZ Diagram Topology and Styling
All figures are drawn natively using vector TikZ primitives:
- **Figure 1 (`fig:threat_model`):**
  - Type: Single-column figure (`\begin{figure}[t]`).
  - Content: Threat model with untrusted external data, untrusted agent core, AI Firewall TCB gateway boundary, and fenced tool execution.
  - Nodes: Styled with explicit `rounded corners`, `minimum width=2.4cm`, `font=\footnotesize`.
  - Edges: Explicit coordinate and anchor connections (`-Latex, thick`).
- **Figure 2 (`fig:pipeline`):**
  - Type: Full-width page span (`\begin{figure*}[t]`).
  - Content: 6-stage authorization pipeline (Protocol Adapters $\rightarrow$ RFC 8785 Canonical Hasher $\rightarrow$ Policy Engine $\rightarrow$ Approval Branching $\rightarrow$ Envelope Verifier $\rightarrow$ SQLite Lifecycle $\rightarrow$ Fenced Dispatch).
  - Nodes: Standardized width (2.4 cm for stages, 4.5 cm for lower stages).
- **Figure 3 (`fig:lifecycle`):**
  - Type: Single-column figure (`\begin{figure}[t]`).
  - Content: Finite state machine showing transitions between `PROPOSED`, `PENDING_APPROVAL`, `APPROVED`, `RESERVED`, `DISPATCHING`, and terminal states (`SUCCEEDED`, `FAILED`, `UNKNOWN`), including lease expiration rollback edge.

### 2.4 Mathematical Typesetting
- 6 display equations (`\begin{equation}...\end{equation}`) typeset canonical action identity ($P, I, R, B$), RFC 8785 hash ($d_{\text{act}}$), risk scoring summation, Ed25519 envelope claims, and wire dispatch boundary.
- All inline math expressions use standard `$...$` syntax. No unmatched delimiters detected.

---

## 3. Checklist of Visual Items to Verify Upon External PDF Generation

When the compiled PDF is generated on Overleaf or external CI, the reviewer must verify the following visual criteria:

1. [ ] **Column Balance & Overfull Hboxes:** Verify that Table 1 and Table 2 span two columns cleanly without clipping into outer page margins.
2. [ ] **TikZ Font Rendering:** Verify that labels within Figure 1, 2, and 3 render with sharp vector text and do not collide with bounding boxes.
3. [ ] **Line Numbering:** Verify that ACM review-mode continuous line numbers appear in the left margin of both columns.
4. [ ] **Page Breaks around Figures:** Confirm that floating figures (`[t]`) appear at the tops of pages and do not produce orphaned single lines or awkward white space.
5. [ ] **Mathematical Symbols:** Verify that KaTeX/LaTeX math glyphs ($\langle, \rangle, \sigma, \Sigma, \cdot, \neq$) render with standard Computer Modern / Times math fonts.
6. [ ] **Hyperlinks:** Confirm that hyperref links from `\ref` and `\cite` resolve cleanly in PDF viewers.

