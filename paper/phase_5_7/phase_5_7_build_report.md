# Phase 5.7: External ACM Build Report and Candidate Preparation

**Audit Date:** October 13, 2026  
**Auditor:** Academic LaTeX Typesetter & Release Engineer  
**Repository:** `/home/shadow777/Github/AI_Firewall`  
**Candidate Directory:** `paper/phase_5_7/`  
**Candidate Source Files:** `paper/phase_5_7/main.tex`, `paper/phase_5_7/references.bib`  
**Submission Package:** `paper/phase_5_7/ai_firewall_submission_candidate.zip`  
**Phase 5.7 Verdict:** **BLOCKED** (Local compilation blocked due to absent host TeX environment; minimal clean candidate packaged for external Overleaf / CI execution)

---

## 1. External Build Environment Evaluation

Per the Task 1 directives:
1. **Host Environment Diagnostic:**
   - Searches across `$PATH`, `/usr`, `/opt`, `/home`, `/snap`, and `/var` confirmed that no TeX distribution (`pdflatex`, `latex`, `xelatex`, `tectonic`, `latexmk`, `kpsewhich`) is installed on the research host.
   - Host Docker engine has no pre-existing TeX Live images (only local web and database containers).
   - Under the phase constraints (*"Do not install software on the research machine"*), package installations via `apt` or pulling external container images were prohibited.
2. **External CI / Overleaf Accessibility:**
   - No pre-authenticated external CI runners, Overleaf APIs, or remote build services are directly accessible to the automated agent.
3. **Execution Decision:**
   - In strict compliance with Task 1 items 4 and 5:
     > *"If no external environment is accessible to the agent, prepare a clean, minimal upload package and provide exact manual instructions for the user to compile it externally. If manual compilation is required, clearly mark compilation and PDF inspection as pending until the generated PDF is returned or otherwise made accessible."*
   - An isolated Phase 5.7 build candidate was established in `paper/phase_5_7/`, packaged into `ai_firewall_submission_candidate.zip`, and documented with exact external build instructions.

---

## 2. Phase 5.7 Candidate Preparation & AgentSpec Integration

The candidate source files were copied from Phase 5.4 into `paper/phase_5_7/`, preserving the original Phase 5.4 files completely unchanged.

### Substantive Integration of AgentSpec (`wang2026agentspec`)
In Phase 5.5 and 5.6, `wang2026agentspec` was identified as an unused entry in `references.bib`. Rather than inserting a superficial `\nocite`, the text in Section 2.2 and Section 2.3 of `paper/phase_5_7/main.tex` was updated to substantively discuss Wang et al.'s runtime behavioral specifications alongside Progent and CaMeL:

**Modified Text (Section 2.2):**
> *"...Shi et al.~\cite{shi2025progent} proposed \emph{Progent}, which enforces least privilege using a policy DSL and an SMT solver to guarantee monotonic privilege narrowing across tool calls. Similarly, Wang et al.~\cite{wang2026agentspec} introduced \emph{AgentSpec}, which specifies customizable runtime behavioral monitors and fine-grained constraints on agent tool invocation sequences."*

**Modified Text (Section 2.3):**
> *"...While CaMeL, Progent, and AgentSpec provide compelling defenses, they require either running code in a bespoke Python interpreter or deeply modifying the internal agent runtime loop..."*

### Citation Resolution:
- **Total keys defined in `references.bib`:** 10
- **Total keys cited in `main.tex`:** 10
- **Unresolved citations (`\cite` without `.bib` entry):** 0
- **Unused bibliography entries (`.bib` entry without `\cite`):** 0

---

## 3. Static Pre-Flight Syntax Audit

Automated static validation of `paper/phase_5_7/main.tex` confirmed zero syntactical barriers:

| Syntax Dimension | Measured Value | Requirement | Status |
| :--- | :--- | :--- | :--- |
| **Brace Balance** | Open: 483, Close: 483 (Diff: 0) | Exact equality | **PASS** |
| **Environment Nesting** | 38 `\begin{...}` / `\end{...}` pairs | Clean LIFO stack | **PASS** |
| **Cross-References** | 7 defined labels, 7 references | 0 dangling references | **PASS** |
| **External Graphics** | 0 `\includegraphics` calls | Self-contained vector TikZ | **PASS** |
| **ACM Document Class** | `\documentclass[sigconf,anonymous,review]{acmart}` | Official ACM standard | **PASS** |

---

## 4. Minimal Upload Package Specification

A clean, minimal submission archive was generated at:
`paper/phase_5_7/ai_firewall_submission_candidate.zip`

### Archive Contents:
```
ai_firewall_submission_candidate.zip
├── main.tex            (40,000 bytes, contains substantive AgentSpec citation)
└── references.bib      (3,482 bytes, contains 10 verified bibliography entries)
```
- **Total Size:** 43,482 bytes uncompressed (~15 KB compressed).
- **Sanitization:** Strictly isolates the LaTeX sources; contains zero student coursework files (`24CE055_*`), binary artifacts, or Git commit history.

---

## 5. Exact External Build Sequence

To compile the candidate externally (on Overleaf, local machine with TeX Live, or CI runner):

### Option A: Overleaf (Recommended)
1. Log into [Overleaf](https://www.overleaf.com).
2. Click **New Project** $\rightarrow$ **Upload Project**.
3. Upload `paper/phase_5_7/ai_firewall_submission_candidate.zip`.
4. In Overleaf project settings, ensure:
   - **Compiler:** `pdfLaTeX`
   - **TeX Live version:** `2024` or `2025`
   - **Main document:** `main.tex`
5. Click **Recompile**.

### Option B: Command Line (with TeX Live installed)
```bash
cd paper/phase_5_7
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

### Option C: Isolated Docker Container
```bash
docker run --rm -v $(pwd)/paper/phase_5_7:/workspace -w /workspace \
  texlive/texlive:latest \
  sh -c "pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex"
```

