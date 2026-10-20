# Phase 5.7: External Compilation Handoff and Readiness Checklist

**Audit Date:** October 13, 2026  
**Auditor:** Academic LaTeX Typesetter & Release Engineer  
**Repository:** `/home/shadow777/Github/AI_Firewall`  
**Candidate Directory:** `paper/phase_5_7/`  
**Candidate Package:** `paper/phase_5_7/ai_firewall_submission_candidate.zip`  
**Phase 5.7 Official Verdict:** **BLOCKED** (Compilation and rendered visual audit pending external build execution)

---

## 1. Readiness Matrix

| Requirement | Evaluation Criterion | Status | Notes |
| :--- | :--- | :--- | :--- |
| **1. Isolated Candidate Source** | Candidate files prepared in `paper/phase_5_7/` | **PASS** | `main.tex` and `references.bib` created. Phase 5.4 preserved. |
| **2. AgentSpec Integration** | Substantive discussion and citation added to Section 2.2 | **PASS** | Wang et al. (AgentSpec) cited in Section 2.2 & 2.3; 10/10 keys cited. |
| **3. Minimal Submission Archive** | `ai_firewall_submission_candidate.zip` generated | **PASS** | 2 files only (43,482 bytes); zero student coursework files. |
| **4. Double-Blind Anonymization** | Anonymized author, institution, no leaked tokens | **PASS** | Zero identifying tokens across `paper/phase_5_7/`. |
| **5. Mathematical Formulations** | 6 display equations match Phase 5.2 baseline | **PASS** | Action identity, hash, risk score, envelope, wire boundary. |
| **6. Microbenchmark Provenance** | Table 3 matches Phase 4.11 hardened data | **PASS** | Median 0.5643 ms, P95 0.8325 ms, P99 0.9679 ms, 1,716.4 ops/s. |
| **7. 46-Scenario Benchmark** | 31/31 attacks blocked, CIs verified | **PASS** | Clopper-Pearson CIs $[88.8\%, 100.0\%]$ and $[78.2\%, 100.0\%]$. |
| **8. 107 Unit Regression Tests** | Distinct from 46-scenario evaluation | **PASS** | Preserved across separate subsections. |
| **9. Quantile Formula Disclosure** | $P_k = S[\lfloor n \cdot k \rfloor]$ disclosed in Table 3 caption | **PASS** | Transparent mathematical disclosure. |
| **10. Static LaTeX Syntax** | 483 balanced braces, 38 matched envs, 7 labels | **PASS** | 0 static errors. |
| **11. Local Host Compilation** | `pdflatex` compilation on research machine | **BLOCKED** | Host lacks TeX distribution; no package install permitted. |
| **12. Rendered PDF Visual Inspection** | Visual inspection of rendered PDF pixels/glyphs | **BLOCKED** | Pending external user compilation. |

---

## 2. User Handoff Guide for External Compilation

Because the research environment lacks a TeX distribution and installing system packages was prohibited, follow one of the three options below to compile the final PDF.

### Option 1: Overleaf (Fastest & Recommended)
1. Navigate to **[Overleaf.com](https://www.overleaf.com)** and sign in.
2. Click **New Project** $\rightarrow$ **Upload Project**.
3. Select and upload the file:
   `/home/shadow777/Github/AI_Firewall/paper/phase_5_7/ai_firewall_submission_candidate.zip`
4. In the Overleaf project menu (top left gear icon), verify:
   - **Compiler:** `pdfLaTeX`
   - **TeX Live version:** `2024` (or `2025`)
   - **Main document:** `main.tex`
5. Click **Recompile**.
6. Download the resulting `main.pdf`.

### Option 2: Isolated Docker Command (if Docker is available on an external machine)
```bash
docker run --rm \
  -v /home/shadow777/Github/AI_Firewall/paper/phase_5_7:/workspace \
  -w /workspace \
  texlive/texlive:latest \
  sh -c "pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex"
```

### Option 3: Local Command Line (on any workstation with TeX Live)
```bash
cd /home/shadow777/Github/AI_Firewall/paper/phase_5_7
pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
```

---

## 3. Post-Compilation PDF Verification Steps

Once `main.pdf` is generated:
1. **Place the compiled PDF in `paper/phase_5_7/main.pdf`**.
2. **Record SHA-256 Hash and Size:**
   ```bash
   sha256sum paper/phase_5_7/main.pdf
   ls -lh paper/phase_5_7/main.pdf
   ```
3. **Verify Visual Formatting:**
   - Confirm review-mode line numbering appears in the outer margins.
   - Confirm Tables 1 and 2 span both columns cleanly without clipping the right margin.
   - Confirm Figures 1, 2, and 3 render crisp vector text and distinct box boundaries.
   - Confirm all 10 references appear in the References section.
4. **Metadata Sanitization:**
   ```bash
   pdfinfo paper/phase_5_7/main.pdf
   ```
   Confirm that the `Author:` field does not contain personal or institutional metadata.

---

## 4. Official Phase 5.7 Verdict

### **VERDICT: BLOCKED**

**Rationale:** In accordance with the phase instructions (*"This phase must produce an actual compiled PDF to pass. Static syntax checks alone are insufficient. If manual compilation is required, clearly mark compilation and PDF inspection as pending until the generated PDF is returned or otherwise made accessible"*), the status is officially recorded as **BLOCKED** pending external PDF compilation by the user.

All preparation, sanitization, evidence verification, and candidate packaging tasks are 100% complete.

