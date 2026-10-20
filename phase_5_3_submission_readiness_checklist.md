# Phase 5.3 Submission-Readiness Checklist

This checklist defines the prioritized requirements necessary before (A) proceeding to LaTeX typesetting and (B) submitting to an academic conference (e.g., ACM CCS, NDSS, or IEEE S&P).

---

## 1. Typesetting Gate (Ready for Conversion to LaTeX)

| Item ID | Verification Item | Target Status | Audit Assessment & Evidence | Status |
| :---: | :--- | :---: | :--- | :---: |
| **TS-01** | Population Disentanglement | Mandatory | The 46-scenario benchmark (31 attacks, 15 benign) is cleanly separated from the 107-test unit regression suite in Abstract and Section 6. | **PASS** |
| **TS-02** | Exact Statistical Intervals | Mandatory | Clopper-Pearson 95% confidence intervals are included for all attack blocking and utility rates ([88.8%, 100.0%] for 31/31, [78.2%, 100.0%] for 15/15). | **PASS** |
| **TS-03** | Architectural Precision | Mandatory | Manager-owned thread connection registry (`self._thread_conns`) is accurately described without claiming `threading.local()`. | **PASS** |
| **TS-04** | Quantile Indexing Convention | Mandatory | Stated as nearest-rank quantile ($P_k = S[\lfloor n \cdot k \rfloor]$ on zero-indexed array of length $n$). Exactly reproduces 0.8325 ms (P95) and 0.9679 ms (P99). | **PASS** |
| **TS-05** | Downstream Boundary Formalization | Mandatory | Boundary condition $\text{Gateway Fencing} \neq \text{End-to-End Exactly-Once}$ is explicitly stated in Abstract and Section 7.2. | **PASS** |
| **TS-06** | Integration Classification Grounding | Mandatory | Real child-process stdio pipes (MCP) and simulated checkpoint reloads (LangGraph) are accurately categorized, with missing pip packages disclosed. | **PASS** |
| **TS-07** | Bibliographic Verification | Mandatory | All 10 references verified; CaMeL, AgentDojo, DataSentinel, IsolateGPT, and Progent citations audited; local `Progent.pdf` corruption documented. | **PASS** |
| **TS-08** | Internal Numbering Consistency | Mandatory | All 7 figures and tables are numbered sequentially, captioned, and referenced in prose; section headings follow standard academic structure. | **PASS** |

**Typesetting Gate Verdict:** **READY FOR TYPESETTING.** The manuscript text in `AI_Firewall_Research_Paper_Phase_5_2_Corrected.md` is scientifically sound, mathematically verified, and ready for translation into an ACM/IEEE LaTeX template.

---

## 2. Conference Submission Gate (Pre-Submission Requirements)

| Item ID | Verification Item | Target Status | Assessment & Required Action | Status |
| :---: | :--- | :---: | :--- | :---: |
| **SUB-01**| Formal LaTeX Template Formatting | Mandatory | Typeset into ACM `acmart` (sigconf) or IEEE conference template with vector figures (TikZ or SVG/PDF) replacing ASCII art. | **PENDING CONVERSION** |
| **SUB-02**| Author & Affiliation Anonymization | Mandatory | For double-blind peer review venues (CCS, NDSS, S&P), remove student name ("Urval Kheni"), roll number ("24CE055"), and institutional affiliation ("CHARUSAT / CSPIT"). | **PENDING ANONYMIZATION** |
| **SUB-03**| Repository Scaffolding & Packaging | Mandatory | Provide `pyproject.toml` or `setup.py` so reviewers can install the package cleanly via `pip install -e .` without manual `PYTHONPATH` manipulation. | **PENDING SCAFFOLDING** |
| **SUB-04**| Coursework Separation | Mandatory | Move untracked `.docx` and `.pptx` coursework assignments from repository root into an unindexed `docs/coursework/` subfolder. | **PENDING SEPARATION** |
| **SUB-05**| Artifact Evaluation Dockerfile | Recommended | Create a reproducible Docker container bundling Python 3.14, SQLite 3.46, and a single-step reproduction script (`run_all_evaluations.sh`). | **RECOMMENDED** |

---

## 3. Post-Submission Experimental Extensions (Future Work Track)

| Item ID | Future Extension Item | Priority | Scope & Technical Objective |
| :---: | :--- | :---: | :--- |
| **EXT-01**| Official Third-Party Framework Testing | Medium | Install official `mcp` and `langgraph` pip packages in an isolated environment and run live multi-agent tool loops. |
| **EXT-02**| Remote HTTP / SSE MCP Transports | Medium | Implement and evaluate asynchronous Server-Sent Events (SSE) and HTTP streaming transports for remote MCP tool servers. |
| **EXT-03**| Enterprise KMS Adapter | Low | Implement pluggable Key Management System (KMS) adapters (AWS KMS, GCP Cloud KMS, HashiCorp Vault) for production key rotation. |
| **EXT-04**| Multi-Tenant Rate Limiting | Low | Evaluate gateway performance under saturated multi-agent burst traffic with token-bucket rate limiters. |

