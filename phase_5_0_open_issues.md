# Phase 5.0 Open Issues and Manuscript Submission Preparation

This document catalogues all outstanding tasks, environment blockers, and documentation requirements necessary before transitioning the research prototype into a formal conference submission or open-source release.

---

## 1. Environment & Package Prerequisites

1. **Official SDK Installation:**
   - **Issue:** The official Python SDKs `mcp` (`anthropic/model-context-protocol`) and `langgraph` are uninstalled in the testing environment (`ModuleNotFoundError`).
   - **Impact:** MCP testing is currently conducted via custom OS child-process stdio pipes (`scratch/mcp_server_subprocess.py`), and LangGraph interrupt/checkpoint cycles are validated via in-memory dictionary state reloads.
   - **Action Needed:** Install `mcp` and `langgraph` in a clean virtual environment and execute end-to-end integration tests using the official SDK classes (`ClientSession`, `create_react_agent`, `MemorySaver`).

2. **Repository Packaging & Scaffolding:**
   - **Issue:** The repository lacks standard Python packaging files (`pyproject.toml`, `setup.cfg`, `requirements.txt`).
   - **Impact:** External researchers must manually configure `PYTHONPATH=src` to run tests and benchmarks.
   - **Action Needed:** Add `pyproject.toml` with build metadata, entry points for the gateway daemon, and dependency pins (`cryptography`, `pytest`).

3. **Workspace Segregation:**
   - **Issue:** The root directory contains 11 untracked academic course documents (`.docx`, `.pptx`) and reference PDFs alongside source code.
   - **Impact:** Pollutes the repository structure for public distribution.
   - **Action Needed:** Relocate coursework documents to an isolated `docs/coursework/` or archive folder prior to public Git staging.

---

## 2. Technical & Protocol Extensions

1. **Downstream Idempotency Contract Specification:**
   - **Issue:** SQLite worker fencing prevents stale workers from updating gateway authorization records, but cannot physically cancel packets in flight over the network.
   - **Action Needed:** Formalize an explicit downstream tool contract requiring tool providers to accept an `Idempotency-Key` HTTP header or JSON-RPC metadata field derived from `action_digest`.

2. **Remote MCP Transports (HTTP & Server-Sent Events):**
   - **Issue:** Current MCP adapter testing is restricted to local stdio communication over OS pipes.
   - **Action Needed:** Implement and test an asynchronous SSE/HTTP transport adapter for remote tool servers once outbound network access is authorized.

3. **Multi-Tenant Key Hierarchy & KMS Integration:**
   - **Issue:** The current prototype maintains public keys in an in-memory `KeyRegistry` class.
   - **Action Needed:** Provide pluggable KMS adapters (AWS KMS, GCP Cloud KMS, HashiCorp Vault) for production deployments managing enterprise signing keys.

---

## 3. Manuscript Polishing & Publication Roadmap

1. **Submission Target:**
   - Target conferences: ACM Conference on Computer and Communications Security (CCS 2026), Network and Distributed System Security Symposium (NDSS 2027), or IEEE Symposium on Security and Privacy (S&P 2027).
   - Workshop alternatives: AISec (ACM CCS), LLM Security Workshop (ICLR/NeurIPS).

2. **Camera-Ready Diagram Generation:**
   - Convert text-based Mermaid architecture diagrams into publication-quality vector graphics (SVG/PDF) using TikZ or Inkscape.

3. **Artifact Evaluation Badge Checklist:**
   - Prepare a Dockerfile containerizing Python 3.14, SQLite 3.46, and the complete 107-test regression suite.
   - Provide a one-step evaluation script `run_benchmarks.sh` reproducing all latency and throughput tables within 60 seconds.

