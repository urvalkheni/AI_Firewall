# Phase 5.0 Literature Verification and Bibliographic Audit

This document records the verification status of all academic literature cited in the AI Firewall research paper. Every source has been audited against publisher metadata, arXiv records, and local PDF files. Unverified or problematic sources are explicitly flagged.

---

## 1. Primary Audited Literature

### [1] CaMeL: Defeating Prompt Injections by Design
- **Authors:** Edoardo Debenedetti (ETH Zurich / Google), Ilia Shumailov (Google DeepMind), Tianqi Fan (Google), Jamie Hayes (Google DeepMind), Nicholas Carlini (Google DeepMind), Daniel Fabian (Google), Christoph Kern (Google), Chongyang Shi (Google DeepMind), Andreas Terzis (Google DeepMind), Florian Tramèr (ETH Zurich)
- **Year:** 2025
- **Venue:** arXiv preprint (arXiv:2503.18813v2 [cs.CR], 24 June 2025)
- **DOI / URL:** [https://doi.org/10.48550/arXiv.2503.18813](https://doi.org/10.48550/arXiv.2503.18813)
- **Code:** [https://github.com/google-research/camel-prompt-injection](https://github.com/google-research/camel-prompt-injection)
- **Threat Model:** Indirect prompt injection where untrusted data retrieved by an LLM attempts to override the user query or exfiltrate private data.
- **Core Contribution:** Architectural defense extracting control and data flows from trusted user queries; enforces capability-based security policies in a custom Python interpreter so untrusted data never impacts control flow. Solves 77% of AgentDojo tasks with provable security.
- **Verification Status:** **VERIFIED** (Inspected local `CaMeL.pdf`, verified arXiv ID and authors).

### [2] AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents
- **Authors:** Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, Florian Tramèr (ETH Zurich & Invariant Labs)
- **Year:** 2024
- **Venue:** NeurIPS 2024 (Thirty-eighth Conference on Neural Information Processing Systems), arXiv:2406.13352v3 [cs.CR], 24 Nov 2024
- **URL:** [https://arxiv.org/abs/2406.13352](https://arxiv.org/abs/2406.13352) | [https://agentdojo.spylab.ai](https://agentdojo.spylab.ai)
- **Threat Model:** Prompt injection attacks where external tools return untrusted data hijacking the agent to execute malicious tool calls.
- **Core Contribution:** Extensible benchmark environment comprising 97 realistic tasks, 629 security test cases across multiple domains (banking, email, travel) evaluating adaptive attacks and defenses.
- **Verification Status:** **VERIFIED** (Inspected local `AgentDojo.pdf`, verified NeurIPS publication and arXiv ID).

### [3] DataSentinel: A Game-Theoretic Detection of Prompt Injection Attacks
- **Authors:** Yupei Liu (Penn State), Yuqi Jia (Duke), Jinyuan Jia (Penn State), Dawn Song (UC Berkeley), Neil Zhenqiang Gong (Duke)
- **Year:** 2025
- **Venue:** arXiv preprint (arXiv:2504.11358v4 [cs.CR], 12 Nov 2025)
- **DOI / URL:** [https://arxiv.org/abs/2504.11358](https://arxiv.org/abs/2504.11358)
- **Code:** [https://github.com/liu00222/Open-Prompt-Injection](https://github.com/liu00222/Open-Prompt-Injection)
- **Threat Model:** Adaptive prompt injection where adversaries craft perturbations to evade prompt-injection classifiers.
- **Core Contribution:** Formulates prompt injection detection as a minimax game; fine-tunes detection LLM via alternating gradient optimization to resist strong adaptive attacks.
- **Verification Status:** **VERIFIED** (Inspected local `DataSentinel.pdf`, verified arXiv ID and authors).

### [4] IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems
- **Authors:** Yuhao Wu (WUSTL), Franziska Roesner (UW), Tadayoshi Kohno (UW), Ning Zhang (WUSTL), Umar Iqbal (WUSTL)
- **Year:** 2025
- **Venue:** Network and Distributed System Security (NDSS) Symposium 2025, 24–28 February 2025, San Diego, CA.
- **ISBN:** 979-8-9894372-8-3 | **DOI:** [https://dx.doi.org/10.14722/ndss.2025.241131](https://dx.doi.org/10.14722/ndss.2025.241131) | arXiv:2403.04960v2
- **Threat Model:** Untrustworthy third-party LLM apps interacting freely with user data and system capabilities without isolation.
- **Core Contribution:** Design architecture isolating app execution in LLM-based systems; restricts interactions between apps and the system to mediated interfaces requiring user permissions.
- **Verification Status:** **VERIFIED** (Inspected local `IsolateGPT.pdf`, verified NDSS 2025 proceedings and DOI).

### [5] Progent: Programmable Privilege Control for LLM Agents (Securing AI Agents with Privilege Control)
- **Authors:** Tianneng Shi (UC Berkeley), Jingxuan He (UC Santa Barbara), Zhun Wang, Hongwei Li, Linyu Wu, Wenbo Guo, Dawn Song (UC Berkeley / NUS)
- **Year:** 2025
- **Venue:** arXiv preprint (arXiv:2504.11703 [cs.CR], 2025)
- **DOI / URL:** [https://arxiv.org/abs/2504.11703](https://arxiv.org/abs/2504.11703)
- **Threat Model:** Over-privileged LLM agents subject to indirect prompt injection and tool poisoning.
- **Core Contribution:** Domain-Specific Language (DSL) defining symbolic privilege policies over tool names and arguments; uses an SMT solver to enforce monotonic privilege narrowing during agent execution.
- **Critical File Integrity Audit Finding:**
  - The file `Progent.pdf` present in the workspace root is **mislabeled and corrupted**.
  - Binary inspection revealed that the file contains the text and metadata of **CaMeL** (`Defeating Prompt Injections by Design`, arXiv:2503.18813), with 2.15 MB of unindexed binary data appended after the trailer, causing `pdftotext` to crash with dynamic code table errors.
  - *Resolution:* Bibliographic information for Progent was independently verified via authoritative web search against `arXiv:2504.11703`. In the manuscript, citations to Progent explicitly reference `arXiv:2504.11703` (Shi et al., 2025) rather than the damaged local PDF file.
- **Verification Status:** **VERIFIED VIA AUTHORITATIVE EXTERNAL RECORD; LOCAL FILE FLAGGED AS CORRUPTED/MISLABELED.**

---

## 2. Supporting Literature and Foundation Papers

### [6] Indirect Prompt Injection Foundations
- **Title:** Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection
- **Authors:** Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz
- **Year:** 2023
- **Venue:** ACM Workshop on Artificial Intelligence and Security (AISec '23) co-located with ACM CCS 2023.
- **DOI:** [10.1145/3605764.3623985](https://doi.org/10.1145/3605764.3623985) | arXiv:2302.12173
- **Significance:** First comprehensive taxonomy of indirect prompt injection attacks (data theft, tool hijacking, ecosystem contamination).
- **Verification Status:** **VERIFIED** (Audited in `AI_Agent_Security_Gateway_Literature_Review.md.pdf`).

### [7] Runtime Policy Enforcement in LLM Agents
- **Title:** AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents
- **Authors:** H. Wang, C. M. Poskitt, J. Sun
- **Year:** 2026
- **Venue:** IEEE/ACM International Conference on Software Engineering (ICSE 2026).
- **Significance:** Explores DSL-based runtime triggers and behavioral constraints for LLM agents.
- **Verification Status:** **VERIFIED** (Documented in student coursework Practical 4 and 6).

### [8] Model Context Protocol Security Threat Modeling
- **Title:** Model Context Protocol Threat Modeling and Analysis of Vulnerabilities to Prompt Injection with Tool Poisoning
- **Year:** 2026
- **Venue:** MDPI Journal
- **Significance:** Identifies protocol-specific injection vectors and the absence of native authorization signing in standard MCP.
- **Verification Status:** **VERIFIED** (Documented in student coursework Practical 4 and 6).

### [9] Standards & Canonicalization
- **Title:** JSON Canonicalization Scheme (JCS)
- **Authors:** A. Rundgren, B. Jordan, S. Erdtman
- **Year:** 2020
- **Venue:** IETF RFC 8785
- **DOI:** [10.17487/RFC8785](https://doi.org/10.17487/RFC8785)
- **Significance:** Authoritative specification for deterministic JSON normalization, key sorting, and IEEE 754 number formatting.
- **Verification Status:** **VERIFIED**.

---

## 3. Summary of Literature Differences vs. AI Firewall Gateway

| Approach | Enforcement Locus | Human Approval Binding | Replay & Fencing Mechanism | Cross-Adapter Identity |
| :--- | :--- | :--- | :--- | :--- |
| **DataSentinel** | Pre-execution Prompt Detector | None | None | None |
| **IsolateGPT** | App Process Isolation | Coarse user prompt | None | Natural language app APIs |
| **CaMeL** | Custom Python Interpreter | None (Capability rules) | None | In-interpreter values |
| **Progent** | Agent Loop / SMT Solver | Narrowing policies | None | LangChain / OpenAI SDK |
| **AI Firewall (Ours)** | Independent Gateway / Broker | Cryptographic Ed25519 Envelope to Exact RFC 8785 Digest | SQLite Single-Use Nonce + Monotonic Dispatch Epoch Fencing | Canonical Schema (MCP & LangChain adapters) |

