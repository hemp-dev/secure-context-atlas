# Compact context for retrieval

Canonical ontology: MITRE CWE 4.20 (`ai/cwe-index.json`, 969 imported entries; 944 active). CAPEC 3.9 is a separate attack-pattern layer (`ai/capec-index.json`).

Core audit equation: `SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK`. A report needs evidence of reachability, a missing/ineffective control, preconditions, impact and a regression test.

High-yield families: authorization/tenant isolation; authentication/session/OAuth/JWT; injection and parsers; browser/client; HTTP proxy/cache/desync; SSRF; paths/uploads/archives; unsafe deserialization; workflows/races/resource limits; secrets/crypto/privacy; configuration/fail-open; API protocols; dependencies/CI/SCM; native memory; cloud/Kubernetes/serverless; mobile; AI/LLM/RAG/agents/MCP; internal enterprise; hardware/firmware/IoT; Web3.

AI-specific control rule: untrusted text, retrieved documents, tool output and model output are data, not authority. Use typed schemas, provenance, separate instruction/data channels, least-privilege capabilities, explicit destination/argument authorization, confirmation for high-impact actions, quotas, timeouts, isolation and audit logs.

Safe verification: test users/tenants, canary markers, local or staging fixtures, mocks, negative assertions, bounded timeouts and synthetic data. Never use real secrets, destructive state, persistence, stealth, public scanning or exfiltration.

Retrieval note: `ai/aliases.json` records alias-to-ID collisions explicitly. Resolve an ambiguous alias such as `XXE` with parser/context evidence before selecting a card; never let an alias alone create a finding.

Release 0.5.0 adds `ai/maturity-map.json`, `evals/manifest.json`, the `sctx` context-pack CLI and SARIF export. Use maturity to distinguish inventory-only records from curated cards; use the evaluation suite as a deterministic retrieval regression, not as proof of a model's correctness.
