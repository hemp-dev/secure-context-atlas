---
id: "vuln.ai.rag-cross-tenant"
title: "RAG/vector retrieval cross-tenant disclosure"
aliases: ["vector store leakage","embedding access control","LLM02"]
summary: "Retrieval or context assembly returns documents, embeddings or metadata outside the caller's tenant, purpose or data classification boundary."
family: "ai-llm-rag-agents"
canonical_cwe: "CWE-639"
related_cwe: []
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: ["API1:2023","API3:2023"]
genai_mappings: ["LLM02:2025","LLM08:2025"]
applies_to: ["source code","configuration","architecture"]
surfaces: ["RAG","vector DB","search","multi-tenant"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["ai","rag","database","cloud"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["query, embedding, document metadata or filter"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["retriever/vector store/context window"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Tenant filter applied after retrieval","Embedding index lacks tenant partition","Cache key omits tenant/user","Model can cite or summarize hidden context"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass rag/vector retrieval cross-tenant disclosure.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace query, embedding, document metadata or filter to retriever/vector store/context window across synchronous, asynchronous, alternate-protocol and provider boundaries."]
audit_questions: ["What exact source and sink are reachable?","Which control should run before the sink?","Do alternate protocols, retries or error paths differ?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["The named library or endpoint is only a signal; confirm reachability and the exact sink."]
impact: ["security boundary bypass","confidentiality/integrity/availability impact"]
severity_factors: ["Severity depends on the asset, privilege and blast radius."]
exploitability_factors: ["Reachability and a controllable input are required; use test fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary.","Make policy explicit, deny by default and cover alternate/async paths.","Add telemetry and bounded failure behaviour."]
secure_patterns: ["Typed inputs and explicit policy checks.","Least privilege, isolation and bounded resource use."]
regression_tests: ["Add a local or staging negative test using a canary and assert the control blocks the unsafe sink."]
related_vulnerabilities: []
references: ["https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/","https://cwe.mitre.org/data/definitions/639.html"]
source_provenance: ["sources/manifest.yaml:owasp-genai","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# RAG/vector retrieval cross-tenant disclosure

Authorize retrieval before data enters model context. Partition or filter by tenant and purpose at the datastore boundary, bind cache keys to identity, minimize citations and test with synthetic cross-tenant canaries.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.ai.rag-cross-tenant`; canonical ontology entry: `CWE-639`.
