---
id: "vuln.ai.unsafe-model-loading"
title: "Unsafe model, plugin or artifact loading"
aliases: ["model supply chain","unsafe pickle","LLM03","LLM04"]
summary: "A model, tokenizer, plugin, adapter or serialized artifact is loaded from an untrusted or mutable source and can execute code, alter behaviour or poison downstream decisions."
family: "ai-llm-rag-agents"
canonical_cwe: "CWE-502"
related_cwe: []
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: ["LLM03:2025","LLM04:2025"]
applies_to: ["source code","configuration","architecture"]
surfaces: ["MLOps","model registry","plugin","CI"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["ai","mlops","supply-chain","cloud"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["registry URI, model file, plugin metadata or training data"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["loader/deserializer, runtime import or inference pipeline"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Remote artifact loaded without hash/signature/provenance","Unsafe serialization format","Plugin executes in training/inference identity","Data lineage and evaluation absent"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass unsafe model, plugin or artifact loading.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace registry URI, model file, plugin metadata or training data to loader/deserializer, runtime import or inference pipeline across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/502.html","https://genai.owasp.org/llmrisk/llm03-supply-chain/"]
source_provenance: ["sources/manifest.yaml:owasp-genai","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Unsafe model, plugin or artifact loading

Pin and verify artifacts, prefer data-only formats, isolate loaders, restrict network/secrets, maintain provenance/SBOM and evaluate behaviour before promotion. Do not load unknown models in a production identity.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.ai.unsafe-model-loading`; canonical ontology entry: `CWE-502`.
