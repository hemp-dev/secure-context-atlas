---
id: "vuln.ai.output-handling"
title: "Unsafe handling of model output at downstream sinks"
aliases: ["LLM05","improper output handling"]
summary: "Model output is treated as trusted markup, query text, code, routing metadata or tool arguments without schema validation and contextual encoding."
family: "ai-llm-rag-agents"
canonical_cwe: "CWE-116"
related_cwe: ["CWE-79","CWE-601"]
capec: ["CAPEC-63"]
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: ["LLM05:2025","ASI02","ASI05"]
applies_to: ["source code","configuration","architecture"]
surfaces: ["LLM","API","HTML","SQL","shell","workflow"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["ai","web","api","worker"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["model output or tool result"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["HTML/DOM, SQL, shell, URL, parser, workflow or user notification"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Free-form output fed to a privileged parser","Structured output schema not enforced","Output displayed without context encoding","Model-generated URL/command accepted as authority"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass unsafe handling of model output at downstream sinks.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace model output or tool result to HTML/DOM, SQL, shell, URL, parser, workflow or user notification across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://genai.owasp.org/llmrisk/llm05-improper-output-handling/","https://cwe.mitre.org/data/definitions/116.html"]
source_provenance: ["sources/manifest.yaml:owasp-genai","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Unsafe handling of model output at downstream sinks

Treat model output as untrusted input. Use typed schemas, allowlisted enums, contextual encoding, dry-run and human approval for side effects; separate generation from execution.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.ai.output-handling`; canonical ontology entry: `CWE-116`.
