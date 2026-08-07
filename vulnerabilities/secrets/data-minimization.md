---
id: "vuln.privacy.data-minimization"
title: "Excessive collection, retention or secondary use of sensitive data"
aliases: ["privacy leakage","data minimization","PII overcollection"]
summary: "The system collects, retains, exposes or reuses personal/sensitive data beyond the stated purpose or access boundary."
family: "information-secrets-privacy"
canonical_cwe: "CWE-359"
related_cwe: []
capec: []
owasp_mappings: ["A09:2025"]
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: ["LLM02:2025"]
applies_to: ["source code","configuration","architecture"]
surfaces: ["API","logs","analytics","RAG","mobile"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["web","cloud","mobile","ai"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["user input, telemetry, prompt/context or provider response"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["storage, logs, analytics, retrieval or model provider"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Whole request/context persisted","Retention not bounded","Purpose/tenant classification absent","Deletion/export path omits derived indexes and logs"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass excessive collection, retention or secondary use of sensitive data.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace user input, telemetry, prompt/context or provider response to storage, logs, analytics, retrieval or model provider across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/359.html"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:owasp-genai"]
last_reviewed: "2026-08-07"
---

# Excessive collection, retention or secondary use of sensitive data

Minimize fields, classify purpose/tenant, bound retention, propagate deletion, isolate derived data and make provider/log access auditable. Use synthetic privacy markers in tests.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.privacy.data-minimization`; canonical ontology entry: `CWE-359`.
