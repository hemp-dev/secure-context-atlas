---
id: "vuln.information.logging"
title: "Sensitive information disclosure through logs and errors"
aliases: ["log leak","error disclosure","debug exposure"]
summary: "Sensitive values, credentials, personal data, prompts, retrieved documents or internal details cross into logs, traces, error responses or monitoring systems without minimization and access control."
family: "information-secrets-privacy"
canonical_cwe: "CWE-532"
related_cwe: []
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["API","logs","tracing","errors","AI telemetry"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","cloud","CI"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request, exception, prompt/context or secret"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["logger, trace exporter, error response or dashboard"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Full request/response logging","Stack traces returned to client","Prompt/RAG/tool content stored without classification","Redaction is regex-only and applied after serialization"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass sensitive information disclosure through logs and errors.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request, exception, prompt/context or secret to logger, trace exporter, error response or dashboard across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/532.html","https://owasp.org/Top10/2025/A09_2025-Logging_Alerting_Failures/"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:owasp-asvs"]
last_reviewed: "2026-08-07"
---

# Sensitive information disclosure through logs and errors

Classify and minimize telemetry, redact at source, separate security audit events from content logs, protect access/retention and test error paths with synthetic secrets and PII markers.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.information.logging`; canonical ontology entry: `CWE-532`.
