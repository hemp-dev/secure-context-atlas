---
id: "vuln.injection.expression"
title: "Expression-language injection"
aliases: ["EL injection","SpEL","OGNL"]
summary: "Untrusted text is evaluated by an expression language with access to objects, methods or properties beyond the intended data model."
family: "injection"
canonical_cwe: "CWE-917"
related_cwe: ["CWE-94","CWE-20"]
capec: ["CAPEC-77"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V5"]
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["web","configuration","policy","workflow"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","worker"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request, configuration or model-generated expression"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["expression evaluator or policy engine"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Dynamic expression evaluation","Method/property access not allowlisted","Evaluation context contains services or secrets"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass expression-language injection.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request, configuration or model-generated expression to expression evaluator or policy engine across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/917.html"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:patt"]
last_reviewed: "2026-08-07"
---

# Expression-language injection

Prefer typed predicates and fixed policy definitions. If expressions are required, use a minimal allowlisted grammar and context with no ambient service, filesystem or network capability.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.injection.expression`; canonical ontology entry: `CWE-917`.
