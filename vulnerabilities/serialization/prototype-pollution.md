---
id: "vuln.serialization.prototype-pollution"
title: "Prototype or class pollution across object merges"
aliases: ["prototype pollution","class pollution"]
summary: "Untrusted keys or object graphs alter shared prototypes, classes or inherited configuration that later code treats as trusted."
family: "serialization-parsers"
canonical_cwe: "CWE-1321"
related_cwe: []
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["JSON API","configuration","templating","request merge"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","browser","runtime"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["JSON/body/query keys or configuration fragments"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["deep merge, object assignment or class metadata"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Recursive merge accepts inherited/special keys","Default object prototypes are shared across requests","Polluted configuration reaches a sensitive sink"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass prototype or class pollution across object merges.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace JSON/body/query keys or configuration fragments to deep merge, object assignment or class metadata across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/1321.html"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:patt"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Prototype or class pollution across object merges

Use schema-driven parsing and own-property checks, reject special keys where applicable, avoid shared mutable prototypes, and keep configuration values typed before they reach security decisions.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.serialization.prototype-pollution`; canonical ontology entry: `CWE-1321`.
