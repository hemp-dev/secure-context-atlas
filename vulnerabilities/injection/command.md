---
id: "vuln.injection.command"
title: "OS command injection"
aliases: ["shell injection","process argument injection"]
summary: "Untrusted data changes a process command or argument at a shell/process execution sink."
family: "injection"
canonical_cwe: "CWE-78"
related_cwe: ["CWE-78","CWE-20"]
capec: ["CAPEC-77"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V5"]
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["web","job","automation","agent tool"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","worker","container"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request, file, environment or model/tool argument"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["OS process execution"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Shell command built by concatenation","Argument boundary lost through a shell","Process inherits secrets or broad filesystem/network access"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass os command injection.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request, file, environment or model/tool argument to OS process execution across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/78.html"]
source_provenance: ["sources/manifest.yaml:patt","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# OS command injection

Pass a fixed executable and typed argument vector to a process API, avoid shell interpretation, validate allowed operations, and isolate the worker with no ambient secrets.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.injection.command`; canonical ontology entry: `CWE-78`.
