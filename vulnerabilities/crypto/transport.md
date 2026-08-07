---
id: "vuln.crypto.transport"
title: "Cleartext or unauthenticated transport of sensitive data"
aliases: ["cleartext transmission","TLS misconfiguration"]
summary: "Sensitive data or credentials cross a network without authenticated confidentiality/integrity or with downgrade/hostname-validation controls disabled."
family: "crypto-transport"
canonical_cwe: "CWE-319"
related_cwe: []
capec: []
owasp_mappings: ["A04:2025"]
asvs_mappings: ["V9"]
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["HTTP","database","message","mobile","internal service"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["web","api","cloud","mobile","iot"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request, secret or service message"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["socket, proxy, database or provider connection"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["TLS disabled/optional","Certificate/hostname verification skipped","Legacy protocol fallback","Sensitive endpoint accessible over cleartext"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass cleartext or unauthenticated transport of sensitive data.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request, secret or service message to socket, proxy, database or provider connection across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/319.html"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:owasp-asvs"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Cleartext or unauthenticated transport of sensitive data

Require modern authenticated transport, validate peer identity, disable insecure fallback, document trust stores and test endpoint/proxy/mobile configurations separately.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.crypto.transport`; canonical ontology entry: `CWE-319`.
