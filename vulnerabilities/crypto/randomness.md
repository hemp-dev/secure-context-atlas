---
id: "vuln.crypto.randomness"
title: "Predictable randomness or weak cryptographic usage"
aliases: ["predictable token","weak PRNG","nonce reuse"]
summary: "Security-sensitive tokens, keys, nonces or identifiers are generated or used with insufficient entropy, unsafe reuse or an inappropriate primitive."
family: "crypto-transport"
canonical_cwe: "CWE-338"
related_cwe: ["CWE-330","CWE-327"]
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["session","reset","CSRF","signature","key generation"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","mobile","firmware"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["time/user/process state or generated token"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["authentication, authorization or cryptographic verification"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Non-cryptographic RNG for security token","Nonce/IV reuse","Custom crypto or unchecked verification result","Key material derived from predictable state"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass predictable randomness or weak cryptographic usage.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace time/user/process state or generated token to authentication, authorization or cryptographic verification across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/338.html","https://cwe.mitre.org/data/definitions/330.html"]
source_provenance: ["sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# Predictable randomness or weak cryptographic usage

Use platform CSPRNGs and reviewed primitives, define nonce/key lifecycle, verify signatures before claims are trusted, and document entropy/rotation requirements.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.crypto.randomness`; canonical ontology entry: `CWE-338`.
