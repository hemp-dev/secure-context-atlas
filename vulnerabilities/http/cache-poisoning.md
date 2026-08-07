---
id: "vuln.http.cache-poisoning"
title: "Unsafe cache keying and cache poisoning"
aliases: ["web cache poisoning","cache confusion"]
summary: "A shared cache stores or serves a response under a key that omits security-relevant request state or accepts attacker-influenced metadata."
family: "http-proxy-cache"
canonical_cwe: "CWE-444"
related_cwe: []
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["HTTP","CDN","reverse proxy","browser"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["web","api","cdn"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request headers, query or host metadata"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["shared cache response"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Cache key excludes host/query/auth-relevant state","Unkeyed header changes response","Private response is stored as public"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass unsafe cache keying and cache poisoning.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request headers, query or host metadata to shared cache response across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://portswigger.net/web-security/web-cache-poisoning"]
source_provenance: ["sources/manifest.yaml:portswigger-academy"]
last_reviewed: "2026-08-07"
---

# Unsafe cache keying and cache poisoning

Cache integrity fails when the cache's identity model is weaker than the origin's response variability. Define cacheability, key all response-affecting state, and never share personalized or security-sensitive responses by default.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.http.cache-poisoning`; canonical ontology entry: `CWE-444`.
