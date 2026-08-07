---
id: "vuln.serialization.unsafe-deserialization"
title: "Unsafe deserialization and object graph execution"
aliases: ["insecure deserialization","unsafe object deserialization"]
summary: "Untrusted serialized data is turned into objects or behaviour without a safe type allowlist, integrity check or isolated parser boundary."
family: "serialization-parsers"
canonical_cwe: "CWE-502"
related_cwe: ["CWE-915","CWE-1321"]
capec: ["CAPEC-586"]
owasp_mappings: ["A08:2025"]
asvs_mappings: ["V5"]
wstg_mappings: ["WSTG-INPV-12"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["API","queue","cache","session","file import"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","worker","runtime"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request, queue, cache or uploaded serialized value"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["deserializer, gadget-capable runtime or object rehydration"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Polymorphic type metadata enabled","Deserializer accepts arbitrary classes","Integrity/authenticity checked after deserialization","Object hooks execute during rehydration"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass unsafe deserialization and object graph execution.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request, queue, cache or uploaded serialized value to deserializer, gadget-capable runtime or object rehydration across synchronous, asynchronous, alternate-protocol and provider boundaries."]
audit_questions: ["What exact source and sink are reachable?","Which control should run before the sink?","Do alternate protocols, retries or error paths differ?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["The named library or endpoint is only a signal; confirm reachability and the exact sink."]
impact: ["security boundary bypass","confidentiality/integrity/availability impact"]
severity_factors: ["Severity depends on the asset, privilege and blast radius."]
exploitability_factors: ["Reachability and a controllable input are required; use test fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary.","Make policy explicit, deny by default and cover alternate/async paths.","Add telemetry and bounded failure behaviour."]
secure_patterns: ["Typed inputs and explicit policy checks.","Least privilege, isolation and bounded resource use."]
regression_tests: ["Add a local or staging negative test using a canary and assert the control blocks the unsafe sink."]
related_vulnerabilities: ["vuln.ai.unsafe-model-loading","vuln.serialization.prototype-pollution"]
references: ["https://cwe.mitre.org/data/definitions/502.html","https://portswigger.net/web-security/deserialization"]
source_provenance: ["sources/manifest.yaml:portswigger-academy","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Unsafe deserialization and object graph execution

Prefer data-only formats and explicit schemas. If object rehydration is required, use an allowlist, authenticated envelope, bounded depth/size and an isolated low-privilege process with no ambient secrets.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.serialization.unsafe-deserialization`; canonical ontology entry: `CWE-502`.
