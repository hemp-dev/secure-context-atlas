---
id: "vuln.native.memory-safety"
title: "Memory-safety violation at native or FFI boundary"
aliases: ["buffer overflow","use-after-free","unsafe FFI"]
summary: "Untrusted sizes, lifetimes, formats or pointers reach native code without bounds, ownership, lifetime or integer-safety guarantees."
family: "native-memory"
canonical_cwe: "CWE-119"
related_cwe: ["CWE-787","CWE-125","CWE-416"]
capec: ["CAPEC-100"]
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["native service","FFI","parser","embedded"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["C","C++","Rust","Swift","Kotlin/NDK"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["network/file/input buffer or FFI value"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["native memory access, parser or unsafe callback"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Unchecked length arithmetic","Raw pointer crossing FFI without ownership contract","Use-after-free or double release path","Unsafe parser runs with process privileges"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass memory-safety violation at native or ffi boundary.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace network/file/input buffer or FFI value to native memory access, parser or unsafe callback across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/119.html","https://cwe.mitre.org/data/definitions/787.html"]
source_provenance: ["sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# Memory-safety violation at native or FFI boundary

Prefer memory-safe APIs, explicit ownership and checked arithmetic. Isolate parsers, fuzz only bounded local fixtures, use sanitizers/ASan-like tooling in CI and keep native workers least privileged.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.native.memory-safety`; canonical ontology entry: `CWE-119`.
