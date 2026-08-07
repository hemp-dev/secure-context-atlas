---
id: "vuln.files.path-traversal"
title: "Path traversal and unsafe file resolution"
aliases: ["directory traversal","Zip Slip","path traversal"]
summary: "Untrusted path-like data changes the file selected or written outside the intended root after incomplete normalization or archive extraction."
family: "files-paths-storage"
canonical_cwe: "CWE-22"
related_cwe: ["CWE-23","CWE-36","CWE-73"]
capec: ["CAPEC-126","CAPEC-139"]
owasp_mappings: ["A01:2025"]
asvs_mappings: ["V12"]
wstg_mappings: ["WSTG-ATHZ-01"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["file download","archive extraction","template/file import"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","container","worker"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["path parameter, archive member name or filename"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["filesystem read/write"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Check-before-canonicalize order","String prefix check instead of resolved-path containment","Archive extraction trusts member names","Symlink or mount changes the effective root"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass path traversal and unsafe file resolution.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace path parameter, archive member name or filename to filesystem read/write across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/22.html","https://portswigger.net/web-security/file-path-traversal"]
source_provenance: ["sources/manifest.yaml:patt","sources/manifest.yaml:portswigger-academy","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# Path traversal and unsafe file resolution

Path safety is a canonicalization and containment property. Resolve against a fixed directory, enforce containment after resolution, reject links where appropriate, and use a dedicated low-privilege storage worker.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.files.path-traversal`; canonical ontology entry: `CWE-22`.
