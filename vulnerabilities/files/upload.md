---
id: "vuln.files.upload"
title: "Unrestricted file upload and unsafe media processing"
aliases: ["unrestricted upload","polyglot upload"]
summary: "An untrusted actor can store or process a file whose type, name, size or parser behaviour exceeds the intended upload contract."
family: "files-paths-storage"
canonical_cwe: "CWE-434"
related_cwe: ["CWE-20","CWE-22","CWE-79"]
capec: ["CAPEC-43"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V12"]
wstg_mappings: ["WSTG-BUSL-08"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["file upload","image/PDF import","object storage"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["web","api","worker"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["multipart body, object key or remote import"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["filesystem/object storage/media parser/browser delivery"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Trust MIME type or filename alone","Upload directory executable or same-origin","Parser runs with service privileges","No size/complexity/quota limit"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass unrestricted file upload and unsafe media processing.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace multipart body, object key or remote import to filesystem/object storage/media parser/browser delivery across synchronous, asynchronous, alternate-protocol and provider boundaries."]
audit_questions: ["What exact source and sink are reachable?","Which control should run before the sink?","Do alternate protocols, retries or error paths differ?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["The named library or endpoint is only a signal; confirm reachability and the exact sink."]
impact: ["security boundary bypass","confidentiality/integrity/availability impact"]
severity_factors: ["Severity depends on the asset, privilege and blast radius."]
exploitability_factors: ["Reachability and a controllable input are required; use test fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary.","Make policy explicit, deny by default and cover alternate/async paths.","Add telemetry and bounded failure behaviour."]
secure_patterns: ["Typed inputs and explicit policy checks.","Least privilege, isolation and bounded resource use."]
regression_tests: ["Add a local or staging negative test using a canary and assert the control blocks the unsafe sink."]
related_vulnerabilities: ["vuln.files.path-traversal","vuln.injection.xxe"]
references: ["https://cwe.mitre.org/data/definitions/434.html","https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"]
source_provenance: ["sources/manifest.yaml:patt","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Unrestricted file upload and unsafe media processing

Uploads need independent validation, storage isolation and safe processing. Treat filename, MIME and content as untrusted; re-encode where appropriate, serve from a separate origin, and scan/parse in a least-privilege bounded worker.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.files.upload`; canonical ontology entry: `CWE-434`.
