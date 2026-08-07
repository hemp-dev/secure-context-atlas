---
id: "vuln.secrets.hardcoded"
title: "Hardcoded secrets and secret residue"
aliases: ["hardcoded secret","credential in source","secret leak"]
summary: "A credential, private key, token or sensitive connection value is embedded in source, configuration, logs, test fixtures or build artifacts beyond its intended exposure."
family: "information-secrets-privacy"
canonical_cwe: "CWE-798"
related_cwe: ["CWE-259","CWE-321","CWE-522"]
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["source","config","CI","logs","artifact"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["repository","build","runtime"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["source/config/log/artifact content"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["authentication, cloud API or downstream connection"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Literal token/secret-like value","Secret copied into image, bundle or log","Test fixture uses a real-looking credential","Rotation cannot identify all copies"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass hardcoded secrets and secret residue.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace source/config/log/artifact content to authentication, cloud API or downstream connection across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/798.html","https://github.com/gitleaks/gitleaks"]
source_provenance: ["sources/manifest.yaml:gitleaks","sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:seclists"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Hardcoded secrets and secret residue

Remove and rotate exposed credentials, use a managed secret store or short-lived identity, prevent secret logging and scan history/artifacts. A scanner match must be triaged for reachability and validity.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.secrets.hardcoded`; canonical ontology entry: `CWE-798`.
