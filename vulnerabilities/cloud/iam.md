---
id: "vuln.cloud.iam"
title: "Cloud IAM over-privilege and resource-policy drift"
aliases: ["cloud IAM","public bucket","overprivileged role"]
summary: "A workload, user or resource policy grants more identity, network, data or control-plane capability than the intended task requires."
family: "cloud-containers-infra"
canonical_cwe: "CWE-732"
related_cwe: ["CWE-284","CWE-269"]
capec: ["CAPEC-1"]
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["cloud API","storage","metadata","serverless"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["cloud","IAM","storage"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request identity, workload role or resource policy"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["cloud control-plane/API or sensitive data store"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Wildcard actions/resources","Public or cross-account resource policy","Metadata credentials reachable from untrusted path","Environment role reused across services"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass cloud iam over-privilege and resource-policy drift.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request identity, workload role or resource policy to cloud control-plane/API or sensitive data store across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/732.html","https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:owasp-asvs"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Cloud IAM over-privilege and resource-policy drift

Model identity and resource policies together. Apply least privilege, condition keys, private endpoints, workload identity, credential rotation and continuous policy testing; remove ambient credentials from untrusted workers.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.cloud.iam`; canonical ontology entry: `CWE-732`.
