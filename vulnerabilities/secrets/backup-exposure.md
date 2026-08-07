---
id: "vuln.secrets.backup-exposure"
title: "Backup, snapshot and export exposure"
aliases: []
summary: "Backups or exports retain sensitive data with weaker access, retention, encryption or tenant isolation controls than the primary store."
family: "information-secrets-privacy"
canonical_cwe: "CWE-530"
related_cwe: []
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["backup","snapshot","export"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["cloud","database","storage"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","The intended validation, authorization, isolation or resource control is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["backup job, snapshot or export request"],"transformations":["decode, normalize or parse input","application-specific routing or policy translation"],"controls":["validation, authorization, provenance or budget control if present"],"sinks":["archive, snapshot store or restore path"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Backup bucket uses different policy","Encryption key scope is broader","Deletion policy excludes derived backups"]
configuration_signals: ["Configuration, default or error paths can bypass backup, snapshot and export exposure.","Review identity, boundary, limit and failure settings for every alternate path."]
architecture_signals: ["Trace backup job, snapshot or export request to archive, snapshot store or restore path across synchronous, asynchronous and provider boundaries.","Check whether a gateway-only control is assumed to protect internal or worker paths."]
audit_questions: ["What exact source and sink are reachable for Backup, snapshot and export exposure?","Which control must run before the sink and where is its decision evidence?","Do retries, alternate protocols, error paths and tenant changes preserve the same control?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial, isolation, limit or safe encoding and inspect only test output; never use real credentials, public targets or destructive state."]
false_positives: ["A library, route or configuration name is only a signal; confirm reachability and the exact security-sensitive sink.","A compensating control may be implemented at a different layer; record its evidence before reporting a finding."]
impact: ["confidentiality, integrity or availability boundary failure","impact depends on asset, principal, tenant and blast radius"]
severity_factors: ["Severity increases with privilege, sensitivity, tenant count, persistence and external reachability."]
exploitability_factors: ["Reachability, input control and missing control evidence are required; use synthetic fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary and make the policy explicit.","Use least privilege, typed inputs, provenance and bounded resources across alternate and asynchronous paths.","Add telemetry that records the decision without storing secrets or sensitive content."]
secure_patterns: ["Deny by default with a typed, testable policy decision.","Isolate capabilities, bound time/size/fan-out and bind identity, tenant, destination and action."]
regression_tests: ["Create a local or staging synthetic fixture for Backup, snapshot and export exposure; assert the control blocks or safely contains the unsafe path and records a redacted decision."]
related_vulnerabilities: []
references: ["https://cwe.mitre.org/data/definitions/530.html"]
source_provenance: ["sources/research-notes.md:normalized defensive topic","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-08"
maturity: "curated"
priority: "P1"
review_status: "reviewed"
fixture_ids: ["eval.backup-exposure.positive","eval.backup-exposure.negative"]
detector_refs: []
---

# Backup, snapshot and export exposure

Backups or exports retain sensitive data with weaker access, retention, encryption or tenant isolation controls than the primary store.

## Defensive audit note

Treat the named signal as a hypothesis. Confirm the reachable source, transformations, missing control and sink with code/configuration evidence before reporting a finding.

## Safe boundary

Verification belongs in a local or staging harness with synthetic data, canaries, mocks, bounded timeouts and no external side effects.

Canonical ID: `vuln.secrets.backup-exposure`; canonical ontology: `CWE-530`.
