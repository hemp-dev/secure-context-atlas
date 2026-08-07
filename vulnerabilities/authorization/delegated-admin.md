---
id: "vuln.authorization.delegated-admin"
title: "Delegated administration privilege escalation"
aliases: []
summary: "A delegated administrator receives a broader scope than the delegated resource, tenant, action or time window allows."
family: "authorization-access"
canonical_cwe: "CWE-269"
related_cwe: []
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["admin API","console","workflow"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["web","api","enterprise"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","The intended validation, authorization, isolation or resource control is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["role assignment, delegation request or group claim"],"transformations":["decode, normalize or parse input","application-specific routing or policy translation"],"controls":["validation, authorization, provenance or budget control if present"],"sinks":["privileged operation or policy update"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Role inheritance is implicit","Scope is checked at login but not at action time","Delegation can grant or revoke the delegator itself"]
configuration_signals: ["Configuration, default or error paths can bypass delegated administration privilege escalation.","Review identity, boundary, limit and failure settings for every alternate path."]
architecture_signals: ["Trace role assignment, delegation request or group claim to privileged operation or policy update across synchronous, asynchronous and provider boundaries.","Check whether a gateway-only control is assumed to protect internal or worker paths."]
audit_questions: ["What exact source and sink are reachable for Delegated administration privilege escalation?","Which control must run before the sink and where is its decision evidence?","Do retries, alternate protocols, error paths and tenant changes preserve the same control?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial, isolation, limit or safe encoding and inspect only test output; never use real credentials, public targets or destructive state."]
false_positives: ["A library, route or configuration name is only a signal; confirm reachability and the exact security-sensitive sink.","A compensating control may be implemented at a different layer; record its evidence before reporting a finding."]
impact: ["confidentiality, integrity or availability boundary failure","impact depends on asset, principal, tenant and blast radius"]
severity_factors: ["Severity increases with privilege, sensitivity, tenant count, persistence and external reachability."]
exploitability_factors: ["Reachability, input control and missing control evidence are required; use synthetic fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary and make the policy explicit.","Use least privilege, typed inputs, provenance and bounded resources across alternate and asynchronous paths.","Add telemetry that records the decision without storing secrets or sensitive content."]
secure_patterns: ["Deny by default with a typed, testable policy decision.","Isolate capabilities, bound time/size/fan-out and bind identity, tenant, destination and action."]
regression_tests: ["Create a local or staging synthetic fixture for Delegated administration privilege escalation; assert the control blocks or safely contains the unsafe path and records a redacted decision."]
related_vulnerabilities: []
references: ["https://cwe.mitre.org/data/definitions/269.html"]
source_provenance: ["sources/research-notes.md:normalized defensive topic","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-08"
maturity: "curated"
priority: "P1"
review_status: "reviewed"
fixture_ids: ["eval.delegated-admin.positive","eval.delegated-admin.negative"]
detector_refs: []
---

# Delegated administration privilege escalation

A delegated administrator receives a broader scope than the delegated resource, tenant, action or time window allows.

## Defensive audit note

Treat the named signal as a hypothesis. Confirm the reachable source, transformations, missing control and sink with code/configuration evidence before reporting a finding.

## Safe boundary

Verification belongs in a local or staging harness with synthetic data, canaries, mocks, bounded timeouts and no external side effects.

Canonical ID: `vuln.authorization.delegated-admin`; canonical ontology: `CWE-269`.
