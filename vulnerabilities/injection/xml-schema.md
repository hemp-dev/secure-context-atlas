---
id: "vuln.injection.xml-schema"
title: "XML schema and entity processing ambiguity"
aliases: []
summary: "XML parser configuration differs across paths, allowing external entities, expansive structures or schema assumptions to change the interpreted document."
family: "injection"
canonical_cwe: "CWE-611"
related_cwe: []
capec: []
owasp_mappings: ["A05:2025"]
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["XML","SOAP","file import"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["web","api","worker"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","The intended validation, authorization, isolation or resource control is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["XML body, upload or provider response"],"transformations":["decode, normalize or parse input","application-specific routing or policy translation"],"controls":["validation, authorization, provenance or budget control if present"],"sinks":["XML parser, resolver or schema validator"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["DTD/entity processing varies by library","Validation occurs after parsing","Resolver can reach network or local resources"]
configuration_signals: ["Configuration, default or error paths can bypass xml schema and entity processing ambiguity.","Review identity, boundary, limit and failure settings for every alternate path."]
architecture_signals: ["Trace XML body, upload or provider response to XML parser, resolver or schema validator across synchronous, asynchronous and provider boundaries.","Check whether a gateway-only control is assumed to protect internal or worker paths."]
audit_questions: ["What exact source and sink are reachable for XML schema and entity processing ambiguity?","Which control must run before the sink and where is its decision evidence?","Do retries, alternate protocols, error paths and tenant changes preserve the same control?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial, isolation, limit or safe encoding and inspect only test output; never use real credentials, public targets or destructive state."]
false_positives: ["A library, route or configuration name is only a signal; confirm reachability and the exact security-sensitive sink.","A compensating control may be implemented at a different layer; record its evidence before reporting a finding."]
impact: ["confidentiality, integrity or availability boundary failure","impact depends on asset, principal, tenant and blast radius"]
severity_factors: ["Severity increases with privilege, sensitivity, tenant count, persistence and external reachability."]
exploitability_factors: ["Reachability, input control and missing control evidence are required; use synthetic fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary and make the policy explicit.","Use least privilege, typed inputs, provenance and bounded resources across alternate and asynchronous paths.","Add telemetry that records the decision without storing secrets or sensitive content."]
secure_patterns: ["Deny by default with a typed, testable policy decision.","Isolate capabilities, bound time/size/fan-out and bind identity, tenant, destination and action."]
regression_tests: ["Create a local or staging synthetic fixture for XML schema and entity processing ambiguity; assert the control blocks or safely contains the unsafe path and records a redacted decision."]
related_vulnerabilities: []
references: ["https://cwe.mitre.org/data/definitions/611.html"]
source_provenance: ["sources/research-notes.md:normalized defensive topic","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-08"
maturity: "curated"
priority: "P1"
review_status: "reviewed"
fixture_ids: ["eval.xml-schema.positive","eval.xml-schema.negative"]
detector_refs: []
---

# XML schema and entity processing ambiguity

XML parser configuration differs across paths, allowing external entities, expansive structures or schema assumptions to change the interpreted document.

## Defensive audit note

Treat the named signal as a hypothesis. Confirm the reachable source, transformations, missing control and sink with code/configuration evidence before reporting a finding.

## Safe boundary

Verification belongs in a local or staging harness with synthetic data, canaries, mocks, bounded timeouts and no external side effects.

Canonical ID: `vuln.injection.xml-schema`; canonical ontology: `CWE-611`.
