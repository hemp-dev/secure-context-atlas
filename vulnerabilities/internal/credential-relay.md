---
id: "vuln.internal.credential-relay"
title: "Credential relay and confused-deputy trust across internal services"
aliases: ["credential relay","confused deputy","internal trust"]
summary: "A service accepts a caller-controlled destination or identity-bearing request and forwards credentials or authority across an internal trust boundary."
family: "internal-enterprise"
canonical_cwe: "CWE-441"
related_cwe: []
capec: ["CAPEC-664"]
owasp_mappings: ["A01:2025"]
asvs_mappings: ["V4"]
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["LDAP","Kerberos","NTLM","SMB","service-to-service"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["enterprise","windows","linux","network"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["name resolution, referral, URL or forwarded identity"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["directory/file/message service or internal proxy"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Unsigned channel or missing binding","Service forwards ambient credentials","Internal proxy accepts arbitrary destination","Trust inferred from network location"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass credential relay and confused-deputy trust across internal services.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace name resolution, referral, URL or forwarded identity to directory/file/message service or internal proxy across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/441.html"]
source_provenance: ["sources/manifest.yaml:internal-all-the-things","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# Credential relay and confused-deputy trust across internal services

Bind identity to the intended service, require signing/channel protection, restrict referrals/destinations, remove ambient credentials and isolate internal proxy capabilities. Test only in a dedicated lab.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.internal.credential-relay`; canonical ontology entry: `CWE-441`.
