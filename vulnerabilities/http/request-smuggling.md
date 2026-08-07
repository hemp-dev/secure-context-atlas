---
id: "vuln.http.request-smuggling"
title: "HTTP request smuggling and connection desynchronization"
aliases: ["HTTP desync","client desync"]
summary: "Different HTTP components parse the same request boundary differently, allowing one connection's bytes to be interpreted as another request."
family: "http-proxy-cache"
canonical_cwe: "CWE-444"
related_cwe: ["CWE-436","CWE-345"]
capec: ["CAPEC-33"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V13"]
wstg_mappings: ["WSTG-INPV-16"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["HTTP/1.1","HTTP/2","reverse proxy","API gateway"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["web","api","proxy"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request framing headers and connection reuse"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["proxy/backend request queue"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Front proxy and backend use different framing rules","Connection reuse is enabled without normalization","HTTP/2 downgrade or alternate parser path is unreviewed"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass http request smuggling and connection desynchronization.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request framing headers and connection reuse to proxy/backend request queue across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/444.html","https://portswigger.net/web-security/request-smuggling"]
source_provenance: ["sources/manifest.yaml:portswigger-academy","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# HTTP request smuggling and connection desynchronization

Request smuggling is a parser differential. Review the entire proxy chain, normalize framing, and use bounded connection handling. Safe validation is a local proxy/backend harness that compares parsed request counts; do not send ambiguous framing to systems outside the lab.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.http.request-smuggling`; canonical ontology entry: `CWE-444`.
