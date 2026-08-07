---
id: "vuln.network.ssrf"
title: "Server-side request forgery and unsafe URL fetching"
aliases: ["SSRF","cloud metadata access","unsafe webhook fetch"]
summary: "A user-controlled or third-party-controlled URL reaches a server-side network client without a robust destination policy and redirect/rebinding defense."
family: "ssrf-network"
canonical_cwe: "CWE-918"
related_cwe: ["CWE-441","CWE-610"]
capec: ["CAPEC-664"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V12"]
wstg_mappings: ["WSTG-SRVS-19"]
masvs_mappings: []
api_security_mappings: ["API6:2023"]
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["webhook","URL preview","import","proxy","API"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","cloud","network"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request URL, webhook target or third-party redirect"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["server-side HTTP client and reachable network"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["URL parsed more than once","Redirects followed without revalidation","DNS resolution and connection destination are not bound","Internal/cloud ranges reachable from service identity"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass server-side request forgery and unsafe url fetching.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request URL, webhook target or third-party redirect to server-side HTTP client and reachable network across synchronous, asynchronous, alternate-protocol and provider boundaries."]
audit_questions: ["What exact source and sink are reachable?","Which control should run before the sink?","Do alternate protocols, retries or error paths differ?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["The named library or endpoint is only a signal; confirm reachability and the exact sink."]
impact: ["security boundary bypass","confidentiality/integrity/availability impact"]
severity_factors: ["Severity depends on the asset, privilege and blast radius."]
exploitability_factors: ["Reachability and a controllable input are required; use test fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary.","Make policy explicit, deny by default and cover alternate/async paths.","Add telemetry and bounded failure behaviour."]
secure_patterns: ["Typed inputs and explicit policy checks.","Least privilege, isolation and bounded resource use."]
regression_tests: ["Add a local or staging negative test using a canary and assert the control blocks the unsafe sink."]
related_vulnerabilities: ["vuln.cloud.iam","vuln.api.graphql"]
references: ["https://cwe.mitre.org/data/definitions/918.html","https://owasp.org/API-Security/editions/2023/en/0xa6-server-side-request-forgery/"]
source_provenance: ["sources/manifest.yaml:owasp-api","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Server-side request forgery and unsafe URL fetching

SSRF is a network-boundary failure, not merely a string validation issue. Resolve and authorize destinations in a controlled client, re-check redirects and connection results, isolate the worker, and remove ambient cloud credentials.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.network.ssrf`; canonical ontology entry: `CWE-918`.
