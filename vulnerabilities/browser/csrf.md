---
id: "vuln.browser.csrf"
title: "Cross-site request forgery"
aliases: ["CSRF","session riding"]
summary: "CSRF occurs when ambient browser credentials authorize an unintended cross-site state change. CORS controls reading, not necessarily sending, so it is not a substitute for CSRF defenses."
family: "browser-client"
canonical_cwe: "CWE-352"
related_cwe: ["CWE-1275"]
capec: ["CAPEC-62"]
owasp_mappings: ["A01:2025"]
asvs_mappings: ["V4"]
wstg_mappings: ["WSTG-SESS-05"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["browser","web","cookie-authenticated API"]
languages: ["any"]
frameworks: ["Spring Security","Django","Rails","ASP.NET","Express"]
platforms: ["browser","web","api"]
preconditions: ["A browser automatically sends ambient authentication to a state-changing endpoint.","The endpoint lacks a robust origin/intent control and accepts cross-site requests."]
trust_boundaries: ["untrusted origin to browser","browser to state-changing service"]
data_flow: {"sources":["cross-site navigation/form/fetch","ambient cookie"],"transformations":["browser credential attachment","request parsing"],"controls":["CSRF token","SameSite/origin validation"],"sinks":["state-changing endpoint","payment/profile/admin action"],"authorization_points":["request intent/origin check before mutation"]}
code_signals: ["State change accepts cookie auth without token/origin check","GET or idempotence assumption triggers mutation","Token checked only on some content types"]
configuration_signals: ["SameSite policy not explicit","CORS mistaken for CSRF control","mobile/browser clients share endpoint semantics"]
architecture_signals: ["An API using explicit bearer headers may be not CSRF-prone while a browser cookie route is"]
audit_questions: ["Is authentication ambient?","Are all mutation methods and content types covered?","Do origin and token checks fail closed?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["SameSite is browser/version/context dependent and defense in depth.","A non-browser API with explicit authorization headers has a different threat model."]
impact: ["unwanted state change","account or transaction action","data integrity loss"]
severity_factors: ["Severity depends on authenticated action sensitivity and reauthentication/confirmation controls."]
exploitability_factors: ["Requires a victim browser session and cross-origin reachability; verify with test accounts only."]
remediation: ["Use synchronizer or signed double-submit tokens and strict Origin/Referer policy where appropriate.","Keep state changes non-GET and require explicit authorization/confirmation for high-impact flows."]
secure_patterns: ["Use typed inputs, explicit policy checks and least-privilege boundaries."]
regression_tests: ["Browser integration tests with synthetic sessions assert cross-origin mutation is rejected and same-origin request succeeds."]
related_vulnerabilities: []
references: ["https://cwe.mitre.org/data/definitions/352.html","https://owasp.org/www-community/attacks/csrf"]
source_provenance: ["sources/manifest.yaml:owasp-asvs","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# Cross-site request forgery

CSRF occurs when ambient browser credentials authorize an unintended cross-site state change. CORS controls reading, not necessarily sending, so it is not a substitute for CSRF defenses.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.browser.csrf`; canonical ontology entry: `CWE-352`.
