---
id: "vuln.browser.xss"
title: "Cross-site scripting and unsafe browser output"
aliases: ["XSS","reflected XSS","stored XSS","DOM XSS"]
summary: "XSS is a context-boundary failure: data enters a browser interpreter as markup, script, style or URL syntax. Always reason about the final sink and context, not about a generic 'sanitize' step."
family: "browser-client"
canonical_cwe: "CWE-79"
related_cwe: ["CWE-116","CWE-829"]
capec: ["CAPEC-63","CAPEC-198"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V5","V6"]
wstg_mappings: ["WSTG-INPV-02","WSTG-CLNT-01"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["browser","web","API-rendered HTML"]
languages: ["JavaScript","TypeScript","Python","Java","C#","Ruby","PHP"]
frameworks: ["React","Vue","Angular","Django templates","Rails","Razor"]
platforms: ["browser","web","admin UI"]
preconditions: ["Untrusted data reaches an HTML, URL, CSS, JavaScript or DOM sink in a browser context.","Contextual encoding, safe templating, sanitization or trusted-types-like controls are absent or bypassed."]
trust_boundaries: ["server/API to browser","DOM source to DOM sink"]
data_flow: {"sources":["query/hash","stored profile/comment","postMessage or API response"],"transformations":["template render","decode/DOM parse","client-side string concatenation"],"controls":["contextual output encoding","sanitization","CSP as defense in depth"],"sinks":["HTML/attribute/script/style/URL sink","innerHTML-like DOM API"],"authorization_points":["not an authorization issue; validate origin/tenant before rendering sensitive data"]}
code_signals: ["HTML string interpolation","unsafe DOM assignment","URL or event-handler context receives untrusted data"]
configuration_signals: ["CSP report-only or absent","sanitizer allows active contexts","legacy server-rendered and SPA paths differ"]
architecture_signals: ["Trusted content is reused in another context, or a safe component is bypassed by raw HTML escape hatches"]
audit_questions: ["What is the exact browser context?","Is encoding applied at the final sink?","Can stored or third-party data reach the same component?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["HTML encoding is not safe for JavaScript/CSS/URL contexts.","A strong CSP reduces impact but does not remove the output-encoding defect."]
impact: ["account takeover in browser context","sensitive DOM data exposure","action execution as user"]
severity_factors: ["Severity depends on user/admin context, cookie protections and data available to the page."]
exploitability_factors: ["Often reachable by low-privilege content authors or reflected inputs; no payload is needed to establish the flow."]
remediation: ["Use context-aware encoders and safe framework bindings.","Sanitize narrowly with a reviewed policy when HTML is required.","Use CSP/Trusted Types-like defense in depth and remove raw sink escape hatches."]
secure_patterns: ["Use typed inputs, explicit policy checks and least-privilege boundaries."]
regression_tests: ["Render synthetic canary text containing harmless markup delimiters in a local browser test; assert it remains text and no event/script sink is invoked."]
related_vulnerabilities: []
references: ["https://cwe.mitre.org/data/definitions/79.html","https://portswigger.net/web-security/cross-site-scripting"]
source_provenance: ["sources/manifest.yaml:patt","sources/manifest.yaml:portswigger-academy","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Cross-site scripting and unsafe browser output

XSS is a context-boundary failure: data enters a browser interpreter as markup, script, style or URL syntax. Always reason about the final sink and context, not about a generic 'sanitize' step.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.browser.xss`; canonical ontology entry: `CWE-79`.
