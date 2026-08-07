---
id: "vuln.injection.xxe"
title: "XML external entity and unsafe XML parsing"
aliases: ["XXE","XML entity expansion"]
summary: "XML parsing becomes dangerous when document-controlled declarations can trigger external resolution or unbounded expansion. Keep parser configuration explicit and test it at each library boundary."
family: "injection"
canonical_cwe: "CWE-611"
related_cwe: ["CWE-827","CWE-776"]
capec: ["CAPEC-221"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V5"]
wstg_mappings: ["WSTG-INPV-07"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["api","file upload","SOAP","document import"]
languages: ["Java","Python","C#","Go","PHP","Ruby"]
frameworks: ["libxml2","Jackson XML","SAX/DOM","lxml","System.Xml"]
platforms: ["api","worker","document parser"]
preconditions: ["Attacker-influenced XML reaches a parser.","External entity, DTD, XInclude, network access or expansion is enabled beyond the use case."]
trust_boundaries: ["upload/request to parser","parser to filesystem/network/resource sink"]
data_flow: {"sources":["XML body","uploaded document","third-party XML"],"transformations":["encoding detection","entity expansion","schema validation"],"controls":["parser hardening if present","size limits"],"sinks":["file/network resolution","expanded document","downstream query/template"],"authorization_points":["resource resolution and document processing"]}
code_signals: ["Default parser constructor","Network/file resolver callback","Schema validation after unsafe entity expansion"]
configuration_signals: ["DTD enabled globally","parser accepts arbitrary URL schemes","large entity/depth limits absent"]
architecture_signals: ["Different XML libraries in sync and async paths or in image/PDF/document pipelines"]
audit_questions: ["Are DTDs/entities needed?","Is external resolution disabled at parser and transport layers?","Are size/depth/time limits enforced before expansion?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["A parser may disable network access but still expose local file reads or resource exhaustion.","Schema validation is not a substitute for parser hardening."]
impact: ["sensitive file disclosure","internal network access","resource exhaustion"]
severity_factors: ["Severity depends on resolver capabilities and service identity/network access."]
exploitability_factors: ["Requires an XML processing path; use parser unit tests, not live endpoints."]
remediation: ["Disable DTD/external entity/XInclude resolution.","Use hardened parser factories, bounded expansion and isolated workers.","Prefer a data format without executable external references when possible."]
secure_patterns: ["Use typed inputs, explicit policy checks and least-privilege boundaries."]
regression_tests: ["Unit-test parser settings with a synthetic document and assert no resolver callback, no external network and bounded resource use."]
related_vulnerabilities: []
references: ["https://cwe.mitre.org/data/definitions/611.html","https://portswigger.net/web-security/xxe"]
source_provenance: ["sources/manifest.yaml:patt","sources/manifest.yaml:portswigger-academy","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# XML external entity and unsafe XML parsing

XML parsing becomes dangerous when document-controlled declarations can trigger external resolution or unbounded expansion. Keep parser configuration explicit and test it at each library boundary.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.injection.xxe`; canonical ontology entry: `CWE-611`.
