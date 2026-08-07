---
id: "vuln.injection.sql"
title: "SQL injection and unsafe query construction"
aliases: ["SQLi","second-order SQL injection"]
summary: "SQL injection is a grammar-boundary failure: data is allowed to become query structure. ORM usage is a signal to inspect, not proof of safety, because raw fragments, identifiers, filters and second-order data often bypass parameterization."
family: "injection"
canonical_cwe: "CWE-89"
related_cwe: ["CWE-20","CWE-943"]
capec: ["CAPEC-66","CAPEC-108"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V1","V5"]
wstg_mappings: ["WSTG-INPV-05"]
masvs_mappings: []
api_security_mappings: ["API10:2023"]
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["web","api","jobs","reporting"]
languages: ["JavaScript","TypeScript","Python","Java","Go","C#","Ruby","PHP","Rust"]
frameworks: ["SQLAlchemy","JPA","Prisma","Entity Framework","ActiveRecord","database/sql"]
platforms: ["web","api","worker","database"]
preconditions: ["Untrusted data reaches a SQL grammar sink.","The query or identifier is assembled through concatenation, unsafe templating or an incomplete ORM escape boundary."]
trust_boundaries: ["request to application","application to database"]
data_flow: {"sources":["query/body/header","stored value later reused"],"transformations":["decode","filter/sort construction","ORM query generation"],"controls":["validation","parameterization if present"],"sinks":["SQL execution","dynamic identifier or clause"],"authorization_points":["query construction and row-level policy"]}
code_signals: ["String interpolation into query text","Dynamic ORDER BY/table/column names without allowlist","Stored input later concatenated into a query"]
configuration_signals: ["Verbose database errors","migration/admin endpoint reachable","different drivers used on async path"]
architecture_signals: ["The ORM may parameterize values but not identifiers or raw fragments"]
audit_questions: ["Which exact expression reaches the driver?","Are identifiers selected from a fixed map?","Are stored values treated as untrusted on second use?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["Parameterized values are safe only for the parameterized positions; they do not authorize dynamic identifiers.","A scanner hit in dead code or test fixtures is not a reachable sink."]
impact: ["unauthorized read/write","data integrity loss","database availability"]
severity_factors: ["Severity increases for write/admin queries, broad database identity and sensitive data."]
exploitability_factors: ["Usually remote and low-complexity when the endpoint is reachable; exact syntax is not needed for a defensive finding."]
remediation: ["Use prepared statements/typed query APIs.","Allowlist dynamic identifiers and enforce row/tenant policy at the data layer.","Avoid returning database errors to clients."]
secure_patterns: ["Use typed inputs, explicit policy checks and least-privilege boundaries."]
regression_tests: ["Run a local integration test with a canary row and a value containing harmless delimiter-like characters; assert query shape remains parameterized and only authorized row is returned."]
related_vulnerabilities: ["vuln.injection.command","vuln.injection.expression"]
references: ["https://cwe.mitre.org/data/definitions/89.html","https://owasp.org/www-community/attacks/SQL_Injection"]
source_provenance: ["sources/manifest.yaml:patt","sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:owasp-asvs"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# SQL injection and unsafe query construction

SQL injection is a grammar-boundary failure: data is allowed to become query structure. ORM usage is a signal to inspect, not proof of safety, because raw fragments, identifiers, filters and second-order data often bypass parameterization.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.injection.sql`; canonical ontology entry: `CWE-89`.
