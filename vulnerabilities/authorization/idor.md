---
id: "vuln.authorization.idor"
title: "Broken object-level authorization (IDOR/BOLA)"
aliases: ["IDOR","BOLA","object authorization"]
summary: "The weakness occurs when a caller-controlled object reference reaches a data or action sink without an authorization decision bound to the actual subject, tenant and operation. Opaque identifiers, route middleware and authentication do not substitute for object-level authorization."
family: "authorization-access"
canonical_cwe: "CWE-639"
related_cwe: ["CWE-862","CWE-863"]
capec: ["CAPEC-1","CAPEC-122"]
owasp_mappings: ["A01:2025"]
asvs_mappings: ["V8"]
wstg_mappings: ["WSTG-ATHZ-01","WSTG-ATHZ-02"]
masvs_mappings: []
api_security_mappings: ["API1:2023","API3:2023"]
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["REST","GraphQL","gRPC","mobile API"]
languages: ["JavaScript","TypeScript","Python","Java","Go","C#","Ruby","PHP","Rust","Kotlin","Swift"]
frameworks: ["Express","Django","Spring","ASP.NET","Rails"]
platforms: ["web","api","mobile","multi-tenant"]
preconditions: ["A caller can supply or influence an object identifier.","The handler returns or mutates the object before checking subject-to-object authorization."]
trust_boundaries: ["untrusted principal to application","application to data/control-plane sink"]
data_flow: {"sources":["route/path/query/body object identifier","tenant or principal claims"],"transformations":["decode and normalize identifier","repository lookup"],"controls":["authentication only","missing object/tenant policy"],"sinks":["object read/update/delete","response or downstream job"],"authorization_points":["service/repository decision before the object leaves the trust boundary"]}
code_signals: ["Direct repository lookup by request ID","Authorization middleware checks role but not object owner/tenant","Bulk endpoint accepts a list of IDs without per-item checks"]
configuration_signals: ["Default-allow policy","IDOR detection based only on route naming","Shared service identity hides caller context"]
architecture_signals: ["Object IDs are globally unique but not secret","A gateway check is assumed to cover internal worker paths"]
audit_questions: ["Which principal, tenant and object owner are compared?","Does every read/write/delete path call the same policy?","Are batch, export, cache and async paths covered?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["A 404 may be intentional resource hiding; verify policy semantics.","A signed or opaque ID is not authorization unless the signature binds subject, tenant and action."]
impact: ["cross-tenant read or write","horizontal privilege escalation","data integrity loss"]
severity_factors: ["Impact grows with object sensitivity, mutation capability and tenant count."]
exploitability_factors: ["Requires a reachable identifier and authenticated principal; predictability is not required."]
remediation: ["Authorize the subject, tenant, action and object at the service boundary.","Centralize policy and apply it to batch, export, cache and background-job paths.","Prefer repository methods that require an authorization context."]
secure_patterns: ["Policy-as-code with deny-by-default.","Tenant-aware data access predicates plus explicit action checks."]
regression_tests: ["Create two test tenants with canary objects; assert cross-tenant read/write returns the documented denial and emits no object body."]
related_vulnerabilities: ["vuln.authorization.function-level","vuln.ai.rag-cross-tenant"]
references: ["https://cwe.mitre.org/data/definitions/639.html","https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"]
source_provenance: ["sources/manifest.yaml:patt","sources/manifest.yaml:owasp-api","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Broken object-level authorization (IDOR/BOLA)

The weakness occurs when a caller-controlled object reference reaches a data or action sink without an authorization decision bound to the actual subject, tenant and operation. Opaque identifiers, route middleware and authentication do not substitute for object-level authorization.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.authorization.idor`; canonical ontology entry: `CWE-639`.
