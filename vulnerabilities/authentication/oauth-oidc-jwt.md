---
id: "vuln.authentication.oauth-oidc-jwt"
title: "OAuth/OIDC/JWT trust and claim-validation failure"
aliases: ["JWT confusion","OAuth redirect trust","OIDC claim validation"]
summary: "Federated identity failures arise when the application treats a decoded or partially checked token as authority. Keep provider trust configuration explicit and fail closed."
family: "authentication-identity"
canonical_cwe: "CWE-347"
related_cwe: ["CWE-287","CWE-346"]
capec: ["CAPEC-115"]
owasp_mappings: ["A07:2025"]
asvs_mappings: ["V2","V3"]
wstg_mappings: ["WSTG-AUTHN-05"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["web","api","mobile","SSO"]
languages: ["JavaScript","Python","Java","Go","C#","Ruby","PHP"]
frameworks: ["oauth2-proxy","Spring Security","Authlib","ASP.NET","openid-client"]
platforms: ["web","api","mobile","identity-provider"]
preconditions: ["A token or authorization response is accepted from an untrusted or weakly validated source.","Redirect URI, issuer, audience, nonce, state, algorithm or key selection is attacker-influenced or incomplete."]
trust_boundaries: ["client to authorization server","identity provider to relying party","gateway to service"]
data_flow: {"sources":["authorization response","JWT header/claims","JWKS/key metadata"],"transformations":["decode","signature verification","claim mapping"],"controls":["partial token validation","role mapping"],"sinks":["principal creation","privileged API call"],"authorization_points":["after complete validation and before principal construction"]}
code_signals: ["Decode claims before verification","Accept issuer/audience from request or token","Allow arbitrary redirect URI or algorithm/key selection"]
configuration_signals: ["Wildcard redirect/CORS policy","Unpinned JWKS host","Fallback to local claims when provider unavailable"]
architecture_signals: ["Different services use different issuer and group-to-role mapping"]
audit_questions: ["Which values are configured, not token-controlled?","Is the identity provider and audience exact?","Does fail-closed behaviour hold on key fetch or claim errors?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["A JWT library's default verification is not evidence of correct issuer/audience policy.","An OAuth login may be safe while a separate token exchange is not."]
impact: ["account impersonation","role escalation","authorization bypass"]
severity_factors: ["External IdP trust, admin role mapping and redirect reachability dominate severity."]
exploitability_factors: ["Requires a reachable login/exchange path and a test IdP or mocked issuer."]
remediation: ["Pin issuer, audience, algorithms, key source, redirect URIs and nonce/state checks.","Separate authentication claims from authorization policy and reject ambiguous/fallback states."]
secure_patterns: ["Use typed inputs, explicit policy checks and least-privilege boundaries."]
regression_tests: ["Use a mock IdP with two clients and roles; assert wrong issuer/audience/nonce/redirect and algorithm combinations are rejected."]
related_vulnerabilities: []
references: ["https://cwe.mitre.org/data/definitions/347.html","https://openid.net/specs/openid-connect-core-1_0.html"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:owasp-asvs"]
last_reviewed: "2026-08-07"
---

# OAuth/OIDC/JWT trust and claim-validation failure

Federated identity failures arise when the application treats a decoded or partially checked token as authority. Keep provider trust configuration explicit and fail closed.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.authentication.oauth-oidc-jwt`; canonical ontology entry: `CWE-347`.
