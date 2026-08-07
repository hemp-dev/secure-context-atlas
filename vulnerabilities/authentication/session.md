---
id: "vuln.authentication.session"
title: "Session fixation, replay and invalidation failure"
aliases: ["session fixation","stale session","replay"]
summary: "Session security is a lifecycle property. A correctly signed token can still be replayed if the lifecycle does not rotate, expire, bind and revoke it at the right boundaries."
family: "authentication-identity"
canonical_cwe: "CWE-384"
related_cwe: ["CWE-613","CWE-614","CWE-1004"]
capec: ["CAPEC-61"]
owasp_mappings: ["A07:2025"]
asvs_mappings: ["V3"]
wstg_mappings: ["WSTG-SESS-01"]
masvs_mappings: []
api_security_mappings: ["API2:2023"]
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["web","api","mobile"]
languages: ["any"]
frameworks: ["Express","Spring Security","ASP.NET","Django"]
platforms: ["web","api","mobile"]
preconditions: ["A bearer session, cookie or refresh token crosses an authentication or privilege transition.","Rotation, expiry, audience, revocation or binding is absent or inconsistent."]
trust_boundaries: ["client to identity boundary","identity provider to application session","application to refresh-token store"]
data_flow: {"sources":["cookie","Authorization bearer token","refresh token"],"transformations":["login exchange","token validation","session lookup"],"controls":["signature/expiry checks","partial logout or rotation"],"sinks":["authenticated request","privileged operation"],"authorization_points":["session issuance and each sensitive action"]}
code_signals: ["Session identifier preserved after login or role elevation","Logout clears browser state but not server-side refresh state","Token accepted without issuer/audience or client binding"]
configuration_signals: ["Long TTL","shared signing key","debug session persistence"]
architecture_signals: ["Multiple gateways disagree on token validation or revocation semantics"]
audit_questions: ["Does authentication rotate the identifier?","What is revoked on logout, password reset and MFA change?","Are refresh tokens one-time or replay-detected?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["Stateless tokens may intentionally lack server revocation; document compensating short TTL and rotation.","A random token alone does not prevent theft or cross-context replay."]
impact: ["account takeover","privilege persistence","session impersonation"]
severity_factors: ["Severity depends on privilege, TTL, replay window and revocation coverage."]
exploitability_factors: ["Requires token reuse or theft path; never test with real accounts."]
remediation: ["Rotate identifiers after authentication and privilege changes.","Validate issuer/audience/expiry/nonce and use bounded refresh-token rotation with replay detection.","Clear server-side sessions and downstream caches on logout/security events."]
secure_patterns: ["Use typed inputs, explicit policy checks and least-privilege boundaries."]
regression_tests: ["Test login, MFA upgrade, password reset and logout with synthetic sessions; assert old session/refresh token is rejected."]
related_vulnerabilities: ["vuln.authentication.oauth-oidc-jwt","vuln.browser.csrf"]
references: ["https://cwe.mitre.org/data/definitions/384.html","https://owasp.org/www-project-application-security-verification-standard/"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:owasp-asvs"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Session fixation, replay and invalidation failure

Session security is a lifecycle property. A correctly signed token can still be replayed if the lifecycle does not rotate, expire, bind and revoke it at the right boundaries.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.authentication.session`; canonical ontology entry: `CWE-384`.
