---
id: "vuln.api.graphql"
title: "GraphQL field authorization and query complexity failure"
aliases: ["GraphQL authz","GraphQL introspection","query complexity"]
summary: "A GraphQL operation exposes fields, resolvers or resource cost without enforcing object/property/function policy and bounded query complexity."
family: "api-protocols"
canonical_cwe: "CWE-285"
related_cwe: []
capec: []
owasp_mappings: ["A01:2025","A10:2025"]
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: ["API3:2023","API4:2023"]
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["GraphQL","API","federation"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["api","web","mobile"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["query document, variables and resolver context"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["parser, resolver, data loader or federation hop"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Authz only at route level","Resolver returns fields beyond caller scope","Aliases/fragments/depth/batching bypass limits","Federated service trusts upstream claims"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass graphql field authorization and query complexity failure.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace query document, variables and resolver context to parser, resolver, data loader or federation hop across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"]
source_provenance: ["sources/manifest.yaml:owasp-api","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# GraphQL field authorization and query complexity failure

Authorize each sensitive field/object in the resolver or data layer, apply tenant-aware loaders, validate schema and complexity/depth limits, and make federation trust explicit.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.api.graphql`; canonical ontology entry: `CWE-285`.
