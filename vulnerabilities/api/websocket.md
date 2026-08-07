---
id: "vuln.api.websocket"
title: "WebSocket origin, authentication and message authorization failure"
aliases: ["WebSocket auth","CSWSH","message-level authorization"]
summary: "A persistent connection or message handler trusts handshake state, origin or channel membership without rechecking the principal's right to each action/data stream."
family: "api-protocols"
canonical_cwe: "CWE-346"
related_cwe: []
capec: []
owasp_mappings: ["A01:2025"]
asvs_mappings: ["V4"]
wstg_mappings: ["WSTG-CLNT-03"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["WebSocket","realtime API","browser"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["api","browser","mobile"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["handshake headers, cookies and message payload"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["connection upgrade, channel subscription or message handler"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Origin not validated for cookie-authenticated browser clients","Connection auth not bound to message/channel","Subscription names map directly to tenant/object data","Reconnect/resume bypasses authorization"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass websocket origin, authentication and message authorization failure.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace handshake headers, cookies and message payload to connection upgrade, channel subscription or message handler across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://portswigger.net/web-security/websockets"]
source_provenance: ["sources/manifest.yaml:portswigger-academy","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# WebSocket origin, authentication and message authorization failure

Validate origin and authentication at upgrade, authorize channel/object/message actions, expire/revoke connections and treat reconnect tokens as bearer credentials.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.api.websocket`; canonical ontology entry: `CWE-346`.
