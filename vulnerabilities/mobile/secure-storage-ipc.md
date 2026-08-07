---
id: "vuln.mobile.secure-storage-ipc"
title: "Mobile insecure storage, IPC and exported component"
aliases: ["mobile data storage","exported component","insecure IPC"]
summary: "Sensitive mobile data or privileged component is exposed through storage, logs, backup, IPC, deep links or exported app surfaces without caller and data-boundary controls."
family: "mobile"
canonical_cwe: "CWE-922"
related_cwe: []
capec: []
owasp_mappings: []
asvs_mappings: []
wstg_mappings: ["WSTG-PLAT-01"]
masvs_mappings: ["MASVS-STORAGE","MASVS-PLATFORM"]
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["Android","iOS","deep link","WebView","IPC"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["android","ios","mobile"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["intent/deep link/IPC input or local storage"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["exported component, WebView bridge, key-value store or log"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Exported activity/service/provider without permission","Sensitive value in preferences/log/backup","WebView bridge trusts origin","Deep link performs action without user/context binding"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass mobile insecure storage, ipc and exported component.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace intent/deep link/IPC input or local storage to exported component, WebView bridge, key-value store or log across synchronous, asynchronous, alternate-protocol and provider boundaries."]
audit_questions: ["What exact source and sink are reachable?","Which control should run before the sink?","Do alternate protocols, retries or error paths differ?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["The named library or endpoint is only a signal; confirm reachability and the exact sink."]
impact: ["security boundary bypass","confidentiality/integrity/availability impact"]
severity_factors: ["Severity depends on the asset, privilege and blast radius."]
exploitability_factors: ["Reachability and a controllable input are required; use test fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary.","Make policy explicit, deny by default and cover alternate/async paths.","Add telemetry and bounded failure behaviour."]
secure_patterns: ["Typed inputs and explicit policy checks.","Least privilege, isolation and bounded resource use."]
regression_tests: ["Add a local or staging negative test using a canary and assert the control blocks the unsafe sink."]
related_vulnerabilities: ["vuln.privacy.data-minimization","vuln.authentication.session"]
references: ["https://mas.owasp.org/","https://cwe.mitre.org/data/definitions/922.html"]
source_provenance: ["sources/manifest.yaml:owasp-mobile","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Mobile insecure storage, IPC and exported component

Use platform keystore/keychain, minimize exported components, validate caller and origin, bind high-impact actions to explicit user intent and exclude secrets from logs/backups/screenshots.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.mobile.secure-storage-ipc`; canonical ontology entry: `CWE-922`.
