---
id: "vuln.availability.resource-exhaustion"
title: "Unbounded resource consumption and algorithmic DoS"
aliases: ["resource exhaustion","ReDoS","unrestricted resource consumption"]
summary: "Untrusted input or a tenant-controlled workload can consume disproportionate CPU, memory, connections, storage or downstream quota."
family: "availability-resources"
canonical_cwe: "CWE-400"
related_cwe: []
capec: ["CAPEC-125"]
owasp_mappings: ["A10:2025"]
asvs_mappings: ["V12"]
wstg_mappings: []
masvs_mappings: []
api_security_mappings: ["API4:2023"]
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["API","parser","search","regex","batch"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","worker","cloud"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["request size, regex/query, batch, file or model context"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["parser, algorithm, queue, downstream call or model inference"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Missing body/depth/time limits","Catastrophic backtracking or expensive query plan","Retries amplify work","Per-tenant quota absent"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass unbounded resource consumption and algorithmic dos.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace request size, regex/query, batch, file or model context to parser, algorithm, queue, downstream call or model inference across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/400.html","https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"]
source_provenance: ["sources/manifest.yaml:owasp-api","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# Unbounded resource consumption and algorithmic DoS

Budget each resource at each boundary: input size, parse depth, CPU/time, concurrency, fan-out, retries, tokens and storage. Fail closed and measure per principal/tenant.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.availability.resource-exhaustion`; canonical ontology entry: `CWE-400`.
