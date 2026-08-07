---
id: "vuln.business.race-condition"
title: "Race condition and TOCTOU in stateful workflows"
aliases: ["race condition","TOCTOU","double spend"]
summary: "A security or business invariant is checked separately from the state change, allowing concurrent requests or workers to observe and commit an invalid interleaving."
family: "business-logic-state"
canonical_cwe: "CWE-362"
related_cwe: ["CWE-367"]
capec: ["CAPEC-26","CAPEC-29"]
owasp_mappings: ["A06:2025"]
asvs_mappings: ["V11"]
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["payment","quota","invite","job","file","API"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["server","database","distributed"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["concurrent request, queue delivery or filesystem state"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["check-then-use, transaction or distributed lock"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Read and write are separate transactions","Idempotency key is accepted but not atomically claimed","Lock scope/expiry does not cover the invariant","Retry duplicates side effect"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass race condition and toctou in stateful workflows.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace concurrent request, queue delivery or filesystem state to check-then-use, transaction or distributed lock across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/362.html"]
source_provenance: ["sources/manifest.yaml:mitre-cwe","sources/manifest.yaml:patt"]
last_reviewed: "2026-08-07"
---

# Race condition and TOCTOU in stateful workflows

Make the invariant atomic: database constraint/transaction, compare-and-set, idempotency record, or a correctly scoped lock. Test with deterministic concurrency in a local harness and assert one committed outcome.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.business.race-condition`; canonical ontology entry: `CWE-362`.
