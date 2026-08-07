---
id: "vuln.supply.ci-cd"
title: "CI/CD workflow trust and artifact integrity failure"
aliases: ["CI injection","untrusted workflow","artifact substitution"]
summary: "Untrusted repository content, event metadata, action/plugin, runner or artifact can influence a privileged build or deployment without isolation and integrity controls."
family: "supply-chain-cicd"
canonical_cwe: "CWE-829"
related_cwe: []
capec: []
owasp_mappings: ["A03:2025","A08:2025"]
asvs_mappings: ["V14"]
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["CI","SCM","release","artifact"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["repository","CI runner","registry","production"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["pull request metadata, branch/tag, build script or artifact"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["CI runner, signing, registry or deployment action"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Untrusted event runs with write/cloud secrets","Mutable action/container reference","Artifact not signed or bound to commit","Runner/workspace reused across trust levels"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass ci/cd workflow trust and artifact integrity failure.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace pull request metadata, branch/tag, build script or artifact to CI runner, signing, registry or deployment action across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/829.html","https://github.com/ossf/scorecard"]
source_provenance: ["sources/manifest.yaml:openssf-scorecard","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# CI/CD workflow trust and artifact integrity failure

Separate trust levels, use least-privilege ephemeral runners, pin actions/images, protect release refs, sign and verify artifacts, and keep secrets out of untrusted jobs.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.supply.ci-cd`; canonical ontology entry: `CWE-829`.
