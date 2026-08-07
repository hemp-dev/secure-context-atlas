---
id: "vuln.web3.reentrancy"
title: "Smart-contract reentrancy and unsafe external call ordering"
aliases: ["reentrancy","checks-effects-interactions"]
summary: "A contract makes an external call before updating an invariant, allowing control to re-enter or observe an intermediate state."
family: "web3-smart-contracts"
canonical_cwe: "CWE-841"
related_cwe: []
capec: []
owasp_mappings: ["A06:2025"]
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["smart contract","wallet","token","bridge"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["blockchain","smart-contract","dapp"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["transaction calldata or external contract callback"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["external call, balance/state update or oracle-dependent branch"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["External call before state update","Untrusted callback contract","Invariant not protected by guard/accounting","Upgrade/admin path changes call target"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass smart-contract reentrancy and unsafe external call ordering.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace transaction calldata or external contract callback to external call, balance/state update or oracle-dependent branch across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/841.html"]
source_provenance: ["sources/manifest.yaml:hacktricks","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Smart-contract reentrancy and unsafe external call ordering

Use checks-effects-interactions, reentrancy guards where appropriate, pull payments, explicit invariants and bounded external trust. Test against local mocked contracts, not public networks.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.web3.reentrancy`; canonical ontology entry: `CWE-841`.
