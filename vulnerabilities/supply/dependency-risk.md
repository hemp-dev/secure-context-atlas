---
id: "vuln.supply.dependency-risk"
title: "Vulnerable, confused or unpinned dependency supply chain"
aliases: ["vulnerable component","dependency confusion","typosquatting"]
summary: "The build or runtime resolves an untrusted, vulnerable, ambiguous or mutable dependency without provenance, pinning, review or compensating controls."
family: "supply-chain-cicd"
canonical_cwe: "CWE-1104"
related_cwe: ["CWE-1395","CWE-1104","CWE-494"]
capec: []
owasp_mappings: ["A03:2025"]
asvs_mappings: ["V14"]
wstg_mappings: ["WSTG-CONF-09"]
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["package manager","build","runtime","plugin"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["repository","CI","artifact","runtime"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["manifest, lockfile, registry metadata or transitive dependency"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["package resolution/build/plugin execution"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Missing lockfile or integrity metadata","Private/public registry ambiguity","Install scripts execute with build secrets","Advisory not connected to deployed version"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass vulnerable, confused or unpinned dependency supply chain.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace manifest, lockfile, registry metadata or transitive dependency to package resolution/build/plugin execution across synchronous, asynchronous, alternate-protocol and provider boundaries."]
audit_questions: ["What exact source and sink are reachable?","Which control should run before the sink?","Do alternate protocols, retries or error paths differ?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["The named library or endpoint is only a signal; confirm reachability and the exact sink."]
impact: ["security boundary bypass","confidentiality/integrity/availability impact"]
severity_factors: ["Severity depends on the asset, privilege and blast radius."]
exploitability_factors: ["Reachability and a controllable input are required; use test fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary.","Make policy explicit, deny by default and cover alternate/async paths.","Add telemetry and bounded failure behaviour."]
secure_patterns: ["Typed inputs and explicit policy checks.","Least privilege, isolation and bounded resource use."]
regression_tests: ["Add a local or staging negative test using a canary and assert the control blocks the unsafe sink."]
related_vulnerabilities: ["vuln.supply.ci-cd","vuln.ai.unsafe-model-loading"]
references: ["https://cwe.mitre.org/data/definitions/1104.html","https://osv.dev/docs/","https://github.com/ossf/scorecard"]
source_provenance: ["sources/manifest.yaml:osv","sources/manifest.yaml:openssf-scorecard","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# Vulnerable, confused or unpinned dependency supply chain

Pin and verify dependencies, use trusted registries and provenance, review install/build scripts, maintain SBOM and query OSV/GHSA data at audit time. Do not report an advisory without reachability and version evidence.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.supply.dependency-risk`; canonical ontology entry: `CWE-1104`.
