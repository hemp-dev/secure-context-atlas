---
id: "vuln.hardware.firmware-update"
title: "Unsigned or rollbackable firmware update"
aliases: ["firmware update","secure boot","rollback attack"]
summary: "A device accepts firmware or configuration without strong authenticity/integrity, version/rollback policy or recovery validation."
family: "hardware-firmware-iot"
canonical_cwe: "CWE-494"
related_cwe: []
capec: []
owasp_mappings: ["A08:2025"]
asvs_mappings: []
wstg_mappings: []
masvs_mappings: ["MASVS-RESILIENCE"]
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["firmware","IoT","OTA","bootloader"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["hardware","firmware","embedded"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["update URL/package, removable media or local debug path"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["bootloader, updater or privileged firmware installer"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Hash without trusted signature","Mutable update source","Rollback protection absent","Debug/update mode exposed in production"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass unsigned or rollbackable firmware update.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace update URL/package, removable media or local debug path to bootloader, updater or privileged firmware installer across synchronous, asynchronous, alternate-protocol and provider boundaries."]
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
references: ["https://cwe.mitre.org/data/definitions/494.html"]
source_provenance: ["sources/manifest.yaml:hardware-all-the-things","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
---

# Unsigned or rollbackable firmware update

Verify signed manifests and image chains, enforce anti-rollback, use authenticated transport, protect update keys, restrict debug paths and test recovery on owned hardware.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.hardware.firmware-update`; canonical ontology entry: `CWE-494`.
