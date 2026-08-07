---
id: "vuln.ai.excessive-agency"
title: "Excessive agency and over-privileged tool use"
aliases: ["LLM06","tool misuse","over-privileged agent"]
summary: "An agent can select tools, identities, destinations or arguments with more authority or side-effect scope than the user-approved task requires."
family: "ai-llm-rag-agents"
canonical_cwe: "CWE-250"
related_cwe: []
capec: ["CAPEC-122"]
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: ["LLM06:2025","ASI02","ASI03"]
applies_to: ["source code","configuration","architecture"]
surfaces: ["agent","tool calling","MCP","automation"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["ai","agent","mcp","cloud"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["model plan/tool arguments/user goal"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["tool/MCP call, cloud API, filesystem or deployment action"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Tool exposed without capability scope","Model-generated arguments not schema-validated","No per-action authorization or confirmation","Service identity broader than task"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass excessive agency and over-privileged tool use.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace model plan/tool arguments/user goal to tool/MCP call, cloud API, filesystem or deployment action across synchronous, asynchronous, alternate-protocol and provider boundaries."]
audit_questions: ["What exact source and sink are reachable?","Which control should run before the sink?","Do alternate protocols, retries or error paths differ?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["The named library or endpoint is only a signal; confirm reachability and the exact sink."]
impact: ["security boundary bypass","confidentiality/integrity/availability impact"]
severity_factors: ["Severity depends on the asset, privilege and blast radius."]
exploitability_factors: ["Reachability and a controllable input are required; use test fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary.","Make policy explicit, deny by default and cover alternate/async paths.","Add telemetry and bounded failure behaviour."]
secure_patterns: ["Typed inputs and explicit policy checks.","Least privilege, isolation and bounded resource use."]
regression_tests: ["Add a local or staging negative test using a canary and assert the control blocks the unsafe sink."]
related_vulnerabilities: ["vuln.authorization.function-level","vuln.ai.output-handling"]
references: ["https://genai.owasp.org/llmrisk/llm06-excessive-agency/","https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/"]
source_provenance: ["sources/manifest.yaml:owasp-genai","sources/manifest.yaml:hacktricks"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Excessive agency and over-privileged tool use

Keep agent capabilities narrow and explicit. Validate arguments as data, authorize destination/object/action outside the model, use separate identities, dry-run/preview and confirmation for consequential changes, and log provenance.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.ai.excessive-agency`; canonical ontology entry: `CWE-250`.
