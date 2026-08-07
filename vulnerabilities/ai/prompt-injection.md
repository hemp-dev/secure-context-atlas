---
id: "vuln.ai.prompt-injection"
title: "Direct and indirect prompt injection / goal hijack"
aliases: ["LLM01","indirect prompt injection","agent goal hijack"]
summary: "Untrusted text, retrieved content, tool output or multimodal data is interpreted as an instruction that can override the intended task, policy or authority hierarchy."
family: "ai-llm-rag-agents"
canonical_cwe: "CWE-1427"
related_cwe: ["CWE-20","CWE-693"]
capec: ["CAPEC-77"]
owasp_mappings: []
asvs_mappings: []
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: ["LLM01:2025","ASI01","ASI02"]
applies_to: ["source code","configuration","architecture"]
surfaces: ["LLM","RAG","agent","email/document","MCP"]
languages: ["any"]
frameworks: ["framework-agnostic"]
platforms: ["ai","agent","rag","mcp"]
preconditions: ["An untrusted or lower-trust input reaches the described boundary.","A security control is expected at or before the sink but is absent, incomplete or applied on only one path."]
trust_boundaries: ["untrusted input to application","application to privileged/resource sink"]
data_flow: {"sources":["user/document/email/web/API/tool content"],"transformations":["decode, normalize or parse input","application-specific routing"],"controls":["validation or policy control if present"],"sinks":["prompt/context assembly, planner or tool selector"],"authorization_points":["the decision point immediately before the sink"]}
code_signals: ["Instruction and data share one channel","Retrieved text is trusted by role or formatting","Model output directly changes plan/tool arguments","No provenance, delimiters or policy enforcement outside the model"]
configuration_signals: ["Configuration flags, defaults or error paths can bypass direct and indirect prompt injection / goal hijack.","Inspect deployment, proxy, identity and resource-limit settings that affect the control."]
architecture_signals: ["Trace user/document/email/web/API/tool content to prompt/context assembly, planner or tool selector across synchronous, asynchronous, alternate-protocol and provider boundaries."]
audit_questions: ["What exact source and sink are reachable?","Which control should run before the sink?","Do alternate protocols, retries or error paths differ?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["The named library or endpoint is only a signal; confirm reachability and the exact sink."]
impact: ["security boundary bypass","confidentiality/integrity/availability impact"]
severity_factors: ["Severity depends on the asset, privilege and blast radius."]
exploitability_factors: ["Reachability and a controllable input are required; use test fixtures only."]
remediation: ["Enforce the control at the sink-facing service boundary.","Make policy explicit, deny by default and cover alternate/async paths.","Add telemetry and bounded failure behaviour."]
secure_patterns: ["Typed inputs and explicit policy checks.","Least privilege, isolation and bounded resource use."]
regression_tests: ["Add a local or staging negative test using a canary and assert the control blocks the unsafe sink."]
related_vulnerabilities: ["vuln.ai.excessive-agency","vuln.ai.output-handling"]
references: ["https://genai.owasp.org/llmrisk/llm01-prompt-injection/","https://atlas.mitre.org/"]
source_provenance: ["sources/manifest.yaml:owasp-genai","sources/manifest.yaml:hacktricks"]
last_reviewed: "2026-08-07"
---

# Direct and indirect prompt injection / goal hijack

Prompt injection is a data/authority confusion. Treat all external content as untrusted data, preserve provenance, enforce typed tool policies in ordinary code, and require explicit confirmation for high-impact actions. A refusal is not a security boundary.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.ai.prompt-injection`; canonical ontology entry: `CWE-1427`.
