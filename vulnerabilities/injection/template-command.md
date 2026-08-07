---
id: "vuln.injection.template-command"
title: "Template, expression and command injection"
aliases: ["SSTI","OS command injection","expression injection","eval"]
summary: "Interpreter injection is present when untrusted content becomes executable syntax. The root cause is the missing data/code boundary; RCE is an impact that must not be confused with the CWE root cause."
family: "injection"
canonical_cwe: "CWE-94"
related_cwe: []
capec: ["CAPEC-15","CAPEC-77"]
owasp_mappings: ["A05:2025"]
asvs_mappings: ["V5"]
wstg_mappings: []
masvs_mappings: []
api_security_mappings: []
genai_mappings: []
applies_to: ["source code","configuration","architecture"]
surfaces: ["web","jobs","automation","AI tool"]
languages: ["JavaScript","Python","Java","Go","C#","Ruby","PHP","Rust"]
frameworks: ["Jinja","Twig","ERB","Freemarker","SpEL","Node child_process"]
platforms: ["web","api","worker","agent"]
preconditions: ["Untrusted text controls template source, expression language, shell arguments or dynamic code.","The application confuses data with executable syntax or invokes a process/evaluator with ambient authority."]
trust_boundaries: ["request/document/model output to interpreter","application to process or template sink"]
data_flow: {"sources":["request fields","uploaded content","model/tool output"],"transformations":["decode","template compile","shell/argument construction"],"controls":["escaping or allowlist if present","process sandbox"],"sinks":["template/evaluator","shell/process","dynamic module loading"],"authorization_points":["before interpreter creation and before side-effectful tool invocation"]}
code_signals: ["Render user-controlled string as template","Shell command assembled from string","eval/dynamic import on user or model output"]
configuration_signals: ["Agent tool accepts arbitrary command/URL","debug evaluator or extension functions enabled","sandbox assumed from prompt policy"]
architecture_signals: ["A safe template value can still be unsafe in a different context or engine"]
audit_questions: ["Is the input template source or a value?","Can the interpreter access filesystem/network/process?","Are arguments typed and capabilities bounded?"]
safe_verification: ["Use a local or staging fixture with synthetic data, test identities and a unique canary; keep egress disabled.","Assert the expected denial or safe encoding and inspect only test output; do not use real credentials, persistence or destructive state."]
false_positives: ["Static template with escaped variables is not the same as dynamic template compilation.","A library name alone is not a finding without a flow to an interpreter."]
impact: ["code execution","secret access","service compromise"]
severity_factors: ["Impact follows interpreter privileges and network/filesystem reachability."]
exploitability_factors: ["Requires a reachable interpreter and controllable source; validate in an isolated test harness."]
remediation: ["Use fixed templates and context-aware escaping.","Pass structured arguments to APIs instead of shell strings.","Isolate interpreters with least privilege, timeouts and no ambient secrets."]
secure_patterns: ["Use typed inputs, explicit policy checks and least-privilege boundaries."]
regression_tests: ["Mock the interpreter/tool and assert input is passed as data/typed arguments; add a regression test that forbidden capabilities are unavailable."]
related_vulnerabilities: []
references: ["https://cwe.mitre.org/data/definitions/94.html","https://portswigger.net/web-security/server-side-template-injection"]
source_provenance: ["sources/manifest.yaml:patt","sources/manifest.yaml:portswigger-academy","sources/manifest.yaml:mitre-cwe"]
last_reviewed: "2026-08-07"
maturity: "curated"
review_status: "reviewed"
---

# Template, expression and command injection

Interpreter injection is present when untrusted content becomes executable syntax. The root cause is the missing data/code boundary; RCE is an impact that must not be confused with the CWE root cause.

## Audit notes

Use the source/transform/control/sink model above. Report only evidence-backed flows and keep verification inside the safe boundary.

## Retrieval

Canonical ID: `vuln.injection.template-command`; canonical ontology entry: `CWE-94`.
