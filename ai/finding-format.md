# AI finding format

Use one record per coherent weakness. Markdown is acceptable for humans, but the fields below must be machine-extractable.

The canonical machine contract is [`schemas/finding.schema.json`](../schemas/finding.schema.json), and each evidence item follows [`schemas/evidence.schema.json`](../schemas/evidence.schema.json). A finding is not complete until the source, sink and missing control are represented by redacted evidence.

```yaml
status: confirmed | probable | needs-review | not-applicable
title: "Short root-cause title"
canonical_id: vuln.authorization.idor
canonical_cwe: CWE-639
severity: low | medium | high | critical
confidence: low | medium | high
evidence:
  - file: src/example.ts
    lines: "42-49"
    excerpt: "short redacted excerpt"
input_and_prerequisite: "test tenant A can submit object identifier owned by tenant B"
flow:
  source: "request.path.object_id"
  transformations: ["route decode", "repository lookup"]
  controls: ["authentication middleware"]
  sink: "object read returned to caller"
missing_control: "object-level authorization at the decision point"
exploitability: "requires authenticated test user and cross-tenant object reference"
impact: ["unauthorized read", "tenant isolation failure"]
mappings: ["CWE-639", "API1:2023", "ASVS-V8"]
safe_verification: "two test tenants, canary object, expected denial, no real data"
remediation: ["authorize subject and object at service boundary", "add tenant-aware repository policy"]
regression_test: "negative integration test asserts 403 and no object body"
references: ["vulnerabilities/authorization/idor.md"]
```

Redact secrets and personal data in evidence. A dangerous-looking API, dependency name or model call is a signal, not a finding, until reachability and missing control are shown.
