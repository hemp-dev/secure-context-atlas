# AI finding format

Use one record per coherent weakness. Markdown is acceptable for humans, but the fields below must be machine-extractable.

The canonical machine contract is [`schemas/finding.schema.json`](../schemas/finding.schema.json), and each evidence item follows [`schemas/evidence.schema.json`](../schemas/evidence.schema.json). A finding is not complete until the source, sink and missing control are represented by redacted evidence.

```yaml
finding_id: finding.authorization.idor
status: confirmed | probable | needs-review | not-applicable
title: "Short root-cause title"
vulnerability_id: vuln.authorization.idor
canonical_cwe: CWE-639
capec: [CAPEC-1]
severity: info | low | medium | high | critical
confidence: low | medium | high
asset: "tenant object API"
trust_boundary: "untrusted caller to application data boundary"
evidence:
  - file: src/example.ts
    lines: "42-49"
    kind: flow
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
safe_verification: "two test tenants, canary object, expected denial, no real data"
remediation: ["authorize subject and object at service boundary", "add tenant-aware repository policy"]
regression_test: "negative integration test asserts 403 and no object body"
references: ["vulnerabilities/authorization/idor.md"]
```

`finding_id`, `vulnerability_id`, `canonical_cwe`, `capec`, `evidence.kind` и остальные поля должны соответствовать [`schemas/finding.schema.json`](../schemas/finding.schema.json). Crosswalks принадлежат карточке уязвимости; finding не должен заменять их произвольным полем `mappings`.

Redact secrets and personal data in evidence. A dangerous-looking API, dependency name or model call is a signal, not a finding, until reachability and missing control are shown.
