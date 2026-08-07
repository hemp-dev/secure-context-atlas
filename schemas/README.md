# Schemas

`vulnerability.schema.json` is the canonical frontmatter contract for `vulnerabilities/**/*.md`; `finding.schema.json` and `evidence.schema.json` define model output; `threat-model.schema.json` defines assets, principals, boundaries, flows, capabilities and controls; `context-pack.schema.json`, `advisory.schema.json`, `provenance.schema.json`, `eval-fixture.schema.json` and `detector-contract.schema.json` cover v0.6 release interfaces; `technique.schema.json`, `audit-check.schema.json` and `source.schema.json` cover supporting records.

The root `vulnerability-record.schema.json` and `vulnerability-records.examples.jsonl` are retained as a legacy JSON-record compatibility format from the preliminary taxonomy. New records must use the `vuln.*` frontmatter schema and the MITRE CWE canonical field.
