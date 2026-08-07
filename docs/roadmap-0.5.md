# Secure Context Atlas roadmap to 0.5.0

This document records the implemented release sequence and its acceptance evidence.

| Release | Scope | Acceptance evidence |
|---|---|---|
| 0.2.0 | 111 curated cards, maturity map, finding/evidence schemas, deterministic evaluation | 134 fixtures, recall@5 >= 0.90, repository validator |
| 0.3.0 | detector contracts, rule manifest, SARIF export, regression fixture | 10 rule mappings, SARIF 2.1.0 sample, rule validator |
| 0.4.0 | agentic AI/MCP profile, OWASP/NIST crosswalk, threat model schema | agentic RAG model and threat-model validator |
| 0.5.0 | `sctx` CLI, source lock/diff, update workflow, release manifest and release gates | CLI smoke tests, source lock check, SHA-256 manifest, full CI |

## 0.5.0 definition of done

- All generated indexes use the `Secure Context Atlas 0.5.0` metadata contract.
- All cards have machine-readable frontmatter and safe verification guidance.
- Findings and evidence have JSON Schema contracts.
- Synthetic fixtures are deterministic and contain no live-target instructions.
- Detector contracts map back to stable `vuln.*` IDs.
- Agentic systems have explicit asset, principal, trust-boundary, capability and control modeling.
- Source inputs are pinned by version, URL, entry count and SHA-256.
- Release files have a generated SHA-256 manifest.
- CI runs source generation, evaluation, schema, repository, rule, threat-model and release validation.

## Explicit non-goals

The release does not bundle raw wordlists, credentials, working exploit chains, public scanning workflows, persistence, evasion or destructive proof-of-concept code.
