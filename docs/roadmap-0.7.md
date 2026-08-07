# Secure Context Atlas roadmap to 0.7.0

v0.7 converts the v0.6 contracts into a release candidate with executable detector checks, provenance-preserving advisory lookups, reproducible release evidence and a reviewed agentic/MCP retrieval benchmark. It remains a defensive knowledge release: execution results are triage signals, not confirmed findings.

| Area | v0.7 outcome | Acceptance evidence |
|---|---|---|
| Detector execution | Seven Semgrep rules and one CodeQL query are executable; three application-specific CodeQL records remain contract-only | `rules/manifest.json`, positive/negative fixtures, `scripts/validate_rules.py` |
| Detector safety | Every executable rule maps to a `vuln.*` card, a safe fixture and a required-control description | `schemas/detector-contract.schema.json`, `rules/tests/` |
| Advisory provenance | OSV and GitHub Advisory Database adapters normalize responses and preserve query/request/response provenance | `scripts/advisory_adapter.py`, `schemas/advisory-bundle.schema.json`, `scripts/validate_advisories.py` |
| Release integrity | SPDX 2.3 SBOM and SHA-256 release manifest cover the committed tree | `scripts/build_sbom.py`, `scripts/validate_sbom.py`, `scripts/validate_release.py` |
| Attestation | Published GitHub Releases trigger artifact provenance and SBOM attestations | `.github/workflows/release-attestations.yml` |
| Agentic evaluation | 27 reviewed synthetic cases cover model/RAG/tool/MCP trust boundaries | `evals/agentic/cases.json`, `schemas/agentic-eval.schema.json`, `ai/evaluation-report.json` |
| CI | Source, schema, rules, advisory, SBOM, threat-model, evaluation and generated-tree gates run together | `.github/workflows/quality.yml` |

## Definition of done

- All generated indexes and context manifests identify release `0.7.0`.
- The v0.7 schemas validate every checked-in sample, including advisory bundles, agentic cases, detector manifest and SPDX SBOM.
- The deterministic suite retains 134 base fixtures and 12 independent holdout cases; the agentic suite has 100% reviewed coverage, no leakage, case recall@5 >= 0.70 and target recall@5 >= 0.75.
- Every executable Semgrep detector matches its positive fixture and does not match its negative fixture.
- CodeQL pack metadata and query identity pass structural validation; `codeql pack check` runs when the CLI is available.
- Offline advisory fixture outputs are byte-for-byte deterministic and record request/response hashes.
- SBOM file set and hashes equal the tracked release tree after documented exclusions.
- Release manifest includes the SBOM and validates every listed SHA-256 hash.
- Published releases have a workflow path for GitHub artifact and SBOM attestations with least-privilege permissions.
- No raw wordlists, credential lists, web shells, working exploit chains, real secrets or destructive verification instructions are present.

## Explicit non-goals

- No automatic conversion of detector matches or advisory presence into confirmed findings.
- No claim that synthetic retrieval metrics prove a specific LLM's correctness.
- No live advisory mirroring into static vulnerability cards.
- No raw payload datasets, credential lists, public scanning or exploit code.
- No application-specific authorization model is inferred from a generic detector.

## Follow-up after 0.7

Potential v0.8 work: application-configurable CodeQL data-flow models, signed/pinned adapter response snapshots for reproducible research, consumer-side SBOM diff policy, broader multilingual agentic evaluation and human review workflow with independent reviewer identities.
