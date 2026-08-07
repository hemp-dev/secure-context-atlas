# Secure Context Atlas roadmap to 0.6.0

v0.6 turns the 0.5 preview into a provenance-aware, machine-validated context release. It does not claim that detector contracts are executable scanners or that retrieval metrics prove an LLM is correct.

| Area | v0.6 outcome | Acceptance evidence |
|---|---|---|
| Contracts | Finding documentation matches `finding.schema.json`; supporting schemas cover packs, advisories, provenance, evals and detector contracts | `scripts/validate_schemas.py` validates every checked-in sample |
| Curation | 44 cards remain curated/reviewed; 67 generated cards are scaffolded/needs-review | `ai/maturity-map.json`, `ai/coverage-report.json` |
| Evaluation | 134 base fixtures plus 12 independent rephrased holdout cases | base recall@5 1.0; holdout recall@5 0.8333; no leakage/forbidden content |
| Retrieval | Strict stack/surface/family/maturity filtering, deterministic pack IDs and provenance | `sctx pack` JSONL manifest validates against context-pack schema |
| Provenance | CWE/CAPEC hashes and five primary repository commit pins | `scripts/validate_sources.py`, `sources/lock.json` |
| Advisories | Normalized OSV/GHSA contract with explicit reachability status | synthetic fixtures pass `advisory.schema.json` |
| CI | Pinned action SHAs, pinned validator dependency, generated-tree diff gate | `.github/workflows/quality.yml` |
| Detection | Ten detector contracts explicitly marked `contract-only` | `rules/manifest.json`, `scripts/validate_rules.py` |

## Definition of done

- All generated indexes identify release `0.6.0`.
- Every vulnerability card contains explicit `maturity` and `review_status`.
- Scaffolded content is excluded from default context packs.
- The holdout query text does not contain the target card ID, title or CWE.
- A missing or malformed JSON Schema instance fails CI.
- The release manifest hashes the committed tree, not arbitrary untracked workspace files.
- The repository source lock contains full commit SHAs for the five primary research repositories.
- No fixture contains credentials, live-target instructions, payload chains or destructive actions.

## Explicit non-goals

- No raw wordlists, credential lists, web shells or working exploit chains.
- No automatic conversion of advisory presence into a source-code finding.
- No claim that a detector contract executes in Semgrep/CodeQL.
- No claim that synthetic retrieval metrics replace application-specific model evaluation.

## Follow-up after 0.6

The next increment should add executable Semgrep/CodeQL query packs, live adapter clients with recorded query provenance, signed release attestations/SBOM, and a larger human-reviewed agentic/MCP benchmark.
