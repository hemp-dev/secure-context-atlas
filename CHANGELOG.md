# Changelog

Все заметные изменения Secure Context Atlas фиксируются здесь. Формат ориентирован на [Keep a Changelog](https://keepachangelog.com/).

## [0.5.0] — 2026-08-08

### Added

- `sctx` CLI: `list`, `show`, `search`, `pack`, `validate` и `export-sarif`.
- JSONL/Markdown context packs с selection metadata, routing order и token budget.
- `schemas/finding.schema.json`, `schemas/evidence.schema.json` и SARIF 2.1.0 exporter.
- `schemas/threat-model.schema.json` и synthetic agentic RAG threat-model example.
- `sources/lock.json`, source hash verification, source diff utility и scheduled source-refresh workflow.
- Release manifest с SHA-256 для артефактов и финальный release validator.
- Agentic AI/MCP platform profile, OWASP Agentic и NIST AI RMF crosswalks.
- 67 новых defensive cards; всего 111 curated cards.
- 134 deterministic synthetic evaluation fixtures с recall@5 baseline 1.0.
- 10 Semgrep/CodeQL detector contracts и regression SARIF fixture.

### Changed

- Release metadata обновлена до `0.5.0`, channel — `stable-preview`.
- CI запускает source fetch, evaluation, rule/threat-model validation и unit tests.
- Coverage report теперь показывает maturity и честный inventory backlog.

### Security and safety

- Fixtures и detector contracts не содержат credentials, live targets, payload chains или destructive actions.
- Model output, retrieved documents и tool results остаются untrusted data; capability checks выполняются обычным кодом.
- Advisory feeds по-прежнему не зеркалируются в статическую taxonomy.

### Known limitations

- 194 normalized leaf classes остаются inventory-only.
- 868 активных CWE не имеют curated-card mapping; часть записей является категориями или абстракциями и не требует отдельной prose-карточки.
- Evaluation suite измеряет deterministic retrieval/evidence contract и не является benchmark конкретной LLM.
- Domain/trademark availability названия не проверялась.

## [0.4.0] — 2026-08-08

- Добавлены agentic AI, MCP, memory, tool, inter-agent и model-supply-chain cards.
- Добавлены `platforms/ai-agentic.md`, `taxonomy/agentic-map.yaml` и threat-model examples.

## [0.3.0] — 2026-08-08

- Добавлены Semgrep/CodeQL detector contracts.
- Добавлен SARIF exporter и regression fixture repository.
- Добавлены rule manifest и detector validation.

## [0.2.0] — 2026-08-08

- Добавлены 67 новых atomic vulnerability cards.
- Добавлены maturity statuses и risk-based curation priorities.
- Добавлен deterministic evaluation suite из 134 synthetic fixtures.
- Добавлены finding/evidence schemas.

## [0.1.0] — 2026-08-07

- Initial Secure Context Atlas foundational-preview release.
- 305 normalized vulnerability leaf classes with stable AI-friendly `vuln.*` IDs.
- 44 atomic defensive vulnerability cards.
- Full CWE 4.20 and CAPEC 3.9 compact indexes.
- Language, framework, platform and AI audit guidance.
- OSV and GitHub Advisory Database adapter contracts.

## [Unreleased]

Planned follow-up: expand production-ready cards, add provider-specific optional model benchmarks, introduce signed artifact attestations and continue framework coverage.
