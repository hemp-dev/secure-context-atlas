# Secure Context Atlas — Secure AI Audit Knowledge Base

Вендорно-нейтральная база знаний для AI-assisted аудита исходного кода, архитектуры, конфигураций, API, cloud, mobile, supply chain и AI/LLM-систем.

Текущий релиз: **Secure Context Atlas 0.5.0 — Stable Context Platform Preview**. Подробности, варианты названия, миграция и checklist находятся в [`RELEASE.md`](RELEASE.md).

Репозиторий нормализует темы из PayloadsAllTheThings, HackTricks, SecLists, Awesome-Hacking и Awesome-Bug-Bounty, но не копирует payloads, секреты, web shells или готовые exploit chains. Каноническая семантика слабостей — MITRE CWE; CAPEC хранится как отдельный слой attack patterns, а стабильные `vuln.*` ID относятся к атомарным карточкам этого репозитория.

## Что внутри

- `taxonomy/` — семейства, алиасы, CWE/CAPEC/OWASP crosswalks и технологический роутинг.
- `vulnerabilities/` — атомарные defensive-карточки: preconditions, trust boundaries, source/transform/control/sink, сигналы кода, safe verification, false positives, remediation и regression tests.
- `languages/`, `frameworks/`, `platforms/` — язык-, framework- и platform-specific guidance.
- `ai/` — компактный контекст, finding format, threat-model protocol, routing и сгенерированные индексы.
- `evals/` — synthetic retrieval/evidence fixtures и deterministic evaluation harness.
- `rules/` — defensive Semgrep/CodeQL detector contracts с canonical `vuln.*` mappings.
- `regression/` — synthetic finding/SARIF fixtures.
- `bin/sctx` — CLI для context packs, поиска и SARIF export.
- `datasets/` — только manifests для wordlists и payload-oriented наборов; загрузка не происходит по умолчанию.
- `advisories/` — адаптеры OSV/GitHub Advisory Database, отделённые от статической taxonomy.
- `scripts/` и `tests/` — воспроизводимая генерация индексов и quality gates.

Полный нормализованный каталог классов и вариантов находится в [`vulnerability-taxonomy-ai.md`](vulnerability-taxonomy-ai.md) и [`vulnerability-taxonomy-ai.json`](vulnerability-taxonomy-ai.json); AI-friendly stable-ID view — [`ai/vulnerability-map.json`](ai/vulnerability-map.json).

Релизные документы: [`RELEASE.md`](RELEASE.md), [`CHANGELOG.md`](CHANGELOG.md), [`SECURITY.md`](SECURITY.md), [`docs/roadmap-0.5.md`](docs/roadmap-0.5.md) и [`docs/release-checklist.md`](docs/release-checklist.md).

## Быстрый старт

```sh
python3 scripts/build_indexes.py
python3 scripts/run_eval.py --output ai/evaluation-report.json
python3 scripts/validate_repo.py
python3 scripts/validate_rules.py
python3 scripts/validate_threat_models.py
```

Валидатор не запускает сетевые проверки и не выполняет найденные значения как команды. Safe verification в карточках рассчитана на локальные unit/integration tests, staging, test tenants, canary markers и mocks.

## Стандарты и версии

Каноническая загрузка CWE 4.20 и CAPEC 3.9 описана в `sources/manifest.yaml`, `sources/versions.yaml` и `sources/lock.json`. Crosswalks покрывают OWASP Top 10 2025, API Security Top 10 2023, ASVS 5.0, WSTG, MASVS/MASTG/MASWE, OWASP GenAI/Agentic guidance и NIST AI RMF. Версии не смешиваются: динамические advisories и changing feeds подключаются только через adapters.

## AI usage contract

Модель должна сначала инвентаризировать стек и границы доверия, затем загружать только релевантные срезы `ai/routing.yaml`, трассировать доказуемый поток `SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK`, отдельно проверять authorization/state/error paths и выдавать finding только с evidence. Формат и обязательные поля находятся в `ai/finding-format.md`; политика безопасной проверки — в `ai/audit-protocol.md`.

## Лицензирование

Собственные тексты и схемы распространяются по лицензии, указанной в `sources/licenses.yaml`. Внешние источники не встраиваются целиком: provenance, URL, версия и правила атрибуции находятся в `sources/manifest.yaml` и `sources/licenses.yaml`; условия конкретного upstream имеют приоритет.
