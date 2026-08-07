# AGENTS.md

## Назначение

Это defensive knowledge repository. Цель — помочь модели находить подтверждённые слабости и проектировать исправления, а не генерировать рабочие атаки.

## Рабочий протокол аудита

Выполняй шаги по порядку:

1. Инвентаризируй проект: репозитории, языки, package manifests, build files, deploy files, public endpoints и тестовые контуры.
2. Определи языки, frameworks, runtime, cloud, container/orchestrator, mobile targets, databases, queues и AI components.
3. Выдели поверхности: web/API, jobs, webhooks, uploads, parsers, CI/CD, secrets, admin paths, storage, model/RAG/tool/MCP boundaries.
4. Построй карту активов и trust boundaries. Для каждого подозрительного потока укажи `SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK`.
5. Загрузи только релевантные карточки из `ai/routing.yaml`; не подмешивай wordlists и payload datasets без явного лабораторного контекста.
6. Найди entry points и проследи attacker-controlled или untrusted data до parser/interpreter/sink.
7. Проверь object-level, property-level, function-level, tenant-level и transaction authorization в месте принятия решения, а не только наличие middleware.
8. Проверь parsers, interpreters, deserializers, redirects, URL resolution, file paths, templates, queries, shell/process APIs и output encoders.
9. Проверь workflows, state transitions, replay/idempotency, race/TOCTOU, rate/resource limits и compensating controls.
10. Проверь dependencies, lockfiles, CI actions/plugins, SCM permissions, artifacts, secrets и deployment configuration.
11. Проверь exception paths, fallback, retries, timeouts и fail-open behaviour.
12. Проверь preconditions и compensating controls безопасным способом: test identities/tenants, canaries, local/staging, unit/integration tests, mocks; не используй реальные секреты, destructive actions, persistence, evasion или exfiltration.
13. Отчитай только то, что подтверждается evidence. Если поток не доказан, пометь finding как hypothesis/needs-review, а не как уязвимость.

## Обязательные поля finding

Каждый finding должен содержать: title, evidence с file/line или config key, input/prerequisite, data flow, missing control, exploitability, impact, confidence, canonical CWE и relevant crosswalks, remediation и regression test. Допустимые состояния: `confirmed`, `probable`, `needs-review`, `not-applicable`.

## Нормализация

- Используй canonical CWE IDs из `ai/cwe-index.json`; не изобретай конкурирующую нумерацию.
- `vuln.*` — стабильные атомарные IDs этого репозитория; старые алиасы допускаются только в `taxonomy/aliases.yaml`.
- CAPEC описывает attack pattern и не заменяет CWE.
- Не переноси payloads, credential lists, web shells или exploit code в карточки. Для dataset достаточно manifest с назначением, лицензией и explicit opt-in.
- Любой новый источник добавляй в `sources/manifest.yaml` с URL, repo, purpose, license, version/date, included/excluded content и update strategy.

## Изменения и проверки

Перед PR запусти `python3 scripts/build_indexes.py` и `python3 scripts/validate_repo.py`. Изменения в исходных источниках требуют обновления provenance и generated artifacts. Новая карточка обязана иметь machine-readable frontmatter из `schemas/vulnerability.schema.json`, safe verification, false positives, remediation и regression tests.
