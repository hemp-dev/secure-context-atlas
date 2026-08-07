# Secure Context Atlas 0.6.0

## Provenance and Evaluation Preview

Дата релиза: **2026-08-08**

Канал: **stable-preview**

Статус: **готов к ограниченному публичному preview-использованию с проверяемыми schemas, provenance и holdout evaluation**

## Что нового в 0.6.0

- Полная JSON Schema validation для карточек, findings, threat models, context packs, advisories, provenance, evaluation и detector contracts.
- Сгенерированные карточки разделены на `curated/reviewed` и `scaffolded/needs-review`; незавершённый контент не загружается в `sctx pack` по умолчанию.
- Добавлен независимый holdout-набор из 12 перефразированных synthetic cases: текущий `recall@5` — **0.8333**, `MRR` — **0.8446**.
- `sctx pack` получил строгие фильтры по stack/surface/family/maturity, deterministic `pack_id`, card IDs и source provenance.
- Добавлены normalized advisory schema и synthetic OSV/GHSA fixtures; advisory не превращается автоматически в code finding.
- Пять primary research repositories закреплены commit SHA в `sources/lock.json`.
- CI использует pinned action SHAs, least-privilege read permissions для quality job и `git diff --exit-code` после генерации.
- Detector pack явно объявлен `contract-only`; executable Semgrep/CodeQL packs остаются отдельным следующим этапом.

## 1. Название и позиционирование

### Выбранное название: Secure Context Atlas

`Secure Context Atlas` прямо передаёт назначение проекта: безопасный контекст для анализа кода, архитектуры, trust boundaries, стандартов и AI-retrieval маршрутов.

Рекомендуемый tagline:

> Evidence-first security knowledge for AI-assisted audits.

Русский вариант:

> Доказательная база знаний для AI-assisted аудита безопасности.

Название позиционирует проект как knowledge base и audit context layer, а не как сканер, exploit framework или коллекцию payloads.

### Альтернативы

| Вариант | Сильная сторона | Компромисс |
|---|---|---|
| `Secure Context Atlas` | Ясно объясняет AI/RAG-направление и роль knowledge base | Длиннее и менее удобно как package/repository name |
| `BoundaryLens` | Точно подчёркивает анализ границ доверия | Звучит уже и менее явно говорит о vulnerability knowledge |
| `CWE Compass` | Сразу понятна связь с канонической ontology | Слишком описательное и менее брендируемое |
| `Secure Context Atlas` | Хорошо объясняет AI/RAG-направление | Длиннее и менее удобно как package/repository name |

В качестве негативного фильтра не использовались `TrustGraph` и `Boundary Atlas`: эти названия уже связаны с существующими AI/context/security-проектами — [TrustGraph](https://docs.trustgraph.ai/) и [Boundary Atlas](https://boundarytitan.wordpress.com/). Это не заменяет полноценную проверку товарных знаков и доменов.

В этом релизе `Secure Context Atlas` используется как выбранное рабочее имя. Для короткого технического slug используется `secure-context-atlas`. Свободность домена, GitHub organization и товарного знака не проверялась; перед публичным брендингом нужна отдельная legal/domain due diligence.

## 2. Что выпускается

Secure Context Atlas — статическая, версионируемая и AI-ориентированная defensive knowledge base для:

- source-code и architecture review;
- web/API, browser, parser, file, network и business-logic аудитов;
- cloud, containers/Kubernetes, mobile, CI/CD, SCM и supply-chain review;
- AI/LLM/RAG/agent/MCP threat modeling и safe verification;
- evidence-based findings с canonical CWE, CAPEC и стандартными crosswalks.

Внешние payloads, credential lists, web shells, реальные секреты и рабочие exploit chains в релиз не входят.

## 3. Состав и метрики релиза

| Область | В релизе |
|---|---:|
| Нормализованные классы и варианты | 305 leaf-классов |
| Atomic vulnerability cards | 111: 44 curated, 67 scaffolded |
| Inventory-only backlog | 194 leaf-класса |
| CWE 4.20 | 969 импортированных записей, 944 активных, 25 deprecated |
| Curated CWE mapping | curated/scaffolded состояния разделены; active CWE backlog публикуется отдельно |
| CAPEC 3.9 | 615 attack patterns |
| Языки | 13 |
| Framework guidance | 6 основных профилей |
| Platform guidance | cloud, containers/Kubernetes, Android, iOS, AI/LLM, CI/CD, enterprise/AD, hardware/IoT |
| Primary repositories | 5 |
| Dynamic advisory adapters | OSV, GitHub Advisory Database |
| Deterministic evaluation fixtures | 134 базовых + 12 независимых holdout |
| Detector contracts | 10 Semgrep/CodeQL adapters |
| Threat-model examples | 1 валидируемый agentic RAG model |
| Context-pack CLI | `sctx list/show/search/pack/validate/export-sarif` |

Полный inventory остаётся доступен даже там, где ещё нет отдельной редакторской карточки: `ai/vulnerability-map.json` содержит все 305 stable-ID records, `ai/maturity-map.json` различает `inventory`, `scaffolded` и `curated`, а `ai/cwe-coverage.json` — все записи текущей CWE-выгрузки. В coverage report отдельно отражены карточки scaffolded и 194 leaf без atomic card; это честный backlog, а не скрытая потеря покрытия.

## 4. Источники и provenance

Первичный research охватывает:

1. [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — гранулярные web/API/parser/auth/file/AI темы.
2. [HackTricks](https://github.com/HackTricks-wiki/hacktricks) — web, network, cloud, host, mobile, hardware, blockchain и AI/MCP контекст.
3. [SecLists](https://github.com/danielmiessler/SecLists) — dataset categories и discovery vocabulary; raw lists не загружаются по умолчанию.
4. [Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking) — discovery graph смежных проектов.
5. [Awesome Bug Bounty](https://github.com/djadmin/awesome-bug-bounty) — report/workflow-oriented topic discovery.

Дополнительные canonical/similar references описаны в [`sources/research-notes.md`](sources/research-notes.md) и [`sources/manifest.yaml`](sources/manifest.yaml): MITRE CWE/CAPEC, OWASP ASVS/WSTG/API/GenAI/Agentic/Mobile, NIST AI RMF, PortSwigger Academy, FuzzDB, Vulhub, CodeQL, Semgrep, Gitleaks, OSV, GitHub Advisory Database, OpenSSF Scorecard, Assetnote Wordlists, InternalAllTheThings, HardwareAllTheThings и другие.

Машинные версии, commit pins и SHA-256 находятся в [`sources/versions.yaml`](sources/versions.yaml), [`sources/lock.json`](sources/lock.json) и [`ai/source-hashes.json`](ai/source-hashes.json). Каноническая ontology опирается на [CWE machine-readable downloads](https://cwe.mitre.org/data/downloads.html); attack-pattern слой хранится отдельно по [CAPEC downloads](https://capec.mitre.org/data/downloads.html).

## 5. Архитектура релиза

```text
source manifests
      |
      v
canonical CWE/CAPEC indexes ---- standards crosswalks
      |                                      |
      +--> normalized vuln.* map -----------+
                         |
                         v
              AI routing + context packs + evaluation
                         |
                         v
         evidence -> finding -> SARIF -> regression test
```

Ключевое правило каждой карточки:

```text
SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK
```

Наличие опасного API, библиотеки, endpoint или слова в конфигурации само по себе не является finding. AI должен доказать reachability, missing/ineffective control, preconditions и impact.

## 6. Быстрый старт для потребителя

### Использовать готовый release artifact

Загрузите репозиторий, затем начните с:

1. [`ai/compact-context.md`](ai/compact-context.md) — минимальный context pack.
2. [`ai/routing.yaml`](ai/routing.yaml) — выбор срезов по стеку и поверхности.
3. [`ai/finding-format.md`](ai/finding-format.md) — формат результата модели.
4. [`AGENTS.md`](AGENTS.md) — обязательный порядок аудита.
5. `vulnerabilities/<family>/<card>.md` — атомарные карточки.
6. `bin/sctx pack --stack python --surface api` — детерминированный context pack.

### Проверить локальную копию

```sh
python3 -m pip install -r requirements-dev.txt
python3 -B scripts/validate_repo.py
python3 -B -m unittest discover -s tests -v
```

Эти команды не выполняют найденный код, не сканируют внешние адреса и не требуют production credentials.

### Перегенерировать индексы после обновления источников

```sh
python3 -B scripts/build_indexes.py --fetch
python3 -B scripts/update_sources.py --write-lock --check
python3 -B scripts/validate_sources.py
python3 -B scripts/run_eval.py --output ai/evaluation-report.json
python3 -B scripts/validate_schemas.py
python3 -B scripts/validate_repo.py
python3 -B scripts/validate_rules.py
python3 -B scripts/validate_threat_models.py
python3 -B scripts/build_release_manifest.py
```

`--fetch` загружает только pinned machine-readable CWE/CAPEC releases, после чего сохраняет компактные индексы, количество записей и SHA-256. `update_sources.py` фиксирует их в `sources/lock.json`. Для обычного использования уже сгенерированные JSON-файлы являются release artifact и сеть не нужна.

## 7. AI integration contract

Модель должна:

1. определить языки, frameworks, infrastructure и AI-компоненты;
2. выбрать релевантные slices по `ai/routing.yaml`;
3. построить карту assets/principals/tenants/trust boundaries;
4. проследить untrusted input от source до sink;
5. проверить object/property/function/tenant/transaction authorization;
6. отдельно проверить parser/interpreter, state/race, error/fail-open, dependencies/CI/secrets;
7. сопоставить доказательство с CWE и versioned crosswalks;
8. валидировать finding по [`schemas/finding.schema.json`](schemas/finding.schema.json);
9. предложить safe verification и regression test;
10. сообщить finding только при наличии evidence.

Для AI-систем external text, retrieved documents, tool results и model output считаются данными, а не authority. Capability, destination, arguments и side effects должны контролироваться обычным кодом и инфраструктурой.

## 8. Безопасные границы

Разрешены: local/staging fixtures, synthetic data, test users/tenants, canary markers, mocks, dry-run tools, bounded timeouts и negative assertions.

Запрещены в содержимом проекта и release workflow: реальные credentials, public scanning, destructive actions, persistence, stealth/evasion, high-volume requests, exfiltration, web shells и working exploit chains. Подробные правила: [`safe-tests/README.md`](safe-tests/README.md) и [`ai/audit-protocol.md`](ai/audit-protocol.md).

## 9. Миграция с предварительной версии

Предварительные файлы сохранены для обратной совместимости:

- `vulnerability-taxonomy-ai.json` — полный normalized inventory;
- `vulnerability-taxonomy-ai.md` — человекочитаемый каталог;
- `vulnerability-record.schema.json` и `vulnerability-records.examples.jsonl` — legacy JSON-record format.

Для нового consumption code используйте:

- `schemas/vulnerability.schema.json` вместо legacy schema;
- `vuln.*` IDs вместо uppercase `INJ.SQL`/`AUTH.IDOR`-подобных legacy IDs;
- `canonical_cwe` вместо самодельного numeric vulnerability ID;
- `ai/vulnerability-map.json` и `ai/aliases.json` для совместимого retrieval;
    - `ai/maturity-map.json` для различения inventory, scaffolded и curated coverage;
- `schemas/finding.schema.json` и `scripts/export_sarif.py` для результатов анализа;
- `bin/sctx` для context packs с token budget и routing trace.

Старые ID не удаляются без migration window: stable mapping и aliases генерируются в `ai/vulnerability-map.json`.

## 10. Лицензия и атрибуция

Оригинальные материалы Secure Context Atlas распространяются по CC BY-SA 4.0, если файл не указывает иное. Условия внешних источников не переопределяются; attribution и excluded content описаны в [`sources/licenses.yaml`](sources/licenses.yaml). Advisories и live feeds не зеркалируются в статическую taxonomy.

## 11. Известные ограничения

- Это knowledge base, а не автономный scanner и не гарантия отсутствия уязвимостей.
- 305 leaf-классов инвентаризованы; 44 карточки curated, 67 scaffolded/needs-review, 194 остаются inventory-only.
- CWE/CAPEC и OWASP projects обновляются; перед production audit нужно обновить provenance и regenerated artifacts.
- Advisory presence не равна reachability/exploitability; нужен package coordinate, version и runtime evidence.
- AI output нельзя считать доказательством без code/config/architecture evidence.
- Evaluation suite включает независимый holdout, но всё ещё проверяет deterministic retrieval contract и не заменяет benchmark конкретной LLM.
- Правовая, domain и trademark проверка названия в этот релиз не входит.

## 12. Release checklist

Короткая версия checklist:

- [ ] `sources/manifest.yaml`, `sources/versions.yaml`, licenses и hashes обновлены.
- [ ] Primary repository commits записаны в `sources/lock.json`; `scripts/validate_sources.py` завершился успешно.
- [ ] `python3 -B scripts/build_indexes.py` выполнен.
- [ ] `python3 -B scripts/update_sources.py --check` завершился успешно.
- [ ] `python3 -B scripts/run_eval.py --output ai/evaluation-report.json` завершился успешно.
- [ ] `python3 -B scripts/validate_schemas.py` завершился успешно.
- [ ] `python3 -B scripts/validate_repo.py` завершился `validation passed`.
- [ ] `python3 -B scripts/validate_rules.py` и `python3 -B scripts/validate_threat_models.py` завершились успешно.
- [ ] `python3 -B -m unittest discover -s tests -v` завершился `OK`.
- [ ] `python3 -B scripts/validate_release.py` завершился успешно.
- [ ] Нет `__pycache__`, raw datasets, secrets или временных XML/ZIP в release tree.
- [ ] Новые карточки содержат safe verification, false positives, remediation и regression tests.
- [ ] Проверены mappings и backward compatibility stable IDs.
- [ ] Changelog, release tag и artifact hashes опубликованы вместе.

Расширенная процедура находится в [`docs/release-checklist.md`](docs/release-checklist.md), а последовательность реализации — в [`docs/roadmap-0.6.md`](docs/roadmap-0.6.md).
