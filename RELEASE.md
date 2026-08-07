# Secure Context Atlas 0.1.0

## Foundational Defensive Knowledge Release

Дата релиза: **2026-08-07**  
Канал: **foundational-preview**  
Статус: **готов к внутреннему и ограниченному публичному preview-использованию**

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

В этом релизе `Secure Context Atlas` используется как выбранное рабочее имя. Для короткого технического slug можно использовать `secure-context-atlas`. Свободность домена, GitHub organization и товарного знака не проверялась; перед публичным брендингом нужна отдельная legal/domain due diligence.

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
| Atomic vulnerability cards | 44 |
| CWE 4.20 | 969 импортированных записей, 944 активных, 25 deprecated |
| CAPEC 3.9 | 615 attack patterns |
| Языки | 13 |
| Framework guidance | 6 основных профилей |
| Platform guidance | cloud, containers/Kubernetes, Android, iOS, AI/LLM, CI/CD, enterprise/AD, hardware/IoT |
| Primary repositories | 5 |
| Dynamic advisory adapters | OSV, GitHub Advisory Database |

Полный inventory остаётся доступен даже там, где ещё нет отдельной редакторской карточки: `ai/vulnerability-map.json` содержит все 305 stable-ID records, а `ai/cwe-coverage.json` — все записи текущей CWE-выгрузки. В coverage report отражены 261 leaf без atomic card и 905 активных CWE без curated-card mapping; это честный backlog, а не скрытая потеря покрытия.

## 4. Источники и provenance

Первичный research охватывает:

1. [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — гранулярные web/API/parser/auth/file/AI темы.
2. [HackTricks](https://github.com/HackTricks-wiki/hacktricks) — web, network, cloud, host, mobile, hardware, blockchain и AI/MCP контекст.
3. [SecLists](https://github.com/danielmiessler/SecLists) — dataset categories и discovery vocabulary; raw lists не загружаются по умолчанию.
4. [Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking) — discovery graph смежных проектов.
5. [Awesome Bug Bounty](https://github.com/djadmin/awesome-bug-bounty) — report/workflow-oriented topic discovery.

Дополнительные canonical/similar references описаны в [`sources/research-notes.md`](sources/research-notes.md) и [`sources/manifest.yaml`](sources/manifest.yaml): MITRE CWE/CAPEC, OWASP ASVS/WSTG/API/GenAI/Mobile, PortSwigger Academy, FuzzDB, Vulhub, CodeQL, Semgrep, Gitleaks, OSV, GitHub Advisory Database, OpenSSF Scorecard, Assetnote Wordlists, InternalAllTheThings, HardwareAllTheThings и другие.

Машинные версии и SHA-256 находятся в [`sources/versions.yaml`](sources/versions.yaml) и [`ai/source-hashes.json`](ai/source-hashes.json). Каноническая ontology опирается на [CWE machine-readable downloads](https://cwe.mitre.org/data/downloads.html); attack-pattern слой хранится отдельно по [CAPEC downloads](https://capec.mitre.org/data/downloads.html).

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
              AI routing + compact context
                         |
                         v
             evidence -> finding -> regression test
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

### Проверить локальную копию

```sh
python3 -B scripts/validate_repo.py
python3 -B -m unittest discover -s tests -v
```

Эти команды не выполняют найденный код, не сканируют внешние адреса и не требуют production credentials.

### Перегенерировать индексы после обновления источников

```sh
python3 -B scripts/build_indexes.py --fetch
python3 -B scripts/validate_repo.py
```

`--fetch` загружает только pinned machine-readable CWE/CAPEC releases, после чего сохраняет компактные индексы, количество записей и SHA-256. Для обычного использования уже сгенерированные JSON-файлы являются release artifact и сеть не нужна.

## 7. AI integration contract

Модель должна:

1. определить языки, frameworks, infrastructure и AI-компоненты;
2. выбрать релевантные slices по `ai/routing.yaml`;
3. построить карту assets/principals/tenants/trust boundaries;
4. проследить untrusted input от source до sink;
5. проверить object/property/function/tenant/transaction authorization;
6. отдельно проверить parser/interpreter, state/race, error/fail-open, dependencies/CI/secrets;
7. сопоставить доказательство с CWE и versioned crosswalks;
8. предложить safe verification и regression test;
9. сообщить finding только при наличии evidence.

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
- `ai/vulnerability-map.json` и `ai/aliases.json` для совместимого retrieval.

Старые ID не удаляются без migration window: stable mapping и aliases генерируются в `ai/vulnerability-map.json`.

## 10. Лицензия и атрибуция

Оригинальные материалы Secure Context Atlas распространяются по CC BY-SA 4.0, если файл не указывает иное. Условия внешних источников не переопределяются; attribution и excluded content описаны в [`sources/licenses.yaml`](sources/licenses.yaml). Advisories и live feeds не зеркалируются в статическую taxonomy.

## 11. Известные ограничения

- Это knowledge base, а не автономный scanner и не гарантия отсутствия уязвимостей.
- 305 leaf-классов инвентаризованы, но не каждый leaf имеет отдельную curated-card.
- CWE/CAPEC и OWASP projects обновляются; перед production audit нужно обновить provenance и regenerated artifacts.
- Advisory presence не равна reachability/exploitability; нужен package coordinate, version и runtime evidence.
- AI output нельзя считать доказательством без code/config/architecture evidence.
- Правовая, domain и trademark проверка названия в этот релиз не входит.

## 12. Release checklist

Короткая версия checklist:

- [ ] `sources/manifest.yaml`, `sources/versions.yaml`, licenses и hashes обновлены.
- [ ] `python3 -B scripts/build_indexes.py` выполнен.
- [ ] `python3 -B scripts/validate_repo.py` завершился `validation passed`.
- [ ] `python3 -B -m unittest discover -s tests -v` завершился `OK`.
- [ ] Нет `__pycache__`, raw datasets, secrets или временных XML/ZIP в release tree.
- [ ] Новые карточки содержат safe verification, false positives, remediation и regression tests.
- [ ] Проверены mappings и backward compatibility stable IDs.
- [ ] Changelog, release tag и artifact hashes опубликованы вместе.

Расширенная процедура находится в [`docs/release-checklist.md`](docs/release-checklist.md).
