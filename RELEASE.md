# Secure Context Atlas 0.7.0

## Executable Detection and Attested Preview

Дата релиза: **2026-08-08**
Канал: **stable-preview**
Репозиторий: [hemp-dev/secure-context-atlas](https://github.com/hemp-dev/secure-context-atlas)

Secure Context Atlas — defensive knowledge base и context layer для AI-assisted аудита. Релиз не является автономным сканером, exploit framework или коллекцией payloads. Любой detector match или advisory — это сигнал для проверки, а не подтверждённая уязвимость.

## Что нового в 0.7.0

- Исполняемые detector packs: семь Semgrep-правил и один CodeQL query pack с positive/negative fixtures; три application-specific CodeQL-контракта остаются явно `executable: false`.
- Новый `scripts/validate_rules.py`: каждый исполняемый Semgrep rule запускается на безопасной локальной positive/negative паре; CodeQL pack проверяется структурно и через `codeql pack check`, если CLI доступен.
- Live OSV и GitHub Advisory Database adapters с package coordinate, timestamp, transport, source URL и SHA-256 canonical request/raw response. Advisory не превращается автоматически в code finding.
- Fixture-backed advisory validation: одинаковый fixture даёт тот же normalized bundle, чтобы provenance и normalization были regression-tested без сети.
- Deterministic SPDX 2.3 file-level SBOM (`ai/sbom.spdx.json`) и SHA-256 release manifest (`ai/release-manifest.json`).
- GitHub Actions workflow [`release-attestations.yml`](.github/workflows/release-attestations.yml) после публикации GitHub Release создаёт artifact provenance и SBOM attestation с least-privilege permissions.
- 27 maintainer-reviewed synthetic agentic/MCP evaluation cases с expected controls, safe boundary, review metadata и OWASP Agentic references.
- JSON Schema contracts расширены для advisory bundles, reviewed agentic cases и SPDX release SBOM.
- CI теперь проверяет advisory adapters, agentic metrics, SBOM coverage, release manifest и generated-tree determinism.

## Метрики и состав

| Область | v0.7.0 |
|---|---:|
| Нормализованные leaf-классы | 305 |
| Atomic vulnerability cards | 111: 44 curated, 67 scaffolded |
| Inventory-only backlog | 194 |
| CWE | 4.20: 969 импортированных, 944 активных, 25 deprecated |
| CAPEC | 3.9: 615 attack patterns |
| Языки / frameworks / platforms | 13 / 6 / 8 профилей |
| Базовые retrieval fixtures | 134 |
| Независимый holdout | 12 |
| Reviewed agentic/MCP cases | 27 |
| Agentic case recall@5 | 0.8519 |
| Agentic target recall@5 | 0.8919 |
| Agentic reviewed fraction | 1.0 |
| Agentic leakage count | 0 |
| Executable Semgrep rules | 7 |
| Executable CodeQL queries | 1 |
| Contract-only detector records | 3 |
| Dynamic advisory adapters | OSV, GitHub Advisory Database |

Базовые значения, holdout, MRR и полный список agentic cases находятся в [`ai/evaluation-report.json`](ai/evaluation-report.json). Эти числа характеризуют воспроизводимый retrieval/evidence contract и не являются оценкой конкретной LLM.

## Архитектура provenance

```text
source manifests + pinned CWE/CAPEC
              |
              v
       canonical indexes + crosswalks
              |
              +--> vuln.* cards --> context packs --> model audit
              |
              +--> detector packs --> SARIF/triage --> evidence review
              |
              +--> advisory adapters --> normalized bundle --> reachability review
              |
              +--> tracked tree --> SPDX SBOM + SHA-256 manifest --> attestations
```

Для статической карточки сохраняется поток:

```text
SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK
```

Для advisory bundle дополнительно сохраняются:

```text
package coordinate -> adapter request -> raw response -> normalized advisories -> dependency/reachability review
```

Для agentic audit external content, retrieved documents, model output и tool result — untrusted data. Authorization capability принадлежит обычному коду и инфраструктуре; модель не является границей авторизации.

## Быстрый старт

```sh
python3 -m pip install -r requirements-dev.txt
python3 -B scripts/run_eval.py --output ai/evaluation-report.json
python3 -B scripts/validate_advisories.py
python3 -B scripts/build_sbom.py
python3 -B scripts/validate_sbom.py
python3 -B scripts/validate_schemas.py
python3 -B scripts/validate_repo.py
python3 -B scripts/validate_rules.py
python3 -B scripts/validate_threat_models.py
python3 -B scripts/build_release_manifest.py
python3 -B scripts/validate_release.py
python3 -B -m unittest discover -s tests -v
```

Для обновления pinned machine-readable sources:

```sh
python3 -B scripts/build_indexes.py --fetch
python3 -B scripts/update_sources.py --write-lock --check
python3 -B scripts/validate_sources.py
```

`--fetch` загружает только pinned CWE/CAPEC inputs. Advisory client обращается в сеть только когда maintainer явно передал package coordinate; для тестов используется `--response` с synthetic fixture.

## Detector packs

Manifest [`rules/manifest.json`](rules/manifest.json) — источник истины для engine, executable status, fixture и canonical `vuln.*` mapping.

Проверка:

```sh
python3 -B scripts/validate_rules.py
```

Semgrep-проверка требует, чтобы каждое executable rule сработало на positive fixture и не сработало на negative fixture. Это проверяет detector contract и снижает false positives, но не заменяет traceability review: найденный API может быть недостижимым, защищённым или использоваться в безопасном режиме.

CodeQL pack находится в [`rules/codeql-pack`](rules/codeql-pack). В окружениях с CodeQL CLI валидатор выполняет `codeql pack check`; в минимальном окружении остаются schema/metadata checks. Контрактные правила без executable query не маскируются под работающий scanner.

## Advisory adapters

Пример безопасного live lookup:

```sh
python3 -B scripts/advisory_adapter.py \
  --source osv --ecosystem PyPI --package requests --version 2.32.0 \
  --output /tmp/requests-advisories.json
```

GitHub Advisory Database использует тот же интерфейс с `--source github-advisory-database`; токен опционален и читается только из `--token`, `GITHUB_TOKEN` или `GH_TOKEN`. Токены не записываются в bundle. В каждом результате фиксируются `query`, `queried_at`, `transport`, `source_url`, `request_sha256` и `response_sha256`.

Проверка fixture-backed normalization:

```sh
python3 -B scripts/validate_advisories.py
```

Наличие GHSA/OSV записи не доказывает, что зависимость reachable, загружена runtime-кодом или попадает в affected range. Эти условия должен подтвердить потребитель по lockfile, dependency graph и runtime evidence.

## SBOM и release attestations

`scripts/build_sbom.py` строит детерминированный SPDX 2.3 file-level SBOM по committed release tree. Каждый файл получает SHA-256; временные raw XML/ZIP, cache и самогенерируемые manifest artifacts исключены по контракту. `scripts/validate_sbom.py` сравнивает список tracked files и hashes с SBOM.

`scripts/build_release_manifest.py` строит SHA-256 manifest того же committed tree. После публикации GitHub Release workflow выполняет оба validator-а и запускает `actions/attest` с `id-token: write` и `attestations: write`. Полученные attestations позволяют потребителю проверить происхождение release manifest и SBOM через GitHub artifact attestation tooling.

SBOM не заменяет license/provenance review: внешние источники и их условия остаются описаны в [`sources/manifest.yaml`](sources/manifest.yaml) и [`sources/licenses.yaml`](sources/licenses.yaml).

## Agentic/MCP evaluation

[`evals/agentic/cases.json`](evals/agentic/cases.json) покрывает prompt/indirect injection, RAG trust, tenant isolation, context leakage, tool authorization, MCP capability confusion, agent identity, memory poisoning, loops, inter-agent trust, output handling, model supply chain, callbacks, fail-open и evaluation integrity.

Каждый case содержит:

- reviewer, review status и дату review;
- primary `vuln.*` target IDs;
- expected controls и expected status;
- безопасную synthetic boundary;
- references на OWASP Agentic guidance;
- leakage-safe query/snippet без target ID, title и CWE в тексте запроса.

Quality gate требует `reviewed_fraction = 1.0`, case recall@5 не ниже 0.70, target recall@5 не ниже 0.75 и нулевую leakage count. Результат не утверждает, что модель правильно использует tools: для этого нужен отдельный application-specific red-team/evaluation контур.

## Миграция с v0.6

- `rules/manifest.json`: потребитель должен учитывать `execution_mode: mixed` и поле `executable`; contract-only rules нельзя запускать как Semgrep/CodeQL queries.
- Advisory fixture: старый одиночный advisory record совместим со schema, но новые adapter outputs — это bundle с `advisories[]` и provenance v1.1.
- `evals/manifest.json`: добавлен `agentic_benchmark`; consumer должен игнорировать его только если явно не использует v0.7 evaluation.
- В release tree появились `ai/sbom.spdx.json`, `schemas/advisory-bundle.schema.json`, `schemas/agentic-eval.schema.json` и `schemas/sbom.schema.json`.
- Для нового consumption code используйте `vuln.*`, `canonical_cwe`, `ai/vulnerability-map.json`, `ai/aliases.json` и `schemas/finding.schema.json`; legacy JSON-record files остаются только для compatibility.

## Безопасные границы

Разрешены local/staging fixtures, synthetic data, test users/tenants, canary markers, mocks, dry-run tools, bounded timeouts и negative assertions.

В репозитории и release workflow запрещены реальные credentials, public scanning, destructive actions, persistence, stealth/evasion, high-volume requests, exfiltration, web shells и working exploit chains. Advisory lookups должны использовать минимально необходимые package coordinates и не сохранять токены.

## Ограничения

- Это knowledge base и audit context layer, а не автономный scanner и не гарантия отсутствия уязвимостей.
- 194 normalized leaf-класса остаются inventory-only; 67 карточек — scaffolded/needs-review.
- Semgrep/CodeQL match требует evidence review и не является confirmed finding.
- Advisory presence не равна reachability или exploitability.
- Synthetic retrieval и reviewed benchmark не заменяют evaluation на коде, инфраструктуре и model/tool policy конкретного потребителя.
- Attestation workflow запускается GitHub после опубликованного release и зависит от настроек repository Actions и attestations.
- Legal/domain/trademark due diligence для названия не входит в этот релиз.

## Release checklist

Подробный checklist находится в [`docs/release-checklist.md`](docs/release-checklist.md), roadmap — в [`docs/roadmap-0.7.md`](docs/roadmap-0.7.md). Перед tag/release должны пройти `validate_sources`, `run_eval`, `validate_advisories`, `validate_sbom`, `validate_schemas`, `validate_repo`, `validate_rules`, `validate_threat_models`, unit tests, `build_release_manifest` и `validate_release`. После генерации tracked artifacts рабочее дерево должно быть чистым.

Название `Secure Context Atlas` — рабочее брендирование релиза; перед коммерческим использованием необходима отдельная проверка товарного знака, домена и организации.
