# Secure Context Atlas 0.7.0 release checklist

Этот checklist предназначен для maintainer/release owner перед публикацией tag и GitHub Release.

## A. Scope, naming and provenance

- [ ] Подтверждены `Secure Context Atlas`, версия `0.7.0`, канал `stable-preview` и дата в `RELEASE.md`, `CHANGELOG.md`, `sources/versions.yaml` и generated indexes.
- [ ] Релиз описан как defensive knowledge base/context layer, а не scanner или exploit collection.
- [ ] Пять primary research repositories имеют URL, commit SHA, дату наблюдения, license и update strategy в `sources/manifest.yaml`/`sources/lock.json`.
- [ ] CWE 4.20 и CAPEC 3.9 пересобраны из pinned machine-readable inputs; URL, counts и SHA-256 совпадают.
- [ ] Advisory feeds остаются dynamic; fixture bundles явно synthetic и не выдаются за production notices.

## B. Generated artifacts

```sh
python3 -B scripts/build_indexes.py --fetch
python3 -B scripts/update_sources.py --write-lock --check
python3 -B scripts/validate_sources.py
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

- [ ] `ai/index.json`, `ai/context-manifest.json`, `ai/maturity-map.json`, `ai/evaluation-report.json`, `ai/coverage-report.json`, `sources/lock.json` и `ai/release-manifest.json` соответствуют 0.7.0.
- [ ] `ai/sbom.spdx.json` имеет SPDX 2.3, правильную версию package и полный список tracked release files после документированных exclusions.
- [ ] `git diff --exit-code` после генерации проходит в CI.

## C. Content and schemas

- [ ] Каждая atomic card содержит `SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK`, safe verification, false positives, remediation и regression test.
- [ ] Scaffolded cards не помечены как reviewed и исключены из default context packs.
- [ ] Agentic cases имеют reviewer, review date, expected controls, safe boundary, expected status и references; `reviewed_fraction = 1.0`.
- [ ] Agentic case recall@5 >= 0.70, target recall@5 >= 0.75, leakage count = 0; holdout recall@5 >= 0.75.
- [ ] Все JSON/YAML samples проходят соответствующие schemas.
- [ ] Проверены stable `vuln.*` IDs, aliases, CWE/CAPEC IDs и crosswalks.

## D. Detector packs

- [ ] `rules/manifest.json` имеет `execution_mode: mixed`, корректный Semgrep engine version и CodeQL pack path.
- [ ] Все executable Semgrep rules срабатывают на positive fixtures и не срабатывают на negative fixtures.
- [ ] CodeQL pack проходит metadata/query validation; при наличии CLI проходит `codeql pack check`.
- [ ] Для каждого rule указаны canonical vulnerability, required control, confidence и safe fixture.
- [ ] Ни один detector match не описан как confirmed finding без reachability/evidence review.

## E. Advisory adapters

- [ ] OSV и GitHub adapters принимают explicit ecosystem/package/version coordinate.
- [ ] Bundle сохраняет `queried_at`, query, source URL, transport и request/response SHA-256.
- [ ] Offline fixtures дают детерминированный normalized output; tokens не попадают в output.
- [ ] Reachability остаётся `unknown`, пока потребитель не проверил dependency graph и runtime path.

## F. Safety and hygiene

- [ ] Нет реальных credentials, private keys, raw wordlists, payload datasets, web shells, exploit chains или destructive instructions.
- [ ] Нет `__pycache__`, временных XML/ZIP, caches или untracked release inputs.
- [ ] Проверены action SHAs и workflow permissions: quality — read-only, attestations — только `contents: read`, `id-token: write`, `attestations: write`.
- [ ] `SECURITY.md`, `AGENTS.md` и license/provenance documents согласованы с release scope.

## G. Publication

- [ ] Review `ai/coverage-report.json` и `ai/evaluation-report.json`; release notes публикуют ограничения и backlog.
- [ ] Создан commit, затем tag `v0.7.0`, затем GitHub Release `v0.7.0` от `hemp-dev`.
- [ ] В release assets приложены `RELEASE.md`, `CHANGELOG.md`, `ai/sbom.spdx.json` и `ai/release-manifest.json`.
- [ ] После публикации `release-attestations.yml` завершился успешно и attestations видны в GitHub.
- [ ] URL release, commit SHA, tag SHA и результаты workflow записаны в handoff.
