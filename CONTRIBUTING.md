# Contributing

1. Выбирайте один coherent weakness family на карточку. Generic weakness и language/framework-specific guidance разделяйте.
2. Сначала обновите `taxonomy/` и provenance, затем карточку, mapping и тестовый пример.
3. Не добавляйте рабочие payloads, реальные секреты, destructive commands, persistence, stealth/evasion или инструкции по несанкционированной эксплуатации.
4. Для safe verification используйте test accounts/tenants, canary values, staging/local harnesses, mocks и assertions о том, что контроль сработал.
5. Запустите полный quality gate:

   ```sh
   python3 -B scripts/build_indexes.py --fetch
   python3 -B scripts/update_sources.py --write-lock --check
   python3 -B scripts/run_eval.py --output ai/evaluation-report.json
   python3 -B scripts/validate_schemas.py
   python3 -B scripts/validate_repo.py
   python3 -B scripts/validate_rules.py
   python3 -B scripts/validate_threat_models.py
   python3 -B scripts/build_release_manifest.py
   python3 -B scripts/validate_release.py
   python3 -B -m unittest discover -s tests -v
   ```

6. В описании изменения укажите source provenance, затронутые mappings, false-positive rationale и regression test.

## Стиль карточек

Карточка должна быть атомарной, evidence-oriented и пригодной для retrieval. Не смешивайте impact с root cause: например, RCE — часто последствие, а canonical CWE должен описывать установленную первопричину.
