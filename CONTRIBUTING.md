# Contributing

1. Выбирайте один coherent weakness family на карточку. Generic weakness и language/framework-specific guidance разделяйте.
2. Сначала обновите `taxonomy/` и provenance, затем карточку, mapping и тестовый пример.
3. Не добавляйте рабочие payloads, реальные секреты, destructive commands, persistence, stealth/evasion или инструкции по несанкционированной эксплуатации.
4. Для safe verification используйте test accounts/tenants, canary values, staging/local harnesses, mocks и assertions о том, что контроль сработал.
5. Запустите:

   ```sh
   python3 scripts/build_indexes.py
   python3 scripts/validate_repo.py
   ```

6. В описании изменения укажите source provenance, затронутые mappings, false-positive rationale и regression test.

## Стиль карточек

Карточка должна быть атомарной, evidence-oriented и пригодной для retrieval. Не смешивайте impact с root cause: например, RCE — часто последствие, а canonical CWE должен описывать установленную первопричину.
