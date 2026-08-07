# Atomic vulnerability cards

Карточки — retrieval-ready единицы. Каждая описывает одну root-cause family и содержит required frontmatter из `schemas/vulnerability.schema.json`.

Полный нормализованный inventory из первичных репозиториев сохранён в `vulnerability-taxonomy-ai.json` и преобразуется в `ai/vulnerability-map.json`. `curated: true` означает, что для leaf уже есть расширенная atomic card; `ai/maturity-map.json` дополнительно различает `inventory`, `scaffolded`, `curated`, `tested` и `production-ready`. Остальные leafs остаются в coverage inventory до отдельной редакторской карточки и не исчезают из поиска.

Новые карточки должны сохранять правило `SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK`, отделять impact от root cause и иметь safe verification, false positives и regression test. Для перехода в `tested` нужны positive/negative synthetic fixtures; для `production-ready` — reviewed detector или явно документированная manual-review rationale.
