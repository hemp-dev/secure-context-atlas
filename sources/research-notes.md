# Research notes and normalization decisions

Исследование выполнено 2026-08-07. Пять заданных репозиториев дополняют друг друга и не являются одной taxonomy:

| Source | Что было полезно | Как нормализовано |
|---|---|---|
| PayloadsAllTheThings | Гранулярные web/API главы и варианты parser, HTTP, auth, files, SSRF, business logic и AI topics | Названия leaf-классов и aliases; payload bodies, bypass strings и exploit chains исключены |
| HackTricks | Широкий охват web, network, cloud, host, mobile, hardware, blockchain и AI/MCP | Trust-boundary вопросы, surface triggers и defensive references |
| SecLists | Категории discovery/fuzzing/credentials/patterns и отдельные LLM testing datasets | Только dataset manifests; сырые списки не загружаются в AI context |
| Awesome-Hacking | Навигационный каталог смежных проектов, cheat sheets, labs, CI/CD, API и AI security | Source discovery graph и provenance, без копирования third-party contents |
| Awesome Bug Bounty | Workflow/report-oriented темы: IDOR, auth, SSRF, upload, race, business logic и writeups | Наблюдаемые finding patterns, false positives и regression-test prompts |

## Similar and canonical references

- FuzzDB — словарь attack/discovery/response categories; используется только как opt-in fixture manifest.
- OWASP ASVS, WSTG, Cheat Sheets, Top 10 и API Security Top 10 — контрольные требования и test crosswalks, а не новая root-cause нумерация.
- OWASP MASVS/MASTG/MASWE — mobile controls, tests and weakness IDs.
- OWASP GenAI/agentic guidance, MITRE ATLAS, garak and promptfoo — AI/LLM/RAG/agent threat vocabulary; jailbreak prompts and red-team payloads не копируются.
- PortSwigger Academy — parser/proxy/browser/API topic index; lab solutions не копируются.
- Vulhub — isolated vulnerable-lab references; запуск только locally/staging and only with authorization.
- CodeQL and Semgrep — source/sink/query abstraction; tool output is evidence to review, not an automatic finding.
- Gitleaks, OSV, GitHub Advisory Database and OpenSSF Scorecard — scanning/advisory posture signals, kept dynamic and separated from conceptual cards.
- Assetnote Wordlists, InternalAllTheThings, HardwareAllTheThings, awesome-web-security and pentest-book — discovery references with explicit opt-in and upstream license provenance.

## Merge policy

1. MITRE CWE is the canonical weakness ontology. Stable `vuln.*` IDs identify repository cards and are not a competing numeric standard.
2. CAPEC remains an attack-pattern layer. One card may have several CAPEC links or none when the current CAPEC release has no precise mapping.
3. OWASP/ASVS/WSTG/MASVS/GenAI IDs are versioned crosswalks. An API risk, AI risk or dataset category is not silently relabeled as a CWE.
4. Every card must show preconditions, trust boundaries, data flow, code/config/architecture signals, safe verification, false positives, remediation and regression tests.
5. Payload-oriented source material is represented by metadata and placeholders only. It is never part of default retrieval.
