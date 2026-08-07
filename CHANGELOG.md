# Changelog

Все заметные изменения проекта фиксируются здесь. Формат ориентирован на [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — 2026-08-07

### Added

- Initial Secure Context Atlas foundational-preview release.
- 305 normalized vulnerability leaf classes with stable AI-friendly `vuln.*` IDs.
- 44 atomic defensive vulnerability cards with machine-readable frontmatter.
- Full CWE 4.20 compact index: 969 entries, including 944 active and 25 deprecated records.
- Full CAPEC 3.9 compact index with 615 attack patterns.
- OWASP Top 10 2025, API Security 2023, ASVS, WSTG, MASVS/MASTG/MASWE and GenAI/agentic crosswalks.
- Language guidance for JavaScript, TypeScript, Python, Java, Go, C#, Ruby, PHP, Rust, C, C++, Swift and Kotlin.
- Framework and platform guidance for web/API stacks, cloud/Kubernetes, mobile, CI/CD, enterprise/AD, hardware/IoT and AI/LLM/RAG/MCP.
- AI audit protocol, routing, compact context, threat-modeling and finding format.
- OSV and GitHub Advisory Database adapter contracts.
- Dataset manifests with explicit opt-in and safe-lab boundaries.
- Dependency-free index builder, validator, coverage report and CI workflow.

### Security and safety

- Payloads, credentials, web shells, destructive PoCs, persistence and exploit chains are intentionally excluded.
- Safe verification is limited to local/staging fixtures, synthetic data, canaries, mocks and negative regression tests.
- Dynamic advisory data is kept separate from static conceptual taxonomy.

### Known limitations

- 261 normalized leaf classes remain inventory-only and are not yet represented by a dedicated curated card.
- 905 active CWE entries are imported but not yet mapped to a curated card; the complete list is retained in `ai/coverage-report.json`.
- Name/domain/trademark availability has not been cleared.

## [Unreleased]

Planned follow-up: expand atomic cards for the remaining high-risk families, add more framework-specific mappings, introduce signed release manifests and publish a machine-readable package manifest.
