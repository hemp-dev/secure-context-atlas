# Secure Context Atlas release checklist

Этот checklist предназначен для maintainer/release owner перед публикацией tag или архива.

## A. Scope and naming

- [ ] Confirm release name, version, channel and date in `RELEASE.md`, `CHANGELOG.md`, `sources/versions.yaml` and `ai/index.json`.
- [ ] Treat `Secure Context Atlas` as a working brand until domain/trademark due diligence is complete.
- [ ] Confirm release is described as a defensive knowledge base, not a scanner or exploit collection.

## B. Source and provenance

- [ ] Review the five primary repositories and update `sources/manifest.yaml`.
- [ ] Pin/retrieve machine-readable CWE and CAPEC versions.
- [ ] Record download URL, release date, entry count and SHA-256.
- [ ] Check upstream license/attribution and excluded content.
- [ ] Keep OSV/GHSA/advisory feeds dynamic or explicitly pinned; never silently embed stale advisory data.

## C. Generated artifacts

```sh
python3 -B scripts/build_indexes.py --fetch
```

- [ ] `ai/cwe-index.json` contains all entries for the pinned release.
- [ ] `ai/cwe-coverage.json` distinguishes imported, curated and taxonomy-only entries.
- [ ] `ai/capec-index.json`, `ai/vulnerability-map.json`, `ai/aliases.json`, `ai/standards-coverage.json` and `ai/index.json` are regenerated.
- [ ] `ai/source-hashes.json` matches the downloaded inputs.

## D. Content quality

- [ ] Every atomic card has complete schema frontmatter.
- [ ] Each card states `SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK`.
- [ ] Preconditions, trust boundaries, authorization points, false positives, impact, remediation and regression tests are present.
- [ ] Safe verification is local/staging/mock based and has no real secrets or destructive action.
- [ ] New aliases do not create an unmarked collision; ambiguous aliases are listed in `ai/aliases.json`.
- [ ] Language, framework, platform and AI routing references resolve to existing files or explicit wildcard IDs.

## E. Safety and hygiene

- [ ] Search for accidental secrets, credentials, web shells, destructive commands, exploit chains and raw payload datasets.
- [ ] Remove `__pycache__`, temporary XML/ZIP, raw wordlists and local test data.
- [ ] Verify `.gitignore` covers caches and raw inputs.
- [ ] Check CI workflow permissions and pin third-party actions according to the hosting policy.

## F. Tests and publication

```sh
python3 -B scripts/validate_repo.py
python3 -B -m unittest discover -s tests -v
```

- [ ] Validator reports `validation passed`.
- [ ] Test suite reports `OK`.
- [ ] Review `ai/coverage-report.json` and include coverage/backlog numbers in release notes.
- [ ] Create the version tag only after generated artifacts are deterministic and reviewed.
- [ ] Publish `RELEASE.md`, `CHANGELOG.md`, source hashes and license/provenance together.
- [ ] Keep a rollback copy of the prior generated artifacts and record the previous source versions.
