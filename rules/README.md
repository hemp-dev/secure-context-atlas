# Detection adapters

Rules in this directory are defensive detector contracts, not executable Semgrep or CodeQL query packs yet. They identify code or configuration signals and point back to a canonical `vuln.*` card; a rule match is not by itself a confirmed finding. The manifest declares this explicitly with `execution_mode: contract-only`.

The first adapter set is intentionally small and reviewable:

- Semgrep-style pattern contracts for common source/sink signals;
- CodeQL query-family references for data-flow or authorization checks;
- SARIF-compatible finding metadata.

Run the manifest and fixture checks with:

```sh
python3 -B scripts/validate_rules.py
```

Rules must use local/staging fixtures and must not contain operational payloads, credentials or public-target instructions.
