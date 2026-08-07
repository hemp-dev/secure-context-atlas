# Detection packs

Rules in this directory are defensive detector packs. The manifest distinguishes executable Semgrep/CodeQL rules from contract-only records. A match is a triage signal, not a confirmed finding: the auditor still has to prove reachability, missing control, preconditions and impact with evidence.

The first adapter set is intentionally small and reviewable:

- executable Semgrep patterns for common source/sink signals;
- an executable CodeQL pack for dynamic-evaluation signals;
- contract-only CodeQL references for data-flow or authorization checks that require application-specific modeling;
- SARIF-compatible finding metadata.

Run the manifest and fixture checks with:

```sh
python3 -B scripts/validate_rules.py
```

The validator runs every executable Semgrep rule against positive and negative local fixtures. If the CodeQL CLI is installed it also runs `codeql pack check`; otherwise it still validates pack metadata, query identity and fixture mappings. Rules must use local/staging fixtures and must not contain operational payloads, credentials or public-target instructions.
