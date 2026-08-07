# Evaluation suite

The evaluation suite measures retrieval and evidence-contract behaviour without calling an external model or touching live targets.

Each fixture is synthetic and contains:

- `id`;
- `vulnerability_id`;
- `polarity`: `positive`, `negative` or `ambiguous`;
- `query`;
- `snippet`;
- `expected_cwe`;
- `expected_status`.

Run it with:

```sh
python3 -B scripts/run_eval.py
python3 -B scripts/run_eval.py --output ai/evaluation-report.json
```

The deterministic runner checks that the expected card is retrievable, the fixture contains no forbidden operational content, and the expected status is preserved. It is a regression baseline, not proof that a particular LLM is secure or accurate.

Fixtures must use local/staging/mocked boundaries, synthetic canaries and redacted examples. Do not add credentials, public targets, payload chains or destructive proof-of-concept steps.
