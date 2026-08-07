# Evaluation suite

The evaluation suites measure retrieval and evidence-contract behaviour without calling an external model or touching live targets. v0.7 adds a reviewed agentic/MCP benchmark for tool authorization, RAG trust, memory, identity, inter-agent and model-supply-chain boundaries.

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

The deterministic runner checks that the expected card is retrievable, the fixture contains no forbidden operational content, and the expected status is preserved. The agentic cases additionally record reviewer, review date, expected controls, safe boundary and OWASP Agentic references; the runner reports case recall@5, target recall@5, MRR, review coverage and leakage. It is a regression baseline, not proof that a particular LLM is secure or accurate.

Agentic cases live in [`evals/agentic/cases.json`](agentic/cases.json) and are validated by [`schemas/agentic-eval.schema.json`](../schemas/agentic-eval.schema.json). They contain synthetic prompts and control expectations only; model output and tool results remain untrusted data.

Fixtures must use local/staging/mocked boundaries, synthetic canaries and redacted examples. Do not add credentials, public targets, payload chains or destructive proof-of-concept steps.
