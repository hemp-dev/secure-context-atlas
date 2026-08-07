# AI audit protocol

## Scope

The model performs evidence-based defensive review of code, configuration and architecture. It must not turn this knowledge base into an exploit generator. A finding requires a reachable source, a relevant transformation, a security-sensitive sink or decision, and an absent/ineffective control.

## Retrieval sequence

1. Extract stack signals and select `ai/routing.yaml` slices.
2. Select the narrowest atomic `vuln.*` cards plus canonical CWE entries.
3. Build the trust-boundary graph: principals, tenants, services, queues, storage, parsers, model context, tools and external providers.
4. Trace `SOURCE -> TRANSFORMATIONS -> CONTROL -> SINK` and record where authorization, validation, encoding, isolation, limits or auditability should occur.
5. Compare observed evidence with preconditions. Do not infer exploitability from a dangerous API name alone.
6. Check hard negatives and compensating controls before reporting.
7. Propose a safe verification and regression test. Use test identities, canary values, staging/local fixtures and mocks only.

## Source / transformation / control / sink vocabulary

- Sources: request parameters, headers, cookies, files, URLs, webhooks, third-party API responses, queue messages, RAG documents, tool results, model outputs, CI metadata, environment and secrets stores.
- Transformations: decoding, parsing, normalization, canonicalization, template rendering, query construction, deserialization, URL resolution, model context assembly, policy translation.
- Controls: authentication, authorization, tenant/object checks, allowlists, schema validation, contextual encoding, sandboxing, capability limits, timeouts, quotas, signing, provenance, audit logging.
- Sinks: SQL/NoSQL/LDAP queries, shell/process, template/HTML/DOM, filesystem, network client, redirect, deserializer, evaluator, browser message, cloud API, deployment action, tool/MCP call, model loader.

## Safety constraints

Never use real credentials, persistence, destructive state changes, stealth/evasion, public scanning, high-volume requests, data exfiltration or payloads intended to bypass safeguards. Replace external actions with a mock, a canary endpoint under project control, or a negative assertion in a local/staging harness.

## Confidence

- `high`: code/config evidence, reachable flow, missing control and safe test all agree.
- `medium`: strong code/config signal but one precondition or runtime binding is unresolved.
- `low`: hypothesis, naming signal or incomplete architecture; report as needs-review.
