# Agentic AI, tool use and MCP

This profile covers systems where a model can retrieve data, maintain memory, choose tools, call MCP servers or trigger workflow side effects.

## Assets and principals

- user and tenant identity;
- system/developer policy;
- retrieved documents and memory;
- tool registry and capability grants;
- tool arguments, destinations and side effects;
- model/provider credentials;
- prompts, traces, evaluation data and audit records.

## Required boundaries

1. External content is data, never authority.
2. Model output is a proposal, never an authorization decision.
3. Tool identity, destination, arguments and side effects are checked by ordinary code.
4. Memory writes require provenance, owner, retention and tenant scope.
5. Every loop has bounded turns, time, tokens, fan-out, retries and cost.
6. High-impact actions require an explicit policy decision and, where appropriate, human confirmation.

## Review slices

Load `vuln.ai.*` together with `vuln.authorization.*`, `vuln.secrets.*`, `vuln.supply.*`, `vuln.availability.*` and `vuln.network.ssrf`.

Prioritize indirect prompt injection, tool authorization, memory/context poisoning, RAG provenance, sensitive context leakage, agent identity, inter-agent messages, model supply chain and unbounded agent loops.

## Safe verification

Use local mock tools, synthetic tenants, canary documents, a deny-by-default capability registry and a fake provider. Assert that untrusted text cannot change policy, destination, tenant, identity or side-effect authorization.
