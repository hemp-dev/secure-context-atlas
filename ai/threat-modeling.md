# Threat modeling for AI-assisted review

Represent the system as a graph of principals, assets, trust boundaries, data flows, decisions and sinks. Include human users, service identities, tenants, background workers, CI actors, cloud control planes, model providers, vector stores, tools and MCP servers.

For each edge ask:

- Is the source attacker-controlled, tenant-controlled, third-party-controlled, model-generated or merely untrusted?
- Which parser, decoder, normalizer, retriever, template, query builder or policy translator changes its meaning?
- Where is authentication performed, and where is authorization for the exact object/function/property/tool performed?
- Can the flow cross a tenant, privilege, network, data classification or execution boundary?
- What happens on timeout, parse failure, redirect, retry, duplicate delivery, partial commit or policy disagreement?
- Can an agent choose a tool, arguments, destination, identity or side effect beyond the intended capability?

Model confidentiality, integrity, availability, privacy, safety and auditability as separate assets. Do not treat a model refusal as an authorization boundary; enforce controls in ordinary code and infrastructure.
