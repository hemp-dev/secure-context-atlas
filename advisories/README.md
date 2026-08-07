# Dynamic advisory adapters

Static vulnerability cards explain root causes and controls. Dependency advisories change independently and must be queried through an adapter with package coordinates, ecosystem, version, timestamp, source and advisory ID.

Adapters must not silently convert an advisory into a source-code finding. Require a dependency edge, affected version range, reachable component and remediation decision.

The canonical normalized record is [`schemas/advisory.schema.json`](../schemas/advisory.schema.json). The files under `advisories/fixtures/` are synthetic contract fixtures; they are not real vulnerability notices and must not be used as production advisories.
