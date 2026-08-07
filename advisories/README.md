# Dynamic advisory adapters

Static vulnerability cards explain root causes and controls. Dependency advisories change independently and must be queried through an adapter with package coordinates, ecosystem, version, timestamp, source and advisory ID.

Adapters must not silently convert an advisory into a source-code finding. Require a dependency edge, affected version range, reachable component and remediation decision.
