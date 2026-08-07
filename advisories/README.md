# Dynamic advisory adapters

Static vulnerability cards explain root causes and controls. Dependency advisories change independently and must be queried through an adapter with package coordinates, ecosystem, version, timestamp, source and advisory ID.

Adapters must not silently convert an advisory into a source-code finding. Require a dependency edge, affected version range, reachable component and remediation decision.

The canonical normalized record is [`schemas/advisory.schema.json`](../schemas/advisory.schema.json); a query response bundle is defined by [`schemas/advisory-bundle.schema.json`](../schemas/advisory-bundle.schema.json). Every bundle records the coordinate, timestamp, transport, source URL and SHA-256 hashes of the canonical request and raw response. Reachability remains `unknown` until the consuming project proves dependency reachability and version applicability.

Run a live query only for an explicitly supplied package coordinate:

```sh
python3 -B scripts/advisory_adapter.py \
  --source osv --ecosystem PyPI --package requests --version 2.32.0 \
  --output /tmp/requests-advisories.json
```

For deterministic tests, pass `--response advisories/fixtures/responses/osv-query.json` (or the GitHub fixture) and validate the checked-in bundles with:

```sh
python3 -B scripts/validate_advisories.py
```

The adapter is an advisory lookup, not an exploit or code scanner. It never turns advisory presence into a finding automatically and does not include credentials, payloads or live-target instructions. The files under `advisories/fixtures/` are synthetic contract fixtures; they are not real vulnerability notices and must not be used as production advisories.
