# Supply-chain and CI/CD checklist

- Inventory manifests, lockfiles, registries, build scripts, actions/plugins, runners, caches, artifacts, signing and deploy identities.
- Check pinning, integrity/provenance, branch/event trust, secret scope, runner isolation and artifact-to-source binding.
- Query OSV/GHSA adapters with package coordinates and timestamps; distinguish advisory existence from reachability.
- Add a regression test for untrusted event isolation and artifact verification.
