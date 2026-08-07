# GitHub Advisory Database adapter contract

Source: [GitHub Advisory Database](https://github.com/github/advisory-database).

Input: ecosystem/package/version or a repository dependency graph. Output: GHSA, CVE if present, affected range, patched version, severity, withdrawn status, published/updated timestamps, source URL and query/pin.

Treat advisory data as dynamic. A high severity label is not proof of reachability or exploitability; connect it to the actual build, lockfile, runtime and compensating controls.
