# OSV adapter contract

Source: [OSV.dev](https://osv.dev/docs/).

Input: ecosystem, package name, version or lockfile coordinate. Output: advisory ID, aliases (CVE/GHSA), affected ranges, fixed versions, severity metadata, published/modified timestamps, database URL and query timestamp.

Safe use: query a pinned package coordinate or parse a local lockfile. Do not run a vulnerable package or fetch arbitrary code as part of advisory lookup. Record uncertainty when a transitive dependency, optional extra or runtime image differs from the lockfile.
