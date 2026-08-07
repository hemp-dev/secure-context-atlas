#!/usr/bin/env python3
"""Run fixture-backed OSV/GHSA adapters and verify normalized provenance."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from advisory_adapter import build_bundle, load_json  # noqa: E402


def main() -> int:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        print("ERROR advisory validation requires jsonschema; install requirements-dev.txt", file=sys.stderr)
        return 1

    bundle_schema = json.loads((ROOT / "schemas/advisory-bundle.schema.json").read_text(encoding="utf-8"))
    advisory_schema = json.loads((ROOT / "schemas/advisory.schema.json").read_text(encoding="utf-8"))

    def inline(value):
        if isinstance(value, list):
            return [inline(item) for item in value]
        if not isinstance(value, dict):
            return value
        if value.get("$ref") == "advisory.schema.json":
            return advisory_schema
        return {key: inline(item) for key, item in value.items()}

    validator = Draft202012Validator(inline(bundle_schema), format_checker=FormatChecker())
    cases = [
        ("osv", "PyPI", "example-package", "1.2.3", "advisories/fixtures/responses/osv-query.json", "advisories/fixtures/osv.json"),
        ("github-advisory-database", "pip", "example-package", "1.2.3", "advisories/fixtures/responses/github-advisory-list.json", "advisories/fixtures/github-advisory.json"),
    ]
    errors: list[str] = []
    for source, ecosystem, package, version, response_rel, expected_rel in cases:
        response, raw_bytes = load_json(ROOT / response_rel)
        descriptor = {"package": {"ecosystem": ecosystem, "name": package}, "version": version} if source == "osv" else {"ecosystem": ecosystem, "affects": f"{package}@{version}", "type": "reviewed", "per_page": 100}
        bundle = build_bundle(
            source=source,
            ecosystem=ecosystem,
            package=package,
            version=version,
            raw=response,
            raw_bytes=raw_bytes,
            transport="fixture",
            queried_at="2026-08-08T00:00:00Z",
            request_descriptor=descriptor,
            http_status=200,
            auth_mode="anonymous",
        )
        for error in validator.iter_errors(bundle):
            errors.append(f"{response_rel}: {error.message}")
        expected = json.loads((ROOT / expected_rel).read_text(encoding="utf-8"))
        if bundle != expected:
            errors.append(f"{expected_rel}: checked-in normalized bundle differs from fixture-backed adapter output")
        if not bundle["advisories"]:
            errors.append(f"{source}: fixture query produced no normalized advisories")
        for advisory in bundle["advisories"]:
            provenance = advisory.get("provenance", {})
            for key in ["queried_at", "query", "source_url", "transport", "request_sha256", "response_sha256"]:
                if not provenance.get(key):
                    errors.append(f"{source}: normalized advisory missing provenance.{key}")
            if advisory.get("reachability", {}).get("status") not in {"unknown", "runtime-dependent", "reachable", "not-reachable"}:
                errors.append(f"{source}: invalid reachability state")
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"advisory validation failed: {len(errors)} error(s)")
        return 1
    print("advisory validation passed: OSV and GitHub Advisory Database fixture adapters with response hashes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
