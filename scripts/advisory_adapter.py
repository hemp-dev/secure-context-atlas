#!/usr/bin/env python3
"""Query OSV/GitHub advisories and emit provenance-rich normalized records.

The adapter deliberately returns advisory evidence, not source-code findings. A
package coordinate and version are required, live responses are hashed, and
fixture mode makes the normalization contract testable without network access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "Secure-Context-Atlas/0.7.0 advisory-adapter"
SOURCE_URLS = {
    "osv": "https://api.osv.dev/v1/query",
    "github-advisory-database": "https://api.github.com/advisories",
}
SEVERITIES = {"unknown", "low", "medium", "high", "critical"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def nonempty_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if isinstance(value, str) and value.strip()))


def normalize_severity(value: Any) -> str:
    if isinstance(value, str) and value.lower() in SEVERITIES:
        return value.lower()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                candidate = item.get("score") or item.get("severity")
                if isinstance(candidate, str) and candidate.lower() in SEVERITIES:
                    return candidate.lower()
    return "unknown"


def load_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), raw


def request_json(url: str, *, method: str, body: dict[str, Any] | None, token: str | None, timeout: int) -> tuple[Any, bytes, int]:
    payload = canonical_json(body) if body is not None else None
    headers = {
        "Accept": "application/vnd.github+json" if "github.com" in url else "application/json",
        "User-Agent": USER_AGENT,
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
        return json.loads(raw.decode("utf-8")), raw, int(response.status)


def osv_request_descriptor(ecosystem: str, package: str, version: str) -> dict[str, Any]:
    return {"package": {"ecosystem": ecosystem, "name": package}, "version": version}


def github_request_descriptor(ecosystem: str, package: str, version: str) -> dict[str, Any]:
    return {"ecosystem": ecosystem.lower(), "affects": f"{package}@{version}", "type": "reviewed", "per_page": 100}


def osv_range(affected: dict[str, Any]) -> tuple[str, list[str]]:
    ranges = affected.get("ranges") if isinstance(affected.get("ranges"), list) else []
    rendered: list[str] = []
    fixed: list[str] = []
    for item in ranges:
        if not isinstance(item, dict):
            continue
        events = item.get("events") if isinstance(item.get("events"), list) else []
        values: list[str] = []
        for event in events:
            if not isinstance(event, dict):
                continue
            for key, value in event.items():
                if isinstance(value, str) and value:
                    values.append(f"{key}={value}")
                    if key == "fixed":
                        fixed.append(value)
        if values:
            rendered.append(f"{item.get('type', 'ECOSYSTEM')}:" + ",".join(values))
    return "; ".join(rendered) or "unspecified affected range", nonempty_unique(fixed)


def advisory_provenance(*, queried_at: str, query: str, source_url: str, transport: str, request_hash: str, response_hash: str, auth_mode: str, http_status: int) -> dict[str, Any]:
    return {
        "queried_at": queried_at,
        "query": query,
        "source_url": source_url,
        "transport": transport,
        "request_sha256": request_hash,
        "response_sha256": response_hash,
        "auth_mode": auth_mode,
        "http_status": http_status,
    }


def normalize_osv(raw: dict[str, Any], *, query: dict[str, str], provenance: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in raw.get("vulns", []) if isinstance(raw.get("vulns"), list) else []:
        if not isinstance(item, dict):
            continue
        advisory_id = str(item.get("id", "")).strip()
        if not advisory_id:
            continue
        fixed_versions: list[str] = []
        ranges: list[str] = []
        for affected in item.get("affected", []) if isinstance(item.get("affected"), list) else []:
            if not isinstance(affected, dict):
                continue
            package = affected.get("package") if isinstance(affected.get("package"), dict) else {}
            if package and (package.get("name") != query["package"] or package.get("ecosystem", "").lower() != query["ecosystem"].lower()):
                continue
            range_text, fixed = osv_range(affected)
            ranges.append(range_text)
            fixed_versions.extend(fixed)
        references = [str(ref.get("url")) for ref in item.get("references", []) if isinstance(ref, dict) and ref.get("url")]
        references.append(f"https://osv.dev/vulnerability/{urllib.parse.quote(advisory_id)}")
        aliases = [str(value) for value in item.get("aliases", []) if isinstance(value, str)]
        severity = normalize_severity((item.get("database_specific") or {}).get("severity") if isinstance(item.get("database_specific"), dict) else None)
        if severity == "unknown":
            severity = normalize_severity(item.get("severity"))
        records.append({
            "schema_version": "1.1",
            "source": "osv",
            "advisory_id": advisory_id,
            "aliases": nonempty_unique(aliases),
            "package": {"ecosystem": query["ecosystem"], "name": query["package"], "version": query["version"]},
            "affected": {"range": "; ".join(nonempty_unique(ranges)) or "unspecified affected range", "fixed_versions": nonempty_unique(fixed_versions)},
            "status": "withdrawn" if item.get("withdrawn") else "affected",
            "severity": severity,
            "published_at": item.get("published"),
            "modified_at": item.get("modified"),
            "references": nonempty_unique(references),
            "provenance": provenance,
            "reachability": {"status": "unknown", "evidence": ["The adapter matched a package coordinate; application dependency and runtime reachability require a separate evidence check."]},
        })
    return records


def normalize_github(raw: list[Any], *, query: dict[str, str], provenance: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        matching: list[dict[str, Any]] = []
        for vulnerability in item.get("vulnerabilities", []) if isinstance(item.get("vulnerabilities"), list) else []:
            if not isinstance(vulnerability, dict):
                continue
            package = vulnerability.get("package") if isinstance(vulnerability.get("package"), dict) else {}
            if package.get("name") == query["package"] and package.get("ecosystem", "").lower() == query["ecosystem"].lower():
                matching.append(vulnerability)
        if not matching:
            continue
        advisory_id = str(item.get("ghsa_id", "")).strip()
        if not advisory_id:
            continue
        aliases = [str(identifier.get("value")) for identifier in item.get("identifiers", []) if isinstance(identifier, dict) and identifier.get("value") and identifier.get("value") != advisory_id]
        references = [str(value) for value in item.get("references", []) if isinstance(value, str)]
        references.extend(str(item.get(key)) for key in ["html_url", "url"] if item.get(key))
        fixed_versions = nonempty_unique([str(vuln.get("first_patched_version")) for vuln in matching if vuln.get("first_patched_version")])
        ranges = nonempty_unique([str(vuln.get("vulnerable_version_range")) for vuln in matching if vuln.get("vulnerable_version_range")])
        records.append({
            "schema_version": "1.1",
            "source": "github-advisory-database",
            "advisory_id": advisory_id,
            "aliases": nonempty_unique(aliases),
            "package": {"ecosystem": query["ecosystem"], "name": query["package"], "version": query["version"]},
            "affected": {"range": "; ".join(ranges) or "unspecified affected range", "fixed_versions": fixed_versions},
            "status": "withdrawn" if item.get("withdrawn_at") else "affected",
            "severity": normalize_severity(item.get("severity")),
            "published_at": item.get("published_at"),
            "modified_at": item.get("updated_at"),
            "references": nonempty_unique(references),
            "provenance": provenance,
            "reachability": {"status": "unknown", "evidence": ["The adapter matched a package coordinate; application dependency and runtime reachability require a separate evidence check."]},
        })
    return records


def build_bundle(*, source: str, ecosystem: str, package: str, version: str, raw: Any, raw_bytes: bytes, transport: str, queried_at: str, request_descriptor: dict[str, Any], http_status: int, auth_mode: str) -> dict[str, Any]:
    request_text = json.dumps(request_descriptor, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    request_hash = sha256_bytes(request_text.encode("utf-8"))
    response_hash = sha256_bytes(raw_bytes)
    source_url = SOURCE_URLS[source]
    query = {"ecosystem": ecosystem, "package": package, "version": version}
    provenance = advisory_provenance(
        queried_at=queried_at,
        query=request_text,
        source_url=source_url,
        transport=transport,
        request_hash=request_hash,
        response_hash=response_hash,
        auth_mode=auth_mode,
        http_status=http_status,
    )
    if source == "osv":
        advisories = normalize_osv(raw if isinstance(raw, dict) else {}, query=query, provenance=provenance)
    else:
        advisories = normalize_github(raw if isinstance(raw, list) else [], query=query, provenance=provenance)
    return {
        "schema_version": "1.0",
        "source": source,
        "transport": transport,
        "query": query,
        "queried_at": queried_at,
        "request_sha256": request_hash,
        "response_sha256": response_hash,
        "advisories": advisories,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["osv", "github-advisory-database"], required=True)
    parser.add_argument("--ecosystem", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--response", type=Path, help="Read a checked-in synthetic response instead of making a network request")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--queried-at", default=None)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--token", default=None, help="GitHub token; defaults to GH_TOKEN/GITHUB_TOKEN for GitHub queries")
    args = parser.parse_args()

    if args.queried_at is not None:
        queried_at = args.queried_at
    else:
        queried_at = now_utc()
    if args.source == "osv":
        descriptor = osv_request_descriptor(args.ecosystem, args.package, args.version)
        method = "POST"
        body: dict[str, Any] | None = descriptor
        url = SOURCE_URLS[args.source]
    else:
        descriptor = github_request_descriptor(args.ecosystem, args.package, args.version)
        method = "GET"
        body = None
        url = SOURCE_URLS[args.source] + "?" + urllib.parse.urlencode(descriptor)

    token = args.token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if args.response:
        raw, raw_bytes = load_json(args.response)
        transport = "fixture"
        http_status = 200
        auth_mode = "anonymous"
    else:
        raw, raw_bytes, http_status = request_json(url, method=method, body=body, token=token if args.source != "osv" else None, timeout=args.timeout)
        transport = "https"
        auth_mode = "token" if token and args.source != "osv" else "anonymous"
    bundle = build_bundle(
        source=args.source,
        ecosystem=args.ecosystem,
        package=args.package,
        version=args.version,
        raw=raw,
        raw_bytes=raw_bytes,
        transport=transport,
        queried_at=queried_at,
        request_descriptor=descriptor,
        http_status=http_status,
        auth_mode=auth_mode,
    )
    rendered = json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
