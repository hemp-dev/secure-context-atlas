#!/usr/bin/env python3
"""Validate SPDX file coverage and SHA-256 hashes against the committed tree."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SBOM = ROOT / "ai/sbom.spdx.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tracked() -> set[str]:
    result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT, check=True, capture_output=True)
    return {
        item for item in result.stdout.decode("utf-8").split("\0") if item and item not in {"ai/sbom.spdx.json", "ai/release-manifest.json"}
        and "raw" not in Path(item).parts and "__pycache__" not in Path(item).parts and Path(item).suffix not in {".zip", ".xml"}
    }


def main() -> int:
    if not SBOM.exists():
        print("ERROR missing ai/sbom.spdx.json")
        return 1
    document = json.loads(SBOM.read_text(encoding="utf-8"))
    errors: list[str] = []
    package = document.get("packages", [{}])[0]
    if package.get("versionInfo") != "0.7.0":
        errors.append("SBOM package version is not 0.7.0")
    actual = tracked()
    listed = {item.get("fileName") for item in document.get("files", [])}
    if actual != listed:
        errors.append(f"SBOM file coverage mismatch: missing={sorted(actual - listed)[:3]} extra={sorted(listed - actual)[:3]}")
    seen_ids: set[str] = set()
    for item in document.get("files", []):
        identifier = item.get("SPDXID")
        if identifier in seen_ids:
            errors.append(f"duplicate SBOM file ID: {identifier}")
        seen_ids.add(identifier)
        path = ROOT / str(item.get("fileName", ""))
        if not path.exists():
            errors.append(f"SBOM file missing from tree: {item.get('fileName')}")
            continue
        checksums = item.get("checksums", [])
        if not checksums or checksums[0].get("checksumValue") != sha256(path):
            errors.append(f"SBOM hash mismatch: {item.get('fileName')}")
    relationships = document.get("relationships", [])
    if not any(item.get("relationshipType") == "DESCRIBES" and item.get("spdxElementId") == "SPDXRef-DOCUMENT" for item in relationships):
        errors.append("SBOM is missing DOCUMENT DESCRIBES relationship")
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"SBOM validation failed: {len(errors)} error(s)")
        return 1
    print(f"SBOM validation passed: {len(listed)} tracked release files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
