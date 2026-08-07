#!/usr/bin/env python3
"""Validate final 0.7.0 release invariants and artifact hashes."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.7.0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    errors: list[str] = []
    index = json.loads((ROOT / "ai/index.json").read_text(encoding="utf-8"))
    if index.get("project") != "Secure Context Atlas":
        errors.append("project metadata is not Secure Context Atlas")
    if index.get("release") != RELEASE_VERSION:
        errors.append(f"release metadata is not {RELEASE_VERSION}")
    if index.get("release_channel") != "stable-preview":
        errors.append("release channel is not stable-preview")
    manifest_path = ROOT / "ai/release-manifest.json"
    if not manifest_path.exists():
        errors.append("missing ai/release-manifest.json")
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("release") != RELEASE_VERSION:
            errors.append("release manifest version mismatch")
        for entry in manifest.get("files", []):
            path = ROOT / entry["path"]
            if not path.exists():
                errors.append(f"manifest file missing: {entry['path']}")
            elif sha256(path) != entry.get("sha256"):
                errors.append(f"manifest hash mismatch: {entry['path']}")
    sbom_path = ROOT / "ai/sbom.spdx.json"
    if not sbom_path.exists():
        errors.append("missing ai/sbom.spdx.json")
    elif manifest_path.exists() and not any(entry.get("path") == "ai/sbom.spdx.json" for entry in manifest.get("files", [])):
        errors.append("release manifest does not include ai/sbom.spdx.json")
    forbidden_paths = []
    for path in ROOT.rglob("*"):
        if any(part in {"raw", "__pycache__"} for part in path.parts) or path.suffix in {".pyc", ".pyo"}:
            forbidden_paths.append(str(path.relative_to(ROOT)))
    if forbidden_paths:
        errors.append("forbidden raw/cache paths present: " + ", ".join(forbidden_paths[:5]))
    for path in ROOT.rglob("*.md"):
        body = path.read_text(encoding="utf-8").lower()
        if re.search(r"-----begin (?:rsa |ec |openpgp )?private key-----", body):
            errors.append(f"private key marker in {path.relative_to(ROOT)}")
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"release validation failed: {len(errors)} error(s)")
        return 1
    print("release validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
