#!/usr/bin/env python3
"""Build a deterministic SPDX 2.3 file-level SBOM for the release tree."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "ai/sbom.spdx.json"
RELEASE_VERSION = "0.7.0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_files() -> list[Path]:
    # Include release-candidate files before the first commit. In CI the same
    # command resolves to the committed tree because the checkout is clean.
    result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT, check=True, capture_output=True)
    return sorted(ROOT / item for item in result.stdout.decode("utf-8").split("\0") if item)


def generated_at() -> str:
    text = (ROOT / "sources/versions.yaml").read_text(encoding="utf-8")
    match = re.search(r"^generated_at:\s*[\"']?([^\"'\s]+)", text, re.M)
    return (match.group(1) if match else "2026-08-08") + "T00:00:00Z"


def file_spdx_id(relative: str) -> str:
    return "SPDXRef-File-" + hashlib.sha256(relative.encode("utf-8")).hexdigest()[:24]


def main() -> int:
    excluded = {OUTPUT, ROOT / "ai/release-manifest.json"}
    files = []
    for path in release_files():
        if not path.is_file() or path in excluded or "raw" in path.parts or "__pycache__" in path.parts or path.suffix in {".zip", ".xml"}:
            continue
        relative = str(path.relative_to(ROOT))
        files.append({
            "SPDXID": file_spdx_id(relative),
            "fileName": relative,
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(path)}],
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
        })
    files.sort(key=lambda item: item["fileName"])
    package_id = "SPDXRef-Package-SecureContextAtlas"
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": package_id}]
    relationships.extend({"spdxElementId": package_id, "relationshipType": "CONTAINS", "relatedSpdxElement": item["SPDXID"]} for item in files)
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"secure-context-atlas-{RELEASE_VERSION}",
        "documentNamespace": f"https://github.com/hemp-dev/secure-context-atlas/releases/tag/v{RELEASE_VERSION}",
        "creationInfo": {"created": generated_at(), "creators": [f"Tool: Secure Context Atlas SBOM generator/{RELEASE_VERSION}"]},
        "packages": [{
            "SPDXID": package_id,
            "name": "secure-context-atlas",
            "versionInfo": RELEASE_VERSION,
            "downloadLocation": "https://github.com/hemp-dev/secure-context-atlas",
            "licenseDeclared": "CC-BY-SA-4.0",
        }],
        "files": files,
        "relationships": relationships,
    }
    OUTPUT.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"SBOM written: {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
