#!/usr/bin/env python3
"""Build a deterministic SHA-256 manifest for release artifacts."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "ai/release-manifest.json"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def release_paths() -> list[Path]:
    """Hash the release tree, including candidate files before the first commit."""
    try:
        result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT, check=True, capture_output=True)
        paths = [ROOT / item for item in result.stdout.decode("utf-8").split("\0") if item]
    except (OSError, subprocess.CalledProcessError):
        paths = list(ROOT.rglob("*"))
    return sorted(paths)


def main() -> int:
    index = json.loads((ROOT / "ai/index.json").read_text(encoding="utf-8"))
    files = []
    for path in release_paths():
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts or path == OUTPUT:
            continue
        if "raw" in path.parts or path.name.endswith((".zip", ".xml")):
            continue
        files.append({"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size, "sha256": digest(path)})
    manifest = {
        "schema_version": "1.0",
        "project": index.get("project"),
        "release": index.get("release"),
        "generated_at": index.get("generated_at"),
        "hash_algorithm": "sha256",
        "file_count": len(files),
        "files": files,
    }
    OUTPUT.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"release manifest written: {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
