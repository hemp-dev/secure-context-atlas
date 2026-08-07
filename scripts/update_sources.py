#!/usr/bin/env python3
"""Check or refresh pinned machine-readable source provenance."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def version_metadata() -> str:
    return (ROOT / "sources/versions.yaml").read_text(encoding="utf-8")


def expected(text: str, key: str) -> str | None:
    match = re.search(rf"^\s+{re.escape(key)}:\s*[\"']?([^\"'\s]+)", text, re.M)
    return match.group(1) if match else None


def build_lock() -> dict:
    hashes = json.loads((ROOT / "ai/source-hashes.json").read_text(encoding="utf-8"))
    cwe = json.loads((ROOT / "ai/cwe-index.json").read_text(encoding="utf-8"))
    capec = json.loads((ROOT / "ai/capec-index.json").read_text(encoding="utf-8"))
    text = version_metadata()
    return {
        "schema_version": "1.0",
        "project": "Secure Context Atlas",
        "release": expected(text, "release") or "0.5.0",
        "generated_at": hashes.get("generated_at"),
        "policy": {"raw_inputs_are_temporary": True, "generated_indexes_are_committed": True, "advisory_feeds_are_dynamic": True, "source_hashes_are_required": True},
        "pins": {
            "cwe": {"version": cwe.get("version"), "url": hashes.get("cwe_url"), "sha256": hashes.get("cwe_xml_zip_sha256"), "entries_total": cwe.get("entries_total"), "entries_active": cwe.get("entries_active")},
            "capec": {"version": capec.get("version"), "url": hashes.get("capec_url"), "sha256": hashes.get("capec_xml_sha256"), "entries_total": capec.get("entries_total")},
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true", help="download pinned sources and regenerate indexes")
    parser.add_argument("--write-lock", action="store_true", help="write sources/lock.json from generated artifacts")
    parser.add_argument("--check", action="store_true", help="verify lock and generated artifacts agree")
    args = parser.parse_args()
    if args.fetch:
        subprocess.run([sys.executable, str(ROOT / "scripts/build_indexes.py"), "--fetch"], cwd=ROOT, check=True)
    if args.write_lock or args.fetch:
        (ROOT / "sources/lock.json").write_text(json.dumps(build_lock(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("source lock updated")
    if args.check or not (args.fetch or args.write_lock):
        lock = json.loads((ROOT / "sources/lock.json").read_text(encoding="utf-8"))
        current = build_lock()
        if lock.get("pins") != current.get("pins"):
            print("source lock mismatch: run update_sources.py --fetch --write-lock", file=sys.stderr)
            return 1
        print("source lock verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
