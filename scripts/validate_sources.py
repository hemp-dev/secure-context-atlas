#!/usr/bin/env python3
"""Validate repository source pins without fetching or executing upstream content."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORIES = {"patt", "hacktricks", "seclists", "awesome-hacking", "awesome-bug-bounty"}


def main() -> int:
    lock = json.loads((ROOT / "sources/lock.json").read_text(encoding="utf-8"))
    errors: list[str] = []
    if lock.get("release") != "0.7.0":
        errors.append("source lock release must be 0.7.0")
    pins = lock.get("repository_pins", {})
    if set(pins) != REPOSITORIES:
        errors.append(f"repository pins must be exactly {sorted(REPOSITORIES)}")
    for identifier in sorted(REPOSITORIES):
        pin = pins.get(identifier, {})
        for field in ["url", "repository", "commit", "observed_at"]:
            if not pin.get(field):
                errors.append(f"{identifier}: missing {field}")
        if pin.get("commit") and not re.fullmatch(r"[a-f0-9]{40}", str(pin["commit"])):
            errors.append(f"{identifier}: commit must be a full 40-character SHA")
    for identifier in ["cwe", "capec"]:
        pin = lock.get("pins", {}).get(identifier, {})
        if not re.fullmatch(r"[a-f0-9]{64}", str(pin.get("sha256", ""))):
            errors.append(f"{identifier}: missing or invalid SHA-256")
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1
    print(f"source provenance passed: {len(pins)} repository pins and 2 machine-readable pins")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
