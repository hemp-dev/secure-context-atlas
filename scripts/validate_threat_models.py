#!/usr/bin/env python3
"""Validate threat-model examples and referenced controls."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    cards = set()
    for path in (ROOT / "vulnerabilities").rglob("*.md"):
        if path.name == "README.md":
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("id:"):
                cards.add(line.split(":", 1)[1].strip().strip('"'))
                break
    errors: list[str] = []
    count = 0
    for path in sorted((ROOT / "ai/threat-model-examples").glob("*.json")):
        count += 1
        model = json.loads(path.read_text(encoding="utf-8"))
        for key in ["id", "system", "assets", "principals", "trust_boundaries", "data_flows", "capabilities", "controls"]:
            if key not in model:
                errors.append(f"{path.relative_to(ROOT)}: missing {key}")
        if not str(model.get("id", "")).startswith("tm."):
            errors.append(f"{path.relative_to(ROOT)}: invalid id")
        for boundary in model.get("trust_boundaries", []):
            for control in boundary.get("required_controls", []):
                if control.startswith("vuln.") and control not in cards:
                    errors.append(f"{path.relative_to(ROOT)}: unknown control card {control}")
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1
    print(f"threat-model validation passed: {count} example(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
