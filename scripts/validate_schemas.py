#!/usr/bin/env python3
"""Dependency-free structural checks for JSON Schema artifacts and samples."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ["schemas/vulnerability.schema.json", "schemas/finding.schema.json", "schemas/evidence.schema.json", "schemas/threat-model.schema.json", "release-manifest.schema.json"]


def main() -> int:
    errors: list[str] = []
    for relative in SCHEMAS:
        path = ROOT / relative
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{relative}: invalid JSON: {exc}")
            continue
        for key in ["$schema", "$id", "title", "type"]:
            if key not in schema:
                errors.append(f"{relative}: missing schema key {key}")
        required = schema.get("required", [])
        if len(required) != len(set(required)):
            errors.append(f"{relative}: duplicate required field")
    for relative, keys in [("regression/findings.json", ["findings"]), ("ai/threat-model-examples/agentic-rag.json", ["id", "assets", "principals", "trust_boundaries", "data_flows", "capabilities", "controls"]), ("ai/release-manifest.json", ["project", "release", "files"])]:
        path = ROOT / relative
        if not path.exists():
            errors.append(f"{relative}: missing sample")
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in keys:
            if key not in data:
                errors.append(f"{relative}: missing sample field {key}")
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1
    print(f"schema validation passed: {len(SCHEMAS)} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
