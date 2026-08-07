#!/usr/bin/env python3
"""Validate detector contracts without requiring a YAML dependency."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def frontmatter_id(path: Path) -> str | None:
    started = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "---":
            if started:
                break
            started = True
            continue
        if started and line.startswith("id:"):
            return line.split(":", 1)[1].strip().strip('"')
    return None


def main() -> int:
    errors: list[str] = []
    manifest = json.loads((ROOT / "rules/manifest.json").read_text(encoding="utf-8"))
    if manifest.get("execution_mode") not in {"contract-only", "semgrep-executable", "codeql-executable", "mixed"}:
        errors.append("rules manifest must declare a supported execution_mode")
    cards = set()
    for path in (ROOT / "vulnerabilities").rglob("*.md"):
        if path.name != "README.md":
            identifier = frontmatter_id(path)
            if identifier:
                cards.add(identifier)
    rule_ids: set[str] = set()
    for rule in manifest.get("rules", []):
        rule_id = rule.get("id")
        if rule_id in rule_ids:
            errors.append(f"duplicate rule id: {rule_id}")
        rule_ids.add(rule_id)
        if rule.get("detector") not in set(manifest.get("detectors", [])):
            errors.append(f"unsupported detector for {rule_id}: {rule.get('detector')}")
        rule_path = ROOT / str(rule.get("path", ""))
        if not rule_path.exists():
            errors.append(f"missing rule file: {rule.get('path')}")
            continue
        body = rule_path.read_text(encoding="utf-8")
        if f"id: {rule_id}" not in body:
            errors.append(f"rule id not present in file: {rule.get('path')}")
        if f"vulnerability_id: {rule.get('vulnerability_id')}" not in body:
            errors.append(f"vulnerability mapping not present in file: {rule.get('path')}")
        if rule.get("vulnerability_id") not in cards:
            errors.append(f"rule references unknown card: {rule.get('vulnerability_id')}")
        fixture = ROOT / str(rule.get("fixture", ""))
        if not fixture.exists():
            errors.append(f"missing rule fixture: {rule.get('fixture')}")
        if any(term in body.lower() for term in ["curl ", "wget ", "rm -rf", "web shell", "real credential"]):
            errors.append(f"operational or secret-like content in rule: {rule.get('path')}")
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"rule validation failed: {len(errors)} error(s)")
        return 1
    print(f"rules validation passed: {len(rule_ids)} rules ({manifest.get('execution_mode')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
