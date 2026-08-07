#!/usr/bin/env python3
"""Convert Secure Context Atlas findings into SARIF 2.1.0."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def line_range(value: str) -> tuple[int, int]:
    parts = str(value).split("-", 1)
    start = max(1, int(parts[0]))
    end = max(start, int(parts[1])) if len(parts) == 2 else start
    return start, end


def level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "warning")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    findings = payload.get("findings", payload if isinstance(payload, list) else [])
    rules: dict[str, dict] = {}
    results = []
    for finding in findings:
        rule_id = finding["vulnerability_id"]
        references = finding.get("references", [])
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.get("title", rule_id)},
            "helpUri": references[0] if references else None,
            "properties": {"canonicalCwe": finding.get("canonical_cwe"), "source": "Secure Context Atlas"},
        })
        locations = []
        for evidence in finding.get("evidence", []):
            start, end = line_range(evidence.get("lines", "1"))
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": evidence.get("file", "unknown")},
                    "region": {"startLine": start, "endLine": end},
                }
            }
            locations.append(location)
        result = {
            "ruleId": rule_id,
            "level": level(finding.get("severity", "medium")),
            "message": {"text": finding.get("title", rule_id)},
            "locations": locations,
            "properties": {
                "findingId": finding.get("finding_id"),
                "status": finding.get("status"),
                "confidence": finding.get("confidence"),
                "canonicalCwe": finding.get("canonical_cwe"),
                "capec": finding.get("capec", []),
            },
        }
        results.append(result)
    for rule in rules.values():
        if rule.get("helpUri") is None:
            rule.pop("helpUri", None)
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": "Secure Context Atlas", "version": "0.5.0", "informationUri": "https://github.com/hemp-dev/secure-context-atlas", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(sarif, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(results)} SARIF result(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
