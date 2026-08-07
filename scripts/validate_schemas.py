#!/usr/bin/env python3
"""Validate release schemas and every checked-in machine-readable sample."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_FILES = [
    "schemas/vulnerability.schema.json",
    "schemas/finding.schema.json",
    "schemas/evidence.schema.json",
    "schemas/threat-model.schema.json",
    "schemas/context-pack.schema.json",
    "schemas/advisory.schema.json",
    "schemas/advisory-bundle.schema.json",
    "schemas/provenance.schema.json",
    "schemas/source.schema.json",
    "schemas/eval-fixture.schema.json",
    "schemas/eval-manifest.schema.json",
    "schemas/agentic-eval.schema.json",
    "schemas/detector-contract.schema.json",
    "schemas/sbom.schema.json",
    "release-manifest.schema.json",
]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_frontmatter(path: Path) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("missing frontmatter")
    result: dict[str, Any] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return result
        if ":" not in line:
            raise ValueError(f"malformed frontmatter line: {line}")
        key, raw = line.split(":", 1)
        try:
            result[key.strip()] = json.loads(raw.strip())
        except json.JSONDecodeError as exc:
            raise ValueError(f"frontmatter values must be JSON: {line}") from exc
    raise ValueError("unterminated frontmatter")


def inline_external_refs(schema: Any, external: dict[str, Any]) -> Any:
    if isinstance(schema, list):
        return [inline_external_refs(item, external) for item in schema]
    if not isinstance(schema, dict):
        return schema
    if schema.get("$ref") == "evidence.schema.json":
        return external["evidence"]
    if schema.get("$ref") == "advisory.schema.json":
        return external["advisory"]
    return {key: inline_external_refs(value, external) for key, value in schema.items()}


def validate_instance(validator: Any, instance: Any, label: str, errors: list[str]) -> None:
    for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(f"{label}:{location}: {error.message}")


def main() -> int:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        import yaml
    except ImportError:
        print("ERROR schema validation requires jsonschema and PyYAML; install requirements-dev.txt", file=sys.stderr)
        return 1

    errors: list[str] = []
    schemas: dict[str, dict[str, Any]] = {}
    for relative in SCHEMA_FILES:
        path = ROOT / relative
        try:
            schema = load_json(path)
            Draft202012Validator.check_schema(schema)
            schemas[relative] = schema
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{relative}: invalid JSON Schema: {exc}")

    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1

    evidence_schema = schemas["schemas/evidence.schema.json"]
    advisory_schema = schemas["schemas/advisory.schema.json"]
    finding_schema = inline_external_refs(schemas["schemas/finding.schema.json"], {"evidence": evidence_schema, "advisory": advisory_schema})
    advisory_bundle_schema = inline_external_refs(schemas["schemas/advisory-bundle.schema.json"], {"evidence": evidence_schema, "advisory": advisory_schema})
    validators = {
        name: Draft202012Validator(schema, format_checker=FormatChecker())
        for name, schema in schemas.items()
    }
    validators["schemas/finding.schema.json"] = Draft202012Validator(finding_schema, format_checker=FormatChecker())
    validators["schemas/advisory-bundle.schema.json"] = Draft202012Validator(advisory_bundle_schema, format_checker=FormatChecker())

    for path in sorted((ROOT / "vulnerabilities").rglob("*.md")):
        if path.name == "README.md":
            continue
        try:
            validate_instance(validators["schemas/vulnerability.schema.json"], parse_frontmatter(path), str(path.relative_to(ROOT)), errors)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path.relative_to(ROOT)}: cannot parse: {exc}")

    regression = ROOT / "regression/findings.json"
    try:
        findings = load_json(regression).get("findings", [])
        for index, finding in enumerate(findings):
            validate_instance(validators["schemas/finding.schema.json"], finding, f"{regression.relative_to(ROOT)}[{index}]", errors)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{regression.relative_to(ROOT)}: cannot parse: {exc}")

    instance_checks = [
        ("schemas/threat-model.schema.json", "ai/threat-model-examples/agentic-rag.json"),
        ("release-manifest.schema.json", "ai/release-manifest.json"),
        ("schemas/provenance.schema.json", "sources/lock.json"),
        ("schemas/detector-contract.schema.json", "rules/manifest.json"),
        ("schemas/eval-manifest.schema.json", "evals/manifest.json"),
        ("schemas/sbom.schema.json", "ai/sbom.spdx.json"),
    ]
    for schema_name, relative in instance_checks:
        path = ROOT / relative
        try:
            validate_instance(validators[schema_name], load_json(path), relative, errors)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{relative}: cannot parse: {exc}")

    fixture_validator = validators["schemas/eval-fixture.schema.json"]
    manifest = load_json(ROOT / "evals/manifest.json")
    for entry in manifest.get("fixtures", []):
        relative = entry["path"]
        path = ROOT / relative
        try:
            validate_instance(fixture_validator, load_json(path), relative, errors)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{relative}: cannot parse: {exc}")

    holdout = ROOT / "evals/holdout/cases.json"
    if holdout.exists():
        try:
            cases = load_json(holdout)
            if not isinstance(cases, list) or not cases:
                errors.append("evals/holdout/cases.json: expected a non-empty array")
            else:
                for index, case in enumerate(cases):
                    validate_instance(fixture_validator, case, f"evals/holdout/cases.json[{index}]", errors)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"evals/holdout/cases.json: cannot parse: {exc}")

    advisory_validator = validators["schemas/advisory.schema.json"]
    for path in sorted((ROOT / "advisories/fixtures").glob("*.json")):
        try:
            instance = load_json(path)
            if isinstance(instance, dict) and "advisories" in instance:
                validate_instance(validators["schemas/advisory-bundle.schema.json"], instance, str(path.relative_to(ROOT)), errors)
            else:
                validate_instance(advisory_validator, instance, str(path.relative_to(ROOT)), errors)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path.relative_to(ROOT)}: cannot parse: {exc}")

    agentic_validator = validators["schemas/agentic-eval.schema.json"]
    agentic_cases = ROOT / "evals/agentic/cases.json"
    if agentic_cases.exists():
        try:
            cases = load_json(agentic_cases)
            if not isinstance(cases, list) or not cases:
                errors.append("evals/agentic/cases.json: expected a non-empty array")
            else:
                for index, case in enumerate(cases):
                    validate_instance(agentic_validator, case, f"evals/agentic/cases.json[{index}]", errors)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"evals/agentic/cases.json: cannot parse: {exc}")

    source_validator = validators["schemas/source.schema.json"] if "schemas/source.schema.json" in validators else None
    if source_validator:
        try:
            source_manifest = yaml.safe_load((ROOT / "sources/manifest.yaml").read_text(encoding="utf-8"))
            for source in source_manifest.get("sources", []):
                validate_instance(source_validator, source, f"sources/manifest.yaml:{source.get('id', '<unknown>')}", errors)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"sources/manifest.yaml: cannot parse: {exc}")

    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"schema validation failed: {len(errors)} error(s)")
        return 1
    print(f"schema validation passed: {len(SCHEMA_FILES)} schemas and all release samples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
