#!/usr/bin/env python3
"""Validate detector contracts and execute the v0.7 detector fixtures."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

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


def semgrep_binary() -> str | None:
    return shutil.which("semgrep") or str(Path(sys.executable).with_name("semgrep")) if Path(sys.executable).with_name("semgrep").exists() else shutil.which("semgrep")


def semgrep_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "false")
    environment.setdefault("SEMGREP_LOG_FILE", str(Path(tempfile.gettempdir()) / "secure-context-atlas-semgrep.log"))
    environment.setdefault("SEMGREP_VERSION_CACHE_PATH", str(Path(tempfile.gettempdir()) / "secure-context-atlas-semgrep-version"))
    try:
        import certifi

        environment.setdefault("SSL_CERT_FILE", certifi.where())
    except ImportError:
        pass
    return environment


def run_semgrep(binary: str, config: Path, target: Path) -> tuple[list[dict[str, Any]], str | None]:
    command = [binary, "--json", "--no-git-ignore", "--config", str(config), str(target)]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False, env=semgrep_environment())
    if result.returncode not in {0, 1}:
        return [], result.stderr.strip() or result.stdout.strip() or f"semgrep exited {result.returncode}"
    try:
        return json.loads(result.stdout).get("results", []), None
    except json.JSONDecodeError as exc:
        return [], f"cannot parse semgrep JSON: {exc}"


def validate_semgrep_config(path: Path, expected_id: str, expected_vulnerability: str, errors: list[str]) -> None:
    try:
        import yaml

        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{path.relative_to(ROOT)}: cannot parse Semgrep YAML: {exc}")
        return
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list) or not document["rules"]:
        errors.append(f"{path.relative_to(ROOT)}: executable Semgrep config must contain rules")
        return
    matches = [item for item in document["rules"] if isinstance(item, dict) and item.get("id") == expected_id]
    if len(matches) != 1:
        errors.append(f"{path.relative_to(ROOT)}: expected exactly one rule with id {expected_id}")
        return
    rule = matches[0]
    if not isinstance(rule.get("languages"), list) or not rule["languages"]:
        errors.append(f"{path.relative_to(ROOT)}: executable rule must declare languages")
    if not isinstance(rule.get("message"), str) or not rule["message"].strip():
        errors.append(f"{path.relative_to(ROOT)}: executable rule must declare message")
    if rule.get("severity") not in {"INFO", "WARNING", "ERROR"}:
        errors.append(f"{path.relative_to(ROOT)}: invalid Semgrep severity")
    if not any(key in rule for key in ["pattern", "patterns", "pattern-either", "mode"]):
        errors.append(f"{path.relative_to(ROOT)}: executable rule has no matching clause")
    metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
    if metadata.get("atlas_rule_id") != expected_id:
        errors.append(f"{path.relative_to(ROOT)}: metadata atlas_rule_id mismatch")
    if metadata.get("vulnerability_id") != expected_vulnerability:
        errors.append(f"{path.relative_to(ROOT)}: metadata vulnerability_id mismatch")


def validate_codeql_query(path: Path, pack_path: Path, expected_id: str, errors: list[str]) -> None:
    body = path.read_text(encoding="utf-8")
    required = {
        "@id": r"@id\s+[a-z0-9][a-z0-9/-]*",
        "@kind": r"@kind\s+(?:problem|path-problem|diagnostic|metric)",
        "@description": r"@description\s+.+",
        "@problem.severity": r"@problem\.severity\s+(?:error|warning|recommendation)",
    }
    for label, pattern in required.items():
        if not re.search(pattern, body):
            errors.append(f"{path.relative_to(ROOT)}: missing CodeQL metadata {label}")
    if not path.name.endswith(".ql"):
        errors.append(f"{path.relative_to(ROOT)}: executable CodeQL rule must use .ql")
    if not pack_path.exists() or not (pack_path / "qlpack.yml").exists():
        errors.append(f"missing CodeQL qlpack.yml: {pack_path.relative_to(ROOT)}")
    query_identity = "secure-context-atlas/" + expected_id.removeprefix("rule.codeql.").replace(".", "/")
    if "@id" in body and expected_id not in body and query_identity not in body:
        errors.append(f"{path.relative_to(ROOT)}: CodeQL query identity is not linked to {expected_id}")


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
    semgrep_rules: list[dict[str, Any]] = []
    executable_count = 0
    for rule in manifest.get("rules", []):
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or rule_id in rule_ids:
            errors.append(f"duplicate or invalid rule id: {rule_id}")
        rule_ids.add(rule_id)
        detector = rule.get("detector")
        if detector not in set(manifest.get("detectors", [])):
            errors.append(f"unsupported detector for {rule_id}: {detector}")
        rule_path = ROOT / str(rule.get("path", ""))
        if not rule_path.exists():
            errors.append(f"missing rule file: {rule.get('path')}")
            continue
        body = rule_path.read_text(encoding="utf-8")
        if rule.get("vulnerability_id") not in cards:
            errors.append(f"rule references unknown card: {rule.get('vulnerability_id')}")
        fixture = ROOT / str(rule.get("fixture", ""))
        if not fixture.exists():
            errors.append(f"missing rule fixture: {rule.get('fixture')}")
        negative = ROOT / str(rule.get("negative_fixture", "")) if rule.get("negative_fixture") else None
        if rule.get("executable") and detector == "semgrep" and (negative is None or not negative.exists()):
            errors.append(f"executable Semgrep rule needs a negative fixture: {rule_id}")
        if any(term in body.lower() for term in ["curl ", "wget ", "rm -rf", "web shell", "real credential"]):
            errors.append(f"operational or secret-like content in rule: {rule.get('path')}")
        if rule.get("executable"):
            executable_count += 1
            if detector == "semgrep":
                semgrep_rules.append({**rule, "fixture_path": fixture, "negative_path": negative})
                validate_semgrep_config(rule_path, rule_id, rule.get("vulnerability_id"), errors)
            elif detector == "codeql":
                validate_codeql_query(rule_path, ROOT / str(manifest.get("codeql_pack", "")), rule_id, errors)
        elif detector == "codeql" and rule_path.suffix == ".yaml":
            if f"id: {rule_id}" not in body or f"vulnerability_id: {rule.get('vulnerability_id')}" not in body:
                errors.append(f"contract rule mapping missing in file: {rule.get('path')}")

    semgrep = semgrep_binary()
    if semgrep_rules and not semgrep:
        errors.append("executable Semgrep rules require semgrep==1.172.0 in the validation environment")
    elif semgrep_rules and semgrep:
        for rule in semgrep_rules:
            config = ROOT / str(rule["path"])
            positive_results, positive_error = run_semgrep(semgrep, config, rule["fixture_path"])
            negative_results, negative_error = run_semgrep(semgrep, config, rule["negative_path"])
            if positive_error:
                errors.append(f"{rule['id']}: {positive_error}")
            if negative_error:
                errors.append(f"{rule['id']}: {negative_error}")
            positive_ids = [str(item.get("check_id", "")) for item in positive_results]
            negative_ids = [str(item.get("check_id", "")) for item in negative_results]
            if not any(identifier.endswith(rule["id"]) for identifier in positive_ids):
                errors.append(f"Semgrep positive fixture did not exercise {rule['id']}")
            if any(identifier.endswith(rule["id"]) for identifier in negative_ids):
                errors.append(f"Semgrep negative fixture matched {rule['id']}")

    codeql = shutil.which("codeql")
    if codeql and manifest.get("codeql_pack"):
        check = subprocess.run([codeql, "pack", "check", str(ROOT / manifest["codeql_pack"])], cwd=ROOT, text=True, capture_output=True, check=False)
        if check.returncode != 0:
            errors.append("CodeQL pack check failed: " + (check.stderr.strip() or check.stdout.strip()))

    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"rule validation failed: {len(errors)} error(s)")
        return 1
    print(f"rules validation passed: {len(rule_ids)} rules ({manifest.get('execution_mode')}), executable={executable_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
