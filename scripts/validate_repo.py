#!/usr/bin/env python3
"""Dependency-free quality gate for the knowledge repository."""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.7.0"
REQUIRED_VULN_FIELDS = {
    "id", "title", "aliases", "summary", "family", "canonical_cwe", "related_cwe", "capec",
    "owasp_mappings", "asvs_mappings", "wstg_mappings", "masvs_mappings", "api_security_mappings",
    "genai_mappings", "applies_to", "surfaces", "languages", "frameworks", "platforms", "preconditions",
    "trust_boundaries", "data_flow", "code_signals", "configuration_signals", "architecture_signals",
    "audit_questions", "safe_verification", "false_positives", "impact", "severity_factors",
    "exploitability_factors", "remediation", "secure_patterns", "regression_tests", "related_vulnerabilities",
    "references", "source_provenance", "last_reviewed", "maturity", "review_status",
}
REQUIRED_LANGUAGES = ["javascript", "typescript", "python", "java", "go", "csharp", "ruby", "php", "rust", "c", "cpp", "swift", "kotlin"]
REQUIRED_PLATFORMS = ["cloud", "containers-kubernetes", "android", "ios", "ai-llm", "ci-cd", "enterprise-ad", "hardware-iot"]
REQUIRED_FRAMEWORKS = ["node-express", "python-web", "spring", "go-services", "aspnet", "php-ruby-web"]


class Validator:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def generated_date(self) -> str:
        metadata = ROOT / "sources/versions.yaml"
        match = re.search(r"^generated_at:\s*[\"']?([^\"'\s]+)", metadata.read_text(encoding="utf-8"), re.M)
        return match.group(1) if match else date.today().isoformat()

    def parse_frontmatter(self, path: Path) -> dict:
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines or lines[0].strip() != "---":
            self.error(f"{path.relative_to(ROOT)}: missing frontmatter")
            return {}
        result: dict = {}
        closed = False
        for line in lines[1:]:
            if line.strip() == "---":
                closed = True
                break
            if ":" not in line:
                self.error(f"{path.relative_to(ROOT)}: malformed frontmatter line: {line}")
                continue
            key, raw = line.split(":", 1)
            raw = raw.strip()
            try:
                result[key.strip()] = json.loads(raw)
            except json.JSONDecodeError:
                result[key.strip()] = raw.strip('"')
        if not closed:
            self.error(f"{path.relative_to(ROOT)}: unterminated frontmatter")
        return result

    def validate_card(self, path: Path, fm: dict, cwe_ids: set[str], capec_ids: set[str], ids: set[str], aliases: set[str]) -> None:
        rel = path.relative_to(ROOT)
        missing = REQUIRED_VULN_FIELDS - set(fm)
        for key in sorted(missing):
            self.error(f"{rel}: missing field {key}")
        card_id = fm.get("id")
        if not isinstance(card_id, str) or not re.fullmatch(r"vuln\.[a-z0-9][a-z0-9.-]*", card_id):
            self.error(f"{rel}: invalid id {card_id!r}")
        elif card_id in ids:
            self.error(f"{rel}: duplicate id {card_id}")
        else:
            ids.add(card_id)
        for value in fm.get("aliases", []) if isinstance(fm.get("aliases"), list) else []:
            if value.lower() in aliases:
                self.error(f"{rel}: duplicate alias {value}")
            aliases.add(value.lower())
        if not isinstance(fm.get("summary"), str) or len(fm.get("summary", "")) < 20:
            self.error(f"{rel}: summary too short")
        if not isinstance(fm.get("last_reviewed"), str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", fm.get("last_reviewed", "")):
            self.error(f"{rel}: invalid last_reviewed")
        if fm.get("maturity") not in {"inventory", "scaffolded", "curated", "tested", "production-ready"}:
            self.error(f"{rel}: invalid maturity {fm.get('maturity')!r}")
        if fm.get("review_status") not in {"unreviewed", "reviewed", "needs-review"}:
            self.error(f"{rel}: invalid review_status {fm.get('review_status')!r}")
        if fm.get("maturity") == "scaffolded" and fm.get("review_status") == "reviewed":
            self.error(f"{rel}: scaffolded card cannot claim reviewed status")
        for field in ["preconditions", "trust_boundaries", "code_signals", "audit_questions", "safe_verification", "false_positives", "remediation", "secure_patterns", "regression_tests", "source_provenance"]:
            if not isinstance(fm.get(field), list) or not fm[field]:
                self.error(f"{rel}: {field} must be a non-empty list")
        flow = fm.get("data_flow")
        if not isinstance(flow, dict) or not all(isinstance(flow.get(key), list) for key in ["sources", "transformations", "controls", "sinks", "authorization_points"]):
            self.error(f"{rel}: data_flow must contain source/transform/control/sink/authorization lists")
        cwe = fm.get("canonical_cwe")
        if cwe not in cwe_ids:
            self.error(f"{rel}: canonical CWE not in imported 4.20 index: {cwe}")
        for field in ["related_cwe"]:
            for value in fm.get(field, []):
                if value not in cwe_ids:
                    self.error(f"{rel}: unknown {field} value {value}")
        for value in fm.get("capec", []):
            if value not in capec_ids:
                self.error(f"{rel}: unknown CAPEC value {value}")
        for source in fm.get("source_provenance", []):
            source_path = source.split(":", 1)[0]
            if not (ROOT / source_path).exists():
                self.error(f"{rel}: provenance path does not exist: {source_path}")
        if not any("local" in item.lower() or "staging" in item.lower() or "mock" in item.lower() for item in fm.get("safe_verification", [])):
            self.error(f"{rel}: safe_verification must name local/staging/mock boundary")
        forbidden = ["real credential", "external exfiltration", "persistence", "web shell"]
        body = path.read_text(encoding="utf-8").lower()
        if any(term in body for term in forbidden) and "do not" not in body and "never" not in body:
            self.error(f"{rel}: unsafe operational wording without defensive prohibition")

    def run(self) -> int:
        for rel in ["README.md", "AGENTS.md", "CONTRIBUTING.md", "sources/manifest.yaml", "sources/versions.yaml", "sources/licenses.yaml", "sources/lock.json", "schemas/vulnerability.schema.json", "schemas/finding.schema.json", "schemas/evidence.schema.json", "schemas/threat-model.schema.json", "schemas/context-pack.schema.json", "schemas/advisory.schema.json", "schemas/advisory-bundle.schema.json", "schemas/agentic-eval.schema.json", "schemas/sbom.schema.json", "schemas/provenance.schema.json", "schemas/eval-fixture.schema.json", "schemas/eval-manifest.schema.json", "schemas/detector-contract.schema.json", "requirements-dev.txt", "release-manifest.schema.json", "taxonomy/families.yaml", "taxonomy/aliases.yaml", "taxonomy/cwe-map.yaml", "taxonomy/capec-map.yaml", "taxonomy/owasp-map.yaml", "taxonomy/priorities.yaml", "taxonomy/agentic-map.yaml", "ai/audit-protocol.md", "ai/routing.yaml", "ai/finding-format.md", "ai/index.json", "ai/maturity-map.json", "ai/evaluation-report.json", "ai/context-manifest.json", "ai/release-manifest.json", "ai/sbom.spdx.json", "platforms/ai-agentic.md", "ai/threat-model-examples/agentic-rag.json", "evals/README.md", "evals/manifest.json", "evals/holdout/cases.json", "evals/agentic/cases.json", "datasets/manifests.yaml", "advisories/adapters/osv.md", "advisories/adapters/github-advisory-database.md", "advisories/fixtures/osv.json", "advisories/fixtures/github-advisory.json", "advisories/fixtures/responses/osv-query.json", "advisories/fixtures/responses/github-advisory-list.json"]:
            if not (ROOT / rel).exists():
                self.error(f"missing required file {rel}")
        for folder, names in [("languages", REQUIRED_LANGUAGES), ("platforms", REQUIRED_PLATFORMS), ("frameworks", REQUIRED_FRAMEWORKS)]:
            for name in names:
                if not (ROOT / folder / f"{name}.md").exists():
                    self.error(f"missing {folder}/{name}.md")

        try:
            cwe_data = json.loads((ROOT / "ai/cwe-index.json").read_text(encoding="utf-8"))
            capec_data = json.loads((ROOT / "ai/capec-index.json").read_text(encoding="utf-8"))
            index_data = json.loads((ROOT / "ai/index.json").read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            self.error(f"cannot load generated indexes: {exc}")
            return self.finish()
        cwe_ids = {entry.get("id") for entry in cwe_data.get("entries", [])}
        capec_ids = {entry.get("id") for entry in capec_data.get("entries", [])}
        if index_data.get("project") != "Secure Context Atlas" or index_data.get("release") != RELEASE_VERSION or index_data.get("release_channel") != "stable-preview":
            self.error(f"ai/index.json does not identify the {RELEASE_VERSION} stable-preview release")
        if cwe_data.get("version") != "4.20" or cwe_data.get("entries_total") != 969 or cwe_data.get("entries_active") != 944:
            self.error("CWE index is not the expected 4.20 969/944 coverage")
        if capec_data.get("version") != "3.9" or capec_data.get("entries_total") != 615:
            self.error("CAPEC index is not the expected 3.9 615 coverage")
        if len(cwe_ids) != cwe_data.get("entries_total"):
            self.error("CWE index contains duplicate or missing entry IDs")
        if len(capec_ids) != capec_data.get("entries_total"):
            self.error("CAPEC index contains duplicate or missing entry IDs")

        ids: set[str] = set()
        aliases: set[str] = set()
        card_count = 0
        maturity_counts: Counter[str] = Counter()
        fixture_references: list[tuple[str, str]] = []
        for path in sorted((ROOT / "vulnerabilities").rglob("*.md")) if (ROOT / "vulnerabilities").exists() else []:
            if path.name == "README.md":
                continue
            fm = self.parse_frontmatter(path)
            if fm:
                card_count += 1
                self.validate_card(path, fm, cwe_ids, capec_ids, ids, aliases)
                maturity = fm.get("maturity", "curated")
                if maturity not in {"inventory", "scaffolded", "curated", "tested", "production-ready"}:
                    self.error(f"{path.relative_to(ROOT)}: invalid maturity {maturity!r}")
                maturity_counts[maturity] += 1
                if isinstance(fm.get("fixture_ids"), list):
                    fixture_references.extend((str(path.relative_to(ROOT)), str(value)) for value in fm["fixture_ids"])
        if card_count < 100:
            self.error(f"only {card_count} atomic cards found; expected at least 100 for {RELEASE_VERSION}")
        if index_data.get("atomic_card_count") != card_count:
            self.error(f"ai/index.json atomic_card_count mismatch: {index_data.get('atomic_card_count')} / {card_count}")
        expected_curated = sum(1 for path in (ROOT / "vulnerabilities").rglob("*.md") if path.name != "README.md" and self.parse_frontmatter(path).get("maturity") in {"curated", "tested", "production-ready"})
        expected_scaffolded = sum(1 for path in (ROOT / "vulnerabilities").rglob("*.md") if path.name != "README.md" and self.parse_frontmatter(path).get("maturity") == "scaffolded")
        if index_data.get("curated_record_count") != expected_curated or index_data.get("scaffolded_record_count") != expected_scaffolded:
            self.error("ai/index.json maturity counts do not match vulnerability cards")
        for path in sorted((ROOT / "vulnerabilities").rglob("*.md")) if (ROOT / "vulnerabilities").exists() else []:
            if path.name == "README.md":
                continue
            fm = self.parse_frontmatter(path)
            for related in fm.get("related_vulnerabilities", []) if isinstance(fm.get("related_vulnerabilities"), list) else []:
                if related not in ids:
                    self.error(f"{path.relative_to(ROOT)}: unknown related vulnerability {related}")

        try:
            legacy = json.loads((ROOT / "vulnerability-taxonomy-ai.json").read_text(encoding="utf-8"))
            legacy_count = sum(len(f.get("items", [])) for f in legacy.get("families", []) if f.get("id") != "AI") + sum(len(s.get("items", [])) for s in next((f for f in legacy.get("families", []) if f.get("id") == "AI"), {}).get("subfamilies", []))
            mapping = json.loads((ROOT / "ai/vulnerability-map.json").read_text(encoding="utf-8"))
            if legacy_count != 305 or len(mapping.get("records", [])) != legacy_count:
                self.error(f"legacy normalized taxonomy coverage mismatch: {legacy_count} / {len(mapping.get('records', []))}")
        except Exception as exc:  # noqa: BLE001
            self.error(f"cannot validate normalized taxonomy: {exc}")

        curated_cwe = set()
        scaffolded_cwe = set()
        for path in (ROOT / "vulnerabilities").rglob("*.md"):
            if path.name != "README.md":
                fm = self.parse_frontmatter(path)
                if fm:
                    if fm.get("maturity") in {"curated", "tested", "production-ready"}:
                        curated_cwe.add(fm.get("canonical_cwe"))
                    elif fm.get("maturity") == "scaffolded":
                        scaffolded_cwe.add(fm.get("canonical_cwe"))
        active_cwe = {entry.get("id") for entry in cwe_data.get("entries", []) if entry.get("status") != "Deprecated"}
        unmapped_active_cwe = sorted(active_cwe - curated_cwe, key=lambda value: int(value.split("-", 1)[1]))
        fixture_manifest = {}
        try:
            fixture_manifest = json.loads((ROOT / "evals/manifest.json").read_text(encoding="utf-8"))
            fixture_ids = {item.get("id") for item in fixture_manifest.get("fixtures", [])}
            for card_path, fixture_id in fixture_references:
                if fixture_id not in fixture_ids:
                    self.error(f"{card_path}: fixture reference not in eval manifest: {fixture_id}")
            evaluation = json.loads((ROOT / "ai/evaluation-report.json").read_text(encoding="utf-8")) if (ROOT / "ai/evaluation-report.json").exists() else {}
            if evaluation.get("errors"):
                self.error("evaluation report contains errors")
            if evaluation.get("fixture_count", 0) < 100:
                self.error("evaluation suite must contain at least 100 fixtures")
            if evaluation.get("retrieval_recall_at_5", 0) < 0.9:
                self.error("evaluation retrieval recall@5 is below 0.90")
            agentic = evaluation.get("agentic", {})
            if agentic.get("reviewed_fraction", 0) < 1.0:
                self.error("agentic benchmark is not fully reviewed")
            if agentic.get("case_recall_at_5", 0) < 0.7:
                self.error("agentic benchmark case recall@5 is below 0.70")
            if agentic.get("target_recall_at_5", 0) < 0.75:
                self.error("agentic benchmark target recall@5 is below 0.75")
            if agentic.get("leakage_count", 1) != 0:
                self.error("agentic benchmark contains leakage")
        except Exception as exc:  # noqa: BLE001
            self.error(f"cannot validate evaluation suite: {exc}")
        maturity_summary = dict(sorted(maturity_counts.items()))
        maturity_summary["inventory"] = max(0, 305 - card_count)
        report = {
            "schema_version": "1.0", "generated_at": self.generated_date(),
            "cwe": {"version": cwe_data.get("version"), "imported": len(cwe_ids), "active": cwe_data.get("entries_active"), "deprecated": cwe_data.get("entries_deprecated"), "curated_by_atomic_card": len(curated_cwe), "curated_ids": sorted(curated_cwe, key=lambda value: int(value.split("-", 1)[1])), "scaffolded_by_atomic_card": len(scaffolded_cwe), "scaffolded_ids": sorted(scaffolded_cwe, key=lambda value: int(value.split("-", 1)[1])), "unmapped_active_count": len(unmapped_active_cwe), "unmapped_active_ids": unmapped_active_cwe},
            "capec": {"version": capec_data.get("version"), "imported": len(capec_ids)},
            "normalized_taxonomy": {"leaf_count": 305, "atomic_cards": card_count, "unscaffolded_leafs": max(0, 305 - card_count), "maturity": maturity_summary},
            "evaluation": {"suite": fixture_manifest.get("suite"), "fixture_count": len(fixture_manifest.get("fixtures", []))},
            "standards": {"owasp_top10_2025": "crosswalked", "owasp_api_2023": "crosswalked", "asvs": "crosswalked", "wstg": "crosswalked", "masvs_mastg_maswe": "mobile guidance and mappings", "genai": "LLM and agentic mappings"},
            "topic_coverage": {"primary_repositories": "normalized in vulnerability-taxonomy-ai.json and sources/research-notes.md", "portswigger": "web/parser topic references in cards and manifest", "cwe": "all entries imported; curated/unmapped lists above", "language_framework_platform": "required files checked below"},
            "source_families": ["PayloadsAllTheThings", "HackTricks", "SecLists", "Awesome-Hacking", "Awesome Bug Bounty"],
            "language_coverage": REQUIRED_LANGUAGES,
            "framework_coverage": REQUIRED_FRAMEWORKS,
            "platform_coverage": REQUIRED_PLATFORMS,
        }
        (ROOT / "ai/coverage-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return self.finish()

    def finish(self) -> int:
        if self.warnings:
            for warning in self.warnings:
                print("WARN", warning)
        if self.errors:
            for error in self.errors:
                print("ERROR", error)
            print(f"validation failed: {len(self.errors)} error(s)")
            return 1
        print("validation passed")
        return 0


if __name__ == "__main__":
    raise SystemExit(Validator().run())
