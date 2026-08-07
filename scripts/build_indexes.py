#!/usr/bin/env python3
"""Build compact, deterministic indexes from the current CWE/CAPEC XML releases.

The generated files intentionally contain metadata and short summaries, not copied
payloads or long operational examples. Network retrieval is opt-in with --fetch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import time
import urllib.request
import zipfile
from collections import Counter
from datetime import date
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "Secure Context Atlas"
RELEASE_VERSION = "0.6.0"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_v3.9.xml"
CWE_NS = "{http://cwe.mitre.org/cwe-7}"
CAPEC_NS = "{http://capec.mitre.org/capec-3}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generated_date() -> str:
    metadata = ROOT / "sources/versions.yaml"
    if metadata.exists():
        match = re.search(r"^generated_at:\s*[\"']?([^\"'\s]+)", metadata.read_text(encoding="utf-8"), re.M)
        if match:
            return match.group(1)
    return date.today().isoformat()


def fetch(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "Secure-Context-Atlas/0.6.0 source-refresh"})
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=90) as response, target.open("wb") as out:
                shutil.copyfileobj(response, out)
            return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url} after 3 attempts: {last_error}")


def text(node: ET.Element | None) -> str:
    if node is None:
        return ""
    value = " ".join("".join(node.itertext()).split())
    return re.sub(r"\s+", " ", value).strip()


def short(value: str, limit: int = 360) -> str:
    value = re.sub(r"<[^>]+>", " ", value)
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def child(node: ET.Element, name: str, namespace: str) -> str:
    return text(node.find(namespace + name))


def cwe_entries(xml_path: Path) -> tuple[dict, list[dict]]:
    with zipfile.ZipFile(xml_path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".xml")]
        if not names:
            raise ValueError("CWE archive contains no XML")
        root = ET.fromstring(archive.read(names[0]))
    entries: list[dict] = []
    for node in root.findall(".//" + CWE_NS + "Weakness"):
        related = [
            {"nature": rel.attrib.get("Nature"), "cwe": "CWE-" + rel.attrib["CWE_ID"], "view": rel.attrib.get("View_ID"), "ordinal": rel.attrib.get("Ordinal")}
            for rel in node.findall(".//" + CWE_NS + "Related_Weakness")
            if rel.attrib.get("CWE_ID", "").isdigit()
        ]
        capec = [
            "CAPEC-" + rel.attrib["CAPEC_ID"]
            for rel in node.findall(".//" + CWE_NS + "Related_Attack_Pattern")
            if rel.attrib.get("CAPEC_ID", "").isdigit()
        ]
        entry = {
            "id": "CWE-" + node.attrib["ID"],
            "name": node.attrib.get("Name", ""),
            "abstraction": node.attrib.get("Abstraction"),
            "structure": node.attrib.get("Structure"),
            "status": node.attrib.get("Status"),
            "description": short(child(node, "Description", CWE_NS)),
            "extended_description": short(child(node, "Extended_Description", CWE_NS)),
            "likelihood": child(node, "Likelihood_Of_Exploit", CWE_NS) or None,
            "related_weaknesses": related,
            "related_capec": sorted(set(capec)),
            "has_mitigations": bool(node.findall(".//" + CWE_NS + "Mitigation")),
            "has_detection_methods": bool(node.findall(".//" + CWE_NS + "Detection_Method")),
            "reference_count": len(node.findall(".//" + CWE_NS + "Reference")),
        }
        entries.append(entry)
    entries.sort(key=lambda item: int(item["id"].split("-")[1]))
    statuses = Counter(entry["status"] for entry in entries)
    meta = {
        "schema_version": "1.0",
        "source": "MITRE CWE",
        "source_url": "https://cwe.mitre.org/data/downloads.html",
        "version": root.attrib.get("Version"),
        "release_date": root.attrib.get("Date"),
        "entries_total": len(entries),
        "entries_active": len([entry for entry in entries if entry["status"] != "Deprecated"]),
        "entries_deprecated": statuses.get("Deprecated", 0),
        "status_counts": dict(sorted(statuses.items())),
    }
    return meta, entries


def capec_entries(xml_path: Path) -> tuple[dict, list[dict]]:
    root = ET.parse(xml_path).getroot()
    entries: list[dict] = []
    for node in root.findall(".//" + CAPEC_NS + "Attack_Pattern"):
        cwes = [
            "CWE-" + rel.attrib["CWE_ID"]
            for rel in node.findall(".//" + CAPEC_NS + "Related_Weakness")
            if rel.attrib.get("CWE_ID", "").isdigit()
        ]
        related = [
            "CAPEC-" + rel.attrib["CAPEC_ID"]
            for rel in node.findall(".//" + CAPEC_NS + "Related_Attack_Pattern")
            if rel.attrib.get("CAPEC_ID", "").isdigit()
        ]
        entry = {
            "id": "CAPEC-" + node.attrib["ID"],
            "name": node.attrib.get("Name", ""),
            "abstraction": node.attrib.get("Abstraction"),
            "status": node.attrib.get("Status"),
            "description": short(child(node, "Description", CAPEC_NS)),
            "likelihood": child(node, "Likelihood_Of_Attack", CAPEC_NS) or None,
            "severity": child(node, "Typical_Severity", CAPEC_NS) or None,
            "related_cwe": sorted(set(cwes)),
            "related_capec": sorted(set(related)),
            "reference_count": len(node.findall(".//" + CAPEC_NS + "Reference")),
        }
        entries.append(entry)
    entries.sort(key=lambda item: int(item["id"].split("-")[1]))
    statuses = Counter(entry["status"] for entry in entries)
    meta = {
        "schema_version": "1.0",
        "source": "MITRE CAPEC",
        "source_url": "https://capec.mitre.org/data/downloads.html",
        "version": root.attrib.get("Version"),
        "release_date": root.attrib.get("Date"),
        "entries_total": len(entries),
        "status_counts": dict(sorted(statuses.items())),
    }
    return meta, entries


def slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    return value


FAMILY_MAP = {
    "INJ": "injection", "BRS": "browser", "AUTH": "authorization",
    "API": "api", "FILE": "files", "LOG": "business", "RUN": "runtime",
    "CRY": "crypto", "SUP": "supply", "NET": "cloud", "HOST": "host",
    "MOB": "mobile", "IOT": "hardware", "WEB3": "web3", "AI": "ai",
}


def stable_id(legacy_id: str) -> str:
    parts = legacy_id.split(".")
    family = FAMILY_MAP.get(parts[0], slug(parts[0]))
    return "vuln." + ".".join([family] + [slug(part) for part in parts[1:]])


def parse_simple_frontmatter(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    result: dict = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        raw = raw.strip()
        try:
            result[key.strip()] = json.loads(raw)
        except json.JSONDecodeError:
            result[key.strip()] = raw.strip('"')
    return result


def curated_records() -> list[dict]:
    records = []
    for path in sorted((ROOT / "vulnerabilities").rglob("*.md")) if (ROOT / "vulnerabilities").exists() else []:
        fm = parse_simple_frontmatter(path)
        if fm.get("id"):
            records.append({"id": fm["id"], "title": fm.get("title"), "family": fm.get("family"), "path": str(path.relative_to(ROOT)), "canonical_cwe": fm.get("canonical_cwe"), "maturity": fm.get("maturity", "curated"), "review_status": fm.get("review_status", "reviewed")})
    return records


def load_legacy_taxonomy() -> list[dict]:
    source = ROOT / "vulnerability-taxonomy-ai.json"
    if not source.exists():
        return []
    data = json.loads(source.read_text(encoding="utf-8"))
    records: list[dict] = []
    for family in data.get("families", []):
        family_id = family.get("id", "")
        items = family.get("items") or []
        if family_id == "AI":
            for subfamily in family.get("subfamilies", []):
                for item in subfamily.get("items", []):
                    records.append({"legacy_id": item["id"], "id": stable_id(item["id"]), "title": item.get("name_en", item["id"]), "family": "ai", "aliases": item.get("aliases", []), "variants": item.get("variants", []), "source": "preliminary-normalized-taxonomy"})
        else:
            for item in items:
                records.append({"legacy_id": item["id"], "id": stable_id(item["id"]), "title": item.get("name_en", item["id"]), "family": FAMILY_MAP.get(family_id, slug(family_id)), "aliases": item.get("aliases", []), "variants": item.get("variants", []), "source": "preliminary-normalized-taxonomy"})
    return records


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build(cwe_path: Path, capec_path: Path) -> None:
    cwe_meta, cwe = cwe_entries(cwe_path)
    capec_meta, capec = capec_entries(capec_path)
    generated_at = generated_date()
    write_json(ROOT / "ai/cwe-index.json", {**cwe_meta, "retrieved_at": generated_at, "entries": cwe})
    cards = curated_records()
    curated = [record for record in cards if record.get("maturity") in {"curated", "tested", "production-ready"}]
    scaffolded = [record for record in cards if record.get("maturity") == "scaffolded"]
    curated_cwe = {record["canonical_cwe"] for record in curated}
    scaffolded_cwe = {record["canonical_cwe"] for record in scaffolded}
    write_json(ROOT / "ai/cwe-coverage.json", {"schema_version": "1.0", "generated_at": generated_at, "source": cwe_meta, "entries": [{"cwe": item["id"], "name": item["name"], "status": item["status"], "coverage_state": "imported", "curation": "curated" if item["id"] in curated_cwe else ("scaffolded" if item["id"] in scaffolded_cwe else "taxonomy-only")} for item in cwe]})
    write_json(ROOT / "ai/capec-index.json", {**capec_meta, "retrieved_at": generated_at, "entries": capec})
    write_json(ROOT / "ai/source-hashes.json", {"generated_at": generated_at, "cwe_xml_zip_sha256": sha256(cwe_path), "capec_xml_sha256": sha256(capec_path), "cwe_url": CWE_URL, "capec_url": CAPEC_URL})

    legacy = load_legacy_taxonomy()
    card_by_id = {item["id"]: item for item in cards}
    curated_ids = {item["id"] for item in curated}
    for record in legacy:
        record["curated"] = record["id"] in curated_ids
        record["maturity"] = card_by_id.get(record["id"], {}).get("maturity", "inventory")
    write_json(ROOT / "ai/vulnerability-map.json", {"schema_version": "1.0", "generated_at": generated_at, "canonical_namespace": "MITRE-CWE", "records": legacy, "curated_records": curated, "scaffolded_records": scaffolded})
    maturity_records = []
    for record in legacy:
        card = card_by_id.get(record["id"])
        maturity_records.append({"id": record["id"], "legacy_id": record.get("legacy_id"), "maturity": card.get("maturity") if card else "inventory", "review_status": card.get("review_status") if card else "unreviewed", "path": card.get("path") if card else None})
    write_json(ROOT / "ai/maturity-map.json", {"schema_version": "1.0", "generated_at": generated_at, "statuses": ["inventory", "scaffolded", "curated", "tested", "production-ready"], "records": maturity_records})

    aliases: dict[str, list[str]] = {}
    alias_path = ROOT / "taxonomy/aliases.yaml"
    if alias_path.exists():
        canonical = None
        for line in alias_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("- canonical:"):
                canonical = line.split(":", 1)[1].strip()
            elif canonical and line.strip().startswith("aliases:"):
                raw = line.split(":", 1)[1].strip()
                try:
                    aliases[canonical] = json.loads(raw.replace("'", '"'))
                except json.JSONDecodeError:
                    aliases[canonical] = []
    for record in legacy:
        if record.get("aliases"):
            aliases.setdefault(record["id"], []).extend(record["aliases"])
    aliases = {key: sorted(set(values)) for key, values in sorted(aliases.items())}
    alias_to_ids: dict[str, list[str]] = {}
    for canonical, values in aliases.items():
        for value in values:
            alias_to_ids.setdefault(value.lower(), []).append(canonical)
    alias_to_ids = {key: sorted(set(values)) for key, values in sorted(alias_to_ids.items())}
    write_json(ROOT / "ai/aliases.json", {"schema_version": "1.0", "generated_at": generated_at, "aliases": aliases, "alias_to_ids": alias_to_ids, "ambiguous_aliases": {key: values for key, values in alias_to_ids.items() if len(values) > 1}})

    standards = {
        "schema_version": "1.0", "generated_at": generated_at,
        "canonical": "MITRE CWE",
        "coverage": {
            "owasp_top10_2025": {"A01": "authorization", "A02": "configuration", "A03": "supply-chain", "A04": "crypto", "A05": "injection", "A06": "design", "A07": "authentication", "A08": "integrity", "A09": "logging", "A10": "exceptional-conditions"},
            "owasp_api_2023": {"API1": "BOLA", "API2": "authentication", "API3": "object-property-authorization", "API4": "resource-consumption", "API5": "function-authorization", "API6": "SSRF", "API7": "automated-threats", "API8": "misconfiguration", "API9": "inventory", "API10": "unsafe-consumption"},
            "owasp_genai_llm_2025": {"LLM01": "prompt-injection", "LLM02": "sensitive-information-disclosure", "LLM03": "supply-chain", "LLM04": "data-model-poisoning", "LLM05": "improper-output-handling", "LLM06": "excessive-agency", "LLM07": "system-prompt-leakage", "LLM08": "vector-embedding-weaknesses", "LLM09": "misinformation", "LLM10": "unbounded-consumption"},
            "owasp_agentic": {f"ASI{i:02d}": label for i, label in enumerate(["goal-hijack", "tool-misuse", "identity-privilege-abuse", "agentic-supply-chain", "unexpected-code-execution", "memory-context-poisoning", "inter-agent-communication", "cascading-failures", "human-agent-trust", "rogue-agents"], 1)},
            "mobile": {"MASVS": "control families", "MASTG": "test families", "MASWE": "weakness identifiers"},
            "web": {"ASVS": "verification requirements", "WSTG": "testing scenarios"},
            "nist_ai_rmf": {"govern": "policy and accountability", "map": "context and risk framing", "measure": "evaluation and evidence", "manage": "controls and residual risk"},
            "nist_ai_600_1": "Generative AI risk profile crosswalked in AI and agentic guidance",
        },
        "curated_record_count": len(curated),
        "scaffolded_record_count": len(scaffolded),
    }
    write_json(ROOT / "ai/standards-coverage.json", standards)
    write_json(ROOT / "ai/index.json", {"schema_version": "1.0", "project": PROJECT_NAME, "release": RELEASE_VERSION, "release_channel": "stable-preview", "generated_at": generated_at, "retrieval_order": ["stack", "surface", "family", "canonical_cwe", "safe_verification", "maturity"], "record_count": len(legacy), "atomic_card_count": len(cards), "curated_record_count": len(curated), "scaffolded_record_count": len(scaffolded), "artifacts": ["ai/cwe-index.json", "ai/cwe-coverage.json", "ai/capec-index.json", "ai/vulnerability-map.json", "ai/maturity-map.json", "ai/aliases.json", "ai/standards-coverage.json", "ai/evaluation-report.json", "ai/context-manifest.json", "ai/release-manifest.json", "ai/compact-context.md"]})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwe", type=Path, default=Path("/tmp/cwec_v4.20.xml.zip"))
    parser.add_argument("--capec", type=Path, default=Path("/tmp/capec_v3.9.xml"))
    parser.add_argument("--fetch", action="store_true", help="download the pinned current releases when inputs are missing")
    args = parser.parse_args()
    cwe_path, capec_path = args.cwe, args.capec
    temp_dir = Path(tempfile.mkdtemp(prefix="secure-ai-audit-")) if args.fetch else None
    try:
        if args.fetch:
            cwe_path = temp_dir / "cwec_v4.20.xml.zip"
            capec_path = temp_dir / "capec_v3.9.xml"
            fetch(CWE_URL, cwe_path)
            fetch(CAPEC_URL, capec_path)
        if not cwe_path.exists() or not capec_path.exists():
            raise SystemExit("CWE/CAPEC inputs missing; provide --cwe/--capec or use --fetch")
        build(cwe_path, capec_path)
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
