#!/usr/bin/env python3
"""Run deterministic retrieval, holdout and fixture-safety checks."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{1,}")
FORBIDDEN = re.compile(r"\b(?:curl|wget|nc|netcat|bash|powershell)\b|rm\s+-rf|real\s+credential|public\s+target|exfiltration|web\s+shell", re.I)


def parse_frontmatter(path: Path) -> dict:
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
        try:
            result[key.strip()] = json.loads(raw.strip())
        except json.JSONDecodeError:
            result[key.strip()] = raw.strip().strip('"')
    return result


def tokens(value: str) -> set[str]:
    return set(TOKEN_RE.findall(value.lower()))


def card_index() -> dict[str, dict]:
    cards: dict[str, dict] = {}
    for path in sorted((ROOT / "vulnerabilities").rglob("*.md")):
        if path.name == "README.md":
            continue
        record = parse_frontmatter(path)
        if not record.get("id"):
            continue
        body = path.read_text(encoding="utf-8")
        searchable = " ".join([
            str(record.get("id", "")), str(record.get("title", "")), str(record.get("summary", "")),
            str(record.get("family", "")), " ".join(record.get("aliases", [])), body,
        ])
        cards[record["id"]] = {"path": str(path.relative_to(ROOT)), "record": record, "tokens": tokens(searchable)}
    return cards


def rank(query: str, cards: dict[str, dict]) -> list[tuple[int, str]]:
    query_tokens = tokens(query)
    scored = []
    for identifier, card in cards.items():
        overlap = len(query_tokens & card["tokens"])
        exact_title = str(card["record"].get("title", "")).lower() in query.lower()
        scored.append((overlap + (100 if exact_title else 0), identifier))
    return sorted(scored, key=lambda item: (-item[0], item[1]))


def evaluate_holdout(cards: dict[str, dict]) -> tuple[dict, list[str]]:
    path = ROOT / "evals/holdout/cases.json"
    errors: list[str] = []
    if not path.exists():
        return {"fixture_count": 0, "hits_at_5": 0, "recall_at_5": 0.0, "mrr": 0.0, "leakage_count": 0, "cases": []}, ["missing holdout: evals/holdout/cases.json"]
    cases = json.loads(path.read_text(encoding="utf-8"))
    results = []
    hits = 0
    reciprocal_rank = 0.0
    leakage_count = 0
    for case in cases:
        target = case.get("vulnerability_id")
        if target not in cards:
            errors.append(f"holdout references unknown card: {target}")
            continue
        text = " ".join(str(case.get(key, "")) for key in ["query", "snippet"]).lower()
        record = cards[target]["record"]
        leakage_terms = [target.lower(), str(record.get("title", "")).lower(), str(record.get("canonical_cwe", "")).lower()]
        leaked = [term for term in leakage_terms if term and term in text]
        if leaked:
            leakage_count += 1
            errors.append(f"holdout leakage in {case.get('id')}: {', '.join(leaked)}")
        ranked = rank(str(case.get("query", "")), cards)
        ordered = [identifier for _, identifier in ranked[:5]]
        position = next((index + 1 for index, item in enumerate(ranked) if item[1] == target), None)
        hit = position is not None and position <= 5
        hits += int(hit)
        if position:
            reciprocal_rank += 1 / position
        results.append({"id": case.get("id"), "vulnerability_id": target, "retrieval_hit_at_5": hit, "rank": position, "top5": ordered})
    total = len(results)
    return {
        "fixture_count": total,
        "hits_at_5": hits,
        "recall_at_5": round(hits / total, 4) if total else 0.0,
        "mrr": round(reciprocal_rank / total, 4) if total else 0.0,
        "leakage_count": leakage_count,
        "cases": results,
    }, errors


def evaluate_agentic(cards: dict[str, dict], benchmark: dict) -> tuple[dict, list[str]]:
    path = ROOT / str(benchmark.get("path", ""))
    errors: list[str] = []
    if not path.exists():
        return {"case_count": 0, "reviewed_count": 0, "reviewed_fraction": 0.0, "target_count": 0, "target_hits_at_5": 0, "target_recall_at_5": 0.0, "case_hits_at_5": 0, "case_recall_at_5": 0.0, "mrr": 0.0, "leakage_count": 0, "categories": {}, "cases": []}, [f"missing agentic benchmark: {benchmark.get('path')}"]
    cases = json.loads(path.read_text(encoding="utf-8"))
    results = []
    reviewed_count = 0
    target_count = 0
    target_hits = 0
    case_hits = 0
    reciprocal_rank = 0.0
    leakage_count = 0
    categories: dict[str, int] = {}
    for case in cases:
        case_id = case.get("id")
        category = str(case.get("category", "unknown"))
        categories[category] = categories.get(category, 0) + 1
        if case.get("review_status") == "reviewed":
            reviewed_count += 1
        else:
            errors.append(f"agentic case is not reviewed: {case_id}")
        targets = list(dict.fromkeys(case.get("vulnerability_ids", [])))
        unknown = [target for target in targets if target not in cards]
        if unknown:
            errors.append(f"agentic case references unknown card(s): {case_id}: {', '.join(unknown)}")
            continue
        text = " ".join(str(case.get(key, "")) for key in ["query", "snippet"]).lower()
        leakage_terms = []
        for target in targets:
            record = cards[target]["record"]
            leakage_terms.extend([target.lower(), str(record.get("title", "")).lower(), str(record.get("canonical_cwe", "")).lower()])
        leaked = [term for term in leakage_terms if term and term in text]
        if leaked:
            leakage_count += 1
            errors.append(f"agentic benchmark leakage in {case_id}: {', '.join(dict.fromkeys(leaked))}")
        ranked = rank(str(case.get("query", "")), cards)
        top5 = [identifier for _, identifier in ranked[:5]]
        positions = [next((index + 1 for index, item in enumerate(ranked) if item[1] == target), None) for target in targets]
        hits = sum(int(target in top5) for target in targets)
        target_count += len(targets)
        target_hits += hits
        all_hit = bool(targets) and hits == len(targets)
        case_hits += int(all_hit)
        first_position = min((position for position in positions if position is not None), default=None)
        if first_position:
            reciprocal_rank += 1 / first_position
        results.append({"id": case_id, "category": category, "vulnerability_ids": targets, "top5": top5, "target_hits_at_5": hits, "target_count": len(targets), "target_recall_at_5": round(hits / len(targets), 4) if targets else 0.0, "case_hit_at_5": all_hit, "first_target_rank": first_position})
    total = len(results)
    report = {
        "case_count": total,
        "reviewed_count": reviewed_count,
        "reviewed_fraction": round(reviewed_count / total, 4) if total else 0.0,
        "target_count": target_count,
        "target_hits_at_5": target_hits,
        "target_recall_at_5": round(target_hits / target_count, 4) if target_count else 0.0,
        "case_hits_at_5": case_hits,
        "case_recall_at_5": round(case_hits / total, 4) if total else 0.0,
        "mrr": round(reciprocal_rank / total, 4) if total else 0.0,
        "leakage_count": leakage_count,
        "categories": dict(sorted(categories.items())),
        "cases": results,
    }
    if report["target_recall_at_5"] < float(benchmark.get("min_target_recall_at_5", 0.0)):
        errors.append(f"agentic target recall {report['target_recall_at_5']:.4f} below threshold")
    if report["case_recall_at_5"] < float(benchmark.get("min_case_recall_at_5", 0.0)):
        errors.append(f"agentic case recall {report['case_recall_at_5']:.4f} below threshold")
    if report["reviewed_fraction"] < float(benchmark.get("min_reviewed_fraction", 0.0)):
        errors.append(f"agentic reviewed fraction {report['reviewed_fraction']:.4f} below threshold")
    if leakage_count:
        errors.append("agentic benchmark contains target leakage")
    return report, errors


def run(output: Path | None) -> int:
    manifest_path = ROOT / "evals/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cards = card_index()
    errors: list[str] = []
    cases: list[dict] = []
    seen: set[str] = set()
    hits = 0
    positive_hits = 0
    positive_total = 0
    forbidden_count = 0
    for entry in manifest.get("fixtures", []):
        fixture_id = entry.get("id")
        if fixture_id in seen:
            errors.append(f"duplicate fixture id: {fixture_id}")
        seen.add(fixture_id)
        fixture_path = ROOT / entry["path"]
        if not fixture_path.exists():
            errors.append(f"missing fixture: {entry['path']}")
            continue
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        if fixture.get("id") != fixture_id:
            errors.append(f"fixture id mismatch: {entry['path']}")
        vulnerability_id = fixture.get("vulnerability_id")
        if vulnerability_id not in cards:
            errors.append(f"fixture references unknown card: {vulnerability_id}")
            continue
        if fixture.get("polarity") not in {"positive", "negative", "ambiguous"}:
            errors.append(f"invalid fixture polarity: {fixture_id}")
        text = " ".join(str(fixture.get(key, "")) for key in ["query", "snippet"])
        if FORBIDDEN.search(text):
            forbidden_count += 1
        ranked = rank(str(fixture.get("query", "")), cards)
        top5 = [identifier for _, identifier in ranked[:5]]
        hit = vulnerability_id in top5
        hits += int(hit)
        if fixture.get("polarity") == "positive":
            positive_total += 1
            positive_hits += int(hit)
        cases.append({"id": fixture_id, "vulnerability_id": vulnerability_id, "polarity": fixture.get("polarity"), "retrieval_hit_at_5": hit, "top5": top5})

    total = len(cases)
    recall = hits / total if total else 0.0
    positive_recall = positive_hits / positive_total if positive_total else 0.0
    holdout, holdout_errors = evaluate_holdout(cards)
    errors.extend(holdout_errors)
    agentic, agentic_errors = evaluate_agentic(cards, manifest.get("agentic_benchmark", {}))
    errors.extend(agentic_errors)
    report = {
        "schema_version": "1.1",
        "suite": manifest.get("suite"),
        "fixture_count": total,
        "retrieval_hits_at_5": hits,
        "retrieval_recall_at_5": round(recall, 4),
        "positive_fixture_count": positive_total,
        "positive_recall_at_5": round(positive_recall, 4),
        "forbidden_fixture_count": forbidden_count,
        "holdout": holdout,
        "agentic": agentic,
        "errors": errors,
        "cases": cases,
    }
    if recall < float(manifest.get("min_retrieval_recall_at_5", 0.0)):
        errors.append(f"retrieval recall {recall:.4f} below threshold")
    if holdout["recall_at_5"] < float(manifest.get("min_holdout_recall_at_5", 0.0)):
        errors.append(f"holdout recall {holdout['recall_at_5']:.4f} below threshold")
    if forbidden_count > int(manifest.get("max_forbidden_fixture_count", 0)):
        errors.append(f"forbidden fixture count {forbidden_count} above threshold")
    report["errors"] = errors
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(json.dumps({key: report[key] for key in ["suite", "fixture_count", "retrieval_recall_at_5", "positive_recall_at_5", "forbidden_fixture_count", "holdout", "agentic", "errors"]}, ensure_ascii=False, sort_keys=True))
    return 1 if errors else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    return run(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
