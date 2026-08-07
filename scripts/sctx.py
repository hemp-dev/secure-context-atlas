#!/usr/bin/env python3
"""Secure Context Atlas context-pack CLI."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{1,}")


def parse_card(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    record: dict = {}
    body_start = 0
    if lines and lines[0].strip() == "---":
        for index, line in enumerate(lines[1:], start=1):
            if line.strip() == "---":
                body_start = index + 1
                break
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            try:
                record[key.strip()] = json.loads(raw.strip())
            except json.JSONDecodeError:
                record[key.strip()] = raw.strip().strip('"')
    record["path"] = str(path.relative_to(ROOT))
    record["body"] = "\n".join(lines[body_start:]).strip()
    return record


def cards() -> list[dict]:
    result = []
    for path in sorted((ROOT / "vulnerabilities").rglob("*.md")):
        if path.name != "README.md":
            record = parse_card(path)
            if record.get("id"):
                result.append(record)
    return result


def tokens(value: str) -> set[str]:
    return set(TOKEN_RE.findall(value.lower()))


def searchable(card: dict) -> str:
    values = [card.get("id", ""), card.get("title", ""), card.get("summary", ""), card.get("family", ""), card.get("maturity", "")]
    for field in ["aliases", "surfaces", "languages", "frameworks", "platforms", "genai_mappings"]:
        values.extend(str(item) for item in card.get(field, []))
    return " ".join(values)


def score(card: dict, query: str) -> int:
    query_tokens = tokens(query)
    card_tokens = tokens(searchable(card))
    return len(query_tokens & card_tokens)


def select_cards(args: argparse.Namespace) -> list[dict]:
    query_parts = []
    for value in [args.stack, args.surface, args.family, args.query]:
        if value:
            query_parts.append(value)
    query = " ".join(query_parts)
    all_cards = cards()
    ranked = sorted(all_cards, key=lambda card: (-score(card, query) if query else 0, card["id"]))
    if query:
        ranked = [card for card in ranked if score(card, query) > 0]
    return ranked[: args.max_cards]


def card_public(card: dict) -> dict:
    return {key: value for key, value in card.items() if key != "body"}


def pack(args: argparse.Namespace) -> str:
    selected = select_cards(args)
    index = json.loads((ROOT / "ai/index.json").read_text(encoding="utf-8"))
    manifest = {
        "type": "context-manifest",
        "project": index.get("project"),
        "release": index.get("release"),
        "selection": {"stack": args.stack, "surface": args.surface, "family": args.family, "query": args.query},
        "card_count": len(selected),
        "token_budget": args.max_tokens,
        "retrieval_order": index.get("retrieval_order", []),
        "safe_boundary": "evidence-backed defensive context; no payloads, credentials or live-target instructions",
    }
    if args.format == "jsonl":
        lines = [json.dumps(manifest, ensure_ascii=False, sort_keys=True)]
        used = len(lines[0]) // 4
        for card in selected:
            payload = {"type": "card", "card": card_public(card)}
            rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            if used + len(rendered) // 4 > args.max_tokens:
                break
            lines.append(rendered)
            used += len(rendered) // 4
        return "\n".join(lines) + "\n"
    parts = [f"# Secure Context Atlas context pack ({index.get('release', 'unknown')})", "", "## Selection", "", f"- stack: `{args.stack or '*'}`", f"- surface: `{args.surface or '*'}`", f"- family: `{args.family or '*'}`", f"- query: `{args.query or '*'}`", "", "## Cards", ""]
    used = len("\n".join(parts)) // 4
    for card in selected:
        section = [f"### {card['id']} — {card.get('title', '')}", "", str(card.get("summary", "")), "", f"Path: `{card['path']}`", f"CWE: `{card.get('canonical_cwe', '')}`", f"Maturity: `{card.get('maturity', 'curated')}`", "", "Audit questions:"]
        section.extend(f"- {item}" for item in card.get("audit_questions", []))
        section.extend(["", "Safe verification:"])
        section.extend(f"- {item}" for item in card.get("safe_verification", []))
        section.extend(["", "Remediation:"])
        section.extend(f"- {item}" for item in card.get("remediation", []))
        rendered = "\n".join(section) + "\n"
        if used + len(rendered) // 4 > args.max_tokens:
            break
        parts.append(rendered)
        used += len(rendered) // 4
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(prog="sctx", description="Build deterministic Secure Context Atlas context packs")
    sub = parser.add_subparsers(dest="command", required=True)
    list_parser = sub.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    show = sub.add_parser("show")
    show.add_argument("id")
    search = sub.add_parser("search")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=10)
    pack_parser = sub.add_parser("pack")
    pack_parser.add_argument("--stack")
    pack_parser.add_argument("--surface")
    pack_parser.add_argument("--family")
    pack_parser.add_argument("--query")
    pack_parser.add_argument("--format", choices=["markdown", "jsonl"], default="markdown")
    pack_parser.add_argument("--max-cards", type=int, default=12)
    pack_parser.add_argument("--max-tokens", type=int, default=12000)
    pack_parser.add_argument("--output", type=Path)
    validate = sub.add_parser("validate")
    validate.add_argument("--rules", action="store_true")
    sarif = sub.add_parser("export-sarif")
    sarif.add_argument("--input", type=Path, required=True)
    sarif.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "list":
        records = [card_public(card) for card in cards()]
        if args.json:
            print(json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            for record in records:
                print(f"{record['id']}\t{record.get('maturity', 'curated')}\t{record.get('title', '')}")
        return 0
    if args.command == "show":
        record = next((card for card in cards() if card.get("id") == args.id), None)
        if record is None:
            print(f"unknown vulnerability: {args.id}", file=sys.stderr)
            return 1
        print(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.command == "search":
        ranked = sorted(cards(), key=lambda card: (-score(card, args.query), card["id"]))
        for card in [card for card in ranked if score(card, args.query) > 0][: args.limit]:
            print(f"{card['id']}\t{score(card, args.query)}\t{card.get('title', '')}")
        return 0
    if args.command == "pack":
        rendered = pack(args)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    if args.command == "validate":
        commands = [[sys.executable, str(ROOT / "scripts/validate_repo.py")]]
        if args.rules:
            commands.append([sys.executable, str(ROOT / "scripts/validate_rules.py")])
        for command in commands:
            subprocess.run(command, cwd=ROOT, check=True)
        return 0
    if args.command == "export-sarif":
        return subprocess.run([sys.executable, str(ROOT / "scripts/export_sarif.py"), "--input", str(args.input), "--output", str(args.output)], cwd=ROOT).returncode
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
