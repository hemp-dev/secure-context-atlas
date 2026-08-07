#!/usr/bin/env python3
"""Smoke test entry point for CI and local runners."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import json


class RepositorySmokeTest(unittest.TestCase):
    def test_generated_indexes_and_cards(self) -> None:
        root = Path(__file__).resolve().parents[1]
        python = [sys.executable, "-B"]
        cwe = Path("/tmp/cwec_v4.20.xml.zip")
        capec = Path("/tmp/capec_v3.9.xml")
        build = python + [str(root / "scripts" / "build_indexes.py")]
        if cwe.exists() and capec.exists():
            build.extend(["--cwe", str(cwe), "--capec", str(capec)])
        else:
            build.append("--fetch")
        subprocess.run(build, cwd=root, check=True)
        subprocess.run(python + [str(root / "scripts" / "run_eval.py"), "--output", str(root / "ai" / "evaluation-report.json")], cwd=root, check=True)
        subprocess.run(python + [str(root / "scripts" / "validate_sources.py")], cwd=root, check=True)
        subprocess.run(python + [str(root / "scripts" / "build_release_manifest.py")], cwd=root, check=True)
        subprocess.run(python + [str(root / "scripts" / "validate_schemas.py")], cwd=root, check=True)
        subprocess.run(python + [str(root / "scripts" / "validate_repo.py")], cwd=root, check=True)
        subprocess.run(python + [str(root / "scripts" / "validate_rules.py")], cwd=root, check=True)
        subprocess.run(python + [str(root / "scripts" / "validate_threat_models.py")], cwd=root, check=True)
        subprocess.run(python + [str(root / "scripts" / "validate_release.py")], cwd=root, check=True)
        with tempfile.TemporaryDirectory() as temp:
            subprocess.run(python + [str(root / "scripts" / "export_sarif.py"), "--input", str(root / "regression" / "findings.json"), "--output", str(Path(temp) / "findings.sarif")], cwd=root, check=True)
            sarif = json.loads((Path(temp) / "findings.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
            pack = Path(temp) / "pack.jsonl"
            subprocess.run([str(root / "bin" / "sctx"), "pack", "--stack", "python", "--surface", "api", "--format", "jsonl", "--max-cards", "3", "--max-tokens", "500", "--output", str(pack)], cwd=root, check=True)
            manifest = json.loads(pack.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(manifest["release"], "0.6.0")
            self.assertTrue(manifest["pack_id"].startswith("pack."))
            self.assertEqual(manifest["card_count"], len(manifest["card_ids"]))
            self.assertEqual(manifest["selection"]["maturity"], ["curated", "production-ready", "tested"])
