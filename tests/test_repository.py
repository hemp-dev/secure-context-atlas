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
        cwe = Path("/tmp/cwec_v4.20.xml.zip")
        capec = Path("/tmp/capec_v3.9.xml")
        build = [sys.executable, str(root / "scripts" / "build_indexes.py")]
        if cwe.exists() and capec.exists():
            build.extend(["--cwe", str(cwe), "--capec", str(capec)])
        else:
            build.append("--fetch")
        subprocess.run(build, cwd=root, check=True)
        subprocess.run([sys.executable, str(root / "scripts" / "run_eval.py"), "--output", str(root / "ai" / "evaluation-report.json")], cwd=root, check=True)
        subprocess.run([sys.executable, str(root / "scripts" / "build_release_manifest.py")], cwd=root, check=True)
        subprocess.run([sys.executable, str(root / "scripts" / "validate_schemas.py")], cwd=root, check=True)
        subprocess.run([sys.executable, str(root / "scripts" / "validate_repo.py")], cwd=root, check=True)
        subprocess.run([sys.executable, str(root / "scripts" / "validate_rules.py")], cwd=root, check=True)
        subprocess.run([sys.executable, str(root / "scripts" / "validate_threat_models.py")], cwd=root, check=True)
        subprocess.run([sys.executable, str(root / "scripts" / "validate_release.py")], cwd=root, check=True)
        with tempfile.TemporaryDirectory() as temp:
            subprocess.run([sys.executable, str(root / "scripts" / "export_sarif.py"), "--input", str(root / "regression" / "findings.json"), "--output", str(Path(temp) / "findings.sarif")], cwd=root, check=True)
            sarif = json.loads((Path(temp) / "findings.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
