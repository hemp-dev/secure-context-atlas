#!/usr/bin/env python3
"""Smoke test entry point for CI and local runners."""
from pathlib import Path
import subprocess
import sys
import unittest


class RepositorySmokeTest(unittest.TestCase):
    def test_generated_indexes_and_cards(self) -> None:
        root = Path(__file__).resolve().parents[1]
        subprocess.run([sys.executable, str(root / "scripts" / "build_indexes.py")], cwd=root, check=True)
        subprocess.run([sys.executable, str(root / "scripts" / "validate_repo.py")], cwd=root, check=True)
