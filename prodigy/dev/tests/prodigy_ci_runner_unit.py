#!/usr/bin/env python3
"""Portable black-box coverage for the Prodigy CTest runner."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if len(sys.argv) != 4:
    raise SystemExit(f"usage: {sys.argv[0]} RUSTC RUNNER_SOURCE CMAKE")
RUSTC = Path(sys.argv[1])
RUNNER_SOURCE = Path(sys.argv[2])
CMAKE = Path(sys.argv[3])
sys.argv = [sys.argv[0]]


class ProdigyCiRunnerUnit(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rustc = RUSTC
        cls.runner_source = RUNNER_SOURCE
        cls.cmake = CMAKE
        cls.tmp = tempfile.TemporaryDirectory(prefix="prodigy-ci-runner-unit-")
        cls.root = Path(cls.tmp.name)
        cls.runner = cls.root / "prodigy_ci"
        subprocess.run(
            [cls.rustc, "--edition=2021", "-C", "opt-level=2", cls.runner_source, "-o", cls.runner],
            check=True,
            text=True,
            capture_output=True,
            timeout=120,
        )
        cls.bin_dir = cls.root / "bin"
        cls.bin_dir.mkdir()
        fake_id = cls.bin_dir / "id"
        fake_id.write_text("#!/bin/sh\n[ \"${1:-}\" = -u ] || exit 2\nprintf '0\\n'\n")
        fake_id.chmod(0o755)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def make_fixture(self, name: str, tests: list[tuple[str, bool]]) -> Path:
        fixture = self.root / name
        fixture.mkdir()
        lines = ["# CMake generated Testfile for black-box runner coverage."]
        for test_name, succeeds in tests:
            result = "true" if succeeds else "false"
            lines.append(
                f'add_test({test_name} "{self.cmake}" -E {result})'
            )
        (fixture / "CTestTestfile.cmake").write_text("\n".join(lines) + "\n")
        return fixture

    def run_runner(self, fixture: Path, *args: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join(
            (str(self.bin_dir), str(self.cmake.parent), environment.get("PATH", ""))
        )
        return subprocess.run(
            [self.runner, f"--build-dir={fixture}", "--skip-build", *args],
            text=True,
            capture_output=True,
            env=environment,
            timeout=30,
        )

    def test_default_selection_includes_hyphenated_names_only(self) -> None:
        fixture = self.make_fixture(
            "default-selection",
            [
                ("prodigy_dev_normal", True),
                ("prodigy_brain_fragmented-artifact_heartbeat", True),
                ("prodigy_brain_tls-fragmented-artifact_heartbeat", True),
                ("unrelated-name", True),
            ],
        )
        result = self.run_runner(fixture)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("prodigy_dev_normal", result.stdout)
        self.assertIn("prodigy_brain_fragmented-artifact_heartbeat", result.stdout)
        self.assertIn("prodigy_brain_tls-fragmented-artifact_heartbeat", result.stdout)
        self.assertNotIn("unrelated-name", result.stdout)

    def test_empty_selection_is_an_error(self) -> None:
        fixture = self.make_fixture("empty-selection", [("prodigy_dev_normal", True)])
        result = self.run_runner(fixture, "--ctest-filter=^missing$")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No tests were found", result.stdout + result.stderr)

    def test_selected_failure_propagates(self) -> None:
        fixture = self.make_fixture(
            "selected-failure",
            [("prodigy_dev_failure-test", False), ("prodigy_dev_normal", True)],
        )
        result = self.run_runner(fixture, "--ctest-filter=^prodigy_dev_failure-test$")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("prodigy_dev_failure-test", result.stdout + result.stderr)
        self.assertIn("ctest failed", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
