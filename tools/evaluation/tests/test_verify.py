#!/usr/bin/env python3
"""Non-runtime rejection coverage for evaluation bundle verification."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


VERIFY_PATH = Path(__file__).parents[1] / "verify.py"
SPEC = importlib.util.spec_from_file_location("evaluation_verify", VERIFY_PATH)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VERIFY)

REQUIRED = {
    "try-prodigy",
    "bin/prodigy",
    "bin/mothership",
    "bin/discombobulator",
    "bin/prodigy.aarch64.bundle.tar.zst",
    "bin/prodigy.aarch64.bundle.tar.zst.sha256",
    "tools/evaluation/session.py",
    "tools/evaluation/verify.py",
    "prodigy/dev/tests/prodigy_dev_test_cluster.sh",
    "examples/hello-prodigy/hello-prodigy-v1.aarch64.container.zst",
    "examples/hello-prodigy/hello-prodigy-v2.aarch64.container.zst",
    "examples/hello-prodigy/hello-prodigy-v1.deployment.plan.v1.json",
    "examples/hello-prodigy/hello-prodigy-v2.deployment.plan.v1.json",
}


def write_rejected_bundle(root, extra_files=None):
    files = {}
    for name in REQUIRED | set(extra_files or {}):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (extra_files or {}).get(name, b"test")
        path.write_bytes(content)
        files[name] = hashlib.sha256(content).hexdigest()
    (root / "evaluation.json").write_text(json.dumps({
        "formatVersion": 1,
        "version": "test",
        "architecture": "aarch64",
        "files": files,
    }))


class VerifyRejectsInvalidInputs(unittest.TestCase):
    def test_rejects_missing_required_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evaluation.json").write_text(json.dumps({
                "formatVersion": 1, "version": "test", "architecture": "aarch64", "files": {},
            }))
            with self.assertRaisesRegex(ValueError, "incomplete evaluation manifest"):
                VERIFY.verify(root)

    def test_rejects_path_escape_even_when_other_files_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_rejected_bundle(root)
            manifest_path = root / "evaluation.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"]["../outside"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "invalid evaluation file entry"):
                VERIFY.verify(root)

    def test_rejects_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_rejected_bundle(root)
            manifest_path = root / "evaluation.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"]["bin/mothership"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "evaluation checksum mismatch: bin/mothership"):
                VERIFY.verify(root)


if __name__ == "__main__":
    unittest.main()
