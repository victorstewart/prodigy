#!/usr/bin/env python3
"""Verify an evaluation distribution before entering its Linux runtime."""

import hashlib
import json
from pathlib import Path
import re
import sys


def verify(root):
    root = Path(root).resolve(strict=True)
    manifest = json.loads((root / "evaluation.json").read_text())
    if manifest.get("formatVersion") != 1:
        raise ValueError("unsupported evaluation manifest version")
    if manifest.get("architecture") not in ("x86_64", "aarch64"):
        raise ValueError("unsupported evaluation architecture")
    if not isinstance(manifest.get("version"), str) or not manifest["version"]:
        raise ValueError("missing evaluation version")
    files = manifest.get("files")
    required = {"try-prodigy", "bin/prodigy", "bin/mothership", "bin/discombobulator",
                "tools/evaluation/session.py", "tools/evaluation/verify.py",
                "prodigy/dev/tests/prodigy_dev_test_cluster.sh",
                f"bin/prodigy.{manifest['architecture']}.bundle.tar.zst",
                f"bin/prodigy.{manifest['architecture']}.bundle.tar.zst.sha256"}
    if not isinstance(files, dict) or not required.issubset(files):
        raise ValueError("incomplete evaluation manifest")
    for name, digest in files.items():
        path = Path(name)
        if (not name or path.is_absolute() or ".." in path.parts
                or str(path) != name or not re.fullmatch(r"[0-9a-f]{64}", str(digest))):
            raise ValueError("invalid evaluation file entry")
        candidate = root / path
        if candidate.is_symlink() or root not in candidate.resolve(strict=True).parents:
            raise ValueError("evaluation file escapes bundle: " + name)
        with candidate.open("rb") as stream:
            actual = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                actual.update(chunk)
        if actual.hexdigest() != digest:
            raise ValueError("evaluation checksum mismatch: " + name)
    for version in ("v1", "v2"):
        for name in (f"examples/hello-prodigy/hello-prodigy-{version}.{manifest['architecture']}.container.zst",
                     f"examples/hello-prodigy/hello-prodigy-{version}.deployment.plan.v1.json"):
            if name not in files:
                raise ValueError("missing demo artifact or plan: " + name)
    return manifest


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: verify.py BUNDLE_DIRECTORY")
        verify(sys.argv[1])
    except (ValueError, OSError, TypeError) as error:
        print("Evaluation bundle: " + str(error), file=sys.stderr)
        sys.exit(1)
