#!/usr/bin/env python3
"""Prepare a portable, rollout-bound context for the G6 BYO probe app."""

import argparse
import json
import os
import pathlib
import platform
import re
import shutil
import sys
import tempfile

from prepare_native_elf_context import sha256, stage_native_elf


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ROW = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

def prepare(args: argparse.Namespace) -> None:
    binary = pathlib.Path(args.binary).resolve(strict=True)
    output = pathlib.Path(args.output).resolve(strict=False)
    host_architecture = platform.machine().lower()
    if sys.platform != "linux" or args.architecture != "x86_64" or host_architecture not in {"x86_64", "amd64"}:
        raise RuntimeError(
            "G6 BYO runtime closure must be staged on native x86_64 Linux before portable artifact packaging"
        )
    if not SHA256.fullmatch(args.challenge):
        raise RuntimeError("challenge must be exactly 64 lowercase hexadecimal characters")
    if not COMMIT.fullmatch(args.commit):
        raise RuntimeError("commit must be exactly 40 lowercase hexadecimal characters")
    if not ROW.fullmatch(args.row):
        raise RuntimeError("row must contain only safe evidence-identity characters")
    if output == pathlib.Path("/") or len(output.parts) < 3:
        raise RuntimeError("refusing an unsafe output context path")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.", dir=output.parent) as temporary:
        root = pathlib.Path(temporary)
        for directory in ("lib", "lib64", "usr/lib", "usr/lib64"):
            (root / directory).mkdir(parents=True)

        binary_digest = stage_native_elf(binary, root, "/app/prodigy_g6_byo_probe_container", args.architecture)
        proof = root / "g6-byo-proof"
        proof.write_text(
            f"PRODIGY_G6_BYO_PROOF {args.challenge} {args.commit} {args.row} {binary_digest}\n",
            encoding="ascii",
        )
        proof.chmod(0o644)

        files = []
        for path in sorted((entry for entry in root.rglob("*") if entry.is_file()), key=str):
            files.append({
                "path": "/" + str(path.relative_to(root)),
                "sha256": sha256(path),
                "size": path.stat().st_size,
            })
        manifest = {
            "binarySHA256": binary_digest,
            "candidateCommit": args.commit,
            "challenge": args.challenge,
            "files": files,
            "row": args.row,
            "schemaVersion": 1,
        }
        (root / "context.manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        (root / ".prepared").write_text(binary_digest + "\n", encoding="ascii")

        if output.exists():
            if output.is_symlink() or not output.is_dir():
                raise RuntimeError("refusing to replace a non-directory output context")
            shutil.rmtree(output)
        os.replace(root, output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--row", required=True)
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
