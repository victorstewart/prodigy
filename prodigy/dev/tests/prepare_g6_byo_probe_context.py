#!/usr/bin/env python3
"""Prepare a portable, rollout-bound context for the G6 BYO probe app."""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ROW = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
INTERPRETER = re.compile(r"Requesting program interpreter:\s*([^\]]+)")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command(*args: str) -> str:
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(args)} failed: {detail}")
    return result.stdout


def interpreter(binary: pathlib.Path) -> pathlib.Path:
    output = command("readelf", "-l", str(binary))
    match = INTERPRETER.search(output)
    if not match or not match.group(1).startswith("/"):
        raise RuntimeError("probe binary has no absolute ELF interpreter")
    return pathlib.Path(match.group(1))


def dependencies(binary: pathlib.Path) -> list[pathlib.Path]:
    output = command("ldd", str(binary))
    if "not found" in output:
        raise RuntimeError("probe binary has an unresolved runtime dependency")
    paths: set[pathlib.Path] = set()
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        candidate = line.split("=>", 1)[1].strip().split()[0] if "=>" in line else line.split()[0]
        if candidate.startswith("/"):
            paths.add(pathlib.Path(candidate))
    paths.add(interpreter(binary))
    return sorted(paths, key=str)


def copy_regular(source: pathlib.Path, destination: pathlib.Path) -> None:
    resolved = source.resolve(strict=True)
    if not resolved.is_file():
        raise RuntimeError(f"runtime dependency is not a regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(resolved, destination)


def prepare(args: argparse.Namespace) -> None:
    binary = pathlib.Path(args.binary).resolve(strict=True)
    output = pathlib.Path(args.output).resolve(strict=False)
    host_architecture = platform.machine().lower()
    if sys.platform != "linux" or args.architecture != "x86_64" or host_architecture not in {"x86_64", "amd64"}:
        raise RuntimeError(
            "G6 BYO runtime closure must be staged on native x86_64 Linux before portable artifact packaging"
        )
    elf_header = command("readelf", "-h", str(binary))
    if not re.search(r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$", elf_header, re.MULTILINE):
        raise RuntimeError("probe binary is not an x86_64 ELF executable")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("probe binary must be an executable regular file")
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

        app = root / "app/prodigy_g6_byo_probe_container"
        copy_regular(binary, app)
        app.chmod(0o755)
        binary_digest = sha256(app)
        proof = root / "g6-byo-proof"
        proof.write_text(
            f"PRODIGY_G6_BYO_PROOF {args.challenge} {args.commit} {args.row} {binary_digest}\n",
            encoding="ascii",
        )
        proof.chmod(0o644)

        for dependency in dependencies(binary):
            relative = pathlib.Path(str(dependency).lstrip("/"))
            if not relative.parts or ".." in relative.parts:
                raise RuntimeError(f"unsafe runtime dependency path: {dependency}")
            copy_regular(dependency, root / relative)

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
