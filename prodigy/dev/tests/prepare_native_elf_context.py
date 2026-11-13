#!/usr/bin/env python3
"""Stage a native executable and its runtime closure for Discombobulator."""

import argparse
import hashlib
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile


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
        raise RuntimeError("native binary has no absolute ELF interpreter")
    return pathlib.Path(match.group(1))


def dependencies(binary: pathlib.Path) -> list[pathlib.Path]:
    output = command("ldd", str(binary))
    if "not found" in output:
        raise RuntimeError("native binary has an unresolved runtime dependency")
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


def stage_native_elf(binary: pathlib.Path, root: pathlib.Path, destination: str, architecture: str) -> str:
    architectures = {
        "x86_64": ({"x86_64", "amd64"}, "Advanced Micro Devices X86-64"),
        "aarch64": ({"aarch64", "arm64"}, "AArch64"),
        "arm64": ({"aarch64", "arm64"}, "AArch64"),
        "riscv64": ({"riscv64"}, "RISC-V"),
    }
    expected = architectures.get(architecture)
    if sys.platform != "linux" or expected is None or platform.machine().lower() not in expected[0]:
        raise RuntimeError("runtime closure must be staged on native Linux matching the target architecture")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("native binary must be an executable regular file")
    header = command("readelf", "-h", str(binary))
    if not re.search(r"^\s*Machine:\s+" + re.escape(expected[1]) + r"\s*$", header, re.MULTILINE):
        raise RuntimeError("native ELF architecture does not match the requested target")
    target = pathlib.PurePosixPath(destination)
    if not target.is_absolute() or len(target.parts) < 2 or ".." in target.parts:
        raise RuntimeError("application destination must be an absolute container file path")
    app = root / str(target).lstrip("/")
    copy_regular(binary, app)
    app.chmod(0o755)
    for dependency in dependencies(binary):
        relative = pathlib.Path(str(dependency).lstrip("/"))
        if not relative.parts or ".." in relative.parts:
            raise RuntimeError(f"unsafe runtime dependency path: {dependency}")
        copy_regular(dependency, root / relative)
    return sha256(app)


def prepare(args: argparse.Namespace) -> None:
    binary = pathlib.Path(args.binary).resolve(strict=True)
    requested_output = pathlib.Path(args.output)
    if requested_output.is_symlink():
        raise RuntimeError("refusing a symlink output context")
    output = requested_output.resolve(strict=False)
    if len(output.parts) < 3 or output == binary or output in binary.parents:
        raise RuntimeError("refusing an unsafe output context path")
    # Ninja may create the stamp's parent directory before running this command.
    if output.exists() and (not output.is_dir() or
                            (any(output.iterdir()) and not (output / ".prepared").is_file())):
        raise RuntimeError("refusing to replace a context not owned by this preparer")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.", dir=output.parent) as temporary:
        root = pathlib.Path(temporary)
        digest = stage_native_elf(binary, root, args.destination, args.architecture)
        (root / ".prepared").write_text(digest + "\n", encoding="ascii")
        if output.exists():
            shutil.rmtree(output)
        os.replace(root, output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--destination", required=True)
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
