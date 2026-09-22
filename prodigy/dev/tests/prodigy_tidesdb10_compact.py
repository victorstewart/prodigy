#!/usr/bin/env python3
"""Focused private-copy maintenance receipt regression."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile


def run(*args, ok=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    if (result.returncode == 0) != ok:
        raise RuntimeError(f"unexpected compact result: {result.stderr}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--exporter", required=True)
    parser.add_argument("--importer", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("compact regression requires root-owned private fixtures")
    with tempfile.TemporaryDirectory(prefix="prodigy-tidesdb10-compact-",
                                     dir=pathlib.Path.cwd()) as temporary:
        work = pathlib.Path(temporary)
        legacy = work / "legacy"
        stream = work / "database.pt9t10kv"
        database = work / "database"
        baseline = work / "baseline.pt9t10kv"
        run(args.fixture, str(legacy))
        run(args.exporter, str(legacy), str(stream))
        run(args.importer, str(stream), str(database))

        missing = work / "missing"
        missing_receipt = work / "missing.pt9t10kv"
        run(args.importer, "--compact", str(missing), str(missing_receipt), ok=False)
        if missing.exists() or missing_receipt.exists():
            raise RuntimeError("compact created an absent database or receipt")

        symlink = work / "database-link"
        symlink.symlink_to(database, target_is_directory=True)
        run(args.importer, "--compact", str(symlink), str(work / "link.pt9t10kv"),
            ok=False)

        result = run(args.importer, "--compact", str(database), str(baseline))
        receipt = json.loads(result.stdout)
        if receipt["records"] < 1 or receipt["columnFamilies"] < 1:
            raise RuntimeError("compact omitted logical receipt counts")
        before = hashlib.sha256(baseline.read_bytes()).digest()
        if receipt["logicalSHA256"] != before.hex():
            raise RuntimeError("reported baseline digest does not match receipt")

        retry = run(args.importer, "--compact", str(database), str(baseline))
        if hashlib.sha256(baseline.read_bytes()).digest() != before:
            raise RuntimeError("retry overwrote durable baseline")
        if json.loads(retry.stdout)["logicalSHA256"] != before.hex():
            raise RuntimeError("retry did not verify the original baseline")

        hard_link = work / "linked.pt9t10kv"
        os.link(baseline, hard_link)
        run(args.importer, "--compact", str(database), str(hard_link), ok=False)
        hard_link.unlink()

        truncated = work / "truncated.pt9t10kv"
        truncated.write_bytes(baseline.read_bytes()[:-1])
        truncated.chmod(0o600)
        run(args.importer, "--compact", str(database), str(truncated), ok=False)

        empty_legacy = work / "empty-legacy"
        empty_stream = work / "empty.pt9t10kv"
        empty_database = work / "empty-database"
        mismatch = work / "mismatch.pt9t10kv"
        run(args.fixture, str(empty_legacy), "--empty")
        run(args.exporter, str(empty_legacy), str(empty_stream))
        run(args.importer, str(empty_stream), str(empty_database))
        run(args.importer, "--compact", str(empty_database), str(mismatch))
        run(args.importer, "--compact", str(database), str(mismatch), ok=False)


if __name__ == "__main__":
    main()
