#!/usr/bin/env python3
"""Offline migration regression: binary keys, all/empty CFs, empty DB, bad stream, immutable source."""
import argparse
import hashlib
import pathlib
import shutil
import struct
import subprocess
import tempfile


def tree_digest(root):
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        h.update(path.relative_to(root).as_posix().encode() + b"\0")
        if path.is_file():
            h.update(path.read_bytes())
    return h.digest()


def run(*args, ok=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (result.returncode == 0) != ok:
        raise RuntimeError("migration command did not have the expected result")


def migrate(fixture, exporter, importer, work, empty):
    original = work / ("empty-original" if empty else "records-original")
    run(fixture, str(original), *( ["--empty"] if empty else [] ))
    before = tree_digest(original)
    copied = work / ("empty-copy" if empty else "records-copy")
    shutil.copytree(original, copied)
    stream = work / ("empty.stream" if empty else "records.stream")
    imported = work / ("empty-imported" if empty else "records-imported")
    run(exporter, str(copied), str(stream))
    if tree_digest(original) != before:
        raise RuntimeError("export modified the original fixture")
    run(importer, str(stream), str(imported))
    corrupt = work / ("empty-corrupt.stream" if empty else "records-corrupt.stream")
    data = bytearray(stream.read_bytes())
    if not data:
        raise RuntimeError("empty migration stream")
    data[-1] ^= 1
    corrupt.write_bytes(data)
    corrupt_db = work / ("empty-corrupt-db" if empty else "records-corrupt-db")
    run(importer, str(corrupt), str(corrupt_db), ok=False)
    if corrupt_db.exists():
        raise RuntimeError("malformed stream created a destination")
    if not empty:
        payload = stream.read_bytes()[:-41]
        first_cf_size = 5 + struct.unpack_from("<I", payload, 9)[0]
        duplicate_cf = payload + payload[8:8 + first_cf_size]
        duplicate_cf += b"\xff" + hashlib.sha256(duplicate_cf).digest() + stream.read_bytes()[-8:]
        duplicate_cf_path = work / "duplicate-cf.stream"
        duplicate_cf_path.write_bytes(duplicate_cf)
        duplicate_cf_db = work / "duplicate-cf-db"
        run(importer, str(duplicate_cf_path), str(duplicate_cf_db), ok=False)
        if duplicate_cf_db.exists():
            raise RuntimeError("duplicate CF stream created a destination")
        offset = 8
        while payload[offset] == 1:
            offset += 5 + struct.unpack_from("<I", payload, offset + 1)[0]
        key_size, value_size = struct.unpack_from("<II", payload, offset + 1)
        record_size = 9 + key_size + value_size
        duplicate_key = payload[:offset + record_size] + payload[offset:offset + record_size] + payload[offset + record_size:]
        count = struct.unpack("<Q", stream.read_bytes()[-8:])[0] + 1
        duplicate_key += b"\xff" + hashlib.sha256(duplicate_key).digest() + struct.pack("<Q", count)
        duplicate_key_path = work / "duplicate-key.stream"
        duplicate_key_path.write_bytes(duplicate_key)
        duplicate_key_db = work / "duplicate-key-db"
        run(importer, str(duplicate_key_path), str(duplicate_key_db), ok=False)
        if duplicate_key_db.exists():
            raise RuntimeError("duplicate key stream created a destination")
        extra_cf = payload + b"\x01" + struct.pack("<I", 5) + b"extra"
        extra_cf += b"\xff" + hashlib.sha256(extra_cf).digest() + stream.read_bytes()[-8:]
        extra_cf_path = work / "extra-cf.stream"
        extra_cf_path.write_bytes(extra_cf)
        extra_cf_db = work / "extra-cf-db"
        run(importer, str(extra_cf_path), str(extra_cf_db))
        run(importer, "--verify", str(stream), str(extra_cf_db), ok=False)
        extra_key = payload + b"\x02" + struct.pack("<II", 1, 1) + b"zq"
        extra_key += b"\xff" + hashlib.sha256(extra_key).digest() + struct.pack("<Q", count)
        extra_key_path = work / "extra-key.stream"
        extra_key_path.write_bytes(extra_key)
        extra_key_db = work / "extra-key-db"
        run(importer, str(extra_key_path), str(extra_key_db))
        run(importer, "--verify", str(stream), str(extra_key_db), ok=False)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--fixture", required=True)
    p.add_argument("--exporter", required=True)
    p.add_argument("--importer", required=True)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="prodigy-tidesdb-migration-", dir=pathlib.Path.cwd()) as temp:
        work = pathlib.Path(temp)
        migrate(args.fixture, args.exporter, args.importer, work, False)
        migrate(args.fixture, args.exporter, args.importer, work, True)


if __name__ == "__main__":
    main()
