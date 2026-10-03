#!/usr/bin/env python3
"""Read-only, ABI-pinned initial BrainView eligibility observer.

The probe is dormant without an exact layout manifest. It reads only
/proc/<pid>/mem and process metadata; it never attaches, pauses, writes, or
calls into a target. Double snapshots detect observed races, not every
intervening mutation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import struct
import sys
from dataclasses import dataclass
from typing import Any

MAX_MEMBERS = 3
MAX_TABLE_SLOTS = 64
EMPTY_CONTROL = 0xFF
PT_LOAD = 1
ELF64_PHDR = struct.Struct("<IIQQQQQQ")
ELF64_EHDR = struct.Struct("<16sHHIQQQIHHHHHH")


class Reject(RuntimeError):
    pass


@dataclass(frozen=True)
class MapEntry:
    start: int
    end: int
    perms: str
    offset: int
    device: tuple[int, int]
    inode: int
    path: str


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def maps_for(pid: int) -> list[MapEntry]:
    result = []
    for line in pathlib.Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue
        begin, end = (int(value, 16) for value in fields[0].split("-", 1))
        major, minor = (int(value, 16) for value in fields[3].split(":", 1))
        path = fields[5] if len(fields) == 6 else ""
        result.append(MapEntry(begin, end, fields[1], int(fields[2], 16), (major, minor), int(fields[4]), path))
    return result


def normalized_map_path(path: str) -> str:
    return path.removesuffix(" (deleted)")


def matching_executable_mappings(maps: list[MapEntry], executable: pathlib.Path) -> list[MapEntry]:
    stat = executable.stat()
    device = (os.major(stat.st_dev), os.minor(stat.st_dev))
    expected = str(executable.resolve())
    return [entry for entry in maps if (entry.device == device and entry.inode == stat.st_ino) or
            normalized_map_path(entry.path) == expected]


def load_segments(executable: pathlib.Path) -> list[tuple[int, int]]:
    with executable.open("rb") as stream:
        header = stream.read(ELF64_EHDR.size)
        if len(header) != ELF64_EHDR.size:
            raise Reject("short ELF header")
        ident, _type, _machine, _version, _entry, phoff, _shoff, _flags, ehsize, phentsize, phnum, *_ = ELF64_EHDR.unpack(header)
        if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1 or ehsize != ELF64_EHDR.size or phentsize != ELF64_PHDR.size:
            raise Reject("unsupported non-ELF64-little-endian executable")
        segments = []
        stream.seek(phoff)
        for _ in range(phnum):
            data = stream.read(ELF64_PHDR.size)
            if len(data) != ELF64_PHDR.size:
                raise Reject("short ELF program header")
            kind, _flags, offset, vaddr, _paddr, _filesz, _memsz, align = ELF64_PHDR.unpack(data)
            if kind == PT_LOAD:
                if not align or offset % align != vaddr % align:
                    raise Reject("invalid PT_LOAD alignment")
                segments.append((offset, vaddr))
    if not segments:
        raise Reject("ELF has no PT_LOAD segments")
    return segments


def pie_base(executable: pathlib.Path, mappings: list[MapEntry]) -> int:
    page = os.sysconf("SC_PAGE_SIZE")
    candidates: set[int] = set()
    for segment_offset, segment_vaddr in load_segments(executable):
        map_offset = segment_offset & -page
        virtual_page = segment_vaddr & -page
        for mapping in mappings:
            if mapping.offset == map_offset:
                candidates.add(mapping.start - virtual_page)
    if len(candidates) != 1:
        raise Reject("cannot bind a unique PIE load base through PT_LOAD mappings")
    return candidates.pop()


def mapped_readable(maps: list[MapEntry], pointer: int, length: int) -> bool:
    return pointer != 0 and length > 0 and pointer + length > pointer and any(
        entry.start <= pointer and pointer + length <= entry.end and "r" in entry.perms for entry in maps)


def pointer_aligned(pointer: int) -> bool:
    return pointer != 0 and pointer % 8 == 0


def process_identity(pid: int) -> str:
    stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
    close = stat.rfind(")")
    values = stat[close + 2:].split()
    if close < 1 or len(values) <= 19:
        raise Reject("malformed /proc/pid/stat")
    starttime = values[19]  # Field 22; suffix starts at field 3.
    netns = os.readlink(f"/proc/{pid}/ns/net")
    executable = pathlib.Path(f"/proc/{pid}/exe")
    return hashlib.sha256(f"{pid}|{starttime}|{netns}|{sha256_file(executable)}".encode()).hexdigest()


class Memory:
    def __init__(self, pid: int, mappings: list[MapEntry]):
        self.mappings = mappings
        self.fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)

    def close(self) -> None:
        os.close(self.fd)

    def read(self, address: int, length: int) -> bytes:
        if not mapped_readable(self.mappings, address, length):
            raise Reject("pointer outside readable mapped memory")
        data = os.pread(self.fd, length, address)
        if len(data) != length:
            raise Reject("short /proc/pid/mem read")
        return data

    def u64(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, 8))[0]

    def u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def i32(self, address: int) -> int:
        return struct.unpack("<i", self.read(address, 4))[0]

    def boolean(self, address: int) -> bool:
        value = self.read(address, 1)[0]
        if value not in (0, 1):
            raise Reject("non-canonical bool in target snapshot")
        return bool(value)

    def u128_hex(self, address: int) -> str:
        low, high = struct.unpack("<QQ", self.read(address, 16))
        return f"0x{high:016x}{low:016x}"


def integer(value: Any) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def require_layout(layout: dict[str, Any]) -> dict[str, int]:
    if layout.get("schema") != 1 or layout.get("abi") != {"pointerSize": 8, "byteOrder": "little"}:
        raise Reject("unsupported layout schema/ABI")
    if not isinstance(layout.get("binary", {}).get("sha256"), str) or not isinstance(layout.get("symbols", {}).get("thisBrain"), (str, int)):
        raise Reject("layout manifest lacks an exact binary or thisBrain symbol")
    required = ("brainBaseBrains", "brainViewUUID", "brainViewPrivate4", "brainViewQuarantined",
                "brainViewConnected", "brainViewTransportEpoch", "brainViewQueuedCloseTransportEpoch",
                "brainViewSocketFslot", "brainViewSocketIsFixedFile", "setEntries", "setSlotsMinusOne",
                "setElements", "blockControlBytes", "blockData", "blockSize", "blockBytes")
    offsets = layout.get("offsets")
    if not isinstance(offsets, dict) or any(key not in offsets for key in required):
        raise Reject("layout manifest lacks a required exact-record offset")
    normalized = {key: integer(offsets[key]) for key in required}
    if any(value < 0 for value in normalized.values()) or normalized["blockSize"] != 16 or \
       normalized["blockControlBytes"] != 0 or normalized["blockData"] < normalized["blockSize"] or \
       normalized["blockBytes"] < normalized["blockData"] + normalized["blockSize"] * 8:
        raise Reject("unexpected bytell BrainView* block layout")
    return normalized


def canonical_uuid(value: Any) -> str:
    parsed = integer(value)
    if parsed <= 0 or parsed >= 1 << 128:
        raise Reject("member UUID is not a nonzero uint128")
    return f"0x{parsed:032x}"


def expected_remote_members(member: dict[str, Any], all_members: list[dict[str, Any]]) -> set[tuple[str, int]]:
    return {(canonical_uuid(other["uuid"]), integer(other["private4"])) for other in all_members
            if integer(other["pid"]) != integer(member["pid"])}


def snapshot_member(member: dict[str, Any], all_members: list[dict[str, Any]], layout: dict[str, Any], offsets: dict[str, int]) -> dict[str, Any]:
    pid = integer(member["pid"])
    executable = pathlib.Path(f"/proc/{pid}/exe")
    actual_sha = sha256_file(executable)
    if actual_sha != layout["binary"]["sha256"]:
        raise Reject(f"pid {pid} executable SHA256 differs from layout manifest")
    mappings = maps_for(pid)
    base = pie_base(executable, matching_executable_mappings(mappings, executable))
    memory = Memory(pid, mappings)
    try:
        symbol_va = integer(layout["symbols"]["thisBrain"])
        brain = memory.u64(base + symbol_va)
        if not pointer_aligned(brain) or not mapped_readable(mappings, brain, offsets["brainBaseBrains"] + 8):
            raise Reject("thisBrain does not point to aligned mapped Brain object")
        table = brain + offsets["brainBaseBrains"]
        entries = memory.u64(table + offsets["setEntries"])
        slots_minus_one = memory.u64(table + offsets["setSlotsMinusOne"])
        elements = memory.u64(table + offsets["setElements"])
        if elements != len(all_members) - 1 or elements > MAX_MEMBERS - 1:
            raise Reject("BrainView set member count is not exact three-member topology")
        slots = slots_minus_one + 1
        if slots <= 0 or slots > MAX_TABLE_SLOTS or not pointer_aligned(entries):
            raise Reject("invalid bounded bytell BrainView table")
        blocks = (slots + offsets["blockSize"] - 1) // offsets["blockSize"]
        if not mapped_readable(mappings, entries, blocks * offsets["blockBytes"]):
            raise Reject("bytell BrainView backing storage is unmapped")
        structural = hashlib.sha256()
        structural.update(struct.pack("<QQQQQ", brain, table, entries, slots, elements))
        views: list[dict[str, Any]] = []
        for slot in range(slots):
            block = entries + (slot // offsets["blockSize"]) * offsets["blockBytes"]
            control = memory.read(block + offsets["blockControlBytes"] + slot % offsets["blockSize"], 1)
            structural.update(control)
            if control[0] == EMPTY_CONTROL:
                continue
            view = memory.u64(block + offsets["blockData"] + (slot % offsets["blockSize"]) * 8)
            structural.update(struct.pack("<Q", view))
            if not pointer_aligned(view) or not mapped_readable(mappings, view, max(offsets["brainViewSocketIsFixedFile"], offsets["brainViewSocketFslot"]) + 8):
                raise Reject("BrainView pointer is unaligned or unmapped")
            state = {"uuid": memory.u128_hex(view + offsets["brainViewUUID"]),
                     "private4": memory.u32(view + offsets["brainViewPrivate4"]),
                     "quarantined": memory.boolean(view + offsets["brainViewQuarantined"]),
                     "connected": memory.boolean(view + offsets["brainViewConnected"]),
                     "transportEpoch": memory.u32(view + offsets["brainViewTransportEpoch"]),
                     "queuedCloseTransportEpoch": memory.u32(view + offsets["brainViewQueuedCloseTransportEpoch"]),
                     "fslot": memory.i32(view + offsets["brainViewSocketFslot"]),
                     "isFixedFile": memory.boolean(view + offsets["brainViewSocketIsFixedFile"])}
            views.append(state)
        expected = expected_remote_members(member, all_members)
        observed = {(view["uuid"].lower(), view["private4"]) for view in views}
        if len(views) != elements or observed != expected or len({view["private4"] for view in views}) != len(views):
            raise Reject("BrainView set does not exactly bind unique expected remote identities")
        for view in views:
            if view["quarantined"] or not view["connected"] or not view["isFixedFile"] or view["fslot"] < 0 or \
               view["queuedCloseTransportEpoch"] == view["transportEpoch"]:
                raise Reject("remote BrainView is not initially eligible")
        return {"pid": pid, "processIdentitySHA256": process_identity(pid), "exeSHA256": actual_sha,
                "loadBaseSHA256": hashlib.sha256(f"{pid}:0x{base:x}".encode()).hexdigest(),
                "structuralSnapshotSHA256": structural.hexdigest(),
                "views": sorted(views, key=lambda value: (value["uuid"], value["private4"]))}
    finally:
        memory.close()


def observe(layout_path: pathlib.Path, members: list[dict[str, Any]], selected_pids: list[int]) -> dict[str, Any]:
    """Return a bounded initial-eligibility receipt for the two untouched peers.

    `layout_path` is runner-supplied generated ABI data, never a repository
    layout. `members` binds the frozen three-member source topology; only the
    master and witness `selected_pids` are decoded. The function exposes no raw
    target memory or addresses.
    """
    layout_bytes = layout_path.read_bytes()
    layout = json.loads(layout_bytes)
    offsets = require_layout(layout)
    if not isinstance(members, list) or len(members) != MAX_MEMBERS or len(set(integer(value["pid"]) for value in members)) != MAX_MEMBERS \
       or len({canonical_uuid(value["uuid"]) for value in members}) != MAX_MEMBERS \
       or len({integer(value["private4"]) for value in members}) != MAX_MEMBERS \
       or any(integer(value["private4"]) <= 0 or integer(value["private4"]) >= 1 << 32 for value in members):
        raise Reject("members must be exactly three distinct nonzero process and identity bindings")
    targets = [next(member for member in members if integer(member["pid"]) == pid) for pid in selected_pids]
    if len(targets) != 2 or len(set(selected_pids)) != 2:
        raise Reject("exactly distinct master and witness PIDs are required")
    first = [snapshot_member(member, members, layout, offsets) for member in targets]
    second = [snapshot_member(member, members, layout, offsets) for member in targets]
    if first != second:
        raise Reject("target eligibility or structural identity changed between snapshots")
    return {"result": "bounded-initial-eligibility-observation", "layoutSHA256": hashlib.sha256(layout_bytes).hexdigest(),
            "snapshots": first, "limits": ["Read-only double snapshot rejects observed structural races but cannot prove absence of an intervening ABA mutation.",
                                             "Requires exact ELF/layout binding and does not replace traffic or commit-availability evidence."]}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", type=pathlib.Path, required=True)
    parser.add_argument("--members", type=pathlib.Path, required=True,
                        help="JSON array of exact three {pid,uuid,private4} members; caller chooses M/W PIDs only")
    parser.add_argument("--pid", type=int, action="append", required=True, help="master and witness Brain parent PIDs")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        receipt = observe(arguments.layout, json.loads(arguments.members.read_text()), arguments.pid)
        arguments.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(f"P3_PEER_MEMORY_PROBE_PASS output={arguments.output}")
        return 0
    except (OSError, KeyError, TypeError, ValueError, StopIteration, Reject, json.JSONDecodeError) as error:
        print(f"P3_PEER_MEMORY_PROBE_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
