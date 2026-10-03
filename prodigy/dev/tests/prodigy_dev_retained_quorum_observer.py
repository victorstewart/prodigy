#!/usr/bin/env python3
"""Read-only continuity receipt for a sealed legacy three-Brain follower replacement.

The old v19 Brain binds its inter-Brain listener to ReservedPorts::brain (313)
(`legacy19b-source/enums/datacenter.h`) and `peerSocketActive` requires the
fixed, non-closing TCP stream (`legacy19b-source/prodigy/brain/brain.h`).
This observer records the one established master<->witness control connection
from both network namespaces through AF_INET and AF_INET6 NETLINK_SOCK_DIAG.
A matching endpoint cookie at both boundaries proves the kernel socket object
was not closed and recreated; this is bounded evidence, not
instruction-by-instruction tracing.

It opens only procfs/netlink descriptors in a short-lived helper process.  It
never sends a control message to Prodigy, changes a namespace, or mutates a
network object.  It deliberately rejects ambiguous parallel port-313 streams.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import re
import hashlib
import ipaddress
import socket
import struct
import subprocess
import sys
import time
from typing import Any

BRAIN_PORT = 313  # legacy19b-source/enums/datacenter.h: ReservedPorts::brain
TCP_ESTABLISHED = 1
NETLINK_INET_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST = 1
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP_INTR = 0x10
NLMSG_DONE = 3
NLMSG_ERROR = 2
RECEIPT_NAME = "retained-quorum-continuity-before.json"
INET_DIAG_FAILURE_NAME = "retained-quorum-inet-diag-failure.json"


class ObservationError(RuntimeError):
    def __init__(self, message: str, socket_metadata: dict[str, Any] | None = None):
        super().__init__(message)
        self.socket_metadata = socket_metadata


def proc_starttime(pid: int) -> str:
    stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
    return stat.rsplit(") ", 1)[1].split()[19]


def proc_identity(pid: int) -> dict[str, str | int]:
    root = pathlib.Path(f"/proc/{pid}")
    if not root.exists():
        raise ObservationError(f"process {pid} is absent")
    return {
        "pid": pid,
        "starttime": proc_starttime(pid),
        "netns": str((root / "ns/net").readlink()),
        "cgroup": (root / "cgroup").read_text(),
        "exe": str((root / "exe").readlink()),
        "exeSHA256": sha256_file(root / "exe"),
    }


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_cluster_report(path: pathlib.Path) -> list[dict[str, Any]]:
    text = path.read_text()
    blocks = re.findall(r"(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)", text)
    records: list[dict[str, Any]] = []
    for block in blocks:
        identity = re.search(r"(?m)^[ \t]*identity uuid=(0x[0-9a-f]+) .*sshAddress=(\S+)", block)
        lifecycle = re.search(r"(?m)^[ \t]*lifecycle .*currentMaster=(\d)\b", block)
        if identity is None or lifecycle is None:
            raise ObservationError("cluster report has a machine block without identity/currentMaster")
        records.append({"uuid": identity.group(1), "address": identity.group(2), "master": lifecycle.group(1) == "1"})
    if len(records) != 3 or sum(record["master"] for record in records) != 1:
        raise ObservationError("cluster report must describe exactly three members and one master")
    return records


def legacy_basics_log_visible(build_ninja: pathlib.Path) -> bool:
    """Accept only compiler evidence that this Prodigy binary emitted basics_log."""
    text = build_ninja.read_text()
    target = re.search(r"^build CMakeFiles/prodigy\.dir/.*?\.o:.*?(?=^build |\Z)", text, re.M | re.S)
    return target is not None and re.search(r"(?:^|\s)-DBASICS_DEBUG=1(?:\s|$)", target.group(0)) is not None


def native_private4(address: str) -> str:
    return str(struct.unpack("=I", socket.inet_aton(address))[0])


def scan_initial_peer_loss_logs(members: dict[str, Any]) -> None:
    """Reject a pre-existing M/W loss; role/election text is intentionally allowed."""
    peer_private4 = {native_private4(str(member["ipv4"])) for member in members.values()}
    peer_loss = re.compile(r"brainMissing private4=(\d+)|brain queueClose .*?private4=(\d+)|"
                           r"brain reconnect(?: waiter)? abandoning stale transport private4=(\d+)", re.I)
    for index, member in members.items():
        log_path = pathlib.Path(str(member["log"]))
        for match in peer_loss.finditer(log_path.read_text(errors="replace")):
            private4 = next(group for group in match.groups() if group is not None)
            if private4 in peer_private4:
                raise ObservationError(f"initial log records prior master/witness peer loss on machine {index}: {match.group(0)[:400]}")


def setns_to_pid(pid: int) -> None:
    namespace = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.setns(namespace, 0) != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
    finally:
        os.close(namespace)


def canonical_ip(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def dump_established_family(family: int) -> list[dict[str, Any]]:
    if family not in (socket.AF_INET, socket.AF_INET6):
        raise ObservationError(f"unsupported inet_diag family {family}")
    request = struct.pack("=BBBBI16s16sHHIII", family, socket.IPPROTO_TCP, 0, 0,
                          1 << TCP_ESTABLISHED, bytes(16), bytes(16), 0, 0, 0, 0, 0)
    netlink = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_INET_DIAG)
    netlink.settimeout(2.0)
    netlink.bind((0, 0))
    try:
        sequence = 0x51554F52
        header = struct.pack("=IHHII", 16 + len(request), SOCK_DIAG_BY_FAMILY,
                             NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH, sequence, 0)
        netlink.send(header + request)
        records: list[dict[str, Any]] = []
        while True:
            payload, _ancillary, flags, _address = netlink.recvmsg(1 << 16)
            if flags & socket.MSG_TRUNC:
                raise ObservationError("inet_diag netlink response was truncated")
            offset = 0
            while offset + 16 <= len(payload):
                length, kind, message_flags, received_sequence, _pid = struct.unpack_from("=IHHII", payload, offset)
                if length < 16 or offset + length > len(payload):
                    raise ObservationError("malformed inet_diag netlink response")
                body = payload[offset + 16:offset + length]
                offset += (length + 3) & ~3
                if received_sequence != sequence:
                    continue
                if message_flags & NLM_F_DUMP_INTR:
                    raise ObservationError("inet_diag dump was interrupted")
                if kind == NLMSG_DONE:
                    return records
                if kind == NLMSG_ERROR:
                    raise ObservationError("inet_diag returned NLMSG_ERROR")
                if kind != SOCK_DIAG_BY_FAMILY or len(body) < 72 or body[0] != family or body[1] != TCP_ESTABLISHED:
                    continue
                sport, dport = struct.unpack_from("!HH", body, 4)
                address_size = 4 if family == socket.AF_INET else 16
                source = socket.inet_ntop(family, body[8:8 + address_size])
                destination = socket.inet_ntop(family, body[24:24 + address_size])
                cookie_low, cookie_high = struct.unpack_from("=II", body, 44)
                records.append({"family": "AF_INET" if family == socket.AF_INET else "AF_INET6",
                                "source": source, "sourcePort": sport, "destination": destination,
                                "destinationPort": dport, "cookie": f"0x{cookie_high:08x}{cookie_low:08x}"})
            if offset != len(payload):
                raise ObservationError("inet_diag response has trailing partial netlink data")
    finally:
        netlink.close()


def dump_established_sockets() -> list[dict[str, Any]]:
    return dump_established_family(socket.AF_INET) + dump_established_family(socket.AF_INET6)


def dump_namespace(pid: int) -> list[dict[str, Any]]:
    command = [sys.executable, str(pathlib.Path(__file__).resolve()), "--_dump-namespace", str(pid)]
    completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
    if completed.returncode != 0:
        raise ObservationError(f"inet_diag namespace helper failed for pid {pid}: {completed.stderr.strip()}")
    try:
        decoded = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ObservationError(f"inet_diag namespace helper emitted invalid JSON: {error}") from error
    if not isinstance(decoded, list):
        raise ObservationError("inet_diag namespace helper did not return a socket list")
    return decoded


def endpoint_address_set(node: dict[str, Any]) -> set[str]:
    addresses: set[str] = set()
    for field in ("ipv4", "private6", "public6"):
        value = node.get(field)
        if not isinstance(value, str) or not value:
            raise ObservationError(f"manifest node {node.get('index')} lacks {field}")
        try:
            addresses.add(canonical_ip(value))
        except ValueError as error:
            raise ObservationError(f"manifest node {node.get('index')} has invalid {field}: {value}") from error
    return addresses


def canonical_socket(entry: dict[str, Any]) -> dict[str, Any]:
    result = dict(entry)
    result["source"] = canonical_ip(str(entry["source"]))
    result["destination"] = canonical_ip(str(entry["destination"]))
    return result


def exact_pair_sockets(local_pid: int, local_addresses: set[str], remote_addresses: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_sockets = dump_namespace(local_pid)
    try:
        sockets = [canonical_socket(entry) for entry in raw_sockets]
    except (KeyError, ValueError) as error:
        raise ObservationError("inet_diag namespace helper returned an invalid socket record",
                               {"pid": local_pid, "records": raw_sockets}) from error
    matches = [entry for entry in sockets if
               ((entry["source"] in local_addresses and entry["destination"] in remote_addresses) or
                (entry["source"] in remote_addresses and entry["destination"] in local_addresses)) and
               (entry["sourcePort"] == BRAIN_PORT or entry["destinationPort"] == BRAIN_PORT)]
    if len(matches) != 1:
        raise ObservationError(f"expected exactly one established Brain control stream on configured endpoint sets:{BRAIN_PORT}; found {len(matches)}",
                               {"pid": local_pid, "records": raw_sockets})
    if matches[0]["cookie"] in ("0x0000000000000000", "0xffffffffffffffff"):
        raise ObservationError("inet_diag returned an unusable socket cookie", {"pid": local_pid, "records": raw_sockets})
    return matches, raw_sockets


def snapshot(manifest_path: pathlib.Path, report_path: pathlib.Path, selected_index: int,
             legacy_build_ninja: pathlib.Path | None = None) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text())
    nodes = {int(node["index"]): node for node in manifest.get("nodes", [])}
    if set(nodes) != {1, 2, 3} or selected_index not in nodes:
        raise ObservationError("manifest/selected member is not the exact three-member fixture")
    report = parse_cluster_report(report_path)
    report_by_address = {entry["address"]: entry for entry in report}
    if set(report_by_address) != {node["ipv4"] for node in nodes.values()}:
        raise ObservationError("cluster-report members do not exactly match manifest IPv4 identities")
    master_address = next(entry["address"] for entry in report if entry["master"])
    master_index = next(index for index, node in nodes.items() if node["ipv4"] == master_address)
    if master_index == selected_index:
        raise ObservationError("selected replacement member must be a follower")
    witnesses = sorted(set(nodes) - {master_index, selected_index})
    if len(witnesses) != 1:
        raise ObservationError("cannot derive one untouched witness")
    witness_index = witnesses[0]
    master_addresses = endpoint_address_set(nodes[master_index])
    witness_addresses = endpoint_address_set(nodes[witness_index])
    if master_addresses & witness_addresses:
        raise ObservationError("master and witness manifest endpoint address sets overlap")
    handoff_path = report_path.parent / "handoff-before.json"
    if not handoff_path.exists():
        raise ObservationError("handoff-before.json is required to bind original Brain process identities")
    handoff = {int(entry["machineIndex"]): entry for entry in json.loads(handoff_path.read_text())}
    result: dict[str, Any] = {"observedAtNs": time.monotonic_ns(), "brainPort": BRAIN_PORT,
                               "selectedIndex": selected_index, "masterIndex": master_index,
                               "witnessIndex": witness_index, "members": {}}
    for index in (master_index, witness_index):
        node = nodes[index]
        prior = handoff.get(index)
        if prior is None or int(prior.get("parentPID", 0)) <= 0:
            raise ObservationError(f"handoff-before has no Brain parent PID for machine {index}")
        identity = proc_identity(int(prior["parentPID"]))
        required_handoff_identity = {
            "parentStarttime": "starttime", "parentNetworkNamespace": "netns",
            "parentCgroup": "cgroup", "runtimeSHA256": "exeSHA256",
        }
        for handoff_field, observed_field in required_handoff_identity.items():
            expected = prior.get(handoff_field)
            if not expected or str(identity[observed_field]) != str(expected):
                raise ObservationError(f"Brain parent identity mismatch for machine {index}: {handoff_field}")
        result["members"][str(index)] = {"machineIndex": index, "uuid": report_by_address[node["ipv4"]]["uuid"],
                                           "ipv4": node["ipv4"], "process": identity,
                                           "log": node.get("stdoutLog", "")}
    master = result["members"][str(master_index)]
    witness = result["members"][str(witness_index)]
    master_sockets, master_raw_sockets = exact_pair_sockets(int(master["process"]["pid"]), master_addresses, witness_addresses)
    witness_sockets, witness_raw_sockets = exact_pair_sockets(int(witness["process"]["pid"]), witness_addresses, master_addresses)
    master_socket, witness_socket = master_sockets[0], witness_sockets[0]
    if (master_socket["source"], master_socket["sourcePort"], master_socket["destination"], master_socket["destinationPort"]) != \
       (witness_socket["destination"], witness_socket["destinationPort"], witness_socket["source"], witness_socket["sourcePort"]):
        raise ObservationError("master/witness inet_diag tuples are not exact inverses",
                               {"masterPID": master["process"]["pid"], "masterRecords": master_raw_sockets,
                                "witnessPID": witness["process"]["pid"], "witnessRecords": witness_raw_sockets})
    result["masterSocket"] = master_socket
    result["witnessSocket"] = witness_socket
    for member in result["members"].values():
        log_path = pathlib.Path(str(member["log"]))
        if not log_path.exists():
            raise ObservationError(f"Brain log missing for machine {member['machineIndex']}: {log_path}")
        metadata = log_path.stat()
        member["logOffset"] = metadata.st_size
        member["logDevice"] = metadata.st_dev
        member["logInode"] = metadata.st_ino
    if legacy_build_ninja is not None and legacy_basics_log_visible(legacy_build_ninja):
        scan_initial_peer_loss_logs(result["members"])
        result["initialPeerLossLogScan"] = "passed: BASICS_DEBUG=1 compiler evidence"
    elif legacy_build_ninja is not None:
        result["initialPeerLossLogScan"] = "unavailable: legacy Prodigy build does not prove BASICS_DEBUG=1"
    else:
        result["initialPeerLossLogScan"] = "unavailable: no legacy build compiler evidence supplied"
    return result


def forbidden_events(prior: dict[str, Any], current: dict[str, Any]) -> list[str]:
    # old log paths encode only private4 for peer-specific events; its unsigned value
    # is enough to exempt the expected selected-follower loss without exempting M/W.
    selected_address = current.get("selectedIPv4", "")
    # Brain logs the native uint32_t holding network-order address bytes.
    selected_private4 = str(struct.unpack("=I", socket.inet_aton(selected_address))[0]) if selected_address else ""
    peer_event = re.compile(r"brainMissing|brain queueClose|quarantin", re.I)
    role_event = re.compile(r"forfeitMasterStatus|electBrainToMaster|selfElectAsMaster|deriveMasterBrain elect-self|registration master override", re.I)
    found: list[str] = []
    for index, previous_member in prior["members"].items():
        now_member = current["members"].get(index)
        if now_member is None:
            found.append(f"machine {index} disappeared from untouched pair")
            continue
        log_path = pathlib.Path(str(previous_member["log"]))
        offset = int(previous_member["logOffset"])
        metadata = log_path.stat()
        if metadata.st_dev != int(previous_member["logDevice"]) or metadata.st_ino != int(previous_member["logInode"]):
            found.append(f"machine {index} log was replaced")
            continue
        if metadata.st_size < offset:
            found.append(f"machine {index} log truncated")
            continue
        with log_path.open("rb") as stream:
            stream.seek(offset)
            lines = stream.read().decode("utf-8", errors="replace").splitlines()
        for line in lines:
            if role_event.search(line):
                found.append(f"machine {index}: {line[:400]}")
            elif peer_event.search(line):
                if selected_private4 and re.search(r"private4=" + re.escape(selected_private4) + r"\b", line):
                    continue
                found.append(f"machine {index}: {line[:400]}")
    return found


def verify_before_after(prior: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    for key in ("selectedIndex", "masterIndex", "witnessIndex", "brainPort"):
        if prior.get(key) != current.get(key):
            raise ObservationError(f"continuity identity changed: {key}")
    for index, old_member in prior["members"].items():
        member = current["members"].get(index)
        if member is None:
            raise ObservationError(f"untouched pair member {index} disappeared")
        for field in ("uuid", "ipv4"):
            if old_member[field] != member[field]:
                raise ObservationError(f"untouched pair member {index} changed {field}")
        for field in ("pid", "starttime", "netns", "cgroup", "exe", "exeSHA256"):
            if old_member["process"][field] != member["process"][field]:
                raise ObservationError(f"untouched pair member {index} changed process {field}")
    for socket_name in ("masterSocket", "witnessSocket"):
        old_socket, new_socket = prior[socket_name], current[socket_name]
        if old_socket != new_socket:
            raise ObservationError(f"{socket_name} tuple or SO_COOKIE changed")
    events = forbidden_events(prior, current)
    if events:
        raise ObservationError("relevant untouched-pair lifecycle event(s): " + " | ".join(events))
    if prior.get("peerMemory") is not None or current.get("peerMemory") is not None:
        if prior.get("peerMemory") is None or current.get("peerMemory") is None:
            raise ObservationError("peer eligibility observation missing at one boundary")
        if prior["peerMemory"]["layoutSHA256"] != current["peerMemory"]["layoutSHA256"]:
            raise ObservationError("peer eligibility layout changed")
        for index, member in prior["members"].items():
            other = next(value for key, value in prior["members"].items() if key != index)
            views = []
            for boundary in (prior, current):
                process = next(value for value in boundary["peerMemory"]["snapshots"]
                               if value["pid"] == member["process"]["pid"])
                views.append(next(value for value in process["views"]
                                  if int(value["uuid"], 16) == int(other["uuid"], 16)))
            if views[0] != views[1]:
                raise ObservationError("surviving peer eligibility or transport incarnation changed")
        return {"result": "bounded-peer-eligibility-and-socket-continuity", "limits": [
            "Exact three-member frozen profile: both surviving peers were eligible at the observed boundaries and retained their transport incarnations and established socket identities.",
            "Source invariants exclude restoring a lost peer without a new transport; unsynchronised double memory reads are bounded evidence, not an instruction-by-instruction trace.",
            "No topology, credential, retirement or privileged external mutation is permitted. Traffic, application durability and leadership-commit availability remain separate checks."
        ]}
    return {"result": "bounded-socket-continuity-evidence", "limits": [
        "This establishes the same established kernel socket objects at both boundaries, not initial BrainView eligibility or a quorum history.",
        "It assumes the sealed profile: no topology, credential, retirement, or external privileged TCP-repair mutation.",
        "It does not substitute for traffic, application, or leadership-commit availability evidence."
    ]}


def write_inet_diag_failure(evidence_root: pathlib.Path | None, error: Exception) -> None:
    if evidence_root is None or not isinstance(error, ObservationError) or error.socket_metadata is None:
        return
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / INET_DIAG_FAILURE_NAME).write_text(
        json.dumps(error.socket_metadata, indent=2, sort_keys=True) + "\n")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--_dump-namespace", type=int, metavar="PID")
    parser.add_argument("--phase", choices=("before", "after"))
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--cluster-report", type=pathlib.Path)
    parser.add_argument("--selected-index", type=int)
    parser.add_argument("--evidence-root", type=pathlib.Path)
    parser.add_argument("--legacy-build-ninja", type=pathlib.Path,
                        help="optional exact legacy build.ninja; enables one-time initial loss scan only with -DBASICS_DEBUG=1")
    parser.add_argument("--peer-memory-layout", type=pathlib.Path,
                        help="optional exact-ELF compiler layout for read-only peer eligibility observation")
    arguments = parser.parse_args(argv)
    if arguments._dump_namespace is not None:
        try:
            setns_to_pid(arguments._dump_namespace)
            print(json.dumps(dump_established_sockets(), sort_keys=True))
            return 0
        except Exception as error:  # helper error reaches parent as an explicit rejection
            print(str(error), file=sys.stderr)
            return 2
    if not all((arguments.phase, arguments.manifest, arguments.cluster_report, arguments.selected_index, arguments.evidence_root)):
        parser.error("--phase, --manifest, --cluster-report, --selected-index and --evidence-root are required")
    try:
        current = snapshot(arguments.manifest, arguments.cluster_report, arguments.selected_index,
                           arguments.legacy_build_ninja)
        manifest_nodes = {int(node["index"]): node for node in json.loads(arguments.manifest.read_text())["nodes"]}
        current["selectedIPv4"] = manifest_nodes[arguments.selected_index]["ipv4"]
        if arguments.peer_memory_layout:
            from prodigy_dev_retained_peer_memory import observe, Reject
            report = {record["address"]: record for record in parse_cluster_report(arguments.cluster_report)}
            members = [{"pid": node["pid"], "uuid": report[node["ipv4"]]["uuid"],
                        "private4": struct.unpack("=I", socket.inet_aton(node["ipv4"]))[0]}
                       for node in manifest_nodes.values()]
            try:
                current["peerMemory"] = observe(arguments.peer_memory_layout, members,
                    [member["process"]["pid"] for member in current["members"].values()])
            except Reject as error:
                raise ObservationError("peer eligibility: " + str(error)) from error
        receipt = arguments.evidence_root / RECEIPT_NAME
        if arguments.phase == "before":
            arguments.evidence_root.mkdir(parents=True, exist_ok=True)
            if receipt.exists():
                raise ObservationError(f"refusing to overwrite existing before receipt: {receipt}")
            receipt.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
            print(f"RETAINED_QUORUM_OBSERVER_BEFORE master={current['masterIndex']} witness={current['witnessIndex']} receipt={receipt}")
            return 0
        prior = json.loads(receipt.read_text())
        result = verify_before_after(prior, current)
        after = dict(current)
        after.update(result)
        after_path = arguments.evidence_root / "retained-quorum-continuity-after.json"
        after_path.write_text(json.dumps(after, indent=2, sort_keys=True) + "\n")
        print(f"RETAINED_QUORUM_OBSERVER_AFTER PASS master={current['masterIndex']} witness={current['witnessIndex']} receipt={after_path}")
        return 0
    except (OSError, ValueError, KeyError, ObservationError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        write_inet_diag_failure(arguments.evidence_root, error)
        print(f"RETAINED_QUORUM_OBSERVER_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
