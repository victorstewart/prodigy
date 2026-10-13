#!/usr/bin/env python3
"""Own one disposable KVM guest and only its overlay, OVMF vars, and QEMU PID."""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from typing import Sequence

MARKER = "/run/prodigy-disposable-linux"
MARKER_CONTENT = "prodigy-disposable-linux-v1"


class BoundaryError(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise BoundaryError(message)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe_path(path: Path, label: str, readonly: bool = False) -> Path:
    require(not path.is_symlink(), f"{label} must not be a symlink")
    resolved = path.resolve(strict=True)
    mode = resolved.stat().st_mode
    require(stat.S_ISREG(mode), f"{label} must be a regular file")
    require("," not in str(resolved) and "\n" not in str(resolved) and "\r" not in str(resolved), f"{label} path is unsafe for QEMU")
    if readonly:
        require(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) == 0, f"{label} must be read-only")
    return resolved


def safe_directory(path: Path, label: str) -> Path:
    require("," not in str(path) and "\n" not in str(path) and "\r" not in str(path), f"{label} path is unsafe for QEMU")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not path.is_symlink(), f"{label} must not be a symlink")
    resolved = path.resolve(strict=True)
    require(resolved.is_dir(), f"{label} must be a directory")
    require("," not in str(resolved) and "\n" not in str(resolved) and "\r" not in str(resolved), f"{label} path is unsafe for QEMU")
    return resolved


def pinned(path: Path, expected: str, label: str, readonly: bool = False) -> Path:
    require(re.fullmatch(r"[0-9a-fA-F]{64}", expected) is not None, f"{label} SHA-256 must be hex")
    resolved = safe_path(path, label, readonly)
    require(digest(resolved).lower() == expected.lower(), f"{label} SHA-256 mismatch")
    return resolved


def proc_starttime(pid: int) -> str | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    except (FileNotFoundError, IndexError):
        return None
    return fields[19] if len(fields) > 19 else None


def process_is_owned(pid: int, starttime: str, overlay: Path) -> bool:
    if proc_starttime(pid) != starttime:
        return False
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except FileNotFoundError:
        return False
    return "qemu-system" in command and str(overlay) in command


def check_prerequisites(qemu: str, qemu_img: str) -> None:
    require(platform.system() == "Linux", "the KVM boundary launcher runs on Linux only")
    require(Path("/dev/kvm").is_char_device() and os.access("/dev/kvm", os.R_OK | os.W_OK), "/dev/kvm must be readable and writable")
    require(shutil.which(qemu) is not None and shutil.which(qemu_img) is not None, "QEMU and qemu-img are required")
    probe = subprocess.run([qemu, "-accel", "help"], text=True, capture_output=True, check=False)
    require(probe.returncode == 0 and re.search(r"(^|\s)kvm(\s|$)", probe.stdout) is not None, "QEMU does not advertise KVM")


def check_backing_chain(qemu_img: str, base: Path) -> None:
    result = subprocess.run([qemu_img, "info", "--output=json", str(base)], text=True, capture_output=True, check=False)
    require(result.returncode == 0, "qemu-img could not inspect base image")
    info = json.loads(result.stdout)
    require(not info.get("backing-filename") and not info.get("full-backing-filename"), "base image backing chain is not allowed")


def choose_loopback_port(port: int) -> None:
    require(1024 <= port <= 65535, "--ssh-port must be in 1024..65535")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", port))


def persistent_network(args: argparse.Namespace) -> dict[str, list[str]]:
    net = f"user,id=guestnet,hostfwd=tcp:127.0.0.1:{args.ssh_port}-:22"
    if args.guest_egress == "isolated":
        net = net.replace("user,", "user,restrict=on,")
    network = {"netdevs": [net], "devices": [f"virtio-net-pci,netdev=guestnet,mac={args.wan_mac}"]}
    if args.lan_mcast is not None:
        network["netdevs"].append(f"socket,id=clusterlan,mcast={args.lan_mcast},localaddr={args.lan_local_address}")
        network["devices"].append(f"virtio-net-pci,netdev=clusterlan,mac={args.lan_mac}")
    elif args.lan_udp_link:
        for index, (local, remote) in enumerate(args.lan_udp_link):
            network["netdevs"].append(f"socket,id=clusterlink{index},udp={remote},localaddr={local}")
            network["netdevs"].append(f"hubport,id=clusterhub{index},hubid=0,netdev=clusterlink{index}")
        network["netdevs"].append("hubport,id=clusterlan,hubid=0")
        network["devices"].append(f"virtio-net-pci,netdev=clusterlan,mac={args.lan_mac}")
    return network


def validate_persistent_network(command: list[str], expected: dict[str, object]) -> None:
    expected_netdevs, expected_devices = expected.get("netdevs"), expected.get("devices")
    require(isinstance(expected_netdevs, list) and isinstance(expected_devices, list) and
            all(isinstance(value, str) for value in expected_netdevs + expected_devices),
            "persistent network expectation is invalid")
    netdevs, devices = [], []
    index = 0
    while index < len(command):
        option = command[index]
        require(not (option == "-net" or option.startswith("-net=") or option == "-nic" or option.startswith("-nic=")),
                "legacy or implicit QEMU host networking is forbidden")
        if option in ("-netdev", "-device"):
            require(index + 1 < len(command), f"{option} lacks its value")
            value = command[index + 1]
            if option == "-netdev":
                require(not any(forbidden in value for forbidden in ("tap", "bridge", "vhost", "fd=", "helper=", "script=", "downscript=")),
                        "host-backed QEMU network mode is forbidden")
                netdevs.append(value)
            elif "netdev=" in value:
                devices.append(value)
            index += 2
        else:
            index += 1
    require(sorted(netdevs) == sorted(expected_netdevs), "QEMU netdevs differ from exact boundary network")
    require(sorted(devices) == sorted(expected_devices), "QEMU network devices differ from exact boundary network")


def qemu_command(args: argparse.Namespace, overlay: Path, vars_copy: Path, qmp_socket: Path | None = None) -> list[str]:
    network = persistent_network(args)
    command = [args.qemu, "-accel", "kvm", "-machine", "q35", "-cpu", "host", "-smp", str(args.cpus), "-m", str(args.memory_mb), "-display", "none", "-nodefaults", "-uuid", str(args.guest_uuid), "-smbios", f"type=1,uuid={args.guest_uuid}", "-drive", f"if=pflash,format=raw,readonly=on,file={args.ovmf_code}", "-drive", f"if=pflash,format=raw,file={vars_copy}", "-serial", f"file:{args.evidence_dir / 'serial.log'}", "-drive", f"file={overlay},if=virtio,format=qcow2,cache=none", "-netdev", network["netdevs"][0], "-device", network["devices"][0], "-pidfile", str(args.evidence_dir / "qemu.pid")]
    for netdev in network["netdevs"][1:]:
        command += ["-netdev", netdev]
    for device in network["devices"][1:]:
        command += ["-device", device]
    if qmp_socket is not None: command += ["-qmp", f"unix:{qmp_socket},server=on,wait=off"]
    return command + (["-drive", f"file={args.cidata},if=virtio,media=cdrom,readonly=on,format={args.cidata_format}"] if args.cidata else []) + (["-kernel", str(args.kernel), "-initrd", str(args.initrd), "-append", args.kernel_append] if args.kernel else [])


def safe_state_file(path: Path) -> Path:
    require(path.is_absolute(), "state path must be absolute")
    require(not path.exists() or not path.is_symlink(), "state path must not be a symlink")
    parent = path.parent.resolve(strict=True)
    require(parent.is_dir() and not parent.is_symlink(), "state parent must be a real directory")
    return parent / path.name


def command_matches(pid: int, starttime: str, command: list[str]) -> bool:
    if proc_starttime(pid) != starttime: return False
    try: actual = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
    except FileNotFoundError: return False
    return actual == [item.encode() for item in command]


def write_persistent_state(path: Path, state: dict[str, object]) -> None:
    require(path.parent.stat().st_mode & 0o022 == 0, "state parent must not be group/other writable")
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(state, output, sort_keys=True); output.write("\n"); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path); os.chmod(path, 0o600)


def load_persistent_state(path: Path, task_id: str) -> dict[str, object]:
    path = safe_state_file(path)
    require(path.is_file() and not path.is_symlink(), "persistent state is absent")
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, "persistent state must be mode 0600")
    state = json.loads(path.read_text())
    required = {"taskID", "qemuPID", "qemuStarttime", "qemuCommand", "overlay", "ovmfVars", "guestUUID", "machineID", "qmpSocket", "network", "boundaryVerification"}
    require(required <= state.keys() and state["taskID"] == task_id, "persistent state task identity mismatch")
    require(isinstance(state["qemuCommand"], list) and all(isinstance(item, str) for item in state["qemuCommand"]), "persistent QEMU command is invalid")
    require(isinstance(state["network"], dict), "persistent network state is invalid")
    validate_persistent_network(state["qemuCommand"], state["network"])
    require(isinstance(state["boundaryVerification"], dict), "persistent guest verification state is invalid")
    return state


def lifecycle_arguments(argv: Sequence[str]) -> tuple[str, Path, str, list[str]]:
    require(len(argv) >= 5 and argv[1:5] == ["--state", argv[2], "--task-id", argv[4]], "lifecycle usage requires OPERATION --state PATH --task-id ID")
    operation, state, task_id = argv[0], safe_state_file(Path(argv[2])), argv[4]
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", task_id) is not None, "task ID is invalid")
    return operation, state, task_id, list(argv[5:])


@contextlib.contextmanager
def task_state_lock(state_path: Path):
    """Serialize one task state without passing the lock to QEMU or the guest."""
    lock_path = state_path.with_name(state_path.name + ".lock")
    require(not lock_path.exists() or not lock_path.is_symlink(), "persistent state lock must not be a symlink")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        lock_state = os.fstat(fd)
        require(stat.S_ISREG(lock_state.st_mode) and lock_state.st_uid == os.geteuid() and
                stat.S_IMODE(lock_state.st_mode) == 0o600,
                "persistent state lock must be a private regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BoundaryError("another lifecycle operation owns this task state") from error
        yield
    finally:
        os.close(fd)


def qmp_quit(socket_path: str) -> None:
    require(Path(socket_path).is_socket(), "QMP socket is absent")
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5); client.connect(socket_path); client.recv(65536)
        client.sendall(b'{"execute":"qmp_capabilities"}' + bytes((13, 10))); client.recv(65536)
        client.sendall(b'{"execute":"quit"}' + bytes((13, 10)))


def stop_persistent_qemu(record: dict[str, object], purpose: str) -> None:
    """Stop only the exact sealed QEMU process, with bounded signal fallback."""
    pid = int(record["qemuPID"])
    starttime = str(record["qemuStarttime"])
    command = record["qemuCommand"]
    require(command_matches(pid, starttime, command), "exact QEMU process identity mismatch")
    qmp_quit(str(record["qmpSocket"]))
    for _ in range(100):
        if proc_starttime(pid) is None:
            return
        time.sleep(.1)
    require(command_matches(pid, starttime, command),
            f"exact QEMU process identity changed during {purpose}")
    os.kill(pid, signal.SIGTERM)
    for _ in range(100):
        if proc_starttime(pid) is None:
            return
        time.sleep(.1)
    require(command_matches(pid, starttime, command),
            f"exact QEMU process identity changed during {purpose}")
    os.kill(pid, signal.SIGKILL)
    for _ in range(100):
        if proc_starttime(pid) is None:
            return
        time.sleep(.1)
    require(proc_starttime(pid) is None, f"QEMU did not exit during {purpose}")


def qemu_pidfile(command: list[str]) -> Path:
    require("-pidfile" in command, "persistent QEMU command has no pidfile")
    index = command.index("-pidfile")
    require(index + 1 < len(command), "persistent QEMU pidfile argument is incomplete")
    return Path(command[index + 1])


def verify_persistent_guest(record: dict[str, object], pid: int, starttime: str) -> None:
    verification = record["boundaryVerification"]
    required = {"knownHosts", "sshPrivateKey", "sshUser", "sshPort", "bootTimeout", "guestUUID", "machineID", "hostMachineID"}
    require(isinstance(verification, dict) and required <= verification.keys(), "persistent guest verification state is incomplete")
    require(isinstance(verification["sshPort"], int) and isinstance(verification["bootTimeout"], int) and
            isinstance(verification["guestUUID"], str) and isinstance(verification["machineID"], str) and
            isinstance(verification["hostMachineID"], str) and
            all(isinstance(verification[key], str) for key in ("knownHosts", "sshPrivateKey", "sshUser")),
            "persistent guest verification state is malformed")
    # Early persistent-boundary records predate these two presentation/executor
    # fields.  Mothership's launch contract used argparse's SSH default; retain
    # that replay while recording explicit values for every new boundary.
    ssh = verification.get("sshCommand", "ssh")
    evidence_dir = verification.get("evidenceDir", ".")
    require(isinstance(ssh, str) and ssh and isinstance(evidence_dir, str) and evidence_dir,
            "persistent guest verification executor state is malformed")
    args = argparse.Namespace(known_hosts=Path(verification["knownHosts"]), ssh_private_key=Path(verification["sshPrivateKey"]),
                              ssh_user=verification["sshUser"], ssh_port=verification["sshPort"],
                              boot_timeout=verification["bootTimeout"], guest_uuid=uuid.UUID(verification["guestUUID"]),
                              expected_machine_id=verification["machineID"], ssh=ssh,
                              evidence_dir=Path(evidence_dir))
    class PersistentProcess:
        returncode = 1
        def poll(self) -> int | None:
            return None if command_matches(pid, starttime, record["qemuCommand"]) else self.returncode
    wait_for_guest(args, PersistentProcess())
    verify_guest_boundary(args, verification["hostMachineID"])


def completed_cold_reboot(record: dict[str, object], operation_id: str) -> dict[str, object] | None:
    receipt = record.get("lastColdReboot")
    if not isinstance(receipt, dict) or receipt.get("operationID") != operation_id or receipt.get("completed") is not True:
        return None
    required = {"operationID", "beforePID", "beforeStarttime", "afterPID", "afterStarttime",
                "startedAtMonotonicMs", "completedAtMonotonicMs", "completed"}
    require(required <= receipt.keys(), "persistent cold reboot receipt is malformed")
    require(isinstance(receipt["startedAtMonotonicMs"], int) and isinstance(receipt["completedAtMonotonicMs"], int) and
            receipt["completedAtMonotonicMs"] > receipt["startedAtMonotonicMs"],
            "persistent cold reboot receipt timestamps are not strictly ordered")
    return receipt


def preserve_cold_reboot_after_session_loss() -> None:
    """Keep the outer-host owner alive when rebooting its SSH caller's VM."""
    require(hasattr(signal, "SIGHUP"), "cold reboot requires POSIX session hangup handling")
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


def _lifecycle_main(argv: Sequence[str]) -> int:
    operation, state_path, task_id, remainder = lifecycle_arguments(argv)
    if operation == "launch":
        require(remainder and remainder[0] == "--", "launch requires normal boundary arguments after --")
        args = parse_args(remainder[1:] + ["--", "true"])
        check_prerequisites(args.qemu, args.qemu_img)
        args.base_image = pinned(args.base_image, args.base_sha256, "base image", True); check_backing_chain(args.qemu_img, args.base_image)
        args.ovmf_code = pinned(args.ovmf_code, args.ovmf_code_sha256, "OVMF code", True); args.ovmf_vars = pinned(args.ovmf_vars, args.ovmf_vars_sha256, "OVMF vars", True)
        args.known_hosts = safe_path(args.known_hosts, "known hosts"); args.ssh_private_key = safe_path(args.ssh_private_key, "SSH private key")
        if args.cidata: args.cidata = safe_path(args.cidata, "cidata", True)
        if args.kernel: args.kernel = pinned(args.kernel, args.kernel_sha256, "kernel", True); args.initrd = pinned(args.initrd, args.initrd_sha256, "initrd", True)
        host_machine_id = Path("/etc/machine-id").read_text().strip(); require(args.expected_machine_id != host_machine_id, "expected machine ID must differ from host")
        choose_loopback_port(args.ssh_port); args.work_dir = safe_directory(args.work_dir, "work directory"); args.evidence_dir = safe_directory(args.evidence_dir, "evidence directory")
        require(not state_path.exists(), "persistent state already exists")
        overlay = args.work_dir / f"prodigy-kvm-{task_id}.qcow2"; vars_copy = args.work_dir / f"prodigy-kvm-vars-{task_id}.fd"; qmp_socket = args.work_dir / f"prodigy-kvm-{task_id}.qmp"
        require(not overlay.exists() and not vars_copy.exists() and not qmp_socket.exists(), "persistent task resource already exists")
        shutil.copyfile(args.ovmf_vars, vars_copy); os.chmod(vars_copy, 0o600); create_overlay(args, overlay)
        qemu_log = (args.evidence_dir / "qemu.log").open("w", encoding="utf-8")
        network = persistent_network(args)
        command = qemu_command(args, overlay, vars_copy, qmp_socket); validate_persistent_network(command, network)
        process = subprocess.Popen(command, text=True, stdout=subprocess.DEVNULL, stderr=qemu_log,
                                   start_new_session=True)
        starttime = proc_starttime(process.pid)
        try:
            require(starttime is not None, "could not record QEMU PID start time"); wait_for_guest(args, process); verify_guest_boundary(args, host_machine_id)
            require(command_matches(process.pid, starttime, command), "QEMU command identity changed before state seal")
            verification = {"knownHosts": str(args.known_hosts), "sshPrivateKey": str(args.ssh_private_key), "sshUser": args.ssh_user, "sshPort": args.ssh_port, "bootTimeout": args.boot_timeout, "guestUUID": str(args.guest_uuid), "machineID": args.expected_machine_id, "hostMachineID": host_machine_id, "sshCommand": args.ssh, "evidenceDir": str(args.evidence_dir)}
            write_persistent_state(state_path, {"taskID": task_id, "qemuPID": process.pid, "qemuStarttime": starttime, "qemuCommand": command, "overlay": str(overlay), "ovmfVars": str(vars_copy), "guestUUID": str(args.guest_uuid), "machineID": args.expected_machine_id, "qmpSocket": str(qmp_socket), "network": network, "boundaryVerification": verification})
        except Exception:
            cleanup_qemu(process, starttime, overlay, vars_copy, {}); raise
        finally: qemu_log.close()
        return 0
    operation_id = None
    if operation == "cold-reboot":
        require(len(remainder) == 2 and remainder[0] == "--operation-id" and
                re.fullmatch(r"[0-9a-f]{32}", remainder[1]) is not None,
                "cold-reboot requires one canonical operation ID")
        operation_id = remainder[1]
        preserve_cold_reboot_after_session_loss()
    else:
        require(not remainder, f"{operation} does not accept extra arguments")
    if operation == "remove" and not state_path.exists():
        return 0
    record = load_persistent_state(state_path, task_id); pid = int(record["qemuPID"]); command = record["qemuCommand"]
    if operation == "query":
        require(command_matches(pid, record["qemuStarttime"], command), "exact QEMU process identity mismatch")
        print(json.dumps(record, sort_keys=True)); return 0
    if operation == "cold-reboot":
        assert operation_id is not None
        completed = completed_cold_reboot(record, operation_id)
        if completed is not None:
            require(command_matches(pid, record["qemuStarttime"], command), "completed cold reboot no longer owns its exact QEMU process")
            verify_persistent_guest(record, pid, record["qemuStarttime"])
            print(json.dumps(completed, sort_keys=True)); return 0
        prior = record.get("lastColdReboot")
        require(prior is None or (isinstance(prior, dict) and prior.get("operationID") == operation_id and
                prior.get("completed") is False), "another cold reboot operation already owns this boundary")
        if prior is None:
            require(command_matches(pid, record["qemuStarttime"], command), "exact QEMU process identity mismatch")
            prior = {"operationID": operation_id, "beforePID": pid, "beforeStarttime": record["qemuStarttime"],
                     "startedAtMonotonicMs": time.monotonic_ns() // 1_000_000, "completed": False}
            record["lastColdReboot"] = prior; write_persistent_state(state_path, record)
        if command_matches(pid, record["qemuStarttime"], command):
            stop_persistent_qemu(record, "cold reboot")
        replacement_pid = None
        pidfile = qemu_pidfile(command)
        if pidfile.is_file():
            try: candidate = int(pidfile.read_text().strip())
            except ValueError: candidate = 0
            if candidate > 0 and command_matches(candidate, proc_starttime(candidate) or "", command): replacement_pid = candidate
        if replacement_pid is None:
            Path(record["qmpSocket"]).unlink(missing_ok=True)
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            replacement_pid = process.pid
        starttime = proc_starttime(replacement_pid)
        require(starttime is not None and command_matches(replacement_pid, starttime, command), "replacement QEMU identity mismatch")
        verify_persistent_guest(record, replacement_pid, starttime)
        completed_at = max(time.monotonic_ns() // 1_000_000, prior["startedAtMonotonicMs"] + 1)
        receipt = dict(prior); receipt.update(beforeIdentity={"pid": prior["beforePID"], "starttime": prior["beforeStarttime"]},
                                              afterIdentity={"pid": replacement_pid, "starttime": starttime},
                                              afterPID=replacement_pid, afterStarttime=starttime,
                                              completedAtMonotonicMs=completed_at,
                                              completed=True)
        record["qemuPID"], record["qemuStarttime"], record["lastColdReboot"] = replacement_pid, starttime, receipt
        write_persistent_state(state_path, record); print(json.dumps(receipt, sort_keys=True)); return 0
    if operation == "remove":
        if command_matches(pid, record["qemuStarttime"], command):
            stop_persistent_qemu(record, "exact cleanup")
        elif proc_starttime(pid) is not None: raise BoundaryError("exact QEMU process identity mismatch")
        for owned in (Path(record["overlay"]), Path(record["ovmfVars"]), Path(record["qmpSocket"])): owned.unlink(missing_ok=True)
        state_path.unlink(missing_ok=True); return 0
    raise BoundaryError("unknown lifecycle operation")


def lifecycle_main(argv: Sequence[str]) -> int:
    _, state_path, _, _ = lifecycle_arguments(argv)
    with task_state_lock(state_path):
        return _lifecycle_main(argv)


def ssh_base(args: argparse.Namespace) -> list[str]:
    return [args.ssh, "-i", str(args.ssh_private_key), "-p", str(args.ssh_port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={args.known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", f"{args.ssh_user}@127.0.0.1"]


def guest_run(args: argparse.Namespace, script: str, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(ssh_base(args) + [shlex.join(["sh", "-ceu", script])], text=True, capture_output=True, timeout=timeout, check=False)


def wait_for_guest(args: argparse.Namespace, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + args.boot_timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise BoundaryError(f"QEMU exited during boot with status {process.returncode}; see {args.evidence_dir / 'qemu.log'}")
        try:
            if guest_run(args, "true", 7).returncode == 0:
                return
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is not None:
                raise BoundaryError(f"QEMU exited during boot with status {process.returncode}; see {args.evidence_dir / 'qemu.log'}")
        time.sleep(1)
    raise BoundaryError("guest SSH did not become ready before --boot-timeout")


def verify_guest_boundary(args: argparse.Namespace, host_machine_id: str) -> None:
    script = "expected_dmi=" + shlex.quote(args.guest_uuid.hex.upper()) + "\nexpected_machine=" + shlex.quote(args.expected_machine_id) + "\nhost_machine=" + shlex.quote(host_machine_id) + "\ntest \"$(id -u)\" = 0\ntest \"$(systemd-detect-virt --vm)\" = kvm\nmachine=$(tr -d '\\n' </etc/machine-id)\ntest \"$machine\" = \"$expected_machine\"\ntest \"$machine\" != \"$host_machine\"\ndmi=$(tr -d '-' </sys/class/dmi/id/product_uuid | tr '[:lower:]' '[:upper:]')\ntest \"$dmi\" = \"$expected_dmi\"\nkernel=$(uname -r); test \"${kernel%%.*}\" -ge 7\ninstall -o root -g root -m 0600 /dev/null " + MARKER + "\nprintf '%s\\n' " + shlex.quote(MARKER_CONTENT) + " >" + MARKER + "\n"
    require(guest_run(args, script, 30).returncode == 0, "guest failed KVM, UUID, machine identity, kernel, or marker verification")


def run_guest_command(args: argparse.Namespace) -> int:
    command = base64.b64encode(json.dumps(args.guest_command).encode()).decode()
    script = "test \"$(cat " + MARKER + ")\" = " + shlex.quote(MARKER_CONTENT) + "\nexec python3 -c 'import base64,json,os,sys;a=json.loads(base64.b64decode(sys.argv[1]));os.execvp(a[0],a)' " + command
    result = guest_run(args, script, args.runtime_timeout)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


def cleanup_qemu(process: subprocess.Popen[str] | None, starttime: str | None, overlay: Path, vars_copy: Path, receipt: dict[str, object]) -> bool:
    if process is not None:
        if process.poll() is None:
            if starttime is None or not process_is_owned(process.pid, starttime, overlay):
                receipt.update(cleanupSuccess=False, cleanupFailure="QEMU identity mismatch", qemuExited=False, overlayRemoved=False)
                return False
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                if not process_is_owned(process.pid, starttime, overlay):
                    receipt.update(cleanupSuccess=False, cleanupFailure="QEMU identity changed during cleanup", qemuExited=False, overlayRemoved=False)
                    return False
                process.kill()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    receipt.update(cleanupSuccess=False, cleanupFailure="QEMU did not exit", qemuExited=False, overlayRemoved=False)
                    return False
        if process.poll() is None:
            receipt.update(cleanupSuccess=False, cleanupFailure="QEMU remained alive", qemuExited=False, overlayRemoved=False)
            return False
    receipt["qemuExited"] = True
    for owned in (overlay, vars_copy):
        if owned.exists():
            owned.unlink()
    receipt.update(cleanupSuccess=True, overlayRemoved=not overlay.exists(), varsRemoved=not vars_copy.exists())
    return True


def create_overlay(args: argparse.Namespace, overlay: Path) -> None:
    subprocess.run([args.qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(args.base_image), str(overlay)],
                   check=True, text=True, capture_output=True)
    if args.disk_size_gb is not None:
        subprocess.run([args.qemu_img, "resize", str(overlay), f"{args.disk_size_gb}G"],
                       check=True, text=True, capture_output=True)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-image", type=Path, required=True); p.add_argument("--base-sha256", required=True)
    p.add_argument("--cidata", type=Path); p.add_argument("--cidata-format", choices=("raw", "qcow2"), default="raw")
    p.add_argument("--kernel", type=Path); p.add_argument("--kernel-sha256"); p.add_argument("--initrd", type=Path); p.add_argument("--initrd-sha256"); p.add_argument("--kernel-append")
    p.add_argument("--ovmf-code", type=Path, required=True); p.add_argument("--ovmf-code-sha256", required=True); p.add_argument("--ovmf-vars", type=Path, required=True); p.add_argument("--ovmf-vars-sha256", required=True)
    p.add_argument("--guest-uuid", required=True); p.add_argument("--expected-machine-id", required=True)
    p.add_argument("--known-hosts", type=Path, required=True); p.add_argument("--ssh-private-key", type=Path, required=True); p.add_argument("--ssh-user", default="root"); p.add_argument("--ssh-port", type=int, required=True)
    p.add_argument("--work-dir", type=Path, required=True); p.add_argument("--evidence-dir", type=Path, required=True); p.add_argument("--guest-egress", choices=("isolated", "wan"), default="isolated")
    p.add_argument("--wan-mac"); p.add_argument("--lan-mcast"); p.add_argument("--lan-local-address"); p.add_argument("--lan-udp-link", action="append", default=[]); p.add_argument("--lan-mac")
    p.add_argument("--disk-size-gb", type=int)
    p.add_argument("--cpus", type=int, default=4); p.add_argument("--memory-mb", type=int, default=8192); p.add_argument("--boot-timeout", type=int, default=180); p.add_argument("--runtime-timeout", type=int, default=3600); p.add_argument("--qemu", default="qemu-system-x86_64"); p.add_argument("--qemu-img", default="qemu-img"); p.add_argument("--ssh", default="ssh"); p.add_argument("guest_command", nargs=argparse.REMAINDER)
    a = p.parse_args(argv); require(a.guest_command and a.guest_command[0] == "--", "supply command after --"); a.guest_command = a.guest_command[1:]; require(a.guest_command, "guest command is required")
    require(a.cpus in range(1, 17) and a.memory_mb in range(1024, 65537), "CPU or memory bound is invalid"); require(a.boot_timeout in range(1, 1801) and a.runtime_timeout in range(1, 14401), "timeout bound is invalid")
    require(a.disk_size_gb is None or a.disk_size_gb in range(2, 129), "--disk-size-gb must be in 2..128")
    require((a.lan_mcast is None) == (a.lan_local_address is None),
            "LAN multicast address and local address are an atomic set")
    require(not (a.lan_mcast is not None and a.lan_udp_link),
            "LAN multicast and UDP-link modes are mutually exclusive")
    require(not a.lan_udp_link or a.lan_mac is not None,
            "LAN UDP links and MAC are an atomic set")
    require(not (a.lan_mcast is not None and a.lan_mac is None),
            "LAN multicast address, local address, and MAC are an atomic set")
    require(not (a.lan_mcast is None and not a.lan_udp_link and a.lan_mac is not None),
            "--lan-mac requires one LAN mode")
    if a.lan_mcast is not None:
        match = re.fullmatch(r"([^:]+):([0-9]{1,5})", a.lan_mcast)
        require(match is not None, "--lan-mcast must be IPv4:port")
        try:
            multicast = ipaddress.IPv4Address(match.group(1))
            local = ipaddress.IPv4Address(a.lan_local_address)
        except ipaddress.AddressValueError as error:
            raise BoundaryError("LAN multicast and local addresses must be canonical IPv4") from error
        require(multicast.is_multicast and 1024 <= int(match.group(2)) <= 65535,
                "--lan-mcast must use an IPv4 multicast address and unprivileged port")
        require(not (local.is_unspecified or local.is_multicast or local.is_loopback or
                     local.is_link_local or local.is_reserved) and int(local) != 0xFFFFFFFF,
                "--lan-local-address must be one exact unicast IPv4 address")
        require(re.fullmatch(r"02(?::[0-9a-f]{2}){5}", a.lan_mac) is not None,
                "--lan-mac must be one lower-case locally administered unicast MAC")
    if a.lan_udp_link:
        require(len(a.lan_udp_link) <= 4, "at most four --lan-udp-link values are allowed")
        links: list[tuple[str, str]] = []
        local_endpoints: set[str] = set()
        remote_endpoints: set[str] = set()
        for value in a.lan_udp_link:
            match = re.fullmatch(r"([^:=]+):([0-9]{1,5})=([^:=]+):([0-9]{1,5})", value)
            require(match is not None, "--lan-udp-link must be LOCAL_IPV4:LOCAL_PORT=REMOTE_IPV4:REMOTE_PORT")
            local_ip, local_port, remote_ip, remote_port = match.groups()
            try:
                local = ipaddress.IPv4Address(local_ip)
                remote = ipaddress.IPv4Address(remote_ip)
            except ipaddress.AddressValueError as error:
                raise BoundaryError("LAN UDP link endpoints must be canonical IPv4") from error
            require(str(local) == local_ip and str(remote) == remote_ip,
                    "LAN UDP link endpoints must be canonical IPv4")
            require(all(not (address.is_unspecified or address.is_multicast or address.is_loopback or
                            address.is_link_local or address.is_reserved or int(address) == 0xFFFFFFFF)
                        for address in (local, remote)),
                    "LAN UDP link endpoints must be safe unicast IPv4")
            require(1024 <= int(local_port) <= 65535 and 1024 <= int(remote_port) <= 65535,
                    "LAN UDP link ports must be unprivileged")
            local_endpoint = f"{local}:{local_port}"
            remote_endpoint = f"{remote}:{remote_port}"
            require(local_endpoint != remote_endpoint, "LAN UDP link local and remote endpoints must differ")
            require(local_endpoint not in local_endpoints and remote_endpoint not in remote_endpoints,
                    "LAN UDP link endpoints must be unique")
            local_endpoints.add(local_endpoint); remote_endpoints.add(remote_endpoint)
            links.append((local_endpoint, remote_endpoint))
        require(re.fullmatch(r"02(?::[0-9a-f]{2}){5}", a.lan_mac) is not None,
                "--lan-mac must be one lower-case locally administered unicast MAC")
        a.lan_udp_link = links
    require((a.kernel is None) == (a.initrd is None) == (a.kernel_append is None) == (a.kernel_sha256 is None) == (a.initrd_sha256 is None), "kernel, initrd, hashes, and --kernel-append are an atomic set")
    a.guest_uuid = uuid.UUID(a.guest_uuid); require(re.fullmatch(r"[0-9a-f]{32}", a.expected_machine_id) is not None, "expected machine ID must be 32 lowercase hex")
    if a.wan_mac is None:
        a.wan_mac = "02:" + ":".join(a.guest_uuid.hex[index:index + 2] for index in range(0, 10, 2))
    require(re.fullmatch(r"02(?::[0-9a-f]{2}){5}", a.wan_mac) is not None,
            "--wan-mac must be one lower-case locally administered unicast MAC")
    require(a.wan_mac != a.lan_mac, "WAN and LAN MAC addresses must differ")
    return a


def main(argv: Sequence[str] | None = None) -> int:
    a = parse_args(sys.argv[1:] if argv is None else argv); check_prerequisites(a.qemu, a.qemu_img)
    a.base_image = pinned(a.base_image, a.base_sha256, "base image", True); check_backing_chain(a.qemu_img, a.base_image)
    a.ovmf_code = pinned(a.ovmf_code, a.ovmf_code_sha256, "OVMF code", True); a.ovmf_vars = pinned(a.ovmf_vars, a.ovmf_vars_sha256, "OVMF vars", True)
    a.known_hosts = safe_path(a.known_hosts, "known hosts"); a.ssh_private_key = safe_path(a.ssh_private_key, "SSH private key")
    if a.cidata: a.cidata = safe_path(a.cidata, "cidata", True)
    if a.kernel: a.kernel = pinned(a.kernel, a.kernel_sha256, "kernel", True); a.initrd = pinned(a.initrd, a.initrd_sha256, "initrd", True)
    host_machine_id = Path("/etc/machine-id").read_text().strip(); require(a.expected_machine_id != host_machine_id, "expected machine ID must differ from host")
    choose_loopback_port(a.ssh_port); a.work_dir = safe_directory(a.work_dir, "work directory"); a.evidence_dir = safe_directory(a.evidence_dir, "evidence directory")
    overlay = a.work_dir / f"prodigy-kvm-{os.getpid()}-{time.monotonic_ns()}.qcow2"; vars_copy = a.work_dir / f"prodigy-kvm-vars-{os.getpid()}-{time.monotonic_ns()}.fd"
    started_at = time.time_ns() // 1_000_000
    receipt: dict[str, object] = {"overlay": str(overlay), "baseSHA256": a.base_sha256.lower(), "ovmfCodeSHA256": a.ovmf_code_sha256.lower(), "ovmfVarsSHA256": a.ovmf_vars_sha256.lower(), "kernelSHA256": a.kernel_sha256.lower() if a.kernel else None, "initrdSHA256": a.initrd_sha256.lower() if a.initrd else None, "guestUUID": str(a.guest_uuid), "machineID": a.expected_machine_id, "confirmedBoundary": False, "startedAtUnixMs": started_at, "qemuStarted": False, "cleanupSuccess": False}
    process = None; starttime = None; result = 1
    old_term, old_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
    def interrupted(signum: int, _frame: object) -> None: raise BoundaryError(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try:
        shutil.copyfile(a.ovmf_vars, vars_copy); os.chmod(vars_copy, 0o600); create_overlay(a, overlay)
        with (a.evidence_dir / "qemu.log").open("w", encoding="utf-8") as qemu_log:
            process = subprocess.Popen(qemu_command(a, overlay, vars_copy), text=True, stdout=subprocess.DEVNULL, stderr=qemu_log)
            starttime = proc_starttime(process.pid); require(starttime is not None, "could not record QEMU PID start time")
            receipt.update(qemuStarted=True, qemuPID=process.pid, qemuStarttime=starttime)
            wait_for_guest(a, process); receipt["bootReadyAtUnixMs"] = time.time_ns() // 1_000_000
            verify_guest_boundary(a, host_machine_id); receipt.update(confirmedBoundary=True, boundaryConfirmedAtUnixMs=time.time_ns() // 1_000_000)
            result = run_guest_command(a); return result
    except subprocess.TimeoutExpired as error:
        receipt["failure"] = f"timeout: {error}"; raise BoundaryError("guest command timed out") from error
    except Exception as error:
        receipt["failure"] = str(error); raise
    finally:
        signal.signal(signal.SIGTERM, old_term); signal.signal(signal.SIGINT, old_int); complete = cleanup_qemu(process, starttime, overlay, vars_copy, receipt); receipt.update(result=result, finishedAtUnixMs=time.time_ns() // 1_000_000); receipt["elapsedMs"] = receipt["finishedAtUnixMs"] - started_at; (a.evidence_dir / "kvm-boundary-cleanup.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")
        if not complete: raise BoundaryError("KVM cleanup incomplete; preserved overlay for inspection")


if __name__ == "__main__":
    try:
        operation = sys.argv[1] if len(sys.argv) > 1 else ""
        raise SystemExit(lifecycle_main(sys.argv[1:]) if operation in ("launch", "query", "cold-reboot", "remove") else main())
    except (BoundaryError, subprocess.CalledProcessError, OSError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr); raise SystemExit(1)
