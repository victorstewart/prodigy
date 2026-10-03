#!/usr/bin/env python3
"""Own one disposable KVM guest and only its overlay, OVMF vars, and QEMU PID."""
from __future__ import annotations

import argparse
import base64
import hashlib
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


def qemu_command(args: argparse.Namespace, overlay: Path, vars_copy: Path) -> list[str]:
    net = f"user,id=guestnet,hostfwd=tcp:127.0.0.1:{args.ssh_port}-:22"
    if args.guest_egress == "isolated":
        net = net.replace("user,", "user,restrict=on,")
    return [args.qemu, "-accel", "kvm", "-machine", "q35", "-cpu", "host", "-smp", str(args.cpus), "-m", str(args.memory_mb), "-display", "none", "-nodefaults", "-uuid", str(args.guest_uuid), "-smbios", f"type=1,uuid={args.guest_uuid}", "-drive", f"if=pflash,format=raw,readonly=on,file={args.ovmf_code}", "-drive", f"if=pflash,format=raw,file={vars_copy}", "-serial", f"file:{args.evidence_dir / 'serial.log'}", "-drive", f"file={overlay},if=virtio,format=qcow2,cache=none", "-netdev", net, "-device", "virtio-net-pci,netdev=guestnet", "-pidfile", str(args.evidence_dir / "qemu.pid")] + (["-drive", f"file={args.cidata},if=virtio,media=cdrom,readonly=on,format={args.cidata_format}"] if args.cidata else []) + (["-kernel", str(args.kernel), "-initrd", str(args.initrd), "-append", args.kernel_append] if args.kernel else [])


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
    p.add_argument("--disk-size-gb", type=int)
    p.add_argument("--cpus", type=int, default=4); p.add_argument("--memory-mb", type=int, default=8192); p.add_argument("--boot-timeout", type=int, default=180); p.add_argument("--runtime-timeout", type=int, default=3600); p.add_argument("--qemu", default="qemu-system-x86_64"); p.add_argument("--qemu-img", default="qemu-img"); p.add_argument("--ssh", default="ssh"); p.add_argument("guest_command", nargs=argparse.REMAINDER)
    a = p.parse_args(argv); require(a.guest_command and a.guest_command[0] == "--", "supply command after --"); a.guest_command = a.guest_command[1:]; require(a.guest_command, "guest command is required")
    require(a.cpus in range(1, 17) and a.memory_mb in range(1024, 65537), "CPU or memory bound is invalid"); require(a.boot_timeout in range(1, 1801) and a.runtime_timeout in range(1, 14401), "timeout bound is invalid")
    require(a.disk_size_gb is None or a.disk_size_gb in range(2, 129), "--disk-size-gb must be in 2..128")
    require((a.kernel is None) == (a.initrd is None) == (a.kernel_append is None) == (a.kernel_sha256 is None) == (a.initrd_sha256 is None), "kernel, initrd, hashes, and --kernel-append are an atomic set")
    a.guest_uuid = uuid.UUID(a.guest_uuid); require(re.fullmatch(r"[0-9a-f]{32}", a.expected_machine_id) is not None, "expected machine ID must be 32 lowercase hex")
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
    try: raise SystemExit(main())
    except (BoundaryError, subprocess.CalledProcessError, OSError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr); raise SystemExit(1)
