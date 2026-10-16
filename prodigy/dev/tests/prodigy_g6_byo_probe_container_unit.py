#!/usr/bin/env python3
"""Unprivileged wire-contract checks for the G6 BYO IPv6 probe payload."""
import socket
import subprocess
import sys
import tempfile
import time
import hashlib
from pathlib import Path


CHALLENGE = "a" * 64
TRACE_IP = "2602:fac0::1234"


def trace_response(body: str) -> str:
    return f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}"


def wait_for_listener(port: int, process) -> socket.socket:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            connection = socket.create_connection(("::1", port), timeout=0.1)
            return connection
        except OSError:
            if process.poll() is not None:
                raise RuntimeError("wormhole exited before listening")
    raise RuntimeError("wormhole did not listen")


def check_wormhole(binary: str) -> None:
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.bind(("::1", 0))
    port = listener.getsockname()[1]
    listener.close()
    process = subprocess.Popen([binary, "wormhole", str(port), "1000"])
    connection = wait_for_listener(port, process)
    request = f"PRODIGY_G6_IPV6_INGRESS_CHALLENGE {CHALLENGE}\n".encode()
    response = f"PRODIGY_G6_IPV6_INGRESS_RESPONSE {CHALLENGE}\n".encode()
    connection.sendall(request)
    received = connection.recv(len(response) + 1)
    connection.close()
    if received != response or process.wait(timeout=2) != 0:
        raise RuntimeError("wormhole did not preserve the exact ingress challenge")


def check_invalid_source_is_rejected(binary: str) -> None:
    result = subprocess.run(
        [binary, "whitehole", "2001:db8::1", "32101", "::1", "32102", "100"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 2:
        raise RuntimeError("whitehole accepted a source outside 2602:fac0::/40")


def check_unassigned_byo_source_is_rejected(binary: str) -> None:
    result = subprocess.run(
        [binary, "whitehole", "2602:fac0::1", "32101", "::1", "32102", "100"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 1:
        raise RuntimeError("whitehole accepted a BYO source absent from every interface")


def check_extra_ingress_data_is_rejected(binary: str) -> None:
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.bind(("::1", 0))
    port = listener.getsockname()[1]
    listener.close()
    process = subprocess.Popen([binary, "wormhole", str(port), "1000"])
    connection = wait_for_listener(port, process)
    connection.sendall(f"PRODIGY_G6_IPV6_INGRESS_CHALLENGE {CHALLENGE}\nextra".encode())
    connection.close()
    if process.wait(timeout=2) == 0:
        raise RuntimeError("wormhole accepted extra protocol data")


def check_partial_ingress_times_out(binary: str) -> None:
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.bind(("::1", 0))
    port = listener.getsockname()[1]
    listener.close()
    process = subprocess.Popen([binary, "wormhole", str(port), "100"])
    connection = wait_for_listener(port, process)
    connection.sendall(b"PRODIGY_G6_IPV6_INGRESS_CHALLENGE ")
    connection.close()
    if process.wait(timeout=2) == 0:
        raise RuntimeError("wormhole accepted a partial request after its deadline")


def check_trace_parser(binary: str) -> None:
    valid = trace_response(f"fl=29f\nip={TRACE_IP}\nts=1\n")
    accepted = subprocess.run([binary, "trace-selftest", TRACE_IP, valid], check=False)
    if accepted.returncode != 0:
        raise RuntimeError("trace parser rejected an exact bounded response")
    for response in (
        trace_response("ip=2602:fac0::9999\n"),
        trace_response(f"ip={TRACE_IP}\n") + "trailing",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nip",
        trace_response(f"ip={TRACE_IP}\n\n"),
    ):
        rejected = subprocess.run([binary, "trace-selftest", TRACE_IP, response], check=False)
        if rejected.returncode == 0:
            raise RuntimeError("trace parser accepted malformed, mismatched, or trailing data")


def check_rollout_proof_parser(binary: str) -> None:
    binary_sha256 = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    valid = f"PRODIGY_G6_BYO_PROOF {CHALLENGE} {'b' * 40} g6-byo-ewr {binary_sha256}\n"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "proof"
        path.write_text(valid)
        if subprocess.run([binary, "proof-selftest", str(path), binary], check=False).returncode != 0:
            raise RuntimeError("rollout proof rejected the exact running executable identity")
        other = Path(directory) / "other"
        other.write_bytes(Path(binary).read_bytes() + b"tampered")
        if subprocess.run([binary, "proof-selftest", str(path), str(other)], check=False).returncode == 0:
            raise RuntimeError("rollout proof accepted a different executable")
        for malformed in (valid + "trailing", valid.replace("g6-byo-ewr", "bad row"), valid.replace(CHALLENGE, "a" * 63)):
            path.write_text(malformed)
            if subprocess.run([binary, "proof-selftest", str(path), binary], check=False).returncode == 0:
                raise RuntimeError("rollout proof parser accepted malformed identity")


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    check_wormhole(sys.argv[1])
    check_invalid_source_is_rejected(sys.argv[1])
    check_unassigned_byo_source_is_rejected(sys.argv[1])
    check_extra_ingress_data_is_rejected(sys.argv[1])
    check_partial_ingress_times_out(sys.argv[1])
    check_trace_parser(sys.argv[1])
    check_rollout_proof_parser(sys.argv[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
