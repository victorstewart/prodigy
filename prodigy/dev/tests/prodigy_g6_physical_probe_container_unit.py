#!/usr/bin/env python3
"""Bounded loopback checks for the G6 observer; run in the verified Linux guest."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


ROOT = Path(__file__).resolve().parents[3]
COMMIT = "a" * 40
ARTIFACT = "b" * 64
ROW = "numeric-probe-unit"
SNI = "g6.numeric.fixture"
ENVIRONMENT = {
    **os.environ,
    "G6_PROBE_CANDIDATE_COMMIT": COMMIT,
    "G6_PROBE_ARTIFACT_SHA256": ARTIFACT,
    "G6_PROBE_ROW": ROW,
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def invoke(binary, *arguments, environment=None, code=1):
    result = subprocess.run(
        [binary, *map(str, arguments)], env=environment or ENVIRONMENT,
        capture_output=True, text=True, timeout=8, check=False,
    )
    require(result.returncode == code, (arguments, result.returncode, result.stdout, result.stderr))
    if code == 2:
        require(not result.stdout, "invalid CLI arguments emitted evidence")
        return None
    lines = result.stdout.splitlines()
    require(len(lines) == 1, (arguments, "expected one JSONL observation", result.stdout))
    event = json.loads(lines[0])
    require(event["schemaVersion"] == 1 and event["candidateCommit"] == COMMIT and
            event["artifactSHA256"] == ARTIFACT and event["row"] == ROW,
            "probe lost its evidence identity")
    require(event["monotonicNs"] > 0 and event["observedAt"].endswith("Z"), "missing observation timestamps")
    return event


@contextlib.contextmanager
def loopback_server(family, tls_context=None, corrupt_echo=False):
    listener = socket.socket(family, socket.SOCK_STREAM)
    stop = threading.Event()
    completed = threading.Event()
    state = {"connections": 0, "errors": [], "peerCertificate": False, "tlsVersion": None}
    thread = None
    try:
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        host = "127.0.0.1" if family == socket.AF_INET else "::1"
        listener.bind((host, 0))
        listener.listen(4)
        listener.settimeout(0.1)

        def serve():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError as error:
                    if not stop.is_set():
                        state["errors"].append(str(error))
                    break
                state["connections"] += 1
                try:
                    with connection:
                        connection.settimeout(2)
                        if tls_context:
                            with tls_context.wrap_socket(connection, server_side=True) as secure:
                                state["peerCertificate"] = bool(secure.getpeercert())
                                state["tlsVersion"] = secure.version()
                        else:
                            while data := connection.recv(4096):
                                connection.sendall(b"x" * len(data) if corrupt_echo else data)
                except (OSError, ssl.SSLError) as error:
                    state["errors"].append(str(error))
                finally:
                    completed.set()

        thread = threading.Thread(target=serve, name="g6-probe-loopback", daemon=True)
        thread.start()
        yield host, listener.getsockname()[1], state, completed
    finally:
        stop.set()
        listener.close()
        if thread:
            thread.join(timeout=3)
            require(not thread.is_alive(), "loopback fixture failed to stop within its deadline")


def check_tcp(binary):
    for family, selector in ((socket.AF_INET, "4"), (socket.AF_INET6, "6")):
        with loopback_server(family) as (host, port, state, completed):
            event = invoke(binary, "tcp", host, selector, port, 32768, code=0)
            detail = event["detail"]
            require(event["method"] == "tcp-connect-bidirectional" and event["status"] == "pass" and
                    detail["connectSucceeded"] is True and detail["payloadMatched"] is True and
                    detail["family"] == family and detail["sentBytes"] == detail["receivedBytes"] == 32768,
                    "numeric TCP endpoint did not exchange the exact echo payload")
            require(completed.wait(2) and not state["errors"], state)
            for invalid_host in ("localhost", "localhost.", "[::1]", "127.1", ""):
                rejected = invoke(binary, "tcp", invalid_host, selector, port, 16)
                require(rejected["status"] == "fail" and rejected["detail"]["connectSucceeded"] is False,
                        (invalid_host, "nonnumeric endpoint was accepted"))
            for invalid_port in ("", "0", "65536", "9999999999999999999999999", "http",
                                 "https", "-1", f"+{port}", f" {port}", f"{port} ", f"{port}x"):
                rejected = invoke(binary, "tcp", host, selector, invalid_port, 16)
                require(rejected["status"] == "fail" and rejected["detail"]["connectSucceeded"] is False,
                        (invalid_port, "invalid numeric port was accepted"))
            other_family = "6" if selector == "4" else "4"
            mismatch = invoke(binary, "tcp", host, other_family, port, 16)
            require(mismatch["status"] == "fail" and mismatch["detail"]["connectSucceeded"] is False,
                    "address was accepted under the wrong family")
            invoke(binary, "tcp", host, "any", port, 16, code=2)
            require(state["connections"] == 1, "rejected TCP arguments reached the loopback listener")
    with loopback_server(socket.AF_INET, corrupt_echo=True) as (host, port, state, completed):
        event = invoke(binary, "tcp", host, "4", port, 16)
        require(event["status"] == "fail" and event["detail"]["connectSucceeded"] is True and
                event["detail"]["payloadMatched"] is False,
                "corrupted echo was accepted as the original payload")
        require(completed.wait(2) and not state["errors"], state)


def check_dns(binary, directory):
    observer = Path(__file__).with_name("prodigy_g6_physical_observe.py")
    for hostname in ("localhost", "g6-no-resolution.invalid"):
        event = invoke(binary, "dns", hostname)
        require(event["method"] == "dns-ttl-cache-expiry" and event["status"] == "unproven" and
                event["detail"] == {"hostname": hostname, "reason": "prodigy-resolver-service-evidence-required"},
                "DNS command produced resolution results or claimed unsupported evidence")
        transcript = directory / "dns.jsonl"
        transcript.write_text(json.dumps(event) + "\n")
        rejected = subprocess.run(
            [sys.executable, "-B", str(observer), "--commit", COMMIT, "--artifact", ARTIFACT,
             "--row", ROW, str(transcript)], capture_output=True, text=True, timeout=5, check=False,
        )
        require(rejected.returncode != 0 and "DNS transcript does not prove TTL/cache expiry" in rejected.stderr,
                ("observer accepted unproven DNS evidence", rejected.stdout, rejected.stderr))


def check_tls(binary, directory):
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl executable is required for the bounded TLS fixture")
    certificate, key = directory / "certificate.pem", directory / "key.pem"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", f"/CN={SNI}", "-keyout", str(key), "-out", str(certificate)],
        capture_output=True, text=True, timeout=15, check=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 0
    context.load_cert_chain(certificate, key)
    context.load_verify_locations(certificate)
    context.verify_mode = ssl.CERT_REQUIRED
    names = []
    context.set_servername_callback(lambda _socket, name, _context: names.append(name))
    environment = {**ENVIRONMENT, "G6_PROBE_TLS_CERT": str(certificate),
                   "G6_PROBE_TLS_KEY": str(key), "G6_PROBE_TLS_CA": str(certificate)}
    for family in (socket.AF_INET, socket.AF_INET6):
        with loopback_server(family, context) as (host, port, state, completed):
            # TLS uses AF_UNSPEC internally, so both numeric families must work.
            event = invoke(binary, "tls", host, port, SNI, environment=environment)
            require(event["method"] == "tls13-sni-mutual-identity" and event["status"] == "unproven" and
                    event["detail"]["negotiatedVersion"] == "TLSv1.3" and
                    event["detail"]["clientCertificateConfigured"] is True and
                    event["detail"]["serverAcceptedClientIdentity"] is None,
                    "numeric TLS transport failed or overstated its evidence")
            require(completed.wait(2) and not state["errors"] and state["peerCertificate"] and
                    state["tlsVersion"] == "TLSv1.3" and names[-1] == SNI, state)
            for invalid_host, invalid_port in (("localhost", str(port)), (host, f"+{port}"), (host, "https")):
                rejected = invoke(binary, "tls", invalid_host, invalid_port, SNI, environment=environment)
                require(rejected["status"] == "fail" and rejected["detail"]["negotiatedVersion"] == "",
                        "TLS accepted hostname resolution or a nonnumeric port")
            require(state["connections"] == 1, "rejected TLS arguments reached the loopback listener")


def main():
    if len(sys.argv) != 2 or sys.platform != "linux":
        raise SystemExit("usage (verified Linux guest only): prodigy_g6_physical_probe_container_unit.py BINARY")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    owner = ROOT / ".run" / "g6-physical-probe-unit"
    owner.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="case-", dir=owner) as temporary:
        directory = Path(temporary)
        check_tcp(binary)
        check_dns(binary, directory)
        check_tls(binary, directory)
    print("PASS: G6 numeric TCP/TLS endpoints and fail-closed DNS evidence")


if __name__ == "__main__":
    main()
