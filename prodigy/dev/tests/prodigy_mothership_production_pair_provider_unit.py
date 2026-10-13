#!/usr/bin/env python3
import json
import ipaddress
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import threading
import time

PROVIDER = pathlib.Path(__file__).resolve().parents[2] / "mothership" / "mothership.production.pair.provider.py"
OPERATION = "0123456789abcdef0123456789abcdef"
CLUSTER = "11111111111111111111111111111111"
MACHINE = "22222222222222222222222222222222"
WITNESS = "33333333333333333333333333333333"


class EchoServer:
    def __init__(self, prefix):
        self.prefix = prefix
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.port = self.socket.getsockname()[1]
        self.running = True
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while self.running:
            try:
                conn, _ = self.socket.accept()
            except OSError:
                return
            threading.Thread(target=self.echo, args=(conn,), daemon=True).start()

    def echo(self, conn):
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(self.prefix + data)

    def close(self):
        self.running = False
        self.socket.close()


def free_port(address):
    value = socket.socket()
    value.bind((address, 0))
    port = value.getsockname()[1]
    value.close()
    return port


def nonloopback_ipv4():
    candidates = []
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        candidates.append(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    try:
        candidates.extend(info[4][0] for info in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM))
    except OSError:
        pass
    for address in candidates:
        parsed = ipaddress.IPv4Address(address)
        if (parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast or
                parsed.is_link_local or parsed == ipaddress.IPv4Address("255.255.255.255")):
            continue
        try:
            value = socket.socket()
            value.bind((address, 0))
            value.close()
            return address
        except OSError:
            pass
    raise RuntimeError("could not discover a bindable non-loopback IPv4 address")


def main():
    root = tempfile.mkdtemp(prefix="prodigy-production-pair-provider-")
    source, target = EchoServer(b"S:"), EchoServer(b"T:")
    listen_address = nonloopback_ipv4()
    listener = free_port(listen_address)
    base = ["python3", str(PROVIDER), "--operation-id", OPERATION,
            "--executor-cluster-id", CLUSTER, "--executor-machine-id", MACHINE,
            "--witness-machine-id", WITNESS,
            "--state-dir", root,
            "--listen-address", listen_address, "--listen-port", str(listener),
            "--source-address", "127.0.0.1", "--source-port", str(source.port),
            "--target-address", "127.0.0.1", "--target-port", str(target.port)]

    def command(action, expected=0):
        result = subprocess.run(base[:2] + [action] + base[2:], check=False, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        assert result.returncode == expected, (action, result.stdout, result.stderr)
        return json.loads(result.stdout)

    def wait_state(predicate, timeout=3.0):
        deadline = time.monotonic() + timeout
        while True:
            state = command("query")["state"]
            if predicate(state):
                return state
            if time.monotonic() >= deadline:
                raise AssertionError(state)
            time.sleep(0.03)

    try:
        for flag in ("--operation-id", "--executor-cluster-id", "--executor-machine-id",
                     "--witness-machine-id"):
            for rejected_identity in ("0x" + OPERATION, OPERATION.upper(), OPERATION[:-1],
                                      OPERATION + "0", OPERATION[:8] + "-" + OPERATION[8:]):
                rejected_base = base[:]
                rejected_base[rejected_base.index(flag) + 1] = rejected_identity
                rejected = subprocess.run(rejected_base[:2] + ["query"] + rejected_base[2:],
                                          check=False, text=True, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, timeout=10)
                assert rejected.returncode == 2 and "32 lowercase hexadecimal characters" in rejected.stderr
        for rejected_address in ("127.0.0.1", "0.0.0.0"):
            rejected_base = base[:]
            rejected_base[rejected_base.index("--listen-address") + 1] = rejected_address
            rejected = subprocess.run(rejected_base[:2] + ["query"] + rejected_base[2:], check=False,
                                      text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            assert rejected.returncode == 2 and "exact numeric non-loopback IPv4" in rejected.stderr
        # The state-root pathname itself is not followed, even when its target
        # happens to have the required owner and mode.
        linked_root = root + "-symlink"
        os.symlink(root, linked_root)
        try:
            linked_base = [linked_root if item == root else item for item in base]
            linked = subprocess.run(linked_base[:2] + ["query"] + linked_base[2:], check=False,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            assert linked.returncode == 1 and "state directory is not a real directory" in linked.stdout
        finally:
            os.unlink(linked_root)
        # The installed provider has a root-owned state boundary.  On a
        # developer host without that identity, verify the fail-closed edge.
        if os.geteuid() != 0:
            rejected = command("query", expected=1)
            assert "root-owned private directory" in rejected["failure"]
            print("PASS: production pair provider rejects a non-root state directory")
            return
        # Parsing accepts typed remote workload identities without attempting a
        # connection; query fails only because this operation has no state.
        remote = subprocess.run(["python3", str(PROVIDER), "query", "--operation-id", "fedcba9876543210fedcba9876543210",
                                 "--executor-cluster-id", CLUSTER, "--executor-machine-id", MACHINE,
                                 "--witness-machine-id", WITNESS,
                                 "--state-dir", root, "--listen-address", listen_address, "--listen-port", str(free_port(listen_address)),
                                 "--source-address", "192.0.2.10", "--source-port", "443",
                                 "--target-address", "198.51.100.20", "--target-port", "8443"],
                                check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        assert remote.returncode == 1 and "selector state does not exist" in remote.stdout
        # Simultaneous retries must observe one selector through the stable
        # operation lock rather than racing a lock unlink/recreate.
        results, failures = [], []
        def launch_once():
            try:
                results.append(command("launch"))
            except BaseException as error:
                failures.append(error)
        workers = [threading.Thread(target=launch_once) for _ in range(6)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        assert not failures and len(results) == 6
        assert all(result["success"] for result in results)
        assert len({result["state"]["pid"] for result in results}) == 1
        first = results[0]
        assert first["success"] and first["state"]["sourceReachable"] and first["state"]["targetReachable"]
        assert first["state"]["version"] == 2
        assert first["state"]["executorClusterID"] == CLUSTER
        assert first["state"]["executorMachineID"] == MACHINE
        assert command("launch")["state"]["pid"] == first["state"]["pid"]
        assert command("select-target", expected=1)["success"] is False
        # A witness result is an explicit Mothership-owned remote observation;
        # it is not selector state and cannot be substituted by local counters.
        witnessed_source = command("witness-source")
        assert witnessed_source["witness"]["side"] == "source"
        assert witnessed_source["witness"]["witnessMachineID"] == WITNESS
        held = socket.create_connection((listen_address, listener), timeout=3)
        held.sendall(b"held")
        assert held.recv(64) == b"S:held"
        source_state = wait_state(lambda state: state["sourceFlows"] == 1)
        assert source_state["sourceConnections"] == 2
        assert source_state["sourceRequestBytes"] > 0 and source_state["sourceResponseBytes"] > 0
        assert command("select-target")["success"] and command("select-target")["success"]
        witnessed_target = command("witness-target")
        assert witnessed_target["witness"]["side"] == "target"
        assert command("launch")["state"]["selectedTarget"] is True
        fresh = socket.create_connection((listen_address, listener), timeout=3)
        fresh.sendall(b"fresh")
        assert fresh.recv(64) == b"T:fresh"
        held.sendall(b"again")
        assert held.recv(64) == b"S:again"
        state = wait_state(lambda observed: observed["sourceFlows"] == 1 and observed["targetFlows"] == 1)
        assert state["sourceFlows"] == 1 and state["targetFlows"] == 1
        assert state["sourceConnections"] == 2 and state["targetConnections"] == 2
        assert state["sourceRequestBytes"] > 0 and state["sourceResponseBytes"] > 0
        assert state["targetRequestBytes"] > 0 and state["targetResponseBytes"] > 0
        assert command("drain", expected=1)["success"] is False
        held.close(); fresh.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            state = command("query")["state"]
            if state["sourceFlows"] == 0 and state["targetFlows"] == 0:
                break
            time.sleep(0.03)
        assert state["sourceFlows"] == 0 and state["targetFlows"] == 0
        assert command("drain")["success"]
        assert command("remove")["success"] and command("remove")["success"]
        state_file = pathlib.Path(root, "production-pair-selector-" + OPERATION + ".json")
        lock_file = pathlib.Path(root, "production-pair-selector-" + OPERATION + ".json.lock")
        assert not state_file.exists()
        lock_identity = lock_file.stat().st_ino
        assert lock_file.is_file()
        retry = command("launch")
        assert retry["success"] and lock_file.stat().st_ino == lock_identity
        assert command("remove")["success"]

        # State symlinks cannot redirect inspection or cleanup outside the
        # trusted directory descriptor.
        state_file.symlink_to("/dev/null")
        unsafe = command("query", expected=1)
        assert "cannot be opened safely" in unsafe["failure"]
        state_file.unlink()

        # An expired launch reservation can retry under the same tombstone.
        reservation = {"version": 2, "operationID": OPERATION,
                       "executorClusterID": CLUSTER, "executorMachineID": MACHINE,
                       "listener": [listen_address, listener],
                       "source": ["127.0.0.1", source.port],
                       "target": ["127.0.0.1", target.port],
                       "status": "launching", "reservedAtUnixNS": time.time_ns() - 16_000_000_000}
        state_file.write_text(json.dumps(reservation), encoding="utf-8")
        os.chmod(state_file, 0o600)
        assert command("launch")["success"]
        assert command("remove")["success"]
        if hasattr(os, "memfd_create") and pathlib.Path("/proc/self/fd").is_dir():
            descriptor = os.memfd_create("prodigy-production-pair-provider", flags=0)
            try:
                os.write(descriptor, PROVIDER.read_bytes())
                os.lseek(descriptor, 0, os.SEEK_SET)
                mem_operation = "11111111111111111111111111111111"
                mem_listener = free_port(listen_address)
                mem_base = ["python3", f"/proc/self/fd/{descriptor}",
                            "--operation-id", mem_operation,
                            "--executor-cluster-id", CLUSTER, "--executor-machine-id", MACHINE,
                            "--witness-machine-id", WITNESS,
                            "--state-dir", root,
                            "--listen-address", listen_address, "--listen-port", str(mem_listener),
                            "--source-address", "127.0.0.1", "--source-port", str(source.port),
                            "--target-address", "127.0.0.1", "--target-port", str(target.port)]
                def mem_command(action):
                    result = subprocess.run(mem_base[:2] + [action] + mem_base[2:], check=False,
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            timeout=10, pass_fds=(descriptor,))
                    assert result.returncode == 0, (action, result.stdout, result.stderr)
                    return json.loads(result.stdout)
                launched = mem_command("launch")
                assert launched["state"]["pid"] == mem_command("query")["state"]["pid"]
                assert mem_command("remove")["success"]
            finally:
                os.close(descriptor)
        print("PASS: production pair provider preserves flows and safely serializes retries, symlinks, and cleanup")
    finally:
        try:
            command("remove")
        except Exception:
            pass
        source.close(); target.close(); shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
