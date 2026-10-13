#!/usr/bin/env python3
"""Unprivileged source-boundary TCP selector for one production-pair operation.

Mothership uploads these sealed bytes to the exact admitted source machine.
The source-machine ingress relay binds one exact non-loopback IPv4 address,
while its upstream connections exercise the real source and inter-cluster
target paths.  The durable owner binds the machine identity and requires
witnessed source and target traffic before it may retire the source workload.
"""
import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
import select
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

MAX_OUTPUT = 8192


def fail(message):
    print(json.dumps({"success": False, "failure": message})[:MAX_OUTPUT])
    return 1


def ingress_ipv4(value):
    try:
        parsed = ipaddress.ip_address(value)
        if (parsed.version != 4 or parsed.is_unspecified or parsed.is_loopback or
                parsed.is_multicast or parsed.is_link_local or
                parsed == ipaddress.IPv4Address("255.255.255.255")):
            raise ValueError
        return str(parsed)
    except ValueError:
        raise argparse.ArgumentTypeError("address must be an exact numeric non-loopback IPv4 address")


def numeric_ipv4(value):
    try:
        parsed = ipaddress.ip_address(value)
        if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast:
            raise ValueError
        return str(parsed)
    except ValueError:
        raise argparse.ArgumentTypeError("address must be a numeric unicast IPv4 address")


def port(value):
    try:
        parsed = int(value)
        if parsed < 1 or parsed > 65535:
            raise ValueError
        return parsed
    except ValueError:
        raise argparse.ArgumentTypeError("port must be in 1..65535")


def operation(value):
    if len(value) != 32 or any(c not in "0123456789abcdef" for c in value):
        raise argparse.ArgumentTypeError("operation ID must be 32 lowercase hexadecimal characters")
    return value


def state_name(args):
    return "production-pair-selector-" + args.operation_id + ".json"


def lock_name(args):
    return state_name(args) + ".lock"


def require_regular_file(descriptor, description):
    """Reject a substituted state file before trusting its contents or lock."""
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            (stat.S_IMODE(info.st_mode) & 0o077) != 0 or info.st_nlink != 1):
        raise RuntimeError("%s is not a root-owned private regular file" % description)


def prepare_directory(args):
    """Open the trusted root once; every later state operation uses this fd."""
    if getattr(args, "state_dir_fd", None) is not None:
        return args.state_dir_fd
    if not os.path.isabs(args.state_dir):
        raise RuntimeError("state directory must be absolute")
    try:
        os.mkdir(args.state_dir, mode=0o700)
    except FileExistsError:
        pass
    except FileNotFoundError as error:
        raise RuntimeError("state directory parent does not exist") from error
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(args.state_dir, flags)
    except OSError as error:
        raise RuntimeError("state directory is not a real directory") from error
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            (stat.S_IMODE(info.st_mode) & 0o077) != 0):
        os.close(descriptor)
        raise RuntimeError("state directory must be a root-owned private directory")
    args.state_dir_fd = descriptor
    return descriptor


@contextlib.contextmanager
def locked(args):
    directory = prepare_directory(args)
    try:
        descriptor = os.open(lock_name(args),
                             os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
    except OSError as error:
        raise RuntimeError("operation lock cannot be opened safely") from error
    try:
        require_regular_file(descriptor, "operation lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield descriptor
    finally:
        os.close(descriptor)


def read_state(args):
    try:
        descriptor = os.open(state_name(args), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=prepare_directory(args))
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError("selector state cannot be opened safely") from error
    try:
        require_regular_file(descriptor, "selector state")
        handle = os.fdopen(descriptor, "r", encoding="utf-8")
        descriptor = None
        with handle:
            value = json.load(handle)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise RuntimeError("selector state is malformed")
    return value


def write_state(args, value):
    directory = prepare_directory(args)
    try:
        existing = os.open(state_name(args),
                           os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=directory)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise RuntimeError("selector state cannot be opened safely") from error
    else:
        try:
            require_regular_file(existing, "selector state")
        finally:
            os.close(existing)
    temporary = ".production-pair-%s" % secrets.token_hex(16)
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    except OSError as error:
        raise RuntimeError("selector state temporary cannot be opened safely") from error
    try:
        require_regular_file(descriptor, "selector state temporary")
        handle = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = None
        with handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, state_name(args), src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def unlink_state(args):
    """Remove only a validated state record.  The lock is a permanent tombstone."""
    directory = prepare_directory(args)
    try:
        descriptor = os.open(state_name(args), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
    except FileNotFoundError:
        return
    except OSError as error:
        raise RuntimeError("selector state cannot be opened safely") from error
    try:
        require_regular_file(descriptor, "selector state")
        os.unlink(state_name(args), dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(descriptor)


def proc_starttime(pid):
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="ascii") as handle:
            # The process name may contain spaces/parentheses. Field 22 follows
            # the final ')' and is the twentieth token after it.
            tail = handle.read().rsplit(")", 1)[1].split()
        return tail[19]
    except (FileNotFoundError, IndexError, OSError):
        try:
            return subprocess.check_output(["ps", "-o", "lstart=", "-p", str(pid)], text=True,
                                           stderr=subprocess.DEVNULL).strip() or None
        except (OSError, subprocess.CalledProcessError):
            return None


def process_argv(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            return [part.decode("utf-8") for part in handle.read().split(b"\0") if part]
    except (FileNotFoundError, UnicodeDecodeError, OSError):
        try:
            command = subprocess.check_output(["ps", "-o", "command=", "-p", str(pid)], text=True,
                                              stderr=subprocess.DEVNULL).strip()
            return ["ps-command", command] if command else None
        except (OSError, subprocess.CalledProcessError):
            return None


def exact_process(state):
    pid = state.get("pid")
    return isinstance(pid, int) and pid > 0 and proc_starttime(pid) == state.get("starttime") and \
        process_argv(pid) == state.get("argv")


def identity(args):
    return {
        "version": 2,
        "operationID": args.operation_id,
        "executorClusterID": args.executor_cluster_id,
        "executorMachineID": args.executor_machine_id,
        "listener": [args.listen_address, args.listen_port],
        "source": [args.source_address, args.source_port],
        "target": [args.target_address, args.target_port],
    }


def same_identity(state, args):
    requested = identity(args)
    return all(state.get(key) == value for key, value in requested.items())


def public_state(state):
    keys = ("version", "operationID", "executorClusterID", "executorMachineID",
            "listener", "source", "target", "selectedTarget",
            "sourceFlows", "targetFlows", "sourceConnections", "targetConnections",
            "sourceRequestBytes", "sourceResponseBytes",
            "targetRequestBytes", "targetResponseBytes",
            "sourceReachable", "targetReachable", "pid", "starttime", "generation", "status")
    return {key: state.get(key) for key in keys}


def emit(state, success=True, failure=None):
    value = {"success": success}
    if state is not None:
        value["state"] = public_state(state)
    if failure:
        value["failure"] = failure
    print(json.dumps(value, sort_keys=True)[:MAX_OUTPUT])


def mutate(args, callback):
    with locked(args):
        state = read_state(args)
        return callback(state)


def launch(args):
    start_child = False
    launch_nonce = None
    with locked(args):
        existing = read_state(args)
        if existing is not None:
            if not same_identity(existing, args):
                return fail("operation ID is already bound to a different selector identity")
            if exact_process(existing):
                emit(existing)
                return 0
            if existing.get("status") != "launching":
                return fail("operation ID has stale or foreign process identity")
            reserved_at = existing.get("reservedAtUnixNS")
            if not isinstance(reserved_at, int) or reserved_at <= 0:
                return fail("selector launch reservation is malformed")
            if time.time_ns() - reserved_at > 15_000_000_000:
                unlink_state(args)
                existing = None
        if existing is None:
            launch_nonce = secrets.token_hex(16)
            reservation = identity(args)
            reservation.update({"selectedTarget": False, "sourceFlows": 0, "targetFlows": 0,
                                "sourceConnections": 0, "targetConnections": 0,
                                "sourceRequestBytes": 0, "sourceResponseBytes": 0,
                                "targetRequestBytes": 0, "targetResponseBytes": 0,
                                "sourceReachable": False, "targetReachable": False,
                                "pid": 0, "starttime": None, "argv": [], "generation": 0,
                                "status": "launching", "launchNonce": launch_nonce,
                                "reservedAtUnixNS": time.time_ns()})
            write_state(args, reservation)
            start_child = True
    if start_child:
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                devnull = os.open(os.devnull, os.O_RDWR)
                for descriptor in (0, 1, 2):
                    os.dup2(devnull, descriptor)
                if devnull > 2:
                    os.close(devnull)
                Selector(args, launch_nonce).run()
            except BaseException:
                pass
            os._exit(0)
    # The child acquires the lock independently to publish its atomic ready state.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        with locked(args):
            state = read_state(args)
            if state is not None:
                if same_identity(state, args) and exact_process(state):
                    emit(state)
                    return 0
                if not same_identity(state, args) or state.get("status") != "launching":
                    return fail("selector published a conflicting identity")
        time.sleep(0.02)
    return fail("selector readiness timed out")


def query(args):
    def run(state):
        if state is None:
            return fail("selector state does not exist")
        if not same_identity(state, args) or not exact_process(state):
            return fail("selector state does not match a live exact process")
        emit(state)
        return 0
    return mutate(args, run)


def select_target(args):
    def run(state):
        if state is None or not same_identity(state, args) or not exact_process(state):
            return fail("selector state does not match a live exact process")
        if not state.get("selectedTarget"):
            if (state.get("sourceFlows", 0) <= 0 or state.get("sourceConnections", 0) <= 0 or
                    state.get("sourceRequestBytes", 0) <= 0 or
                    state.get("sourceResponseBytes", 0) <= 0):
                emit(state, False,
                     "target selection requires witnessed bidirectional active source traffic")
                return 1
            state["selectedTarget"] = True
            state["generation"] += 1
            write_state(args, state)
        emit(state)
        return 0
    return mutate(args, run)


def drain(args):
    def run(state):
        if state is None or not same_identity(state, args) or not exact_process(state):
            return fail("selector state does not match a live exact process")
        if (not state.get("selectedTarget") or state.get("sourceFlows") != 0 or
                state.get("targetConnections", 0) <= 0 or
                state.get("targetRequestBytes", 0) <= 0 or
                state.get("targetResponseBytes", 0) <= 0):
            emit(state, False,
                 "drain requires selected target, witnessed target traffic, and zero active source flows")
            return 1
        emit(state)
        return 0
    return mutate(args, run)


def remove(args):
    def cleanup_files():
        # Never unlink the operation lock.  An opener holding the old inode
        # must serialize with all future callers, and this durable lock is the
        # tombstone that prevents an unlink/recreate split-brain race.
        unlink_state(args)

    def run(state):
        if state is None:
            cleanup_files()
            emit(None)
            return 0
        if not same_identity(state, args):
            return fail("operation ID is bound to a different selector identity")
        if exact_process(state):
            os.kill(state["pid"], signal.SIGTERM)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and exact_process(state):
                time.sleep(0.02)
            if exact_process(state):
                return fail("selector did not stop after bounded SIGTERM")
        elif proc_starttime(state.get("pid", 0)) is not None:
            return fail("selector PID exists but identity differs")
        cleanup_files()
        emit(None)
        return 0
    return mutate(args, run)


def witness(args, side):
    """Make one Mothership-requested ingress observation from a peer machine.

    This action deliberately has no access to selector state: the caller binds
    its sealed output to before/after selector observations and persists that
    receipt.  A selector-local client therefore cannot manufacture a witness.
    """
    nonce = secrets.token_hex(16).encode("ascii")
    try:
        with socket.create_connection((args.listen_address, args.listen_port), timeout=3.0) as connection:
            connection.settimeout(3.0)
            connection.sendall(b"prodigy-mothership-ingress-witness:" + nonce + b"\n")
            if not connection.recv(1):
                return fail("ingress witness received no response through the exact selector")
    except OSError as error:
        return fail("ingress witness cannot reach the exact selector: %s" % error)
    print(json.dumps({"success": True, "witness": {
        "version": 1, "operationID": args.operation_id,
        "witnessMachineID": args.witness_machine_id,
        "selector": [args.listen_address, args.listen_port], "side": side,
    }}, sort_keys=True))
    return 0


class Selector:
    def __init__(self, args, launch_nonce=None):
        self.args = args
        self.launch_nonce = launch_nonce
        self.running = True
        self.listener = None
        self.connections = set()
        self.connections_lock = threading.Lock()

    def update_count(self, side, increment):
        with locked(self.args):
            state = read_state(self.args)
            if state is None or not same_identity(state, self.args):
                return False
            key = "sourceFlows" if side == "source" else "targetFlows"
            state[key] += increment
            if increment > 0:
                connection_key = "sourceConnections" if side == "source" else "targetConnections"
                state[connection_key] += 1
            state["generation"] += 1
            write_state(self.args, state)
            return True

    def selected_target(self):
        with locked(self.args):
            state = read_state(self.args)
            return bool(state and state.get("selectedTarget"))

    def update_bytes(self, side, request, count):
        if count <= 0:
            return True
        with locked(self.args):
            state = read_state(self.args)
            if state is None or not same_identity(state, self.args):
                return False
            key = ("sourceRequestBytes" if request else "sourceResponseBytes") if side == "source" else \
                ("targetRequestBytes" if request else "targetResponseBytes")
            state[key] += count
            state["generation"] += 1
            write_state(self.args, state)
            return True

    def relay(self, client, side):
        upstream = None
        counted = False
        try:
            address = (self.args.target_address, self.args.target_port) if side == "target" else (self.args.source_address, self.args.source_port)
            upstream = socket.create_connection(address, timeout=3.0)
            if not self.update_count(side, 1):
                return
            counted = True
            client.setblocking(False)
            upstream.setblocking(False)
            while self.running:
                readable, _, _ = select.select([client, upstream], [], [], 0.2)
                for current, other in ((client, upstream), (upstream, client)):
                    if current not in readable:
                        continue
                    payload = current.recv(65536)
                    if not payload:
                        return
                    other.sendall(payload)
                    if not self.update_bytes(side, current is client, len(payload)):
                        return
        except OSError:
            pass
        finally:
            for current in (client, upstream):
                if current is not None:
                    try:
                        current.close()
                    except OSError:
                        pass
            if counted:
                self.update_count(side, -1)
            with self.connections_lock:
                self.connections.discard(client)

    def stop(self, _signal, _frame):
        self.running = False
        if self.listener:
            self.listener.close()
        with self.connections_lock:
            for connection in list(self.connections):
                try:
                    connection.close()
                except OSError:
                    pass

    def run(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((self.args.listen_address, self.args.listen_port))
        self.listener.listen(128)
        # Admission is not inferred from configuration alone.  Before the
        # selector publishes ready state it proves that both exact workload
        # endpoints accept a TCP connection from this transit owner.
        for endpoint in ((self.args.source_address, self.args.source_port),
                         (self.args.target_address, self.args.target_port)):
            with socket.create_connection(endpoint, timeout=3.0):
                pass
        state = identity(self.args)
        state.update({"selectedTarget": False, "sourceFlows": 0, "targetFlows": 0,
                      "sourceConnections": 0, "targetConnections": 0,
                      "sourceRequestBytes": 0, "sourceResponseBytes": 0,
                      "targetRequestBytes": 0, "targetResponseBytes": 0,
                      "sourceReachable": True, "targetReachable": True,
                      "pid": os.getpid(), "starttime": proc_starttime(os.getpid()),
                      "argv": process_argv(os.getpid()), "generation": 1, "status": "running"})
        if state["starttime"] is None:
            raise RuntimeError("Linux /proc starttime identity is unavailable")
        with locked(self.args):
            existing = read_state(self.args)
            if existing is not None and (not same_identity(existing, self.args) or
                                         existing.get("status") != "launching" or
                                         existing.get("launchNonce") != self.launch_nonce):
                raise RuntimeError("selector state already exists")
            write_state(self.args, state)
        while self.running:
            try:
                client, _ = self.listener.accept()
            except (OSError, socket.timeout):
                continue
            side = "target" if self.selected_target() else "source"
            with self.connections_lock:
                self.connections.add(client)
            threading.Thread(target=self.relay, args=(client, side), daemon=True).start()


def common_arguments(args):
    return ["--operation-id", args.operation_id,
            "--executor-cluster-id", args.executor_cluster_id,
            "--executor-machine-id", args.executor_machine_id,
            "--state-dir", args.state_dir,
            "--listen-address", args.listen_address, "--listen-port", str(args.listen_port),
            "--source-address", args.source_address, "--source-port", str(args.source_port),
            "--target-address", args.target_address, "--target-port", str(args.target_port)]


def parser():
    value = argparse.ArgumentParser()
    value.add_argument("action", choices=("launch", "query", "select-target", "drain", "remove", "serve",
                                            "witness-source", "witness-target"))
    value.add_argument("--operation-id", required=True, type=operation)
    value.add_argument("--executor-cluster-id", required=True, type=operation)
    value.add_argument("--executor-machine-id", required=True, type=operation)
    value.add_argument("--witness-machine-id", required=True, type=operation)
    value.add_argument("--state-dir", required=True)
    value.add_argument("--listen-address", required=True, type=ingress_ipv4)
    value.add_argument("--listen-port", required=True, type=port)
    # These are exact workload addresses from typed deployment reports. They
    # may be LAN, private-cloud, or public IPv4.  The selector listener is an
    # ingress relay on its admitted source machine and uses one exact IPv4.
    value.add_argument("--source-address", required=True, type=numeric_ipv4)
    value.add_argument("--source-port", required=True, type=port)
    value.add_argument("--target-address", required=True, type=numeric_ipv4)
    value.add_argument("--target-port", required=True, type=port)
    return value


def main():
    args = parser().parse_args()
    try:
        if args.action == "serve":
            selector = Selector(args)
            signal.signal(signal.SIGTERM, selector.stop)
            signal.signal(signal.SIGINT, selector.stop)
            selector.run()
            return 0
        if args.action == "witness-source":
            return witness(args, "source")
        if args.action == "witness-target":
            return witness(args, "target")
        return {"launch": launch, "query": query, "select-target": select_target,
                "drain": drain, "remove": remove}[args.action](args)
    except RuntimeError as error:
        return fail(str(error))
    finally:
        descriptor = getattr(args, "state_dir_fd", None)
        if descriptor is not None:
            os.close(descriptor)


if __name__ == "__main__":
    sys.exit(main())
