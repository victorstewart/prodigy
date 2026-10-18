#!/usr/bin/env python3
"""Sealed Linux executor for one bounded guest-owned peer-host blackhole.

This is intentionally not a general route tool.  Every retry must repeat the
same operation, role, guest identity, peer address, and duration; all other
states fail closed.  The caller is expected to have already admitted those
identities through Mothership's typed fault contract.
"""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Optional


SCHEMA_VERSION = 2
MAX_DURATION_MS = 60_000
ROUTE_PROTOCOL = "186"
ROUTE_PROTOCOL_RENDERINGS = {ROUTE_PROTOCOL, "bgp"}
FIXED_STATE_ROOT = Path("/var/lib/prodigy/mothership-physical-faults")
FIXED_STATE_PARENT = FIXED_STATE_ROOT.parent
FIXED_STATE_GRANDPARENT = FIXED_STATE_PARENT.parent
OPERATION = re.compile(r"^[0-9a-f]{32}$")
GUEST = re.compile(r"^[0-9a-f]{32}$")
ROLES = {"source", "target"}


class ProviderError(RuntimeError):
    pass


class ProviderInterrupted(ProviderError):
    pass


@dataclass(frozen=True)
class Request:
    operationID: str
    role: str
    guestID: str
    peerAddress: str
    durationMilliseconds: int

    @property
    def prefix(self) -> str:
        address = ipaddress.ip_address(self.peerAddress)
        return f"{address}/{32 if address.version == 4 else 128}"


def validate_request(request: Request) -> None:
    if not OPERATION.fullmatch(request.operationID):
        raise ProviderError("operationID must be exactly 32 lower-case hex characters")
    if request.role not in ROLES:
        raise ProviderError("role must be source or target")
    if not GUEST.fullmatch(request.guestID):
        raise ProviderError("guestID must be exactly 32 lower-case hex characters")
    try:
        address = ipaddress.ip_address(request.peerAddress)
    except ValueError as error:
        raise ProviderError("peerAddress must be one unicast host address") from error
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
        raise ProviderError("peerAddress must be a non-local unicast host address")
    if not isinstance(request.durationMilliseconds, int) or isinstance(request.durationMilliseconds, bool) or not (0 < request.durationMilliseconds <= MAX_DURATION_MS):
        raise ProviderError("durationMilliseconds must be in the bounded fault window")


def boot_identity(path: str = "/proc/sys/kernel/random/boot_id") -> str:
    try:
        value = Path(path).read_text(encoding="ascii").strip()
    except OSError as error:
        raise ProviderError(f"cannot read boot identity: {error}") from error
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
        raise ProviderError("boot identity is malformed")
    return value


def _state_name(operation_id: str) -> str:
    if not OPERATION.fullmatch(operation_id):
        raise ProviderError("unsafe operationID")
    return f"physical-fault-{operation_id}.json"


def _state_path(root: Path, operation_id: str) -> Path:
    # Kept for callers which only need a display path; all state I/O is dirfd-relative.
    return root / _state_name(operation_id)


def _expected_uid(require_root: bool) -> int:
    return 0 if require_root else os.geteuid()


def _validate_file(metadata: os.stat_result, *, mode: int, uid: int, description: str) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != mode or metadata.st_nlink != 1:
        raise ProviderError(f"{description} is not a private regular file")


def _validate_state_parent(parent_fd: int, *, require_root: bool) -> None:
    metadata = os.fstat(parent_fd)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != _expected_uid(require_root)
            or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)):
        raise ProviderError("fault state parent permissions or ownership are unsafe")


def _open_state_root(root: Path, require_root: bool) -> int:
    """Open the one private state directory, creating it only below a safe parent.

    The root-mode CLI is intentionally not a generic directory creator: Mothership
    pins this exact path.  The dirfd sequence closes the symlink/rename window
    between validating the root-owned parent and provisioning the task directory.
    """
    root = Path(root)
    if require_root and root != FIXED_STATE_ROOT:
        raise ProviderError("fault state root is not the fixed provider directory")
    try:
        if require_root:
            # A newly provisioned guest may not yet have /var/lib/prodigy.
            # Create only that fixed intermediate directory below /var/lib after
            # validating the latter, never a caller-selected hierarchy.
            grandparent_fd = os.open(FIXED_STATE_GRANDPARENT,
                                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _validate_state_parent(grandparent_fd, require_root=True)
                try:
                    os.mkdir(FIXED_STATE_PARENT.name, 0o700, dir_fd=grandparent_fd)
                except FileExistsError:
                    pass
                parent_fd = os.open(FIXED_STATE_PARENT.name,
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=grandparent_fd)
            finally:
                os.close(grandparent_fd)
        else:
            parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProviderError(f"cannot open fault state parent: {error}") from error
    try:
        _validate_state_parent(parent_fd, require_root=require_root)
        try:
            os.mkdir(root.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as error:
            raise ProviderError(f"cannot provision fault state root: {error}") from error
        try:
            fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as error:
            raise ProviderError(f"cannot open fault state root: {error}") from error
    finally:
        os.close(parent_fd)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != _expected_uid(require_root)
                or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise ProviderError("fault state root permissions or ownership are unsafe")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_lock(directory_fd: int, require_root: bool) -> int:
    name = ".physical-fault.lock"
    flags = os.O_RDWR | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
    except FileExistsError:
        try:
            fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError as error:
            raise ProviderError(f"cannot open fault lock: {error}") from error
    except OSError as error:
        raise ProviderError(f"cannot create fault lock: {error}") from error
    try:
        _validate_file(os.fstat(fd), mode=0o600, uid=_expected_uid(require_root), description="fault lock")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _run_ip(ip_binary: str, arguments: list[str]) -> str:
    try:
        completed = subprocess.run([ip_binary, *arguments], check=False, shell=False,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProviderError(f"ip command failed to execute: {error}") from error
    if completed.returncode != 0:
        raise ProviderError(f"ip command failed: {completed.stderr.strip() or completed.stdout.strip()}")
    return completed.stdout


def _route_entries(ip_binary: str, prefix: str) -> list[dict]:
    output = _run_ip(ip_binary, ["-j", "route", "show", "exact", prefix])
    try:
        entries = json.loads(output or "[]")
    except json.JSONDecodeError as error:
        raise ProviderError("ip route query returned malformed JSON") from error
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise ProviderError("ip route query returned an invalid route inventory")
    return entries


def _route_metric(operation_id: str) -> int:
    # A route protocol alone is not an ownership token: it is shared by every
    # provider operation.  Bind the kernel route to this opaque operation too.
    return (int(operation_id[:8], 16) % 2_147_483_646) + 1


def _entry_is_ours(entry: dict, prefix: str, metric: int) -> bool:
    try:
        entry_metric = int(entry.get("metric"))
        expected = ipaddress.ip_network(prefix, strict=True)
        rendered = entry.get("dst")
        if not isinstance(rendered, str):
            return False
        # iproute2 omits /32 and /128 from JSON when rendering a host route.
        # Canonicalize both representations, but continue to require the exact
        # full-length host destination rather than accepting a covering route.
        if "/" in rendered:
            observed = ipaddress.ip_network(rendered, strict=True)
        else:
            address = ipaddress.ip_address(rendered)
            observed = ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=True)
    except (TypeError, ValueError):
        return False
    # iproute2 renders protocol 186 either numerically or through the standard
    # rt_protos name "bgp", depending on the guest's protocol-name database.
    # Both describe the same kernel protocol byte supplied above; retain the
    # exact host and per-operation metric checks as the ownership token.
    return (observed == expected and entry.get("type") == "blackhole"
            and str(entry.get("protocol")) in ROUTE_PROTOCOL_RENDERINGS and entry_metric == metric)


def _route_is_ours(entries: list[dict], prefix: str, metric: int) -> bool:
    return sum(_entry_is_ours(entry, prefix, metric) for entry in entries) == 1


def _ensure_no_route(ip_binary: str, request: Request) -> None:
    if _route_entries(ip_binary, request.prefix):
        raise ProviderError("refusing a pre-existing exact peer-host route")


def _remove(ip_binary: str, request: Request, metric: int) -> None:
    entries = _route_entries(ip_binary, request.prefix)
    if not _route_is_ours(entries, request.prefix, metric):
        if not entries:
            return
        raise ProviderError("refusing to remove a route not owned by this provider")
    _run_ip(ip_binary, ["route", "del", "blackhole", request.prefix, "proto", ROUTE_PROTOCOL,
                        "metric", str(metric)])
    if _route_is_ours(_route_entries(ip_binary, request.prefix), request.prefix, metric):
        raise ProviderError("blackhole route removal could not be verified")


def _state_route_metric(state: dict, request: Request) -> int:
    metric = state.get("routeMetric")
    if not isinstance(metric, int) or isinstance(metric, bool) or metric != _route_metric(request.operationID):
        raise ProviderError("fault state lacks the exact route ownership token")
    return metric


def _mark_restored(state: dict, directory_fd: int, name: str, installed: int,
                   now: Callable[[], int], *, require_root: bool) -> dict:
    restored = now()
    if restored <= installed:
        raise ProviderError("monotonic clock did not advance through fault cleanup")
    state["restored"] = True
    state["restoredAtMonotonicMs"] = restored
    _atomic_write(directory_fd, name, state, require_root=require_root)
    return _receipt(state)


def _remove_our_route_if_present(ip_binary: str, request: Request, metric: int) -> bool:
    entries = _route_entries(ip_binary, request.prefix)
    if not _route_is_ours(entries, request.prefix, metric):
        return False
    _remove(ip_binary, request, metric)
    return True


def _atomic_write(directory_fd: int, name: str, payload: dict, *, require_root: bool) -> None:
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temporary = None
    try:
        for nonce in range(128):
            candidate = f".{name}.{os.getpid()}.{nonce}"
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                             dir_fd=directory_fd)
                temporary = candidate
                break
            except FileExistsError:
                continue
        else:
            raise ProviderError("cannot allocate private fault state temporary")
        _validate_file(os.fstat(fd), mode=0o600, uid=_expected_uid(require_root), description="fault state temporary")
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(encoded); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
    except OSError as error:
        raise ProviderError(f"cannot write durable fault state: {error}") from error
    finally:
        if temporary is not None:
            try: os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError: pass


def _read_state(directory_fd: int, name: str, *, require_root: bool) -> Optional[dict]:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ProviderError(f"cannot read durable fault state: {error}") from error
    try:
        _validate_file(os.fstat(fd), mode=0o600, uid=_expected_uid(require_root), description="fault state")
    except BaseException:
        os.close(fd)
        raise
    try:
        with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ProviderError(f"cannot read durable fault state: {error}") from error
    if not isinstance(value, dict) or value.get("schemaVersion") != SCHEMA_VERSION:
        raise ProviderError("fault state has an unsupported schema")
    return value

def _request_from_state(state: dict) -> Request:
    raw = state.get("request")
    if not isinstance(raw, dict):
        raise ProviderError("fault state lacks a request")
    try:
        request = Request(**raw)
    except TypeError as error:
        raise ProviderError("fault state request is malformed") from error
    validate_request(request)
    return request


def _same_request(left: Request, right: Request) -> bool:
    return left == right


def _receipt(state: dict) -> dict:
    required = ("operationID", "role", "guestID", "peerAddress", "durationMilliseconds",
                "bootID", "installedAtMonotonicMs", "restoredAtMonotonicMs", "restored")
    if any(key not in state for key in required) or state["restored"] is not True:
        raise ProviderError("fault state has no terminal restoration receipt")
    if not isinstance(state["installedAtMonotonicMs"], int) or not isinstance(state["restoredAtMonotonicMs"], int) or state["installedAtMonotonicMs"] >= state["restoredAtMonotonicMs"]:
        raise ProviderError("fault receipt monotonic timestamps are not strictly ordered")
    return {key: state[key] for key in required}


def _reject_colliding_active_state(directory_fd: int, request: Request, *, require_root: bool) -> None:
    for name in os.listdir(directory_fd):
        if not name.startswith("physical-fault-") or not name.endswith(".json"):
            continue
        if name == _state_name(request.operationID):
            continue
        state = _read_state(directory_fd, name, require_root=require_root)
        if state is None or state.get("restored") is True:
            continue
        existing = _request_from_state(state)
        if existing.role == request.role and existing.guestID == request.guestID and existing.peerAddress == request.peerAddress:
            raise ProviderError("refusing colliding active peer-host fault state")


def _complete_active(state: dict, directory_fd: int, name: str, request: Request, ip_binary: str,
                     now: Callable[[], int], sleep: Callable[[float], None], *, require_root: bool) -> dict:
    installed = state.get("installedAtMonotonicMs")
    if not isinstance(installed, int) or installed <= 0:
        raise ProviderError("active fault state lacks an installation timestamp")
    metric = _state_route_metric(state, request)
    if not _route_is_ours(_route_entries(ip_binary, request.prefix), request.prefix, metric):
        # The durable intent is written before route add.  If a crash happened
        # before the add, or a competing route won that add race, there is no
        # owned route to clean up.  Never delete a merely matching peer route.
        if state.get("installIntent") is True and state.get("routeInstalled") is False:
            return _mark_restored(state, directory_fd, name, installed, now, require_root=require_root)
        raise ProviderError("active fault state does not own the expected blackhole route")
    remaining = request.durationMilliseconds - (now() - installed)
    if remaining > 0:
        sleep(remaining / 1000.0)
    _remove(ip_binary, request, metric)
    return _mark_restored(state, directory_fd, name, installed, now, require_root=require_root)


def execute(request: Request, state_root: Path, ip_binary: str, *, require_root: bool = True,
            boot_id: Optional[str] = None, now: Callable[[], int] = lambda: time.monotonic_ns() // 1_000_000,
            sleep: Callable[[float], None] = time.sleep) -> dict:
    validate_request(request)
    if require_root and os.geteuid() != 0:
        raise ProviderError("physical fault provider requires root")
    current_boot = boot_id or boot_identity()
    directory_fd = _open_state_root(state_root, require_root)
    try:
        lock_fd = _open_lock(directory_fd, require_root)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            name = _state_name(request.operationID)
            state = _read_state(directory_fd, name, require_root=require_root)
            if state is not None:
                recorded = _request_from_state(state)
                if not _same_request(recorded, request):
                    raise ProviderError("operationID replay does not exactly match durable request")
                if state.get("bootID") != current_boot:
                    raise ProviderError("refusing state from a different boot identity")
                if state.get("restored") is True:
                    if _route_entries(ip_binary, request.prefix):
                        raise ProviderError("restored state collides with a live peer-host route")
                    return _receipt(state)
                return _complete_active(state, directory_fd, name, request, ip_binary, now, sleep,
                                        require_root=require_root)

            _reject_colliding_active_state(directory_fd, request, require_root=require_root)
            _ensure_no_route(ip_binary, request)
            installed = now()
            if installed <= 0:
                raise ProviderError("monotonic clock is unavailable")
            metric = _route_metric(request.operationID)
            state = {"schemaVersion": SCHEMA_VERSION, "request": asdict(request), "operationID": request.operationID,
                     "role": request.role, "guestID": request.guestID, "peerAddress": request.peerAddress,
                     "durationMilliseconds": request.durationMilliseconds, "bootID": current_boot,
                     "installedAtMonotonicMs": installed, "routeMetric": metric,
                     "installIntent": True, "routeInstalled": False, "restored": False}
            installed_route = False
            prior_handlers = {}
            blocked = set()
            def interrupted(signum, _frame):
                raise ProviderInterrupted(f"interrupted by signal {signum}")
            try:
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    prior_handlers[signum] = signal.signal(signum, interrupted)
                # No handled signal may arrive from the durable install intent through
                # the post-add state commit. SIGKILL/power loss is covered by that
                # durable intent, which contains the exact route ownership token.
                blocked = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
                signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
                _atomic_write(directory_fd, name, state, require_root=require_root)
                # Route-add is the ownership boundary.  If a competing owner
                # wins after our precheck, `ip route add` fails and we must not
                # remove its matching-looking route.  Once our add succeeds we
                # own cleanup even if the verification or durable write fails.
                _ensure_no_route(ip_binary, request)
                _run_ip(ip_binary, ["route", "add", "blackhole", request.prefix,
                                    "proto", ROUTE_PROTOCOL, "metric", str(metric)])
                installed_route = True
                if not _route_is_ours(_route_entries(ip_binary, request.prefix), request.prefix, metric):
                    raise ProviderError("blackhole route installation could not be verified")
                state["routeInstalled"] = True
                _atomic_write(directory_fd, name, state, require_root=require_root)
                signal.pthread_sigmask(signal.SIG_UNBLOCK, blocked)
                blocked = set()
                return _complete_active(state, directory_fd, name, request, ip_binary, now, sleep,
                                        require_root=require_root)
            finally:
                if installed_route:
                    # A signal or executor failure after install must attempt the same
                    # verified cleanup before propagating the failure.
                    try:
                        entries = _route_entries(ip_binary, request.prefix)
                        if _route_is_ours(entries, request.prefix, metric):
                            _remove(ip_binary, request, metric)
                        elif entries:
                            raise ProviderError("route changed before provider cleanup")
                        if state.get("restored") is not True:
                            _mark_restored(state, directory_fd, name, installed, now, require_root=require_root)
                    except ProviderError:
                        # Preserve active durable state for a fail-closed same-boot retry.
                        pass
                for signum, handler in prior_handlers.items():
                    signal.signal(signum, handler)
                if blocked:
                    signal.pthread_sigmask(signal.SIG_UNBLOCK, blocked)
        finally:
            os.close(lock_fd)
    finally:
        os.close(directory_fd)


def query(request: Request, state_root: Path, *, boot_id: Optional[str] = None,
          require_root: bool = False) -> dict:
    validate_request(request)
    directory_fd = _open_state_root(state_root, require_root)
    try:
        state = _read_state(directory_fd, _state_name(request.operationID), require_root=require_root)
    finally:
        os.close(directory_fd)
    if state is None or not _same_request(_request_from_state(state), request):
        raise ProviderError("no exact durable fault request exists")
    if boot_id is not None and state.get("bootID") != boot_id:
        raise ProviderError("fault state is from a different boot identity")
    return _receipt(state) if state.get("restored") is True else dict(state)


def remove(request: Request, state_root: Path, ip_binary: str, *, require_root: bool = True,
           boot_id: Optional[str] = None, now: Callable[[], int] = lambda: time.monotonic_ns() // 1_000_000) -> dict:
    # Removal is intentionally an exact-idempotent execute retry, except it does
    # not wait for the requested window.  It is used only for caller-requested
    # emergency cleanup and still proves restored=true.
    validate_request(request)
    if require_root and os.geteuid() != 0:
        raise ProviderError("physical fault provider requires root")
    directory_fd = _open_state_root(state_root, require_root)
    try:
        lock_fd = _open_lock(directory_fd, require_root)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            name = _state_name(request.operationID)
            state = _read_state(directory_fd, name, require_root=require_root)
            if state is None or not _same_request(_request_from_state(state), request):
                raise ProviderError("no exact durable fault request exists")
            if state.get("bootID") != (boot_id or boot_identity()):
                raise ProviderError("refusing state from a different boot identity")
            if state.get("restored") is True:
                return _receipt(state)
            installed = state.get("installedAtMonotonicMs")
            if not isinstance(installed, int) or installed <= 0:
                raise ProviderError("active fault state lacks an installation timestamp")
            metric = _state_route_metric(state, request)
            if not _remove_our_route_if_present(ip_binary, request, metric):
                if not (state.get("installIntent") is True and state.get("routeInstalled") is False):
                    raise ProviderError("active fault state does not own the expected blackhole route")
            return _mark_restored(state, directory_fd, name, installed, now, require_root=require_root)
        finally:
            os.close(lock_fd)
    finally:
        os.close(directory_fd)


def _request_from_args(args: argparse.Namespace) -> Request:
    return Request(args.operation_id, args.role, args.guest_id, args.peer_address, args.duration_ms)


def _system_ip_binary() -> str:
    for candidate in ("/sbin/ip", "/usr/sbin/ip", "/usr/bin/ip"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise ProviderError("no fixed system ip executable is available")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("execute", "query", "remove"))
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--guest-id", required=True)
    parser.add_argument("--peer-address", required=True)
    parser.add_argument("--duration-ms", required=True, type=int)
    args = parser.parse_args(argv)
    request = _request_from_args(args)
    try:
        # The executable path is deliberately fixed; tests call the functions
        # directly with a fake binary rather than weakening the CLI boundary.
        ip_binary = _system_ip_binary()
        root = Path(args.state_root)
        if args.command == "execute": result = execute(request, root, ip_binary)
        elif args.command == "query": result = query(request, root, boot_id=boot_identity(), require_root=True)
        else: result = remove(request, root, ip_binary)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except ProviderError as error:
        print(f"physical fault provider rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
