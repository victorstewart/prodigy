#!/usr/bin/env python3
"""Unit tests for the sealed physical fault provider; never alters networking."""
import importlib.util
import json
import os
import signal
import stat
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


PROVIDER = Path(__file__).parents[2] / "mothership" / "mothership.physical.fault.provider.py"
GUEST = "abcdef0123456789abcdef0123456789"
SPEC = importlib.util.spec_from_file_location("physical_fault_provider", PROVIDER)
provider = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = provider
SPEC.loader.exec_module(provider)


class Clock:
    def __init__(self): self.value = 100
    def now(self): return self.value
    def sleep(self, seconds): self.value += max(1, int(seconds * 1000))


class PhysicalFaultProviderUnit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "state"
        self.root.mkdir(mode=0o700)
        self.ip_state = Path(self.temp.name) / "routes.json"
        self.ip_state.write_text("[]")
        self.ip = Path(self.temp.name) / "ip"
        self.ip.write_text("""#!/usr/bin/env python3
import json, os, sys
p=os.environ['FAKE_IP_STATE']; routes=json.load(open(p))
a=sys.argv[1:]
if a[:4] == ['-j','route','show','exact']:
 print(json.dumps([r for r in routes if r['dst'].split('/')[0] == a[4].split('/')[0]])); raise SystemExit(0)
if a[:3] == ['route','add','blackhole']:
 dst=a[3].split('/')[0]
 if routes: raise SystemExit(9)
 metric=a[a.index('metric')+1]
 routes.append({'dst':dst,'type':'blackhole','protocol':'186','metric':metric}); json.dump(routes,open(p,'w')); raise SystemExit(0)
if a[:3] == ['route','del','blackhole']:
 dst=a[3].split('/')[0]; metric=a[a.index('metric')+1]
 routes=[r for r in routes if not (r['dst'].split('/')[0] == dst and str(r.get('metric')) == metric)]
 json.dump(routes,open(p,'w')); raise SystemExit(0)
raise SystemExit(8)
""")
        self.ip.chmod(0o700)
        self.environment = os.environ.copy(); self.environment["FAKE_IP_STATE"] = str(self.ip_state)
        self.old = os.environ.get("FAKE_IP_STATE"); os.environ["FAKE_IP_STATE"] = str(self.ip_state)
        self.clock = Clock()
        self.request = provider.Request("0123456789abcdef0123456789abcdef", "source", GUEST, "198.51.100.9", 10)
        self.boot = "01234567-89ab-cdef-0123-456789abcdef"

    def tearDown(self):
        if self.old is None: os.environ.pop("FAKE_IP_STATE", None)
        else: os.environ["FAKE_IP_STATE"] = self.old
        self.temp.cleanup()

    def execute(self):
        return provider.execute(self.request, self.root, str(self.ip), require_root=False, boot_id=self.boot,
                                now=self.clock.now, sleep=self.clock.sleep)

    def apply(self):
        return provider.apply(self.request, self.root, str(self.ip), require_root=False, boot_id=self.boot,
                              now=self.clock.now)

    def test_execute_compatibility_holds_window_and_restores(self):
        receipt = self.execute()
        self.assertTrue(receipt["restored"])
        self.assertGreaterEqual(receipt["restoredAtMonotonicMs"] - receipt["installedAtMonotonicMs"],
                                self.request.durationMilliseconds)
        self.assertEqual(json.loads(self.ip_state.read_text()), [])

    def test_apply_is_nonblocking_and_deadline_query_auto_restores(self):
        receipt = self.apply()
        self.assertEqual(receipt["phase"], "applied")
        self.assertTrue(receipt["authenticated"])
        self.assertFalse(receipt["restored"])
        self.assertEqual(receipt["gatewayEndpoint"], self.request.peerAddress)
        self.assertEqual(receipt["flowTarget"], "peer-host")
        self.assertEqual(receipt["flowIdentity"], "host:" + self.request.peerAddress)
        self.assertNotEqual(json.loads(self.ip_state.read_text()), [])
        self.assertEqual(provider.query(self.request, self.root, boot_id=self.boot,
                                        now=self.clock.now)["phase"], "applied")
        self.clock.value = receipt["autoRestoreDeadlineMonotonicMs"] + 1
        restored = provider.query(self.request, self.root, boot_id=self.boot, require_root=False,
                                  ip_binary=str(self.ip), now=self.clock.now)
        self.assertTrue(restored["restored"])
        self.assertLess(restored["installedAtMonotonicMs"], restored["restoredAtMonotonicMs"])
        self.assertEqual(json.loads(self.ip_state.read_text()), [])
        path = self.root / f"physical-fault-{self.request.operationID}.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(provider.query(self.request, self.root, boot_id=self.boot), restored)

    def test_iproute_host_destination_rendering_is_canonicalized(self):
        metric = provider._route_metric(self.request.operationID)
        base = {"type": "blackhole", "protocol": "186", "metric": str(metric)}
        self.assertTrue(provider._entry_is_ours({**base, "dst": "198.51.100.9"},
                                                "198.51.100.9/32", metric))
        self.assertTrue(provider._entry_is_ours({**base, "dst": "2001:db8::9"},
                                                "2001:db8::9/128", metric))
        self.assertFalse(provider._entry_is_ours({**base, "dst": "198.51.100.0/24"},
                                                 "198.51.100.9/32", metric))

    def test_iproute_named_bgp_protocol_is_the_same_kernel_protocol(self):
        metric = provider._route_metric(self.request.operationID)
        self.assertTrue(provider._entry_is_ours(
            {"dst": "198.51.100.9", "type": "blackhole", "protocol": "bgp", "metric": metric},
            "198.51.100.9/32", metric))

    def test_exact_retry_is_idempotent_and_retarget_rejected(self):
        first = self.apply()
        self.assertEqual(self.apply(), first)
        changed = provider.Request(self.request.operationID, "source", GUEST, "198.51.100.10", 10)
        with self.assertRaisesRegex(provider.ProviderError, "does not exactly match"):
            provider.apply(changed, self.root, str(self.ip), require_root=False, boot_id=self.boot,
                           now=self.clock.now)
        changed_identity = provider.Request(self.request.operationID, "source", GUEST,
                                            self.request.peerAddress, 10, self.request.peerAddress,
                                            "peer-host", "masque:other-gateway")
        with self.assertRaisesRegex(provider.ProviderError, "does not exactly match"):
            provider.apply(changed_identity, self.root, str(self.ip), require_root=False,
                           boot_id=self.boot, now=self.clock.now)

    def test_preexisting_route_and_boot_mismatch_fail_closed(self):
        self.ip_state.write_text(json.dumps([{"dst":"198.51.100.9/32", "type":"unicast", "protocol":"kernel"}]))
        with self.assertRaisesRegex(provider.ProviderError, "pre-existing"):
            self.apply()
        # It is particularly important not to delete a matching-looking route
        # which was present before this request acquired install ownership.
        matching = [{"dst":"198.51.100.9/32", "type":"blackhole", "protocol":"186", "metric":"7"}]
        self.ip_state.write_text(json.dumps(matching))
        with self.assertRaisesRegex(provider.ProviderError, "pre-existing"):
            self.apply()
        self.assertEqual(json.loads(self.ip_state.read_text()), matching)
        self.ip_state.write_text("[]")
        self.apply()
        with self.assertRaisesRegex(provider.ProviderError, "different boot"):
            provider.apply(self.request, self.root, str(self.ip), require_root=False,
                           boot_id="11111111-1111-1111-1111-111111111111", now=self.clock.now)

    def test_competing_route_after_precheck_is_never_removed(self):
        real_check = provider._ensure_no_route
        checks = 0
        matching = [{"dst":"198.51.100.9/32", "type":"blackhole", "protocol":"186", "metric":"7"}]
        def race(ip_binary, request):
            nonlocal checks
            checks += 1
            if checks == 2:
                self.ip_state.write_text(json.dumps(matching))
            return real_check(ip_binary, request)
        with mock.patch.object(provider, "_ensure_no_route", side_effect=race):
            with self.assertRaisesRegex(provider.ProviderError, "pre-existing"):
                self.apply()
        self.assertEqual(checks, 2)
        self.assertEqual(json.loads(self.ip_state.read_text()), matching)

    def test_invalid_request_and_colliding_state_rejected(self):
        invalid = provider.Request("not-an-operation", "source", GUEST, "127.0.0.1", 0)
        with self.assertRaises(provider.ProviderError): provider.validate_request(invalid)
        for invalid_guest in ("guest-a", "0x" + GUEST, GUEST.upper(), GUEST[:-1], GUEST + "2"):
            invalid = provider.Request(self.request.operationID, "source", invalid_guest, "198.51.100.9", 10)
            with self.assertRaisesRegex(provider.ProviderError, "guestID must be exactly 32"):
                provider.validate_request(invalid)
        other = provider.Request("11111111111111111111111111111111", "source", GUEST, "198.51.100.9", 10)
        state = {"schemaVersion":provider.SCHEMA_VERSION, "request":provider.asdict(other), "operationID":other.operationID,
                 "role":other.role, "guestID":other.guestID, "peerAddress":other.peerAddress,
                 "durationMilliseconds":other.durationMilliseconds, "bootID":self.boot,
                 "installedAtMonotonicMs":100, "restored":False}
        directory_fd = provider._open_state_root(self.root, require_root=False)
        try:
            provider._atomic_write(directory_fd, provider._state_name(other.operationID), state,
                                   require_root=False)
        finally:
            os.close(directory_fd)
        with self.assertRaisesRegex(provider.ProviderError, "colliding active"):
            self.apply()

    def test_state_root_and_lock_reject_symlinks_or_unsafe_files(self):
        unsafe = Path(self.temp.name) / "unsafe"
        unsafe.mkdir(mode=0o755)
        with self.assertRaisesRegex(provider.ProviderError, "permissions or ownership"):
            provider.apply(self.request, unsafe, str(self.ip), require_root=False,
                           boot_id=self.boot, now=self.clock.now)
        lock = self.root / ".physical-fault.lock"
        lock.symlink_to(self.ip_state)
        with self.assertRaisesRegex(provider.ProviderError, "fault lock"):
            self.apply()

    def test_fresh_state_directory_is_provisioned_only_below_a_safe_parent(self):
        fresh = Path(self.temp.name) / "fresh-state"
        self.assertFalse(fresh.exists())
        receipt = provider.apply(self.request, fresh, str(self.ip), require_root=False,
                                 boot_id=self.boot, now=self.clock.now)
        self.assertEqual(receipt["phase"], "applied")
        self.assertEqual(stat.S_IMODE(fresh.stat().st_mode), 0o700)

        unsafe_parent = Path(self.temp.name) / "unsafe-parent"
        unsafe_parent.mkdir(mode=0o700)
        unsafe_parent.chmod(0o770)
        with self.assertRaisesRegex(provider.ProviderError, "state parent permissions"):
            provider.apply(self.request, unsafe_parent / "state", str(self.ip), require_root=False,
                           boot_id=self.boot, now=self.clock.now)

    def test_root_mode_accepts_only_and_provisions_the_fixed_state_directory(self):
        fixed_parent = Path(self.temp.name) / "fixed-parent"
        fixed_root = fixed_parent / "physical-faults"
        with self.assertRaisesRegex(provider.ProviderError, "not the fixed"):
            provider._open_state_root(self.root, require_root=True)
        with mock.patch.object(provider, "FIXED_STATE_ROOT", fixed_root), \
             mock.patch.object(provider, "FIXED_STATE_PARENT", fixed_parent), \
             mock.patch.object(provider, "FIXED_STATE_GRANDPARENT", fixed_parent.parent), \
             mock.patch.object(provider, "_expected_uid", return_value=os.geteuid()):
            directory_fd = provider._open_state_root(fixed_root, require_root=True)
        try:
            self.assertEqual(stat.S_IMODE(os.fstat(directory_fd).st_mode), 0o700)
        finally:
            os.close(directory_fd)

    def test_recovery_from_post_add_journal_gap_removes_only_its_exact_route(self):
        metric = provider._route_metric(self.request.operationID)
        intent = {"schemaVersion": provider.SCHEMA_VERSION, "request": provider.asdict(self.request),
                  "operationID": self.request.operationID, "role": self.request.role,
                  "guestID": self.request.guestID, "peerAddress": self.request.peerAddress,
                  "gatewayEndpoint": self.request.peerAddress,
                  "flowTarget": "peer-host", "flowIdentity": "host:" + self.request.peerAddress,
                  "durationMilliseconds": self.request.durationMilliseconds, "bootID": self.boot,
                  "installedAtMonotonicMs": 100, "routeMetric": metric,
                  "autoRestoreDeadlineMonotonicMs": 110, "authenticated": True,
                  "installIntent": True, "routeInstalled": False, "restored": False}
        directory_fd = provider._open_state_root(self.root, require_root=False)
        try:
            provider._atomic_write(directory_fd, provider._state_name(self.request.operationID), intent,
                                   require_root=False)
        finally:
            os.close(directory_fd)
        competing = {"dst": self.request.prefix, "type": "blackhole", "protocol": "186", "metric": "7"}
        owned = {"dst": self.request.prefix, "type": "blackhole", "protocol": "186", "metric": str(metric)}
        self.ip_state.write_text(json.dumps([competing, owned]))
        self.clock.value = 111

        receipt = self.apply()

        self.assertTrue(receipt["restored"])
        self.assertEqual(json.loads(self.ip_state.read_text()), [competing])

    def test_route_install_is_masked_until_ownership_state_is_durable(self):
        calls = []
        real_write = provider._atomic_write
        def record_mask(how, signals):
            calls.append((how, set(signals)))
        def checked_write(*args, **kwargs):
            if args[1].startswith("physical-fault-") and args[2].get("restored") is False:
                self.assertTrue(calls)
                self.assertEqual(calls[-1][0], signal.SIG_BLOCK)
            return real_write(*args, **kwargs)
        with mock.patch.object(provider.signal, "pthread_sigmask", side_effect=record_mask), \
             mock.patch.object(provider, "_atomic_write", side_effect=checked_write):
            self.apply()
        self.assertEqual(calls[0][0], signal.SIG_BLOCK)
        self.assertEqual(calls[0][1], {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
        self.assertEqual(calls[1][0], signal.SIG_UNBLOCK)

    def test_state_symlink_is_rejected_by_dirfd_open(self):
        self.apply()
        path = self.root / f"physical-fault-{self.request.operationID}.json"
        path.unlink()
        path.symlink_to(self.ip_state)
        with self.assertRaisesRegex(provider.ProviderError, "cannot read durable"):
            provider.query(self.request, self.root, boot_id=self.boot)


if __name__ == "__main__":
    unittest.main()
