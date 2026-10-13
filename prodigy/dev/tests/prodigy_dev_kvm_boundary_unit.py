#!/usr/bin/env python3
"""No-QEMU safety tests for the disposable KVM boundary launcher."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name("prodigy_dev_kvm_boundary.py")
SPEC = importlib.util.spec_from_file_location("prodigy_dev_kvm_boundary", SOURCE)
assert SPEC and SPEC.loader
KVM = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(KVM)


class KvmBoundaryUnit(unittest.TestCase):
    def arguments(self, root: Path, *command: str, egress: str = "isolated", disk_size_gb: int | None = None,
                  lan: tuple[str, str, str] | None = None, udp_links: tuple[str, ...] = (), wan_mac: str | None = None):
        files = {}
        for name in ("base.qcow2", "OVMF_CODE.fd", "OVMF_VARS.fd", "known_hosts", "key"):
            files[name] = root / name; files[name].write_bytes(b"pinned-" + name.encode()); files[name].chmod(0o400)
        disk = [] if disk_size_gb is None else ["--disk-size-gb", str(disk_size_gb)]
        lan_args = [] if lan is None else ["--lan-mcast", lan[0], "--lan-local-address", lan[1], "--lan-mac", lan[2]]
        udp_args = [part for link in udp_links for part in ("--lan-udp-link", link)]
        wan_args = [] if wan_mac is None else ["--wan-mac", wan_mac]
        if udp_links and lan is None:
            lan_args = ["--lan-mac", "02:06:00:00:00:01"]
        return KVM.parse_args(["--base-image", str(files["base.qcow2"]), "--base-sha256", KVM.digest(files["base.qcow2"]), "--ovmf-code", str(files["OVMF_CODE.fd"]), "--ovmf-code-sha256", KVM.digest(files["OVMF_CODE.fd"]), "--ovmf-vars", str(files["OVMF_VARS.fd"]), "--ovmf-vars-sha256", KVM.digest(files["OVMF_VARS.fd"]), "--guest-uuid", "12345678-1234-4234-9234-123456789abc", "--expected-machine-id", "0123456789abcdef0123456789abcdef", "--known-hosts", str(files["known_hosts"]), "--ssh-private-key", str(files["key"]), "--ssh-port", "22222", "--work-dir", str(root / "work"), "--evidence-dir", str(root / "evidence"), "--guest-egress", egress, *disk, *wan_args, *lan_args, *udp_args, "--", *command])

    def test_command_requires_kvm_uefi_uuid_and_loopback_only(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "echo", "ok")
            rendered = " ".join(KVM.qemu_command(args, Path(directory) / "overlay.qcow2", Path(directory) / "vars.fd"))
        self.assertIn("-accel kvm", rendered); self.assertIn("-machine q35", rendered); self.assertIn("-uuid 12345678-1234-4234-9234-123456789abc", rendered)
        self.assertIn("hostfwd=tcp:127.0.0.1:22222-:22", rendered); self.assertIn("restrict=on", rendered); self.assertIn("if=pflash", rendered)
        self.assertIn("virtio-net-pci,netdev=guestnet,mac=02:12:34:56:78:12", rendered)
        self.assertNotIn("tcg", rendered.lower()); self.assertNotIn("tap", rendered.lower()); self.assertNotIn("bridge", rendered.lower())

    def test_all_persistent_qemu_launches_detach_from_the_ssh_session(self):
        source = SOURCE.read_text()
        launches = source.count("subprocess.Popen(command")
        self.assertEqual(launches, 2)
        self.assertEqual(source.count("start_new_session=True"), launches)

    def test_explicit_wan_egress_removes_only_default_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "true", egress="wan")
            rendered = " ".join(KVM.qemu_command(args, Path(directory) / "overlay", Path(directory) / "vars"))
        self.assertIn("hostfwd=tcp:127.0.0.1:22222-:22", rendered); self.assertNotIn("restrict=on", rendered)

    def test_wan_mac_is_deterministic_or_a_bounded_explicit_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            default = root / "default"; default.mkdir()
            explicit = root / "explicit"; explicit.mkdir()
            invalid = root / "invalid"; invalid.mkdir()
            self.assertEqual(self.arguments(default, "true").wan_mac, "02:12:34:56:78:12")
            self.assertEqual(self.arguments(explicit, "true", wan_mac="02:06:00:00:00:02").wan_mac, "02:06:00:00:00:02")
            with self.assertRaises(KVM.BoundaryError):
                self.arguments(invalid, "true", wan_mac="00:06:00:00:00:02")

    def test_optional_lan_is_socket_multicast_without_host_interface_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "true", lan=("239.192.6.1:31661", "10.0.0.22", "02:06:00:00:00:01"))
            rendered = " ".join(KVM.qemu_command(args, Path(directory) / "overlay", Path(directory) / "vars"))
        self.assertIn("socket,id=clusterlan,mcast=239.192.6.1:31661,localaddr=10.0.0.22", rendered)
        self.assertIn("virtio-net-pci,netdev=clusterlan,mac=02:06:00:00:00:01", rendered)
        self.assertNotIn("tap", rendered); self.assertNotIn("bridge", rendered)

    def test_udp_center_lan_renders_two_exact_links_through_one_guest_nic(self):
        links = ("10.0.0.11:31661=10.0.0.12:31661", "10.0.0.11:31662=10.0.0.13:31661")
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "true", udp_links=links)
            network = KVM.persistent_network(args)
            rendered = " ".join(KVM.qemu_command(args, Path(directory) / "overlay", Path(directory) / "vars"))
        self.assertEqual(network["netdevs"], [
            "user,restrict=on,id=guestnet,hostfwd=tcp:127.0.0.1:22222-:22",
            "socket,id=clusterlink0,udp=10.0.0.12:31661,localaddr=10.0.0.11:31661",
            "hubport,id=clusterhub0,hubid=0,netdev=clusterlink0",
            "socket,id=clusterlink1,udp=10.0.0.13:31661,localaddr=10.0.0.11:31662",
            "hubport,id=clusterhub1,hubid=0,netdev=clusterlink1",
            "hubport,id=clusterlan,hubid=0",
        ])
        self.assertIn("virtio-net-pci,netdev=clusterlan,mac=02:06:00:00:00:01", rendered)
        self.assertNotIn("tap", rendered); self.assertNotIn("bridge", rendered)

    def test_udp_leaf_lan_and_saved_network_are_exactly_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            args = self.arguments(root, "true", udp_links=("10.0.0.12:31661=10.0.0.11:31661",))
            network = KVM.persistent_network(args)
            command = KVM.qemu_command(args, root / "overlay", root / "vars")
            KVM.validate_persistent_network(command, network)
            record = {"taskID": "g6-local", "qemuPID": 42, "qemuStarttime": "7", "qemuCommand": command,
                      "overlay": str(root / "overlay"), "ovmfVars": str(root / "vars"),
                      "guestUUID": "12345678-1234-4234-9234-123456789abc", "machineID": "0" * 32,
                      "qmpSocket": str(root / "guest.qmp"), "network": network,
                      "boundaryVerification": {"knownHosts": str(root / "known_hosts"), "sshPrivateKey": str(root / "key"),
                                               "sshUser": "root", "sshPort": 22222, "bootTimeout": 30,
                                               "guestUUID": "12345678-1234-4234-9234-123456789abc",
                                               "machineID": "0" * 32, "hostMachineID": "f" * 32}}
            state = root / "udp.state"; KVM.write_persistent_state(state, record)
            self.assertEqual(KVM.load_persistent_state(state, "g6-local")["network"], network)
            tampered = dict(network); tampered["netdevs"] = list(network["netdevs"]); tampered["netdevs"][1] = "socket,id=clusterlink0,udp=10.0.0.99:31661,localaddr=10.0.0.12:31661"
            with self.assertRaises(KVM.BoundaryError):
                KVM.validate_persistent_network(command, tampered)
            record["network"] = tampered; KVM.write_persistent_state(state, record)
            with self.assertRaises(KVM.BoundaryError):
                KVM.load_persistent_state(state, "g6-local")
        self.assertEqual(network["netdevs"][-1], "hubport,id=clusterlan,hubid=0")

    def test_lan_socket_parameters_are_atomic_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"; first.mkdir()
            with self.assertRaises(KVM.BoundaryError):
                self.arguments(first, "true", lan=("192.0.2.1:31661", "10.0.0.22", "02:06:00:00:00:01"))
            second = root / "second"; second.mkdir()
            with self.assertRaises(KVM.BoundaryError):
                self.arguments(second, "true", lan=("239.192.6.1:31661", "10.0.0.22", "00:06:00:00:00:01"))
            for index, local in enumerate(("127.0.0.1", "169.254.1.1", "255.255.255.255")):
                candidate = root / f"unsafe-{index}"; candidate.mkdir()
                with self.assertRaises(KVM.BoundaryError):
                    self.arguments(candidate, "true", lan=("239.192.6.1:31661", local, "02:06:00:00:00:01"))

    def test_udp_lan_rejects_multicast_mixed_unsafe_duplicate_and_excess_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = [
                {"lan": ("239.192.6.1:31661", "10.0.0.22", "02:06:00:00:00:01"), "udp_links": ("10.0.0.11:31661=10.0.0.12:31661",)},
                {"udp_links": ("127.0.0.1:31661=10.0.0.12:31661",)},
                {"udp_links": ("10.0.0.11:31661=10.0.0.11:31661",)},
                {"udp_links": ("10.0.0.11:31661=10.0.0.12:31661", "10.0.0.11:31661=10.0.0.13:31661")},
                {"udp_links": tuple(f"10.0.0.11:{31661 + index}=10.0.0.{12 + index}:31661" for index in range(5))},
            ]
            for index, options in enumerate(cases):
                candidate = root / str(index); candidate.mkdir()
                with self.subTest(options=options), self.assertRaises(KVM.BoundaryError):
                    self.arguments(candidate, "true", **options)

    def test_persistent_network_allows_only_exact_user_and_optional_socket_lan(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "true", lan=("239.192.6.1:31661", "10.0.0.22", "02:06:00:00:00:01"))
            expected = KVM.persistent_network(args)
            KVM.validate_persistent_network(KVM.qemu_command(args, Path(directory) / "overlay", Path(directory) / "vars"), expected)

    def test_persistent_network_rejects_host_backends_and_extra_netdevs(self):
        expected = {"netdevs": ["user,id=guestnet,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22"],
                    "devices": ["virtio-net-pci,netdev=guestnet"]}
        cases = [
            ["qemu", "-netdev", expected["netdevs"][0], "-device", expected["devices"][0], "-netdev", "tap,id=evil,ifname=eth0"],
            ["qemu", "-net", "bridge,br=br0"],
            ["qemu", "-nic", "tap,ifname=eth0"],
            ["qemu", "-netdev", "user,id=guestnet,helper=/tmp/helper", "-device", expected["devices"][0]],
            ["qemu", "-netdev", expected["netdevs"][0], "-device", "e1000,netdev=guestnet"],
        ]
        for command in cases:
            with self.subTest(command=command), self.assertRaises(KVM.BoundaryError):
                KVM.validate_persistent_network(command, expected)

    def test_guest_script_is_one_quoted_remote_command_and_exact_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "echo", "space here")
            with mock.patch.object(KVM.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")) as run:
                KVM.guest_run(args, "line one\nline two", 3)
        self.assertEqual(run.call_args.args[0][-1], KVM.shlex.join(["sh", "-ceu", "line one\nline two"]))
        self.assertEqual(KVM.MARKER, "/run/prodigy-disposable-linux"); self.assertEqual(KVM.MARKER_CONTENT, "prodigy-disposable-linux-v1")

    def test_cleanup_identity_mismatch_preserves_overlay_and_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            overlay, vars_copy = Path(directory) / "overlay", Path(directory) / "vars"; overlay.write_bytes(b"x"); vars_copy.write_bytes(b"x")
            process, receipt = mock.Mock(pid=12), {}; process.poll.return_value = None
            with mock.patch.object(KVM, "process_is_owned", return_value=False): self.assertFalse(KVM.cleanup_qemu(process, "1", overlay, vars_copy, receipt))
            process.terminate.assert_not_called(); self.assertTrue(overlay.exists()); self.assertTrue(vars_copy.exists()); self.assertFalse(receipt["cleanupSuccess"])

    def test_cleanup_known_exited_child_removes_owned_files_without_proc_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            overlay, vars_copy = Path(directory) / "overlay", Path(directory) / "vars"; overlay.write_bytes(b"x"); vars_copy.write_bytes(b"x")
            process, receipt = mock.Mock(pid=12), {}; process.poll.return_value = 0
            with mock.patch.object(KVM, "process_is_owned", return_value=False): self.assertTrue(KVM.cleanup_qemu(process, "1", overlay, vars_copy, receipt))
            process.terminate.assert_not_called(); self.assertFalse(overlay.exists()); self.assertTrue(receipt["qemuExited"])

    def test_disk_resize_is_bounded_and_only_follows_overlay_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); args = self.arguments(root, "true", disk_size_gb=12); args.base_image = root / "base.qcow2"
            overlay = root / "work" / "overlay.qcow2"
            with mock.patch.object(KVM.subprocess, "run") as run:
                KVM.create_overlay(args, overlay)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args_list[0].args[0][:4], [args.qemu_img, "create", "-f", "qcow2"])
            self.assertEqual(run.call_args_list[1].args[0], [args.qemu_img, "resize", str(overlay), "12G"])

    def test_wait_for_guest_stops_when_known_qemu_child_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "true"); process = mock.Mock(); process.poll.return_value = 17; process.returncode = 17
            with self.assertRaisesRegex(KVM.BoundaryError, "QEMU exited during boot"):
                KVM.wait_for_guest(args, process)

    def test_kernel_and_initrd_pins_are_an_atomic_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(KVM.BoundaryError): KVM.parse_args(["--base-image", "a", "--base-sha256", "0" * 64, "--ovmf-code", "b", "--ovmf-code-sha256", "0" * 64, "--ovmf-vars", "c", "--ovmf-vars-sha256", "0" * 64, "--guest-uuid", "12345678-1234-4234-9234-123456789abc", "--expected-machine-id", "0" * 32, "--known-hosts", "k", "--ssh-private-key", "p", "--ssh-port", "22222", "--work-dir", str(root), "--evidence-dir", str(root), "--kernel", "kernel", "--", "true"])

    def test_base_validation_rejects_a_symlink_and_a_writable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / "target"; target.write_bytes(b"base")
            link = root / "base-link"; link.symlink_to(target)
            with self.assertRaises(KVM.BoundaryError): KVM.safe_path(link, "base image", True)
            with self.assertRaises(KVM.BoundaryError): KVM.safe_path(target, "base image", True)

    def test_work_and_evidence_paths_reject_qemu_option_separators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(KVM.BoundaryError): KVM.safe_directory(root / "work,bad", "work directory")
            with self.assertRaises(KVM.BoundaryError): KVM.safe_directory(root / "evidence\nbad", "evidence directory")

    def test_disk_size_is_limited_to_private_overlay_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for size in (1, 129):
                isolated = root / str(size); isolated.mkdir()
                with self.assertRaises(KVM.BoundaryError): self.arguments(isolated, "true", disk_size_gb=size)

    def test_persistent_state_is_private_and_bound_to_its_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700); state = root / "guest.state"
            record = {"taskID": "g6-local", "qemuPID": 42, "qemuStarttime": "7", "qemuCommand": ["qemu-system-x86_64", "-netdev", "user,id=guestnet,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22", "-device", "virtio-net-pci,netdev=guestnet"], "overlay": str(root / "overlay"), "ovmfVars": str(root / "vars"), "guestUUID": "12345678-1234-4234-9234-123456789abc", "machineID": "0" * 32, "qmpSocket": str(root / "guest.qmp"), "network": {"netdevs": ["user,id=guestnet,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22"], "devices": ["virtio-net-pci,netdev=guestnet"]}, "boundaryVerification": {"knownHosts": str(root / "known_hosts"), "sshPrivateKey": str(root / "key"), "sshUser": "root", "sshPort": 2222, "bootTimeout": 30, "guestUUID": "12345678-1234-4234-9234-123456789abc", "machineID": "0" * 32, "hostMachineID": "f" * 32}}
            KVM.write_persistent_state(state, record)
            self.assertEqual(KVM.stat.S_IMODE(state.stat().st_mode), 0o600)
            self.assertEqual(KVM.load_persistent_state(state, "g6-local")["qemuPID"], 42)
            with self.assertRaisesRegex(KVM.BoundaryError, "task identity"):
                KVM.load_persistent_state(state, "different-task")

    def test_lifecycle_requires_explicit_private_state_and_task_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            operation, state, task, rest = KVM.lifecycle_arguments(["query", "--state", str(root / "state"), "--task-id", "g6-local"])
            self.assertEqual((operation, state, task, rest), ("query", (root / "state").resolve(), "g6-local", []))
            with self.assertRaises(KVM.BoundaryError):
                KVM.lifecycle_arguments(["query", "--state", str(root / "state"), "--task-id", "BAD_TASK"])

    def test_task_state_lock_is_private_nonblocking_and_not_inherited_by_qemu(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700); state = root / "state"
            with KVM.task_state_lock(state):
                lock = root / "state.lock"
                self.assertEqual(KVM.stat.S_IMODE(lock.stat().st_mode), 0o600)
                with mock.patch.object(KVM.fcntl, "flock", side_effect=BlockingIOError):
                    with self.assertRaisesRegex(KVM.BoundaryError, "another lifecycle operation"):
                        with KVM.task_state_lock(state): pass
        self.assertIn("with task_state_lock(state_path):", SOURCE.read_text())

    def test_persistent_launch_validates_cidata_and_kernel_inputs_before_qemu(self):
        source = SOURCE.read_text()
        lifecycle = source[source.index("def _lifecycle_main"):source.index("def lifecycle_main", source.index("def _lifecycle_main"))]
        self.assertIn('safe_path(args.cidata, "cidata", True)', lifecycle)
        self.assertIn('pinned(args.kernel, args.kernel_sha256, "kernel", True)', lifecycle)
        self.assertIn('pinned(args.initrd, args.initrd_sha256, "initrd", True)', lifecycle)

    def test_persistent_qemu_command_requires_exact_pid_starttime_and_argv(self):
        with mock.patch.object(KVM, "proc_starttime", return_value="99"), mock.patch.object(KVM.Path, "read_bytes", return_value=b"qemu\0-enable-kvm\0"):
            self.assertTrue(KVM.command_matches(5, "99", ["qemu", "-enable-kvm"]))
        with mock.patch.object(KVM, "proc_starttime", return_value="99"), mock.patch.object(KVM.Path, "read_bytes", return_value=b"qemu\0-tcg\0"):
            self.assertFalse(KVM.command_matches(5, "99", ["qemu", "-enable-kvm"]))

    def test_remove_of_absent_private_state_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            self.assertEqual(KVM.lifecycle_main(["remove", "--state", str(root / "absent"), "--task-id", "g6-local"]), 0)

    def test_persistent_stop_falls_back_to_exact_identity_checked_signals(self):
        record = {"qemuPID": 42, "qemuStarttime": "99", "qemuCommand": ["qemu", "-accel", "kvm"],
                  "qmpSocket": "/private/qmp"}
        observations = iter(["99"] * 101 + ["99"] * 101 + [None])
        with mock.patch.object(KVM, "command_matches", return_value=True) as identity, \
             mock.patch.object(KVM, "qmp_quit") as qmp, \
             mock.patch.object(KVM, "proc_starttime", side_effect=lambda _pid: next(observations)), \
             mock.patch.object(KVM.time, "sleep"), \
             mock.patch.object(KVM.os, "kill") as kill:
            KVM.stop_persistent_qemu(record, "exact cleanup")
        qmp.assert_called_once_with("/private/qmp")
        self.assertEqual([call.args for call in kill.call_args_list],
                         [(42, KVM.signal.SIGTERM), (42, KVM.signal.SIGKILL)])
        self.assertEqual(identity.call_count, 3)

    def test_persistent_stop_never_signals_after_identity_change(self):
        record = {"qemuPID": 42, "qemuStarttime": "99", "qemuCommand": ["qemu", "-accel", "kvm"],
                  "qmpSocket": "/private/qmp"}
        with mock.patch.object(KVM, "command_matches", side_effect=[True, False]), \
             mock.patch.object(KVM, "qmp_quit"), \
             mock.patch.object(KVM, "proc_starttime", return_value="99"), \
             mock.patch.object(KVM.time, "sleep"), \
             mock.patch.object(KVM.os, "kill") as kill, \
             self.assertRaisesRegex(KVM.BoundaryError, "identity changed"):
            KVM.stop_persistent_qemu(record, "exact cleanup")
        kill.assert_not_called()

    def test_cold_reboot_receipt_is_exact_retry_identity(self):
        record = {"lastColdReboot": {"operationID": "1" * 32, "beforePID": 4, "beforeStarttime": "8",
                  "afterPID": 5, "afterStarttime": "9", "startedAtMonotonicMs": 10,
                  "completedAtMonotonicMs": 20, "completed": True}}
        self.assertIsNotNone(KVM.completed_cold_reboot(record, "1" * 32))
        self.assertIsNone(KVM.completed_cold_reboot(record, "2" * 32))
        record["lastColdReboot"]["completedAtMonotonicMs"] = 10
        with self.assertRaisesRegex(KVM.BoundaryError, "strictly ordered"):
            KVM.completed_cold_reboot(record, "1" * 32)

    def test_cold_reboot_survives_loss_of_the_rebooted_guests_ssh_session(self):
        with mock.patch.object(KVM.signal, "signal") as install:
            KVM.preserve_cold_reboot_after_session_loss()
        install.assert_called_once_with(KVM.signal.SIGHUP, KVM.signal.SIG_IGN)

    def test_incomplete_cold_reboot_retry_adopts_exact_live_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "boundary.json"
            pidfile = root / "qemu.pid"
            pidfile.write_text("55\n")
            operation = "1" * 32
            record = {"qemuPID": 42, "qemuStarttime": "old",
                      "qemuCommand": ["qemu", "-pidfile", str(pidfile)],
                      "qmpSocket": str(root / "qmp.sock"),
                      "lastColdReboot": {"operationID": operation, "beforePID": 42,
                                         "beforeStarttime": "old", "startedAtMonotonicMs": 10,
                                         "completed": False}}
            written = []
            def matches(pid, starttime, _command):
                return pid == 55 and starttime == "new"
            with mock.patch.object(KVM, "preserve_cold_reboot_after_session_loss"), \
                 mock.patch.object(KVM, "load_persistent_state", return_value=record), \
                 mock.patch.object(KVM, "write_persistent_state", side_effect=lambda _path, value: written.append(value.copy())), \
                 mock.patch.object(KVM, "command_matches", side_effect=matches), \
                 mock.patch.object(KVM, "proc_starttime", side_effect=lambda pid: "new" if pid == 55 else None), \
                 mock.patch.object(KVM, "verify_persistent_guest") as verify, \
                 mock.patch.object(KVM, "stop_persistent_qemu") as stop, \
                 mock.patch.object(KVM.subprocess, "Popen") as spawn, \
                 mock.patch.object(KVM.time, "monotonic_ns", return_value=20_000_000):
                self.assertEqual(KVM._lifecycle_main([
                    "cold-reboot", "--state", str(state_path), "--task-id", "g6-task",
                    "--operation-id", operation]), 0)
            stop.assert_not_called()
            spawn.assert_not_called()
            verify.assert_called_once_with(record, 55, "new")
            self.assertEqual(len(written), 1)
            self.assertEqual(written[0]["qemuPID"], 55)
            self.assertEqual(written[0]["qemuStarttime"], "new")
            self.assertTrue(written[0]["lastColdReboot"]["completed"])
            self.assertEqual(written[0]["lastColdReboot"]["beforePID"], 42)
            self.assertEqual(written[0]["lastColdReboot"]["afterPID"], 55)

    def test_qemu_pidfile_is_part_of_persistent_command_identity(self):
        self.assertEqual(KVM.qemu_pidfile(["qemu", "-pidfile", "/run/g6.pid"]), Path("/run/g6.pid"))
        with self.assertRaises(KVM.BoundaryError): KVM.qemu_pidfile(["qemu"])

    def test_reboot_verification_reuses_ssh_and_guest_boundary_proof(self):
        record = {"qemuCommand": ["qemu", "-accel", "kvm"],
                  "boundaryVerification": {"knownHosts": "/private/known_hosts", "sshPrivateKey": "/private/key",
                                           "sshUser": "root", "sshPort": 2222, "bootTimeout": 30,
                                           "guestUUID": "12345678-1234-4234-9234-123456789abc",
                                           "machineID": "0" * 32, "hostMachineID": "f" * 32}}
        with mock.patch.object(KVM, "command_matches", return_value=True), \
             mock.patch.object(KVM, "wait_for_guest") as wait, \
             mock.patch.object(KVM, "verify_guest_boundary") as verify:
            KVM.verify_persistent_guest(record, 12, "99")
        self.assertEqual(wait.call_args.args[0].ssh_port, 2222)
        self.assertEqual(wait.call_args.args[0].ssh, "ssh")
        self.assertEqual(wait.call_args.args[0].evidence_dir, Path("."))
        self.assertEqual(verify.call_args.args[1], "f" * 32)

    def test_reboot_verification_reuses_explicit_saved_executor_fields(self):
        record = {"qemuCommand": ["qemu", "-accel", "kvm"],
                  "boundaryVerification": {"knownHosts": "/private/known_hosts", "sshPrivateKey": "/private/key",
                                           "sshUser": "root", "sshPort": 2222, "bootTimeout": 30,
                                           "guestUUID": "12345678-1234-4234-9234-123456789abc",
                                           "machineID": "0" * 32, "hostMachineID": "f" * 32,
                                           "sshCommand": "/usr/bin/ssh", "evidenceDir": "/private/evidence"}}
        completed = KVM.subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(KVM, "command_matches", return_value=True), \
             mock.patch.object(KVM.subprocess, "run", return_value=completed) as run, \
             mock.patch.object(KVM, "verify_guest_boundary"):
            KVM.verify_persistent_guest(record, 12, "99")
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/ssh")
        self.assertIn("UserKnownHostsFile=/private/known_hosts", run.call_args.args[0])

    def test_reboot_verification_reports_saved_evidence_path_if_qemu_exits(self):
        record = {"qemuCommand": ["qemu", "-accel", "kvm"],
                  "boundaryVerification": {"knownHosts": "/private/known_hosts", "sshPrivateKey": "/private/key",
                                           "sshUser": "root", "sshPort": 2222, "bootTimeout": 30,
                                           "guestUUID": "12345678-1234-4234-9234-123456789abc",
                                           "machineID": "0" * 32, "hostMachineID": "f" * 32,
                                           "sshCommand": "/usr/bin/ssh", "evidenceDir": "/private/evidence"}}
        with mock.patch.object(KVM, "command_matches", return_value=False), \
             self.assertRaisesRegex(KVM.BoundaryError, "/private/evidence/qemu.log"):
            KVM.verify_persistent_guest(record, 12, "99")

    def test_reboot_verification_rejects_incomplete_saved_verification_inputs(self):
        with self.assertRaisesRegex(KVM.BoundaryError, "incomplete"):
            KVM.verify_persistent_guest({"qemuCommand": ["qemu"], "boundaryVerification": {}}, 1, "1")


if __name__ == "__main__": unittest.main()
