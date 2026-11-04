#!/usr/bin/env python3
"""No-QEMU safety tests for the disposable KVM boundary launcher."""
from __future__ import annotations
import importlib.util
import copy
import json
from pathlib import Path
import subprocess
import sys
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

    def test_cluster_lan_ipv6_is_task_stable_and_guest_unique(self):
        subnet, first = KVM.derive_cluster_lan_ipv6(
            "g6-local", "02:06:00:00:00:01", "12345678-1234-4234-9234-123456789abc")
        repeated_subnet, repeated = KVM.derive_cluster_lan_ipv6(
            "g6-local", "02:06:00:00:00:01", "12345678-1234-4234-9234-123456789abc")
        _, second = KVM.derive_cluster_lan_ipv6(
            "g6-local", "02:06:00:00:00:02", "12345678-1234-4234-9234-123456789abc")
        other_subnet, _ = KVM.derive_cluster_lan_ipv6(
            "g7-local", "02:06:00:00:00:01", "12345678-1234-4234-9234-123456789abc")
        self.assertEqual((subnet, first), (repeated_subnet, repeated))
        self.assertTrue(subnet.network_address.is_private); self.assertIn(first, subnet)
        self.assertNotEqual(first, second); self.assertNotEqual(subnet, other_subnet)

    def test_cluster_lan_mac_requires_one_saved_clusterlan_device(self):
        record = {"qemuCommand": ["qemu", "-netdev", "user,id=guestnet", "-device", "virtio-net-pci,netdev=guestnet",
                                  "-netdev", "hubport,id=clusterlan,hubid=0", "-device", "virtio-net-pci,netdev=clusterlan,mac=02:06:00:00:00:01"],
                  "network": {"netdevs": ["user,id=guestnet", "hubport,id=clusterlan,hubid=0"],
                              "devices": ["virtio-net-pci,netdev=guestnet", "virtio-net-pci,netdev=clusterlan,mac=02:06:00:00:00:01"]}}
        self.assertEqual(KVM.cluster_lan_mac_from_persistent_network(record), "02:06:00:00:00:01")
        record["network"] = dict(record["network"])
        record["network"]["devices"] = ["virtio-net-pci,netdev=guestnet"]
        with self.assertRaisesRegex(KVM.BoundaryError, "QEMU network devices differ"):
            KVM.cluster_lan_mac_from_persistent_network(record)

    def test_cluster_lan_action_is_exact_identity_bound_and_owner_shaped(self):
        record = {"qemuPID": 42, "qemuStarttime": "7", "qemuCommand": ["qemu", "-netdev", "user,id=guestnet", "-device", "virtio-net-pci,netdev=guestnet",
                                                                             "-netdev", "hubport,id=clusterlan,hubid=0", "-device", "virtio-net-pci,netdev=clusterlan,mac=02:06:00:00:00:01"],
                  "network": {"netdevs": ["user,id=guestnet", "hubport,id=clusterlan,hubid=0"],
                              "devices": ["virtio-net-pci,netdev=guestnet", "virtio-net-pci,netdev=clusterlan,mac=02:06:00:00:00:01"]}}
        args = mock.Mock(guest_uuid=KVM.uuid.UUID("12345678-1234-4234-9234-123456789abc"))
        result = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(KVM, "command_matches", return_value=True), \
             mock.patch.object(KVM, "persistent_guest_args", return_value=(args, "f" * 32)), \
             mock.patch.object(KVM, "verify_persistent_guest") as verify, \
             mock.patch.object(KVM, "guest_run", return_value=result) as run:
            receipt = KVM.configure_cluster_lan_ipv6(record, "g6-local")
        verify.assert_called_once_with(record, 42, "7")
        script = run.call_args.args[1]
        self.assertIn("/sys/class/net/lan0/address", script)
        self.assertIn("10-cloud-init-lan0.network.d/50-prodigy-cluster-lan-ipv6.conf", script)
        self.assertIn("networkctl reload", script); self.assertIn("networkctl reconfigure lan0", script)
        self.assertIn("if test ! -f \"$dropin\"", script)
        self.assertNotIn("guest_command", script)
        self.assertEqual(receipt["interface"], "lan0"); self.assertEqual(receipt["mac"], "02:06:00:00:00:01")
        with mock.patch.object(KVM, "command_matches", return_value=False):
            with self.assertRaisesRegex(KVM.BoundaryError, "exact QEMU process identity"):
                KVM.configure_cluster_lan_ipv6(record, "g6-local")

    def test_guest_linux_identity_uses_the_pinned_boundary_and_exact_qemu(self):
        machine_id = "1" * 32
        boot_id = "12345678-1234-4abc-8def-123456789abc"
        record = {"qemuPID": 42, "qemuStarttime": "7", "qemuCommand": ["qemu"]}
        args = mock.Mock(expected_machine_id=machine_id)
        result = mock.Mock(returncode=0, stdout=f"{machine_id}\n{boot_id}\n", stderr="")
        with mock.patch.object(KVM, "command_matches", return_value=True), \
             mock.patch.object(KVM, "persistent_guest_args", return_value=(args, "f" * 32)), \
             mock.patch.object(KVM, "verify_persistent_guest") as verify, \
             mock.patch.object(KVM, "guest_run", return_value=result) as run:
            identity = KVM.query_guest_linux_identity(record)
        verify.assert_called_once_with(record, 42, "7")
        self.assertIn("/etc/machine-id", run.call_args.args[1])
        self.assertIn("/proc/sys/kernel/random/boot_id", run.call_args.args[1])
        self.assertEqual(identity, {"machineID": machine_id, "bootID": boot_id,
                                    "qemuPID": 42, "qemuStarttime": "7"})
        result.stdout = f"{machine_id}\nnot-a-boot-id\n"
        with mock.patch.object(KVM, "command_matches", return_value=True), \
             mock.patch.object(KVM, "persistent_guest_args", return_value=(args, "f" * 32)), \
             mock.patch.object(KVM, "verify_persistent_guest"), \
             mock.patch.object(KVM, "guest_run", return_value=result), \
             self.assertRaisesRegex(KVM.BoundaryError, "identity observation is invalid"):
            KVM.query_guest_linux_identity(record)

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

    def test_spawned_qemu_identity_observation_tolerates_exec_proc_visibility_race(self):
        process = mock.Mock(pid=55, returncode=None); process.poll.return_value = None
        with mock.patch.object(KVM, "proc_starttime", side_effect=[None, "old", "new"]), \
             mock.patch.object(KVM, "command_matches", side_effect=[False, True]), \
             mock.patch.object(KVM.time, "monotonic", side_effect=[0.0, .01, .02]), \
             mock.patch.object(KVM.time, "sleep") as sleep:
            self.assertEqual(KVM.observe_spawned_qemu_identity(process, ["qemu"]), "new")
        self.assertEqual(sleep.call_count, 2)

    def test_spawned_qemu_identity_observation_rejects_exit_or_persistent_mismatch(self):
        exited = mock.Mock(pid=55, returncode=17); exited.poll.return_value = 17
        with self.assertRaisesRegex(KVM.BoundaryError, "exited during exec observation"):
            KVM.observe_spawned_qemu_identity(exited, ["qemu"])
        running = mock.Mock(pid=55, returncode=None); running.poll.return_value = None
        with mock.patch.object(KVM, "proc_starttime", return_value="wrong"), \
             mock.patch.object(KVM, "command_matches", return_value=False), \
             mock.patch.object(KVM.time, "monotonic", side_effect=[0.0, 2.0]), \
             mock.patch.object(KVM.time, "sleep"):
            with self.assertRaisesRegex(KVM.BoundaryError, "bounded exec observation"):
                KVM.observe_spawned_qemu_identity(running, ["qemu"])

    def stopped_recovery_record(self, root: Path, *, pid: int = 42, starttime: str = "old"):
        root = root.resolve()
        overlay, vars_copy = root / "overlay.qcow2", root / "vars.fd"
        overlay.write_bytes(b"overlay"); vars_copy.write_bytes(b"vars")
        guest, host = "12345678-1234-4234-9234-123456789abc", "f" * 32
        net = "user,id=guestnet,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22"
        command = ["qemu-system-x86_64", "-accel", "kvm", "-uuid", guest,
                   "-drive", f"if=pflash,format=raw,file={vars_copy}", "-drive",
                   f"file={overlay},if=virtio,format=qcow2,cache=none", "-netdev", net,
                   "-device", "virtio-net-pci,netdev=guestnet", "-pidfile", str(root / "qemu.pid"),
                   "-qmp", f"unix:{root / 'qmp.sock'},server=on,wait=off"]
        return {"taskID": "g6-task", "qemuPID": pid, "qemuStarttime": starttime,
                "qemuCommand": command, "overlay": str(overlay), "ovmfVars": str(vars_copy),
                "guestUUID": guest, "machineID": "0" * 32, "qmpSocket": str(root / "qmp.sock"),
                "network": {"netdevs": [net], "devices": ["virtio-net-pci,netdev=guestnet"]},
                "boundaryVerification": {"knownHosts": str(root / "known_hosts"),
                    "sshPrivateKey": str(root / "key"), "sshUser": "root", "sshPort": 2222,
                    "bootTimeout": 30, "guestUUID": guest, "machineID": "0" * 32,
                    "hostMachineID": host}}

    def test_recover_stopped_binds_absent_exact_pid_and_reuses_cold_reboot(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, operation = Path(directory), Path(directory) / "state", "1" * 32
            record = self.stopped_recovery_record(root); expected = "a" * 64
            receipt = {"operationID": operation, "beforePID": 42, "beforeStarttime": "old",
                       "afterPID": 55, "afterStarttime": "new", "startedAtMonotonicMs": 1,
                       "completedAtMonotonicMs": 2, "completed": True,
                       "recoveryProtocol": "prodigy-kvm-stopped-recovery-v1",
                       "recoveryExpectedGuestUUID": record["guestUUID"],
                       "recoveryExpectedStateSHA256": expected,
                       "recoveryPriorIdentity": {"pid": 42, "starttime": "old"}}
            def resume(value, _path, _operation):
                value["qemuPID"], value["qemuStarttime"], value["lastColdReboot"] = 55, "new", receipt
                return receipt
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value=None), \
                 mock.patch.object(KVM, "command_matches", return_value=True), \
                 mock.patch.object(KVM, "verify_persistent_guest") as verify, \
                 mock.patch.object(KVM, "write_persistent_state") as write, \
                 mock.patch.object(KVM, "resume_cold_reboot", side_effect=resume) as resume:
                recovered = KVM.recover_stopped_boundary(record, state, operation,
                                                          record["guestUUID"], expected, expected)
            resume.assert_called_once_with(record, state, operation)
            self.assertTrue(recovered["completed"])
            self.assertEqual(recovered["recoveryPriorIdentity"], {"pid": 42, "starttime": "old"})
            self.assertEqual(recovered["recoveryExpectedStateSHA256"], expected)
            verify.assert_called_once_with(record, 55, "new")
            self.assertEqual(write.call_count, 1)

    def test_recover_stopped_cli_requires_one_typed_exact_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, operation = Path(directory), Path(directory) / "state", "1" * 32
            record = self.stopped_recovery_record(root); expected = "a" * 64
            response = {"operationUUID": operation, "completed": True}
            arguments = ["recover-stopped", "--state", str(state), "--task-id", "g6-task",
                         "--operation-uuid", operation, "--expected-guest-uuid", record["guestUUID"],
                         "--expected-state-sha256", expected]
            with mock.patch.object(KVM, "digest", return_value=expected), \
                 mock.patch.object(KVM, "load_persistent_state", return_value=record), \
                 mock.patch.object(KVM, "recover_stopped_boundary", return_value=response) as recover:
                self.assertEqual(KVM._lifecycle_main(arguments), 0)
            recover.assert_called_once_with(record, state.resolve(), operation, record["guestUUID"], expected, expected)
            with self.assertRaisesRegex(KVM.BoundaryError, "requires canonical"):
                KVM._lifecycle_main(arguments[:-2])

    def test_recover_stopped_subprocess_dispatches_to_lifecycle_not_normal_argparse(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, operation = Path(directory), Path(directory) / "boundary.json", "1" * 32
            record = self.stopped_recovery_record(root)
            KVM.write_persistent_state(state, record); expected = KVM.digest(state)
            # Fail before any host-dependent checks or lifecycle action on
            # both Darwin and Linux, while still exercising the real CLI.
            expected = ("0" if expected[0] != "0" else "1") + expected[1:]
            result = subprocess.run([sys.executable, str(SOURCE), "recover-stopped", "--state", str(state),
                                     "--task-id", "g6-task", "--operation-uuid", operation,
                                     "--expected-guest-uuid", record["guestUUID"],
                                     "--expected-state-sha256", expected], text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("persistent state SHA-256 differs from recovery request", result.stderr)
            self.assertNotIn("the following arguments are required", result.stderr)

    def test_recover_stopped_rejects_wrong_hash_uuid_host_or_live_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, operation = Path(directory), Path(directory) / "state", "1" * 32
            record = self.stopped_recovery_record(root); expected = "a" * 64
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value=None):
                with self.assertRaisesRegex(KVM.BoundaryError, "SHA-256"):
                    KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], expected, "b" * 64)
                with self.assertRaisesRegex(KVM.BoundaryError, "UUID"):
                    KVM.recover_stopped_boundary(record, state, operation, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", expected, expected)
            record = self.stopped_recovery_record(root)
            with mock.patch.object(KVM, "current_host_machine_id", return_value="e" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value=None), \
                 self.assertRaisesRegex(KVM.BoundaryError, "host machine identity"):
                KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], expected, expected)
            record = self.stopped_recovery_record(root)
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value="reused"), \
                 self.assertRaisesRegex(KVM.BoundaryError, "still live or has been reused"):
                KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], expected, expected)

    def test_recover_stopped_rejects_competing_unfinished_reboot(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state = Path(directory), Path(directory) / "state"
            record = self.stopped_recovery_record(root)
            record["lastColdReboot"] = {"operationID": "2" * 32, "beforePID": 42,
                                        "beforeStarttime": "old", "startedAtMonotonicMs": 1,
                                        "completed": False}
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value=None), \
                 self.assertRaisesRegex(KVM.BoundaryError, "unfinished reboot"):
                KVM.recover_stopped_boundary(record, state, "1" * 32, record["guestUUID"], "a" * 64, "a" * 64)

    def test_recover_stopped_requires_exact_saved_qmp_and_pidfile_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, operation = Path(directory), Path(directory) / "state", "1" * 32
            for option, value in (("-qmp", "unix:/tmp/wrong.sock,server=on,wait=off"), ("-pidfile", "relative.pid")):
                record = self.stopped_recovery_record(root)
                index = record["qemuCommand"].index(option) + 1; record["qemuCommand"][index] = value
                with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                     mock.patch.object(KVM, "proc_starttime", return_value=None), \
                     self.assertRaisesRegex(KVM.BoundaryError, "unsafe|identity command"):
                    KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], "a" * 64, "a" * 64)
            record = self.stopped_recovery_record(root); Path(record["qmpSocket"]).mkdir()
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value=None), \
                 self.assertRaisesRegex(KVM.BoundaryError, "QMP socket path is unsafe"):
                KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], "a" * 64, "a" * 64)
            fresh = root / "pidfile-case"; fresh.mkdir()
            record = self.stopped_recovery_record(fresh); pidfile = Path(record["qemuCommand"][record["qemuCommand"].index("-pidfile") + 1]); pidfile.mkdir()
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value=None), \
                 self.assertRaisesRegex(KVM.BoundaryError, "pidfile path is unsafe"):
                KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], "a" * 64, "a" * 64)

    def test_recover_stopped_crash_resume_and_completed_retry_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, operation = Path(directory), Path(directory) / "state", "1" * 32
            record = self.stopped_recovery_record(root, pid=55, starttime="new"); expected = "a" * 64
            prior = {"pid": 42, "starttime": "old"}
            completed = {"operationID": operation, "beforePID": 42, "beforeStarttime": "old",
                         "afterPID": 55, "afterStarttime": "new", "startedAtMonotonicMs": 1,
                         "completedAtMonotonicMs": 2, "completed": True,
                         "recoveryProtocol": "prodigy-kvm-stopped-recovery-v1",
                         "recoveryExpectedGuestUUID": record["guestUUID"],
                         "recoveryExpectedStateSHA256": expected,
                         "recoveryPriorIdentity": prior}
            record["lastColdReboot"] = completed
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value=None), \
                 mock.patch.object(KVM, "command_matches", return_value=True), \
                 mock.patch.object(KVM, "verify_persistent_guest"), \
                 mock.patch.object(KVM, "resume_cold_reboot", return_value=completed) as resume, \
                 mock.patch.object(KVM, "write_persistent_state"):
                recovered = KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], expected, "changed" * 9 + "a")
            resume.assert_not_called(); self.assertTrue(recovered["completed"])
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "command_matches", return_value=True), \
                 mock.patch.object(KVM, "verify_persistent_guest") as verify, \
                 mock.patch.object(KVM, "write_persistent_state") as write:
                retried = KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], expected, "different" * 8)
            self.assertIs(retried, record["lastColdReboot"]); verify.assert_called_once(); write.assert_not_called()
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 self.assertRaisesRegex(KVM.BoundaryError, "inputs differ"):
                KVM.recover_stopped_boundary(record, state, operation, record["guestUUID"], "b" * 64, expected)

    def test_recover_stopped_archives_completed_receipt_before_a_later_oom_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, first, second = Path(directory), Path(directory) / "state", "1" * 32, "2" * 32
            record = self.stopped_recovery_record(root, pid=55, starttime="new"); old_hash, new_hash = "a" * 64, "b" * 64
            record["lastColdReboot"] = {"operationID": first, "beforePID": 42, "beforeStarttime": "old",
                "afterPID": 55, "afterStarttime": "new", "startedAtMonotonicMs": 1,
                "completedAtMonotonicMs": 2, "completed": True,
                "recoveryProtocol": "prodigy-kvm-stopped-recovery-v1",
                "recoveryExpectedGuestUUID": record["guestUUID"], "recoveryExpectedStateSHA256": old_hash,
                "recoveryPriorIdentity": {"pid": 42, "starttime": "old"}}
            completed = {"operationID": second, "beforePID": 55, "beforeStarttime": "new",
                "afterPID": 66, "afterStarttime": "next", "startedAtMonotonicMs": 3,
                "completedAtMonotonicMs": 4, "completed": True,
                "recoveryProtocol": "prodigy-kvm-stopped-recovery-v1",
                "recoveryExpectedGuestUUID": record["guestUUID"], "recoveryExpectedStateSHA256": new_hash,
                "recoveryPriorIdentity": {"pid": 55, "starttime": "new"}}
            def resume(value, _path, _operation):
                value["qemuPID"], value["qemuStarttime"], value["lastColdReboot"] = 66, "next", completed
                return completed
            with mock.patch.object(KVM, "current_host_machine_id", return_value="f" * 32), \
                 mock.patch.object(KVM, "proc_starttime", return_value=None), \
                 mock.patch.object(KVM, "command_matches", return_value=True), \
                 mock.patch.object(KVM, "verify_persistent_guest"), \
                 mock.patch.object(KVM, "resume_cold_reboot", side_effect=resume) as restart, \
                 mock.patch.object(KVM, "write_persistent_state"):
                result = KVM.recover_stopped_boundary(record, state, second, record["guestUUID"], new_hash, new_hash)
            restart.assert_called_once_with(record, state, second)
            self.assertEqual(result["operationID"], second)
            self.assertEqual(record["completedColdReboots"][0]["operationID"], first)

    def test_cold_reboot_receipt_is_exact_retry_identity(self):
        record = {"lastColdReboot": {"operationID": "1" * 32, "beforePID": 4, "beforeStarttime": "8",
                  "afterPID": 5, "afterStarttime": "9", "startedAtMonotonicMs": 10,
                  "completedAtMonotonicMs": 20, "completed": True}}
        self.assertIsNotNone(KVM.completed_cold_reboot(record, "1" * 32))
        self.assertIsNone(KVM.completed_cold_reboot(record, "2" * 32))
        record["lastColdReboot"]["completedAtMonotonicMs"] = 10
        with self.assertRaisesRegex(KVM.BoundaryError, "strictly ordered"):
            KVM.completed_cold_reboot(record, "1" * 32)

    def completed_receipt(self, operation: str, cohort: str | None = None, *, after_pid: int = 5):
        receipt = {"operationID": operation, "beforePID": 4, "beforeStarttime": "8",
                   "afterPID": after_pid, "afterStarttime": str(after_pid + 4),
                   "startedAtMonotonicMs": 10, "completedAtMonotonicMs": 20,
                   "completed": True, "phase": "completed"}
        if cohort is not None:
            receipt["cohortID"] = cohort
        return receipt

    def archive_record(self, receipt: dict[str, object]):
        return {"taskID": "archive-task", "guestUUID": "12345678-1234-4234-9234-123456789abc",
                "lastColdReboot": receipt, "completedColdReboots": []}

    def test_durable_archive_rollover_preserves_old_exact_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "boundary.json"
            total = 100
            record = self.archive_record(self.completed_receipt(f"{1:032x}", "a" * 32))
            for number in range(1, total + 1):
                record["lastColdReboot"] = self.completed_receipt(f"{number:032x}", "a" * 32,
                                                                    after_pid=number + 10)
                KVM.archive_completed_cold_reboot(record, state)
            self.assertEqual(len(record["completedColdReboots"]), KVM.COLD_REBOOT_HISTORY_LIMIT)
            self.assertEqual(KVM.completed_cold_reboot_for(record, f"{1:032x}", "a" * 32,
                                                           state_path=state)["afterPID"], 11)
            self.assertEqual(KVM.completed_cold_reboot_for(record, f"{total:032x}", "a" * 32,
                                                           state_path=state)["afterPID"], total + 10)
            with self.assertRaisesRegex(KVM.BoundaryError, "cohort differs"):
                KVM.completed_cold_reboot_for(record, f"{1:032x}", "b" * 32, state_path=state)
            archive = state.with_name(state.name + ".completed-cold-reboots")
            self.assertTrue((archive / f"{1:032x}.json").is_file())
            self.assertLess(len(KVM.state_bytes(record)), 64 * 1024)

    def test_full_legacy_ledger_arms_and_preserves_evicted_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state = Path(directory), Path(directory) / "boundary.json"
            record = self.stopped_recovery_record(root)
            record["completedColdReboots"] = [self.completed_receipt(f"{n:032x}", "a" * 32)
                                               for n in range(1, 17)]
            record["lastColdReboot"] = self.completed_receipt(f"{17:032x}", "a" * 32)
            KVM.write_persistent_state(state, record)
            with mock.patch.object(KVM, "command_matches", return_value=True), \
                 mock.patch.object(KVM, "stop_persistent_qemu") as stop, \
                 mock.patch.object(KVM.os, "fork") as fork:
                self.assertEqual(KVM.lifecycle_main([
                    "arm-cold-reboot", "--state", str(state), "--task-id", "g6-task",
                    "--operation-id", f"{18:032x}", "--cohort-id", "a" * 32,
                    "--not-before-unix-ms", str(KVM.time.time_ns() // 1_000_000 + 1_000)]), 0)
            stop.assert_not_called(); fork.assert_not_called()
            persisted = KVM.load_persistent_state(state, "g6-task")
            self.assertEqual(persisted["lastColdReboot"]["phase"], "armed")
            self.assertEqual(len(persisted["completedColdReboots"]), 16)
            self.assertEqual(persisted["completedColdReboots"][0]["operationID"], f"{2:032x}")
            self.assertEqual(KVM.completed_cold_reboot_for(persisted, f"{1:032x}", "a" * 32,
                                                           state_path=state), record["completedColdReboots"][0])
            self.assertLess(len(KVM.state_bytes(persisted)), 64 * 1024 - 4096)

    def test_capacity_failure_preserves_released_vm_and_does_not_fork(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, operation, cohort = Path(directory), Path(directory) / "boundary.json", "1" * 32, "a" * 32
            record = self.stopped_recovery_record(root)
            record["lastColdReboot"] = {"operationID": operation, "cohortID": cohort,
                "beforePID": 42, "beforeStarttime": "old", "startedAtMonotonicMs": 1,
                "notBeforeUnixMs": 1000, "phase": "armed", "completed": False}
            KVM.write_persistent_state(state, record)
            before = state.read_bytes()
            low_bytes = mock.Mock(f_bavail=1, f_frsize=4096, f_files=1, f_favail=100)
            with mock.patch.object(KVM.os, "statvfs", return_value=low_bytes), \
                 mock.patch.object(KVM, "stop_persistent_qemu") as stop, \
                 mock.patch.object(KVM.os, "fork") as fork, \
                 mock.patch.object(KVM.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(KVM.BoundaryError, "insufficient recovery storage"):
                    KVM.lifecycle_main(["release-cold-reboot", "--state", str(state), "--task-id", "g6-task",
                                        "--operation-id", operation, "--cohort-id", cohort])
                record["lastColdReboot"]["phase"] = "released"
                with self.assertRaisesRegex(KVM.BoundaryError, "insufficient recovery storage"):
                    KVM.resume_cold_reboot(record, state, operation, cohort)
            stop.assert_not_called(); fork.assert_not_called(); spawn.assert_not_called()
            self.assertEqual(state.read_bytes(), before)

    def test_archive_persists_before_state_replacement_and_replays_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "boundary.json"
            receipt = self.completed_receipt("1" * 32, "a" * 32)
            durable = self.archive_record(copy.deepcopy(receipt))
            KVM.archive_completed_cold_reboot(durable, state)
            # Simulated interruption: archive publication completed but the
            # replacement state still owns the old current receipt.
            pre_replace = self.archive_record(copy.deepcopy(receipt))
            self.assertEqual(KVM.completed_cold_reboot_for(pre_replace, "1" * 32, "a" * 32,
                                                           state_path=state), receipt)
            post_replace = self.archive_record(copy.deepcopy(receipt))
            post_replace.pop("lastColdReboot")
            self.assertEqual(KVM.completed_cold_reboot_for(post_replace, "1" * 32, "a" * 32,
                                                           state_path=state), receipt)

    def test_archive_rejects_immutable_collision_corruption_symlink_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root, state, operation = Path(directory), Path(directory) / "boundary.json", "1" * 32
            record = self.archive_record(self.completed_receipt(operation, "a" * 32))
            KVM.archive_completed_cold_reboot(record, state)
            record["lastColdReboot"] = self.completed_receipt(operation, "a" * 32, after_pid=99)
            with self.assertRaises(KVM.BoundaryError):
                KVM.archive_completed_cold_reboot(record, state)
            receipt_path = state.with_name(state.name + ".completed-cold-reboots") / f"{operation}.json"
            lookup = {"taskID": "archive-task", "guestUUID": record["guestUUID"]}
            receipt_path.chmod(0o644)
            with self.assertRaises(KVM.BoundaryError):
                KVM.completed_cold_reboot_for(lookup, operation, "a" * 32, state_path=state)
            receipt_path.chmod(0o600); receipt_path.write_text("not-json\n")
            with self.assertRaises(KVM.BoundaryError):
                KVM.completed_cold_reboot_for(lookup, operation, "a" * 32, state_path=state)
            receipt_path.unlink()
            target = root / "other"; target.write_text(json.dumps({}))
            receipt_path.symlink_to(target)
            with self.assertRaises(KVM.BoundaryError):
                KVM.completed_cold_reboot_for(lookup, operation, "a" * 32, state_path=state)

    def test_recovery_capacity_rejects_disk_inode_and_oversize_before_stop_or_fork(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "boundary.json"
            record = self.archive_record(self.completed_receipt("1" * 32, "a" * 32))
            low_bytes = mock.Mock(f_bavail=1023, f_frsize=4096, f_files=1, f_favail=100)
            with mock.patch.object(KVM.os, "statvfs", return_value=low_bytes), self.assertRaises(KVM.BoundaryError):
                KVM.ensure_recovery_capacity(state, record)
            low_inodes = mock.Mock(f_bavail=4096, f_frsize=4096, f_files=1, f_favail=7)
            with mock.patch.object(KVM.os, "statvfs", return_value=low_inodes), self.assertRaises(KVM.BoundaryError):
                KVM.ensure_recovery_capacity(state, record)
            record["qemuCommand"] = ["x" * (64 * 1024)]
            with self.assertRaises(KVM.BoundaryError):
                KVM.ensure_recovery_capacity(state, record)
            lifecycle_record = {"qemuPID": 42, "qemuStarttime": "old", "qemuCommand": ["qemu"], "lastColdReboot": None}
            with mock.patch.object(KVM, "load_persistent_state", return_value=lifecycle_record), \
                 mock.patch.object(KVM, "command_matches", return_value=True), \
                 mock.patch.object(KVM, "ensure_recovery_capacity", side_effect=KVM.BoundaryError("capacity")), \
                 mock.patch.object(KVM, "stop_persistent_qemu") as stop, \
                 mock.patch.object(KVM.subprocess, "Popen") as spawn, \
                 self.assertRaisesRegex(KVM.BoundaryError, "capacity"):
                KVM._lifecycle_main(["arm-cold-reboot", "--state", str(state), "--task-id", "g6-task",
                                     "--operation-id", "1" * 32, "--cohort-id", "2" * 32,
                                     "--not-before-unix-ms", str(KVM.time.time_ns() // 1_000_000 + 1_000)])
            stop.assert_not_called(); spawn.assert_not_called()

    def test_completed_reboot_history_replays_exactly_and_rejects_changed_cohort(self):
        receipt = {"operationID": "1" * 32, "cohortID": "a" * 32, "beforePID": 4,
                   "beforeStarttime": "8", "afterPID": 5, "afterStarttime": "9",
                   "startedAtMonotonicMs": 10, "completedAtMonotonicMs": 20,
                   "completed": True, "phase": "completed"}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "boundary.json"
            record = self.archive_record(dict(receipt))
            KVM.archive_completed_cold_reboot(record, state)
            self.assertIsNone(record.get("lastColdReboot"))
            self.assertEqual(KVM.completed_cold_reboot_for(record, "1" * 32, "a" * 32,
                                                           state_path=state)["afterPID"], 5)
            with self.assertRaisesRegex(KVM.BoundaryError, "cohort differs"):
                KVM.completed_cold_reboot_for(record, "1" * 32, "b" * 32, state_path=state)

    def test_arm_cold_reboot_persists_exact_identity_before_any_qemu_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / "state"; operation, cohort = "1" * 32, "2" * 32
            record = {"qemuPID": 42, "qemuStarttime": "old", "qemuCommand": ["qemu"],
                      "lastColdReboot": None}
            written = []
            with mock.patch.object(KVM, "load_persistent_state", return_value=record), \
                 mock.patch.object(KVM, "command_matches", return_value=True), \
                 mock.patch.object(KVM, "write_persistent_state", side_effect=lambda _p, value: written.append(dict(value))), \
                 mock.patch.object(KVM, "stop_persistent_qemu") as stop, \
                 mock.patch.object(KVM.subprocess, "Popen") as spawn, \
                 mock.patch.object(KVM.time, "time_ns", return_value=1_000_000), \
                 mock.patch.object(KVM.time, "monotonic_ns", return_value=2_000_000):
                self.assertEqual(KVM._lifecycle_main(["arm-cold-reboot", "--state", str(state), "--task-id", "g6-task",
                                                       "--operation-id", operation, "--cohort-id", cohort,
                                                       "--not-before-unix-ms", "1001"]), 0)
            stop.assert_not_called(); spawn.assert_not_called()
            self.assertEqual(written[0]["lastColdReboot"]["phase"], "armed")
            self.assertEqual(written[0]["lastColdReboot"]["beforeStarttime"], "old")

    def test_release_cold_reboot_detaches_after_durable_release_and_parent_never_stops_qemu(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / "state"; operation, cohort = "1" * 32, "2" * 32
            armed = {"operationID": operation, "cohortID": cohort, "beforePID": 42, "beforeStarttime": "old",
                     "startedAtMonotonicMs": 1, "armedAtUnixMs": 2, "notBeforeUnixMs": 9_999,
                     "phase": "armed", "completed": False}
            record = {"qemuPID": 42, "qemuStarttime": "old", "qemuCommand": ["qemu"], "lastColdReboot": armed}
            written = []
            with mock.patch.object(KVM, "load_persistent_state", return_value=record), \
                 mock.patch.object(KVM, "write_persistent_state", side_effect=lambda _p, value: written.append(dict(value))), \
                 mock.patch.object(KVM.os, "fork", return_value=123) as fork, \
                 mock.patch.object(KVM.time, "time_ns", return_value=10_000_000_000), \
                 mock.patch.object(KVM.time, "monotonic_ns", return_value=20_000_000_000), \
                 mock.patch.object(KVM, "stop_persistent_qemu") as stop:
                self.assertEqual(KVM._lifecycle_main(["release-cold-reboot", "--state", str(state), "--task-id", "g6-task",
                                                       "--operation-id", operation, "--cohort-id", cohort]), 0)
            fork.assert_called_once(); stop.assert_not_called()
            self.assertEqual(written[0]["lastColdReboot"]["phase"], "released")
            self.assertEqual(written[0]["lastColdReboot"]["notBeforeUnixMs"],
                             10_000 + KVM.COLD_REBOOT_RELEASE_GRACE_MS)
            self.assertEqual(written[0]["lastColdReboot"]["startedAtMonotonicMs"], 20_000)

    def test_release_retry_refreshes_a_stranded_detached_attempt_before_refork(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"; operation, cohort = "1" * 32, "2" * 32
            released = {"operationID": operation, "cohortID": cohort, "beforePID": 42,
                        "beforeStarttime": "old", "startedAtMonotonicMs": 1,
                        "armedAtUnixMs": 2, "releasedAtUnixMs": 3, "notBeforeUnixMs": 4,
                        "phase": "released", "completed": False}
            record = {"qemuPID": 42, "qemuStarttime": "old", "qemuCommand": ["qemu"],
                      "lastColdReboot": released}
            written = []
            with mock.patch.object(KVM, "load_persistent_state", return_value=record), \
                 mock.patch.object(KVM, "write_persistent_state", side_effect=lambda _p, value: written.append(dict(value))), \
                 mock.patch.object(KVM.os, "fork", return_value=123), \
                 mock.patch.object(KVM.time, "time_ns", return_value=50_000_000_000), \
                 mock.patch.object(KVM.time, "monotonic_ns", return_value=60_000_000_000):
                self.assertEqual(KVM._lifecycle_main(["release-cold-reboot", "--state", str(state),
                                                       "--task-id", "g6-task", "--operation-id", operation,
                                                       "--cohort-id", cohort]), 0)
            self.assertEqual(written[0]["lastColdReboot"]["releasedAtUnixMs"], 50_000)
            self.assertEqual(written[0]["lastColdReboot"]["startedAtMonotonicMs"], 60_000)
            self.assertEqual(written[0]["lastColdReboot"]["notBeforeUnixMs"],
                             50_000 + KVM.COLD_REBOOT_RELEASE_GRACE_MS)

    def test_two_phase_reboot_source_contract_keeps_the_lock_in_a_detached_child(self):
        source = SOURCE.read_text()
        self.assertIn("def released_cold_reboot_child", source)
        self.assertIn("os.setsid()", source)
        self.assertIn("signal.signal(signal.SIGHUP, signal.SIG_IGN)", source)
        self.assertIn("resume_cold_reboot(record, state_path, operation_id, cohort_id)", source)
        self.assertIn('current["phase"] = "released"', source)

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

    def test_executor_upgrade_adopts_only_an_exact_already_live_legacy_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state_path = root / "boundary.json"; pidfile = root / "qemu.pid"
            pidfile.write_text("55\n")
            operation = "1" * 32
            record = {"qemuPID": 42, "qemuStarttime": "old",
                      "qemuCommand": ["qemu", "-pidfile", str(pidfile)],
                      "lastColdReboot": {"operationID": operation, "beforePID": 42,
                                         "beforeStarttime": "old", "startedAtMonotonicMs": 10,
                                         "completed": False}}
            written = []
            def matches(pid, starttime, _command):
                return pid == 55 and starttime == "new"
            with mock.patch.object(KVM, "command_matches", side_effect=matches), \
                 mock.patch.object(KVM, "proc_starttime", side_effect=lambda pid: "new" if pid == 55 else None), \
                 mock.patch.object(KVM, "verify_persistent_guest") as verify, \
                 mock.patch.object(KVM, "write_persistent_state", side_effect=lambda _path, value: written.append(value.copy())), \
                 mock.patch.object(KVM, "stop_persistent_qemu") as stop, \
                 mock.patch.object(KVM.subprocess, "Popen") as spawn, \
                 mock.patch.object(KVM.time, "monotonic_ns", return_value=20_000_000):
                reconciled = KVM.reconcile_executor_upgrade(record, state_path)
            stop.assert_not_called(); spawn.assert_not_called()
            verify.assert_called_once_with(record, 55, "new")
            self.assertEqual((reconciled["qemuPID"], reconciled["qemuStarttime"]), (55, "new"))
            self.assertTrue(reconciled["lastColdReboot"]["completed"])
            self.assertEqual(len(written), 1)

    def test_executor_upgrade_is_read_only_when_the_recorded_vm_is_live(self):
        record = {"qemuPID": 42, "qemuStarttime": "live", "qemuCommand": ["qemu"]}
        with mock.patch.object(KVM, "command_matches", return_value=True), \
             mock.patch.object(KVM, "verify_persistent_guest") as verify, \
             mock.patch.object(KVM, "write_persistent_state") as write, \
             mock.patch.object(KVM.subprocess, "Popen") as spawn:
            self.assertIs(KVM.reconcile_executor_upgrade(record, Path("/private/state")), record)
        verify.assert_called_once_with(record, 42, "live")
        write.assert_not_called(); spawn.assert_not_called()

    def test_executor_upgrade_proves_but_does_not_advance_a_live_armed_cohort(self):
        operation, cohort = "1" * 32, "2" * 32
        armed = {"operationID": operation, "cohortID": cohort, "beforePID": 42,
                 "beforeStarttime": "live", "startedAtMonotonicMs": 10,
                 "armedAtUnixMs": 20, "notBeforeUnixMs": 30,
                 "phase": "armed", "completed": False}
        record = {"qemuPID": 42, "qemuStarttime": "live", "qemuCommand": ["qemu"],
                  "lastColdReboot": armed}
        with mock.patch.object(KVM, "command_matches", return_value=True), \
             mock.patch.object(KVM, "verify_persistent_guest") as verify, \
             mock.patch.object(KVM, "write_persistent_state") as write:
            self.assertIs(KVM.reconcile_executor_upgrade(
                record, Path("/private/state"), operation, cohort), record)
        verify.assert_called_once_with(record, 42, "live")
        write.assert_not_called()
        self.assertEqual(record["lastColdReboot"], armed)

    def test_executor_upgrade_refuses_an_incomplete_operation_for_a_new_or_different_cohort(self):
        operation, cohort = "1" * 32, "2" * 32
        record = {"qemuPID": 42, "qemuStarttime": "live", "qemuCommand": ["qemu"],
                  "lastColdReboot": {"operationID": operation, "cohortID": cohort,
                                     "beforePID": 42, "beforeStarttime": "live",
                                     "startedAtMonotonicMs": 10, "armedAtUnixMs": 20,
                                     "notBeforeUnixMs": 30, "phase": "armed", "completed": False}}
        with mock.patch.object(KVM, "command_matches", return_value=True), \
             mock.patch.object(KVM, "verify_persistent_guest") as verify, \
             mock.patch.object(KVM, "write_persistent_state") as write:
            with self.assertRaisesRegex(KVM.BoundaryError, "not owned"):
                KVM.reconcile_executor_upgrade(record, Path("/private/state"))
            with self.assertRaisesRegex(KVM.BoundaryError, "not owned"):
                KVM.reconcile_executor_upgrade(
                    record, Path("/private/state"), "3" * 32, cohort)
        verify.assert_not_called(); write.assert_not_called()

    def test_executor_upgrade_refuses_cohort_state_and_never_starts_a_missing_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            operation, cohort = "1" * 32, "2" * 32
            record = {"qemuPID": 42, "qemuStarttime": "old",
                      "qemuCommand": ["qemu", "-pidfile", str(Path(directory) / "missing.pid")],
                      "lastColdReboot": {"operationID": operation, "cohortID": cohort,
                                         "beforePID": 42, "beforeStarttime": "old",
                                         "startedAtMonotonicMs": 10, "phase": "released", "completed": False}}
            with mock.patch.object(KVM, "command_matches", return_value=False), \
                 mock.patch.object(KVM, "write_persistent_state") as write, \
                 mock.patch.object(KVM.subprocess, "Popen") as spawn, \
                 self.assertRaisesRegex(KVM.BoundaryError, "non-legacy"):
                KVM.reconcile_executor_upgrade(record, Path(directory) / "state")
        write.assert_not_called(); spawn.assert_not_called()

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
