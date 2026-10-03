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
    def arguments(self, root: Path, *command: str, egress: str = "isolated", disk_size_gb: int | None = None):
        files = {}
        for name in ("base.qcow2", "OVMF_CODE.fd", "OVMF_VARS.fd", "known_hosts", "key"):
            files[name] = root / name; files[name].write_bytes(b"pinned-" + name.encode()); files[name].chmod(0o400)
        disk = [] if disk_size_gb is None else ["--disk-size-gb", str(disk_size_gb)]
        return KVM.parse_args(["--base-image", str(files["base.qcow2"]), "--base-sha256", KVM.digest(files["base.qcow2"]), "--ovmf-code", str(files["OVMF_CODE.fd"]), "--ovmf-code-sha256", KVM.digest(files["OVMF_CODE.fd"]), "--ovmf-vars", str(files["OVMF_VARS.fd"]), "--ovmf-vars-sha256", KVM.digest(files["OVMF_VARS.fd"]), "--guest-uuid", "12345678-1234-4234-9234-123456789abc", "--expected-machine-id", "0123456789abcdef0123456789abcdef", "--known-hosts", str(files["known_hosts"]), "--ssh-private-key", str(files["key"]), "--ssh-port", "22222", "--work-dir", str(root / "work"), "--evidence-dir", str(root / "evidence"), "--guest-egress", egress, *disk, "--", *command])

    def test_command_requires_kvm_uefi_uuid_and_loopback_only(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "echo", "ok")
            rendered = " ".join(KVM.qemu_command(args, Path(directory) / "overlay.qcow2", Path(directory) / "vars.fd"))
        self.assertIn("-accel kvm", rendered); self.assertIn("-machine q35", rendered); self.assertIn("-uuid 12345678-1234-4234-9234-123456789abc", rendered)
        self.assertIn("hostfwd=tcp:127.0.0.1:22222-:22", rendered); self.assertIn("restrict=on", rendered); self.assertIn("if=pflash", rendered)
        self.assertNotIn("tcg", rendered.lower()); self.assertNotIn("tap", rendered.lower()); self.assertNotIn("bridge", rendered.lower())

    def test_explicit_wan_egress_removes_only_default_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(Path(directory), "true", egress="wan")
            rendered = " ".join(KVM.qemu_command(args, Path(directory) / "overlay", Path(directory) / "vars"))
        self.assertIn("hostfwd=tcp:127.0.0.1:22222-:22", rendered); self.assertNotIn("restrict=on", rendered)

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


if __name__ == "__main__": unittest.main()
