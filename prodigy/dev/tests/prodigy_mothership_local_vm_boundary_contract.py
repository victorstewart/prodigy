#!/usr/bin/env python3
"""Regression contract for Mothership-owned local KVM launcher execution."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
MOTHERSHIP = (ROOT / "prodigy/mothership/mothership.cpp").read_text()
CMAKE = (ROOT / "prodigy/dev/CMakeLists.txt").read_text()


class LocalVMBoundaryOwnerContract(unittest.TestCase):
    def test_launcher_is_embedded_and_cli_cannot_choose_its_authority(self):
        self.assertIn('PRODIGY_LOCAL_VM_BOUNDARY_SOURCE "${PRODIGY_ROOT}/prodigy/dev/tests/prodigy_dev_kvm_boundary.py"', CMAKE)
        self.assertIn("mothershipLocalVMBoundarySource", CMAKE)
        self.assertIn('#include "mothership.local.vm.boundary.inc"', MOTHERSHIP)
        self.assertIn("bool valid = argc == 10", MOTHERSHIP)
        help_line = next(line for line in MOTHERSHIP.splitlines() if line.startswith('    message.append("registerLocalVMBoundary'))
        self.assertNotIn("executorPath", help_line)
        self.assertNotIn("executorSHA256", help_line)

    def test_hash_and_execution_share_one_opened_remote_descriptor(self):
        begin = MOTHERSHIP.index("bool runLocalVMBoundarySealedLauncher")
        end = MOTHERSHIP.index("bool queryLocalVMBoundaryExecutor", begin)
        helper = MOTHERSHIP[begin:end]
        self.assertIn("mothershipLocalVMBoundarySource", helper)
        self.assertIn("os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)", helper)
        self.assertIn("digest.hexdigest()==expected", helper)
        self.assertIn("/proc/self/fd/%d", helper)
        self.assertNotIn("descriptor.executorPath", helper)
        query_begin = MOTHERSHIP.index("bool queryLocalVMBoundaryExecutor")
        query_end = MOTHERSHIP.index("bool runLocalVMBoundaryExecutorAction", query_begin)
        self.assertNotIn("sha256sum --", MOTHERSHIP[query_begin:query_end])


if __name__ == "__main__":
    unittest.main()
