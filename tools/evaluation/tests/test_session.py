#!/usr/bin/env python3
"""Regression for private client state leaking its umask into runtime owners."""

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from session import Client


class ClientPermissionsTest(unittest.TestCase):
    def test_runtime_directories_remain_traversable_with_private_client_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            run = root / "state"
            run.mkdir(mode=0o700)
            # A local process probe; no cluster or deployment artifacts are involved.
            probe = root / "bin/mothership"
            probe.write_text(
                "#!" + sys.executable + "\nimport os\n"
                "os.mkdir(os.environ['PRODIGY_MOTHERSHIP_TIDESDB_PATH'] + '.directory')\n"
            )
            probe.chmod(0o700)
            previous = os.umask(0o077)
            try:
                Client(root, {"run": str(run)}).command("permission-probe")
                (run / "client-state").touch()
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE((run / "mothership.tidesdb.directory").stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((run / "client-state").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(run.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
