#!/usr/bin/env python3
"""Pure receipt-fence checks for prodigy_dev_retained_quorum_observer."""
import importlib.util
import pathlib
import socket
import struct
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("retained_quorum", HERE / "prodigy_dev_retained_quorum_observer.py")
assert SPEC and SPEC.loader
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


class RetainedQuorumObserverTests(unittest.TestCase):
    def test_inet_diag_normalizes_ipv4_mapped_and_keeps_inverse_ipv6_endpoint_matches_exact(self):
        mapped = {"family": "AF_INET6", "source": "::ffff:10.0.0.10", "sourcePort": 313,
                  "destination": "::ffff:10.0.0.11", "destinationPort": 44000,
                  "cookie": "0x0102030405060708"}
        master6 = {"family": "AF_INET6", "source": "fd00:31::a", "sourcePort": 313,
                   "destination": "fd00:31::b", "destinationPort": 44000,
                   "cookie": "0x1112131415161718"}
        witness6 = {"family": "AF_INET6", "source": "fd00:31::b", "sourcePort": 44000,
                    "destination": "fd00:31::a", "destinationPort": 313,
                    "cookie": "0x2122232425262728"}
        original = observer.dump_namespace
        try:
            observer.dump_namespace = lambda _pid: [mapped]
            matches, _raw = observer.exact_pair_sockets(1, {"10.0.0.10"}, {"10.0.0.11"})
            self.assertEqual(matches[0]["source"], "10.0.0.10")
            self.assertEqual(matches[0]["destination"], "10.0.0.11")

            observer.dump_namespace = lambda pid: [master6] if pid == 1 else [witness6]
            master, _raw = observer.exact_pair_sockets(1, {"fd00:31::a"}, {"fd00:31::b"})
            witness, _raw = observer.exact_pair_sockets(2, {"fd00:31::b"}, {"fd00:31::a"})
            self.assertEqual(
                (master[0]["source"], master[0]["sourcePort"], master[0]["destination"], master[0]["destinationPort"]),
                (witness[0]["destination"], witness[0]["destinationPort"], witness[0]["source"], witness[0]["sourcePort"]))

            observer.dump_namespace = lambda _pid: [mapped, dict(mapped, cookie="0x9999999999999999")]
            with self.assertRaises(observer.ObservationError):
                observer.exact_pair_sockets(1, {"10.0.0.10"}, {"10.0.0.11"})
        finally:
            observer.dump_namespace = original

    def test_report_parser_requires_exact_three_with_one_master(self):
        report = """\
 Machine: state=healthy role=brain
  identity uuid=0x1 source=created sshAddress=10.0.0.10 sshPort=22
  lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=1
 Machine: state=healthy role=brain
  identity uuid=0x2 source=created sshAddress=10.0.0.11 sshPort=22
  lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=0
 Machine: state=healthy role=brain
  identity uuid=0x3 source=created sshAddress=10.0.0.12 sshPort=22
  lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=0
"""
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "report.log"
            path.write_text(report)
            self.assertEqual(observer.parse_cluster_report(path)[0], {"uuid": "0x1", "address": "10.0.0.10", "master": True})
            for invalid in (report.split(' Machine:')[0] + ' Machine:'.join(report.split(' Machine:')[:3]),
                            report.replace('currentMaster=0', 'currentMaster=1', 1)):
                path.write_text(invalid)
                with self.assertRaises(observer.ObservationError):
                    observer.parse_cluster_report(path)

    def receipt(self, log: pathlib.Path):
        metadata = log.stat()
        process = {"starttime": "20", "netns": "net:[1]", "cgroup": "0::/x\n", "exe": "/runtime", "exeSHA256": "a" * 64}
        socket = {"source": "10.0.0.10", "sourcePort": 313, "destination": "10.0.0.11", "destinationPort": 44000, "cookie": "0x0102030405060708"}
        reverse = {"source": "10.0.0.11", "sourcePort": 44000, "destination": "10.0.0.10", "destinationPort": 313, "cookie": "0x1112131415161718"}
        return {"selectedIndex": 3, "selectedIPv4": "10.0.0.12", "masterIndex": 1, "witnessIndex": 2, "brainPort": 313,
                "masterSocket": socket, "witnessSocket": reverse,
                "members": {str(index): {"machineIndex": index, "uuid": f"0x{index}", "ipv4": f"10.0.0.1{index - 1}",
                                           "process": dict(process, pid=100 + index), "log": str(log), "logOffset": 0,
                                           "logDevice": metadata.st_dev, "logInode": metadata.st_ino}
                            for index in (1, 2)}}

    def test_receipt_rejects_cookie_identity_logswap_and_foreign_role_but_allows_selected_drop(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "brain.log"
            log.write_bytes(b"")
            prior = self.receipt(log)
            current = self.receipt(log)
            current["masterSocket"] = dict(current["masterSocket"], cookie="0x9999999999999999")
            with self.assertRaises(observer.ObservationError):
                observer.verify_before_after(prior, current)

            current = self.receipt(log)
            current["members"]["1"]["process"]["exeSHA256"] = "b" * 64
            with self.assertRaises(observer.ObservationError):
                observer.verify_before_after(prior, current)

            private4 = struct.unpack("=I", socket.inet_aton("10.0.0.12"))[0]
            log.write_text(f"brainMissing private4={private4} expected selected follower\n")
            current = self.receipt(log)
            self.assertEqual(observer.verify_before_after(prior, current)["result"], "bounded-socket-continuity-evidence")

            # A role transition is never exempt merely because it mentions the selected follower.
            prior = self.receipt(log)
            log.write_text(log.read_text() + f"selfElectAsMaster begin private4={private4}\n")
            current = self.receipt(log)
            with self.assertRaises(observer.ObservationError):
                observer.verify_before_after(prior, current)

    def peer_memory(self, receipt):
        snapshots = []
        members = receipt["members"]
        for index, member in members.items():
            other_index = next(value for value in members if value != index)
            other = members[other_index]
            snapshots.append({
                "pid": member["process"]["pid"],
                "processIdentitySHA256": f"identity-{index}",
                "exeSHA256": "a" * 64,
                "loadBaseSHA256": f"base-{index}",
                "structuralSnapshotSHA256": f"structure-{index}",
                "views": [{"uuid": other["uuid"], "private4": observer.native_private4(other["ipv4"]),
                           "quarantined": False, "connected": True, "isFixedFile": True,
                           "fslot": 8 + int(index), "transportEpoch": 7,
                           "queuedCloseTransportEpoch": 0}]
            })
        return {"result": "bounded-initial-eligibility-observation", "layoutSHA256": "f" * 64,
                "snapshots": snapshots}

    def test_peer_memory_requires_both_boundaries_and_unchanged_surviving_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "brain.log"
            log.write_bytes(b"")
            prior = self.receipt(log)
            prior["peerMemory"] = self.peer_memory(prior)
            current = self.receipt(log)
            current["peerMemory"] = self.peer_memory(current)
            self.assertEqual(observer.verify_before_after(prior, current)["result"],
                             "bounded-peer-eligibility-and-socket-continuity")

            changed_epoch = self.receipt(log)
            changed_epoch["peerMemory"] = self.peer_memory(changed_epoch)
            changed_epoch["peerMemory"]["snapshots"][0]["views"][0]["transportEpoch"] = 8
            with self.assertRaises(observer.ObservationError):
                observer.verify_before_after(prior, changed_epoch)

            missing = self.receipt(log)
            with self.assertRaises(observer.ObservationError):
                observer.verify_before_after(prior, missing)

            changed_layout = self.receipt(log)
            changed_layout["peerMemory"] = self.peer_memory(changed_layout)
            changed_layout["peerMemory"]["layoutSHA256"] = "e" * 64
            with self.assertRaises(observer.ObservationError):
                observer.verify_before_after(prior, changed_layout)

    def test_initial_loss_scan_needs_compiler_evidence_and_rejects_pair_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            ninja = root / "build.ninja"
            ninja.write_text("build CMakeFiles/prodigy.dir/x.o: CXX_COMPILER\n  DEFINES = -DBASICS_DEBUG=1\n")
            self.assertTrue(observer.legacy_basics_log_visible(ninja))
            log = root / "brain.log"
            log.write_text(f"brainMissing private4={observer.native_private4('10.0.0.10')}\n")
            members = {"1": {"ipv4": "10.0.0.10", "log": str(log)},
                       "2": {"ipv4": "10.0.0.11", "log": str(log)}}
            with self.assertRaises(observer.ObservationError):
                observer.scan_initial_peer_loss_logs(members)
            ninja.write_text("build CMakeFiles/prodigy.dir/x.o: CXX_COMPILER\n  DEFINES = -DPRODIGY_DEBUG=0\n")
            self.assertFalse(observer.legacy_basics_log_visible(ninja))

            prior = self.receipt(log)
            replacement = pathlib.Path(directory) / "replacement.log"
            replacement.write_text("new log\n")
            replacement.replace(log)
            current = self.receipt(log)
            with self.assertRaises(observer.ObservationError):
                observer.verify_before_after(prior, current)


if __name__ == "__main__":
    unittest.main()
