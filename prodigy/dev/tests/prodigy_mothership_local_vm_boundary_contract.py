#!/usr/bin/env python3
"""Regression contract for Mothership-owned local KVM launcher execution."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
MOTHERSHIP = (ROOT / "prodigy/mothership/mothership.cpp").read_text()
KVM_BOUNDARY = (ROOT / "prodigy/dev/tests/prodigy_dev_kvm_boundary.py").read_text()
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
        begin = MOTHERSHIP.index("bool runCurrentLocalVMBoundarySealedLauncher")
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
        inspect_begin = MOTHERSHIP.index("bool inspectLocalVMBoundaryExecutor")
        inspect_end = MOTHERSHIP.index("bool queryLocalVMBoundaryExecutor", inspect_begin)
        inspect = MOTHERSHIP[inspect_begin:inspect_end]
        self.assertIn("observedStarttime->assign(starttime.data(), starttime.size())", inspect)
        self.assertNotIn("observedStarttime->setInvariant", inspect)

    def test_boundary_inspection_does_not_mutate_registry_or_lifecycle_and_suppresses_key_comments(self):
        registry = (ROOT / "prodigy/mothership/mothership.cluster.registry.h").read_text()
        registry_begin = registry.index("bool listLocalVMBoundaries")
        registry_end = registry.index("bool findActiveLocalVMBoundary", registry_begin)
        registry_helper = registry[registry_begin:registry_end]
        self.assertIn("db.listValues(localVMBoundariesColumnFamily", registry_helper)
        self.assertNotIn("db.write", registry_helper)
        begin = MOTHERSHIP.index("void runInspectLocalVMBoundaries")
        end = MOTHERSHIP.index("void runFaultLocalClusterMachine", begin)
        command = MOTHERSHIP[begin:end]
        self.assertIn('{"inspectLocalVMBoundaries",        &Mothership::runInspectLocalVMBoundaries', MOTHERSHIP)
        self.assertIn("registry.listLocalVMBoundaries", command)
        self.assertIn("activeLocalVMBoundariesExactForMachines", command)
        self.assertIn("queryLocalVMBoundaryExecutor", command)
        self.assertIn("statePath", command)
        self.assertNotIn("boundary.hostPrivateKeyPath", command)
        self.assertNotIn("boundary.hostPublicKeyOpenSSH", command)
        self.assertNotIn("db.write", command)
        self.assertNotIn("runLocalVMBoundaryExecutorAction", command)
        self.assertIn("never writes the registry or invokes a VM lifecycle action", command)
        self.assertIn("const bool boundaryValid = queried &&", command)
        self.assertIn("valid = valid && boundaryValid", command)
        self.assertNotIn("valid = queried &&", command)
        self.assertIn('"inspectLocalVMBoundaries success=%u', command)
        self.assertNotIn('"inspectLocalVMBoundaries success=1', command)

    def test_executor_upgrade_is_separate_exact_and_rotates_only_after_immutable_proof(self):
        pinned_begin = MOTHERSHIP.index("bool runLocalVMBoundarySealedLauncher")
        pinned_end = MOTHERSHIP.index("bool inspectLocalVMBoundaryExecutor", pinned_begin)
        pinned = MOTHERSHIP[pinned_begin:pinned_end]
        self.assertIn("expectedSHA != descriptor.executorSHA256", pinned)
        self.assertIn("runCurrentLocalVMBoundarySealedLauncher", pinned)
        reconcile_begin = MOTHERSHIP.index("bool reconcileLocalVMBoundaryExecutorBinding")
        reconcile_end = MOTHERSHIP.index("bool awaitLocalAuthorityRecoveryNonSeed", reconcile_begin)
        reconcile = MOTHERSHIP[reconcile_begin:reconcile_end]
        self.assertIn("reconcileLocalVMBoundaryExecutorForUpgrade", reconcile)
        self.assertIn("if ((expectedOperationUUID == 0) != (expectedCohortUUID == 0))", reconcile)
        resume_guard = reconcile.index(
            "if (!refreshRequired && expectedOperationUUID != 0 && expectedCohortUUID != 0) return true")
        self.assertLess(resume_guard, reconcile.index("reconcileLocalVMBoundaryExecutorForUpgrade"))
        self.assertLess(reconcile.index("immutable != boundary.immutableStateSHA256"),
                        reconcile.index("refreshLocalVMBoundaryExecutor"))
        self.assertIn('set(prior) == legacy_fields', KVM_BOUNDARY)
        self.assertIn('proc_starttime(pid) is None', KVM_BOUNDARY)
        self.assertIn('"incomplete lifecycle operation is not owned by this recovery cohort"', KVM_BOUNDARY)

    def test_verified_vm_probe_does_not_reopen_the_live_brain_store(self):
        begin = MOTHERSHIP.index("bool buildLocalClusterMachineProbe")
        end = MOTHERSHIP.index("bool findLocalClusterMachineInTopology", begin)
        helper = MOTHERSHIP[begin:end]
        verified = helper.index("if (verifiedLocalVM)")
        fallback = helper.index("ProdigyPersistentStateStore persistentStateStore")
        self.assertLess(verified, fallback)
        self.assertIn("localMachine.uuid = verifiedLocalVMUUID", helper[verified:fallback])
        self.assertIn("else\n    {\n      ProdigyPersistentStateStore", helper[verified:fallback + 80])

    def test_authority_recovery_seed_uses_only_stored_topology_and_fails_closed(self):
        begin = MOTHERSHIP.index("bool findLocalAuthorityRecoverySeedMachine")
        end = MOTHERSHIP.index("bool bootstrapLocalClusterMachine", begin)
        helper = MOTHERSHIP[begin:end]
        self.assertIn("prodigyCollectLocalPeerAddressCandidates", helper)
        self.assertIn("matches == 0", helper)
        self.assertIn("matches != 1", helper)
        self.assertIn("MachineConfig::MachineKind::vm", helper)
        self.assertNotIn("ProdigyPersistentStateStore", helper)

        begin = MOTHERSHIP.index("void runRecoverLocalClusterAuthority")
        end = MOTHERSHIP.index("void runPrepareProductionPair", begin)
        owner = MOTHERSHIP[begin:end]
        self.assertIn("findLocalAuthorityRecoverySeedMachine(cluster.topology, seedMachine, &failure)", owner)
        self.assertNotIn("buildLocalClusterMachineProbe(cluster, seedMachine", owner)

    def test_authority_recovery_retry_retains_its_admitted_topology_generation(self):
        begin = MOTHERSHIP.index("void runRecoverLocalClusterAuthority")
        end = MOTHERSHIP.index("void runPrepareProductionPair", begin)
        owner = MOTHERSHIP[begin:end]
        self.assertIn(
            "request.topologyVersion = existingCohort ?\n"
            "          existingCohortRecord.request.topologyVersion : cluster.topology.version;",
            owner,
        )
        self.assertIn(
            "mothershipLocalAuthorityRecoveryTopologyMatches(existingCohortRecord.request, cluster.topology)",
            owner,
        )
        self.assertIn(
            "mothershipPhysicalFaultExactSerializedEqual(existingCohortRecord.request, request)",
            owner,
        )

    def test_cold_reboot_accepts_only_fixed_width_provider_operation_identity(self):
        self.assertIn('re.fullmatch(r"[0-9a-f]{32}", value) is not None', KVM_BOUNDARY)
        self.assertIn('canonical_cold_reboot_id(options.get("--operation-id"), "operation ID")', KVM_BOUNDARY)
        begin = MOTHERSHIP.index("bool runLocalVMBoundaryExecutorAction")
        end = MOTHERSHIP.index("void runPrepareProductionPair", begin)
        helper = MOTHERSHIP[begin:end]
        self.assertIn("mothershipAssignProviderHex128(operationUUID, operation);", helper)
        self.assertNotIn("operation.assignItoh", helper)

    def test_cold_reboot_parser_accepts_only_the_completed_executor_receipt(self):
        begin = MOTHERSHIP.index("bool runLocalVMBoundaryExecutorAction")
        end = MOTHERSHIP.index("enum class LocalAuthorityRecoveryExecutorPhase", begin)
        helper = MOTHERSHIP[begin:end]
        self.assertIn('document.get_object().size() != 11', helper)
        self.assertIn('document["phase"].get(phase) || phase != "completed"', helper)
        self.assertIn('completedAtMonotonicMs - startedAtMonotonicMs > timeoutMilliseconds', helper)
        self.assertIn('completedAtMonotonicMs=completed_at, phase="completed"', KVM_BOUNDARY)

    def test_authority_recovery_receipt_owns_process_identity_strings(self):
        begin = MOTHERSHIP.index("bool parseLocalAuthorityRecoveryExecutorReceipt")
        end = MOTHERSHIP.index("bool runLocalAuthorityRecoveryExecutor", begin)
        parser = MOTHERSHIP[begin:end]
        self.assertIn("receipt.beforeStarttime.assign(beforeStarttime.data(), beforeStarttime.size())", parser)
        self.assertIn("receipt.afterStarttime.assign(afterStarttime.data(), afterStarttime.size())", parser)
        self.assertNotIn("receipt.beforeStarttime.setInvariant", parser)
        self.assertNotIn("receipt.afterStarttime.setInvariant", parser)

    def test_authority_recovery_arms_all_boundaries_and_releases_the_seed_last(self):
        begin = MOTHERSHIP.index("void runRecoverLocalClusterAuthority")
        end = MOTHERSHIP.index("void runPrepareProductionPair", begin)
        owner = MOTHERSHIP[begin:end]
        self.assertIn('"arm-cold-reboot"', owner)
        self.assertIn('"release-cold-reboot"', owner)
        peer_completion = owner.index("!awaitLocalAuthorityRecoveryNonSeed")
        seed_release = owner.index("targets[seedIndex].boundary")
        self.assertLess(peer_completion, seed_release)
        self.assertIn("if (targets[index].localSeed", owner)
        self.assertIn("MothershipLocalAuthorityRecoveryPhase::armed", owner)
        self.assertIn("MothershipLocalAuthorityRecoveryPhase::released", owner)
        self.assertIn("awaitLocalAuthorityRecoveryClusterHealth", owner)
        self.assertIn("existingCohort ? target.executor.executorOperationUUID", owner)
        self.assertIn("existingCohort ? operationUUID", owner)
        self.assertIn("exit(75)", owner)
        self.assertIn("COLD_REBOOT_RELEASE_GRACE_MS", KVM_BOUNDARY)
        self.assertIn('current["notBeforeUnixMs"] = max', KVM_BOUNDARY)


if __name__ == "__main__":
    unittest.main()
