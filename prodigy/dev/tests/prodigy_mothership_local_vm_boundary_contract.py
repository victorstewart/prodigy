#!/usr/bin/env python3
"""Regression contract for Mothership-owned local KVM launcher execution."""

from pathlib import Path
import importlib.util
import tempfile
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

    def test_cluster_lan_ipv6_is_one_exact_serialized_boundary_action(self):
        begin = MOTHERSHIP.index("void runConfigureLocalVMClusterLANIPv6")
        end = MOTHERSHIP.index("void runFaultLocalClusterMachine", begin)
        command = MOTHERSHIP[begin:end]
        self.assertIn('argc == 1', command)
        self.assertIn('activeLocalVMBoundariesExactForMachines', command)
        self.assertIn('reconcileLocalVMBoundaryExecutorBinding(boundary, failure)', command)
        self.assertIn('arguments.emplace_back("configure-cluster-lan-ipv6"_ctv)', command)
        self.assertIn('runLocalVMBoundarySealedLauncher(boundary, arguments', command)
        self.assertIn('/etc/systemd/network/10-cloud-init-lan0.network.d/50-prodigy-cluster-lan-ipv6.conf', command)
        self.assertIn('afterPID != observedPIDs[index]', command)
        self.assertIn('{"configureLocalVMClusterLANIPv6",  &Mothership::runConfigureLocalVMClusterLANIPv6', MOTHERSHIP)
        self.assertNotIn('guest command', command.lower())

    def test_fresh_local_vm_launch_is_a_fixed_persistent_sealed_boundary_action(self):
        begin = MOTHERSHIP.index("[[noreturn]] void runLaunchLocalVM")
        end = MOTHERSHIP.index("void runPrepareRetainedRecoveryArtifactLocal", begin)
        command = MOTHERSHIP[begin:end]
        self.assertIn('arguments.emplace_back("launch"_ctv)', command)
        self.assertIn('arguments.emplace_back("--state"_ctv); arguments.emplace_back(argv[0])', command)
        self.assertIn('arguments.emplace_back("--task-id"_ctv); arguments.emplace_back(argv[1])', command)
        self.assertIn('arguments.emplace_back("--"_ctv)', command)
        self.assertIn('arguments.emplace_back("--qemu"_ctv); arguments.emplace_back("qemu-system-x86_64"_ctv)', command)
        self.assertIn('arguments.emplace_back("--qemu-img"_ctv); arguments.emplace_back("qemu-img"_ctv)', command)
        self.assertIn('arguments.emplace_back("--ssh"_ctv); arguments.emplace_back("ssh"_ctv)', command)
        caller_arguments = command.index('for (int index = 2; index < argc; ++index) arguments.emplace_back(argv[index])')
        fixed_qemu = command.index('arguments.emplace_back("--qemu"_ctv)', caller_arguments)
        delimiter = command.index('arguments.emplace_back("--"_ctv)')
        self.assertEqual(command.count('arguments.emplace_back("--"_ctv)'), 1)
        self.assertLess(delimiter, caller_arguments)
        self.assertLess(caller_arguments, fixed_qemu)
        self.assertIn('mothershipRunSealedPythonProvider("mothership-local-vm-boundary"', command)
        self.assertIn('sizeof(mothershipLocalVMBoundarySource)', command)
        self.assertIn('std::strcmp(argv[index], "--") == 0', command)
        self.assertNotIn('runLocalVMBoundaryExecutorAction', command)
        self.assertNotIn('recover-stopped', command)
        self.assertIn('{"launchLocalVM",                   &Mothership::runLaunchLocalVM', MOTHERSHIP)
        help_line = next(line for line in MOTHERSHIP.splitlines() if line.startswith('    message.append("launchLocalVM'))
        self.assertIn("boundary launch arguments", help_line)

    def test_fresh_launch_vector_reaches_the_existing_parser_and_pins_executables(self):
        spec = importlib.util.spec_from_file_location("local_vm_launch_contract",
            ROOT / "prodigy/dev/tests/prodigy_dev_kvm_boundary.py")
        boundary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boundary)
        with tempfile.TemporaryDirectory() as temporary:
            caller = ["--base-image", "base", "--base-sha256", "0" * 64,
                "--ovmf-code", "code", "--ovmf-code-sha256", "0" * 64,
                "--ovmf-vars", "vars", "--ovmf-vars-sha256", "0" * 64,
                "--guest-uuid", "12345678-1234-4234-9234-123456789abc",
                "--expected-machine-id", "1" * 32, "--known-hosts", "known",
                "--ssh-private-key", "key", "--ssh-port", "22223",
                "--work-dir", temporary, "--evidence-dir", temporary,
                "--memory-mb", "16384", "--disk-size-gb", "64",
                "--qemu", "unowned-qemu", "--qemu-i", "unowned-img", "--ssh", "unowned-ssh"]
            pinned = ["--qemu", "qemu-system-x86_64", "--qemu-img", "qemu-img", "--ssh", "ssh"]
            operation, _, _, remainder = boundary.lifecycle_arguments([
                "launch", "--state", str(Path(temporary) / "boundary.json"),
                "--task-id", "nametag-unit", "--", *caller, *pinned])
            self.assertEqual(operation, "launch")
            self.assertEqual(remainder[0], "--")
            parsed = boundary.parse_args(remainder[1:] + ["--", "true"])
            self.assertEqual((parsed.qemu, parsed.qemu_img, parsed.ssh),
                             ("qemu-system-x86_64", "qemu-img", "ssh"))
            self.assertEqual((parsed.memory_mb, parsed.disk_size_gb), (16384, 64))
            self.assertEqual(parsed.guest_command, ["true"])

    def test_remove_local_vm_is_the_fixed_sealed_idempotent_boundary_action(self):
        begin = MOTHERSHIP.index("[[noreturn]] void runRemoveLocalVM")
        end = MOTHERSHIP.index("void runPrepareRetainedRecoveryArtifactLocal", begin)
        command = MOTHERSHIP[begin:end]
        self.assertIn('argc != 2 || argv[0][0] != \'/\'', command)
        self.assertIn('arguments.emplace_back("remove"_ctv)', command)
        self.assertIn('arguments.emplace_back("--state"_ctv); arguments.emplace_back(argv[0])', command)
        self.assertIn('arguments.emplace_back("--task-id"_ctv); arguments.emplace_back(argv[1])', command)
        self.assertIn('mothershipRunSealedPythonProvider("mothership-local-vm-boundary"', command)
        self.assertNotIn('runLocalVMBoundaryExecutorAction', command)
        self.assertNotIn('recover-stopped', command)
        self.assertIn('{"removeLocalVM",                   &Mothership::runRemoveLocalVM', MOTHERSHIP)
        self.assertIn('if operation == "remove" and not state_path.exists():\n        return 0', KVM_BOUNDARY)

        spec = importlib.util.spec_from_file_location("local_vm_remove_contract",
            ROOT / "prodigy/dev/tests/prodigy_dev_kvm_boundary.py")
        boundary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boundary)
        with tempfile.TemporaryDirectory() as temporary:
            operation, _, task_id, remainder = boundary.lifecycle_arguments([
                "remove", "--state", str(Path(temporary) / "boundary.json"),
                "--task-id", "nametag-unit"])
        self.assertEqual((operation, task_id, remainder), ("remove", "nametag-unit", []))

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
        admitted_runtime = owner.index(
            "request.admittedRuntime=existingCohortRecord.request.admittedRuntime;"
        )
        prepare_runtime = owner.index("valid=prepareLocalRecoveryRuntimeIntent", admitted_runtime)
        self.assertLess(admitted_runtime, prepare_runtime)
        self.assertIn(
            "if (valid && existingCohort &&\n"
            "          !mothershipLocalAuthorityRecoveryTopologyMatches(existingCohortRecord.request, cluster.topology)",
            owner,
        )
        self.assertIn(
            "else if (valid && existingCohort &&\n"
            "               !mothershipPhysicalFaultExactSerializedEqual(existingCohortRecord.request, request)",
            owner,
        )

    def test_cold_reboot_accepts_only_fixed_width_provider_operation_identity(self):
        self.assertIn('re.fullmatch(r"[0-9a-f]{32}", value) is not None', KVM_BOUNDARY)
        self.assertIn('canonical_cold_reboot_id(options.get("--operation-id"), "operation ID")', KVM_BOUNDARY)
        begin = MOTHERSHIP.index("bool runLocalVMBoundaryExecutorAction")
        end = MOTHERSHIP.index("enum class LocalAuthorityRecoveryExecutorPhase", begin)
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

    def test_interrupted_upgrade_keeps_existing_executor_and_installs_before_release(self):
        begin = MOTHERSHIP.index("void runRecoverLocalClusterAuthority")
        end = MOTHERSHIP.index("void runPrepareProductionPair", begin)
        owner = MOTHERSHIP[begin:end]
        self.assertIn('(argc == 3 || interruptedUpgrade)', owner)
        self.assertIn('"--complete-interrupted-upgrade"', owner)
        install = owner.index("!installLocalRecoveryRuntime(cluster,targets[index]")
        release = owner.index('"release-cold-reboot"', install)
        observed = owner.index("!awaitLocalAuthorityRecoveryNonSeed", release)
        activate = owner.index("!activateLocalRecoveryRuntime(cluster,targets[index]", observed)
        self.assertLess(install, release)
        self.assertLess(observed, activate)
        seed_install = owner.index("!installLocalRecoveryRuntime(cluster,targets[seedIndex]")
        self.assertLess(seed_install, owner.index('"release-cold-reboot"', seed_install))
        completion = owner.index("localRecoveryRuntimeFreshAuthority(cluster,request,repairBundle,true,failure)",
                                 owner.index("ClusterStatusReport status"))
        self.assertLess(completion, owner.index("MothershipLocalAuthorityRecoveryPhase::recovered, completedReceiptSHA256s", completion))
        self.assertNotIn("qemu-system", owner)
        self.assertNotIn("beginUpdateSelfBundle", owner)

    def test_admitted_active_runtime_reuses_the_guarded_recovery_owner(self):
        begin = MOTHERSHIP.index("bool prepareLocalRecoveryRuntimeIntent")
        end = MOTHERSHIP.index("bool installLocalRecoveryRuntime", begin)
        prepare = MOTHERSHIP[begin:end]
        self.assertIn('"--admitted-active-runtime"', prepare)
        self.assertIn("admittedRuntimeUpgradeVersion", prepare)
        self.assertIn("loadUpgradeAdmission", prepare)
        self.assertIn("captureLocalRecoveryWorkloads", prepare)
        self.assertIn("localRecoveryRuntimeFreshAuthority", prepare)
        owner_begin = MOTHERSHIP.index("void runRecoverLocalClusterAuthority")
        owner_end = MOTHERSHIP.index("void runPrepareProductionPair", owner_begin)
        owner = MOTHERSHIP[owner_begin:owner_end]
        self.assertIn("prepareLocalRecoveryRuntimeIntent", owner)
        self.assertIn("reconcileLocalVMBoundaryExecutorBinding", owner)
        self.assertIn('"arm-cold-reboot"', owner)
        self.assertIn("installLocalRecoveryRuntime", owner)
        self.assertIn('"release-cold-reboot"', owner)
        self.assertIn("activateLocalRecoveryRuntime", owner)
        fault_begin = MOTHERSHIP.index("void runFaultLocalClusterMachine")
        fault_end = MOTHERSHIP.index("struct PhysicalFaultProviderRequest", fault_begin)
        self.assertNotIn("admitted-active-runtime", MOTHERSHIP[fault_begin:fault_end])

    def test_interrupted_install_and_activation_reconcile_durable_progress(self):
        begin = MOTHERSHIP.index("bool installLocalRecoveryRuntime")
        end = MOTHERSHIP.index("bool activateLocalRecoveryRuntime", begin)
        install = MOTHERSHIP[begin:end]
        self.assertLess(install.index('"query",0,request.timeoutMilliseconds'),
                        install.index("if(!progress.installDispatched)"))
        self.assertIn("if(reboot.phase!=LocalAuthorityRecoveryExecutorPhase::armed)", install)
        dispatched = install.index("progress.installDispatched=true")
        checkpoint = install.index("checkpointLocalRecoveryRuntime", dispatched)
        self.assertLess(checkpoint, install.index("runtimeStartupFenceCommand", checkpoint))
        baseline = install.index("progress.stateSHA256=stateSHA")
        self.assertLess(install.index("checkpointLocalRecoveryRuntime", baseline),
                        install.index("retainedRuntimePublicationCommand", baseline))
        self.assertIn("stateSHA==progress.stateSHA256 && secretsSHA==progress.secretsSHA256", install)
        activation = MOTHERSHIP[end:MOTHERSHIP.index("void runRecoverLocalClusterAuthority", end)]
        self.assertIn("progress.activationBootID!=boot", activation)
        self.assertLess(activation.index("progress.activationBootID=boot"), activation.index("systemctl start prodigy"))
        self.assertIn("localRecoveryGatewayInventory(record.request,member.machineUUID,true)", activation)

    def test_seed_runtime_install_uses_verified_local_owner_and_observation_program_parses(self):
        begin = MOTHERSHIP.index("bool localRecoveryRuntimeCommand")
        end = MOTHERSHIP.index("static std::string localRecoveryRuntimeRoot", begin)
        transport = MOTHERSHIP[begin:end]
        self.assertIn("resolveVerifiedDisposableLocalVMIdentity", transport)
        self.assertIn("local!=target.executor.machineUUID", transport)
        self.assertIn("mothershipConnectSSHSession", transport)
        self.assertIn("machine.ssh.hostPublicKeyOpenSSH.empty()", transport)
        self.assertNotIn("StrictHostKeyChecking=no", transport)
        self.assertNotIn("qemu", transport)
        program = MOTHERSHIP.split("python3 - <<'LOCAL_RUNTIME'\n", 1)[1].split("\nLOCAL_RUNTIME\n", 1)[0]
        compile(program, "embedded-local-runtime-observation", "exec")
        self.assertIn("split(b'\\0')", program)


if __name__ == "__main__":
    unittest.main()
