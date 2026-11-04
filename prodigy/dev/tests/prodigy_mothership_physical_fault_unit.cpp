#include <prodigy/mothership/mothership.physical.fault.h>
#include <services/debug.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>

class TestSuite {
public:
  int failed = 0;
  void expect(bool condition, const char *name)
  {
    std::printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) ++failed;
  }
};

static String digest(char byte)
{
  String result = {};
  for (uint32_t index = 0; index != 64; ++index) result.append(byte);
  return result;
}

// Frozen v1 layout, independent of the new conditional serializer branches.
struct LocalRecoveryRequestV1Fixture { MothershipLocalAuthorityRecoveryCohortRequest value; };
template<typename S> static void serialize(S&& s,LocalRecoveryRequestV1Fixture& old) {
  auto& r=old.value;s.value4b(r.protocolVersion);s.value16b(r.operationUUID);s.value16b(r.clusterUUID);
  s.value8b(r.topologyVersion);s.value4b(r.timeoutMilliseconds);s.object(r.executors);
}
struct LocalRecoveryRecordV1Fixture {
  uint32_t version=1;LocalRecoveryRequestV1Fixture request;
  MothershipLocalAuthorityRecoveryPhase phase=MothershipLocalAuthorityRecoveryPhase::admitted;
  Vector<MothershipLocalAuthorityRecoveryBoundaryProgress> boundaries;
};
template<typename S> static void serialize(S&& s,LocalRecoveryRecordV1Fixture& old) {
  s.value4b(old.version);s.object(old.request);s.value1b(old.phase);s.object(old.boundaries);
}

static MothershipPhysicalFaultMachineObservation observation(uint128_t cluster, uint128_t machine,
                                                             uint64_t topology, char state)
{
  MothershipPhysicalFaultMachineObservation value = {};
  value.clusterUUID = cluster; value.machineUUID = machine; value.topologyVersion = topology;
  value.stateSHA256 = digest(state);
  return value;
}

int main(void)
{
  TestSuite suite;
  String failure = {};

  auto sourceRoot = std::filesystem::path(__FILE__).parent_path().parent_path();
  if (!std::filesystem::exists(sourceRoot / "mothership")) sourceRoot = sourceRoot.parent_path();
  const auto mothershipSource = sourceRoot / "mothership" / "mothership.cpp";
  std::ifstream sourceFile(mothershipSource);
  const std::string source((std::istreambuf_iterator<char>(sourceFile)), std::istreambuf_iterator<char>());
  suite.expect(source.find("exactUDPLinkNetdev") != std::string::npos &&
                   source.find("exactUDPHubport") != std::string::npos &&
                   source.find("hubport,id=clusterlan,hubid=0") != std::string::npos &&
                   source.find("UDP cluster links are not contiguous") != std::string::npos,
               "local_vm_boundary_contract_accepts_only_bounded_udp_hub_lan");
  suite.expect(source.find("exactMulticastNetdev") != std::string::npos &&
                   source.find("unapproved host-network QEMU backend") != std::string::npos,
               "local_vm_boundary_contract_retains_legacy_lan_and_host_backend_rejection");

  String providerIdentity = {};
  mothershipAssignProviderHex128(uint128_t(1), providerIdentity);
  suite.expect(providerIdentity == "00000000000000000000000000000001"_ctv,
               "provider_identity_is_fixed_width_lowercase_without_prefix");
  mothershipAssignProviderHex128(
      String::numberFromHexString<uint128_t>("c776150f4271478e84caada31f261c77"_ctv),
      providerIdentity);
  suite.expect(providerIdentity == "c776150f4271478e84caada31f261c77"_ctv,
               "provider_identity_preserves_all_128_bits");

  const auto providerSection = [&](const char *begin, const char *end) {
    const size_t first = source.find(begin);
    const size_t last = first == std::string::npos ? std::string::npos : source.find(end, first);
    return first == std::string::npos || last == std::string::npos ? std::string() :
        source.substr(first, last - first);
  };
  const std::string pairArguments = providerSection(
      "void productionPairProviderArguments", "bool parseProductionPairProviderOutput");
  const std::string pairRunner = providerSection(
      "bool runProductionPairProvider", "bool parseProductionPairIngressWitness");
  const std::string pairOutput = providerSection(
      "bool parseProductionPairProviderOutput", "bool mothershipRunRemoteSealedPythonProvider");
  const std::string pairWitness = providerSection(
      "bool parseProductionPairIngressWitness", "bool productionPairIngressWitness");
  const std::string productionPairCommand = providerSection(
      "void runProductionPair", "void runPrepareTestPairMigration");
  const std::string prepareProductionPairCommand = providerSection(
      "void runPrepareProductionPair", "void runRegisterLocalVMBoundary");
  const std::string localAction = providerSection(
      "bool runLocalVMBoundaryExecutorAction", "enum class LocalAuthorityRecoveryExecutorPhase");
  const std::string physicalIdentity = providerSection(
      "static bool physicalFaultProviderIdentityMatches", "bool parsePhysicalFaultProviderReceipt");
  const std::string physicalReceipt = providerSection(
      "bool parsePhysicalFaultProviderReceipt", "bool describePhysicalFaultExecutorBoundary");
  const std::string physicalArguments = providerSection(
      "void physicalFaultProviderArguments", "bool runPhysicalFaultProvider");
  const std::string physicalExecutorBoundary = providerSection(
      "bool describePhysicalFaultExecutorBoundary", "bool resolvePhysicalFaultExecutor");
  const std::string localRecoveryIntent = providerSection(
      "bool prepareLocalRecoveryRuntimeIntent", "bool installLocalRecoveryRuntime");
  const std::string localRecoveryFreshAuthority = providerSection(
      "bool localRecoveryRuntimeFreshAuthority", "static bool captureLocalRecoveryWorkloads");
  const std::string upgradePlanner = providerSection(
      "void runPlanUpgrade", "void runClusterReport");
  suite.expect(!pairArguments.empty() && pairArguments.find("assignItoh") == std::string::npos &&
                   pairArguments.find("mothershipAssignProviderHex128(record.intent.operationUUID, operation);") != std::string::npos &&
                   pairArguments.find("mothershipAssignProviderHex128(record.intent.sourceWorkload.clusterUUID, executorCluster);") != std::string::npos &&
                   pairArguments.find("mothershipAssignProviderHex128(record.intent.selectorMachineUUID, executorMachine);") != std::string::npos &&
                   pairArguments.find("mothershipAssignProviderHex128(record.intent.ingressWitnessMachineUUID, witnessMachine);") != std::string::npos &&
                   !pairOutput.empty() && pairOutput.find("assignItoh") == std::string::npos &&
                   pairOutput.find("mothershipAssignProviderHex128(record.intent.operationUUID, expectedOperation);") != std::string::npos &&
                   pairOutput.find("mothershipAssignProviderHex128(record.intent.sourceWorkload.clusterUUID, expectedCluster);") != std::string::npos &&
                   pairOutput.find("mothershipAssignProviderHex128(record.intent.selectorMachineUUID, expectedMachine);") != std::string::npos &&
                   !pairWitness.empty() && pairWitness.find("assignItoh") == std::string::npos &&
                   pairWitness.find("mothershipAssignProviderHex128(record.intent.operationUUID, expectedOperation);") != std::string::npos &&
                   pairWitness.find("mothershipAssignProviderHex128(record.intent.ingressWitnessMachineUUID, expectedMachine);") != std::string::npos,
               "production_pair_provider_wire_identities_use_exact_provider_hex");
  suite.expect(!productionPairCommand.empty() &&
                   productionPairCommand.find("action == \"abortBeforeTransit\"_ctv") != std::string::npos &&
                   productionPairCommand.find("mothership-production-pair-pre-transit-abort-receipt-v1") != std::string::npos &&
                   productionPairCommand.find("runProductionPairProvider(record, source, \"remove\"") <
                       productionPairCommand.find("closePhysicalServiceTransitBoundaryBeforeTransit") &&
                   productionPairCommand.find("closePhysicalServiceTransitBoundaryBeforeTransit") <
                       productionPairCommand.find("abortProductionPairBeforeTransit"),
               "production_pair_pre_transit_abort_removes_then_closes_then_terminalizes");
  suite.expect(!pairRunner.empty() && pairRunner.find("--manage-firewall") != std::string::npos,
               "production_pair_selector_owns_exact_host_firewall_admission");
  suite.expect(!productionPairCommand.empty() &&
                   productionPairCommand.find("action == \"abortBeforeCutover\"_ctv") != std::string::npos &&
                   productionPairCommand.find("mothership-production-pair-pre-cutover-abort-pending-receipt-v1") != std::string::npos &&
                   productionPairCommand.find("mothership-production-pair-pre-cutover-abort-receipt-v2") != std::string::npos &&
                   productionPairCommand.find("state.sourceConnections != 0") == std::string::npos &&
                   productionPairCommand.find("state.sourceRequestBytes != 0") == std::string::npos &&
                   productionPairCommand.find("state.sourceResponseBytes != 0") == std::string::npos &&
                   productionPairCommand.find("state.sourceFlows != 0") != std::string::npos &&
                   productionPairCommand.find("state.targetFlows != 0") != std::string::npos &&
                   productionPairCommand.find("state.targetConnections != 0") != std::string::npos &&
                   productionPairCommand.find("state.targetRequestBytes != 0") != std::string::npos &&
                   productionPairCommand.find("state.targetResponseBytes != 0") != std::string::npos &&
                   productionPairCommand.find("runProductionPairProvider(record, source, \"query\"") <
                       productionPairCommand.find("prepareProductionPairAbortBeforeCutover") &&
                   productionPairCommand.find("prepareProductionPairAbortBeforeCutover") <
                       productionPairCommand.find("runProductionPairProvider(record, source, \"abort-before-cutover\"") &&
                   productionPairCommand.find("runProductionPairProvider(record, source, \"abort-before-cutover\"") <
                       productionPairCommand.find("abortProductionPairBeforeCutover"),
               "production_pair_pre_cutover_abort_write_ahead_retries_checked_provider_removal");
  suite.expect(!prepareProductionPairCommand.empty() &&
                   prepareProductionPairCommand.find("TidesDB owns an exclusive process lock") != std::string::npos &&
                   prepareProductionPairCommand.find("MothershipProductionPairRecord advancedRecord = {};") != std::string::npos &&
                   prepareProductionPairCommand.find("advanceProductionPair(operationUUID, MothershipProductionPairPhase::transitApplied,\n"
                                                     "                                                      transitReceipt, Time::now<TimeResolution::ms>(), advancedRecord") != std::string::npos &&
                   prepareProductionPairCommand.find("if (valid) record = std::move(advancedRecord);") != std::string::npos,
               "production_pair_prepare_releases_registry_and_preserves_compensation_identity");
  suite.expect(!prepareProductionPairCommand.empty() &&
                   prepareProductionPairCommand.find("ReservedPorts::neuron") != std::string::npos &&
                   prepareProductionPairCommand.find("ReservedPorts::brain") != std::string::npos &&
                   prepareProductionPairCommand.find("ReservedPorts::mothership") != std::string::npos &&
                   prepareProductionPairCommand.find("ReservedPorts::clusterPairControl") != std::string::npos,
               "production_pair_selector_rejects_all_runtime_reserved_ports");
  suite.expect(!prepareProductionPairCommand.empty() &&
                   prepareProductionPairCommand.find("machine.uuid != intent.selectorMachineUUID") != std::string::npos &&
                   prepareProductionPairCommand.find("machine.uuid != intent.sourceWorkload.endpointMachineUUID") != std::string::npos &&
                   prepareProductionPairCommand.find("!topologyMachineOwnsAddress(admissionSourceStatus, machine.uuid") != std::string::npos,
               "production_pair_ingress_witness_excludes_selector_and_source_endpoint_owners");
  suite.expect(!prepareProductionPairCommand.empty() &&
                   prepareProductionPairCommand.find("boundary.sourceAddress = record.intent.selectorAddress;") != std::string::npos &&
                   prepareProductionPairCommand.find("boundary.sourceTCPPort = record.intent.selectorTCPPort;") != std::string::npos,
               "production_pair_physical_boundary_binds_the_selector_to_target_relay_leg");
  suite.expect(!physicalExecutorBoundary.empty() &&
                   physicalExecutorBoundary.find("topologyMachine->ssh.user != \"root\"_ctv") != std::string::npos,
               "production_physical_fault_provider_requires_a_root_managed_cloud_vm_boundary");
  suite.expect(!localRecoveryIntent.empty() &&
                   localRecoveryIntent.find("--supersede-released-runtime=") != std::string::npos &&
                   localRecoveryIntent.find("admittedRuntimeSupersedingUpgradeVersion") != std::string::npos &&
                   localRecoveryIntent.find("mothershipLocalRecoveryWorkloadCanRecoverTo") != std::string::npos &&
                   localRecoveryIntent.find("prior.request.admittedRuntime.workloads") != std::string::npos,
               "local_runtime_recovery_cli_binds_released_predecessor_and_frozen_workloads");
  suite.expect(!localRecoveryFreshAuthority.empty() &&
                   localRecoveryFreshAuthority.find("mothershipLocalRecoveryGatewayQualificationAttempts") != std::string::npos &&
                   localRecoveryFreshAuthority.find("mothershipLocalRecoveryGatewayQualificationPollMilliseconds") != std::string::npos &&
                   localRecoveryFreshAuthority.find("local runtime recovery gateway authority remains unqualified") != std::string::npos &&
                   mothershipLocalRecoveryGatewayQualificationAttempts == 30 &&
                   mothershipLocalRecoveryGatewayQualificationPollMilliseconds == 100,
               "local_runtime_recovery_boundedly_polls_exact_unqualified_gateway_authority");
  suite.expect(!upgradePlanner.empty() &&
                   upgradePlanner.find("degradedLocalRecoveryAdmission") != std::string::npos &&
                   upgradePlanner.find("upgrade admission capacity report is missing commissioned-peer measurements") != std::string::npos &&
                   upgradePlanner.find("reportReceived = true") != std::string::npos,
               "local_runtime_recovery_preserves_explicit_rejected_degraded_admission");
  suite.expect(!localAction.empty() && localAction.find("assignItoh") == std::string::npos &&
                   localAction.find("mothershipAssignProviderHex128(operationUUID, operation);") != std::string::npos,
               "local_vm_fault_operation_uses_exact_provider_hex");
  suite.expect(!physicalIdentity.empty() && physicalIdentity.find("assignItoh") == std::string::npos &&
                   physicalIdentity.find("mothershipAssignProviderHex128(request.operationUUID, expectedOperation);") != std::string::npos &&
                   physicalIdentity.find("mothershipAssignProviderHex128(request.guestUUID, expectedGuest);") != std::string::npos &&
                   !physicalArguments.empty() && physicalArguments.find("assignItoh") == std::string::npos &&
                   physicalArguments.find("mothershipAssignProviderHex128(request.operationUUID, operation);") != std::string::npos &&
                   physicalArguments.find("mothershipAssignProviderHex128(request.guestUUID, guest);") != std::string::npos,
               "physical_fault_provider_wire_identities_use_exact_provider_hex");
  const std::string physicalLifecycle = providerSection(
      "bool runPhysicalFaultProviderLifecycle", "void runFaultClusterNetwork");
  suite.expect(!physicalLifecycle.empty() &&
                   physicalLifecycle.find("physicalFaultProviderRequestValid") != std::string::npos &&
                   physicalLifecycle.find("parsePhysicalFaultProviderReceipt(output, request, allowActive, allowTerminal") != std::string::npos &&
                   physicalLifecycle.find("\"apply\", request, true, false") != std::string::npos &&
                   physicalLifecycle.find("\"query\", request, true, true") != std::string::npos &&
                   physicalLifecycle.find("\"remove\", request, false, true") != std::string::npos,
               "physical_fault_provider_lifecycle_requires_exact_apply_query_remove_receipts");
  suite.expect(!physicalReceipt.empty() &&
                   physicalReceipt.find("object.size() == 15") != std::string::npos &&
                   physicalReceipt.find("object.size() == 13") != std::string::npos &&
                   physicalReceipt.find("object[\"gatewayEndpoint\"]") != std::string::npos &&
                   physicalReceipt.find("object[\"flowTarget\"]") != std::string::npos &&
                   physicalReceipt.find("object[\"flowIdentity\"]") != std::string::npos &&
                   physicalReceipt.find("object[\"autoRestoreDeadlineMonotonicMs\"]") != std::string::npos,
               "physical_fault_provider_receipts_have_disjoint_exact_active_and_terminal_schemas");

  uint128_t verifiedVMUUID = 0;
  suite.expect(mothershipParseVerifiedLocalVMIdentity(
                   "prodigy-disposable-linux-v1\n"_ctv,
                   "12345678-1234-4234-9234-123456789abc\n"_ctv, verifiedVMUUID) &&
                   verifiedVMUUID == String::numberFromHexString<uint128_t>("12345678123442349234123456789abc"_ctv),
               "local_vm_marker_binds_exact_qemu_dmi_uuid");
  suite.expect(!mothershipParseVerifiedLocalVMIdentity(
                   "prodigy-disposable-linux-v1\n"_ctv,
                   "00000000-0000-0000-0000-000000000000\n"_ctv, verifiedVMUUID) && verifiedVMUUID == 0,
               "local_vm_marker_rejects_zero_dmi_uuid");
  suite.expect(!mothershipParseVerifiedLocalVMIdentity(
                   "unverified\n"_ctv,
                   "12345678-1234-4234-9234-123456789abc\n"_ctv, verifiedVMUUID),
               "local_vm_marker_rejects_unverified_boundary");
  const uint128_t boundaryMachineUUID =
      String::numberFromHexString<uint128_t>("c776150f4271478e84caada31f261c77"_ctv);
  suite.expect(mothershipLocalVMGuestUUIDMatches(
                   boundaryMachineUUID, "c776150f-4271-478e-84ca-ada31f261c77"),
               "local_vm_boundary_matches_hyphenated_dmi_uuid_without_formatter_prefix");
  suite.expect(mothershipLocalVMGuestUUIDMatches(
                   boundaryMachineUUID, "C776150F-4271-478E-84CA-ADA31F261C77"),
               "local_vm_boundary_matches_uppercase_dmi_uuid");
  suite.expect(!mothershipLocalVMGuestUUIDMatches(
                   boundaryMachineUUID, "0xc776150f4271478e84caada31f261c77") &&
                   !mothershipLocalVMGuestUUIDMatches(
                       boundaryMachineUUID, "c776150f-4271-478e-84ca-ada31f261c78"),
               "local_vm_boundary_rejects_non_dmi_or_different_uuid");

  MothershipPhysicalServiceTransitBoundary boundary = {};
  boundary.boundaryUUID = 0x10; boundary.pairOperationUUID = 0x11;
  boundary.routeUUID = 0x12; boundary.routeGeneration = 1;
  boundary.sourceClusterUUID = 0x13; boundary.targetClusterUUID = 0x14;
  boundary.sourceMachineUUID = 0x15; boundary.targetMachineUUID = 0x16;
  boundary.sourceExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  boundary.sourceLocalVMBoundaryUUID = 0x17;
  boundary.targetExecutorKind = MothershipPhysicalFaultExecutorKind::providerCloudVM;
  boundary.targetCloudID = "cloud-instance-18"_ctv;
  boundary.sourceAddress = "192.0.2.10"_ctv; boundary.targetAddress = "198.51.100.10"_ctv;
  boundary.sourceTCPPort = 8080; boundary.targetTCPPort = 8080; boundary.pathMTU = 1500;
  boundary.routeAuthorizationSHA256 = digest('1'); boundary.admissionReceiptSHA256 = digest('2');
  boundary.admittedAtMs = 100;
  suite.expect(mothershipPhysicalServiceTransitBoundaryValid(boundary, &failure) && failure.empty(),
               "physical_boundary_requires_typed_local_or_cloud_vm_executors");
  auto unsafeBoundary = boundary; unsafeBoundary.sourceLocalVMBoundaryUUID = 0;
  suite.expect(!mothershipPhysicalServiceTransitBoundaryValid(unsafeBoundary, &failure),
               "physical_boundary_rejects_unproven_local_execution");
  unsafeBoundary = boundary; unsafeBoundary.targetCloudID.clear();
  suite.expect(!mothershipPhysicalServiceTransitBoundaryValid(unsafeBoundary, &failure),
               "physical_boundary_rejects_unproven_cloud_execution");

  MothershipPhysicalClusterNetworkFaultRequest network = {};
  network.operationUUID = 0x1001; network.boundaryUUID = 0x2001;
  network.sourceClusterUUID = 0x3001; network.targetClusterUUID = 0x3002;
  network.sourceMachineUUID = 0x4001; network.targetMachineUUID = 0x4002;
  network.direction = MothershipPhysicalFaultDirection::sourceToTarget;
  network.durationMilliseconds = 1000;
  network.routeUUID = 0x5001; network.routeGeneration = 3;
  network.routeAuthorizationSHA256 = digest('a');
  network.sourceAddress = "192.0.2.40"_ctv; network.targetAddress = "198.51.100.40"_ctv;
  network.sourceTopologyVersion = 7; network.targetTopologyVersion = 9;
  suite.expect(mothershipPhysicalClusterNetworkFaultRequestValid(network, &failure) && failure.empty(),
               "network_request_accepts_exact_bounded_authority");
  auto masqueGateway = network;
  masqueGateway.flowTarget = MothershipPhysicalFaultFlowTarget::masqueGateway;
  masqueGateway.gatewayEndpoint = "198.51.100.40"_ctv;
  masqueGateway.flowIdentity = "masque:gateway-40/session-7"_ctv;
  suite.expect(mothershipPhysicalClusterNetworkFaultRequestValid(masqueGateway, &failure) && failure.empty(),
               "network_request_binds_exact_masque_gateway_and_flow");
  auto unsafeFlow = masqueGateway;
  unsafeFlow.flowIdentity.clear();
  suite.expect(!mothershipPhysicalClusterNetworkFaultRequestValid(unsafeFlow, &failure),
               "network_request_rejects_unidentified_masque_or_bgp_flow");
  unsafeFlow = masqueGateway;
  unsafeFlow.gatewayEndpoint = "not-an-address"_ctv;
  suite.expect(!mothershipPhysicalClusterNetworkFaultRequestValid(unsafeFlow, &failure),
               "network_request_rejects_unproven_gateway_endpoint");

  MothershipPhysicalClusterNetworkFaultReceipt networkReceipt = {};
  networkReceipt.operationUUID = network.operationUUID; networkReceipt.boundaryUUID = network.boundaryUUID;
  networkReceipt.admission = network;
  networkReceipt.sourceBefore = observation(network.sourceClusterUUID, network.sourceMachineUUID, 7, 'a');
  networkReceipt.targetBefore = observation(network.targetClusterUUID, network.targetMachineUUID, 9, 'b');
  networkReceipt.sourceAfter = networkReceipt.sourceBefore; networkReceipt.targetAfter = networkReceipt.targetBefore;
  networkReceipt.sourceInstalledAtMonotonicMilliseconds = 100;
  networkReceipt.sourceRestoredAtMonotonicMilliseconds = 1100;
  networkReceipt.sourceRestored = true; networkReceipt.restored = true;
  suite.expect(mothershipPhysicalClusterNetworkFaultReceiptValid(network, networkReceipt, &failure) && failure.empty(),
               "network_receipt_requires_exact_pre_and_post_restoration");

  MothershipPhysicalClusterNetworkFaultRequest retargeted = network;
  retargeted.targetMachineUUID = 0x4003;
  suite.expect(!mothershipPhysicalClusterNetworkFaultReplayAdmissible(network, retargeted),
               "network_replay_rejects_retargeted_machine");
  retargeted = network; retargeted.durationMilliseconds = 1001;
  suite.expect(!mothershipPhysicalClusterNetworkFaultReplayAdmissible(network, retargeted),
               "network_replay_rejects_duration_change");
  retargeted = network; retargeted.targetAddress = "198.51.100.41"_ctv;
  suite.expect(!mothershipPhysicalClusterNetworkFaultReplayAdmissible(network, retargeted),
               "network_replay_rejects_reassigned_endpoint_address");
  suite.expect(mothershipPhysicalClusterNetworkFaultReplayAdmissible(network, network),
               "network_replay_allows_exact_retry_only");

  MothershipPhysicalClusterNetworkFaultReceipt tamperedNetwork = networkReceipt;
  tamperedNetwork.targetAfter.stateSHA256 = digest('c');
  suite.expect(!mothershipPhysicalClusterNetworkFaultReceiptValid(network, tamperedNetwork, &failure),
               "network_receipt_rejects_unrestored_post_observation");
  tamperedNetwork = networkReceipt; tamperedNetwork.boundaryUUID = 0x2002;
  suite.expect(!mothershipPhysicalClusterNetworkFaultReceiptValid(network, tamperedNetwork, &failure),
               "network_receipt_rejects_boundary_substitution");
  tamperedNetwork = networkReceipt; tamperedNetwork.admission.targetTopologyVersion++;
  suite.expect(!mothershipPhysicalClusterNetworkFaultReceiptValid(network, tamperedNetwork, &failure),
               "network_receipt_rejects_changed_admission_proof");
  tamperedNetwork = networkReceipt; tamperedNetwork.restored = false;
  suite.expect(!mothershipPhysicalClusterNetworkFaultReceiptValid(network, tamperedNetwork, &failure),
               "network_receipt_rejects_missing_cleanup_proof");
  auto bidirectional = network; bidirectional.direction = MothershipPhysicalFaultDirection::both;
  suite.expect(!mothershipPhysicalClusterNetworkFaultReceiptValid(bidirectional, networkReceipt, &failure),
               "bidirectional_network_receipt_requires_target_side_proof");
  auto bidirectionalReceipt = networkReceipt;
  bidirectionalReceipt.admission = bidirectional;
  bidirectionalReceipt.targetInstalledAtMonotonicMilliseconds = 101;
  bidirectionalReceipt.targetRestoredAtMonotonicMilliseconds = 1101;
  bidirectionalReceipt.targetRestored = true;
  suite.expect(mothershipPhysicalClusterNetworkFaultReceiptValid(bidirectional, bidirectionalReceipt, &failure),
               "bidirectional_network_receipt_preserves_both_side_proofs");
  retargeted = network; retargeted.sourceClusterUUID = retargeted.targetClusterUUID;
  suite.expect(!mothershipPhysicalClusterNetworkFaultRequestValid(retargeted, &failure),
               "network_request_rejects_same_cluster_boundary");

  MothershipLocalVMMachineFaultRequest local = {};
  local.operationUUID = 0x5001; local.vmBoundaryUUID = 0x6001;
  local.clusterUUID = 0x7001; local.machineUUID = 0x8001;
  local.action = MothershipLocalVMMachineFaultAction::coldReboot;
  local.durationMilliseconds = 1000; local.expectedBootSHA256 = digest('d');
  suite.expect(mothershipLocalVMMachineFaultRequestValid(local, &failure) && failure.empty(),
               "local_vm_request_requires_typed_vm_boundary");

  MothershipLocalVMMachineFaultReceipt localReceipt = {};
  localReceipt.operationUUID = local.operationUUID; localReceipt.vmBoundaryUUID = local.vmBoundaryUUID;
  localReceipt.before = observation(local.clusterUUID, local.machineUUID, 11, 'd');
  localReceipt.after = observation(local.clusterUUID, local.machineUUID, 12, 'e');
  localReceipt.restoredBootSHA256 = digest('e');
  localReceipt.faultedAtMonotonicMilliseconds = 1000; localReceipt.restoredAtMonotonicMilliseconds = 2000;
  localReceipt.restored = true;
  suite.expect(mothershipLocalVMMachineFaultReceiptValid(local, localReceipt, &failure) && failure.empty(),
               "local_vm_receipt_proves_new_boot_and_restoration");

  MothershipLocalVMMachineFaultRequest localReplay = local;
  localReplay.vmBoundaryUUID = 0x6002;
  suite.expect(!mothershipLocalVMMachineFaultReplayAdmissible(local, localReplay),
               "local_vm_replay_rejects_boundary_substitution");
  suite.expect(mothershipLocalVMMachineFaultReplayAdmissible(local, local),
               "local_vm_replay_allows_exact_retry_only");
  MothershipLocalVMMachineFaultReceipt tamperedLocal = localReceipt;
  tamperedLocal.restoredBootSHA256 = local.expectedBootSHA256;
  suite.expect(!mothershipLocalVMMachineFaultReceiptValid(local, tamperedLocal, &failure),
               "local_vm_receipt_rejects_unchanged_boot_identity");
  tamperedLocal = localReceipt; tamperedLocal.after.machineUUID = 0x8002;
  suite.expect(!mothershipLocalVMMachineFaultReceiptValid(local, tamperedLocal, &failure),
               "local_vm_receipt_rejects_machine_substitution");
  tamperedLocal = localReceipt; tamperedLocal.restoredAtMonotonicMilliseconds = 8000;
  suite.expect(!mothershipLocalVMMachineFaultReceiptValid(local, tamperedLocal, &failure),
               "local_vm_receipt_rejects_unbounded_recovery");
  localReplay = local; localReplay.expectedBootSHA256 = "not-a-digest"_ctv;
  suite.expect(!mothershipLocalVMMachineFaultRequestValid(localReplay, &failure),
               "local_vm_request_rejects_untyped_boot_identity");

  MothershipLocalVMMachineFaultRequest unready = local;
  unready.protocolVersion = MothershipLocalVMMachineFaultRequest::unreadyUpgradeRecoveryVersion;
  unready.operationUUID = 0x5002;
  unready.action = MothershipLocalVMMachineFaultAction::recoverUnreadyUpgrade;
  unready.upgradeOperationUUID = 0x9001;
  unready.targetBundleSHA256 = digest('1');
  unready.targetContractSHA256 = digest('2');
  unready.upgradeAdmissionSHA256 = digest('3');
  unready.expectedBoundarySHA256 = digest('4');
  for (uint32_t index = 0; index != 32; ++index) unready.expectedLinuxMachineID.append('5');
  unready.expectedLinuxBootID = "12345678-1234-4abc-8def-123456789abc"_ctv;
  unready.expectedQemuPID = 42; unready.expectedQemuStarttime = "700"_ctv;
  unready.incompleteObservationReceiptVersion = 7;
  suite.expect(mothershipLocalVMMachineFaultRequestValid(unready, &failure) && failure.empty(),
               "unready_vm_recovery_binds_upgrade_boundary_process_and_linux_boot");
  auto unboundUnready = unready; unboundUnready.expectedLinuxBootID.clear();
  suite.expect(!mothershipLocalVMMachineFaultRequestValid(unboundUnready, &failure),
               "unready_vm_recovery_rejects_missing_linux_boot_identity");
  unboundUnready = unready; unboundUnready.action = MothershipLocalVMMachineFaultAction::coldReboot;
  suite.expect(!mothershipLocalVMMachineFaultRequestValid(unboundUnready, &failure),
               "unready_vm_recovery_is_distinct_from_the_healthy_fault_mode");

  MothershipLocalVMMachineFaultReceipt unreadyReceipt = localReceipt;
  unreadyReceipt.protocolVersion = MothershipLocalVMMachineFaultReceipt::unreadyUpgradeRecoveryVersion;
  unreadyReceipt.operationUUID = unready.operationUUID;
  unreadyReceipt.beforeLinuxMachineID = unready.expectedLinuxMachineID;
  unreadyReceipt.beforeLinuxBootID = unready.expectedLinuxBootID;
  unreadyReceipt.beforeQemuPID = unready.expectedQemuPID;
  unreadyReceipt.beforeQemuStarttime = unready.expectedQemuStarttime;
  unreadyReceipt.afterLinuxMachineID = unready.expectedLinuxMachineID;
  unreadyReceipt.afterLinuxBootID = "abcdef12-3456-4abc-8def-123456789abc"_ctv;
  unreadyReceipt.afterQemuPID = 43; unreadyReceipt.afterQemuStarttime = "800"_ctv;
  unreadyReceipt.completedObservationReceiptVersion = 8;
  unreadyReceipt.completedUpgradeReportSHA256 = digest('6');
  suite.expect(mothershipLocalVMMachineFaultReceiptValid(unready, unreadyReceipt, &failure) && failure.empty(),
               "unready_vm_recovery_receipt_requires_new_linux_boot_and_fresh_complete_inventory");
  auto incompleteInventoryReceipt = unreadyReceipt;
  incompleteInventoryReceipt.completedObservationReceiptVersion = 7;
  suite.expect(!mothershipLocalVMMachineFaultReceiptValid(unready, incompleteInventoryReceipt, &failure),
               "unready_vm_recovery_receipt_rejects_nonadvancing_inventory");
  auto unchangedLinuxBootReceipt = unreadyReceipt;
  unchangedLinuxBootReceipt.afterLinuxBootID = unready.expectedLinuxBootID;
  suite.expect(!mothershipLocalVMMachineFaultReceiptValid(unready, unchangedLinuxBootReceipt, &failure),
               "unready_vm_recovery_receipt_rejects_unchanged_linux_boot");

  MothershipLocalAuthorityRecoveryCohortRequest cohort = {};
  cohort.operationUUID = 0x9001; cohort.clusterUUID = 0x9002; cohort.topologyVersion = 17;
  cohort.timeoutMilliseconds = mothershipLocalAuthorityRecoveryMinimumTimeoutMilliseconds;
  for (uint128_t machine : {uint128_t(0x11), uint128_t(0x22), uint128_t(0x33)})
  {
    MothershipLocalAuthorityRecoveryExecutor executor = {};
    executor.machineUUID = machine; executor.boundaryUUID = machine + 0x100;
    executor.executorOperationUUID = machine + 0x200; executor.immutableBoundarySHA256 = digest('f');
    cohort.executors.push_back(std::move(executor));
  }
  suite.expect(mothershipLocalAuthorityRecoveryCohortRequestValid(cohort, &failure) && failure.empty(),
               "authority_recovery_requires_canonical_three_boundary_cohort");
  auto shortCohort = cohort; shortCohort.timeoutMilliseconds--;
  suite.expect(!mothershipLocalAuthorityRecoveryCohortRequestValid(shortCohort, &failure),
               "authority_recovery_rejects_timeout_below_supported_recovery_bound");
  auto invalidCohort = cohort; invalidCohort.executors[1].machineUUID = invalidCohort.executors[0].machineUUID;
  suite.expect(!mothershipLocalAuthorityRecoveryCohortRequestValid(invalidCohort, &failure),
               "authority_recovery_rejects_noncanonical_or_duplicate_machine_cohort");
  invalidCohort = cohort; invalidCohort.executors[2].boundaryUUID = invalidCohort.executors[1].boundaryUUID;
  suite.expect(!mothershipLocalAuthorityRecoveryCohortRequestValid(invalidCohort, &failure),
               "authority_recovery_rejects_duplicate_boundary_identity");

  MothershipLocalRecoveryWorkloadIdentity expectedWorkload = {};
  expectedWorkload.applicationID = 42;
  expectedWorkload.deploymentID = (uint64_t(42) << 48) | 7;
  expectedWorkload.stateful = true;
  expectedWorkload.shardGroups = 3;
  expectedWorkload.target = 3;
  expectedWorkload.targetBase = 3;
  auto dormantWorkload = expectedWorkload;
  dormantWorkload.target = 0;
  dormantWorkload.targetBase = 0;
  suite.expect(
      mothershipLocalRecoveryWorkloadCanRecoverTo(
          dormantWorkload, expectedWorkload) &&
          mothershipLocalRecoveryActiveDeploymentCountCoversRequired(5, 3),
      "authority_recovery_accepts_retained_workload_deficit_and_conservative_count");
  auto expandedWorkload = expectedWorkload;
  expandedWorkload.target = 4;
  expandedWorkload.targetBase = 4;
  auto substitutedWorkload = dormantWorkload;
  ++substitutedWorkload.deploymentID;
  suite.expect(
      !mothershipLocalRecoveryWorkloadCanRecoverTo(
          expandedWorkload, expectedWorkload) &&
          !mothershipLocalRecoveryWorkloadCanRecoverTo(
              substitutedWorkload, expectedWorkload) &&
          !mothershipLocalRecoveryActiveDeploymentCountCoversRequired(2, 3) &&
          !mothershipLocalRecoveryActiveDeploymentCountCoversRequired(3, 0),
      "authority_recovery_rejects_workload_expansion_substitution_or_missing_count");

  ClusterTopology recoveryTopology = {};
  recoveryTopology.version = cohort.topologyVersion;
  for (const auto& executor : cohort.executors)
  {
    ClusterMachine machine = {};
    machine.uuid = executor.machineUUID;
    machine.kind = MachineConfig::MachineKind::vm;
    machine.backing = ClusterMachineBacking::owned;
    machine.lifetime = MachineLifetime::owned;
    machine.isBrain = true;
    recoveryTopology.machines.push_back(std::move(machine));
  }
  suite.expect(mothershipLocalAuthorityRecoveryTopologyMatches(cohort, recoveryTopology),
               "authority_recovery_accepts_admitted_exact_topology");
  recoveryTopology.version += 5;
  suite.expect(mothershipLocalAuthorityRecoveryTopologyMatches(cohort, recoveryTopology),
               "authority_recovery_accepts_newer_generation_with_exact_owned_vm_identities");
  recoveryTopology.version = cohort.topologyVersion - 1;
  suite.expect(!mothershipLocalAuthorityRecoveryTopologyMatches(cohort, recoveryTopology),
               "authority_recovery_rejects_topology_older_than_admission");
  recoveryTopology.version = cohort.topologyVersion + 5;
  recoveryTopology.machines[1].lifetime = MachineLifetime::reserved;
  suite.expect(!mothershipLocalAuthorityRecoveryTopologyMatches(cohort, recoveryTopology),
               "authority_recovery_rejects_newer_topology_with_boundary_ownership_drift");

  CrossClusterMasqueGatewayAuthority gatewayAuthority = {};
  gatewayAuthority.pairUUID = 0xa001;
  gatewayAuthority.localClusterUUID = cohort.clusterUUID;
  gatewayAuthority.localMachineUUID = cohort.executors[0].machineUUID;
  ProdigyCrossClusterMasqueGatewayAuthorityResponse gatewayResponse = {};
  gatewayResponse.success = true;
  gatewayResponse.found = true;
  gatewayResponse.localClusterUUID = cohort.clusterUUID;
  gatewayResponse.currentAuthorityGeneration = 7;
  gatewayResponse.authority = gatewayAuthority;
  suite.expect(
      mothershipLocalRecoveryGatewayAuthorityDisposition(
          cohort.clusterUUID, gatewayAuthority, gatewayResponse) ==
          MothershipLocalRecoveryGatewayAuthorityDisposition::pendingQualification,
      "authority_recovery_retries_byte_exact_unqualified_gateway_authority");
  gatewayResponse.qualified = true;
  ++gatewayResponse.currentAuthorityGeneration;
  suite.expect(
      mothershipLocalRecoveryGatewayAuthorityDisposition(
          cohort.clusterUUID, gatewayAuthority, gatewayResponse) ==
          MothershipLocalRecoveryGatewayAuthorityDisposition::qualified,
      "authority_recovery_ignores_generation_metadata_for_exact_qualified_gateway_authority");
  ++gatewayResponse.authority.keyGeneration;
  suite.expect(
      mothershipLocalRecoveryGatewayAuthorityDisposition(
          cohort.clusterUUID, gatewayAuthority, gatewayResponse) ==
          MothershipLocalRecoveryGatewayAuthorityDisposition::changed,
      "authority_recovery_rejects_serialized_gateway_authority_drift");
  gatewayResponse.authority = gatewayAuthority;
  gatewayResponse.found = false;
  suite.expect(
      mothershipLocalRecoveryGatewayAuthorityDisposition(
          cohort.clusterUUID, gatewayAuthority, gatewayResponse) ==
          MothershipLocalRecoveryGatewayAuthorityDisposition::changed,
      "authority_recovery_rejects_missing_gateway_authority");
  gatewayResponse.found = true;
  ++gatewayResponse.localClusterUUID;
  suite.expect(
      mothershipLocalRecoveryGatewayAuthorityDisposition(
          cohort.clusterUUID, gatewayAuthority, gatewayResponse) ==
          MothershipLocalRecoveryGatewayAuthorityDisposition::changed,
      "authority_recovery_rejects_cross_cluster_gateway_authority_substitution");
  gatewayResponse.localClusterUUID = cohort.clusterUUID;
  gatewayResponse.success = false;
  suite.expect(
      mothershipLocalRecoveryGatewayAuthorityDisposition(
          cohort.clusterUUID, gatewayAuthority, gatewayResponse) ==
          MothershipLocalRecoveryGatewayAuthorityDisposition::changed,
      "authority_recovery_rejects_failed_gateway_authority_response");

  LocalRecoveryRequestV1Fixture legacyRequest;legacyRequest.value=cohort;
  String legacyRequestBytes,currentRequestBytes;
  BitseryEngine::serialize(legacyRequestBytes,legacyRequest);BitseryEngine::serialize(currentRequestBytes,cohort);
  suite.expect(legacyRequestBytes==currentRequestBytes,"local_recovery_v1_request_bytes_preserved");
  LocalRecoveryRecordV1Fixture legacy;legacy.request=legacyRequest;
  for(const auto& executor:cohort.executors) {
    MothershipLocalAuthorityRecoveryBoundaryProgress p;p.boundaryUUID=executor.boundaryUUID;
    legacy.boundaries.push_back(p);
  }
  String legacyBytes,currentBytes;BitseryEngine::serialize(legacyBytes,legacy);
  MothershipLocalAuthorityRecoveryCohortRecord decoded;
  suite.expect(BitseryEngine::deserializeSafe(legacyBytes,decoded) &&
      mothershipLocalAuthorityRecoveryCohortRecordValid(decoded,&failure),"local_recovery_reads_frozen_v1_record");
  BitseryEngine::serialize(currentBytes,decoded);
  suite.expect(currentBytes==legacyBytes && decoded.runtimeProgress.empty(),"local_recovery_v1_record_roundtrip_byte_exact");
  auto invalidRuntime=cohort;invalidRuntime.protocolVersion=2;
  suite.expect(!mothershipLocalAuthorityRecoveryCohortRequestValid(invalidRuntime,&failure),
               "local_runtime_repair_rejects_unbound_version_two_request");
  decoded.protocolVersion=2;
  suite.expect(!mothershipLocalAuthorityRecoveryCohortRecordValid(decoded,&failure),
               "local_runtime_repair_cannot_reinterpret_legacy_recovery_record");

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
