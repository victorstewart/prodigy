#pragma once

static bool decodeDeploymentIdentityResponse(String& bytes, DeploymentIdentityReport& report)
{
  bool decoded = false;
  forEachMessageInBuffer(bytes, [&](Message *message) {
    if (MothershipTopic(message->topic) != MothershipTopic::pullDeploymentIdentity) return;
    uint8_t *args = message->args;
    String payload = {};
    Message::extractToStringView(args, payload);
    decoded = args == message->terminal() && BitseryEngine::deserializeSafe(payload, report);
  });
  return decoded;
}

static bool queryDeploymentIdentity(
    TestBrain& brain,
    Mothership& mothership,
    uint64_t deploymentID,
    DeploymentIdentityReport& report)
{
  mothership.wBuffer.clear();
  String frame = {};
  brain.mothershipHandler(&mothership, buildMothershipMessage(
      frame, MothershipTopic::pullDeploymentIdentity, deploymentID));
  return decodeDeploymentIdentityResponse(mothership.wBuffer, report);
}

static void testDeploymentIdentityReceipt(TestSuite& suite)
{
  TestBrain brain = {};
  Mothership mothership = {};
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.persistedMachineInventoryEnumerated = true;
  brain.mothership = &mothership;
  mothership.isFixedFile = true;
  mothership.fslot = 1;
  suite.expect(brain.activateMothershipConnection(&mothership), "deployment_identity_fixture_activates_master_control_connection");
  constexpr uint16_t applicationID = 62'001;
  constexpr uint64_t deploymentID = (uint64_t(applicationID) << 48) | 9;
  constexpr uint128_t clusterUUID = uint128_t(0xC1A551);
  constexpr uint128_t prefixUUID = uint128_t(0xABCD);
  constexpr uint128_t endpointMachineUUID = uint128_t(0xBA5E);

  DeploymentPlan plan = {};
  plan.config.applicationID = applicationID;
  plan.config.versionID = 9;
  plan.config.type = ApplicationType::stateless;
  plan.config.containerBlobSHA256.assign(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
  plan.config.containerBlobBytes = 1234;
  Wormhole endpoint = {};
  endpoint.source = ExternalAddressSource::registeredRoutablePrefix;
  endpoint.routablePrefixUUID = prefixUUID;
  endpoint.layer4 = IPPROTO_TCP;
  endpoint.externalPort = 443;
  endpoint.containerPort = 8443;
  endpoint.externalAddress.is6 = false;
  const bool parsedEndpoint = inet_pton(AF_INET, "203.0.113.7", endpoint.externalAddress.v6) == 1;
  plan.wormholes.push_back(endpoint);

  DistributableExternalSubnet prefix = {};
  prefix.uuid = prefixUUID;
  prefix.ingressScope = RoutableIngressScope::singleMachine;
  prefix.machineUUID = endpointMachineUUID;
  brain.brainConfig.clusterUUID = clusterUUID;
  brain.brainConfig.distributableExternalSubnets.push_back(prefix);
  brain.deploymentPlans.insert_or_assign(deploymentID, plan);
  brain.masterAuthorityRuntimeState.generation = 17;
  brain.boottimens = 77;

  DeploymentIdentityReport persisted = {};
  const bool persistedDecoded = queryDeploymentIdentity(brain, mothership, deploymentID, persisted);
  String serialized = {}, expected = {}, failure = {};
  BitseryEngine::serialize(serialized, plan);
  const bool hashed = prodigyComputeSHA256Hex(serialized, expected, &failure);
  suite.expect(persistedDecoded && parsedEndpoint && hashed && persisted.version == 5 && persisted.found && !persisted.live &&
                   persisted.applicationID == applicationID && persisted.deploymentID == deploymentID &&
                   persisted.versionID == 9 && persisted.clusterUUID == clusterUUID &&
                   persisted.canonicalPlanSHA256 == expected &&
                   persisted.containerBlobSHA256 == plan.config.containerBlobSHA256 &&
                   persisted.containerBlobBytes == plan.config.containerBlobBytes &&
                   persisted.authorityGeneration == 17 && persisted.masterBootNs == 77 &&
                   persisted.profileEligible && persisted.observedPrefixUUID == prefixUUID &&
                   persisted.observedEndpointIPv4.equal("203.0.113.7"_ctv) &&
                   persisted.observedEndpointPort == 443 && persisted.observedEndpointMachineUUID == endpointMachineUUID,
               "deployment_identity_observes_normalized_persisted_plan_without_claiming_durability");

  DeploymentPlan ipv6Plan = plan;
  ipv6Plan.wormholes[0].externalAddress = IPAddress("2602:fac0:0:12ab:34cd::7", true);
  brain.deploymentPlans.insert_or_assign(deploymentID, ipv6Plan);
  DeploymentIdentityReport ipv6 = {};
  suite.expect(queryDeploymentIdentity(brain, mothership, deploymentID, ipv6) && ipv6.profileEligible &&
                   ipv6.observedEndpointIPv4.equal("2602:fac0:0:12ab:34cd::7"_ctv) &&
                   ipv6.observedEndpointPort == 443 && ipv6.observedEndpointMachineUUID == endpointMachineUUID,
               "deployment_identity_accepts_concrete_ipv6_endpoint");
  brain.deploymentPlans.insert_or_assign(deploymentID, plan);

  // A recovered active deployment must remain observable after becomeMaster has
  // cleared the transient deploymentPlans map. A stale map entry must not win.
  ApplicationDeployment recovered = {};
  recovered.plan = plan;
  recovered.plan.config.versionID = 10;
  recovered.plan.config.containerBlobSHA256.assign(
      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"_ctv);
  brain.deployments.insert_or_assign(deploymentID, &recovered);
  DeploymentIdentityReport live = {};
  const bool liveDecoded = queryDeploymentIdentity(brain, mothership, deploymentID, live);
  String recoveredSerialized = {}, recoveredDigest = {};
  BitseryEngine::serialize(recoveredSerialized, recovered.plan);
  const bool recoveredHashed = prodigyComputeSHA256Hex(recoveredSerialized, recoveredDigest, &failure);
  suite.expect(liveDecoded && recoveredHashed && live.found && live.live && live.versionID == 10 &&
                   live.canonicalPlanSHA256 == recoveredDigest &&
                   live.containerBlobSHA256 == recovered.plan.config.containerBlobSHA256,
               "deployment_identity_prefers_reconstructed_live_plan_over_stale_persisted_snapshot");

  recovered.plan.config.type = ApplicationType::task;
  DeploymentIdentityReport task = {};
  suite.expect(queryDeploymentIdentity(brain, mothership, deploymentID, task) && task.found && !task.profileEligible,
               "deployment_identity_rejects_task_endpoint_profile");
  recovered.plan = plan;
  recovered.plan.isStateful = true;
  DeploymentIdentityReport stateful = {};
  suite.expect(queryDeploymentIdentity(brain, mothership, deploymentID, stateful) && stateful.found && !stateful.profileEligible,
               "deployment_identity_rejects_stateful_endpoint_profile");
  recovered.plan = plan;
  recovered.plan.useHostNetworkNamespace = true;
  DeploymentIdentityReport hostNetwork = {};
  suite.expect(queryDeploymentIdentity(brain, mothership, deploymentID, hostNetwork) && hostNetwork.found && !hostNetwork.profileEligible,
               "deployment_identity_rejects_host_network_endpoint_profile");
  recovered.plan = plan;
  recovered.plan.wormholes[0].layer4 = IPPROTO_UDP;
  DeploymentIdentityReport udp = {};
  suite.expect(queryDeploymentIdentity(brain, mothership, deploymentID, udp) && udp.found && !udp.profileEligible,
               "deployment_identity_rejects_unsupported_udp_endpoint_profile");

  brain.deployments.erase(deploymentID);
  brain.deploymentPlans.erase(deploymentID);
  DeploymentIdentityReport missing = {};
  suite.expect(queryDeploymentIdentity(brain, mothership, deploymentID, missing) && !missing.found && !missing.live &&
                   missing.deploymentID == 0 && !missing.profileEligible,
               "deployment_identity_not_found_is_observation_not_admission_or_retry_authorization");

  uint8_t malformed[sizeof(uint64_t) - 1] = {};
  suite.expect(!ProdigyIngressValidation::validateMothershipPayload(
                   uint16_t(MothershipTopic::pullDeploymentIdentity), malformed, malformed + sizeof(malformed)),
               "deployment_identity_ingress_rejects_truncated_request");

  DeploymentIdentityReport runtime = {};
  runtime.version = 4; runtime.found = runtime.live = runtime.isStateful = true;
  runtime.clusterUUID = clusterUUID; runtime.statefulRuntimeCohortConverged = true;
  DeploymentIdentityStatefulMember member = {};
  member.storeKind = DeploymentIdentityStoreKind::kv; member.shardGroup = 2;
  member.replicaUUID = member.containerUUID = 0xC0FFEE; member.clusterUUID = clusterUUID;
  member.machineUUID = 0xBEEF; member.writable = member.clientServing = member.allMasters = true;
  member.siblingSessionUUID = 0x1234; member.siblingSessionGeneration = 7; member.siblingSessionHealthy = true;
  member.seededFromClusterUUID = 0x55; member.seededFromContainerUUID = 0x66;
  member.seedCatchupSHA256 = expected; member.seedCatchupGeneration = 9;
  member.replayWatermarkSHA256 = expected; member.catchupWatermarkSHA256 = expected;
  member.sourceContentWatermarkSHA256 = expected; member.sourceCatchupWatermarkSHA256 = expected;
  runtime.statefulRuntimeCohort.push_back(member);
  DeploymentIdentityApp6TruthMeshReceipt mesh = {};
  mesh.localClusterUUID = clusterUUID; mesh.remoteClusterUUID = 0x77;
  mesh.truthWriterContainerUUID = 0x88; mesh.sessionUUID = 0x99; mesh.reconnectGeneration = 10; mesh.healthy = true;
  runtime.app6TruthMeshReceipts.push_back(mesh);
  String runtimeBytes = {}; DeploymentIdentityReport decodedRuntime = {};
  suite.expect(BitseryEngine::serialize(runtimeBytes, runtime) && BitseryEngine::deserializeSafe(runtimeBytes, decodedRuntime) &&
                   decodedRuntime.version == 4 && decodedRuntime.statefulRuntimeCohortConverged &&
                   decodedRuntime.statefulRuntimeCohort.size() == 1 && decodedRuntime.statefulRuntimeCohort.front().seedCatchupGeneration == 9 &&
                   decodedRuntime.statefulRuntimeCohort.front().sourceContentWatermarkSHA256 == expected &&
                   decodedRuntime.app6TruthMeshReceipts.size() == 1 && decodedRuntime.app6TruthMeshReceipts.front().reconnectGeneration == 10,
               "deployment_identity_v4_roundtrips_native_source_boundary_and_app6_receipts");

  suite.expect(prodigyDeploymentIdentityReportVersionSupported(2, 2) &&
      prodigyDeploymentIdentityReportVersionSupported(4, 2) && prodigyDeploymentIdentityReportVersionSupported(5, 2) &&
      !prodigyDeploymentIdentityReportVersionSupported(1, 2) && !prodigyDeploymentIdentityReportVersionSupported(6, 2) &&
      !prodigyDeploymentIdentityReportVersionSupported(3, 4) && prodigyDeploymentIdentityReportVersionSupported(5, 4),
      "deployment_identity_versions_keep_required_field_gates");

  ProdigyStatefulStoreReceipt storeReceipt = {};
  storeReceipt.localContainerUUID = 0xC0FFEE; storeReceipt.localClusterUUID = clusterUUID;
  storeReceipt.deploymentID = 0x1234000000000001ULL; storeReceipt.storeKind = DeploymentIdentityStoreKind::kv;
  storeReceipt.shardGroup = 2; storeReceipt.nShardGroups = 3; storeReceipt.writable = true;
  storeReceipt.siblingSessionUUID = 0x1234; storeReceipt.siblingSessionGeneration = 7; storeReceipt.siblingSessionHealthy = true;
  storeReceipt.seededFromClusterUUID = 0x55; storeReceipt.seededFromContainerUUID = 0x66;
  storeReceipt.seedGeneration = 9; storeReceipt.seedFixtureSHA256 = expected; storeReceipt.appliedWatermarkSHA256 = expected;
  storeReceipt.sourceContentWatermarkSHA256 = expected; storeReceipt.sourceCatchupWatermarkSHA256 = expected;
  String storeBytes = {}; ProdigyStatefulStoreReceipt decodedStoreReceipt = {};
  suite.expect(prodigyStatefulStoreReceiptValid(storeReceipt) && BitseryEngine::serialize(storeBytes, storeReceipt) &&
                   BitseryEngine::deserializeSafe(storeBytes, decodedStoreReceipt) &&
                   prodigyStatefulStoreReceiptValid(decodedStoreReceipt) && decodedStoreReceipt.localContainerUUID == storeReceipt.localContainerUUID &&
                   decodedStoreReceipt.sourceCatchupWatermarkSHA256 == expected,
               "stateful_store_receipt_v3_roundtrips_source_boundary_evidence");
  ProdigyStatefulStoreSeedAuthority cutAuthority = {};
  cutAuthority.protocolVersion = ProdigyStatefulStoreSeedAuthority::sourceCutVersion;
  cutAuthority.authorityGeneration = 9; cutAuthority.operationUUID = 10; cutAuthority.applicationID = 3;
  cutAuthority.storeKind = storeReceipt.storeKind; cutAuthority.shardGroup = storeReceipt.shardGroup;
  cutAuthority.nShardGroups = storeReceipt.nShardGroups; cutAuthority.targetClusterUUID = storeReceipt.localClusterUUID;
  cutAuthority.targetDeploymentID = storeReceipt.deploymentID; cutAuthority.targetContainerUUID = storeReceipt.localContainerUUID;
  cutAuthority.sourceClusterUUID = storeReceipt.seededFromClusterUUID; cutAuthority.sourceDeploymentID = 11;
  cutAuthority.sourceContainerUUID = storeReceipt.seededFromContainerUUID; cutAuthority.seedGeneration = storeReceipt.seedGeneration;
  cutAuthority.fixtureSHA256 = expected; cutAuthority.sourceContentWatermarkSHA256 = expected;
  cutAuthority.sourceCatchupWatermarkSHA256 = expected; cutAuthority.sourceBaselineOperationUUID = 12;
  cutAuthority.sourceRequestUUID = 13; cutAuthority.sourceMemberRequestUUID = 14;
  cutAuthority.seedRouteUUID = 17; cutAuthority.cutUUID = 15; cutAuthority.cutGeneration = 16; cutAuthority.retainUntilMilliseconds = 12345;
  auto cutReceipt = storeReceipt; cutReceipt.protocolVersion = ProdigyStatefulStoreReceipt::sourceCutVersion;
  cutReceipt.operationUUID = cutAuthority.operationUUID; cutReceipt.sourceBaselineOperationUUID = cutAuthority.sourceBaselineOperationUUID;
  cutReceipt.sourceRequestUUID = cutAuthority.sourceRequestUUID; cutReceipt.sourceMemberRequestUUID = cutAuthority.sourceMemberRequestUUID;
  cutReceipt.seedRouteUUID = cutAuthority.seedRouteUUID; cutReceipt.sourceDeploymentID = cutAuthority.sourceDeploymentID; cutReceipt.cutUUID = cutAuthority.cutUUID;
  cutReceipt.cutGeneration = cutAuthority.cutGeneration; cutReceipt.retainUntilMilliseconds = cutAuthority.retainUntilMilliseconds;
  cutReceipt.materializedContentSHA256 = expected; cutReceipt.materializedHeadsSHA256 = expected;
  cutReceipt.cutMaterialized = true; cutReceipt.committedHeadsDominateCut = true;
  String authorityBytes = {}, proofBytes = {}; ProdigyStatefulStoreSeedAuthority decodedAuthority = {};
  ProdigyStatefulStoreReceipt decodedProof = {};
  suite.expect(prodigyStatefulStoreReceiptMatchesSourceCutAuthority(cutReceipt, cutAuthority) &&
      BitseryEngine::serialize(authorityBytes, cutAuthority) && BitseryEngine::deserializeSafe(authorityBytes, decodedAuthority) &&
      BitseryEngine::serialize(proofBytes, cutReceipt) && BitseryEngine::deserializeSafe(proofBytes, decodedProof) &&
      prodigyStatefulStoreReceiptMatchesSourceCutAuthority(decodedProof, decodedAuthority), "stateful_source_cut_native_proof_roundtrip");
  ProdigyStatefulStoreProofRecovery recovery = {}; recovery.authority = cutAuthority; recovery.expected = cutReceipt; recovery.nonce = 1;
  String recoveryBytes = {}; ProdigyStatefulStoreProofRecovery decodedRecovery = {};
  suite.expect(prodigyStatefulStoreProofRecoveryValid(recovery) && BitseryEngine::serialize(recoveryBytes, recovery) &&
      BitseryEngine::deserializeSafe(recoveryBytes, decodedRecovery) && prodigyStatefulStoreProofRecoveryValid(decodedRecovery),
      "stateful_proof_recovery_wire_roundtrip");
  auto badRecovery = recovery; badRecovery.expected.cutUUID++;
  suite.expect(!prodigyStatefulStoreProofRecoveryValid(badRecovery), "stateful_proof_recovery_rejects_other_cut");
  badRecovery = recovery; badRecovery.expected.state = ProdigyStatefulStoreReceiptState::withdrawn;
  badRecovery.expected.siblingSessionHealthy = false;
  suite.expect(!prodigyStatefulStoreProofRecoveryValid(badRecovery), "stateful_proof_recovery_rejects_withdrawn_history");
  String recoveryFrame = {}; Message::construct(recoveryFrame, NeuronTopic::statefulStoreProofRecovery,
      recovery.authority.targetContainerUUID, recoveryBytes);
  auto *recoveryMessage = reinterpret_cast<Message *>(recoveryFrame.data());
  suite.expect(ProdigyIngressValidation::validateNeuronPayloadForNeuron(recoveryMessage->topic, recoveryMessage->args, recoveryMessage->terminal()) &&
      !ProdigyIngressValidation::validateNeuronPayloadForNeuron(recoveryMessage->topic, recoveryMessage->args, recoveryMessage->terminal() - 1),
      "stateful_proof_recovery_neuron_frame_bounded");
  recoveryFrame.clear(); Message::construct(recoveryFrame, ContainerTopic::statefulStoreProofRecovery, recoveryBytes);
  recoveryMessage = reinterpret_cast<Message *>(recoveryFrame.data());
  suite.expect(ProdigyIngressValidation::validateContainerPayloadForHub(recoveryMessage->topic, recoveryMessage->args, recoveryMessage->terminal()) &&
      !ProdigyIngressValidation::validateContainerPayloadForHub(recoveryMessage->topic, recoveryMessage->args, recoveryMessage->terminal() - 1),
      "stateful_proof_recovery_container_frame_bounded");
  runtime.version = 5; runtime.statefulRuntimeCohort.front().nativeSourceCutReceipt = cutReceipt;
  runtimeBytes.clear(); decodedRuntime = {};
  suite.expect(BitseryEngine::serialize(runtimeBytes, runtime) && BitseryEngine::deserializeSafe(runtimeBytes, decodedRuntime) &&
      decodedRuntime.version == 5 && decodedRuntime.statefulRuntimeCohort.size() == 1 &&
      prodigyStatefulStoreReceiptMatchesSourceCutAuthority(decodedRuntime.statefulRuntimeCohort.front().nativeSourceCutReceipt, cutAuthority),
      "deployment_identity_v5_preserves_native_source_cut_proof");
  auto wrongRouteProof = cutReceipt; ++wrongRouteProof.seedRouteUUID;
  suite.expect(!prodigyStatefulStoreReceiptMatchesSourceCutAuthority(wrongRouteProof, cutAuthority),
      "stateful_source_cut_rejects_other_seed_route");
  decodedProof.committedHeadsDominateCut = false;
  suite.expect(!prodigyStatefulStoreReceiptMatchesSourceCutAuthority(decodedProof, decodedAuthority), "stateful_source_cut_requires_native_dominance");
  decodedProof.committedHeadsDominateCut = true; decodedProof.sourceMemberRequestUUID++;
  suite.expect(!prodigyStatefulStoreReceiptMatchesSourceCutAuthority(decodedProof, decodedAuthority), "stateful_source_cut_rejects_other_challenge");
  decodedProof.sourceMemberRequestUUID--; decodedProof.materializedContentSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  suite.expect(!prodigyStatefulStoreReceiptMatchesSourceCutAuthority(decodedProof, decodedAuthority), "stateful_source_cut_rejects_other_snapshot");
  decodedAuthority.expectedCatchupWatermarkSHA256 = expected;
  suite.expect(!prodigyStatefulStoreSeedAuthorityValid(decodedAuthority), "stateful_source_cut_rejects_legacy_watermark");
  ProdigyStatefulStoreSourceCut cut = {};
  cut.operationUUID = 1; cut.requestUUID = 2; cut.memberRequestUUID = 3;
  cut.sourceClusterUUID = clusterUUID; cut.sourceContainerUUID = 4;
  cut.sourceDeploymentID = (uint64_t(3) << 48) | 1; cut.applicationID = 3;
  cut.storeKind = DeploymentIdentityStoreKind::kv; cut.shardGroup = 2; cut.nShardGroups = 3;
  cut.retainUntilMilliseconds = 12345;
  String cutBytes = {}; ProdigyStatefulStoreSourceCut decodedCut = {};
  suite.expect(prodigyStatefulStoreSourceCutValid(cut) && BitseryEngine::serialize(cutBytes, cut) &&
      BitseryEngine::deserializeSafe(cutBytes, decodedCut) && prodigyStatefulStoreSourceCutValid(decodedCut) &&
      prodigyStatefulStoreSourceCutContextEqual(cut, decodedCut), "source_cut_prepare_wire_roundtrip");
  String sourceCutFrame = {};
  Message::construct(sourceCutFrame, NeuronTopic::statefulStoreSourceCut, cut.sourceContainerUUID, cutBytes);
  Message *sourceCutMessage = reinterpret_cast<Message *>(sourceCutFrame.data());
  suite.expect(ProdigyIngressValidation::validateNeuronPayloadForNeuron(sourceCutMessage->topic, sourceCutMessage->args, sourceCutMessage->terminal()) &&
      ProdigyIngressValidation::validateNeuronPayloadForBrain(sourceCutMessage->topic, sourceCutMessage->args, sourceCutMessage->terminal()) &&
      !ProdigyIngressValidation::validateNeuronPayloadForNeuron(sourceCutMessage->topic, sourceCutMessage->args, sourceCutMessage->terminal() - 1),
      "source_cut_neuron_wire_bounded_both_directions");
  sourceCutFrame.clear(); Message::construct(sourceCutFrame, ContainerTopic::statefulStoreSourceCut, cutBytes);
  sourceCutMessage = reinterpret_cast<Message *>(sourceCutFrame.data());
  suite.expect(ProdigyIngressValidation::validateContainerPayloadForNeuron(sourceCutMessage->topic, sourceCutMessage->args, sourceCutMessage->terminal()) &&
      ProdigyIngressValidation::validateContainerPayloadForHub(sourceCutMessage->topic, sourceCutMessage->args, sourceCutMessage->terminal()),
      "source_cut_container_wire_bounded_both_directions");
  auto response = cut; response.response = true; response.ready = true; response.cutUUID = 5;
  response.cutGeneration = 6; response.contentSHA256 = expected; response.headsSHA256 = expected;
  suite.expect(prodigyStatefulStoreSourceCutResponseMatches(cut, response), "source_cut_ready_matches_prepare");
  auto mismatched = response; mismatched.memberRequestUUID++;
  suite.expect(!prodigyStatefulStoreSourceCutResponseMatches(cut, mismatched), "source_cut_rejects_other_incarnation");
  auto query = cut; query.action = ProdigyStatefulStoreSourceCutAction::query; query.cutUUID = 5; query.cutGeneration = 6;
  auto queryResponse = response; queryResponse.action = query.action;
  suite.expect(prodigyStatefulStoreSourceCutResponseMatches(query, queryResponse), "source_cut_query_binds_retained_cut");
  queryResponse.cutGeneration++;
  suite.expect(!prodigyStatefulStoreSourceCutResponseMatches(query, queryResponse), "source_cut_rejects_other_generation");
  auto release = query; release.action = ProdigyStatefulStoreSourceCutAction::release;
  auto releaseResponse = release; releaseResponse.response = true;
  suite.expect(prodigyStatefulStoreSourceCutResponseMatches(release, releaseResponse), "source_cut_release_can_be_pending");
  releaseResponse.released = true;
  suite.expect(prodigyStatefulStoreSourceCutResponseMatches(release, releaseResponse), "source_cut_release_completion_matches");
  auto invalid = cut; invalid.contentSHA256 = expected;
  suite.expect(!prodigyStatefulStoreSourceCutValid(invalid), "source_cut_rejects_request_proof");
  invalid = response; invalid.headsSHA256.clear();
  suite.expect(!prodigyStatefulStoreSourceCutValid(invalid), "source_cut_rejects_incomplete_proof");
  invalid = cut; invalid.applicationID = 6;
  suite.expect(!prodigyStatefulStoreSourceCutValid(invalid), "source_cut_rejects_non_store_app");
  storeReceipt.siblingSessionHealthy = false;
  suite.expect(!prodigyStatefulStoreReceiptValid(storeReceipt),
               "stateful_store_receipt_fails_closed_without_live_authenticated_sibling");
}
