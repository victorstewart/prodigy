#pragma once

static bool decodeStatelessDeploymentAdmissionReceipt(String& bytes, StatelessDeploymentAdmissionReceipt& receipt)
{
  bool decoded = false;
  forEachMessageInBuffer(bytes, [&](Message *message) {
    if (MothershipTopic(message->topic) != MothershipTopic::pullStatelessDeploymentAdmission) return;
    uint8_t *args = message->args;
    String payload = {};
    Message::extractToStringView(args, payload);
    decoded = args == message->terminal() && BitseryEngine::deserializeSafe(payload, receipt);
  });
  return decoded;
}

static bool pullStatelessDeploymentAdmissionForTest(
    TestBrain& brain, Mothership& mothership, uint128_t operationID, StatelessDeploymentAdmissionReceipt& receipt)
{
  mothership.wBuffer.clear();
  String frame = {};
  brain.mothershipHandler(&mothership, buildMothershipMessage(
      frame, MothershipTopic::pullStatelessDeploymentAdmission, uint8_t(1), operationID));
  return decodeStatelessDeploymentAdmissionReceipt(mothership.wBuffer, receipt);
}

static void testStatelessDeploymentAdmissionContract(TestSuite& suite)
{
  ProdigyStatelessDeploymentAdmission admission = {};
  admission.operationID = uint128_t(0x71);
  admission.clusterUUID = uint128_t(0x72);
  admission.deploymentID = (uint64_t(62'010) << 48) | 4;
  admission.applicationID = 62'010;
  admission.versionID = 4;
  admission.requestPlanSHA256.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
  admission.normalizedPlanSHA256.assign("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"_ctv);
  admission.artifactSHA256.assign("1111111111111111111111111111111111111111111111111111111111111111"_ctv);
  admission.artifactBytes = 123;
  admission.acceptedAuthorityGeneration = 8;
  admission.acceptedMasterUUID = uint128_t(0x73);
  admission.acceptedMasterBootNs = 9;
  suite.expect(prodigyStatelessDeploymentAdmissionValid(admission), "stateless_admission_valid_immutable_record");

  ProdigyMasterAuthorityRuntimeState state = {};
  state.generation = 8;
  state.statelessDeploymentAdmissions.push_back(admission);
  String encoded = {};
  BitseryEngine::serialize(encoded, state);
  ProdigyMasterAuthorityRuntimeState restored = {};
  const bool decodedRuntimeState = BitseryEngine::deserializeSafe(encoded, restored) &&
      prodigyStatelessDeploymentAdmissionsValid(restored.statelessDeploymentAdmissions, restored.generation);
  suite.require(decodedRuntimeState, "stateless_admission_v8_roundtrip_validates_immutable_record");
  if (!decodedRuntimeState || restored.statelessDeploymentAdmissions.empty()) return;
  restored.statelessDeploymentAdmissions[0].artifactBytes += 1;
  suite.expect(!prodigyStatelessDeploymentAdmissionsEqual(state.statelessDeploymentAdmissions,
                                                           restored.statelessDeploymentAdmissions),
               "stateless_admission_changed_artifact_identity_conflicts");
  restored = state;
  restored.statelessDeploymentAdmissions.push_back(admission);
  suite.expect(!prodigyStatelessDeploymentAdmissionsValid(restored.statelessDeploymentAdmissions, restored.generation),
               "stateless_admission_duplicate_operation_rejected");
  restored = state;
  restored.statelessDeploymentAdmissions[0].applicationID += 1;
  suite.expect(!prodigyStatelessDeploymentAdmissionsValid(restored.statelessDeploymentAdmissions, restored.generation),
               "stateless_admission_rejects_deployment_application_identity_mismatch");

  ProdigyStatelessDeploymentAdmissionRequest request = {};
  request.operationID = admission.operationID;
  request.clusterUUID = admission.clusterUUID;
  request.expectedAuthorityGeneration = admission.acceptedAuthorityGeneration;
  request.expectedMasterUUID = admission.acceptedMasterUUID;
  request.expectedMasterBootNs = admission.acceptedMasterBootNs;
  request.requestPlanSHA256 = admission.requestPlanSHA256;
  request.artifactSHA256 = admission.artifactSHA256;
  request.artifactBytes = admission.artifactBytes;
  String encodedRequest = {};
  BitseryEngine::serialize(encodedRequest, request);
  ProdigyStatelessDeploymentAdmissionRequest decodedRequest = {};
  suite.expect(BitseryEngine::deserializeSafe(encodedRequest, decodedRequest) &&
                   decodedRequest.operationID == request.operationID &&
                   decodedRequest.expectedMasterUUID == request.expectedMasterUUID,
               "stateless_admission_request_roundtrip_binds_operation_and_authority");
  encodedRequest.append(uint8_t(0));
  suite.expect(!BitseryEngine::deserializeSafe(encodedRequest, decodedRequest),
               "stateless_admission_request_rejects_trailing_bytes");

  DeploymentPlan plan = {};
  plan.config.type = ApplicationType::stateless;
  plan.config.applicationID = 62'010;
  plan.config.versionID = 4;
  plan.isStateful = false;
  plan.useHostNetworkNamespace = false;
  plan.canaryCount = 0;
  plan.stateless.nBase = 1;
  plan.hasApiCredentialPolicy = true;
  plan.apiCredentialPolicy.applicationID = plan.config.applicationID;
  Wormhole endpoint = {};
  endpoint.source = ExternalAddressSource::registeredRoutablePrefix;
  endpoint.routablePrefixUUID = uint128_t(0x74);
  endpoint.layer4 = IPPROTO_TCP;
  endpoint.externalPort = 443;
  endpoint.containerPort = 8443;
  plan.wormholes.push_back(endpoint);
  suite.expect(prodigyStatelessDeploymentAdmissionPlanEligible(plan), "stateless_admission_profile_accepts_single_tcp_prefix_endpoint");
  plan.wormholes[0].hasDNSConfig = true;
  suite.expect(!prodigyStatelessDeploymentAdmissionPlanEligible(plan), "stateless_admission_profile_rejects_dns");
  plan.wormholes[0].hasDNSConfig = false;
  plan.wormholes[0].layer4 = IPPROTO_UDP;
  suite.expect(!prodigyStatelessDeploymentAdmissionPlanEligible(plan), "stateless_admission_profile_rejects_non_tcp");
  plan.wormholes[0].layer4 = IPPROTO_TCP;
  plan.isStateful = true;
  suite.expect(!prodigyStatelessDeploymentAdmissionPlanEligible(plan), "stateless_admission_profile_rejects_stateful");

  // The query fixture must hold the exact normalized plan referenced by its
  // receipt.  A local v8 record without that plan is deliberately provisional.
  plan.isStateful = false;
  plan.config.containerBlobSHA256 = admission.artifactSHA256;
  plan.config.containerBlobBytes = admission.artifactBytes;
  admission.deploymentID = plan.config.deploymentID();
  String normalizedQueryPlan = {}, normalizedQueryPlanSHA256 = {};
  BitseryEngine::serialize(normalizedQueryPlan, plan);
  suite.require(prodigyComputeSHA256Hex(normalizedQueryPlan, normalizedQueryPlanSHA256),
                "stateless_admission_query_fixture_hashes_normalized_plan");
  admission.normalizedPlanSHA256 = normalizedQueryPlanSHA256;
  state.statelessDeploymentAdmissions.clear();
  state.statelessDeploymentAdmissions.push_back(admission);

  TestNeuron self = {};
  self.uuid = admission.acceptedMasterUUID;
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &self;
  StreamingTestBrain brain = {};
  Mothership mothership = {};
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.persistedMachineInventoryEnumerated = true;
  brain.brainConfig.clusterUUID = admission.clusterUUID;
  brain.masterAuthorityRuntimeState = state;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = state.generation;
  brain.boottimens = admission.acceptedMasterBootNs;
  brain.nBrains = 1;
  brain.hasAuthoritativeTopology = true;
  ClusterMachine local = {};
  local.isBrain = true;
  local.uuid = admission.acceptedMasterUUID;
  brain.authoritativeTopology.machines.push_back(std::move(local));
  brain.deploymentPlans.insert_or_assign(admission.deploymentID, plan);
  suite.expect(brain.statelessDeploymentAdmissionMatchesPlan(admission, plan),
               "stateless_admission_query_fixture_matches_supported_normalized_plan");
  DeploymentPlan unsupportedMatchingPlan = plan;
  unsupportedMatchingPlan.isStateful = true;
  String unsupportedBytes = {}, unsupportedSHA256 = {};
  BitseryEngine::serialize(unsupportedBytes, unsupportedMatchingPlan);
  suite.require(prodigyComputeSHA256Hex(unsupportedBytes, unsupportedSHA256),
                "stateless_admission_profile_rejection_fixture_hashes_unsupported_plan");
  ProdigyStatelessDeploymentAdmission unsupportedMatchingAdmission = admission;
  unsupportedMatchingAdmission.normalizedPlanSHA256 = unsupportedSHA256;
  suite.expect(!brain.statelessDeploymentAdmissionMatchesPlan(unsupportedMatchingAdmission, unsupportedMatchingPlan),
               "stateless_admission_matching_hash_rejects_unsupported_profile");
  mothership.isFixedFile = true;
  mothership.fslot = 1;
  brain.mothership = &mothership;
  suite.require(brain.activateMothershipConnection(&mothership), "stateless_admission_query_fixture_activates_control_connection");
  StatelessDeploymentAdmissionReceipt found = {};
  suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, admission.operationID, found) &&
                   found.version == 2 && found.supported && found.accepted && !found.live && found.launchPending &&
                   found.admission.operationID == admission.operationID &&
                   found.currentAuthorityGeneration == state.generation &&
                   found.currentMasterUUID == admission.acceptedMasterUUID,
               "stateless_admission_query_returns_durable_operation_and_current_authority");
  StatelessDeploymentAdmissionReceipt missing = {};
  suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, uint128_t(0x75), missing) &&
                   missing.supported && !missing.accepted && missing.admission.operationID == 0 &&
                   missing.currentAuthorityGeneration == state.generation,
               "stateless_admission_query_reports_missing_operation_without_authorizing_retry");
  uint8_t malformed[sizeof(uint128_t)] = {};
  suite.expect(!ProdigyIngressValidation::validateMothershipPayload(
                   uint16_t(MothershipTopic::pullStatelessDeploymentAdmission), malformed, malformed + sizeof(malformed)),
               "stateless_admission_query_ingress_rejects_truncated_versioned_request");

  // An authority candidate is visible in memory while its writer is held, but
  // it must not become an accepted retry receipt until that exact generation
  // has a durable completion.
  StreamingTestBrain held = {};
  Mothership heldMothership = {};
  held.weAreMaster = true;
  held.noMasterYet = false;
  held.ignited = true;
  held.persistedMachineInventoryEnumerated = true;
  held.boottimens = admission.acceptedMasterBootNs;
  held.brainConfig.clusterUUID = admission.clusterUUID;
  held.nBrains = 1;
  held.hasAuthoritativeTopology = true;
  ClusterMachine heldLocal = {};
  heldLocal.isBrain = true;
  heldLocal.uuid = admission.acceptedMasterUUID;
  held.authoritativeTopology.machines.push_back(std::move(heldLocal));
  held.deploymentPlans.insert_or_assign(admission.deploymentID, plan);
  held.masterAuthorityRuntimeState = state;
  held.masterAuthorityRuntimeStateDurable = false;
  held.durableMasterAuthorityRuntimeStateGeneration = 0;
  held.holdRuntimePersistence = true;
  heldMothership.isFixedFile = true;
  heldMothership.fslot = 2;
  held.mothership = &heldMothership;
  suite.require(held.activateMothershipConnection(&heldMothership), "stateless_admission_held_fixture_activates_control_connection");
  held.commitMasterAuthorityStateChangeAsync({}, false);
  StatelessDeploymentAdmissionReceipt beforeDurable = {};
  suite.expect(pullStatelessDeploymentAdmissionForTest(held, heldMothership, admission.operationID, beforeDurable) &&
                   !beforeDurable.accepted && beforeDurable.launchPending,
               "stateless_admission_query_does_not_accept_held_authority_candidate");
  held.finishRuntimePersistence(false);
  StatelessDeploymentAdmissionReceipt afterFailure = {};
  suite.expect(pullStatelessDeploymentAdmissionForTest(held, heldMothership, admission.operationID, afterFailure) &&
                   !afterFailure.accepted,
               "stateless_admission_query_does_not_accept_failed_authority_candidate");
  held.commitMasterAuthorityStateChangeAsync({}, false);
  held.finishRuntimePersistence(true);
  StatelessDeploymentAdmissionReceipt afterDurable = {};
  suite.expect(pullStatelessDeploymentAdmissionForTest(held, heldMothership, admission.operationID, afterDurable) &&
                   afterDurable.accepted && !afterDurable.live && afterDurable.launchPending,
               "stateless_admission_query_accepts_only_after_exact_durable_generation");
  thisNeuron = previousNeuron;
}
