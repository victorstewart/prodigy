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
  suite.expect(persistedDecoded && parsedEndpoint && hashed && persisted.version == 1 && persisted.found && !persisted.live &&
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
}
