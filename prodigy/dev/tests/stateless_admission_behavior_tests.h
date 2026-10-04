#pragma once

// These tests deliberately enter the public Mothership handler.  They use a
// real Discombobulator artifact because an accepted admission is a runtime
// contract, not a synthetic blob parser test.
static bool loadStatelessAdmissionBehaviorArtifact(String& blob, String& failure)
{
  blob.clear();
  failure.clear();
  const char *path = ::getenv("PRODIGY_TEST_ADMISSION_APP_ARTIFACT");
  if (path == nullptr || path[0] == '\0') path = PRODIGY_TEST_APP_ARTIFACT;
  if (path == nullptr || path[0] == '\0')
  {
    failure.assign("a real PRODIGY_TEST_ADMISSION_APP_ARTIFACT is required for stateless admission behavior tests"_ctv);
    return false;
  }
  Filesystem::openReadAtClose(-1, String(path), blob);
  const String headerText = prodigyDiscombobulatorBlobHeaderText();
  if (blob.size() <= headerText.size())
  {
    failure.assign("stateless admission artifact is truncated"_ctv);
    return false;
  }
  String header = {};
  header.assign(blob.substr(0, headerText.size(), Copy::yes));
  return prodigyValidateDiscombobulatorBlobHeaderText(header, &failure);
}

static DeploymentPlan statelessAdmissionBehaviorPlan(uint16_t applicationID, uint16_t versionID = 1)
{
  DeploymentPlan plan = {};
  seedDeployRequestPlan(plan, applicationID);
  plan.config.type = ApplicationType::stateless;
  plan.config.versionID = versionID;
  plan.isStateful = false;
  plan.useHostNetworkNamespace = false;
  plan.moveConstructively = false;
  plan.requiresDatacenterUniqueTag = false;
  plan.canaryCount = 0;
  plan.stateless.nBase = 1;
  plan.advertisements.clear();
  plan.subscriptions.clear();
  plan.whiteholes.clear();
  plan.wormholes.clear();
  Wormhole endpoint = {};
  endpoint.name.assign("admission"_ctv);
  endpoint.source = ExternalAddressSource::registeredRoutablePrefix;
  endpoint.routablePrefixUUID = uint128_t(0x7a110001);
  endpoint.layer4 = IPPROTO_TCP;
  endpoint.externalPort = 443;
  endpoint.containerPort = 8443;
  plan.wormholes.push_back(std::move(endpoint));
  return plan;
}

static bool decodeStatelessAdmissionBehaviorReply(
    String& bytes, StatelessDeploymentAdmissionReceipt& receipt)
{
  bool decoded = false;
  forEachMessageInBuffer(bytes, [&](Message *message) {
    if (MothershipTopic(message->topic) != MothershipTopic::admitStatelessDeployment) return;
    uint8_t *args = message->args;
    String serialized = {};
    Message::extractToStringView(args, serialized);
    decoded = args == message->terminal() && BitseryEngine::deserializeSafe(serialized, receipt) && receipt.version == 2;
  });
  return decoded;
}

static bool submitStatelessAdmissionBehaviorRequest(
    StreamingTestBrain& brain,
    Mothership& mothership,
    const ProdigyStatelessDeploymentAdmissionRequest& request,
    const DeploymentPlan& plan,
    const String& blob,
    StatelessDeploymentAdmissionReceipt *receipt = nullptr)
{
  String serializedRequest = {}, serializedPlan = {}, frame = {};
  BitseryEngine::serialize(serializedRequest, const_cast<ProdigyStatelessDeploymentAdmissionRequest&>(request));
  BitseryEngine::serialize(serializedPlan, const_cast<DeploymentPlan&>(plan));
  mothership.wBuffer.clear();
  brain.mothershipHandler(
      &mothership,
      buildMothershipMessage(frame, MothershipTopic::admitStatelessDeployment, serializedRequest, serializedPlan, blob));
  return receipt == nullptr || decodeStatelessAdmissionBehaviorReply(mothership.wBuffer, *receipt);
}

static ProdigyStatelessDeploymentAdmissionRequest statelessAdmissionBehaviorRequest(
    const StreamingTestBrain& brain,
    uint128_t operationID,
    const DeploymentPlan& plan,
    const String& blob)
{
  ProdigyStatelessDeploymentAdmissionRequest request = {};
  request.operationID = operationID;
  request.clusterUUID = brain.brainConfig.clusterUUID;
  request.expectedAuthorityGeneration = brain.masterAuthorityRuntimeState.generation;
  request.expectedMasterUUID = brain.selfBrainUUID();
  request.expectedMasterBootNs = brain.boottimens;
  String serializedPlan = {}, failure = {};
  BitseryEngine::serialize(serializedPlan, const_cast<DeploymentPlan&>(plan));
  (void)prodigyComputeSHA256Hex(serializedPlan, request.requestPlanSHA256, &failure);
  (void)prodigyComputeSHA256Hex(blob, request.artifactSHA256, &failure);
  request.artifactBytes = blob.size();
  return request;
}

class ScopedStatelessAdmissionBehaviorIdentity {
public:
  NeuronBase *previousNeuron = nullptr;
  BrainBase *previousBrain = nullptr;

  ScopedStatelessAdmissionBehaviorIdentity(StreamingTestBrain& brain, TestNeuron& neuron, uint128_t uuid)
  {
    neuron.uuid = uuid;
    previousNeuron = thisNeuron;
    previousBrain = thisBrain;
    thisNeuron = &neuron;
    thisBrain = &brain;
  }

  ~ScopedStatelessAdmissionBehaviorIdentity()
  {
    thisNeuron = previousNeuron;
    thisBrain = previousBrain;
  }
};

// Admission staging owns a raw artifact-I/O poll.  Every early test return
// must quiesce that owner while the async ring and its Mothership stream still
// exist; otherwise Brain teardown tries to queue a rejection after the stream
// has already been destroyed.
class ScopedStatelessAdmissionBehaviorArtifactIO {
public:
  ScopedTempDir store;
  StreamingTestBrain& brain;
  Mothership& mothership;

  ScopedStatelessAdmissionBehaviorArtifactIO(StreamingTestBrain& value, Mothership& stream)
      : brain(value), mothership(stream)
  {
    if (store.valid())
    {
      brain.testContainerArtifactStoreRoot.assign(store.path.c_str());
    }
  }

  ~ScopedStatelessAdmissionBehaviorArtifactIO()
  {
    if (brain.artifactIO)
    {
      (void)quiesceArtifactIOForTest(brain.artifactIO.get());
      brain.artifactIO.reset();
    }
    RingDispatcher::eraseMultiplexee(&mothership);
    brain.activeMotherships.erase(&mothership);
    brain.testContainerArtifactStoreRoot.clear();
  }
};

static void initializeStatelessAdmissionBehaviorFixture(
    StreamingTestBrain& brain, Mothership& mothership, uint128_t clusterUUID)
{
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.persistedMachineInventoryEnumerated = true;
  brain.nBrains = 1;
  brain.boottimens = 0x7a110010;
  brain.brainConfig.clusterUUID = clusterUUID;
  brain.masterAuthorityRuntimeState.generation = 1;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 1;
  const uint128_t localUUID = brain.selfBrainUUID();
  DistributableExternalSubnet prefix = {};
  prefix.uuid = uint128_t(0x7a110001);
  prefix.usage = ExternalSubnetUsage::wormholes;
  prefix.ingressScope = RoutableIngressScope::singleMachine;
  prefix.machineUUID = localUUID;
  prefix.subnet = IPPrefix("198.51.100.0", false, 30);
  brain.brainConfig.distributableExternalSubnets.push_back(std::move(prefix));
  brain.authoritativeTopology.version = 1;
  ClusterMachine member = {};
  member.isBrain = true;
  member.uuid = localUUID;
  brain.authoritativeTopology.machines.push_back(std::move(member));
  brain.hasAuthoritativeTopology = true;
  mothership.isFixedFile = true;
  mothership.fslot = 1;
  mothership.pendingSend = true;
  brain.mothership = &mothership;
}

static bool addStatelessAdmissionBehaviorAuthenticatedPeer(
    TestSuite& suite, StreamingTestBrain& brain, BrainView& peer, uint128_t uuid, int64_t bootNs)
{
  peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = 71;
  peer.registrationFresh = true;
  peer.uuid = uuid;
  peer.boottimens = bootNs;
  peer.ioGeneration = 1;
  peer.version = ProdigyBinaryVersion;
  peer.existingMasterUUID = brain.selfBrainUUID();
  reserveTransportStream(peer);
  ProdigyTransportTLSStream client = {};
  reserveTransportStream(client);
  if (!configureSingleNodeTransportRuntime(suite, "stateless_admission_behavior_peer", peer.uuid) ||
      !peer.beginTransportTLS(true) || !client.beginTransportTLS(false) ||
      !completeTransportHandshake(client, peer)) return false;
  peer.tlsPeerVerified = true;
  peer.tlsPeerUUID = peer.uuid;
  peer.clearQueuedSendBytes();
  peer.pendingSend = true;
  peer.pendingSendBytes = 0;
  peer.containerRetirementCapabilityAcknowledged = true;
  peer.containerRetirementCapabilityUUID = peer.uuid;
  peer.containerRetirementCapabilityBootNs = peer.boottimens;
  peer.containerRetirementCapabilityIOGeneration = peer.ioGeneration;
  peer.statelessDeploymentAdmissionCapabilityAcknowledged = true;
  brain.brains.insert(&peer);
  brain.nBrains = 2;
  ClusterMachine member = {};
  member.isBrain = true;
  member.uuid = peer.uuid;
  brain.authoritativeTopology.machines.push_back(std::move(member));
  return true;
}

static ProdigyStatelessDeploymentAdmission statelessAdmissionBehaviorRecord(
    const StreamingTestBrain& brain,
    const ProdigyStatelessDeploymentAdmissionRequest& request,
    const DeploymentPlan& normalizedPlan)
{
  ProdigyStatelessDeploymentAdmission record = {};
  record.operationID = request.operationID;
  record.clusterUUID = request.clusterUUID;
  record.deploymentID = normalizedPlan.config.deploymentID();
  record.applicationID = normalizedPlan.config.applicationID;
  record.versionID = normalizedPlan.config.versionID;
  record.requestPlanSHA256.assign(request.requestPlanSHA256);
  String serialized = {}, failure = {};
  DeploymentPlan copy = normalizedPlan;
  BitseryEngine::serialize(serialized, copy);
  (void)prodigyComputeSHA256Hex(serialized, record.normalizedPlanSHA256, &failure);
  record.artifactSHA256.assign(request.artifactSHA256);
  record.artifactBytes = request.artifactBytes;
  record.acceptedAuthorityGeneration = brain.masterAuthorityRuntimeState.generation;
  record.acceptedMasterUUID = brain.selfBrainUUID();
  record.acceptedMasterBootNs = brain.boottimens;
  return record;
}

static void acknowledgeStatelessAdmissionBehaviorAuthority(StreamingTestBrain& brain, BrainView& peer)
{
  String serialized = {}, digest = {};
  if (!brain.serializeCurrentMasterAuthorityTransition(serialized, digest)) return;
  brain.noteMasterAuthorityTransitionSentToPeer(&peer, brain.masterAuthorityRuntimeState, digest);
  ProdigyMasterAuthorityStateTransitionAck acknowledgement = {};
  acknowledgement.generation = brain.masterAuthorityRuntimeState.generation;
  acknowledgement.peerUUID = peer.uuid;
  acknowledgement.peerBootNs = peer.boottimens;
  acknowledgement.transitionDigest.assign(digest);
  brain.acknowledgeMasterAuthorityTransition(&peer, acknowledgement);
}

static void testStatelessDeploymentAdmissionBehavior(TestSuite& suite)
{
  // The admission poll retains this text in the Brain log for an existing
  // operation.  Keep the numeric fields printable: String's generic {}
  // formatter writes integral values as raw bytes, which makes fprintf stop
  // at the first boolean NUL.
  {
    StreamingTestBrain brain = {};
    TestNeuron self = {};
    ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110011));
    Mothership mothership = {};
    initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110090));
    brain.nBrains = 2;
    String blocker = {};
    brain.describeStatelessDeploymentAdmissionCapabilityBlocker(blocker);
    const std::string_view text(blocker.c_str(), blocker.size());
    suite.expect(text.find("topologyBrains=1 localBrainCount=2") != std::string_view::npos &&
                     text.find('\0') == std::string_view::npos,
                 "stateless_admission_behavior_capability_blocker_formats_topology_counts_without_nul");
  }

  {
    StreamingTestBrain brain = {};
    TestNeuron self = {};
    ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110011));
    Mothership mothership = {};
    initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110091));
    BrainView peer = {};
    const bool peerReady = addStatelessAdmissionBehaviorAuthenticatedPeer(
        suite, brain, peer, uint128_t(0x7a110420), 0x7a110430);
    suite.require(peerReady, "stateless_admission_behavior_capability_blocker_authenticates_peer");
    if (peerReady)
    {
      peer.statelessDeploymentAdmissionCapabilityAcknowledged = false;
      String blocker = {};
      brain.describeStatelessDeploymentAdmissionCapabilityBlocker(blocker);
      const std::string_view text(blocker.c_str(), blocker.size());
      suite.expect(text.find("present=1 quarantined=0 registrationFresh=1 socketActive=1 tlsEnabled=1 tlsNegotiated=1 tlsVerified=1") != std::string_view::npos &&
                       text.find("retirementWitness=1") != std::string_view::npos &&
                       text.find("witnessBootNs=2047935536 witnessIOGeneration=1 admissionWitness=0") != std::string_view::npos &&
                       text.find('\0') == std::string_view::npos,
                   "stateless_admission_behavior_capability_blocker_formats_authenticated_missing_ack");
      brain.brains.erase(&peer);
    }
    ProdigyTransportTLSRuntime::clear();
  }

  String artifact = {}, artifactFailure = {};
  const bool artifactLoaded = loadStatelessAdmissionBehaviorArtifact(artifact, artifactFailure);
  suite.require(artifactLoaded, "stateless_admission_behavior_loads_real_discombobulator_artifact");
  if (!artifactLoaded) return;

  // A held write may expose a transient in-memory record, but handler queries
  // and lease/start owners must never treat it as accepted.
  {
    ScopedAsyncMothershipRing ring = {};
    StreamingTestBrain brain = {};
    TestNeuron self = {};
    ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110011));
    NoopBrainIaaS iaas = {};
    Mothership mothership = {};
    ScopedStatelessAdmissionBehaviorArtifactIO artifactIO(brain, mothership);
    brain.iaas = &iaas;
    initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110100));
    suite.require(brain.activateMothershipConnection(&mothership), "stateless_admission_behavior_held_activates_stream");
    if (!brain.streamIsActive(&mothership)) return;
    DeploymentPlan plan = statelessAdmissionBehaviorPlan(62'101);
    String reserveFailure = {};
    suite.require(brain.reserveApplicationIDMapping("AdmissionHeld"_ctv, plan.config.applicationID, &reserveFailure),
                  "stateless_admission_behavior_held_reserves_application");
    if (!brain.isApplicationIDReserved(plan.config.applicationID)) return;
    brain.holdRuntimePersistence = true;
    const auto request = statelessAdmissionBehaviorRequest(brain, uint128_t(0x7a110101), plan, artifact);
    (void)submitStatelessAdmissionBehaviorRequest(brain, mothership, request, plan, artifact);
    ring.runFor(200);
    suite.require(!brain.pendingRuntimePersistence.empty() &&
                      !brain.masterAuthorityRuntimeState.statelessDeploymentAdmissions.empty(),
                  "stateless_admission_behavior_held_write_reaches_durability_owner");
    if (brain.pendingRuntimePersistence.empty() || brain.masterAuthorityRuntimeState.statelessDeploymentAdmissions.empty()) return;
    const uint32_t pendingPersistenceBeforeRetry = brain.pendingRuntimePersistence.size();
    const uint32_t pendingAdmissionRequestsBeforeRetry = brain.pendingStatelessDeploymentAdmissionRequests.size();
    const uint32_t deploymentsBeforeRetry = brain.deployments.size();
    const uint32_t leasesBeforeRetry = brain.routableResourceLeaseRuntimeState.size();
    // A retry carries a newly serialized request header for the current
    // authority generation, but its immutable operation/plan/blob identity is
    // exactly the held writer's.  It is a provisional receipt, never a second
    // staging owner or lease.
    const auto retryRequest = statelessAdmissionBehaviorRequest(brain, request.operationID, plan, artifact);
    StatelessDeploymentAdmissionReceipt provisional = {};
    suite.expect(submitStatelessAdmissionBehaviorRequest(
                     brain, mothership, retryRequest, plan, artifact, &provisional) &&
                     provisional.admission.operationID == request.operationID && !provisional.accepted &&
                     provisional.launchPending && provisional.failure.empty() &&
                     brain.pendingRuntimePersistence.size() == pendingPersistenceBeforeRetry &&
                     brain.pendingStatelessDeploymentAdmissionRequests.size() == pendingAdmissionRequestsBeforeRetry &&
                     brain.deployments.size() == deploymentsBeforeRetry &&
                     brain.routableResourceLeaseRuntimeState.size() == leasesBeforeRetry,
                 "stateless_admission_behavior_held_exact_retry_returns_provisional_receipt_without_duplicate_owner");
    StatelessDeploymentAdmissionReceipt queried = {};
    suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, request.operationID, queried) &&
                     !queried.accepted && !queried.live && queried.launchPending,
                 "stateless_admission_behavior_held_write_never_accepts_or_starts");
    suite.expect(brain.routableResourceLeaseRuntimeState.empty(),
                 "stateless_admission_behavior_held_write_never_leases_endpoint");
    brain.finishRuntimePersistence(false);
    queried = {};
    suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, request.operationID, queried) && !queried.accepted,
                 "stateless_admission_behavior_failed_write_never_accepts");
    suite.expect(!brain.deployments.contains(plan.config.deploymentID()) && brain.routableResourceLeaseRuntimeState.empty(),
                 "stateless_admission_behavior_failed_write_never_starts_or_leases");
  }

  // A durable admission is not revoked when its originating Mothership stream
  // disappears.  The new stream may resume only the exact immutable request.
  {
    ScopedAsyncMothershipRing ring = {};
    StreamingTestBrain brain = {};
    TestNeuron self = {};
    ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110011));
    NoopBrainIaaS iaas = {};
    Mothership mothership = {};
    ScopedStatelessAdmissionBehaviorArtifactIO artifactIO(brain, mothership);
    brain.iaas = &iaas;
    initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110180));
    suite.require(brain.activateMothershipConnection(&mothership), "stateless_admission_behavior_retry_activates_stream");
    DeploymentPlan plan = statelessAdmissionBehaviorPlan(62'107);
    String reserveFailure = {};
    suite.require(brain.reserveApplicationIDMapping("AdmissionRetry"_ctv, plan.config.applicationID, &reserveFailure),
                  "stateless_admission_behavior_retry_reserves_application");
    brain.holdRuntimePersistence = true;
    const auto request = statelessAdmissionBehaviorRequest(brain, uint128_t(0x7a110181), plan, artifact);
    (void)submitStatelessAdmissionBehaviorRequest(brain, mothership, request, plan, artifact);
    ring.runFor(200);
    suite.require(!brain.pendingRuntimePersistence.empty() &&
                      !brain.masterAuthorityRuntimeState.statelessDeploymentAdmissions.empty(),
                  "stateless_admission_behavior_retry_reaches_durable_owner");
    if (brain.pendingRuntimePersistence.empty()) return;
    ++mothership.connectionIncarnation;
    brain.finishRuntimePersistence(true);
    StatelessDeploymentAdmissionReceipt durable = {};
    suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, request.operationID, durable) &&
                     durable.accepted && durable.launchPending && !durable.live,
                 "stateless_admission_behavior_lost_stream_retains_durable_operation");
    (void)submitStatelessAdmissionBehaviorRequest(brain, mothership, request, plan, artifact);
    ring.runFor(200);
    StatelessDeploymentAdmissionReceipt retried = {};
    suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, request.operationID, retried) &&
                     retried.admission.operationID == request.operationID &&
                     brain.masterAuthorityRuntimeState.statelessDeploymentAdmissions.size() == 1,
                 "stateless_admission_behavior_exact_retry_reuses_durable_operation");
  }

  // The pending callback is fenced by the authority epoch.  A stream/authority
  // change before completion cannot publish or launch that old request.
  {
    ScopedAsyncMothershipRing ring = {};
    StreamingTestBrain brain = {};
    TestNeuron self = {};
    ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110011));
    NoopBrainIaaS iaas = {};
    Mothership mothership = {};
    ScopedStatelessAdmissionBehaviorArtifactIO artifactIO(brain, mothership);
    brain.iaas = &iaas;
    initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110200));
    suite.require(brain.activateMothershipConnection(&mothership), "stateless_admission_behavior_stale_activates_stream");
    DeploymentPlan plan = statelessAdmissionBehaviorPlan(62'102);
    String reserveFailure = {};
    suite.require(brain.reserveApplicationIDMapping("AdmissionStale"_ctv, plan.config.applicationID, &reserveFailure),
                  "stateless_admission_behavior_stale_reserves_application");
    brain.holdRuntimePersistence = true;
    const auto request = statelessAdmissionBehaviorRequest(brain, uint128_t(0x7a110201), plan, artifact);
    (void)submitStatelessAdmissionBehaviorRequest(brain, mothership, request, plan, artifact);
    ring.runFor(200);
    suite.require(!brain.pendingRuntimePersistence.empty() &&
                      !brain.masterAuthorityRuntimeState.statelessDeploymentAdmissions.empty(),
                  "stateless_admission_behavior_stale_write_reaches_durability_owner");
    if (brain.pendingRuntimePersistence.empty() || brain.masterAuthorityRuntimeState.statelessDeploymentAdmissions.empty()) return;
    ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(true);
    StatelessDeploymentAdmissionReceipt queried = {};
    suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, request.operationID, queried) && !queried.accepted,
                 "stateless_admission_behavior_stale_authority_callback_cannot_accept");
    suite.expect(!brain.deployments.contains(plan.config.deploymentID()),
                 "stateless_admission_behavior_stale_authority_callback_cannot_start");
  }

  // The handler binds operation, raw request plan, and artifact identity before
  // it delegates to the ordinary deployment owner.  A different request for a
  // recorded operation or deployment must not replace that durable intent.
  {
    ScopedAsyncMothershipRing ring = {};
    StreamingTestBrain brain = {};
    TestNeuron self = {};
    ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110011));
    NoopBrainIaaS iaas = {};
    Mothership mothership = {};
    ScopedStatelessAdmissionBehaviorArtifactIO artifactIO(brain, mothership);
    brain.iaas = &iaas;
    initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110300));
    suite.require(brain.activateMothershipConnection(&mothership), "stateless_admission_behavior_conflict_activates_stream");
    DeploymentPlan plan = statelessAdmissionBehaviorPlan(62'103);
    String reserveFailure = {};
    suite.require(brain.reserveApplicationIDMapping("AdmissionConflict"_ctv, plan.config.applicationID, &reserveFailure),
                  "stateless_admission_behavior_conflict_reserves_application");
    brain.holdRuntimePersistence = true;
    const auto request = statelessAdmissionBehaviorRequest(brain, uint128_t(0x7a110301), plan, artifact);
    (void)submitStatelessAdmissionBehaviorRequest(brain, mothership, request, plan, artifact);
    ring.runFor(200);
    DeploymentPlan conflictingPlan = plan;
    conflictingPlan.config.versionID += 1;
    const auto conflictingRequest = statelessAdmissionBehaviorRequest(brain, request.operationID, conflictingPlan, artifact);
    StatelessDeploymentAdmissionReceipt conflict = {};
    const bool replied = submitStatelessAdmissionBehaviorRequest(
        brain, mothership, conflictingRequest, conflictingPlan, artifact, &conflict);
    suite.expect(replied && !conflict.accepted && conflict.failure.size() > 0,
                 "stateless_admission_behavior_rejects_conflicting_operation_raw_plan");
    const auto conflictingOperation = statelessAdmissionBehaviorRequest(brain, uint128_t(0x7a110302), plan, artifact);
    StatelessDeploymentAdmissionReceipt deploymentConflict = {};
    const bool deploymentReplied = submitStatelessAdmissionBehaviorRequest(
        brain, mothership, conflictingOperation, plan, artifact, &deploymentConflict);
    suite.expect(deploymentReplied && !deploymentConflict.accepted && deploymentConflict.failure.size() > 0,
                 "stateless_admission_behavior_rejects_conflicting_deployment_operation");
  }

  // The authority transition atomically carries the normalized plan and
  // admission record.  It may fan out before the ordinary blob receipt, but
  // launch still waits for the exact authority ACK and that blob receipt.
  {
    const char *orderName = "stateless_admission_behavior_plan_then_authority";
    ScopedAsyncMothershipRing ring = {};
    StreamingTestBrain brain = {};
    TestNeuron self = {};
    ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110011));
    NoopBrainIaaS iaas = {};
    Mothership mothership = {};
    ScopedStatelessAdmissionBehaviorArtifactIO artifactIO(brain, mothership);
    BrainView peer = {};
    brain.iaas = &iaas;
    initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110400));
    suite.require(brain.activateMothershipConnection(&mothership), orderName);
    if (!addStatelessAdmissionBehaviorAuthenticatedPeer(
            suite, brain, peer, uint128_t(0x7a110420), 0x7a110430))
    {
      brain.brains.erase(&peer);
      ProdigyTransportTLSRuntime::clear();
      return;
    }
    DeploymentPlan rawPlan = statelessAdmissionBehaviorPlan(uint16_t(62'104));
    String reserveFailure = {};
    suite.require(brain.reserveApplicationIDMapping("AdmissionAckOrder"_ctv, rawPlan.config.applicationID, &reserveFailure), orderName);
    const auto request = statelessAdmissionBehaviorRequest(brain, uint128_t(0x7a110440), rawPlan, artifact);
    DeploymentPlan normalizedPlan = rawPlan;
    normalizedPlan.config.containerBlobSHA256.assign(request.artifactSHA256);
    normalizedPlan.config.containerBlobBytes = request.artifactBytes;
    const auto record = statelessAdmissionBehaviorRecord(brain, request, normalizedPlan);
    brain.masterAuthorityRuntimeState.statelessDeploymentAdmissions.push_back(record);
    brain.deploymentPlans.insert_or_assign(record.deploymentID, normalizedPlan);
    ApplicationDeployment deployment = {};
    deployment.plan = normalizedPlan;
    brain.deployments.insert_or_assign(record.deploymentID, &deployment);

    auto authorityFrames = [&]() {
      uint32_t count = 0;
      forEachMessageInBuffer(peer.wBuffer, [&](Message *message) {
        if (BrainTopic(message->topic) == BrainTopic::replicateMasterAuthorityState) ++count;
      });
      return count;
    };
    // The v8 record has been staged in memory but its persistence completion
    // has not fired: neither the record nor its transition may reach a peer.
    brain.masterAuthorityRuntimeStateDurable = false;
    brain.durableMasterAuthorityRuntimeStateGeneration = 0;
    brain.queueMasterAuthorityRuntimeStateReplication(false);
    suite.expect(authorityFrames() == 0,
                 "stateless_admission_behavior_held_durability_blocks_v8_fanout");
    peer.wBuffer.clear();
    peer.clearQueuedSendBytes();
    peer.pendingSend = true;
    peer.pendingSendBytes = 0;
    brain.masterAuthorityRuntimeStateDurable = true;
    brain.durableMasterAuthorityRuntimeStateGeneration = brain.masterAuthorityRuntimeState.generation;
    suite.expect(!brain.statelessDeploymentRecoveryLaunchAllowed(&deployment), orderName);
    const uint32_t deploymentsBeforeAuthorityQuery = brain.deployments.size();
    const uint32_t pendingArtifactsBeforeAuthorityQuery = brain.pendingMothershipSpinArtifacts.size();
    StatelessDeploymentAdmissionReceipt beforeAuthorityAck = {};
    suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, record.operationID, beforeAuthorityAck) &&
                     beforeAuthorityAck.admission.operationID == record.operationID && !beforeAuthorityAck.accepted &&
                     beforeAuthorityAck.launchPending && beforeAuthorityAck.failure.empty() &&
                     brain.deployments.size() == deploymentsBeforeAuthorityQuery &&
                     brain.pendingMothershipSpinArtifacts.size() == pendingArtifactsBeforeAuthorityQuery,
                 "stateless_admission_behavior_query_is_pending_before_v3_authority_ack");
    brain.queueMasterAuthorityRuntimeStateReplication(false);
    suite.expect(authorityFrames() == 1,
                 "stateless_admission_behavior_atomic_plan_and_record_allow_v8_fanout_before_blob_ack");
    suite.expect(!brain.deploymentReplicationAllowedForPeer(record.deploymentID, &peer),
                 "stateless_admission_behavior_blocks_plan_blob_sender_before_exact_authority_ack");
    suite.expect(!brain.statelessDeploymentRecoveryLaunchAllowed(&deployment),
                 "stateless_admission_behavior_authority_and_blob_receipts_both_required");
    acknowledgeStatelessAdmissionBehaviorAuthority(brain, peer);
    StatelessDeploymentAdmissionReceipt afterAuthorityAck = {};
    suite.expect(pullStatelessDeploymentAdmissionForTest(brain, mothership, record.operationID, afterAuthorityAck) &&
                     afterAuthorityAck.admission.operationID == record.operationID && afterAuthorityAck.accepted &&
                     afterAuthorityAck.launchPending && afterAuthorityAck.failure.empty(),
                 "stateless_admission_behavior_query_accepts_after_v3_authority_ack");
    suite.expect(brain.deploymentReplicationAllowedForPeer(record.deploymentID, &peer),
                 "stateless_admission_behavior_allows_plan_blob_sender_after_exact_authority_ack");
    suite.expect(!brain.statelessDeploymentRecoveryLaunchAllowed(&deployment),
                 "stateless_admission_behavior_authority_ack_before_blob_cannot_start");
    deployment.brainBlobEchoPeerKeys.insert(peer.uuid);
    suite.expect(brain.statelessDeploymentRecoveryLaunchAllowed(&deployment), orderName);
    brain.deployments.erase(record.deploymentID);
    brain.brains.erase(&peer);
    ProdigyTransportTLSRuntime::clear();
  }

  // A v3 transition persists each v8 operation with the exact normalized
  // plan.  Receiver preparation rejects a receipt without that plan or with a
  // plan whose blob-bound normalized bytes no longer match.
  {
    ScopedAsyncMothershipRing ring = {};
    StreamingTestBrain sender = {};
    TestNeuron senderSelf = {};
    ScopedStatelessAdmissionBehaviorIdentity senderIdentity(sender, senderSelf, uint128_t(0x7a110611));
    NoopBrainIaaS senderIaaS = {};
    Mothership senderMothership = {};
    ScopedStatelessAdmissionBehaviorArtifactIO senderArtifactIO(sender, senderMothership);
    sender.iaas = &senderIaaS;
    initializeStatelessAdmissionBehaviorFixture(sender, senderMothership, uint128_t(0x7a110600));
    DeploymentPlan rawPlan = statelessAdmissionBehaviorPlan(62'108);
    String reserveFailure = {};
    suite.require(sender.reserveApplicationIDMapping("AdmissionV3"_ctv, rawPlan.config.applicationID, &reserveFailure),
                  "stateless_admission_behavior_v3_reserves_application");
    const auto request = statelessAdmissionBehaviorRequest(sender, uint128_t(0x7a110601), rawPlan, artifact);
    DeploymentPlan normalizedPlan = rawPlan;
    normalizedPlan.config.containerBlobSHA256.assign(request.artifactSHA256);
    normalizedPlan.config.containerBlobBytes = request.artifactBytes;
    const auto record = statelessAdmissionBehaviorRecord(sender, request, normalizedPlan);
    sender.masterAuthorityRuntimeState.statelessDeploymentAdmissions.push_back(record);
    sender.deploymentPlans.insert_or_assign(record.deploymentID, normalizedPlan);
    String serialized = {}, digest = {};
    suite.require(sender.serializeCurrentMasterAuthorityTransition(serialized, digest),
                  "stateless_admission_behavior_v3_serializes_atomic_candidate");
    ProdigyMasterAuthorityStateTransition transition = {};
    suite.require(BitseryEngine::deserializeSafe(serialized, transition) && transition.version == 3 &&
                      transition.statelessAdmissionPlans.size() == 1 &&
                      transition.statelessAdmissionPlans[0].config.containerBlobSHA256.equals(request.artifactSHA256),
                  "stateless_admission_behavior_v3_roundtrips_record_with_normalized_plan");
    if (transition.version != 3 || transition.statelessAdmissionPlans.size() != 1) return;

    StreamingTestBrain receiver = {};
    TestNeuron receiverSelf = {};
    ScopedStatelessAdmissionBehaviorIdentity receiverIdentity(receiver, receiverSelf, uint128_t(0x7a110612));
    NoopBrainIaaS receiverIaaS = {};
    Mothership receiverMothership = {};
    ScopedStatelessAdmissionBehaviorArtifactIO receiverArtifactIO(receiver, receiverMothership);
    receiver.iaas = &receiverIaaS;
    initializeStatelessAdmissionBehaviorFixture(receiver, receiverMothership, sender.brainConfig.clusterUUID);
    receiver.masterAuthorityRuntimeState.generation = 0;
    receiver.masterAuthorityRuntimeStateDurable = true;
    receiver.durableMasterAuthorityRuntimeStateGeneration = 0;
    Brain::PreparedMasterAuthorityTransition prepared = {};
    ProdigyMasterAuthorityStateTransition missingPlan = transition;
    missingPlan.statelessAdmissionPlans.clear();
    suite.expect(!receiver.prepareReplicatedMasterAuthorityTransition(missingPlan, prepared),
                 "stateless_admission_behavior_v3_rejects_missing_normalized_plan");
    ProdigyMasterAuthorityStateTransition mismatchedPlan = transition;
    mismatchedPlan.statelessAdmissionPlans[0].config.versionID += 1;
    suite.expect(!receiver.prepareReplicatedMasterAuthorityTransition(mismatchedPlan, prepared),
                 "stateless_admission_behavior_v3_rejects_mismatched_normalized_plan");
    suite.expect(receiver.applyReplicatedMasterAuthorityTransition(transition, true) &&
                     receiver.deploymentPlans.contains(record.deploymentID) && receiver.deployments.empty() &&
                     receiver.masterAuthorityRuntimeState.statelessDeploymentAdmissions.size() == 1,
                 "stateless_admission_behavior_v3_cold_apply_restores_atomic_receipt_before_blob");
  }

  // A cold package already contains the immutable record and normalized plan.
  // An exact handler retry must reuse that plan and existing none-state owner;
  // it must not replace the object or accept a changed raw request.
  {
    ScopedAsyncMothershipRing ring = {};
    StreamingTestBrain brain = {};
    TestNeuron self = {};
    ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110011));
    NoopBrainIaaS iaas = {};
    Mothership mothership = {};
    ScopedStatelessAdmissionBehaviorArtifactIO artifactIO(brain, mothership);
    brain.iaas = &iaas;
    initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110500));
    suite.require(brain.activateMothershipConnection(&mothership), "stateless_admission_behavior_cold_activates_stream");
    DeploymentPlan rawPlan = statelessAdmissionBehaviorPlan(62'106);
    String reserveFailure = {};
    suite.require(brain.reserveApplicationIDMapping("AdmissionCold"_ctv, rawPlan.config.applicationID, &reserveFailure),
                  "stateless_admission_behavior_cold_reserves_application");
    const auto request = statelessAdmissionBehaviorRequest(brain, uint128_t(0x7a110501), rawPlan, artifact);
    DeploymentPlan normalizedPlan = rawPlan;
    normalizedPlan.config.containerBlobSHA256.assign(request.artifactSHA256);
    normalizedPlan.config.containerBlobBytes = request.artifactBytes;
    const auto record = statelessAdmissionBehaviorRecord(brain, request, normalizedPlan);
    ProdigyPersistentMasterAuthorityPackage package = {};
    package.runtimeState = brain.masterAuthorityRuntimeState;
    package.runtimeState.statelessDeploymentAdmissions.push_back(record);
    package.deploymentPlans.insert_or_assign(record.deploymentID, normalizedPlan);
    package.reservedApplicationIDsByName = brain.reservedApplicationIDsByName;
    package.reservedApplicationNamesByID = brain.reservedApplicationNamesByID;
    package.nextReservableApplicationID = brain.nextReservableApplicationID;
    suite.require(brain.applyPersistentMasterAuthorityPackage(package),
                  "stateless_admission_behavior_cold_applies_durable_package");
    if (!brain.masterAuthorityRuntimeStateDurable) return;
    ApplicationDeployment recovered = {};
    recovered.plan = normalizedPlan;
    recovered.state = DeploymentState::none;
    brain.deployments.insert_or_assign(record.deploymentID, &recovered);
    (void)submitStatelessAdmissionBehaviorRequest(brain, mothership, request, rawPlan, artifact);
    ring.runFor(200);
    suite.expect(brain.deployments.contains(record.deploymentID) && brain.deployments.at(record.deploymentID) == &recovered &&
                     brain.deploymentPlans.at(record.deploymentID).config.containerBlobSHA256.equals(request.artifactSHA256),
                 "stateless_admission_behavior_cold_exact_retry_reuses_original_plan_and_owner");
    DeploymentPlan changedRawPlan = rawPlan;
    changedRawPlan.config.versionID += 1;
    const auto changedRequest = statelessAdmissionBehaviorRequest(brain, request.operationID, changedRawPlan, artifact);
    StatelessDeploymentAdmissionReceipt conflict = {};
    suite.expect(submitStatelessAdmissionBehaviorRequest(brain, mothership, changedRequest, changedRawPlan, artifact, &conflict) &&
                     !conflict.accepted && conflict.failure.size() > 0,
                 "stateless_admission_behavior_cold_rejects_changed_exact_retry");
    brain.deployments.erase(record.deploymentID);
  }

  // A promoted master materializes ordinary deferred plans, but an already
  // durable v8 receipt still needs its exact normalized plan to serialize the
  // v3 authority revision and release ordinary plan/blob replication.  Cover
  // the real promotion path rather than simulating its post-election state.
  {
    char directoryTemplate[] = "/tmp/prodigy-admission-election-XXXXXX";
    char *directory = ::mkdtemp(directoryTemplate);
    suite.require(directory != nullptr,
                  "stateless_admission_behavior_election_creates_private_listener_directory");
    if (directory == nullptr) return;
    String socketPath = {};
    socketPath.assign(directory);
    socketPath.append("/mothership.sock"_ctv);
    const char *previousSocketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
    String previousSocketPathText = {};
    if (previousSocketPath != nullptr) previousSocketPathText.assign(previousSocketPath);
    ::setenv("PRODIGY_MOTHERSHIP_SOCKET", socketPath.c_str(), 1);
    {
      ScopedAsyncMothershipRing ring = {};
      StreamingTestBrain brain = {};
      TestNeuron self = {};
      ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x7a110711));
      NoopBrainIaaS iaas = {};
      Mothership mothership = {};
      ScopedStatelessAdmissionBehaviorArtifactIO artifactIO(brain, mothership);
      brain.iaas = &iaas;
      initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x7a110700));
      DeploymentPlan normalizedPlan = statelessAdmissionBehaviorPlan(62'108);
      String reserveFailure = {};
      suite.require(brain.reserveApplicationIDMapping("AdmissionElection"_ctv,
                                                       normalizedPlan.config.applicationID,
                                                       &reserveFailure),
                    "stateless_admission_behavior_election_reserves_application");
      const auto request = statelessAdmissionBehaviorRequest(brain, uint128_t(0x7a110701), normalizedPlan, artifact);
      normalizedPlan.config.containerBlobSHA256.assign(request.artifactSHA256);
      normalizedPlan.config.containerBlobBytes = request.artifactBytes;
      const auto record = statelessAdmissionBehaviorRecord(brain, request, normalizedPlan);
      brain.masterAuthorityRuntimeState.statelessDeploymentAdmissions.push_back(record);
      brain.deploymentPlans.insert_or_assign(record.deploymentID, normalizedPlan);
      DeploymentPlan ordinaryPlan = statelessAdmissionBehaviorPlan(62'109);
      brain.deploymentPlans.insert_or_assign(ordinaryPlan.config.deploymentID(), ordinaryPlan);
      BrainView peer = {};
      const bool peerReady = addStatelessAdmissionBehaviorAuthenticatedPeer(
          suite, brain, peer, uint128_t(0x7a110712), 0x7a110713);
      if (peerReady)
      {
        brain.weAreMaster = false;
        brain.noMasterYet = true;
        suite.require(brain.selfElectAsMaster("stateless-admission-election"),
                      "stateless_admission_behavior_election_promotes_durable_admission_owner");
        String serialized = {}, digest = {};
        suite.expect(brain.deploymentPlans.size() == 1 && brain.deploymentPlans.contains(record.deploymentID) &&
                         brain.statelessDeploymentAdmissionPlanIsCurrent(record) &&
                         brain.serializeCurrentMasterAuthorityTransition(serialized, digest),
                     "stateless_admission_behavior_election_retains_only_exact_admitted_plan_for_v3");
        suite.expect(!brain.deploymentReplicationAllowedForPeer(record.deploymentID, &peer),
                     "stateless_admission_behavior_election_keeps_blob_fanout_blocked_before_v3_ack");
        acknowledgeStatelessAdmissionBehaviorAuthority(brain, peer);
        suite.expect(brain.deploymentReplicationAllowedForPeer(record.deploymentID, &peer),
                     "stateless_admission_behavior_election_releases_blob_fanout_after_exact_v3_ack");
        brain.brains.erase(&peer);
      }
      brain.deployments.clear();
      brain.deploymentsByApp.clear();
    }
    if (previousSocketPath != nullptr) ::setenv("PRODIGY_MOTHERSHIP_SOCKET", previousSocketPathText.c_str(), 1);
    else ::unsetenv("PRODIGY_MOTHERSHIP_SOCKET");
    ::unlink(socketPath.c_str());
    ::rmdir(directory);
  }
}
