#include <switchboard/pair.control.h>
#include "persistence_fixture.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <utility>
#include <vector>

namespace {

constexpr uint128_t firstClusterUUID = 0x7a01;
constexpr uint128_t secondClusterUUID = 0x7a02;
constexpr uint128_t firstNodeUUID = 0x7b01;
constexpr uint128_t secondNodeUUID = 0x7b02;
constexpr uint16_t controlPort = 15315;
constexpr uint32_t pairControlFanoutWidth = 3;

struct PairProjections {
  ProdigyLocalClusterPairControlProjection first = {};
  ProdigyLocalClusterPairControlProjection second = {};
};

struct PairFanoutProjections {
  std::array<ProdigyLocalClusterPairControlProjection, pairControlFanoutWidth * 2> nodes = {};
};

static ClusterPairControlEndpoint endpoint(uint128_t clusterUUID, uint128_t nodeUUID, const char *address)
{
  ClusterPairControlEndpoint value = {};
  value.clusterUUID = clusterUUID;
  value.nodeUUID = nodeUUID;
  value.role = ClusterPairControlNodeRole::switchboard;
  value.address = IPAddress(address, true);
  value.port = controlPort;
  return value;
}

static bool populateCredential(ProdigyLocalClusterPairControlCredential& credential,
                               const ClusterPairRoot& root,
                               const ClusterPairControlEndpoint& initiator,
                               const ClusterPairControlEndpoint& responder,
                               ClusterPairControlResolver& local,
                               const ClusterPairControlResolver& remote, uint64_t keyEpoch = 11)
{
  std::array<uint8_t, 32> psk = {};
  String context = {};
  uint128_t peerUUID = 0;
  if (!local.resolve(remote.localPublicClaim(), psk, context, peerUUID)) return false;
  credential.pairUUID = root.pairUUID;
  credential.rootGeneration = root.rootGeneration;
  credential.keyEpoch = keyEpoch;
  credential.initiator = initiator;
  credential.responder = responder;
  credential.localClaim = local.localPublicClaim();
  credential.remoteClaim = remote.localPublicClaim();
  credential.canonicalContext = std::move(context);
  std::memcpy(credential.psk, psk.data(), psk.size());
  return peerUUID != 0;
}

static bool buildComplementaryProjections(PairProjections& output, uint64_t committedGeneration,
                                          bool corruptInitiatorPSK = false)
{
  output = {};
  ClusterPairRoot root = {};
  root.pairUUID = 0x7c01;
  root.firstClusterUUID = firstClusterUUID;
  root.secondClusterUUID = secondClusterUUID;
  root.rootGeneration = 5;
  for (uint32_t index = 0; index < root.root.size(); ++index) root.root[index] = uint8_t(index + 1);

  const auto initiator = endpoint(firstClusterUUID, firstNodeUUID, "fd00:ffff:1234::1");
  const auto responder = endpoint(secondClusterUUID, secondNodeUUID, "fd00:ffff:1234::2");
  ClusterPairControlResolver firstResolver = {}, secondResolver = {};
  if (!clusterPairPrepareControlResolver(root, initiator, responder, initiator, responder, 11,
                                         "pair-control-ring-unit"_ctv, firstResolver) ||
      !clusterPairPrepareControlResolver(root, initiator, responder, responder, initiator, 11,
                                         "pair-control-ring-unit"_ctv, secondResolver)) return false;

  output.first.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
  output.first.localClusterUUID = firstClusterUUID;
  output.first.nodeUUID = firstNodeUUID;
  output.first.committedAuthorityGeneration = committedGeneration;
  output.second.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
  output.second.localClusterUUID = secondClusterUUID;
  output.second.nodeUUID = secondNodeUUID;
  output.second.committedAuthorityGeneration = committedGeneration;

  ProdigyLocalClusterPairControlCredential firstCredential = {}, secondCredential = {};
  if (!populateCredential(firstCredential, root, initiator, responder, firstResolver, secondResolver) ||
      !populateCredential(secondCredential, root, initiator, responder, secondResolver, firstResolver)) return false;
  if (corruptInitiatorPSK) firstCredential.psk[0] ^= 0x80;
  output.first.credentials.push_back(std::move(firstCredential));
  output.second.credentials.push_back(std::move(secondCredential));
  return prodigyLocalClusterPairControlProjectionValid(output.first, true) &&
      prodigyLocalClusterPairControlProjectionValid(output.second, true);
}

static ProdigyCousinDiscoveryPublication buildDiscoveryPublication(uint128_t nodeUUID,
                                                                  uint128_t sourceClusterUUID,
                                                                  uint128_t peerClusterUUID,
                                                                  uint128_t pairUUID,
                                                                  uint64_t rootGeneration,
                                                                  uint64_t keyEpoch,
                                                                  uint64_t projectionGeneration)
{
  ProdigyCousinDiscoveryPublication publication = {};
  publication.nodeUUID = nodeUUID;
  publication.projectionGeneration = projectionGeneration;
  auto& snapshot = publication.snapshot;
  snapshot.pairUUID = pairUUID;
  snapshot.sourceClusterUUID = sourceClusterUUID;
  snapshot.peerClusterUUID = peerClusterUUID;
  snapshot.rootGeneration = rootGeneration;
  snapshot.keyEpoch = keyEpoch;
  snapshot.authorityGeneration = projectionGeneration;
  ProdigyCousinCounterpart counterpart = {};
  counterpart.permission.permissionUUID = 0x7e01;
  counterpart.permission.pairUUID = pairUUID;
  counterpart.permission.logicalWorkloadUUID = 0x7e02;
  counterpart.permission.logicalServiceUUID = 0x7e03;
  counterpart.permission.localClusterUUID = sourceClusterUUID;
  counterpart.permission.peerClusterUUID = peerClusterUUID;
  counterpart.permission.localHalf = CousinRouteHalf::destination;
  counterpart.permission.localApplicationID = 7;
  counterpart.permission.peerApplicationID = 19;
  counterpart.permission.localCousinServicePrefix = MeshServices::generateStatefulService(7, 3);
  counterpart.permission.peerCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
  counterpart.permission.slots.insert(3);
  counterpart.permission.localDeploymentID = 0x7000000000001;
  for (uint32_t index = 0; index < 64; ++index) {
    counterpart.permission.canonicalPlanSHA256.append('a'); counterpart.permission.artifactSHA256.append('b');
  }
  counterpart.permission.artifactBytes = 1;
  counterpart.permission.generation = 1;
  counterpart.permission.acceptedAuthorityGeneration = projectionGeneration;
  counterpart.permission.state = ProdigyLocalCousinServicePermissionState::active;
  counterpart.containerUUID = 0x7e04;
  counterpart.nodeUUID = nodeUUID;
  counterpart.containerID = 9;
  counterpart.shardGroups = 2;
  counterpart.shardGroup = statefulServiceGroupOwnerForSlot(3, counterpart.shardGroups);
  counterpart.service = MeshServices::constrainPrefixToGroup(counterpart.permission.localCousinServicePrefix,
                                                               counterpart.shardGroup);
  counterpart.servicePort = 9443;
  for (uint16_t slot = 0; slot < nStatefulServiceGroupSlots; ++slot)
    if (counterpart.permission.slots.contains(slot) &&
        statefulServiceGroupOwnerForSlot(slot, counterpart.shardGroups) == counterpart.shardGroup)
      counterpart.ownedSlots.insert(slot);
  counterpart.routablePrefixUUID = 0x7e05;
  counterpart.publicAddress = IPAddress("fd00:ffff:1234::7", true);
  counterpart.publicTCPPort = 8443;
  for (uint32_t index = 0; index < 64; ++index) counterpart.wormholeRevision.append('c');
  snapshot.records.push_back(std::move(counterpart));
  return publication;
}

static ProdigyCousinSessionControl buildSessionControl(const ProdigyCousinCounterpart& destination,
                                                       uint64_t rootGeneration, uint64_t keyEpoch)
{
  ProdigyCousinSessionControl control = {};
  control.kind = ProdigyCousinSessionControlKind::propose;
  auto& session = control.session;
  session.sessionUUID = 0x7f01; session.requestUUID = 0x7f02;
  session.rootGeneration = rootGeneration; session.keyEpoch = keyEpoch; session.slot = 3;
  session.destination = destination;
  session.sourcePermission = destination.permission;
  session.sourcePermission.permissionUUID = 0x7f03;
  session.sourcePermission.localHalf = CousinRouteHalf::source;
  std::swap(session.sourcePermission.localClusterUUID, session.sourcePermission.peerClusterUUID);
  std::swap(session.sourcePermission.localApplicationID, session.sourcePermission.peerApplicationID);
  std::swap(session.sourcePermission.localCousinServicePrefix, session.sourcePermission.peerCousinServicePrefix);
  session.sourcePermission.localDeploymentID = uint64_t(session.sourcePermission.localApplicationID) << 48 | 1;
  session.sourceContainerUUID = 0x7f04; session.sourceNodeUUID = firstNodeUUID; session.sourceContainerID = 0x01020304;
  session.sourceShardGroups = 2; session.sourceShardGroup = statefulServiceGroupOwnerForSlot(3, 2);
  session.sourceService = MeshServices::constrainPrefixToGroup(session.sourcePermission.localCousinServicePrefix,
                                                                 session.sourceShardGroup);
  session.sourceBindingNonce = 1; session.sourceAddress = IPAddress("fd00:ffff:1234::1", true); session.sourceTCPPort = 40001;
  return control;
}

static bool appendComplementaryEpoch(PairProjections& output, uint64_t keyEpoch)
{
  ClusterPairRoot root = {};
  root.pairUUID = 0x7c01;
  root.firstClusterUUID = firstClusterUUID;
  root.secondClusterUUID = secondClusterUUID;
  root.rootGeneration = 5;
  for (uint32_t index = 0; index < root.root.size(); ++index) root.root[index] = uint8_t(index + 1);
  const auto initiator = endpoint(firstClusterUUID, firstNodeUUID, "fd00:ffff:1234::1");
  const auto responder = endpoint(secondClusterUUID, secondNodeUUID, "fd00:ffff:1234::2");
  ClusterPairControlResolver firstResolver = {}, secondResolver = {};
  if (!clusterPairPrepareControlResolver(root, initiator, responder, initiator, responder, keyEpoch,
                                         "pair-control-ring-unit"_ctv, firstResolver) ||
      !clusterPairPrepareControlResolver(root, initiator, responder, responder, initiator, keyEpoch,
                                         "pair-control-ring-unit"_ctv, secondResolver)) return false;
  ProdigyLocalClusterPairControlCredential firstCredential = {}, secondCredential = {};
  if (!populateCredential(firstCredential, root, initiator, responder, firstResolver, secondResolver, keyEpoch) ||
      !populateCredential(secondCredential, root, initiator, responder, secondResolver, firstResolver, keyEpoch)) return false;
  output.first.credentials.push_back(std::move(firstCredential));
  output.second.credentials.push_back(std::move(secondCredential));
  return true;
}

static bool buildThreeByThreeFanout(PairFanoutProjections& output, uint64_t committedGeneration)
{
  output = {};
  ClusterPairRoot root = {};
  root.pairUUID = 0x7c02;
  root.firstClusterUUID = firstClusterUUID;
  root.secondClusterUUID = secondClusterUUID;
  root.rootGeneration = 5;
  for (uint32_t index = 0; index < root.root.size(); ++index) root.root[index] = uint8_t(index + 17);

  const std::array<ClusterPairControlEndpoint, pairControlFanoutWidth> initiators = {
      endpoint(firstClusterUUID, firstNodeUUID + 0, "fd00:ffff:1234::1"),
      endpoint(firstClusterUUID, firstNodeUUID + 1, "fd00:ffff:1234::2"),
      endpoint(firstClusterUUID, firstNodeUUID + 2, "fd00:ffff:1234::3")};
  const std::array<ClusterPairControlEndpoint, pairControlFanoutWidth> responders = {
      endpoint(secondClusterUUID, secondNodeUUID + 0, "fd00:ffff:1234::4"),
      endpoint(secondClusterUUID, secondNodeUUID + 1, "fd00:ffff:1234::5"),
      endpoint(secondClusterUUID, secondNodeUUID + 2, "fd00:ffff:1234::6")};

  for (uint32_t index = 0; index < pairControlFanoutWidth; ++index)
  {
    auto& initiatorProjection = output.nodes[index];
    initiatorProjection.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
    initiatorProjection.localClusterUUID = firstClusterUUID;
    initiatorProjection.nodeUUID = initiators[index].nodeUUID;
    initiatorProjection.committedAuthorityGeneration = committedGeneration;

    auto& responderProjection = output.nodes[pairControlFanoutWidth + index];
    responderProjection.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
    responderProjection.localClusterUUID = secondClusterUUID;
    responderProjection.nodeUUID = responders[index].nodeUUID;
    responderProjection.committedAuthorityGeneration = committedGeneration;
  }

  for (uint32_t initiatorIndex = 0; initiatorIndex < pairControlFanoutWidth; ++initiatorIndex)
  {
    for (uint32_t responderIndex = 0; responderIndex < pairControlFanoutWidth; ++responderIndex)
    {
      ClusterPairControlResolver initiatorResolver = {}, responderResolver = {};
      if (!clusterPairPrepareControlResolver(root, initiators[initiatorIndex], responders[responderIndex],
                                             initiators[initiatorIndex], responders[responderIndex], 11,
                                             "pair-control-ring-fanout"_ctv, initiatorResolver) ||
          !clusterPairPrepareControlResolver(root, initiators[initiatorIndex], responders[responderIndex],
                                             responders[responderIndex], initiators[initiatorIndex], 11,
                                             "pair-control-ring-fanout"_ctv, responderResolver))
      {
        return false;
      }

      ProdigyLocalClusterPairControlCredential initiatorCredential = {}, responderCredential = {};
      if (!populateCredential(initiatorCredential, root, initiators[initiatorIndex], responders[responderIndex],
                              initiatorResolver, responderResolver) ||
          !populateCredential(responderCredential, root, initiators[initiatorIndex], responders[responderIndex],
                              responderResolver, initiatorResolver))
      {
        return false;
      }
      output.nodes[initiatorIndex].credentials.push_back(std::move(initiatorCredential));
      output.nodes[pairControlFanoutWidth + responderIndex].credentials.push_back(std::move(responderCredential));
    }
  }

  for (const auto& projection : output.nodes)
    if (!prodigyLocalClusterPairControlProjectionValid(projection, true)) return false;
  return true;
}

static bool addEpochStatus(ProdigyLocalClusterPairControlProjection& projection,
                           uint128_t peerClusterUUID, uint64_t authorityGeneration,
                           ProdigyClusterPairEpochPhase phase = ProdigyClusterPairEpochPhase::prepared)
{
  ProdigyClusterPairEpochStatus status = {};
  status.protocolVersion = ProdigyClusterPairEpochProtocolVersion;
  status.pairUUID = projection.credentials[0].pairUUID;
  status.rootGeneration = projection.credentials[0].rootGeneration;
  status.sourceClusterUUID = projection.localClusterUUID;
  status.peerClusterUUID = peerClusterUUID;
  status.agreedKeyEpoch = projection.credentials[0].keyEpoch;
  status.agreementUUID = 0x7d01;
  status.oldEpoch = projection.credentials[0].keyEpoch;
  status.nextEpoch = status.oldEpoch + 1;
  status.phase = phase;
  status.authorityGeneration = authorityGeneration;
  if (phase == ProdigyClusterPairEpochPhase::committed || phase == ProdigyClusterPairEpochPhase::complete)
  {
    status.agreedKeyEpoch = status.nextEpoch;
    status.committedAgreementUUID = status.agreementUUID;
  }
  if (!prodigyClusterPairEpochAgreementDigest(status.pairUUID, status.rootGeneration, status.sourceClusterUUID,
      status.peerClusterUUID, status.agreementUUID, status.oldEpoch, status.nextEpoch, status.agreementDigest)) return false;
  projection.epochStatuses.push_back(std::move(status));
  return true;
}

static ProdigyLocalClusterPairControlProjection revokedProjection(const ProdigyLocalClusterPairControlProjection& current,
                                                                   uint64_t generation)
{
  ProdigyLocalClusterPairControlProjection revoked = {};
  revoked.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
  revoked.localClusterUUID = current.localClusterUUID;
  revoked.nodeUUID = current.nodeUUID;
  revoked.committedAuthorityGeneration = generation;
  return revoked;
}

static bool runUntil(PersistenceRing& ring, const std::function<bool()>& done, uint64_t timeoutMs)
{
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  bool timedOut = false;
  Ring::exit = false;
  ring.tickAction = [&] {
    if (done()) { Ring::exit = true; return; }
    if (std::chrono::steady_clock::now() >= deadline) { timedOut = true; Ring::exit = true; return; }
    ring.armTick(5);
  };
  ring.armTick(1);
  Ring::start();
  ring.tickAction = {};
  Ring::exit = false;
  return !timedOut && done();
}

static bool runFor(PersistenceRing& ring, uint64_t durationMs)
{
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(durationMs);
  Ring::exit = false;
  ring.tickAction = [&] {
    if (std::chrono::steady_clock::now() >= deadline) { Ring::exit = true; return; }
    ring.armTick(5);
  };
  ring.armTick(1);
  Ring::start();
  ring.tickAction = {};
  Ring::exit = false;
  return std::chrono::steady_clock::now() >= deadline;
}

static bool quiescePair(PersistenceRing& ring, SwitchboardPairControlRuntime& first,
                        SwitchboardPairControlRuntime& second)
{
  return runUntil(ring, [&] { return first.quiesce() && second.quiesce(); }, 3000);
}

static bool quiesceFanout(PersistenceRing& ring,
                          std::array<SwitchboardPairControlRuntime, pairControlFanoutWidth * 2>& runtimes)
{
  return runUntil(ring, [&] {
    bool quiesced = true;
    for (auto& runtime : runtimes) quiesced = runtime.quiesce() && quiesced;
    return quiesced;
  }, 3000);
}

static void pairControlCarrierReadyAndGenerationAdvance(TestSuite& suite)
{
  PersistenceRing ring;
  PairProjections initial = {};
  suite.expect(buildComplementaryProjections(initial, 1), "pair_control_ring_builds_complementary_projections");
  SwitchboardPairControlRuntime first = {}, second = {};
  const bool installed = first.installProjection(initial.first) && second.installProjection(initial.second);
  suite.expect(installed && first.start() && second.start(), "pair_control_ring_starts_complementary_carriers");
  const bool ready = installed && runUntil(ring, [&] { return first.readyCount() == 1 && second.readyCount() == 1; }, 6000);
  suite.expect(ready, "pair_control_ring_both_sides_ready_after_authenticated_hello");

  PairProjections advanced = {};
  const bool advancePrepared = buildComplementaryProjections(advanced, 2);
  const bool advancedInstalled = advancePrepared && first.installProjection(advanced.first) && second.installProjection(advanced.second);
  suite.expect(advancedInstalled && first.readyCount() == 1 && second.readyCount() == 1,
               "pair_control_ring_generation_only_advance_preserves_connection");
  suite.expect(advancedInstalled && runFor(ring, 1500) && first.readyCount() == 1 && second.readyCount() == 1,
               "pair_control_ring_generation_only_advance_survives_next_reconcile");
  suite.expect(quiescePair(ring, first, second), "pair_control_ring_generation_scenario_quiesces_before_destruction");
}

static void pairControlCarrierRevocationDropsReadinessAndDrains(TestSuite& suite)
{
  PersistenceRing ring;
  PairProjections initial = {};
  suite.expect(buildComplementaryProjections(initial, 1), "pair_control_ring_builds_revocation_fixture");
  SwitchboardPairControlRuntime first = {}, second = {};
  const bool installed = first.installProjection(initial.first) && second.installProjection(initial.second);
  suite.expect(installed && first.start() && second.start(), "pair_control_ring_starts_revocation_fixture");
  suite.expect(installed && runUntil(ring, [&] { return first.readyCount() == 1 && second.readyCount() == 1; }, 6000),
               "pair_control_ring_revocation_fixture_reaches_ready");

  const auto firstRevoked = revokedProjection(initial.first, 2);
  const auto secondRevoked = revokedProjection(initial.second, 2);
  const bool revoked = first.installProjection(firstRevoked) && second.installProjection(secondRevoked);
  suite.expect(revoked && first.readyCount() == 0 && second.readyCount() == 0,
               "pair_control_ring_revocation_immediately_clears_ready");
  suite.expect(quiescePair(ring, first, second), "pair_control_ring_revocation_drains_before_destruction");
}

static void pairControlCarrierRejectsWrongPSK(TestSuite& suite)
{
  PersistenceRing ring;
  PairProjections projections = {};
  suite.expect(buildComplementaryProjections(projections, 1, true), "pair_control_ring_builds_wrong_psk_fixture");
  SwitchboardPairControlRuntime first = {}, second = {};
  const bool installed = first.installProjection(projections.first) && second.installProjection(projections.second);
  suite.expect(installed && first.start() && second.start(), "pair_control_ring_starts_wrong_psk_fixture");
  suite.expect(installed && runFor(ring, 3000) && first.readyCount() == 0 && second.readyCount() == 0,
               "pair_control_ring_wrong_psk_never_becomes_ready_before_deadline");
  suite.expect(quiescePair(ring, first, second), "pair_control_ring_wrong_psk_drains_before_destruction");
}

static void pairControlCarrierTransfersExactEpochStatus(TestSuite& suite)
{
  PersistenceRing ring;
  PairProjections projections = {};
  const bool built = buildComplementaryProjections(projections, 7) &&
      addEpochStatus(projections.first, secondClusterUUID, 7) &&
      addEpochStatus(projections.second, firstClusterUUID, 7);
  suite.expect(built && prodigyLocalClusterPairControlProjectionValid(projections.first, true) &&
      prodigyLocalClusterPairControlProjectionValid(projections.second, true),
      "pair_control_ring_builds_valid_prepared_epoch_status_projections");

  SwitchboardPairControlRuntime first = {}, second = {};
  std::vector<ProdigyClusterPairEpochReceipt> firstReceipts = {}, secondReceipts = {};
  first.onEpochStatus = [&](const ProdigyClusterPairEpochReceipt& receipt) { firstReceipts.push_back(receipt); };
  second.onEpochStatus = [&](const ProdigyClusterPairEpochReceipt& receipt) { secondReceipts.push_back(receipt); };
  const bool installed = built && first.installProjection(projections.first) && second.installProjection(projections.second);
  suite.expect(installed && first.start() && second.start(), "pair_control_ring_starts_epoch_status_carriers");
  const bool transferred = installed && runUntil(ring, [&] {
    return first.readyCount() == 1 && second.readyCount() == 1 && !firstReceipts.empty() && !secondReceipts.empty();
  }, 6000);
  const auto exactReceipt = [&](const std::vector<ProdigyClusterPairEpochReceipt>& receipts,
                                uint128_t localClusterUUID, uint128_t remoteClusterUUID) {
    return !receipts.empty() && receipts[0].localEndpoint.clusterUUID == localClusterUUID &&
        receipts[0].remoteEndpoint.clusterUUID == remoteClusterUUID && receipts[0].wireEpoch == 11 &&
        receipts[0].projectionGeneration == 7 && receipts[0].status.phase == ProdigyClusterPairEpochPhase::prepared &&
        receipts[0].status.sourceClusterUUID == remoteClusterUUID && receipts[0].status.peerClusterUUID == localClusterUUID;
  };
  suite.expect(transferred && exactReceipt(firstReceipts, firstClusterUUID, secondClusterUUID) &&
      exactReceipt(secondReceipts, secondClusterUUID, firstClusterUUID),
      "pair_control_ring_forwards_only_exact_authenticated_epoch_receipts");

  PairProjections malformed = {};
  const bool malformedBuilt = buildComplementaryProjections(malformed, 7) &&
      addEpochStatus(malformed.first, secondClusterUUID, 7);
  if (malformedBuilt) malformed.first.epochStatuses[0].peerClusterUUID = 0xdead;
  suite.expect(malformedBuilt && !prodigyLocalClusterPairControlProjectionValid(malformed.first, true),
      "pair_control_ring_rejects_epoch_status_with_unapproved_peer_binding");
  suite.expect(quiescePair(ring, first, second), "pair_control_ring_epoch_status_scenario_quiesces_before_destruction");
}

static void pairControlCarrierReadyStatusUsesBothOverlapEpochs(TestSuite& suite)
{
  // Dual epochs need one listener and both outbound/inbound socket pairs;
  // use the existing spacious Ring fixture rather than the default unit slot
  // budget, which is deliberately sized for one credential pair.
  PersistenceRing ring(64, 32);
  PairProjections projections = {};
  const bool built = buildComplementaryProjections(projections, 8) && appendComplementaryEpoch(projections, 12) &&
      addEpochStatus(projections.first, secondClusterUUID, 8, ProdigyClusterPairEpochPhase::ready) &&
      addEpochStatus(projections.second, firstClusterUUID, 8, ProdigyClusterPairEpochPhase::ready);
  suite.expect(built && prodigyLocalClusterPairControlProjectionValid(projections.first, true) &&
      prodigyLocalClusterPairControlProjectionValid(projections.second, true),
      "pair_control_ring_builds_exact_ready_dual_epoch_overlap");
  SwitchboardPairControlRuntime first = {}, second = {};
  std::vector<ProdigyClusterPairEpochReceipt> firstReceipts = {}, secondReceipts = {};
  first.onEpochStatus = [&](const ProdigyClusterPairEpochReceipt& receipt) { firstReceipts.push_back(receipt); };
  second.onEpochStatus = [&](const ProdigyClusterPairEpochReceipt& receipt) { secondReceipts.push_back(receipt); };
  const bool installed = built && first.installProjection(projections.first) && second.installProjection(projections.second);
  suite.expect(installed && first.start() && second.start(), "pair_control_ring_starts_ready_dual_epoch_overlap");
  const auto sawBothEpochs = [](const std::vector<ProdigyClusterPairEpochReceipt>& receipts) {
    bool oldEpoch = false, nextEpoch = false;
    for (const auto& receipt : receipts)
    {
      oldEpoch = oldEpoch || receipt.wireEpoch == 11;
      nextEpoch = nextEpoch || receipt.wireEpoch == 12;
    }
    return oldEpoch && nextEpoch;
  };
  const bool transferred = installed && runUntil(ring, [&] {
    return first.readyCount() == 2 && second.readyCount() == 2 && sawBothEpochs(firstReceipts) && sawBothEpochs(secondReceipts);
  }, 6000);
  suite.expect(transferred, "pair_control_ring_ready_status_is_accepted_on_old_and_next_overlap_epochs");
  suite.expect(quiescePair(ring, first, second), "pair_control_ring_ready_overlap_quiesces_before_destruction");
}

static void pairControlCarrierTransfersAndWithdrawsDiscovery(TestSuite& suite)
{
  PersistenceRing ring(64, 32);
  PairProjections projections = {};
  const bool built = buildComplementaryProjections(projections, 1);
  SwitchboardPairControlRuntime first = {}, second = {};
  std::vector<ProdigyCousinDiscoveryReceipt> receipts = {}, reverseReceipts = {};
  second.onDiscoverySnapshot = [&](const ProdigyCousinDiscoveryReceipt& receipt) { receipts.push_back(receipt); };
  first.onDiscoverySnapshot = [&](const ProdigyCousinDiscoveryReceipt& receipt) { reverseReceipts.push_back(receipt); };
  const bool installed = built && first.installProjection(projections.first) && second.installProjection(projections.second);
  suite.expect(installed && first.start() && second.start(), "pair_control_ring_starts_discovery_carriers");
  const bool ready = installed && runUntil(ring, [&] { return first.readyCount() == 1 && second.readyCount() == 1; }, 6000);
  const bool hasCredential = !projections.first.credentials.empty();
  const ProdigyLocalClusterPairControlCredential credential = hasCredential ?
      projections.first.credentials[0] : ProdigyLocalClusterPairControlCredential {};
  auto publication = buildDiscoveryPublication(firstNodeUUID, firstClusterUUID, secondClusterUUID,
      credential.pairUUID, credential.rootGeneration, credential.keyEpoch, 1);
  publication.snapshot.authorityGeneration = 2;
  if (!publication.snapshot.records.empty())
    publication.snapshot.records.front().permission.acceptedAuthorityGeneration = 2;
  const bool publicationValid = hasCredential && prodigyCousinDiscoveryPublicationValid(publication);
  const bool publicationInstalled = ready && publicationValid && first.installDiscoverySnapshot(publication);
  suite.expect(publicationValid,
               "pair_control_ring_builds_structurally_valid_local_discovery_publication");
  suite.expect(publicationInstalled,
               "pair_control_ring_installs_current_local_discovery_publication");
  const bool received = publicationInstalled && runUntil(ring, [&] { return receipts.size() == 1 && !receipts[0].withdrawn; }, 6000);
  suite.expect(received && receipts[0].connectionID != 0 && receipts[0].sequence != 0 &&
                    receipts[0].projectionGeneration == 1 && receipts[0].snapshot.authorityGeneration == 2 &&
                    receipts[0].snapshot.records.size() == 1 &&
                    receipts[0].snapshot.sourceClusterUUID == firstClusterUUID,
               "pair_control_ring_receives_exact_authenticated_discovery_snapshot");
  auto withdrawn = publication;
  withdrawn.snapshot.records.clear();
  suite.expect(received && first.installDiscoverySnapshot(withdrawn),
               "pair_control_ring_accepts_full_empty_discovery_replacement");
  const bool withdrew = received && runUntil(ring, [&] { return receipts.size() >= 2 && receipts.back().withdrawn; }, 6000);
  suite.expect(withdrew && receipts.back().connectionID == receipts.front().connectionID &&
                    receipts.back().sequence > receipts.front().sequence,
               "pair_control_ring_binds_empty_withdrawal_to_same_connection_and_sequence");
  const auto reversePublication = buildDiscoveryPublication(secondNodeUUID, secondClusterUUID, firstClusterUUID,
      credential.pairUUID, credential.rootGeneration, credential.keyEpoch, 1);
  suite.expect(withdrew && second.installDiscoverySnapshot(reversePublication),
               "pair_control_ring_accepts_responder_owned_discovery_publication");
  const bool reverseReceived = withdrew && runUntil(ring, [&] {
    return reverseReceipts.size() == 1 && !reverseReceipts[0].withdrawn;
  }, 6000);
  suite.expect(reverseReceived && reverseReceipts[0].snapshot.sourceClusterUUID == secondClusterUUID,
               "pair_control_ring_transfers_responder_to_initiator_discovery_snapshot");
  const uint64_t reverseConnectionID = reverseReceipts.empty() ? 0 : reverseReceipts[0].connectionID;
  const bool expired = reverseReceived && runUntil(ring, [&] {
    return reverseReceipts.size() >= 2 && reverseReceipts.back().withdrawn;
  }, ProdigyCousinDiscoveryMaximumAgeMs + 3000);
  suite.expect(expired && reverseReceipts.back().connectionID == reverseConnectionID,
               "pair_control_ring_local_publication_expiry_withdraws_remote_snapshot_within_bounded_ttl");
  suite.expect(expired && second.installDiscoverySnapshot(reversePublication),
               "pair_control_ring_reinstalls_fresh_publication_after_local_expiry");
  const bool reinstalled = expired && runUntil(ring, [&] {
    return reverseReceipts.size() >= 3 && !reverseReceipts.back().withdrawn;
  }, 6000);
  const bool disconnected = reinstalled && first.installProjection(revokedProjection(projections.first, 2));
  suite.expect(disconnected && reverseReceipts.back().withdrawn &&
                    reverseReceipts.back().connectionID == reverseConnectionID,
               "pair_control_ring_projection_disconnect_invalidates_remote_discovery_by_exact_connection");
  suite.expect(quiescePair(ring, first, second), "pair_control_ring_discovery_scenario_quiesces_before_destruction");
}

static void pairControlCarrierTransfersSessionControl(TestSuite& suite)
{
  PersistenceRing ring(64, 32); PairProjections projections = {};
  SwitchboardPairControlRuntime first = {}, second = {};
  std::vector<ProdigyCousinSessionReceipt> receipts = {};
  std::vector<ProdigyCousinDiscoveryReceipt> discoveryReceipts = {};
  first.onDiscoverySnapshot = [&](const ProdigyCousinDiscoveryReceipt& receipt) { discoveryReceipts.push_back(receipt); };
  second.onSessionControl = [&](const ProdigyCousinSessionReceipt& receipt) { receipts.push_back(receipt); };
  const bool installed = buildComplementaryProjections(projections, 1) &&
      first.installProjection(projections.first) && second.installProjection(projections.second);
  suite.expect(installed && first.start() && second.start(), "pair_control_ring_starts_session_control_carriers");
  const bool ready = installed && runUntil(ring, [&] { return first.readyCount() == 1 && second.readyCount() == 1; }, 6000);
  const auto publication = buildDiscoveryPublication(secondNodeUUID, secondClusterUUID, firstClusterUUID,
      projections.first.credentials[0].pairUUID, projections.first.credentials[0].rootGeneration,
      projections.first.credentials[0].keyEpoch, 1);
  const bool discovered = ready && second.installDiscoverySnapshot(publication) && runUntil(ring, [&] {
    return !discoveryReceipts.empty() && !discoveryReceipts.back().withdrawn;
  }, 6000);
  suite.expect(discovered, "pair_control_ring_observes_actual_session_carrier_connection");
  ProdigyCousinSessionPublication outbound = {};
  outbound.nodeUUID = firstNodeUUID; outbound.projectionGeneration = 1;
  outbound.connectionID = discovered ? discoveryReceipts.back().connectionID : 0;
  outbound.localEndpoint = projections.first.credentials[0].initiator;
  outbound.remoteEndpoint = projections.first.credentials[0].responder;
  outbound.control = buildSessionControl(publication.snapshot.records[0],
                                         projections.first.credentials[0].rootGeneration,
                                         projections.first.credentials[0].keyEpoch);
  const bool queued = discovered && prodigyCousinSessionPublicationValid(outbound) && first.sendSessionControl(outbound);
  const bool received = queued && runUntil(ring, [&] { return receipts.size() == 1; }, 6000);
  suite.expect(received && !receipts[0].disconnected && receipts[0].sequence == 1 &&
                   receipts[0].control.kind == ProdigyCousinSessionControlKind::propose,
               "pair_control_ring_transfers_exact_authenticated_session_control");
  auto staleConnection = outbound; staleConnection.connectionID = outbound.connectionID + 1;
  suite.expect(!first.sendSessionControl(staleConnection), "pair_control_ring_rejects_stale_session_publication_connection_fence");
  const bool disconnected = received && first.installProjection(revokedProjection(projections.first, 2));
  suite.expect(disconnected && runUntil(ring, [&] { return !receipts.empty() && receipts.back().disconnected; }, 6000),
               "pair_control_ring_emits_session_disconnect_receipt");
  suite.expect(quiescePair(ring, first, second), "pair_control_ring_session_control_quiesces_before_destruction");
}

static void pairControlCarrierThreeByThreeFanout(TestSuite& suite)
{
  // Nine initiating sockets plus three listeners, and nine accepted sockets.
  PersistenceRing ring(64, 32);
  PairFanoutProjections projections = {};
  std::array<SwitchboardPairControlRuntime, pairControlFanoutWidth * 2> runtimes = {};
  const bool built = buildThreeByThreeFanout(projections, 1);
  suite.expect(built, "pair_control_ring_3x3_builds_nine_complementary_credentials");

  bool installed = built;
  for (uint32_t index = 0; index < runtimes.size(); ++index)
    installed = runtimes[index].installProjection(projections.nodes[index]) && installed;

  bool initiatorsStarted = installed;
  for (uint32_t index = 0; index < pairControlFanoutWidth; ++index)
    initiatorsStarted = runtimes[index].start() && initiatorsStarted;
  const bool initialReconnectWindow = initiatorsStarted && runFor(ring, 1500);

  bool respondersStarted = installed;
  for (uint32_t index = pairControlFanoutWidth; index < runtimes.size(); ++index)
    respondersStarted = runtimes[index].start() && respondersStarted;
  const bool started = initiatorsStarted && respondersStarted;
  suite.expect(installed && initialReconnectWindow && started,
               "pair_control_ring_3x3_retries_initiators_before_starting_three_responders");

  // The deliberately unavailable-responder window consumes 1.5 seconds of
  // the six-second bounded case deadline.
  const bool ready = installed && initialReconnectWindow && started && runUntil(ring, [&] {
    return std::all_of(runtimes.begin(), runtimes.end(), [](const auto& runtime) {
      return runtime.readyCount() == pairControlFanoutWidth;
    });
  }, 4500);
  suite.expect(ready, "pair_control_ring_3x3_reaches_three_ready_peers_per_carrier_within_six_seconds");

  // Always drain every started owner before array destruction, including after
  // a failed readiness assertion.  The Ring owns close CQE completion.
  suite.expect(quiesceFanout(ring, runtimes), "pair_control_ring_3x3_quiesces_all_six_carriers");
}

} // namespace

int main()
{
  const char *enabled = std::getenv("PRODIGY_TEST_PAIR_CONTROL_RING");
  if (enabled == nullptr || std::strcmp(enabled, "1") != 0) return 77;

  TestSuite suite = {};
  const char *selection = std::getenv("PRODIGY_TEST_ONLY");
  if (selection != nullptr && std::strcmp(selection, "cousin-session") == 0) {
    pairControlCarrierTransfersSessionControl(suite);
    return suite.failed == 0 ? 0 : 1;
  }
  pairControlCarrierReadyAndGenerationAdvance(suite);
  pairControlCarrierRevocationDropsReadinessAndDrains(suite);
  pairControlCarrierRejectsWrongPSK(suite);
  pairControlCarrierTransfersExactEpochStatus(suite);
  pairControlCarrierReadyStatusUsesBothOverlapEpochs(suite);
  pairControlCarrierTransfersAndWithdrawsDiscovery(suite);
  pairControlCarrierThreeByThreeFanout(suite);
  return suite.failed == 0 ? 0 : 1;
}
