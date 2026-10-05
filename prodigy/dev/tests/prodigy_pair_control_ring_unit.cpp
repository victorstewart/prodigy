#include <switchboard/pair.control.h>
#include "persistence_fixture.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <utility>

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
                               const ClusterPairControlResolver& remote)
{
  std::array<uint8_t, 32> psk = {};
  String context = {};
  uint128_t peerUUID = 0;
  if (!local.resolve(remote.localPublicClaim(), psk, context, peerUUID)) return false;
  credential.pairUUID = root.pairUUID;
  credential.rootGeneration = root.rootGeneration;
  credential.keyEpoch = 11;
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
  pairControlCarrierReadyAndGenerationAdvance(suite);
  pairControlCarrierRevocationDropsReadinessAndDrains(suite);
  pairControlCarrierRejectsWrongPSK(suite);
  pairControlCarrierThreeByThreeFanout(suite);
  return suite.failed == 0 ? 0 : 1;
}
