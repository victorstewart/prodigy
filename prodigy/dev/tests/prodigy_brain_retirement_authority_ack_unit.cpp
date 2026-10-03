#include <prodigy/prodigy.h>
#include <prodigy/brain/brain.h>

#include <cstdio>
#include <functional>
#include <sys/socket.h>
#include <unistd.h>

class Suite {
public:
  int failed = 0;

  void expect(bool value, const char *name)
  {
    std::fprintf(value ? stdout : stderr, "%s: %s\n", value ? "PASS" : "FAIL", name);
    failed += value ? 0 : 1;
  }
};

class LocalNeuron final : public NeuronBase {
public:
  void pushContainer(Container *) override {}
  void popContainer(Container *) override {}
  bool ensureHostNetworkingReady(String *) override { return false; }
  void downloadContainer(CoroutineStack *, uint64_t) override {}
};

class RetirementAckBrain final : public Brain {
public:
  ClusterTopology topology = {};
  ClusterTopology pendingTopology = {};
  std::function<void(bool)> pendingTopologyPersistence;
  uint32_t topologyPersistenceCalls = 0;

  void armMachineNeuronControl(Machine *) override {}
  void pushSpinApplicationProgressToMothership(ApplicationDeployment *, const String&) override {}
  void spinApplicationFailed(ApplicationDeployment *, const String&) override {}
  bool persistLocalRuntimeState(void) override { return true; }

  bool loadAuthoritativeClusterTopology(ClusterTopology& loaded) const override
  {
    loaded = topology;
    return true;
  }

  void persistAuthoritativeClusterTopologyAsync(
      ClusterTopology persisted, PersistenceCompletion completion) override
  {
    ++topologyPersistenceCalls;
    pendingTopology = std::move(persisted);
    pendingTopologyPersistence = std::move(completion);
  }

  void finishTopologyPersistence(bool durable)
  {
    if (!pendingTopologyPersistence) return;
    auto completion = std::move(pendingTopologyPersistence);
    if (durable) topology = std::move(pendingTopology);
    completion(durable);
  }

  bool installRetirement(uint128_t uuid, uint64_t topologyVersion, bool isBrain,
                         ProdigyMasterAuthorityRuntimeState& state)
  {
    Machine machine = {};
    machine.uuid = uuid;
    machine.creationTimeMs = 100;
    machine.privateAddress.assign("10.77.0.7"_ctv);
    RetiredMachineIdentity retirement = {};
    retirement.id = 1;
    retirement.machine = retiredMachineIdentity(machine);
    retirement.machine.isBrain = isBrain;
    retirement.topologyVersion = topologyVersion;
    retiredMachineIdentities.insert_or_assign(retirement.id, std::move(retirement));
    if (!writeMachineRetirementJournalCarrier()) return false;
    masterAuthorityRuntimeState.generation = 77;
    masterAuthorityRuntimeStateDurable = true;
    durableMasterAuthorityRuntimeStateGeneration = masterAuthorityRuntimeState.generation;
    state = masterAuthorityRuntimeState;
    return true;
  }
};

class PeerTransport final {
public:
  BrainView peer = {};
  int fd = -1;

  bool open(RetirementAckBrain& brain)
  {
    int sockets[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    fd = sockets[1];
    peer.fd = sockets[0];
    peer.fslot = Ring::adoptProcessFDIntoFixedFileSlot(peer.fd, false);
    if (peer.fslot < 0)
    {
      ::close(peer.fd);
      ::close(fd);
      peer.fd = fd = -1;
      return false;
    }
    peer.isFixedFile = true;
    peer.connected = true;
    peer.registrationFresh = true;
    peer.isMasterBrain = true;
    peer.uuid = uint128_t(0x7701);
    peer.boottimens = 7701;
    brain.brains.insert(&peer);
    RingDispatcher::installMultiplexee(&peer, &brain);
    return true;
  }

  void close(RetirementAckBrain& brain)
  {
    brain.brains.erase(&peer);
    RingDispatcher::eraseMultiplexee(&peer);
    if (peer.isFixedFile && peer.fslot > 0)
    {
      Ring::uninstallFromFixedFileSlot(&peer);
    }
    if (peer.fd >= 0) ::close(peer.fd);
    if (fd >= 0) ::close(fd);
    peer.fd = fd = -1;
  }
};

static bool prepareRetirementState(
    Suite& suite, RetirementAckBrain& brain, ProdigyMasterAuthorityRuntimeState& state,
    bool retiresBrain = false)
{
  state = {};
  const bool installed = brain.installRetirement(uint128_t(0x7707), 3, retiresBrain, state);
  suite.expect(installed, "retirement_ack_installs_durable_carrier");
  if (!installed) return false;
  ClusterMachine survivor = {};
  survivor.uuid = uint128_t(0x7710);
  survivor.creationTimeMs = 101;
  survivor.isBrain = retiresBrain;
  brain.topology.version = 1;
  brain.topology.machines.push_back(brain.retiredMachineIdentities.begin()->second.machine);
  brain.topology.machines.push_back(std::move(survivor));
  return true;
}

static uint32_t countAuthorityAcknowledgements(
    String& buffer, uint64_t generation, const String& digest)
{
  uint32_t count = 0;
  uint8_t *cursor = buffer.data();
  uint8_t *end = buffer.data() + buffer.size();
  while (cursor < end)
  {
    Message *message = reinterpret_cast<Message *>(cursor);
    if (message->size == 0 || cursor + message->size > end) return 0;
    if (BrainTopic(message->topic) == BrainTopic::replicateMasterAuthorityState)
    {
      uint8_t *args = message->args;
      String serialized = {};
      ProdigyMasterAuthorityStateTransitionAck acknowledgement = {};
      Message::extractToStringView(args, serialized);
      if (BitseryEngine::deserializeSafe(serialized, acknowledgement) &&
          acknowledgement.generation == generation && acknowledgement.transitionDigest.equals(digest))
      {
        ++count;
      }
    }
    cursor += message->size;
  }
  return count;
}

static void testTopologyReceiptGatesAuthorityAck(Suite& suite)
{
  Ring::createRing(16, 16, 16, 16, -1, -1, 0);
  LocalNeuron local = {};
  local.uuid = 0x7700;
  thisNeuron = &local;
  RetirementAckBrain brain = {};
  brain.boottimens = 7700;
  brain.brainConfig.clusterUUID = 0x77;
  PeerTransport transport = {};
  if (!transport.open(brain))
  {
    suite.expect(false, "retirement_ack_opens_current_peer_transport");
    Ring::shutdownForExec();
    thisNeuron = nullptr;
    return;
  }
  suite.expect(true, "retirement_ack_opens_current_peer_transport");

  auto invoke = [&](ProdigyMasterAuthorityRuntimeState state) {
    String serialized = {};
    ProdigyMasterAuthorityStateTransition transition = {};
    transition.runtimeState = state;
    BitseryEngine::serialize(serialized, transition);
    brain.acknowledgeAppliedMasterAuthorityTransition(&transport.peer, state, serialized);
  };

  ProdigyMasterAuthorityRuntimeState state = {};
  if (!prepareRetirementState(suite, brain, state))
  {
    transport.close(brain);
    Ring::shutdownForExec();
    thisNeuron = nullptr;
    return;
  }
  invoke(state);
  suite.expect(brain.topologyPersistenceCalls == 1 && brain.pendingTopologyPersistence &&
                   transport.peer.wBuffer.outstandingBytes() == 0,
               "retirement_ack_withholds_while_topology_receipt_is_held");
  brain.finishTopologyPersistence(false);
  suite.expect(transport.peer.wBuffer.outstandingBytes() == 0 && brain.topology.version == 1 &&
                   brain.topology.machines.size() == 2,
               "retirement_ack_withholds_after_failed_topology_receipt");

  // A stale completion must not send an acknowledgement to a reused peer object.
  invoke(state);
  ++transport.peer.ioGeneration;
  brain.finishTopologyPersistence(true);
  suite.expect(brain.topologyPersistenceCalls == 2 && transport.peer.wBuffer.outstandingBytes() == 0,
               "retirement_ack_withholds_after_stale_peer_receipt");

  // Rebuild the fixture after the successful stale receipt applied its topology.
  RetirementAckBrain success = {};
  success.boottimens = 7700;
  success.brainConfig.clusterUUID = 0x77;
  PeerTransport successTransport = {};
  if (!successTransport.open(success))
  {
    suite.expect(false, "retirement_ack_opens_success_peer_transport");
    transport.close(brain);
    Ring::shutdownForExec();
    thisNeuron = nullptr;
    return;
  }
  suite.expect(true, "retirement_ack_opens_success_peer_transport");
  ProdigyMasterAuthorityRuntimeState successState = {};
  if (!prepareRetirementState(suite, success, successState))
  {
    successTransport.close(success);
    transport.close(brain);
    Ring::shutdownForExec();
    thisNeuron = nullptr;
    return;
  }
  String serialized = {};
  ProdigyMasterAuthorityStateTransition transition = {};
  transition.runtimeState = successState;
  BitseryEngine::serialize(serialized, transition);
  String successDigest = {};
  suite.expect(prodigyComputeSHA256Hex(serialized, successDigest),
               "retirement_ack_computes_success_transition_digest");
  success.acknowledgeAppliedMasterAuthorityTransition(&successTransport.peer, successState, serialized);
  suite.expect(successTransport.peer.wBuffer.outstandingBytes() == 0,
               "retirement_ack_waits_for_success_receipt");
  success.finishTopologyPersistence(true);
  const uint32_t acknowledged = countAuthorityAcknowledgements(
      successTransport.peer.wBuffer, successState.generation, successDigest);
  success.finishTopologyPersistence(true);
  suite.expect(acknowledged == 1 && countAuthorityAcknowledgements(
                   successTransport.peer.wBuffer, successState.generation, successDigest) == 1,
               "retirement_ack_sends_exactly_once_after_durable_topology");

  RetirementAckBrain staleEpoch = {};
  staleEpoch.boottimens = 7700;
  staleEpoch.brainConfig.clusterUUID = 0x77;
  PeerTransport staleEpochTransport = {};
  if (!staleEpochTransport.open(staleEpoch))
  {
    suite.expect(false, "retirement_ack_opens_epoch_stale_peer_transport");
  }
  else
  {
    ProdigyMasterAuthorityRuntimeState staleEpochState = {};
    if (prepareRetirementState(suite, staleEpoch, staleEpochState))
    {
      String staleSerialized = {};
      ProdigyMasterAuthorityStateTransition staleTransition = {};
      staleTransition.runtimeState = staleEpochState;
      BitseryEngine::serialize(staleSerialized, staleTransition);
      staleEpoch.acknowledgeAppliedMasterAuthorityTransition(
          &staleEpochTransport.peer, staleEpochState, staleSerialized);
      ++staleEpoch.masterAuthorityEpoch;
      staleEpoch.finishTopologyPersistence(true);
      suite.expect(staleEpoch.topologyPersistenceCalls == 1 &&
                       staleEpochTransport.peer.wBuffer.outstandingBytes() == 0,
                   "retirement_ack_withholds_after_stale_authority_receipt");
    }
    staleEpochTransport.close(staleEpoch);
  }

  RetirementAckBrain newerRevision = {};
  newerRevision.boottimens = 7700;
  newerRevision.brainConfig.clusterUUID = 0x77;
  newerRevision.nBrains = 9;
  PeerTransport newerRevisionTransport = {};
  if (!newerRevisionTransport.open(newerRevision))
  {
    suite.expect(false, "retirement_ack_opens_newer_revision_peer_transport");
  }
  else
  {
    ProdigyMasterAuthorityRuntimeState newerRevisionState = {};
    if (prepareRetirementState(suite, newerRevision, newerRevisionState, true))
    {
      String newerSerialized = {};
      ProdigyMasterAuthorityStateTransition newerTransition = {};
      newerTransition.runtimeState = newerRevisionState;
      BitseryEngine::serialize(newerSerialized, newerTransition);
      newerRevision.acknowledgeAppliedMasterAuthorityTransition(
          &newerRevisionTransport.peer, newerRevisionState, newerSerialized);
      ++newerRevision.masterAuthorityRuntimeState.generation;
      newerRevision.finishTopologyPersistence(true);
      suite.expect(newerRevision.topologyPersistenceCalls == 1 &&
                       newerRevisionTransport.peer.wBuffer.outstandingBytes() == 0 && newerRevision.nBrains == 9,
                   "retirement_ack_withholds_and_skips_membership_for_same_epoch_newer_revision");
    }
    newerRevisionTransport.close(newerRevision);
  }

  RetirementAckBrain coverageMismatch = {};
  coverageMismatch.boottimens = 7700;
  coverageMismatch.brainConfig.clusterUUID = 0x77;
  PeerTransport coverageMismatchTransport = {};
  if (!coverageMismatchTransport.open(coverageMismatch))
  {
    suite.expect(false, "retirement_ack_opens_coverage_mismatch_peer_transport");
  }
  else
  {
    ProdigyMasterAuthorityRuntimeState coverageMismatchState = {};
    if (prepareRetirementState(suite, coverageMismatch, coverageMismatchState))
    {
      String coverageSerialized = {};
      ProdigyMasterAuthorityStateTransition coverageTransition = {};
      coverageTransition.runtimeState = coverageMismatchState;
      BitseryEngine::serialize(coverageSerialized, coverageTransition);
      coverageMismatch.masterAuthorityRuntimeStateDurable = false;
      coverageMismatch.acknowledgeAppliedMasterAuthorityTransition(
          &coverageMismatchTransport.peer, coverageMismatchState, coverageSerialized);
      coverageMismatch.finishTopologyPersistence(true);
      suite.expect(coverageMismatch.topologyPersistenceCalls == 1 &&
                       coverageMismatchTransport.peer.wBuffer.outstandingBytes() == 0 &&
                       coverageMismatch.topology.version == 3 && coverageMismatch.topology.machines.size() == 1,
                   "retirement_topology_applies_while_elastic_coverage_withholds_ack");
    }
    coverageMismatchTransport.close(coverageMismatch);
  }

  RetirementAckBrain admission = {};
  admission.weAreMaster = true;
  admission.nBrains = 2;
  BrainView legacyPeer = {};
  legacyPeer.uuid = uint128_t(0x7720);
  legacyPeer.boottimens = 7720;
  legacyPeer.version = 4;
  legacyPeer.registrationFresh = true;
  admission.brains.insert(&legacyPeer);
  Machine candidate = {};
  candidate.uuid = uint128_t(0x7721);
  candidate.creationTimeMs = 100;
  uint64_t retirementID = 0;
  suite.expect(admission.journalMachineRetirement({&candidate}, false, retirementID) == false &&
                   retirementID == 0 && admission.retiredMachineIdentities.empty(),
               "retirement_journal_rejects_unsupported_initial_carrier_before_mutation");

  successTransport.close(success);
  transport.close(brain);
  Ring::shutdownForExec();
  thisNeuron = nullptr;
}

int main(void)
{
  Suite suite = {};
  testTopologyReceiptGatesAuthorityAck(suite);
  return suite.failed == 0 ? 0 : 1;
}
