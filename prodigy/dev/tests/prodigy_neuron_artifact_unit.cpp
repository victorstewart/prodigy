#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/message.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>
#include <prodigy/neuron/neuron.h>

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <vector>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

class ContainerManagerGatewayRecoveryTestAccess {
public:
  static bool socketPath(uint128_t uuid, String& path)
  {
    return ContainerManager::gatewayRecoverySocketPath(uuid, path);
  }

  static bool writeRecordAt(int rootFD, const ContainerPlan& plan, const String& token)
  {
    return ContainerManager::writeGatewayRecoveryRecordAt(rootFD, plan, token);
  }

  static bool readRecordAt(int rootFD, const ContainerPlan& plan, String& token)
  {
    return ProdigyGatewayRecovery::readGatewayRecoveryRecordAt(rootFD, plan, token);
  }
};

class TestSuite {
public:
  int failed = 0;
  void expect(bool value, const char *name)
  {
    if (!value)
    {
      dprintf(STDERR_FILENO, "FAIL: %s\n", name);
      ++failed;
    }
  }
};

// Frozen pre-G3B Brain/Neuron frame. This topic has no version negotiation;
// current readers and writers must remain byte-compatible with this layout.
struct LegacySwitchboardWormholeOperation {
  uint32_t containerID = 0;
  SwitchboardWormholeOperationStatus status = SwitchboardWormholeOperationStatus::request;
  String revision;
  String desired;
};

template <typename S>
static void serialize(S&& serializer, LegacySwitchboardWormholeOperation& operation)
{
  serializer.value4b(operation.containerID);
  serializer.value1b(operation.status);
  serializer.text1b(operation.revision, 64);
  serializer.text1b(operation.desired, SwitchboardWormholeOperation::maximumDesiredBytes);
}

class ScopedArtifactStore {
public:
  String root = {};
  ScopedArtifactStore()
  {
    std::filesystem::create_directories(".run");
    char pattern[] = ".run/prodigy-neuron-artifact-XXXXXX";
    if (char *created = ::mkdtemp(pattern)) root.assign(created);
  }
  ~ScopedArtifactStore()
  {
    if (root.size()) std::filesystem::remove_all(root.c_str());
  }
};

class ArtifactRing final : public TimeoutDispatcher {
public:
  RingDispatcher dispatcher;
  TimeoutPacket deadline = {};
  bool timedOut = false;
  bool shutdown = false;
  ArtifactRing()
  {
    Ring::interfacer = &dispatcher;
    Ring::lifecycler = &dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    deadline.dispatcher = this;
  }
  ~ArtifactRing()
  {
    shutdownRing();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    RingDispatcher::dispatcher = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
  }
  void shutdownRing()
  {
    if (shutdown == false)
    {
      Ring::shutdownForExec();
      shutdown = true;
    }
  }
  void arm(uint64_t ms)
  {
    deadline.clear();
    deadline.setTimeoutMs(ms);
    Ring::queueTimeout(&deadline);
  }
  void dispatchTimeout(TimeoutPacket *) override
  {
    timedOut = true;
    Ring::exit = true;
  }
};

class SwitchboardRingTestAccess {
public:
  static const local_container_subnet6& subnet(const Switchboard& board)
  {
    return board.subnet;
  }
  static void setBoundaryConsumer(Switchboard& board, BPFProgram *router, EthDevice *ingress)
  {
    board.bpf_router = router;
    board.additionalIngressEth = ingress;
  }

  static bool hasAdditionalIngress(const Switchboard& board)
  {
    return board.additionalIngressEth != nullptr;
  }

  static bool retainedAdditionalIngressWitnessMatches(uint32_t witnessedProgramID,
                                                      uint32_t candidateProgramID,
                                                      uint32_t candidateMapCount,
                                                      uint32_t candidateType,
                                                      const char *candidateName,
                                                      uint8_t candidateTag)
  {
    Switchboard::RetainedAdditionalIngressXDPWitness witness = {};
    witness.programID = witnessedProgramID;
    witness.mapCount = candidateMapCount;
    witness.valid = true;
    memset(witness.tag, candidateTag, sizeof(witness.tag));

    struct bpf_prog_info info = {};
    info.id = candidateProgramID;
    info.type = candidateType;
    info.nr_map_ids = candidateMapCount;
    strncpy(reinterpret_cast<char *>(info.name), candidateName, BPF_OBJ_NAME_LEN - 1);
    memset(info.tag, candidateTag, sizeof(info.tag));
    return Switchboard::retainedAdditionalIngressProgramInfoMatches(witness, candidateProgramID, info);
  }

  static bool retainedAdditionalIngressMatchesCurrentFamily(uint32_t candidateProgramID,
                                                            uint32_t currentProgramID,
                                                            uint32_t candidateMapCount,
                                                            uint8_t candidateTag,
                                                            uint8_t currentTag)
  {
    struct bpf_prog_info candidate = {};
    candidate.id = candidateProgramID;
    candidate.type = BPF_PROG_TYPE_XDP;
    candidate.nr_map_ids = candidateMapCount;
    strncpy(reinterpret_cast<char *>(candidate.name), "bal_ingress", BPF_OBJ_NAME_LEN - 1);
    memset(candidate.tag, candidateTag, sizeof(candidate.tag));
    struct bpf_prog_info current = {};
    current.id = currentProgramID;
    current.type = BPF_PROG_TYPE_XDP;
    current.nr_map_ids = candidateMapCount;
    strncpy(reinterpret_cast<char *>(current.name), "bal_ingress", BPF_OBJ_NAME_LEN - 1);
    memset(current.tag, currentTag, sizeof(current.tag));
    return Switchboard::retainedAdditionalIngressProgramMatchesCurrentFamily(candidateProgramID, candidate, current);
  }
};

class TestNeuron final : public Neuron {
public:
  enum class GatewayRecoveryFault : uint8_t {
    none, helloToken, helloTuple, nonceFailure, nonceZero, receiptNonce,
    identity, authority, epoch, brainGeneration, fragment, launchGeneration,
    candidatePID, candidatePidfd, brainPointer, boundToken, unsettled,
    malformed, oversized, coalesced, duplicate, eof
  };
  struct GatewayRecoveryTransitionResult {
    uint32_t sends = 0, recvs = 0, closes = 0;
    bool challengeIssued = false, receiptAccepted = false;
    bool retainedCandidate = false, pendingLaunch = false;
    bool basePublished = false, recoveryLeasePreserved = false;
    bool pathFaultAccepted = false;
    bool carrierRemoved = false, readinessRevoked = false;
    uint32_t waitidCalls = 0;
  };
  struct GatewayRecoveryListenerProof {
    bool opened = false, procIdentityCaptured = false, accepted = false;
    bool peerExact = false, changedIdentityRejected = false, cleaned = false;
  };
  String root = {};
  int gatewayRecoveryRuntimeRootFD = -1;
  NeuronBrainControlStream *retained = nullptr;
  std::vector<NeuronBrainControlStream *> retired = {};
  uint32_t artifactFinishes = 0;
  bool lastArtifactAdopted = false;
  bool lastArtifactSourceCurrent = false;
  std::function<void(bool)> pendingRestoreCompletion = {};
  uint32_t restoreSubmissions = 0;
  uint32_t publishedContainers = 0;
  uint32_t restoredWaitidCalls = 0;
  bool useBaseGatewayPublication = false;
  uint32_t killAcknowledgements = 0;
  uint128_t lastKillAcknowledgement = 0;
  std::vector<std::unique_ptr<Container>> publishedContainerOwners = {};
  CrossClusterMasqueGatewayReadinessListener::PeerIdentity retainedGatewayPeerIdentityForTest = {};
  bool retainedGatewayPeerIdentityEnabledForTest = false;

  ProdigyHostTask<bool> restoreStateUploadNetworkAsync(
      Container *, CoroutineStack *, String *, std::function<bool()> current) override
  {
    co_return co_await ProdigyHostCompletion<bool>([this, current = std::move(current)](std::function<void(bool)> complete) mutable {
      restoreSubmissions += 1;
      pendingRestoreCompletion = [current = std::move(current), complete = std::move(complete)](bool value) mutable {
        complete(current() && value);
      };
    });
  }

  bool readGatewayRecoveryRecordForStateUpload(const ContainerPlan& plan, String& token) override
  {
    return gatewayRecoveryRuntimeRootFD >= 0 &&
        ContainerManagerGatewayRecoveryTestAccess::readRecordAt(gatewayRecoveryRuntimeRootFD, plan, token);
  }

  bool captureRetainedGatewayPeerIdentity(
      pid_t pid, CrossClusterMasqueGatewayReadinessListener::PeerIdentity& identity) override
  {
    if (!retainedGatewayPeerIdentityEnabledForTest || pid != retainedGatewayPeerIdentityForTest.pid) return false;
    identity = retainedGatewayPeerIdentityForTest;
    return true;
  }

  void configureRetainedGatewayPeerIdentityForTest(const Container& container)
  {
    retainedGatewayPeerIdentityForTest = {};
    retainedGatewayPeerIdentityForTest.pid = container.pid;
    retainedGatewayPeerIdentityForTest.startTime = 1;
    prodigyContainerCgroupProcLeafSuffix(container.name, retainedGatewayPeerIdentityForTest.cgroupLeaf);
    retainedGatewayPeerIdentityForTest.netnsDevice = 1;
    retainedGatewayPeerIdentityForTest.netnsInode = 1;
    retainedGatewayPeerIdentityEnabledForTest = true;
  }

  bool gatewayRuntimeOwnerForTest(uint128_t pairUUID, uint128_t expectedUUID, bool expectedAdmitted)
  {
    const auto *runtime = crossClusterMasqueGatewayRuntimeForPair(pairUUID);
    return runtime != nullptr && runtime->systemContainerUUID == expectedUUID &&
        runtime->systemPlanAdmitted == expectedAdmitted;
  }

  void assignGatewayRuntimeOwnerForTest(uint128_t pairUUID, uint128_t owner, bool admitted)
  {
    auto *runtime = crossClusterMasqueGatewayRuntimeForPair(pairUUID);
    if (runtime != nullptr) { runtime->systemContainerUUID = owner; runtime->systemPlanAdmitted = admitted; }
  }

  bool retainedGatewayRestoreStateForTest(uint128_t containerUUID, uint64_t& epoch,
                                          bool& networkRestored, bool& listenerArmed)
  {
    const auto found = pendingStateUploadRestores.find(containerUUID);
    if (found == pendingStateUploadRestores.end() || found->second == nullptr) return false;
    epoch = found->second->epoch;
    networkRestored = found->second->networkRestored;
    listenerArmed = crossClusterMasqueGatewayListenerForContainer(containerUUID) != nullptr;
    return true;
  }

  void cleanupRetainedGatewayRecoveryForTest(uint128_t containerUUID)
  {
    removeCrossClusterMasqueGatewayListener(containerUUID);
    const auto found = pendingStateUploadRestores.find(containerUUID);
    if (found != pendingStateUploadRestores.end()) {
      found->second->coro.cancelSuspended();
      found->second->runner.reset();
      finishPendingContainerLaunch(containerUUID, found->second->launchAdmissionGeneration);
      pendingStateUploadRestores.erase(found);
    }
  }

  bool installGatewayAuthorityForStateUploadTest(const CrossClusterMasqueGatewayAuthority& authority)
  {
    if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority)) return false;
    uuid = authority.localMachineUUID;
    crossClusterMasqueGatewayRuntimes.clear();
    crossClusterMasqueGatewayRuntimes.emplace_back();
    crossClusterMasqueGatewayRuntimes.back().authority = authority;
    return true;
  }

  bool prepareGatewayPrivateBGPWithdrawalForTest(const CrossClusterMasqueGatewayAuthority& authority)
  {
    replaceBrainWithoutClosing();
    controlTransportCredentials.self.clusterUUID = authority.localClusterUUID;
    return installGatewayAuthorityForStateUploadTest(authority);
  }

  void forgetGatewayPrivateBGPRuntimeForTest()
  {
    crossClusterMasqueGatewayRuntimes.clear();
  }

  bool withdrawGatewayPrivateBGPForTest(const ProdigyPairPrivateBGPSecretScope& scope,
                                        bool& acknowledged)
  {
    acknowledged = false;
    if (brain == nullptr) return false;
    brain->wBuffer.clear();
    String frame = {};
    Message::construct(frame, NeuronTopic::withdrawCrossClusterPrivateBGPSecret,
        scope.pairUUID, scope.operationUUID, scope.keyEpoch, scope.tunnelSlot,
        scope.clusterUUID, scope.machineUUID, scope.authorityGeneration,
        scope.gatewayGeneration);
    neuronHandler(reinterpret_cast<Message *>(frame.data()));
    if (brain->wBuffer.size() < Message::headerBytes) return false;
    auto *reply = reinterpret_cast<Message *>(brain->wBuffer.data());
    if (reply->size != brain->wBuffer.size() ||
        NeuronTopic(reply->topic) != NeuronTopic::crossClusterPrivateBGPSecretRevocationAck)
      return false;
    uint8_t *args = reply->args;
    uint128_t pair = 0, operation = 0, cluster = 0, machine = 0;
    uint64_t epoch = 0, authorityGeneration = 0, gatewayGeneration = 0;
    uint8_t slot = 0, accepted = 0;
    Message::extractArg<ArgumentNature::fixed>(args, pair);
    Message::extractArg<ArgumentNature::fixed>(args, operation);
    Message::extractArg<ArgumentNature::fixed>(args, epoch);
    Message::extractArg<ArgumentNature::fixed>(args, slot);
    Message::extractArg<ArgumentNature::fixed>(args, cluster);
    Message::extractArg<ArgumentNature::fixed>(args, machine);
    Message::extractArg<ArgumentNature::fixed>(args, authorityGeneration);
    Message::extractArg<ArgumentNature::fixed>(args, gatewayGeneration);
    Message::extractArg<ArgumentNature::fixed>(args, accepted);
    acknowledged = args == reply->terminal() && accepted == 1 &&
        pair == scope.pairUUID && operation == scope.operationUUID && epoch == scope.keyEpoch &&
        slot == scope.tunnelSlot && cluster == scope.clusterUUID && machine == scope.machineUUID &&
        authorityGeneration == scope.authorityGeneration && gatewayGeneration == scope.gatewayGeneration;
    return true;
  }

  bool projectGatewayAuthorityForStateUploadTest(const CrossClusterMasqueGatewayAuthority& authority)
  {
    uuid = authority.localMachineUUID;
    controlTransportCredentials.self.clusterUUID = authority.localClusterUUID;
    ProdigyCrossClusterMasqueGatewayAuthorityProjection projection = {};
    projection.authorities.push_back(authority);
    return reconcileCrossClusterMasqueGatewayAuthorityProjection(projection);
  }

  bool retainedGatewayRecoveryForTest(uint128_t containerUUID, String& socket, String& token,
                                      String& boundToken, bool& bound, bool& settled) const
  {
    auto found = pendingStateUploadRestores.find(containerUUID);
    if (found == pendingStateUploadRestores.end() || found->second == nullptr ||
        found->second->container == nullptr) return false;
    const StateUploadRestoreOperation& operation = *found->second;
    socket.assign(operation.container->plan.system.gatewayRecoverySocket);
    token.assign(operation.container->plan.system.gatewayRecoveryToken);
    boundToken.assign(operation.boundGatewayRecoveryToken);
    bound = operation.gatewayRecoveryTokenBound;
    settled = operation.settled;
    return true;
  }

  bool beginStateUploadRestoreForTest(std::unique_ptr<Container> container, uint64_t epoch)
  {
    (void)epoch;
    return beginStateUploadRestore(std::move(container), currentStateUploadRestoreRound());
  }

  bool admitRestoreReplayForTest(const ContainerPlan& plan)
  {
    return admitRepeatedStateUploadRestore(plan, {}, currentStateUploadRestoreRound());
  }
  bool restoreBarrierPendingForTest() const { return stateUploadRestoresPending(); }
  void fenceCurrentRestoreControlForTest() { fenceStateUploadRestoresForControl(brain); }
  void assignFragmentForLazySwitchboardTest(uint8_t datacenter, uint8_t machine0, uint8_t machine1, uint8_t machine2)
  {
    lcsubnet6.dpfx = datacenter;
    lcsubnet6.mpfx[0] = machine0;
    lcsubnet6.mpfx[1] = machine1;
    lcsubnet6.mpfx[2] = machine2;
  }
  Switchboard *createLazySwitchboardForTest() { return ensureSwitchboard(); }

  bool pendingStateUploadRestoreForTest(uint128_t uuid) const
  {
    return isPendingContainerLaunch(uuid);
  }

  GatewayRecoveryListenerProof gatewayRecoveryListenerPeerProofForTest(
      const String& root, const String& token, const ProdigyGatewayLocalTuple& tuple)
  {
    GatewayRecoveryListenerProof result = {};
    if (root.empty() || geteuid() != getegid()) return result;
    Container candidate = {};
    candidate.plan.uuid = uint128_t(0xa551f0a1);
    candidate.pid = getpid();
    candidate.executionHostID = uint32_t(geteuid());
    candidate.name.assign("gateway-rebind-offline"_ctv);
    String socketPath = {};
    socketPath.assign(root);
    if (socketPath[socketPath.size() - 1] != '/') socketPath.append('/');
    socketPath.append("gateway-rebind-listener.sock"_ctv);

    CrossClusterMasqueGatewayReadinessListener listener = {};
    CrossClusterMasqueGatewayReadinessListener::PeerIdentity synthetic = {};
    synthetic.pid = candidate.pid; synthetic.startTime = 1;
    prodigyContainerCgroupProcLeafSuffix(candidate.name, synthetic.cgroupLeaf);
    synthetic.netnsDevice = 1; synthetic.netnsInode = 1;
    listener.capturePeerIdentity = [synthetic](pid_t pid, CrossClusterMasqueGatewayReadinessListener::PeerIdentity& identity) {
      identity = synthetic; return pid == synthetic.pid;
    };
    result.opened = listener.openForRecovery(candidate, socketPath, token, tuple, 41);
    CrossClusterMasqueGatewayReadinessListener::PeerIdentity actual = {};
    result.procIdentityCaptured = CrossClusterMasqueGatewayReadinessListener::capturePeerIdentityFromProc(candidate.pid, actual) &&
        actual.pid == candidate.pid && actual.startTime != 0 && !actual.cgroupLeaf.empty() &&
        actual.netnsDevice != 0 && actual.netnsInode != 0;
    if (!result.opened || !result.procIdentityCaptured) {
      listener.teardown();
      result.cleaned = access(socketPath.c_str(), F_OK) != 0;
      return result;
    }
    listener.retainedIdentity = actual;
    listener.expectedCgroup.assign(actual.cgroupLeaf);
    listener.capturePeerIdentity = CrossClusterMasqueGatewayReadinessListener::capturePeerIdentityFromProc;
    const auto connectClient = [&]() {
      const int client = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (client < 0) return -1;
      sockaddr_un address = {}; address.sun_family = AF_UNIX;
      memcpy(address.sun_path, socketPath.data(), socketPath.size());
      const socklen_t length = socklen_t(offsetof(sockaddr_un, sun_path) + socketPath.size() + 1);
      if (::connect(client, reinterpret_cast<sockaddr *>(&address), length) != 0) { ::close(client); return -1; }
      return client;
    };
    int client = connectClient(), acceptedFD = -1; pid_t peerPID = -1;
    result.accepted = client >= 0 && listener.acceptCarrier(acceptedFD, peerPID);
    result.peerExact = result.accepted && peerPID == candidate.pid;
    if (acceptedFD >= 0) ::close(acceptedFD);
    if (client >= 0) ::close(client);

    ++listener.retainedIdentity.startTime;
    client = connectClient(); acceptedFD = -1; peerPID = -1;
    result.changedIdentityRejected = client >= 0 && !listener.acceptCarrier(acceptedFD, peerPID) &&
        acceptedFD < 0 && peerPID < 0;
    if (acceptedFD >= 0) ::close(acceptedFD);
    if (client >= 0) ::close(client);
    listener.teardown();
    result.cleaned = listener.fd < 0 && access(socketPath.c_str(), F_OK) != 0;
    return result;
  }

  GatewayRecoveryTransitionResult processGatewayRecoveryTransitionForTest(
      const CrossClusterMasqueGatewayAuthority& authority, const String& token,
      GatewayRecoveryFault fault = GatewayRecoveryFault::none)
  {
    GatewayRecoveryTransitionResult result = {};
    const uint128_t containerUUID = uint128_t(0xa551f001);
    stateUploadRestoreEpoch = 41;
    crossClusterMasqueGatewayRuntimes.clear();
    crossClusterMasqueGatewayRuntimes.emplace_back();
    auto& runtime = crossClusterMasqueGatewayRuntimes.back();
    runtime.authority = authority; runtime.systemContainerUUID = containerUUID; runtime.systemPlanAdmitted = true;
    brain = new NeuronBrainControlStream(); brain->connected = true;
    brain->fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    auto operation = std::make_unique<StateUploadRestoreOperation>();
    operation->container = std::make_unique<Container>();
    operation->container->plan.uuid = containerUUID;
    operation->container->plan.system.kind = SystemContainerKind::crossClusterMasqueGateway;
    operation->container->plan.system.gatewayPairUUID = authority.pairUUID;
    operation->container->pid = 77;
    operation->container->pidfd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    operation->launchAdmissionGeneration = beginPendingContainerLaunch(operation->container->plan);
    operation->fragment = lcsubnet6; operation->stream = brain; operation->requestedStream = brain;
    operation->streamGeneration = brain->ioGeneration; operation->requestedGeneration = brain->ioGeneration;
    operation->epoch = stateUploadRestoreEpoch; operation->settled = true;
    operation->boundGatewayRecoveryToken.assign(token); operation->gatewayRecoveryTokenBound = true;
    pendingStateUploadRestores.insert_or_assign(containerUUID, std::move(operation));

    auto heldCarrier = std::make_unique<CrossClusterMasqueGatewayReadinessCarrier>();
    auto& carrier = *heldCarrier;
    carrier.containerUUID = containerUUID; carrier.peerPID = 77; carrier.recovery = true;
    carrier.recoveryEpoch = stateUploadRestoreEpoch; carrier.recoveryTuple = gatewayRecoveryTuple(authority);
    carrier.recoveryToken.assign(token); carrier.localPhase = ProdigyGatewayLocalCarrierPhase::rebindHello;
    carrier.retainedIdentity.pid = carrier.peerPID; carrier.retainedIdentity.startTime = 1;
    carrier.retainedIdentity.cgroupLeaf.assign("test"_ctv); carrier.retainedIdentity.netnsDevice = 1; carrier.retainedIdentity.netnsInode = 1;
    auto identityChanged = std::make_shared<bool>(false);
    carrier.capturePeerIdentity = [&carrier, identityChanged](pid_t pid, CrossClusterMasqueGatewayReadinessListener::PeerIdentity& identity) {
      identity = carrier.retainedIdentity;
      if (*identityChanged) ++identity.startTime;
      return pid == carrier.peerPID;
    };
    auto listener = std::make_unique<CrossClusterMasqueGatewayReadinessListener>();
    listener->containerUUID = containerUUID; listener->recovery = true;
    crossClusterMasqueGatewayReadinessListeners.push_back(std::move(listener));
    activeCrossClusterMasqueGatewayReadinessCarriers.insert_or_assign(containerUUID, &carrier);
    crossClusterMasqueGatewayReadinessCarriers.push_back(std::move(heldCarrier));
    useBaseGatewayPublication = true;
    ProdigyGatewayLocalControlFrame hello = {};
    hello.direction = ProdigyGatewayLocalDirection::gatewayToNeuron; hello.kind = ProdigyGatewayLocalKind::rebindHello;
    hello.rebindHello.recoveryToken.assign(token); hello.rebindHello.tuple = carrier.recoveryTuple;
    if (fault == GatewayRecoveryFault::helloToken) hello.rebindHello.recoveryToken.assign("fedcba9876543210fedcba9876543210"_ctv);
    if (fault == GatewayRecoveryFault::helloTuple) ++hello.rebindHello.tuple.gatewayGeneration;
    String encoded = {};
    if (fault == GatewayRecoveryFault::malformed) { const uint32_t zero = 0; encoded.append(reinterpret_cast<const char *>(&zero), sizeof(zero)); }
    else if (fault == GatewayRecoveryFault::oversized) { const uint32_t huge = 513; encoded.append(reinterpret_cast<const char *>(&huge), sizeof(huge)); }
    else if (!prodigyEncodeGatewayLocalControlFrame(hello, encoded)) return result;
    carrier.rBuffer.append(encoded);
    if (fault == GatewayRecoveryFault::coalesced) carrier.rBuffer.append(encoded);
    const RecoveryFrameDispatch dispatch = {
      [&result](CrossClusterMasqueGatewayReadinessCarrier *) { ++result.sends; },
      [&result](CrossClusterMasqueGatewayReadinessCarrier *) { ++result.recvs; },
      [this, &result](CrossClusterMasqueGatewayReadinessCarrier *item) {
        ++result.closes; closeCrossClusterMasqueGatewayCarriers(item->containerUUID);
      },
      [fault](uint8_t *bytes, uint32_t size) {
        if (fault == GatewayRecoveryFault::nonceFailure || size != 16) return false;
        memset(bytes, fault == GatewayRecoveryFault::nonceZero ? 0 : 0x5a, size); return true; }};
    processRecoveryFrame(&carrier, dispatch);
    ProdigyGatewayLocalControlFrame challenge = {};
    result.challengeIssued = result.sends == 1 && prodigyDecodeGatewayLocalControlFrame(
        carrier.wBuffer.pHead(), uint32_t(carrier.wBuffer.outstandingBytes()), challenge) &&
        prodigyGatewayLocalControlFrameAllowedForSend(ProdigyGatewayLocalCarrierPhase::rebindHello, challenge);
    const auto finish = [&]() {
      const auto found = pendingStateUploadRestores.find(containerUUID);
      result.retainedCandidate = found != pendingStateUploadRestores.end() && found->second != nullptr && found->second->container != nullptr;
      result.pendingLaunch = isPendingContainerLaunch(containerUUID);
      result.basePublished = containers.contains(containerUUID);
      result.recoveryLeasePreserved = crossClusterMasqueGatewayListenerForContainer(containerUUID) != nullptr &&
          crossClusterMasqueGatewayCarrierForContainer(containerUUID) == &carrier;
      result.carrierRemoved = crossClusterMasqueGatewayCarrierForContainer(containerUUID) == nullptr;
      result.readinessRevoked = !runtime.readiness.authenticatedMasqueQUICReady;
      result.waitidCalls = restoredWaitidCalls;
    };
    if (!result.challengeIssued) { finish(); return result; }
    ProdigyGatewayLocalControlFrame receipt = {};
    receipt.direction = ProdigyGatewayLocalDirection::gatewayToNeuron; receipt.kind = ProdigyGatewayLocalKind::rebindReceipt;
    receipt.rebindReceipt.tuple = carrier.recoveryTuple;
    memcpy(receipt.rebindReceipt.nonce, carrier.recoveryNonce, sizeof(carrier.recoveryNonce));
    receipt.rebindReceipt.authenticatedMasqueQUICReady = true; receipt.rebindReceipt.ready = true;
    receipt.rebindReceipt.routeSetSHA256.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
    if (fault == GatewayRecoveryFault::receiptNonce) receipt.rebindReceipt.nonce[0] ^= 1;
    if (fault == GatewayRecoveryFault::identity) *identityChanged = true;
    if (fault == GatewayRecoveryFault::authority) ++runtime.authority.generation;
    if (fault == GatewayRecoveryFault::epoch) ++stateUploadRestoreEpoch;
    if (fault == GatewayRecoveryFault::brainGeneration) ++brain->ioGeneration;
    if (fault == GatewayRecoveryFault::fragment) ++lcsubnet6.dpfx;
    auto foundBeforeReceipt = pendingStateUploadRestores.find(containerUUID);
    if (foundBeforeReceipt != pendingStateUploadRestores.end() && foundBeforeReceipt->second != nullptr) {
      if (fault == GatewayRecoveryFault::launchGeneration) ++foundBeforeReceipt->second->launchAdmissionGeneration;
      if (fault == GatewayRecoveryFault::candidatePID) ++foundBeforeReceipt->second->container->pid;
      if (fault == GatewayRecoveryFault::candidatePidfd) {
        ::close(foundBeforeReceipt->second->container->pidfd);
        foundBeforeReceipt->second->container->pidfd = -1;
      }
      if (fault == GatewayRecoveryFault::brainPointer) foundBeforeReceipt->second->stream = nullptr;
      if (fault == GatewayRecoveryFault::boundToken)
        foundBeforeReceipt->second->boundGatewayRecoveryToken.assign("fedcba9876543210fedcba9876543210"_ctv);
      if (fault == GatewayRecoveryFault::unsettled) foundBeforeReceipt->second->settled = false;
    }
    encoded.clear(); if (!prodigyEncodeGatewayLocalControlFrame(receipt, encoded)) return result;
    carrier.rBuffer.append(encoded); processRecoveryFrame(&carrier, dispatch);
    result.receiptAccepted = carrier.receiptAccepted;
    if (result.receiptAccepted) {
      ProdigyGatewayLocalControlFrame pathFault = {};
      pathFault.direction = ProdigyGatewayLocalDirection::gatewayToNeuron;
      pathFault.kind = ProdigyGatewayLocalKind::pathFault;
      pathFault.pathFault.fromGateway = true; carrier.faultFramePending = true;
      encoded.clear();
      if (prodigyEncodeGatewayLocalControlFrame(pathFault, encoded)) {
        carrier.rBuffer.append(encoded); processRecoveryFrame(&carrier, dispatch);
        result.pathFaultAccepted = !carrier.faultFramePending && result.closes == 0;
      }
    }
    if (fault == GatewayRecoveryFault::duplicate && prodigyEncodeGatewayLocalControlFrame(receipt, encoded)) {
      carrier.rBuffer.append(encoded); processRecoveryFrame(&carrier, dispatch);
    }
    if (fault == GatewayRecoveryFault::eof) {
      CrossClusterMasqueGatewayReadinessCarrier *closing = &carrier;
      carrier.pendingRecv = true;
      recvCrossClusterMasqueGatewayReadinessCarrier(closing, 0);
      closeHandler(closing);
      const auto found = pendingStateUploadRestores.find(containerUUID);
      result.retainedCandidate = found != pendingStateUploadRestores.end() && found->second != nullptr && found->second->container != nullptr;
      result.pendingLaunch = isPendingContainerLaunch(containerUUID);
      result.basePublished = containers.contains(containerUUID);
      result.recoveryLeasePreserved = false;
      result.carrierRemoved = crossClusterMasqueGatewayCarrierForContainer(containerUUID) == nullptr &&
          crossClusterMasqueGatewayReadinessCarriers.empty();
      result.readinessRevoked = !runtime.readiness.authenticatedMasqueQUICReady;
      result.waitidCalls = restoredWaitidCalls;
      return result;
    }
    finish();
    return result;
  }

  bool cleanupGatewayRecoveryTransitionForTest(void)
  {
    constexpr uint128_t containerUUID = uint128_t(0xa551f001);
    for (;;) {
      CrossClusterMasqueGatewayReadinessCarrier *carrier = nullptr;
      for (const auto& candidate : crossClusterMasqueGatewayReadinessCarriers)
        if (candidate != nullptr && candidate->containerUUID == containerUUID) { carrier = candidate.get(); break; }
      if (carrier == nullptr) break;
      closeHandler(carrier);
    }
    removeCrossClusterMasqueGatewayListener(containerUUID);
    const auto found = containers.find(containerUUID);
    if (found != containers.end() && found->second != nullptr) {
      Container *container = found->second;
      popContainer(container);
      delete container;
    }
    useBaseGatewayPublication = false;
    return crossClusterMasqueGatewayCarrierForContainer(containerUUID) == nullptr &&
        crossClusterMasqueGatewayListenerForContainer(containerUUID) == nullptr &&
        crossClusterMasqueGatewayReadinessCarriers.empty() && !containers.contains(containerUUID);
  }

  bool stateUploadRestoreOperationExistsForTest(uint128_t uuid) const
  {
    return pendingStateUploadRestores.contains(uuid);
  }

  bool retainedCandidatePreservedForTest(uint128_t uuid, pid_t pid) const
  {
    auto found = pendingStateUploadRestores.find(uuid);
    return found != pendingStateUploadRestores.end() && found->second != nullptr &&
           found->second->settled && found->second->container != nullptr &&
           found->second->container->pendingDestroy == false && found->second->container->pid == pid &&
           isPendingContainerLaunch(uuid);
  }

  String containerArtifactStoreRoot(void) const override { return root; }
  void receivedContainerArtifactFinished(uint64_t, bool adopted, bool sourceCurrent) override
  {
    ++artifactFinishes;
    lastArtifactAdopted = adopted;
    lastArtifactSourceCurrent = sourceCurrent;
  }
  void pushContainer(Container *container) override
  {
    ++publishedContainers;
    if (useBaseGatewayPublication) { Neuron::pushContainer(container); return; }
    publishedContainerOwners.emplace_back(container);
  }
  void queueRestoredStateUploadContainerWaitid(Container *) override { ++restoredWaitidCalls; }
  void popContainer(Container *container) override
  {
    if (container == nullptr) return;
    containers.erase(container->plan.uuid);
    if (container->pid > 0) containerByPid.erase(container->pid);
    RingDispatcher::eraseMultiplexee(container);
  }
  void queueContainerKillAck(uint128_t containerUUID) override
  {
    ++killAcknowledgements;
    lastKillAcknowledgement = containerUUID;
  }
  void downloadContainer(CoroutineStack *, uint64_t) override {}
  bool ensureHostNetworkingReady(String *failure = nullptr) override
  {
    if (failure) failure->clear();
    return true;
  }

  void releasePublishedContainersAfterRingShutdownForTest()
  {
    publishedContainerOwners.clear();
  }

  bool startForArtifactTest(const String& storeRoot)
  {
    root.assign(storeRoot);
    artifactIO = ProdigyArtifactIO::startOwned();
    if (!artifactIO) return false;
    brain = new NeuronBrainControlStream();
    brain->connected = true;
    brain->fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    return brain->fd >= 0;
  }

  bool submit(uint64_t deploymentID, String&& blob)
  {
    return queueReceivedContainerArtifact(brain, deploymentID, std::move(blob));
  }

  void replaceBrainWithoutClosing(void)
  {
    if (brain != nullptr)
    {
      fenceStateUploadRestoresForControl(brain);
      resetContainerLaunchControlForBrainReplacement();
    }
    if (retained != nullptr) retired.push_back(retained);
    retained = brain;
    brain = new NeuronBrainControlStream();
    brain->connected = true;
    brain->fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  }

  void retainPendingDownload(uint64_t deploymentID)
  {
    pendingContainerDownloads.insert(deploymentID, nullptr);
  }

  bool hasPendingDownload(uint64_t deploymentID)
  {
    return pendingContainerDownloads.contains(deploymentID);
  }

  bool stored(uint64_t deploymentID, const String& expectedBlob) const
  {
    String path = ContainerStore::pathForContainerImage(deploymentID, &root);
    struct stat metadata = {};
    if (::stat(path.c_str(), &metadata) != 0 || S_ISREG(metadata.st_mode) == false) return false;
    String storedBlob = {};
    Filesystem::openReadAtClose(-1, path, storedBlob);
    if (storedBlob.size() != expectedBlob.size()) return false;
    String expectedDigest = {};
    String storedDigest = {};
    return prodigyComputeSHA256Hex(expectedBlob, expectedDigest) &&
           prodigyComputeSHA256Hex(storedBlob, storedDigest) && expectedDigest == storedDigest;
  }

  bool artifactFinished(void) const { return artifactFinishes > 0; }

  bool quiesceArtifactIOForTest()
  {
    if (artifactIO == nullptr) return true;
    if (quiesceArtifactIOForBundleExec() == false) return false;
    artifactIO.reset();
    return true;
  }

  bool replacementQueuesPendingDownload(uint64_t deploymentID)
  {
    installedBundleDigest.assign("test-installed-bundle-digest"_ctv);
    installedBundleDigestReady = true;
    brain->pendingSend = true; // Inspect the same accepted-stream queue before I/O submission.
    queueAttestedInitialBrainControlFrames(brain);
    bool requested = false;
    uint64_t offset = 0;
    while (offset + Message::headerBytes <= brain->wBuffer.size())
    {
      Message *message = reinterpret_cast<Message *>(brain->wBuffer.data() + offset);
      if (message->size < Message::headerBytes || offset + message->size > brain->wBuffer.size()) return false;
      if (NeuronTopic(message->topic) == NeuronTopic::requestContainerBlob)
      {
        uint8_t *args = message->args;
        uint64_t receivedDeploymentID = 0;
        Message::extractArg<ArgumentNature::fixed>(args, receivedDeploymentID);
        requested = (receivedDeploymentID == deploymentID);
      }
      offset += message->size;
    }
    return offset == brain->wBuffer.size() && requested;
  }

  std::function<void(bool)> prepareWormholeOperationReply(SwitchboardWormholeOperation operation)
  {
    return wormholeOperationReply(std::move(operation));
  }

  std::function<void(bool)> prepareWormholeContainerRefresh(Container *container)
  {
    return wormholeContainerRefresh(container);
  }

  bool buildContainerWormholeDesiredStateForTest(const ContainerPlan& plan,
                                                 const Vector<Wormhole>& wormholes,
                                                 SwitchboardWormholeDesiredState& desired)
  {
    return buildContainerWormholeDesiredState(plan, wormholes, desired);
  }

  bool strengthenWormholeDesiredStateForLocalPlanForTest(const ContainerPlan& plan,
                                                         SwitchboardWormholeDesiredState& desired)
  {
    return strengthenWormholeDesiredStateForLocalPlan(plan, desired);
  }

  void trackContainerForReplyTest(Container *container)
  {
    containers.insert_or_assign(container->plan.uuid, container);
  }

  void untrackContainerForReplyTest(uint128_t uuid)
  {
    containers.erase(uuid);
  }

  void prepareContainerReplyBuffer(Container *container)
  {
    container->wBuffer.clear();
    container->pendingSend = true; // Inspect the queued container reply without I/O.
  }

  bool readContainerWormholeRefresh(Container *container, String& serialized) const
  {
    if (container == nullptr || container->wBuffer.size() < Message::headerBytes) return false;
    Message *message = reinterpret_cast<Message *>(container->wBuffer.data());
    if (message->size != container->wBuffer.size() || ContainerTopic(message->topic) != ContainerTopic::wormholesRefresh)
      return false;
    uint8_t *args = message->args;
    Message::extractToStringView(args, serialized);
    return true;
  }

  void prepareBrainReplyBuffer(void)
  {
    brain->wBuffer.clear();
    brain->pendingSend = true; // Keep the reply in the accepted-stream buffer for inspection.
  }

  bool readWormholeOperationReply(SwitchboardWormholeOperation& operation) const
  {
    if (brain == nullptr || brain->wBuffer.size() < Message::headerBytes) return false;
    Message *message = reinterpret_cast<Message *>(brain->wBuffer.data());
    if (message->size != brain->wBuffer.size() || NeuronTopic(message->topic) != NeuronTopic::openSwitchboardWormholes)
      return false;
    uint8_t *args = message->args;
    String serialized = {};
    Message::extractToStringView(args, serialized);
    return BitseryEngine::deserializeSafe(serialized, operation);
  }

  bool replyBufferEmpty(void) const { return brain == nullptr || brain->wBuffer.size() == 0; }

  void advanceBrainGenerationForReplyTest(void) { ++brain->ioGeneration; }
  void deactivateBrainForReplyTest(void) { brain->connected = false; }
  void reactivateBrainForReplyTest(void) { brain->connected = true; }
  void expireReplyLifetimeForTest(void) { asyncOperationLifetime.reset(); }
  void restoreReplyLifetimeForTest(void) { asyncOperationLifetime = std::make_shared<uint8_t>(0); }
  void prepareBrainForArtifactTest(void)
  {
    brain->wBuffer.clear();
    brain->pendingSend = false;
    brain->connected = true;
  }

  ~TestNeuron()
  {
    // main() keeps this owner alive until quiesceForExec observes the terminal
    // raw-poll cancellation CQE. Do not destroy it beside Ring shutdown.
    if (artifactIO != nullptr) std::abort();
    if (brain && brain->fd >= 0) ::close(brain->fd);
    if (retained && retained->fd >= 0) ::close(retained->fd);
    for (NeuronBrainControlStream *stream : retired)
    {
      if (stream && stream->fd >= 0) ::close(stream->fd);
      delete stream;
    }
    delete brain;
    delete retained;
    brain = nullptr;
    retained = nullptr;
  }
};

static bool loadFixture(String& blob)
{
  const char *path = ::getenv("PRODIGY_TEST_APP_ARTIFACT");
  if (path == nullptr || path[0] == '\0') return false;
  Filesystem::openReadAtClose(-1, String(path), blob);
  String header = {};
  String headerText = prodigyDiscombobulatorBlobHeaderText();
  header.assign(blob.substr(0, headerText.size(), Copy::yes));
  String failure = {};
  return blob.size() > headerText.size() && prodigyValidateDiscombobulatorBlobHeaderText(header, &failure);
}

static void runRingUntil(ArtifactRing& ring, const std::function<bool()>& done)
{
  Ring::exit = false;
  TimeoutPacket tick = {};
  class Tick final : public TimeoutDispatcher {
  public:
    TimeoutPacket *packet = nullptr;
    std::function<bool()> done = {};
    void dispatchTimeout(TimeoutPacket *) override
    {
      if (done()) { Ring::exit = true; return; }
      packet->clear();
      packet->setTimeoutMs(5);
      Ring::queueTimeout(packet);
    }
  } tickDispatcher;
  tick.dispatcher = &tickDispatcher;
  tickDispatcher.packet = &tick;
  tickDispatcher.done = done;
  tick.setTimeoutMs(5);
  Ring::queueTimeout(&tick);
  ring.arm(1500);
  Ring::start();
  Ring::exit = false;
}

class ArtifactMaterializationTask final {
public:
  bool completed = false;
  bool result = true;
  String failure = {};

  void start(Container *container, const String& path, uint64_t admissionGeneration)
  {
    result = co_await ContainerManager::materializeContainerArtifactAsync(
        container, path.substr(0, path.size(), Copy::yes), admissionGeneration, &failure);
    completed = true;
  }
};

class ArtifactMaterializationPulse final : public TimeoutDispatcher {
public:
  std::atomic<bool> *workerEntered = nullptr;
  ArtifactMaterializationTask *task = nullptr;
  bool firedWhileWorkerBlocked = false;

  void dispatchTimeout(TimeoutPacket *) override
  {
    // The operation itself must still be suspended behind the worker. An
    // inline implementation can leave an unrelated worker busy yet complete
    // this launch before the Ring gets its timer turn.
    firedWhileWorkerBlocked = workerEntered != nullptr && workerEntered->load() &&
        task != nullptr && task->completed == false;
  }
};

static bool waitForArtifactWorker(std::atomic<bool>& entered)
{
  for (uint32_t attempt = 0; attempt != 100; ++attempt)
  {
    if (entered.load()) return true;
    usleep(1'000);
  }
  return entered.load();
}

static void testContainerMaterializationYieldsRingAndFencesRetirement(TestSuite& suite)
{
  ScopedArtifactStore store = {};
  ArtifactRing ring = {};
  TestNeuron neuron = {};
  NeuronBase *savedNeuron = thisNeuron;
  thisNeuron = &neuron;
  const bool started = store.root.size() != 0 && neuron.startForArtifactTest(store.root);
  suite.expect(started, "container_materialization_test_starts_artifact_worker");
  if (!started)
  {
    thisNeuron = savedNeuron;
    return;
  }

  auto queueBlocker = [&](std::atomic<bool>& entered) {
    ProdigyArtifactIO *io = neuron.containerArtifactIO();
    return io != nullptr && io->submit(
        0,
        [&entered] { entered.store(true); usleep(250'000); },
        [] {},
        [](std::exception_ptr) {});
  };
  auto queuePulse = [&](std::atomic<bool>& entered, ArtifactMaterializationTask& task,
                        ArtifactMaterializationPulse& pulse, TimeoutPacket& packet) {
    pulse.workerEntered = &entered;
    pulse.task = &task;
    packet.dispatcher = &pulse;
    packet.clear();
    packet.setTimeoutMs(25);
    Ring::queueTimeout(&packet);
  };

  Container valid = {};
  valid.plan.uuid = uint128_t(0xc011a001);
  valid.name.assignItoa(valid.plan.uuid);
  const uint64_t validGeneration = neuron.beginPendingContainerLaunch(valid.plan);
  std::atomic<bool> validWorkerEntered {false};
  suite.expect(validGeneration != 0 && queueBlocker(validWorkerEntered) && waitForArtifactWorker(validWorkerEntered),
               "container_materialization_test_queues_blocking_predecessor");
  ArtifactMaterializationTask validTask = {};
  validTask.start(&valid, "/prodigy-unit-intentionally-absent-image"_ctv, validGeneration);
  ArtifactMaterializationPulse validPulse = {};
  TimeoutPacket validPacket = {};
  queuePulse(validWorkerEntered, validTask, validPulse, validPacket);
  runRingUntil(ring, [&] { return validTask.completed; });
  suite.expect(ring.timedOut == false && validPulse.firedWhileWorkerBlocked,
               "container_materialization_worker_leaves_ring_timers_responsive");
  suite.expect(validTask.completed && !validTask.result && validTask.failure.size() > 0 &&
                   neuron.isPendingContainerLaunch(valid.plan.uuid),
               "container_materialization_valid_admission_reports_worker_failure_without_retiring_launch");
  neuron.finishPendingContainerLaunch(valid.plan.uuid, validGeneration);

  ring.timedOut = false;
  Container stale = {};
  stale.plan.uuid = uint128_t(0xc011a002);
  stale.name.assignItoa(stale.plan.uuid);
  const uint64_t staleGeneration = neuron.beginPendingContainerLaunch(stale.plan);
  std::atomic<bool> staleWorkerEntered {false};
  suite.expect(staleGeneration != 0 && queueBlocker(staleWorkerEntered) && waitForArtifactWorker(staleWorkerEntered),
               "container_materialization_test_queues_stale_predecessor");
  ArtifactMaterializationTask staleTask = {};
  staleTask.start(&stale, "/prodigy-unit-intentionally-absent-image"_ctv, staleGeneration);
  neuron.finishPendingContainerLaunch(stale.plan.uuid, staleGeneration);
  ArtifactMaterializationPulse stalePulse = {};
  TimeoutPacket stalePacket = {};
  queuePulse(staleWorkerEntered, staleTask, stalePulse, stalePacket);
  runRingUntil(ring, [&] { return staleTask.completed; });
  suite.expect(ring.timedOut == false && stalePulse.firedWhileWorkerBlocked,
               "container_materialization_retired_launch_still_leaves_ring_timers_responsive");
  suite.expect(staleTask.completed && !staleTask.result && !neuron.isPendingContainerLaunch(stale.plan.uuid) &&
                   staleTask.failure.equal("container launch retired during artifact preparation"_ctv),
               "container_materialization_retired_launch_rejects_late_worker_completion_and_finishes_admission");

  ring.timedOut = false;
  runRingUntil(ring, [&] { return neuron.quiesceArtifactIOForTest(); });
  suite.expect(ring.timedOut == false, "container_materialization_test_quiesces_artifact_worker_before_ring_shutdown");
  thisNeuron = savedNeuron;
}

static void testRetainedGatewayRecoveryAdmission(TestSuite& suite)
{
  ArtifactRing ring = {};
  ScopedArtifactStore store = {};
  const uint128_t retainedUUID = uint128_t(0xa551f002);
  String retainedName = {}; retainedName.assignItoa(retainedUUID);
  const std::filesystem::path runtimeDirectory =
      std::filesystem::path("/run/prodigy/containers") / retainedName.c_str();
  std::error_code cleanupError = {};
  std::filesystem::remove_all(runtimeDirectory, cleanupError);
  std::filesystem::create_directories(runtimeDirectory, cleanupError);
  chmod(runtimeDirectory.c_str(), 0711);
  const std::filesystem::path recoveryRecordDirectory =
      store.root.empty() ? std::filesystem::path() : std::filesystem::path(store.root.c_str()) / retainedName.c_str();
  if (!recoveryRecordDirectory.empty()) {
    std::filesystem::create_directories(recoveryRecordDirectory, cleanupError);
    if (!cleanupError) chmod(recoveryRecordDirectory.c_str(), 0711);
  }
  const int recoveryRootFD = store.root.empty() ? -1 :
      open(store.root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  suite.expect(recoveryRootFD >= 0 && !cleanupError,
               "neuron_retained_gateway_recovery_fixture_roots_created");
  if (recoveryRootFD < 0 || cleanupError) {
    if (recoveryRootFD >= 0) close(recoveryRootFD);
    std::filesystem::remove_all(runtimeDirectory, cleanupError);
    ring.shutdownRing();
    return;
  }

  auto authority = [] {
    CrossClusterMasqueGatewayAuthority value = {};
    value.pairUUID = 0x8101; value.pairOperationUUID = 0x8102;
    value.localClusterUUID = 0x8103; value.peerClusterUUID = 0x8104;
    value.localMachineUUID = 0x8105; value.peerMachineUUID = 0x8106;
    value.localDatacenterFragment = 1; value.peerDatacenterFragment = 2;
    value.localSitePrefix = prodigyContainerDatacenterSitePrefix(1);
    value.peerSitePrefix = prodigyContainerDatacenterSitePrefix(2);
    value.artifactSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
    value.artifactBytes = 1;
    value.listenerPublicUDPEndpoint = IPAddress("2001:db8::10", true);
    value.listenerPublicUDPPort = 4433; value.tunnelSlot = 0; value.gatewaySlot = 0;
    value.privateTunnelInterface.assign("mtbgpstate0"_ctv);
    value.privateTunnelLocalIPv6 = IPAddress("fd5a:4d53::1", true);
    value.privateTunnelPeerIPv6 = IPAddress("fd5a:4d53::2", true);
    value.privateLocalASN = 42001; value.privatePeerASN = 42002;
    value.privateLocalBGPID = 1; value.privatePeerBGPID = 2;
    value.privateSessionCredentialSHA256.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
    value.localIdentitySHA256.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
    value.peerIdentitySHA256.assign("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv);
    value.peerTrustSHA256.assign("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"_ctv);
    value.generation = 6; value.pairAuthorityGeneration = 5; value.keyGeneration = 4;
    value.localRole = CrossClusterMasqueGatewayRole::listener;
    value.state = CrossClusterMasqueGatewayState::active;
    return value;
  }();
  auto makePlan = [&](uint128_t uuid, ContainerPlan& plan) {
    Vector<CrossClusterMasqueGatewayAuthority> authorities = {authority};
    plan = {}; plan.uuid = uuid; plan.createdAtMs = 1; plan.restartOnFailure = true;
    plan.fragment = prodigyCrossClusterMasqueGatewayRuntimeFragment(
        authorities, authority.pairUUID, authority.localMachineUUID);
    plan.system.kind = SystemContainerKind::crossClusterMasqueGateway;
    plan.config.capabilities.insert(CAP_NET_ADMIN);
    plan.system.artifact.sha256.assign(authority.artifactSHA256);
    plan.system.artifact.bytes = authority.artifactBytes;
    plan.system.egress = prodigyCrossClusterMasqueGatewayEgressPolicy(authority);
    plan.state = ContainerState::scheduled; plan.requiresDatacenterUniqueTag = true;
    return prodigyCrossClusterMasqueGatewayWormholes(authority, plan.wormholes) &&
        prodigyBindCrossClusterMasqueGatewayRuntimePlanAuthority(plan.system, authority);
  };
  ContainerPlan plan = {};
  String token = "0123456789abcdef0123456789abcdef"_ctv;
  suite.expect(makePlan(retainedUUID, plan) &&
                   ContainerManagerGatewayRecoveryTestAccess::writeRecordAt(recoveryRootFD, plan, token),
               "neuron_retained_gateway_recovery_fixture_has_exact_authority_plan_and_durable_token");

  TestNeuron neuron = {};
  neuron.gatewayRecoveryRuntimeRootFD = recoveryRootFD;
  neuron.replaceBrainWithoutClosing();
  suite.expect(neuron.installGatewayAuthorityForStateUploadTest(authority) &&
                   neuron.gatewayRuntimeOwnerForTest(authority.pairUUID, 0, false),
               "neuron_retained_gateway_recovery_starts_with_authority_but_no_launch_owner");
  auto candidate = std::make_unique<Container>();
  candidate->plan = plan; candidate->name = retainedName; candidate->pid = getpid();
  candidate->pidfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  neuron.configureRetainedGatewayPeerIdentityForTest(*candidate);
  suite.expect(candidate->pidfd >= 0 && neuron.beginStateUploadRestoreForTest(std::move(candidate), 1) &&
                   neuron.restoreSubmissions == 1 && bool(neuron.pendingRestoreCompletion),
               "neuron_retained_gateway_recovery_begins_exact_network_adoption_once");
  auto completed = std::exchange(neuron.pendingRestoreCompletion, {});
  if (completed) completed(true);
  uint64_t initialEpoch = 0; bool networkRestored = false, listenerArmed = false;
  suite.expect(neuron.gatewayRuntimeOwnerForTest(authority.pairUUID, retainedUUID, true) &&
                   neuron.retainedGatewayRestoreStateForTest(retainedUUID, initialEpoch, networkRestored, listenerArmed) &&
                   networkRestored && listenerArmed && neuron.publishedContainers == 0,
               "neuron_retained_gateway_recovery_binds_unowned_runtime_and_arms_exact_listener_before_publication");
  suite.expect(neuron.admitRestoreReplayForTest(plan),
               "neuron_retained_gateway_recovery_replay_admits_same_authoritative_plan");
  uint64_t replayEpoch = 0; bool replayNetworkRestored = false, replayListenerArmed = false;
  suite.expect(neuron.restoreSubmissions == 1 && !neuron.pendingRestoreCompletion &&
                   neuron.retainedGatewayRestoreStateForTest(retainedUUID, replayEpoch, replayNetworkRestored, replayListenerArmed) &&
                   replayEpoch == initialEpoch && replayNetworkRestored && replayListenerArmed,
               "neuron_retained_gateway_recovery_replay_preserves_epoch_listener_and_network_adoption");

  TestNeuron foreign = {};
  foreign.gatewayRecoveryRuntimeRootFD = recoveryRootFD;
  foreign.replaceBrainWithoutClosing();
  suite.expect(foreign.installGatewayAuthorityForStateUploadTest(authority),
               "neuron_retained_gateway_recovery_foreign_owner_authority_installed");
  const uint128_t foreignUUID = uint128_t(0xa551f003);
  foreign.assignGatewayRuntimeOwnerForTest(authority.pairUUID, foreignUUID, true);
  auto foreignCandidate = std::make_unique<Container>();
  foreignCandidate->plan = plan; foreignCandidate->name = retainedName; foreignCandidate->pid = getpid();
  foreignCandidate->pidfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  foreign.configureRetainedGatewayPeerIdentityForTest(*foreignCandidate);
  suite.expect(foreign.beginStateUploadRestoreForTest(std::move(foreignCandidate), 1) &&
                   bool(foreign.pendingRestoreCompletion),
               "neuron_retained_gateway_recovery_foreign_owner_candidate_is_fenced_for_check");
  auto foreignCompleted = std::exchange(foreign.pendingRestoreCompletion, {});
  if (foreignCompleted) foreignCompleted(true);
  uint64_t foreignEpoch = 0; bool foreignNetworkRestored = false, foreignListenerArmed = false;
  suite.expect(foreign.gatewayRuntimeOwnerForTest(authority.pairUUID, foreignUUID, true) &&
                   foreign.retainedGatewayRestoreStateForTest(retainedUUID, foreignEpoch, foreignNetworkRestored, foreignListenerArmed) &&
                   !foreignListenerArmed && foreign.publishedContainers == 0,
               "neuron_retained_gateway_recovery_foreign_runtime_owner_never_rebinds_or_publishes_candidate");

  neuron.cleanupRetainedGatewayRecoveryForTest(retainedUUID);
  foreign.cleanupRetainedGatewayRecoveryForTest(retainedUUID);
  close(recoveryRootFD);
  std::filesystem::remove_all(runtimeDirectory, cleanupError);
  ring.shutdownRing();
}

static void testGatewayPrivateBGPWithdrawalIdempotence(TestSuite& suite)
{
  ArtifactRing ring = {};
  CrossClusterMasqueGatewayAuthority authority = {};
  authority.pairUUID = 0x9101; authority.pairOperationUUID = 0x9102;
  authority.localClusterUUID = 0x9103; authority.peerClusterUUID = 0x9104;
  authority.localMachineUUID = 0x9105; authority.peerMachineUUID = 0x9106;
  authority.localDatacenterFragment = 1; authority.peerDatacenterFragment = 2;
  authority.localSitePrefix = prodigyContainerDatacenterSitePrefix(1);
  authority.peerSitePrefix = prodigyContainerDatacenterSitePrefix(2);
  authority.artifactSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  authority.artifactBytes = 1;
  authority.listenerPublicUDPEndpoint = IPAddress("2001:db8::10", true);
  authority.listenerPublicUDPPort = 4433;
  authority.tunnelSlot = 0; authority.gatewaySlot = 0;
  authority.privateTunnelInterface.assign("mtbgpwithdraw0"_ctv);
  authority.privateTunnelLocalIPv6 = IPAddress("fd5a:4d53::1", true);
  authority.privateTunnelPeerIPv6 = IPAddress("fd5a:4d53::2", true);
  authority.privateLocalASN = 42001; authority.privatePeerASN = 42002;
  authority.privateLocalBGPID = 1; authority.privatePeerBGPID = 2;
  authority.privateSessionCredentialSHA256.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  authority.localIdentitySHA256.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
  authority.peerIdentitySHA256.assign("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv);
  authority.peerTrustSHA256.assign("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"_ctv);
  authority.generation = 6; authority.pairAuthorityGeneration = 5; authority.keyGeneration = 4;
  authority.localRole = CrossClusterMasqueGatewayRole::listener;
  authority.state = CrossClusterMasqueGatewayState::active;
  const ProdigyPairPrivateBGPSecretScope scope = {
      authority.pairUUID, authority.pairOperationUUID, authority.keyGeneration,
      authority.tunnelSlot, authority.localClusterUUID, authority.localMachineUUID,
      authority.pairAuthorityGeneration, authority.generation};
  TestNeuron neuron = {};
  bool firstAcknowledged = false, repeatedAcknowledged = false, newerRejected = false;
  const bool prepared = neuron.prepareGatewayPrivateBGPWithdrawalForTest(authority);
  const bool firstParsed = prepared && neuron.withdrawGatewayPrivateBGPForTest(scope, firstAcknowledged);
  const bool repeatedParsed = firstParsed && neuron.withdrawGatewayPrivateBGPForTest(scope, repeatedAcknowledged);
  auto newer = scope; ++newer.authorityGeneration;
  const bool newerParsed = repeatedParsed && neuron.withdrawGatewayPrivateBGPForTest(newer, newerRejected);
  suite.expect(firstParsed && repeatedParsed && newerParsed && firstAcknowledged && repeatedAcknowledged && !newerRejected,
               "neuron_gateway_private_bgp_withdrawal_acknowledges_exact_empty_owner_idempotently_and_rejects_newer_authority");

  TestNeuron absent = {};
  bool absentAcknowledged = false;
  suite.expect(absent.prepareGatewayPrivateBGPWithdrawalForTest(authority),
               "neuron_gateway_private_bgp_withdrawal_absent_scope_fixture_is_authenticated");
  absent.forgetGatewayPrivateBGPRuntimeForTest();
  Container anchored = {};
  anchored.plan.uuid = 0x9107;
  anchored.plan.system.kind = SystemContainerKind::crossClusterMasqueGateway;
  anchored.plan.system.gatewayPairUUID = scope.pairUUID;
  anchored.plan.system.gatewayLocalClusterUUID = scope.clusterUUID;
  anchored.plan.system.gatewayLocalMachineUUID = scope.machineUUID;
  anchored.plan.system.gatewayKeyEpoch = scope.keyEpoch;
  anchored.plan.system.gatewayAuthorityGeneration = scope.authorityGeneration;
  anchored.plan.system.gatewayGeneration = scope.gatewayGeneration;
  absent.trackContainerForReplyTest(&anchored);
  bool anchoredAcknowledged = true;
  const bool anchoredParsed = absent.withdrawGatewayPrivateBGPForTest(scope, anchoredAcknowledged);
  absent.untrackContainerForReplyTest(anchored.plan.uuid);
  const bool absentParsed = absent.withdrawGatewayPrivateBGPForTest(scope, absentAcknowledged);
  suite.expect(anchoredParsed && !anchoredAcknowledged && absentParsed && absentAcknowledged,
               "neuron_gateway_private_bgp_withdrawal_requires_exactly_absent_gateway_scope");
  ring.shutdownRing();
}

int main()
{
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY");
      only != nullptr && strcmp(only, "gateway-private-bgp-withdrawal-idempotence") == 0)
  {
    TestSuite suite = {};
    testGatewayPrivateBGPWithdrawalIdempotence(suite);
    std::printf("GATEWAY_PRIVATE_BGP_WITHDRAWAL_IDEMPOTENCE_RESULT failed_assertions=%d\n", suite.failed);
    return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  }
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY");
      only != nullptr && strcmp(only, "gateway-retained-recovery-admission") == 0)
  {
    TestSuite suite = {};
    testRetainedGatewayRecoveryAdmission(suite);
    std::printf("GATEWAY_RETAINED_RECOVERY_ADMISSION_RESULT failed_assertions=%d\n", suite.failed);
    return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  }
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY");
      only != nullptr && strcmp(only, "container-materialization-async") == 0)
  {
    TestSuite suite = {};
    testContainerMaterializationYieldsRingAndFencesRetirement(suite);
    std::printf("CONTAINER_MATERIALIZATION_ASYNC_RESULT failed_assertions=%d\n", suite.failed);
    return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  }
  TestSuite suite = {};
  const bool gatewayStateUploadRecoveryOnly =
      std::getenv("PRODIGY_TEST_GATEWAY_STATE_UPLOAD_RECOVERY_ONLY") != nullptr;
  const bool gatewayRebindRecoveryOnly =
      std::getenv("PRODIGY_TEST_GATEWAY_REBIND_RECOVERY_ONLY") != nullptr;
  String fixture = {};
  bool hasArtifactFixture = false;
  ScopedArtifactStore store = {};
  if (gatewayStateUploadRecoveryOnly || gatewayRebindRecoveryOnly) goto gateway_state_upload_recovery;
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressWitnessMatches(
          10713, 10713, 12, BPF_PROG_TYPE_XDP, "bal_ingress", 0x5a),
      "neuron_retained_additional_ingress_accepts_exact_preexec_primary_xdp");
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressWitnessMatches(
          10713, 10923, 12, BPF_PROG_TYPE_XDP, "bal_ingress", 0x5a) == false,
      "neuron_retained_additional_ingress_rejects_reconnected_or_replaced_xdp");
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressWitnessMatches(
          10713, 10713, 12, BPF_PROG_TYPE_XDP, "foreign_xdp", 0x5a) == false,
      "neuron_retained_additional_ingress_rejects_unknown_xdp");
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressMatchesCurrentFamily(10713, 10923, 12, 0x5a, 0x5a),
      "neuron_retained_additional_ingress_accepts_orphaned_prior_family_after_exec");
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressMatchesCurrentFamily(10713, 10923, 12, 0x5a, 0x6b) == false,
      "neuron_retained_additional_ingress_rejects_foreign_compiled_family");
  {
    ArtifactRing lazySwitchboardRing = {};
    TestNeuron lazySwitchboardNeuron = {};
    lazySwitchboardNeuron.assignFragmentForLazySwitchboardTest(9, 4, 5, 6);
    Switchboard *lazySwitchboard = lazySwitchboardNeuron.createLazySwitchboardForTest();
    const local_container_subnet6& seeded = SwitchboardRingTestAccess::subnet(*lazySwitchboard);
    suite.expect(lazySwitchboard != nullptr && seeded.dpfx == 9 && seeded.mpfx[0] == 4 &&
                     seeded.mpfx[1] == 5 && seeded.mpfx[2] == 6,
                 "neuron_lazy_switchboard_receives_existing_fragment_before_optional_ingress");
    BPFProgram retainedRouter = {};
    EthDevice selectedIngress = {};
    SwitchboardRingTestAccess::setBoundaryConsumer(*lazySwitchboard, &retainedRouter, &selectedIngress);
    lazySwitchboard->resetState();
    suite.expect(lazySwitchboard->boundaryRouterProgram() == &retainedRouter,
                 "switchboard_reset_preserves_router_used_by_selected_ingress");
    SwitchboardRingTestAccess::setBoundaryConsumer(*lazySwitchboard, &retainedRouter, nullptr);
    lazySwitchboard->resetState();
    suite.expect(lazySwitchboard->boundaryRouterProgram() == nullptr,
                 "switchboard_reset_releases_router_without_remaining_consumers");
    SwitchboardRingTestAccess::setBoundaryConsumer(*lazySwitchboard, &retainedRouter, &selectedIngress);
    lazySwitchboardNeuron.detachAdditionalIngressForShutdown();
    suite.expect(SwitchboardRingTestAccess::hasAdditionalIngress(*lazySwitchboard) == false,
                 "neuron_shutdown_detaches_additional_ingress_before_guardian_exit");
    lazySwitchboardNeuron.detachAdditionalIngressForShutdown();
    suite.expect(SwitchboardRingTestAccess::hasAdditionalIngress(*lazySwitchboard) == false,
                 "neuron_shutdown_additional_ingress_detach_is_idempotent");
  }
  hasArtifactFixture = loadFixture(fixture);
  if (!hasArtifactFixture)
  {
    suite.expect(false, "neuron_artifact_fixture_requires_PRODIGY_TEST_APP_ARTIFACT");
  }
  suite.expect(store.root.size() > 0, "neuron_artifact_private_store_created");

gateway_state_upload_recovery:
  // This selector is intentionally offline. It exercises one temporary local
  // Unix listener plus the exact held-carrier bytes without a NeuronHub
  // stream, launcher, external network, container namespace, or BPF path.
  if (gatewayRebindRecoveryOnly)
  {
    int pair[2] = {-1, -1};
    const String token = "0123456789abcdef0123456789abcdef"_ctv;
    ProdigyGatewayLocalTuple tuple = {};
    tuple.pairUUID = 1; tuple.localClusterUUID = 2; tuple.localMachineUUID = 3;
    tuple.keyEpoch = 4; tuple.authorityGeneration = 5; tuple.gatewayGeneration = 6;
    ProdigyGatewayLocalControlFrame hello = {};
    hello.direction = ProdigyGatewayLocalDirection::gatewayToNeuron;
    hello.kind = ProdigyGatewayLocalKind::rebindHello;
    hello.rebindHello.recoveryToken = token; hello.rebindHello.tuple = tuple;
    String encoded = {}; uint8_t received[512] = {};
    const bool socketReady = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0 &&
        prodigyEncodeGatewayLocalControlFrame(hello, encoded) &&
        write(pair[0], encoded.data(), encoded.size()) == ssize_t(encoded.size()) &&
        read(pair[1], received, sizeof(received)) == ssize_t(encoded.size());
    ProdigyGatewayLocalControlFrame decoded = {};
    ProdigyGatewayLocalCarrierMode mode = ProdigyGatewayLocalCarrierMode::undecided;
    suite.expect(socketReady && prodigyGatewayLocalCarrierLockMode(mode, received, uint32_t(encoded.size()), true) &&
                     mode == ProdigyGatewayLocalCarrierMode::v2 &&
                     prodigyDecodeGatewayLocalControlFrame(received, uint32_t(encoded.size()), decoded) &&
                     prodigyGatewayLocalControlFrameAllowed(mode, ProdigyGatewayLocalCarrierPhase::rebindHello, decoded) &&
                     decoded.rebindHello.recoveryToken == token,
                 "neuron_gateway_rebind_socketpair_accepts_exact_v2_hello_only");
    ProdigyGatewayLocalControlFrame challenge = {};
    challenge.direction = ProdigyGatewayLocalDirection::neuronToGateway;
    challenge.kind = ProdigyGatewayLocalKind::rebindChallenge; challenge.rebindChallenge.tuple = tuple;
    challenge.rebindChallenge.nonce[0] = 1;
    ProdigyGatewayLocalControlFrame receipt = {};
    receipt.direction = ProdigyGatewayLocalDirection::gatewayToNeuron;
    receipt.kind = ProdigyGatewayLocalKind::rebindReceipt; receipt.rebindReceipt.tuple = tuple;
    memcpy(receipt.rebindReceipt.nonce, challenge.rebindChallenge.nonce, sizeof(challenge.rebindChallenge.nonce));
    receipt.rebindReceipt.authenticatedMasqueQUICReady = true; receipt.rebindReceipt.ready = true;
    receipt.rebindReceipt.routeSetSHA256.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
    suite.expect(prodigyGatewayLocalNonceValid(challenge.rebindChallenge.nonce) &&
                     prodigyGatewayLocalControlFrameValid(receipt) &&
                     prodigyGatewayLocalControlFrameAllowed(mode, ProdigyGatewayLocalCarrierPhase::rebindReceipt, receipt),
                 "neuron_gateway_rebind_challenge_is_nonzero_and_exact_receipt_is_ready");
    receipt.rebindReceipt.nonce[0] ^= 1;
    hello.rebindHello.recoveryToken.assign("fedcba9876543210fedcba9876543210"_ctv);
    hello.rebindHello.tuple.gatewayGeneration++;
    suite.expect(hello.rebindHello.recoveryToken != token && hello.rebindHello.tuple.gatewayGeneration != tuple.gatewayGeneration &&
                     memcmp(receipt.rebindReceipt.nonce, challenge.rebindChallenge.nonce, sizeof(challenge.rebindChallenge.nonce)) != 0,
                 "neuron_gateway_rebind_token_tuple_nonce_identity_authority_epoch_and_duplicate_fences_are_explicit");
    auto recoveryAuthority = [] {
      CrossClusterMasqueGatewayAuthority authority = {};
      authority.pairUUID = 1; authority.pairOperationUUID = 7; authority.localClusterUUID = 2; authority.peerClusterUUID = 8;
      authority.localMachineUUID = 3; authority.peerMachineUUID = 9; authority.localDatacenterFragment = 1; authority.peerDatacenterFragment = 2;
      authority.localSitePrefix = prodigyContainerDatacenterSitePrefix(1); authority.peerSitePrefix = prodigyContainerDatacenterSitePrefix(2);
      authority.artifactSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv); authority.artifactBytes = 1;
      authority.listenerPublicUDPEndpoint = IPAddress("2001:db8::10", true); authority.listenerPublicUDPPort = 4433;
      authority.privateTunnelInterface.assign("mtbgpstate0"_ctv); authority.privateTunnelLocalIPv6 = IPAddress("fd5a:4d53::1", true); authority.privateTunnelPeerIPv6 = IPAddress("fd5a:4d53::2", true);
      authority.privateLocalASN = 42001; authority.privatePeerASN = 42002; authority.privateLocalBGPID = 1; authority.privatePeerBGPID = 2;
      authority.privateSessionCredentialSHA256.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
      authority.localIdentitySHA256.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
      authority.peerIdentitySHA256.assign("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv);
      authority.peerTrustSHA256.assign("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"_ctv);
      authority.generation = 6; authority.pairAuthorityGeneration = 5; authority.keyGeneration = 4;
      authority.localRole = CrossClusterMasqueGatewayRole::listener; authority.state = CrossClusterMasqueGatewayState::active;
      return authority;
    }();
    TestNeuron listenerRecovery = {};
    const auto listenerProof = listenerRecovery.gatewayRecoveryListenerPeerProofForTest(store.root, token, tuple);
    suite.expect(listenerProof.opened && listenerProof.procIdentityCaptured && listenerProof.accepted &&
                     listenerProof.peerExact && listenerProof.changedIdentityRejected && listenerProof.cleaned,
                 "neuron_gateway_rebind_real_listener_accepts_exact_peer_and_rejects_changed_identity");
    ArtifactRing recoveryTransitionRing = {};
    TestNeuron acceptedRecovery = {};
    const auto acceptedTransition = acceptedRecovery.processGatewayRecoveryTransitionForTest(
        recoveryAuthority, token, TestNeuron::GatewayRecoveryFault::none);
    suite.expect(acceptedTransition.challengeIssued && acceptedTransition.receiptAccepted &&
                     acceptedTransition.pathFaultAccepted && acceptedTransition.sends == 1 && acceptedTransition.recvs == 3 && acceptedTransition.closes == 0 &&
                     acceptedRecovery.publishedContainers == 1 && acceptedTransition.basePublished &&
                     acceptedTransition.recoveryLeasePreserved && acceptedTransition.waitidCalls == 1 &&
                     !acceptedTransition.retainedCandidate && !acceptedTransition.pendingLaunch,
                 "neuron_gateway_rebind_exact_receipt_base_publication_preserves_one_recovery_listener_carrier_and_waitid_owner");
    const std::vector<TestNeuron::GatewayRecoveryFault> recoveryPrepublicationFaults = {
      TestNeuron::GatewayRecoveryFault::helloToken, TestNeuron::GatewayRecoveryFault::helloTuple,
      TestNeuron::GatewayRecoveryFault::nonceFailure, TestNeuron::GatewayRecoveryFault::nonceZero,
      TestNeuron::GatewayRecoveryFault::receiptNonce, TestNeuron::GatewayRecoveryFault::identity,
      TestNeuron::GatewayRecoveryFault::authority, TestNeuron::GatewayRecoveryFault::epoch,
      TestNeuron::GatewayRecoveryFault::brainGeneration, TestNeuron::GatewayRecoveryFault::fragment,
      TestNeuron::GatewayRecoveryFault::launchGeneration, TestNeuron::GatewayRecoveryFault::candidatePID,
      TestNeuron::GatewayRecoveryFault::candidatePidfd, TestNeuron::GatewayRecoveryFault::brainPointer,
      TestNeuron::GatewayRecoveryFault::boundToken, TestNeuron::GatewayRecoveryFault::unsettled,
      TestNeuron::GatewayRecoveryFault::malformed,
      TestNeuron::GatewayRecoveryFault::oversized, TestNeuron::GatewayRecoveryFault::coalesced};
    for (const auto fault : recoveryPrepublicationFaults) {
      TestNeuron rejectedRecovery = {};
      const auto rejected = rejectedRecovery.processGatewayRecoveryTransitionForTest(recoveryAuthority, token, fault);
      suite.expect(!rejected.receiptAccepted && rejected.closes == 1 && rejectedRecovery.publishedContainers == 0 &&
                       rejected.waitidCalls == 0 && rejected.retainedCandidate && rejected.pendingLaunch &&
                       rejected.carrierRemoved,
                   "neuron_gateway_rebind_prepublication_fault_closes_and_preserves_candidate_launch_fence");
    }
    TestNeuron duplicateRecovery = {};
    const auto duplicateTransition = duplicateRecovery.processGatewayRecoveryTransitionForTest(
        recoveryAuthority, token, TestNeuron::GatewayRecoveryFault::duplicate);
    suite.expect(duplicateTransition.receiptAccepted && duplicateTransition.closes == 1 && duplicateRecovery.publishedContainers == 1 &&
                     duplicateTransition.waitidCalls == 1 && duplicateTransition.carrierRemoved && duplicateTransition.readinessRevoked,
                 "neuron_gateway_rebind_duplicate_receipt_never_republishes_and_revokes_carrier_readiness");
    TestNeuron eofRecovery = {};
    const auto eofTransition = eofRecovery.processGatewayRecoveryTransitionForTest(
        recoveryAuthority, token, TestNeuron::GatewayRecoveryFault::eof);
    suite.expect(eofTransition.receiptAccepted && eofRecovery.publishedContainers == 1 && eofTransition.waitidCalls == 1 &&
                     eofTransition.carrierRemoved && eofTransition.readinessRevoked,
                 "neuron_gateway_rebind_eof_cleanup_revokes_carrier_readiness_without_republication");
    suite.expect(acceptedRecovery.cleanupGatewayRecoveryTransitionForTest() &&
                     duplicateRecovery.cleanupGatewayRecoveryTransitionForTest() && eofRecovery.cleanupGatewayRecoveryTransitionForTest(),
                 "neuron_gateway_rebind_base_published_test_owners_are_cleaned_before_ring_teardown");
    recoveryTransitionRing.shutdownRing();
    if (pair[0] >= 0) close(pair[0]); if (pair[1] >= 0) close(pair[1]);
  }
  if (store.root.empty())
  {
    suite.expect(false, "neuron_state_upload_gateway_private_store_created");
    return EXIT_FAILURE;
  }
  {
    TestNeuron restoreNeuron = {};
    auto first = std::make_unique<Container>();
    first->plan.uuid = uint128_t(0xA5510001);
    first->plan.fragment = 1;
    suite.expect(restoreNeuron.beginStateUploadRestoreForTest(std::move(first), 7) &&
                     restoreNeuron.restoreSubmissions == 1 &&
                     restoreNeuron.pendingStateUploadRestoreForTest(uint128_t(0xA5510001)),
                 "neuron_state_upload_restore_admission_retains_uuid_until_async_completion");

    auto duplicate = std::make_unique<Container>();
    duplicate->plan.uuid = uint128_t(0xA5510001);
    duplicate->plan.fragment = 1;
    suite.expect(restoreNeuron.beginStateUploadRestoreForTest(std::move(duplicate), 7) == false &&
                     restoreNeuron.restoreSubmissions == 1,
                 "neuron_state_upload_restore_duplicate_uuid_does_not_start_second_operation");

    suite.expect(bool(restoreNeuron.pendingRestoreCompletion),
                 "neuron_state_upload_restore_test_completion_is_held");
    restoreNeuron.pendingRestoreCompletion(true);
    suite.expect(restoreNeuron.pendingStateUploadRestoreForTest(uint128_t(0xA5510001)),
                 "neuron_state_upload_restore_stale_completion_preserves_retained_candidate");
  }
  {
    // A successful retry reaches the normal publication tail, which queues
    // retained-process observation on Ring even though this test does not run
    // the queued I/O.
    ArtifactRing restoreRing = {};
    TestNeuron failedRestore = {};
    failedRestore.replaceBrainWithoutClosing();
    auto candidate = std::make_unique<Container>();
    candidate->plan.uuid = uint128_t(0xA5510005);
    candidate->plan.fragment = 1;
    candidate->plan.restartOnFailure = true;
    // Keep this synthetic candidate outside process supervision: no real PID
    // can be observed if the publication path later acquires a pidfd seam.
    candidate->pid = -1;
    candidate->retainedPidfdWaitabilityFailed = true;
    ContainerPlan replay = candidate->plan;
    suite.expect(failedRestore.beginStateUploadRestoreForTest(std::move(candidate), 11) &&
                     bool(failedRestore.pendingRestoreCompletion),
                 "neuron_state_upload_restore_failure_admits_retained_candidate");
    auto failed = std::exchange(failedRestore.pendingRestoreCompletion, {});
    failed(false);
    suite.expect(failedRestore.restoreSubmissions == 1 && !failedRestore.restoreBarrierPendingForTest() &&
                     failedRestore.publishedContainers == 0 &&
                     failedRestore.retainedCandidatePreservedForTest(replay.uuid, -1),
                 "neuron_state_upload_restore_failure_preserves_live_process_and_launch_fence");
    suite.expect(failedRestore.admitRestoreReplayForTest(replay) &&
                     failedRestore.restoreSubmissions == 2 && failedRestore.restoreBarrierPendingForTest(),
                 "neuron_state_upload_restore_failure_retries_only_after_matching_authoritative_upload");
    auto succeeded = std::exchange(failedRestore.pendingRestoreCompletion, {});
    succeeded(true);
    suite.expect(failedRestore.publishedContainers == 1 &&
                     !failedRestore.pendingStateUploadRestoreForTest(replay.uuid),
                 "neuron_state_upload_restore_successful_retry_publishes_once");
    // The publication tail can leave Ring operations holding the raw wrapper.
    // Keep test ownership through Ring teardown, then release it explicitly.
    restoreRing.shutdownRing();
    failedRestore.releasePublishedContainersAfterRingShutdownForTest();
  }
  {
    // System gateway plans intentionally leave application config CPU fields
    // at zero; the plan owns the one-core system-container rule used at both
    // launch and retained stateUpload recovery.
    ContainerPlan gatewayPlan = {};
    gatewayPlan.system.kind = SystemContainerKind::crossClusterMasqueGateway;
    suite.expect(gatewayPlan.config.nLogicalCores == 0 &&
                     gatewayPlan.usesIsolatedCPUs() && gatewayPlan.logicalCores() == 1,
                 "neuron_state_upload_gateway_uses_plan_cpu_semantics_not_application_config");
  }
  {
    // Gateway stateUpload carries only the durable typed plan. The replacement
    // Neuron must recover the exact launch-local token from its root-owned
    // runtime record, bind it once, and keep the retained process fenced when
    // that record is absent or changes.
    ArtifactRing restoreRing = {};
    const std::filesystem::path recoveryRoot =
        std::filesystem::path(store.root.c_str()) / "gateway-recovery-runtime";
    std::filesystem::create_directories(recoveryRoot);
    chmod(recoveryRoot.c_str(), 0700);
    const int recoveryRootFD = open(recoveryRoot.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    suite.expect(recoveryRootFD >= 0, "neuron_state_upload_gateway_private_recovery_root_opened");

    auto gatewayAuthority = [] {
      CrossClusterMasqueGatewayAuthority authority = {};
      authority.pairUUID = 0x7101; authority.pairOperationUUID = 0x7102;
      authority.localClusterUUID = 0x7103; authority.peerClusterUUID = 0x7104;
      authority.localMachineUUID = 0x7105; authority.peerMachineUUID = 0x7106;
      authority.localDatacenterFragment = 1; authority.peerDatacenterFragment = 2;
      authority.localSitePrefix = prodigyContainerDatacenterSitePrefix(1);
      authority.peerSitePrefix = prodigyContainerDatacenterSitePrefix(2);
      authority.artifactSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
      authority.artifactBytes = 1;
      authority.listenerPublicUDPEndpoint = IPAddress("2001:db8::10", true);
      authority.listenerPublicUDPPort = 4433;
      authority.tunnelSlot = 0; authority.gatewaySlot = 0;
      authority.privateTunnelInterface.assign("mtbgpstate0"_ctv);
      authority.privateTunnelLocalIPv6 = IPAddress("fd5a:4d53::1", true);
      authority.privateTunnelPeerIPv6 = IPAddress("fd5a:4d53::2", true);
      authority.privateLocalASN = 42001; authority.privatePeerASN = 42002;
      authority.privateLocalBGPID = 1; authority.privatePeerBGPID = 2;
      authority.privateSessionCredentialSHA256.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
      authority.localIdentitySHA256.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
      authority.peerIdentitySHA256.assign("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv);
      authority.peerTrustSHA256.assign("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"_ctv);
      authority.generation = 6; authority.pairAuthorityGeneration = 5; authority.keyGeneration = 4;
      authority.localRole = CrossClusterMasqueGatewayRole::listener;
      authority.state = CrossClusterMasqueGatewayState::active;
      return authority;
    }();
    auto buildGatewayPlan = [&](uint128_t uuid, ContainerPlan& plan) {
      Vector<CrossClusterMasqueGatewayAuthority> authorities = {}; authorities.push_back(gatewayAuthority);
      plan = {}; plan.uuid = uuid; plan.createdAtMs = 1; plan.restartOnFailure = true;
      plan.fragment = prodigyCrossClusterMasqueGatewayRuntimeFragment(
          authorities, gatewayAuthority.pairUUID, gatewayAuthority.localMachineUUID);
      plan.system.kind = SystemContainerKind::crossClusterMasqueGateway;
      plan.config.capabilities.insert(CAP_NET_ADMIN);
      plan.system.artifact.sha256.assign(gatewayAuthority.artifactSHA256);
      plan.system.artifact.bytes = gatewayAuthority.artifactBytes;
      plan.system.egress = prodigyCrossClusterMasqueGatewayEgressPolicy(gatewayAuthority);
      plan.state = ContainerState::scheduled;
      plan.requiresDatacenterUniqueTag = true;
      return prodigyCrossClusterMasqueGatewayWormholes(gatewayAuthority, plan.wormholes) &&
          prodigyBindCrossClusterMasqueGatewayRuntimePlanAuthority(plan.system, gatewayAuthority);
    };
    auto roundTripStateUploadPlan = [](const ContainerPlan& source, ContainerPlan& decoded) {
      NeuronContainerBootstrap bootstrap = {}; bootstrap.plan = source;
      String bytes = {};
      if (!BitseryEngine::serialize(bytes, bootstrap)) return false;
      NeuronContainerBootstrap observed = {};
      if (!BitseryEngine::deserializeSafe(bytes, observed)) return false;
      decoded = std::move(observed.plan);
      return true;
    };
    auto createRecoveryDirectory = [&](uint128_t uuid, std::filesystem::path& directory) {
      String name = {}; name.assignItoa(uuid);
      directory = recoveryRoot / name.c_str();
      return std::filesystem::create_directory(directory) && chmod(directory.c_str(), 0711) == 0;
    };

    if (recoveryRootFD >= 0)
    {
      const String tokenA = "0123456789abcdef0123456789abcdef"_ctv;
      const String tokenB = "fedcba9876543210fedcba9876543210"_ctv;
      ContainerPlan durablePlan = {}, replay = {};
      std::filesystem::path runtimeDirectory = {};
      suite.expect(buildGatewayPlan(99124, durablePlan) &&
                       roundTripStateUploadPlan(durablePlan, replay) &&
                       replay.system.gatewayRecoverySocket.empty() && replay.system.gatewayRecoveryToken.empty() &&
                       createRecoveryDirectory(replay.uuid, runtimeDirectory) &&
                       ContainerManagerGatewayRecoveryTestAccess::writeRecordAt(recoveryRootFD, replay, tokenA),
                   "neuron_state_upload_gateway_fixture_has_serialized_plan_and_exact_record");

      TestNeuron gatewayRestore = {};
      gatewayRestore.gatewayRecoveryRuntimeRootFD = recoveryRootFD;
      gatewayRestore.replaceBrainWithoutClosing();
      suite.expect(gatewayRestore.installGatewayAuthorityForStateUploadTest(gatewayAuthority),
                   "neuron_state_upload_gateway_installs_typed_current_authority");
      auto candidate = std::make_unique<Container>();
      candidate->plan = replay;
      candidate->pid = -1;
      candidate->retainedPidfdWaitabilityFailed = true;
      suite.expect(gatewayRestore.beginStateUploadRestoreForTest(std::move(candidate), 14) &&
                       gatewayRestore.restoreSubmissions == 1 && bool(gatewayRestore.pendingRestoreCompletion),
                   "neuron_state_upload_gateway_initial_record_starts_one_restore");
      String socket = {}, token = {}, boundToken = {};
      bool bound = false, settled = false;
      String expectedSocket = {};
      ContainerManagerGatewayRecoveryTestAccess::socketPath(replay.uuid, expectedSocket);
      suite.expect(gatewayRestore.retainedGatewayRecoveryForTest(
                       replay.uuid, socket, token, boundToken, bound, settled) &&
                       socket == expectedSocket && token == tokenA && boundToken == tokenA && bound && !settled,
                   "neuron_state_upload_gateway_initial_plan_hydrates_and_binds_exact_token");

      ContainerPlan repeated = {};
      const std::filesystem::path recordPath = runtimeDirectory / "masque-gateway-recovery.v1";
      suite.expect(roundTripStateUploadPlan(durablePlan, repeated) && unlink(recordPath.c_str()) == 0 &&
                       ContainerManagerGatewayRecoveryTestAccess::writeRecordAt(recoveryRootFD, replay, tokenB) &&
                       gatewayRestore.admitRestoreReplayForTest(repeated) &&
                       gatewayRestore.restoreSubmissions == 1 && !gatewayRestore.restoreBarrierPendingForTest() &&
                       gatewayRestore.retainedGatewayRecoveryForTest(
                           replay.uuid, socket, token, boundToken, bound, settled) &&
                       socket.empty() && token.empty() && boundToken == tokenA && bound && settled,
                   "neuron_state_upload_gateway_changed_token_cancels_inflight_restore_and_fences");
      auto staleCompletion = std::exchange(gatewayRestore.pendingRestoreCompletion, {});
      if (staleCompletion) staleCompletion(true);
      suite.expect(gatewayRestore.restoreSubmissions == 1 && gatewayRestore.publishedContainers == 0 &&
                       gatewayRestore.retainedCandidatePreservedForTest(replay.uuid, -1),
                   "neuron_state_upload_gateway_cancelled_completion_cannot_publish");
      suite.expect(unlink(recordPath.c_str()) == 0 &&
                       gatewayRestore.admitRestoreReplayForTest(repeated) &&
                       gatewayRestore.restoreSubmissions == 1 &&
                       ContainerManagerGatewayRecoveryTestAccess::writeRecordAt(recoveryRootFD, replay, tokenA) &&
                       gatewayRestore.admitRestoreReplayForTest(repeated) &&
                       gatewayRestore.restoreSubmissions == 2 && bool(gatewayRestore.pendingRestoreCompletion),
                   "neuron_state_upload_gateway_missing_then_restored_bound_record_resumes_once");
      auto resumedFailure = std::exchange(gatewayRestore.pendingRestoreCompletion, {});
      if (resumedFailure) resumedFailure(false);
      suite.expect(gatewayRestore.admitRestoreReplayForTest(repeated) &&
                       gatewayRestore.restoreSubmissions == 3 && bool(gatewayRestore.pendingRestoreCompletion),
                   "neuron_state_upload_gateway_repeated_serialized_plan_rehydrates_same_record");
      auto repeatedFailure = std::exchange(gatewayRestore.pendingRestoreCompletion, {});
      if (repeatedFailure) repeatedFailure(false);
      suite.expect(gatewayRestore.publishedContainers == 0,
                   "neuron_state_upload_gateway_never_uses_generic_neuronhub_publication");

      ContainerPlan lateDurable = {}, lateReplay = {};
      std::filesystem::path lateRuntimeDirectory = {};
      suite.expect(buildGatewayPlan(99125, lateDurable) &&
                       roundTripStateUploadPlan(lateDurable, lateReplay) &&
                       createRecoveryDirectory(lateReplay.uuid, lateRuntimeDirectory),
                   "neuron_state_upload_gateway_late_record_fixture_created");
      TestNeuron lateRestore = {};
      lateRestore.gatewayRecoveryRuntimeRootFD = recoveryRootFD;
      lateRestore.replaceBrainWithoutClosing();
      lateRestore.assignFragmentForLazySwitchboardTest(9, 8, 7, 6);
      suite.expect(lateRestore.installGatewayAuthorityForStateUploadTest(gatewayAuthority),
                   "neuron_state_upload_gateway_late_record_authority_installed");
      auto lateCandidate = std::make_unique<Container>();
      lateCandidate->plan = lateReplay;
      lateCandidate->pid = -1;
      lateCandidate->retainedPidfdWaitabilityFailed = true;
      suite.expect(lateRestore.beginStateUploadRestoreForTest(std::move(lateCandidate), 15) &&
                       lateRestore.restoreSubmissions == 0 && !lateRestore.pendingRestoreCompletion &&
                       lateRestore.retainedGatewayRecoveryForTest(
                           lateReplay.uuid, socket, token, boundToken, bound, settled) && !bound && settled,
                   "neuron_state_upload_gateway_missing_initial_record_remains_settled_and_fenced");
      suite.expect(ContainerManagerGatewayRecoveryTestAccess::writeRecordAt(recoveryRootFD, lateReplay, tokenA) &&
                       lateRestore.admitRestoreReplayForTest(lateReplay) &&
                       lateRestore.restoreSubmissions == 1 && bool(lateRestore.pendingRestoreCompletion) &&
                       lateRestore.retainedGatewayRecoveryForTest(
                           lateReplay.uuid, socket, token, boundToken, bound, settled) &&
                       bound && boundToken == tokenA && !settled,
                   "neuron_state_upload_gateway_late_exact_record_binds_once_and_resumes");
      auto lateFailure = std::exchange(lateRestore.pendingRestoreCompletion, {});
      if (lateFailure) lateFailure(false);
      suite.expect(lateRestore.publishedContainers == 0,
                   "neuron_state_upload_gateway_late_record_never_publishes_before_rebind_receipt");

      ContainerPlan authorityLateDurable = {}, authorityLateReplay = {};
      std::filesystem::path authorityLateRuntimeDirectory = {};
      suite.expect(buildGatewayPlan(99126, authorityLateDurable) &&
                       roundTripStateUploadPlan(authorityLateDurable, authorityLateReplay) &&
                       createRecoveryDirectory(authorityLateReplay.uuid, authorityLateRuntimeDirectory) &&
                       ContainerManagerGatewayRecoveryTestAccess::writeRecordAt(
                           recoveryRootFD, authorityLateReplay, tokenA),
                   "neuron_state_upload_gateway_late_authority_fixture_created");
      TestNeuron authorityLateRestore = {};
      authorityLateRestore.gatewayRecoveryRuntimeRootFD = recoveryRootFD;
      authorityLateRestore.replaceBrainWithoutClosing();
      authorityLateRestore.assignFragmentForLazySwitchboardTest(9, 8, 7, 6);
      auto authorityLateCandidate = std::make_unique<Container>();
      authorityLateCandidate->plan = authorityLateReplay;
      authorityLateCandidate->pid = -1;
      authorityLateCandidate->retainedPidfdWaitabilityFailed = true;
      suite.expect(authorityLateRestore.beginStateUploadRestoreForTest(
                       std::move(authorityLateCandidate), 16) &&
                       authorityLateRestore.restoreSubmissions == 0 &&
                       !authorityLateRestore.pendingRestoreCompletion,
                   "neuron_state_upload_gateway_missing_authority_stays_fenced");
      suite.expect(authorityLateRestore.projectGatewayAuthorityForStateUploadTest(gatewayAuthority) &&
                       authorityLateRestore.restoreSubmissions == 1 &&
                       bool(authorityLateRestore.pendingRestoreCompletion) &&
                       authorityLateRestore.retainedGatewayRecoveryForTest(
                           authorityLateReplay.uuid, socket, token, boundToken, bound, settled) &&
                       bound && boundToken == tokenA && !settled,
                   "neuron_state_upload_gateway_authority_arrival_resumes_without_repeated_upload");
      auto authorityLateFailure = std::exchange(authorityLateRestore.pendingRestoreCompletion, {});
      if (authorityLateFailure) authorityLateFailure(false);
      suite.expect(authorityLateRestore.publishedContainers == 0,
                   "neuron_state_upload_gateway_authority_retry_remains_fenced_before_rebind_receipt");
    }
    if (recoveryRootFD >= 0) close(recoveryRootFD);
    restoreRing.shutdownRing();
  }
  if (gatewayStateUploadRecoveryOnly) return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  {
    TestNeuron replacementNeuron = {};
    replacementNeuron.replaceBrainWithoutClosing();
    auto candidate = std::make_unique<Container>();
    candidate->plan.uuid = uint128_t(0xA5510003);
    candidate->plan.fragment = 1;
    ContainerPlan replay = candidate->plan;
    suite.expect(replacementNeuron.beginStateUploadRestoreForTest(std::move(candidate), 9),
                 "neuron_state_upload_restore_replacement_admits_candidate");
    replacementNeuron.replaceBrainWithoutClosing();
    suite.expect(replacementNeuron.admitRestoreReplayForTest(replay),
                 "neuron_state_upload_restore_replacement_admits_exact_authoritative_plan");
    auto obsolete = std::exchange(replacementNeuron.pendingRestoreCompletion, {});
    obsolete(true);
    suite.expect(replacementNeuron.restoreSubmissions == 2 && bool(replacementNeuron.pendingRestoreCompletion) &&
                     replacementNeuron.restoreBarrierPendingForTest(),
                 "neuron_state_upload_restore_replacement_retries_without_releasing_reply_barrier");
    // A second replacement without a new state-upload request cannot silently
    // adopt the old request. It settles without publication or another retry.
    replacementNeuron.replaceBrainWithoutClosing();
    auto unrequested = std::exchange(replacementNeuron.pendingRestoreCompletion, {});
    unrequested(true);
    suite.expect(replacementNeuron.restoreSubmissions == 2 && !replacementNeuron.restoreBarrierPendingForTest() &&
                     replacementNeuron.pendingStateUploadRestoreForTest(replay.uuid),
                 "neuron_state_upload_restore_replacement_without_upload_cannot_authorize_retry");
    ContainerPlan divergent = replay;
    divergent.fragment += 1;
    suite.expect(!replacementNeuron.admitRestoreReplayForTest(divergent) && replacementNeuron.restoreSubmissions == 2,
                 "neuron_state_upload_restore_divergent_plan_cannot_resume_retained_candidate");
    suite.expect(replacementNeuron.admitRestoreReplayForTest(replay) && replacementNeuron.restoreSubmissions == 3 &&
                     replacementNeuron.restoreBarrierPendingForTest(),
                 "neuron_state_upload_restore_settled_candidate_resumes_only_after_matching_upload");
  }
  {
    TestNeuron retiredIdentity = {};
    retiredIdentity.replaceBrainWithoutClosing();
    auto candidate = std::make_unique<Container>();
    candidate->plan.uuid = uint128_t(0xA5510004);
    candidate->plan.fragment = 1;
    suite.expect(retiredIdentity.beginStateUploadRestoreForTest(std::move(candidate), 10),
                 "neuron_state_upload_restore_identity_fence_admits_candidate");
    retiredIdentity.fenceCurrentRestoreControlForTest();
    // Keep the exact pointer and numeric socket generation visible, as they
    // could be after allocator reuse. The retirement fence must still win.
    auto completion = std::exchange(retiredIdentity.pendingRestoreCompletion, {});
    completion(true);
    suite.expect(retiredIdentity.restoreSubmissions == 1 && !retiredIdentity.restoreBarrierPendingForTest() &&
                     retiredIdentity.pendingStateUploadRestoreForTest(uint128_t(0xA5510004)),
                 "neuron_state_upload_restore_retired_control_identity_cannot_authorize_completion");
  }
  {
    ArtifactRing restoreKillRing = {};
    TestNeuron restoreKillNeuron = {};
    restoreKillNeuron.replaceBrainWithoutClosing();
    NeuronBase *previousNeuron = thisNeuron;
    thisNeuron = &restoreKillNeuron;

    const uint128_t containerUUID = uint128_t(0xA5510006);
    pid_t child = fork();
    if (child == 0)
    {
      for (;;) pause();
    }

    auto candidate = std::make_unique<Container>();
    candidate->plan.uuid = containerUUID;
    candidate->plan.fragment = 1;
    candidate->plan.config.applicationID = 62'901;
    candidate->plan.config.versionID = 1;
    candidate->plan.config.cpuMode = ApplicationCPUMode::shared;
    candidate->plan.config.nLogicalCores = 1;
    candidate->plan.config.sharedCPUMillis = 1'000;
    candidate->plan.restartOnFailure = true;
    candidate->name.assignItoa(containerUUID);
    candidate->pid = child;
    candidate->pidfd = child > 0 ? int(syscall(SYS_pidfd_open, child, 0)) : -1;
    ContainerPlan replay = candidate->plan;
    ContainerRegistry::retain(candidate->plan.config.deploymentID());

    suite.expect(child > 0 && candidate->pidfd >= 0 &&
                     restoreKillNeuron.beginStateUploadRestoreForTest(std::move(candidate), 12),
                 "neuron_state_upload_restore_kill_admits_live_retained_candidate");
    auto obsoleteCompletion = std::exchange(restoreKillNeuron.pendingRestoreCompletion, {});
    String killFrame = {};
    Message::construct(killFrame, NeuronTopic::killContainer, containerUUID);
    restoreKillNeuron.neuronHandler(reinterpret_cast<Message *>(killFrame.data()));
    if (obsoleteCompletion) obsoleteCompletion(true);
    runRingUntil(restoreKillRing, [&] { return restoreKillNeuron.killAcknowledgements == 1; });

    errno = 0;
    const bool childGone = child > 0 && kill(child, 0) != 0 && errno == ESRCH;
    suite.expect(restoreKillRing.timedOut == false && childGone &&
                     restoreKillNeuron.killAcknowledgements == 1 &&
                     restoreKillNeuron.lastKillAcknowledgement == containerUUID,
                 "neuron_state_upload_restore_kill_acks_only_after_exact_process_exit");
    suite.expect(!restoreKillNeuron.pendingStateUploadRestoreForTest(containerUUID) &&
                     !restoreKillNeuron.stateUploadRestoreOperationExistsForTest(containerUUID) &&
                     !restoreKillNeuron.containers.contains(containerUUID) &&
                     restoreKillNeuron.publishedContainers == 0,
                 "neuron_state_upload_restore_kill_retires_unpublished_owner_without_publication");

    restoreKillNeuron.replaceBrainWithoutClosing();
    suite.expect(!restoreKillNeuron.pendingStateUploadRestoreForTest(replay.uuid) &&
                     !restoreKillNeuron.stateUploadRestoreOperationExistsForTest(replay.uuid),
                 "neuron_state_upload_restore_kill_cannot_reappear_after_control_replacement");
    if (!childGone && child > 0)
    {
      kill(child, SIGKILL);
      (void)waitpid(child, nullptr, 0);
    }
    thisNeuron = previousNeuron;
  }
  {
    TestNeuron noPidfdRestoreKillNeuron = {};
    noPidfdRestoreKillNeuron.replaceBrainWithoutClosing();

    const uint128_t containerUUID = uint128_t(0xA5510007);
    pid_t child = fork();
    if (child == 0)
    {
      for (;;) pause();
    }

    auto candidate = std::make_unique<Container>();
    candidate->plan.uuid = containerUUID;
    candidate->plan.fragment = 1;
    candidate->plan.config.applicationID = 62'902;
    candidate->plan.config.versionID = 1;
    candidate->plan.config.cpuMode = ApplicationCPUMode::shared;
    candidate->plan.config.nLogicalCores = 1;
    candidate->plan.config.sharedCPUMillis = 1'000;
    candidate->plan.restartOnFailure = true;
    candidate->name.assignItoa(containerUUID);
    candidate->pid = child;
    candidate->pidfd = -1;

    suite.expect(child > 0 &&
                     noPidfdRestoreKillNeuron.beginStateUploadRestoreForTest(std::move(candidate), 13),
                 "neuron_state_upload_restore_no_pidfd_admits_live_retained_candidate");
    auto obsoleteCompletion = std::exchange(noPidfdRestoreKillNeuron.pendingRestoreCompletion, {});
    String killFrame = {};
    Message::construct(killFrame, NeuronTopic::killContainer, containerUUID);
    noPidfdRestoreKillNeuron.neuronHandler(reinterpret_cast<Message *>(killFrame.data()));
    if (obsoleteCompletion) obsoleteCompletion(true);

    const bool childStillAlive = child > 0 && kill(child, 0) == 0;
    suite.expect(childStillAlive && noPidfdRestoreKillNeuron.killAcknowledgements == 0 &&
                     noPidfdRestoreKillNeuron.stateUploadRestoreOperationExistsForTest(containerUUID) &&
                     noPidfdRestoreKillNeuron.isContainerLaunchRetired(containerUUID) &&
                     noPidfdRestoreKillNeuron.publishedContainers == 0,
                 "neuron_state_upload_restore_no_pidfd_fails_closed_without_signalling_or_acknowledging");

    noPidfdRestoreKillNeuron.replaceBrainWithoutClosing();
    suite.expect(child > 0 && kill(child, 0) == 0 &&
                     noPidfdRestoreKillNeuron.killAcknowledgements == 0 &&
                     noPidfdRestoreKillNeuron.stateUploadRestoreOperationExistsForTest(containerUUID) &&
                     noPidfdRestoreKillNeuron.isContainerLaunchRetired(containerUUID) &&
                     !noPidfdRestoreKillNeuron.pendingStateUploadRestoreForTest(containerUUID) &&
                     noPidfdRestoreKillNeuron.publishedContainers == 0,
                 "neuron_state_upload_restore_no_pidfd_remains_fenced_across_control_replacement");

    if (child > 0)
    {
      kill(child, SIGKILL);
      (void)waitpid(child, nullptr, 0);
    }
  }
  {
    std::function<void(bool)> lateCompletion = {};
    {
      TestNeuron shutdownNeuron = {};
      auto candidate = std::make_unique<Container>();
      candidate->plan.uuid = uint128_t(0xA5510002);
      candidate->plan.fragment = 1;
      suite.expect(shutdownNeuron.beginStateUploadRestoreForTest(std::move(candidate), 8),
                   "neuron_state_upload_restore_shutdown_admits_owned_runner");
      lateCompletion = shutdownNeuron.pendingRestoreCompletion;
    }
    // The destroyed runner has detached its HostCompletion. A terminal
    // callback after Neuron destruction must be inert.
    if (lateCompletion) lateCompletion(true);
    suite.expect(bool(lateCompletion), "neuron_state_upload_restore_shutdown_late_completion_is_inert");
  }
  if (store.root.size() == 0) return EXIT_FAILURE;

  ArtifactRing ring = {};
  TestNeuron neuron = {};
  const bool started = neuron.startForArtifactTest(store.root);
  suite.expect(started, "neuron_artifact_starts_worker_and_control_stream");
  if (started)
  {
    LegacySwitchboardWormholeOperation legacy = {};
    legacy.containerID = 0x00a1b2c3;
    legacy.status = SwitchboardWormholeOperationStatus::applied;
    legacy.revision.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
    legacy.desired.assign("requested-wormhole-state"_ctv);
    SwitchboardWormholeOperation current = {};
    current.containerID = legacy.containerID;
    current.status = legacy.status;
    current.revision = legacy.revision;
    current.desired = legacy.desired;
    String legacyBytes = {}, currentBytes = {};
    LegacySwitchboardWormholeOperation legacyFromCurrent = {};
    SwitchboardWormholeOperation currentFromLegacy = {};
    suite.expect(BitseryEngine::serialize(legacyBytes, legacy) &&
                     BitseryEngine::serialize(currentBytes, current) &&
                     legacyBytes.equals(currentBytes) &&
                     BitseryEngine::deserializeSafe(currentBytes, legacyFromCurrent) &&
                     BitseryEngine::deserializeSafe(legacyBytes, currentFromLegacy) &&
                     legacyFromCurrent.containerID == legacy.containerID &&
                     legacyFromCurrent.status == legacy.status &&
                     legacyFromCurrent.revision.equals(legacy.revision) &&
                     legacyFromCurrent.desired.equals(legacy.desired) &&
                     currentFromLegacy.containerID == current.containerID &&
                     currentFromLegacy.status == current.status &&
                     currentFromLegacy.revision.equals(current.revision) &&
                     currentFromLegacy.desired.equals(current.desired),
                 "neuron_wormhole_operation_preserves_legacy_bidirectional_wire_layout");

    auto operation = [] {
      SwitchboardWormholeOperation value = {};
      value.containerID = 0x00a1b2c3;
      value.status = SwitchboardWormholeOperationStatus::applied;
      value.revision.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
      value.desired.assign("requested-wormhole-state"_ctv);
      return value;
    };
    auto isExactReply = [&](SwitchboardWormholeOperationStatus expectedStatus) {
      SwitchboardWormholeOperation reply = {};
      return neuron.readWormholeOperationReply(reply) && reply.containerID == 0x00a1b2c3 &&
             reply.status == expectedStatus &&
             reply.revision.equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv) &&
             reply.desired.size() == 0;
    };

    neuron.prepareBrainReplyBuffer();
    auto heldSuccess = neuron.prepareWormholeOperationReply(operation());
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_pending_callback_appends_no_reply_before_receipt");
    heldSuccess(true);
    suite.expect(isExactReply(SwitchboardWormholeOperationStatus::applied),
                 "neuron_wormhole_reply_success_sends_one_applied_exact_id_revision_empty_desired");

    neuron.prepareBrainReplyBuffer();
    auto heldFailure = neuron.prepareWormholeOperationReply(operation());
    heldFailure(false);
    suite.expect(isExactReply(SwitchboardWormholeOperationStatus::rollbackFailed),
                 "neuron_wormhole_reply_failure_sends_rollback_failed_not_applied");

    neuron.prepareBrainReplyBuffer();
    auto replaced = neuron.prepareWormholeOperationReply(operation());
    neuron.replaceBrainWithoutClosing();
    neuron.prepareBrainReplyBuffer();
    replaced(true);
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_replaced_brain_suppresses_late_append");

    neuron.prepareBrainReplyBuffer();
    auto changedGeneration = neuron.prepareWormholeOperationReply(operation());
    neuron.advanceBrainGenerationForReplyTest();
    changedGeneration(true);
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_generation_change_suppresses_late_append");

    neuron.prepareBrainReplyBuffer();
    auto inactive = neuron.prepareWormholeOperationReply(operation());
    neuron.deactivateBrainForReplyTest();
    inactive(true);
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_inactive_stream_suppresses_late_append");
    neuron.reactivateBrainForReplyTest();

    neuron.prepareBrainReplyBuffer();
    auto expiredLifetime = neuron.prepareWormholeOperationReply(operation());
    neuron.expireReplyLifetimeForTest();
    expiredLifetime(true);
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_expired_lifetime_suppresses_late_append");

    // The late callback retains the old weak lifetime. Restore a fresh owner
    // and a neutral stream before optional artifact cases use this fixture.
    neuron.restoreReplyLifetimeForTest();
    neuron.prepareBrainForArtifactTest();

    auto localContainer = std::make_unique<Container>();
    localContainer->fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    localContainer->plan.uuid = uint128_t(0x00c0ffee);
    localContainer->plan.wormholes.emplace_back();
    localContainer->plan.wormholes.back().name.assign("current-wormhole"_ctv);
    localContainer->plan.wormholes.back().containerPort = 8443;
    localContainer->plan.wormholes.back().externalPort = 443;

    {
      const uint64_t cousinService = MeshServices::constrainPrefixToGroup(
          MeshServices::generateStatefulService(17, 3), 0);
      ContainerPlan protectedPlan = {};
      protectedPlan.isStateful = true;
      protectedPlan.statefulMeshRoles.cousin = cousinService;
      protectedPlan.advertisements.emplace(
          cousinService,
          Advertisement(cousinService, ContainerState::healthy, ContainerState::destroying, 8443));

      Wormhole direct = {};
      direct.name.assign("cousin-public"_ctv);
      direct.externalAddress = IPAddress("2001:db8::44", true);
      direct.externalPort = 443;
      direct.containerPort = 8443;
      direct.layer4 = IPPROTO_TCP;
      Vector<Wormhole> directWormholes = {direct};

      SwitchboardWormholeDesiredState localDesired = {};
      suite.expect(neuron.buildContainerWormholeDesiredStateForTest(protectedPlan, directWormholes, localDesired) &&
                       prodigyWormholeRequiresPairAdmission(localDesired, 8443, IPPROTO_TCP),
                   "neuron_wormhole_startup_derives_cousin_protection_from_plan_definition");

      SwitchboardWormholeDesiredState legacyFleet = {};
      legacyFleet.wormholes = directWormholes;
      String rawFleetBytes = {};
      suite.expect(prodigyEncodeWormholeDesiredState(legacyFleet, rawFleetBytes),
                   "neuron_wormhole_fleet_raw_state_has_canonical_legacy_bytes");
      suite.expect(neuron.strengthenWormholeDesiredStateForLocalPlanForTest(protectedPlan, legacyFleet) &&
                       prodigyWormholeRequiresPairAdmission(legacyFleet, 8443, IPPROTO_TCP),
                   "neuron_wormhole_fleet_legacy_state_is_strengthened_by_tracked_local_plan");
      String strengthenedFleetBytes = {};
      suite.expect(prodigyEncodeWormholeDesiredState(legacyFleet, strengthenedFleetBytes) &&
                       strengthenedFleetBytes.equals(rawFleetBytes) == false,
                   "neuron_wormhole_fleet_strengthening_requires_retry_with_protected_revision");

      Wormhole separatelyProtected = direct;
      separatelyProtected.name.assign("already-protected"_ctv);
      separatelyProtected.externalAddress = IPAddress("2001:db8::45", true);
      separatelyProtected.externalPort = 444;
      separatelyProtected.containerPort = 9443;
      legacyFleet = {};
      legacyFleet.wormholes = {direct, separatelyProtected};
      legacyFleet.pairAdmissionTCPPorts = {9443};
      suite.expect(neuron.strengthenWormholeDesiredStateForLocalPlanForTest(protectedPlan, legacyFleet) &&
                       legacyFleet.pairAdmissionTCPPorts.size() == 2 &&
                       legacyFleet.pairAdmissionTCPPorts[0] == 8443 && legacyFleet.pairAdmissionTCPPorts[1] == 9443,
                   "neuron_wormhole_local_protection_never_downgrades_live_fleet_profile");

      protectedPlan.advertisements.emplace(
          cousinService + 1,
          Advertisement(cousinService + 1, ContainerState::healthy, ContainerState::destroying, 8443));
      legacyFleet = {};
      legacyFleet.wormholes = directWormholes;
      suite.expect(!neuron.strengthenWormholeDesiredStateForLocalPlanForTest(protectedPlan, legacyFleet) &&
                       legacyFleet.pairAdmissionTCPPorts.empty(),
                   "neuron_wormhole_ambiguous_cousin_definition_rejects_before_switchboard_open");
    }
    neuron.trackContainerForReplyTest(localContainer.get());
    String expectedWormholes = {};
    BitseryEngine::serialize(expectedWormholes, localContainer->plan.wormholes);

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto pendingRefresh = neuron.prepareWormholeContainerRefresh(localContainer.get());
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_pending_callback_appends_no_container_frame_before_receipt");
    pendingRefresh(true);
    String receivedWormholes = {};
    suite.expect(neuron.readContainerWormholeRefresh(localContainer.get(), receivedWormholes) &&
                     receivedWormholes == expectedWormholes,
                 "neuron_wormhole_refresh_success_sends_exact_current_plan_serialization");

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto failedRefresh = neuron.prepareWormholeContainerRefresh(localContainer.get());
    failedRefresh(false);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_failed_receipt_suppresses_container_frame");

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto obsoleteContainer = neuron.prepareWormholeContainerRefresh(localContainer.get());
    neuron.untrackContainerForReplyTest(localContainer->plan.uuid);
    obsoleteContainer(true);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_obsolete_container_entry_suppresses_late_frame");
    neuron.trackContainerForReplyTest(localContainer.get());

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto changedContainerGeneration = neuron.prepareWormholeContainerRefresh(localContainer.get());
    ++localContainer->ioGeneration;
    changedContainerGeneration(true);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_container_generation_change_suppresses_late_frame");

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto pendingDestroy = neuron.prepareWormholeContainerRefresh(localContainer.get());
    localContainer->pendingDestroy = true;
    pendingDestroy(true);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_pending_destroy_suppresses_late_frame");
    localContainer->pendingDestroy = false;

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto replacedSourceBrain = neuron.prepareWormholeContainerRefresh(localContainer.get());
    neuron.replaceBrainWithoutClosing();
    replacedSourceBrain(true);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_replaced_source_brain_suppresses_late_frame");

    neuron.untrackContainerForReplyTest(localContainer->plan.uuid);
    if (localContainer->fd >= 0)
    {
      ::close(localContainer->fd);
      localContainer->fd = -1;
    }
    localContainer.reset();
    neuron.prepareBrainForArtifactTest();
    if (hasArtifactFixture)
    {
      constexpr uint64_t currentDeploymentID = 0xE71F01ULL;
      suite.expect(neuron.submit(currentDeploymentID, fixture.substr(0, fixture.size(), Copy::yes)),
                   "neuron_artifact_queues_current_stream_fixture");
      runRingUntil(ring, [&] { return neuron.artifactFinished(); });
      suite.expect(ring.timedOut == false && neuron.stored(currentDeploymentID, fixture),
                   "neuron_artifact_current_stream_prepares_publishes_and_adopts_fixture");
      suite.expect(neuron.artifactFinished() && neuron.lastArtifactAdopted && neuron.lastArtifactSourceCurrent,
                   "neuron_artifact_current_stream_completes_on_ring_after_durable_adoption");

      constexpr uint64_t staleDeploymentID = 0xE71F02ULL;
      ring.timedOut = false;
      neuron.artifactFinishes = 0;
      neuron.retainPendingDownload(staleDeploymentID);
      suite.expect(neuron.submit(staleDeploymentID, fixture.substr(0, fixture.size(), Copy::yes)),
                   "neuron_artifact_queues_stale_stream_fixture");
      neuron.replaceBrainWithoutClosing();
      runRingUntil(ring, [&] { return neuron.artifactFinished(); });
      suite.expect(ring.timedOut == false && neuron.stored(staleDeploymentID, fixture) == false &&
                       neuron.lastArtifactAdopted == false && neuron.lastArtifactSourceCurrent == false,
                   "neuron_artifact_stale_incarnation_suppresses_publish_and_adoption");
      suite.expect(neuron.hasPendingDownload(staleDeploymentID),
                   "neuron_artifact_replacement_retains_download_for_existing_reconnect_replay");
      suite.expect(neuron.replacementQueuesPendingDownload(staleDeploymentID),
                   "neuron_artifact_replacement_requeues_retained_download_on_accepted_control_stream");
    }
  }

  ring.timedOut = false;
  runRingUntil(ring, [&] { return neuron.quiesceArtifactIOForTest(); });
  suite.expect(ring.timedOut == false, "neuron_artifact_raw_poll_retired_before_ring_shutdown");
  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
