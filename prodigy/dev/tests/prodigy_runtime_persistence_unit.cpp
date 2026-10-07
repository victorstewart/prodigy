#define PRODIGY_RUNTIME_PERSISTENCE_UNIT
#include "../../prodigy.cpp"

#include <array>
#include <cstdio>

#include <prodigy/dev/tests/persistence_fixture.h>

class RuntimeTestNeuronIaaS final : public NeuronIaaS {
public:
  void gatherSelfData(CoroutineStack *, uint128_t& uuid, String& metro, bool& isBrain,
                      EthDevice& eth, IPAddress& private4) override
  {
    uuid = 0;
    metro.clear();
    isBrain = false;
    (void)eth;
    private4 = {};
  }
};

class ReceiptTestNeuron final : public Neuron {
public:
  RuntimeTestNeuronIaaS testIaaS;
  uint32_t submissions = 0;
  String targetOSID, targetOSVersionID, command;
  std::function<void(bool, String)> receipt;

  ReceiptTestNeuron() { iaas = &testIaaS; }
  void pushContainer(Container *) override {}
  void popContainer(Container *) override {}
  bool ensureHostNetworkingReady(String *failure = nullptr) override
  {
    if (failure) failure->clear();
    return true;
  }
  void downloadContainer(CoroutineStack *, uint64_t) override {}
  void startOperatingSystemUpdateAsync(String osID, String version, String update,
                                       std::function<void(bool, String)> completion) override
  {
    ++submissions;
    targetOSID = std::move(osID);
    targetOSVersionID = std::move(version);
    command = std::move(update);
    receipt = std::move(completion);
  }
};

class ProjectionReceiptTestNeuron final : public Neuron {
public:
  using Neuron::beginAcceptedBrainTransportTLS;
  uint32_t projectionPersistenceCalls = 0;
  bool admitProjectionPersistence = true;
  std::deque<std::function<void(bool)>> projectionReceipts;
  uint32_t pairProjectionPersistenceCalls = 0;
  std::deque<std::function<void(bool)>> pairProjectionReceipts;
  uint32_t lifecycleProjectionPersistenceCalls = 0;
  bool admitLifecycleProjectionPersistence = true;
  std::deque<std::function<void(bool)>> lifecycleProjectionReceipts;

  bool persistTransportCredentialPeerProjection(
      const ProdigyTransportCredentialBootstrap&, std::function<void(bool)> completion) override
  {
    ++projectionPersistenceCalls;
    if (!admitProjectionPersistence) return false;
    projectionReceipts.push_back(std::move(completion));
    return true;
  }

  void finishProjectionPersistence(bool durable)
  {
    if (projectionReceipts.empty()) return;
    auto completion = std::move(projectionReceipts.front());
    projectionReceipts.pop_front();
    completion(durable);
  }

  bool persistClusterPairControlProjection(
      const ProdigyLocalClusterPairControlProjection&, uint128_t, std::function<void(bool)> completion) override
  {
    ++pairProjectionPersistenceCalls;
    pairProjectionReceipts.push_back(std::move(completion));
    return true;
  }
  void finishPairProjectionPersistence(bool durable)
  {
    if (pairProjectionReceipts.empty()) return;
    auto completion = std::move(pairProjectionReceipts.front()); pairProjectionReceipts.pop_front(); completion(durable);
  }

  bool persistTransportCredentialLifecycleProjection(
      const ProdigyTransportCredentialLifecycleProjection&, std::function<void(bool)> completion) override
  {
    ++lifecycleProjectionPersistenceCalls;
    if (!admitLifecycleProjectionPersistence) return false;
    lifecycleProjectionReceipts.push_back(std::move(completion));
    return true;
  }

  void finishLifecycleProjectionPersistence(bool durable)
  {
    if (lifecycleProjectionReceipts.empty()) return;
    auto completion = std::move(lifecycleProjectionReceipts.front());
    lifecycleProjectionReceipts.pop_front();
    completion(durable);
  }
};

static void reserveProjectionTransport(ProdigyTransportTLSStream& stream)
{
  stream.rBuffer.reserve(8192);
  stream.wBuffer.reserve(16384);
}

static bool pumpProjectionTransport(ProdigyTransportTLSStream& from, ProdigyTransportTLSStream& to)
{
  const uint32_t bytes = from.nBytesToSend();
  if (bytes == 0) return false;
  if (to.rBuffer.remainingCapacity() < bytes) to.rBuffer.reserve(to.rBuffer.size() + bytes);
  from.noteSendQueued();
  std::memcpy(to.rBuffer.pTail(), from.pBytesToSend(), bytes);
  const bool accepted = to.decryptTransportTLS(bytes);
  from.consumeSentBytes(bytes, false);
  from.noteSendCompleted();
  return accepted;
}

static bool completeProjectionTransportHandshake(ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server)
{
  for (uint32_t round = 0; round < 128; ++round)
  {
    const bool progressed = pumpProjectionTransport(client, server) || pumpProjectionTransport(server, client);
    if (client.isTransportNegotiated() && server.isTransportNegotiated()) return true;
    if (!progressed) return false;
  }
  return false;
}

static ProdigyTransportCredentialEnrollment projectionEnrollment(uint128_t operationUUID, uint128_t nodeUUID,
                                                                  uint64_t generation)
{
  ProdigyTransportCredentialEnrollment enrollment = {};
  enrollment.operationUUID = operationUUID;
  enrollment.nodeUUID = nodeUUID;
  enrollment.clusterUUID = uint128_t(0x7101);
  enrollment.authorityEpoch = 7;
  enrollment.keyEpoch = 9;
  enrollment.authorityGeneration = generation;
  enrollment.role = ProdigyTransportCredentialNodeRole::brain;
  enrollment.state = ProdigyTransportCredentialEnrollmentState::active;
  return enrollment;
}

static ProdigyTransportCredentialEnrollment projectionNeuronEnrollment(uint128_t operationUUID, uint128_t nodeUUID,
                                                                        uint64_t generation)
{
  auto enrollment = projectionEnrollment(operationUUID, nodeUUID, generation);
  enrollment.role = ProdigyTransportCredentialNodeRole::neuron;
  return enrollment;
}

static ProdigyTransportCredentialAuthorityRoot projectionCredentialAuthorityRoot()
{
  ProdigyTransportCredentialAuthorityRoot authority = {};
  authority.authorityEpoch = 7;
  authority.keyEpoch = 9;
  authority.authorityGeneration = 10;
  std::memset(authority.root, 0x5a, sizeof(authority.root));
  return authority;
}

static ProdigyTransportCredentialBootstrap projectionCredentialBootstrap(uint128_t neuronUUID, uint128_t brainUUID,
                                                                          uint64_t revision)
{
  const auto authority = projectionCredentialAuthorityRoot();
  const auto neuron = projectionNeuronEnrollment(0x7102, neuronUUID, 10);
  const auto brain = projectionEnrollment(0x7103, brainUUID, 10);
  const Vector<ProdigyTransportCredentialEnrollment> ledger = {brain, neuron};
  ProdigyTransportCredentialBootstrap bootstrap = {};
  (void)prodigyBuildTransportCredentialBootstrap(authority, neuron, ledger, true, bootstrap, revision);
  return bootstrap;
}

static bool beginProjectionBrainControlTransport(ProjectionReceiptTestNeuron& neuron, NeuronBrainControlStream& stream,
                                                 ProdigyTransportTLSStream& remote,
                                                 const ProdigyTransportCredentialBootstrap& bootstrap,
                                                 bool installCredentials = true)
{
  if (!prodigyTransportCredentialBootstrapValid(bootstrap) ||
      bootstrap.self.role != ProdigyTransportCredentialNodeRole::neuron ||
      bootstrap.authorizedPeers.size() != 1) return false;
  const auto authority = projectionCredentialAuthorityRoot();
  const auto brain = bootstrap.authorizedPeers.front();
  ProdigyTransportCredentialEnrollment local = {};
  local.operationUUID = bootstrap.self.operationUUID;
  local.nodeUUID = bootstrap.self.nodeUUID;
  local.clusterUUID = bootstrap.self.clusterUUID;
  local.authorityEpoch = bootstrap.self.authorityEpoch;
  local.keyEpoch = bootstrap.self.keyEpoch;
  local.authorityGeneration = bootstrap.self.authorityGeneration;
  local.role = bootstrap.self.role;
  local.state = ProdigyTransportCredentialEnrollmentState::active;
  if (brain.role != ProdigyTransportCredentialNodeRole::brain ||
      bootstrap.self.rootAuthorityGeneration != authority.authorityGeneration) return false;
  const Vector<ProdigyTransportCredentialEnrollment> ledger = {brain, local};
  ProdigyTransportCredentialPrelude brainPrelude = {};
  brainPrelude.operationUUID = brain.operationUUID;
  brainPrelude.nodeUUID = brain.nodeUUID;
  brainPrelude.authorityEpoch = brain.authorityEpoch;
  brainPrelude.keyEpoch = brain.keyEpoch;
  brainPrelude.authorityGeneration = brain.authorityGeneration;
  brainPrelude.role = brain.role;
  String encodedBrainPrelude = {};
  if (installCredentials) neuron.controlTransportCredentials = bootstrap;
  return prodigyRenderTransportCredentialPrelude(brainPrelude, encodedBrainPrelude) &&
      neuron.beginAcceptedBrainTransportTLS(&stream) &&
      remote.beginTransportAEGISWithPrelude(false, brain.nodeUUID, encodedBrainPrelude,
          [authority, ledger, brain](const String& claimed, std::array<uint8_t, 32>& psk,
                                     String& context, uint128_t& peerUUID) {
            return prodigyResolveBrainTransportCredentialPeer(authority, ledger, brain.nodeUUID, brain.role,
                claimed, "brain-neuron"_ctv, psk.data(), context, peerUUID);
          }) &&
      completeProjectionTransportHandshake(remote, stream);
}

static ProdigyTransportCredentialLifecycleProjection projectionCredentialRotation(
    const ProdigyTransportCredentialBootstrap& source, uint128_t operationUUID)
{
  ProdigyTransportCredentialLifecycleProjection projection = {};
  projection.protocolVersion = 1;
  auto& operation = projection.operation;
  operation.protocolVersion = 2;
  operation.lifecycleOperationUUID = operationUUID;
  operation.predecessor.operationUUID = source.self.operationUUID;
  operation.predecessor.nodeUUID = source.self.nodeUUID;
  operation.predecessor.clusterUUID = source.self.clusterUUID;
  operation.predecessor.authorityEpoch = source.self.authorityEpoch;
  operation.predecessor.keyEpoch = source.self.keyEpoch;
  operation.predecessor.authorityGeneration = source.self.authorityGeneration;
  operation.predecessor.role = source.self.role;
  operation.predecessor.state = ProdigyTransportCredentialEnrollmentState::active;
  operation.successor = operation.predecessor;
  operation.successor.operationUUID = operationUUID + 1;
  operation.successor.authorityGeneration = source.committedAuthorityGeneration + 1;
  operation.successor.state = ProdigyTransportCredentialEnrollmentState::pending;
  for (const auto& peer : source.authorizedPeers) operation.electorate.push_back(peer.nodeUUID);
  operation.frozenAuthorityGeneration = source.committedAuthorityGeneration;
  operation.transitionGeneration = source.committedAuthorityGeneration + 1;
  operation.pinnedMasterAuthorityEpoch = source.self.authorityEpoch;
  projection.committedAuthorityGeneration = operation.transitionGeneration;
  projection.target = source;
  projection.target.committedAuthorityGeneration = projection.committedAuthorityGeneration;
  const auto authority = projectionCredentialAuthorityRoot();
  auto successor = operation.successor;
  successor.state = ProdigyTransportCredentialEnrollmentState::active;
  (void)prodigyDeriveTransportNodeCredential(authority, successor, projection.target.self);
  return projection;
}

static ProdigyTransportCredentialLifecycleProjection projectionCredentialRevocation(
    const ProdigyTransportCredentialBootstrap& source, uint128_t operationUUID)
{
  auto projection = projectionCredentialRotation(source, operationUUID);
  projection.operation.lifecycleKind = ProdigyTransportCredentialLifecycleKind::revoke;
  projection.operation.successor = {};
  projection.operation.predecessor.state = ProdigyTransportCredentialEnrollmentState::revoked;
  projection.operation.lifecyclePhase = ProdigyTransportCredentialLifecyclePhase::active;
  projection.operation.activationGeneration = projection.operation.transitionGeneration;
  projection.target = {};
  return projection;
}

static bool projectionLifecycleAck(NeuronBrainControlStream& stream, uint128_t nonce,
                                   uint64_t revision, bool accepted)
{
  if (stream.wBuffer.empty()) return false;
  auto *message = reinterpret_cast<Message *>(stream.wBuffer.data());
  if (message->topic != uint16_t(NeuronTopic::transportCredentialLifecycleAck) ||
      !ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal())) return false;
  uint8_t *args = message->args;
  uint128_t actualNonce = 0;
  uint64_t actualRevision = 0;
  uint8_t actualAccepted = 0;
  Message::extractArg<ArgumentNature::fixed>(args, actualNonce);
  Message::extractArg<ArgumentNature::fixed>(args, actualRevision);
  Message::extractArg<ArgumentNature::fixed>(args, actualAccepted);
  return actualNonce == nonce && actualRevision == revision && actualAccepted == uint8_t(accepted);
}

static ClusterPairControlEndpoint runtimePairControlEndpoint(
    uint128_t clusterUUID, uint128_t nodeUUID, const char *address)
{
  ClusterPairControlEndpoint endpoint = {};
  endpoint.clusterUUID = clusterUUID;
  endpoint.nodeUUID = nodeUUID;
  endpoint.role = ClusterPairControlNodeRole::switchboard;
  endpoint.address = IPAddress(address, true);
  endpoint.port = uint16_t(ReservedPorts::clusterPairControl);
  return endpoint;
}

static bool buildRuntimePairControlProjections(
    uint128_t localNodeUUID, uint128_t remoteNodeUUID,
    ProdigyLocalClusterPairControlProjection& local,
    ProdigyLocalClusterPairControlProjection& remote)
{
  constexpr uint128_t localClusterUUID = 0x7101, remoteClusterUUID = 0x7201;
  ClusterPairRoot root = {};
  root.pairUUID = 0x72a1;
  root.firstClusterUUID = localClusterUUID;
  root.secondClusterUUID = remoteClusterUUID;
  root.rootGeneration = 1;
  for (uint32_t index = 0; index < root.root.size(); ++index) root.root[index] = uint8_t(0x81 + index);

  const auto initiator = runtimePairControlEndpoint(localClusterUUID, localNodeUUID, "fd00:ffff:1234::1");
  const auto responder = runtimePairControlEndpoint(remoteClusterUUID, remoteNodeUUID, "fd00:ffff:1234::2");
  ClusterPairControlResolver localResolver = {}, remoteResolver = {};
  if (!clusterPairPrepareControlResolver(root, initiator, responder, initiator, responder, 1,
                                         "runtime-persistence-pair-control"_ctv, localResolver) ||
      !clusterPairPrepareControlResolver(root, initiator, responder, responder, initiator, 1,
                                         "runtime-persistence-pair-control"_ctv, remoteResolver)) return false;

  std::array<uint8_t, 32> localKey = {}, remoteKey = {};
  String localContext = {}, remoteContext = {};
  uint128_t localPeer = 0, remotePeer = 0;
  if (!localResolver.resolve(remoteResolver.localPublicClaim(), localKey, localContext, localPeer) ||
      !remoteResolver.resolve(localResolver.localPublicClaim(), remoteKey, remoteContext, remotePeer) ||
      localPeer != remoteNodeUUID || remotePeer != localNodeUUID) return false;

  local = {};
  local.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
  local.localClusterUUID = localClusterUUID;
  local.nodeUUID = localNodeUUID;
  local.committedAuthorityGeneration = 12;
  remote = {};
  remote.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
  remote.localClusterUUID = remoteClusterUUID;
  remote.nodeUUID = remoteNodeUUID;
  remote.committedAuthorityGeneration = 12;

  ProdigyLocalClusterPairControlCredential localCredential = {}, remoteCredential = {};
  localCredential.pairUUID = root.pairUUID;
  localCredential.rootGeneration = root.rootGeneration;
  localCredential.keyEpoch = 1;
  localCredential.initiator = initiator;
  localCredential.responder = responder;
  localCredential.localClaim = localResolver.localPublicClaim();
  localCredential.remoteClaim = remoteResolver.localPublicClaim();
  localCredential.canonicalContext = std::move(localContext);
  std::memcpy(localCredential.psk, localKey.data(), localKey.size());
  remoteCredential.pairUUID = root.pairUUID;
  remoteCredential.rootGeneration = root.rootGeneration;
  remoteCredential.keyEpoch = 1;
  remoteCredential.initiator = initiator;
  remoteCredential.responder = responder;
  remoteCredential.localClaim = remoteResolver.localPublicClaim();
  remoteCredential.remoteClaim = localResolver.localPublicClaim();
  remoteCredential.canonicalContext = std::move(remoteContext);
  std::memcpy(remoteCredential.psk, remoteKey.data(), remoteKey.size());
  OPENSSL_cleanse(localKey.data(), localKey.size());
  OPENSSL_cleanse(remoteKey.data(), remoteKey.size());
  local.credentials.push_back(std::move(localCredential));
  remote.credentials.push_back(std::move(remoteCredential));
  return prodigyLocalClusterPairControlProjectionValid(local, true) &&
      prodigyLocalClusterPairControlProjectionValid(remote, true);
}

static bool runPairControlUntil(PersistenceRing& ring, const std::function<bool()>& complete, uint64_t timeoutMs)
{
  uint64_t elapsedMs = 0;
  bool timedOut = false;
  Ring::exit = false;
  ring.tickAction = [&] {
    if (complete()) { Ring::exit = true; return; }
    elapsedMs += 5;
    if (elapsedMs >= timeoutMs) { timedOut = true; Ring::exit = true; return; }
    ring.armTick(5);
  };
  ring.armTick(1);
  Ring::start();
  ring.tickAction = {};
  Ring::exit = false;
  return !timedOut && complete();
}

static bool runPairControlFor(PersistenceRing& ring, uint64_t durationMs)
{
  uint64_t elapsedMs = 0;
  Ring::exit = false;
  ring.tickAction = [&] {
    elapsedMs += 5;
    if (elapsedMs >= durationMs) { Ring::exit = true; return; }
    ring.armTick(5);
  };
  ring.armTick(1);
  Ring::start();
  ring.tickAction = {};
  Ring::exit = false;
  return elapsedMs >= durationMs;
}

template <typename... Args>
static Message *runtimePersistenceMessage(String& buffer, NeuronTopic topic, Args&&...args)
{
  buffer.clear();
  Message::construct(buffer, topic, std::forward<Args>(args)...);
  return reinterpret_cast<Message *>(buffer.data());
}

static ProdigyPersistentBootState runtimePersistenceBootState(void)
{
  ProdigyPersistentBootState boot = {};
  boot.bootstrapConfig.nodeRole = ProdigyBootstrapNodeRole::brain;
  boot.bootstrapSshUser.assign("bootstrap-user"_ctv);
  return boot;
}

static void testPersistentWriterDetachesViewBackedSchemaFields(TestSuite& suite)
{
  String backing = {};
  backing.assign("original-certificate"_ctv);
  ProdigyPersistentLocalBrainState state = {};
  state.transportTLS.localCertPem = String(const_cast<uint8_t *>(backing.data()), backing.size(), Copy::no, backing.size());

  const bool detached = ProdigyPersistentStateWriter::detach(state);
  backing.assign("mutated-certificate!"_ctv);
  suite.expect(detached && state.transportTLS.localCertPem.equals("original-certificate"_ctv),
               "runtime_persistence_writer_detaches_view_backed_local_state");

  String bootBacking = {};
  bootBacking.assign("bootstrap-user"_ctv);
  ProdigyPersistentBootState boot = {};
  boot.bootstrapSshUser = String(const_cast<uint8_t *>(bootBacking.data()), bootBacking.size(), Copy::no, bootBacking.size());
  const bool detachedBoot = ProdigyPersistentStateWriter::detach(boot);
  bootBacking.assign("changed-bootstrap"_ctv);
  suite.expect(detachedBoot && boot.bootstrapSshUser.equals("bootstrap-user"_ctv),
               "runtime_persistence_writer_detaches_view_backed_boot_state");

  String snapshotBacking = {};
  snapshotBacking.assign("snapshot-user"_ctv);
  ProdigyPersistentBrainSnapshot snapshot = {};
  snapshot.brainConfig.bootstrapSshUser = String(const_cast<uint8_t *>(snapshotBacking.data()), snapshotBacking.size(), Copy::no, snapshotBacking.size());
  const bool detachedSnapshot = ProdigyPersistentStateWriter::detach(snapshot);
  snapshotBacking.assign("changed-snapshot"_ctv);
  suite.expect(detachedSnapshot && snapshot.brainConfig.bootstrapSshUser.equals("snapshot-user"_ctv),
               "runtime_persistence_writer_detaches_view_backed_snapshot");

  String mapKeyBacking = {}, mapValueBacking = {};
  mapKeyBacking.assign("token"_ctv);
  mapValueBacking.assign("nested-secret"_ctv);
  String mapKey(const_cast<uint8_t *>(mapKeyBacking.data()), mapKeyBacking.size(), Copy::no, mapKeyBacking.size());
  String mapValue(const_cast<uint8_t *>(mapValueBacking.data()), mapValueBacking.size(), Copy::no, mapValueBacking.size());
  snapshot.brainConfig.dnsCredential.metadata.insert_or_assign(std::move(mapKey), std::move(mapValue));
  const bool detachedMap = ProdigyPersistentStateWriter::detach(snapshot);
  mapKeyBacking.assign("other"_ctv);
  mapValueBacking.assign("changed-secret"_ctv);
  const auto nested = snapshot.brainConfig.dnsCredential.metadata.find("token"_ctv);
  suite.expect(detachedMap && nested != snapshot.brainConfig.dnsCredential.metadata.end() &&
                   nested->second.equals("nested-secret"_ctv),
               "runtime_persistence_writer_detaches_nested_map_views");
}

static void testPersistentWriterPreservesTransportLifecycleSchema(TestSuite& suite)
{
  PersistenceRing ring;
  ScopedPersistentRoot root;
  ProdigyPersistentStateStore store(root.path);
  auto original = projectionCredentialBootstrap(0x7171, 0x7172, 11);
  // The delivered cohort was admitted by an already enrolled Brain voter.
  const auto enrolledNeuron = projectionNeuronEnrollment(original.self.operationUUID, original.self.nodeUUID, 11);
  suite.expect(prodigyDeriveTransportNodeCredential(projectionCredentialAuthorityRoot(), enrolledNeuron, original.self),
      "runtime_lifecycle_writer_builds_delivered_cohort_after_its_voter");
  const auto projection = projectionCredentialRotation(original, 0x7173);
  ProdigyPersistentBrainSnapshot snapshot;
  snapshot.brainConfig.clusterUUID = original.self.clusterUUID;
  auto& authority = snapshot.masterAuthority.runtimeState;
  authority.generation = projection.committedAuthorityGeneration;
  authority.transportCredentialAuthorityRoot = projectionCredentialAuthorityRoot();
  authority.transportCredentialEnrollments = {original.authorizedPeers.front(), projection.operation.predecessor};
  ProdigyTransportCredentialEnrollmentOperation legacy;
  legacy.enrollment = projection.operation.predecessor;
  legacy.electorate = projection.operation.electorate;
  legacy.pinnedMasterAuthorityEpoch = projection.operation.pinnedMasterAuthorityEpoch;
  legacy.transitionGeneration = original.committedAuthorityGeneration;
  legacy.phase = ProdigyTransportCredentialEnrollmentOperationPhase::delivered;
  authority.transportCredentialEnrollmentOperations = {legacy, projection.operation};
  ProdigyPersistentLocalBrainState local;
  local.uuid = original.self.nodeUUID;
  local.ownerClusterUUID = original.self.clusterUUID;
  local.transportCredentials = original;
  ProdigyTransportCredentialBootstrap staged;
  bool revoked = false;
  suite.expect(prodigyApplyLocalTransportCredentialLifecycleProjection(local, projection, staged, revoked) && !revoked,
      "runtime_lifecycle_writer_builds_valid_staged_local_record");
  const auto expectedSnapshot = snapshot;
  const auto expectedLocal = local;
  suite.expect(ProdigyPersistentStateWriter::detach(snapshot) && ProdigyPersistentStateWriter::detach(local) &&
      prodigyPersistentSerializedEqual(snapshot, expectedSnapshot) && prodigyPersistentSerializedEqual(local, expectedLocal) &&
      authority.transportCredentialEnrollmentOperations == expectedSnapshot.masterAuthority.runtimeState.transportCredentialEnrollmentOperations,
      "runtime_lifecycle_owning_visitor_preserves_legacy_receipt_lifecycle_operation_and_local_projection");
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "runtime_lifecycle_writer_starts");
  if (!io) return;
  auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io);
  uint32_t receipts = 0;
  bool allDurable = true;
  auto completed = [&](auto&& result) {
    ++receipts; allDurable &= result.durable;
    if (receipts == 2) Ring::exit = true;
  };
  const bool snapshotQueued = writer->submitSnapshot(snapshot, runtimePersistenceBootState(),
      ProdigyPersistentStateWriter::retainedBytesFor(snapshot) + 1048576, completed);
  const bool localQueued = writer->submitLocalBrainState(local, ProdigyPersistentStateWriter::retainedBytesFor(local) + 65536, completed);
  suite.expect(snapshotQueued && localQueued, "runtime_lifecycle_writer_admits_snapshot_and_local_projection");
  ring.armDeadline(5000); Ring::start();
  suite.expect(!ring.timedOut && receipts == 2 && allDurable && writer->drainForExec(),
      "runtime_lifecycle_writer_commits_both_exact_durable_records");
  writer.reset(); io->stop(); ring.drainStoppedIO(); io.reset(); store.close();
  ProdigyPersistentStateStore reopened(root.path);
  ProdigyPersistentBrainSnapshot loadedSnapshot;
  ProdigyPersistentLocalBrainState loadedLocal;
  String failure;
  suite.expect(reopened.loadBrainSnapshot(loadedSnapshot, &failure) && reopened.loadLocalBrainState(loadedLocal, &failure) &&
      loadedSnapshot.masterAuthority.runtimeState.transportCredentialEnrollmentOperations ==
          expectedSnapshot.masterAuthority.runtimeState.transportCredentialEnrollmentOperations &&
      prodigyPersistentSerializedEqual(loadedLocal, expectedLocal),
      "runtime_lifecycle_writer_reopens_exact_operations_and_staged_secret");
  reopened.close();
}

static void testTerminalLocalBrainFenceOverridesOlderSnapshot(TestSuite& suite)
{
  PersistenceRing ring;
  const auto root = projectionCredentialAuthorityRoot();
  const auto ownBrain = projectionEnrollment(0x7181, 0x7180, 10);
  const auto peerBrain = projectionEnrollment(0x7183, 0x7182, 10);
  const auto ownNeuron = projectionNeuronEnrollment(0x7184, 0x7180, 10);
  const Vector<ProdigyTransportCredentialEnrollment> ledger = {ownBrain, peerBrain, ownNeuron};
  ProdigyPersistentLocalBrainState local;
  const bool built = prodigyBuildLocalTransportCredentialState(root, ledger, ownBrain.nodeUUID,
      ProdigyTransportCredentialNodeRole::brain, local, 10);
  suite.expect(built, "runtime_terminal_brain_fixture_has_separate_brain_and_neuron_credentials");
  if (!built) return;
  const auto original = local;
  ProdigyTransportCredentialLifecycleProjection prepared;
  prepared.protocolVersion = 1;
  auto& operation = prepared.operation;
  operation.protocolVersion = 2;
  operation.lifecycleOperationUUID = 0x7185;
  operation.lifecycleKind = ProdigyTransportCredentialLifecycleKind::revoke;
  operation.predecessor = ownBrain;
  operation.electorate = {ownBrain.nodeUUID, peerBrain.nodeUUID};
  operation.frozenAuthorityGeneration = 10;
  operation.transitionGeneration = prepared.committedAuthorityGeneration = 11;
  operation.pinnedMasterAuthorityEpoch = 7;
  (void)prodigyBuildLocalNeuronTransportCredentialBootstrap(local, prepared.target);
  prepared.target.authorizedPeers = {peerBrain};
  prepared.target.committedAuthorityGeneration = 11;
  auto active = prepared;
  active.operation.predecessor.state = ProdigyTransportCredentialEnrollmentState::revoked;
  active.operation.lifecyclePhase = ProdigyTransportCredentialLifecyclePhase::active;
  active.operation.activationGeneration = active.operation.transitionGeneration = 12;
  active.committedAuthorityGeneration = active.target.committedAuthorityGeneration = 12;
  ProdigyTransportCredentialBootstrap neuronCredential;
  bool revoked = false;
  const bool applied = prodigyApplyLocalTransportCredentialLifecycleProjection(local, prepared, neuronCredential, revoked) &&
      prodigyApplyLocalTransportCredentialLifecycleProjection(local, active, neuronCredential, revoked);
  suite.expect(applied && !revoked && prodigyLocalBrainTransportCredentialRevoked(local),
      "runtime_terminal_brain_fixture_durably_fences_only_the_brain_role");
  if (!applied) return;
  ProdigyMasterAuthorityRuntimeState older;
  older.generation = 11;
  older.transportCredentialAuthorityRoot = root;
  older.transportCredentialEnrollments = ledger;
  older.transportCredentialEnrollmentOperations = {prepared.operation};
  const auto terminal = local;
  suite.expect(prodigyRestoreLocalTransportCredentialsFromAuthority(older, ProdigyTransportCredentialNodeRole::brain, local) &&
      prodigyPersistentSerializedEqual(local, terminal) && local.transportCredentials.self.secretIsZero() &&
      prodigyBuildLocalNeuronTransportCredentialBootstrap(local, neuronCredential) &&
      neuronCredential.self.nodeUUID == ownNeuron.nodeUUID && !neuronCredential.self.secretIsZero() &&
      neuronCredential.authorizedPeers == Vector<ProdigyTransportCredentialEnrollment>{peerBrain},
      "runtime_terminal_brain_restore_preserves_local_fence_and_healthy_neuron");

  const auto savedLocal = persistentLocalBrainState;
  auto *savedNeuron = thisNeuron;
  ProjectionReceiptTestNeuron neuron;
  neuron.uuid = ownNeuron.nodeUUID;
  thisNeuron = &neuron;
  ProdigyHostControlNetwork network;
  persistentLocalBrainState = original;
  {
    ProdigyBrain brain(network, {});
    brain.brainConfig.clusterUUID = ownBrain.clusterUUID;
    brain.masterAuthorityRuntimeState = older;
    brain.weAreMaster = true;
    suite.expect(brain.localInternalTransportCredentialCurrent() && brain.isActiveMaster(),
        "runtime_terminal_brain_old_snapshot_would_authorize_predecessor_without_local_fence");
    persistentLocalBrainState = local;
    ProdigyTransportTLSStream incoming, outgoing;
    suite.expect(!brain.localInternalTransportCredentialCurrent() && !brain.localBrainEligibleForMasterElection() &&
        !brain.isActiveMaster() &&
        !brain.beginInternalControlTransport(&incoming, true, ProdigyTransportCredentialNodeRole::brain, peerBrain.nodeUUID) &&
        !brain.beginInternalControlTransport(&outgoing, false, ProdigyTransportCredentialNodeRole::brain, peerBrain.nodeUUID) &&
        !incoming.transportEncryptionEnabled() && !outgoing.transportEncryptionEnabled() &&
        brain.masterAuthorityRuntimeState == older,
        "runtime_terminal_brain_persisted_fence_denies_election_and_both_handshake_directions_without_rewriting_authority");
    brain.masterAuthorityRuntimeState = {};
    brain.transportCredentialBootstrapRequired = false;
    suite.expect(!brain.internalTransportAEGISRequired() &&
        !brain.localInternalTransportCredentialCurrent() && !brain.localBrainEligibleForMasterElection() &&
        !brain.isActiveMaster() &&
        !brain.beginInternalControlTransport(&incoming, true, ProdigyTransportCredentialNodeRole::brain, peerBrain.nodeUUID) &&
        !brain.beginInternalControlTransport(&outgoing, false, ProdigyTransportCredentialNodeRole::brain, peerBrain.nodeUUID) &&
        !incoming.transportEncryptionEnabled() && !outgoing.transportEncryptionEnabled(),
        "runtime_terminal_brain_persisted_fence_precedes_legacy_transport_fallback_without_loaded_authority");
  }
  thisNeuron = savedNeuron;
  persistentLocalBrainState = savedLocal;
}

static void testPersistentWriterRetainedAccountingChargesManyShortStrings(TestSuite& suite)
{
  ProdigyPersistentBrainSnapshot snapshot = {};
  for (uint32_t index = 0; index < 512; ++index)
  {
    String key = {}, value = {};
    key.snprintf<"key-{itoa}"_ctv>(index);
    value.snprintf<"value-{itoa}"_ctv>(index);
    snapshot.brainConfig.dnsCredential.metadata.insert_or_assign(std::move(key), std::move(value));
  }
  String wire = {};
  ProdigyPersistentBrainSnapshot wireCopy = snapshot;
  BitseryEngine::serialize(wire, wireCopy);
  const uint64_t oldFlatEstimate = 2 * sizeof(snapshot) + 3 * wire.size();
  const uint64_t retained = ProdigyPersistentStateWriter::retainedBytesFor(snapshot);
  suite.expect(retained > oldFlatEstimate && retained <= ProdigyPersistentStateWriter::maximumRetainedBytes,
               "runtime_persistence_writer_accounts_many_short_string_allocations");
}

static void testNeuronOSUpdateUsesOwnedReceiptDrivenRequest(TestSuite& suite)
{
  ReceiptTestNeuron neuron;
  String buffer = {};
  Message *message = runtimePersistenceMessage(buffer, NeuronTopic::updateOS,
                                               "ubuntu"_ctv, "24.04"_ctv, "update-command"_ctv);
  neuron.neuronHandler(message);
  buffer.clear();
  suite.expect(neuron.submissions == 1 && neuron.targetOSID.equals("ubuntu"_ctv) &&
                   neuron.targetOSVersionID.equals("24.04"_ctv) &&
                   neuron.command.equals("update-command"_ctv),
               "runtime_persistence_neuron_os_update_owns_request_before_receipt");
  suite.expect(bool(neuron.receipt), "runtime_persistence_neuron_os_update_retains_receipt_callback");
  if (neuron.receipt) neuron.receipt(false, "injected receipt failure"_ctv);
}

static void testRuntimeAwareBrainActivatesOnlyTheAsyncPersistenceOwner(TestSuite& suite)
{
  const ProdigyPersistentBootState boot = runtimePersistenceBootState();
  RuntimeAwareBrainIaaS iaas(nullptr, boot.bootstrapConfig, boot, {});
  uint32_t submissions = 0;
  uint32_t completions = 0;
  uint64_t retainedBytes = 0;
  iaas.setAsyncBootStatePersistence([&](ProdigyPersistentBootState submitted, uint64_t bytes,
                                        std::function<void(bool)> completion) {
    ++submissions;
    retainedBytes = bytes;
    suite.expect(submitted.bootstrapSshUser.equals("bootstrap-user"_ctv),
                 "runtime_persistence_brain_preserves_boot_state_payload");
    completion(true);
    ++completions;
    return true;
  });

  ProdigyBootstrapConfig changed = boot.bootstrapConfig;
  iaas.configureBootstrapTopology(changed);

  suite.expect(submissions == 1 && completions == 1,
               "runtime_persistence_brain_activation_submits_once");
  suite.expect(retainedBytes > sizeof(ProdigyPersistentBootState) &&
                   retainedBytes < ProdigyPersistentStateWriter::maximumRetainedBytes,
               "runtime_persistence_brain_measures_schema_without_encoding");
}

static void testRuntimeAwareNeuronActivatesOnlyTheAsyncPersistenceOwner(TestSuite& suite)
{
  const ProdigyPersistentBootState boot = runtimePersistenceBootState();
  RuntimeAwareNeuronIaaS iaas(nullptr, boot.bootstrapConfig, boot, {});
  uint32_t submissions = 0;
  uint64_t retainedBytes = 0;
  iaas.setAsyncBootStatePersistence([&](ProdigyPersistentBootState submitted, uint64_t bytes,
                                        std::function<void(bool)> completion) {
    ++submissions;
    retainedBytes = bytes;
    suite.expect(submitted.bootstrapSshUser.equals("bootstrap-user"_ctv),
                 "runtime_persistence_neuron_preserves_boot_state_payload");
    completion(true);
    return true;
  });

  ProdigyBootstrapConfig changed = boot.bootstrapConfig;
  iaas.configureBootstrapTopology(changed);

  suite.expect(submissions == 1,
               "runtime_persistence_neuron_activation_submits_once");
  suite.expect(retainedBytes > sizeof(ProdigyPersistentBootState) &&
                   retainedBytes < ProdigyPersistentStateWriter::maximumRetainedBytes,
               "runtime_persistence_neuron_measures_schema_without_encoding");
}

static void testBootPersistenceAdmissionRejectionHasNoReceipt(TestSuite& suite)
{
  // The live submission contract is deliberately asymmetric: false means the
  // caller retained ownership and therefore no completion may be delivered.
  livePersistentWriter.reset();
  bool helperReceipt = false;
  ProdigyPersistentBootState state = runtimePersistenceBootState();
  const uint64_t retainedBytes = ProdigyPersistentStateWriter::retainedBytesFor(state);
  const bool helperAdmitted = prodigySubmitLiveBootState(std::move(state), retainedBytes,
      [&](bool) { helperReceipt = true; });
  suite.expect(!helperAdmitted && !helperReceipt,
               "runtime_persistence_live_boot_rejection_has_no_receipt");

  const ProdigyPersistentBootState boot = runtimePersistenceBootState();
  RuntimeAwareBrainIaaS brain(nullptr, boot.bootstrapConfig, boot, {});
  uint32_t brainAdmissions = 0;
  uint32_t brainReceipts = 0;
  brain.setAsyncBootStatePersistence([&](ProdigyPersistentBootState, uint64_t,
                                         std::function<void(bool)> completion) {
    ++brainAdmissions;
    (void)completion;
    return false;
  });
  brain.configureBootstrapTopology(boot.bootstrapConfig);
  suite.expect(brainAdmissions == 1 && brainReceipts == 0,
               "runtime_persistence_brain_handles_boot_admission_rejection");

  RuntimeAwareNeuronIaaS neuron(nullptr, boot.bootstrapConfig, boot, {});
  uint32_t neuronAdmissions = 0;
  uint32_t neuronReceipts = 0;
  neuron.setAsyncBootStatePersistence([&](ProdigyPersistentBootState, uint64_t,
                                          std::function<void(bool)> completion) {
    ++neuronAdmissions;
    (void)completion;
    return false;
  });
  neuron.configureBootstrapTopology(boot.bootstrapConfig);
  suite.expect(neuronAdmissions == 1 && neuronReceipts == 0,
               "runtime_persistence_neuron_handles_boot_admission_rejection");
}

static void testProductionPersistenceAPI(TestSuite& suite)
{
  for (int failureMode = 0; failureMode < 3; ++failureMode)
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    suite.expect(io != nullptr, "runtime_api_worker_starts");
    if (!io) continue;
    std::atomic<bool> release = false, entered = false;
    uint32_t ticks = 0, ownershipReceipts = 0, snapshotReceipts = 0;
    bool snapshotSucceeded = false, drainInsideCallback = true;
    bool localSaved = false, snapshotSaved = false, bootSaved = false;
    auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io,
        [&](auto& backingStore, auto& request) {
          entered = true;
          while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
          if (request.writeLocalState)
          {
            request.result.durable = backingStore.saveLocalBrainState(request.localState, &request.result.failure);
            localSaved = request.result.durable;
          }
          else
          {
            if (failureMode == 1) { request.result.failure.assign("injected snapshot failure"_ctv); return; }
            request.result.snapshotDurable = backingStore.saveBrainSnapshot(request.snapshot, &request.result.failure);
            request.result.durable = request.result.snapshotDurable;
            snapshotSaved = request.result.snapshotDurable;
            if (failureMode == 2) { request.result.failure.assign("injected boot follow-up failure"_ctv); return; }
            request.result.bootStateDurable = backingStore.saveBootState(request.bootState, &request.result.failure);
            bootSaved = request.result.bootStateDurable;
          }
        });
    persistentLocalBrainState = {};
    persistentLocalBrainState.uuid = 0x9901;
    persistentBootState = {};
    persistedBrainSnapshot = {};
    havePersistedBrainSnapshot = false;
    ProdigyHostControlNetwork network;
    {
      ProdigyBrain brain(network, writer);
      brain.brainConfig.clusterUUID = 0x9902;
      brain.brainConfig.bootstrapSshUser.assign("candidate-bootstrap-user"_ctv);
      suite.expect(!brain.persistLocalRuntimeState(), "runtime_api_rejects_live_sync_call");
      suite.expect(brain.claimLocalClusterOwnershipAsync(0x9902, [&](bool owned) {
        ++ownershipReceipts;
        suite.expect(owned && persistentLocalBrainState.ownerClusterUUID == 0x9902,
                     "runtime_api_ownership_cache_follows_durable_receipt");
        brain.persistLocalRuntimeStateAsync([&](bool durable) {
          ++snapshotReceipts;
          snapshotSucceeded = durable;
          drainInsideCallback = writer->drainForExec();
          Ring::exit = true;
        });
      }), "runtime_api_ownership_admitted");
      suite.expect(ownershipReceipts == 0 && snapshotReceipts == 0,
                   "runtime_api_no_inline_success_for_pending_disk");
      ring.tickAction = [&] {
        ++ticks;
        if (ticks == 30) release = true;
        else if (ticks < 30) ring.armTick(5);
      };
      ring.armTick(5); ring.armDeadline(5000);
      Ring::start();
      release = true;
      suite.expect(!ring.timedOut && ticks == 30 && ownershipReceipts == 1 && snapshotReceipts == 1,
                   "runtime_api_ring_progress_and_reentrant_ownership_to_snapshot");
      suite.expect(snapshotSucceeded == (failureMode == 0) && !drainInsideCallback && writer->drainForExec(),
                   "runtime_api_durability_and_drain_follow_terminal_receipt");
      suite.expect(localSaved && snapshotSaved == (failureMode != 1) && bootSaved == (failureMode == 0) &&
                       havePersistedBrainSnapshot == (failureMode != 1),
                   "runtime_api_partial_commit_cache_matches_durable_records");
      if (failureMode == 0)
        suite.expect(persistentBootState.bootstrapSshUser.equals("candidate-bootstrap-user"_ctv),
                     "runtime_api_boot_cache_uses_candidate_configuration");
    }
    writer.reset();
    io->stop(); ring.drainStoppedIO(); io.reset();
    (void)network.shutdown();
    store.close();
    ProdigyPersistentStateStore reopened(root.path);
    ProdigyPersistentBrainSnapshot snapshot;
    String failure;
    suite.expect(reopened.loadBrainSnapshot(snapshot, &failure) == (failureMode != 1),
                 "runtime_api_reopen_matches_snapshot_durability");
    reopened.close();
  }
}

static void testProductionPersistenceAdmissionFromArtifactCompletion(TestSuite& suite)
{
  PersistenceRing ring;
  ScopedPersistentRoot root;
  ProdigyPersistentStateStore store(root.path);
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "runtime_artifact_completion_starts_shared_writer");
  if (!io) return;

  persistentLocalBrainState = {};
  persistentBootState = {};
  persistedBrainSnapshot = {};
  havePersistedBrainSnapshot = false;
  auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io);
  ProdigyHostControlNetwork network;
  bool artifactPublished = false;
  bool receiptWasInline = false;
  bool receiptDelivered = false;
  bool durable = false;
  bool queued = false;
  {
    ProdigyBrain brain(network, writer);
    brain.brainConfig.clusterUUID = 0xA51EULL;
    brain.brainConfig.bootstrapSshUser.assign("artifact-receipt"_ctv);
    queued = io->submit(1, [] {}, [&] {
      artifactPublished = true;
      brain.persistLocalRuntimeStateAsync([&](bool result) {
        receiptDelivered = true;
        durable = result;
        Ring::exit = true;
      });
      receiptWasInline = receiptDelivered;
    }, [](std::exception_ptr) { Ring::exit = true; });
    ring.armDeadline(1000);
    Ring::start();
    suite.expect(queued && !ring.timedOut && artifactPublished && !receiptWasInline && receiptDelivered && durable && writer->drainForExec(),
                 "runtime_artifact_publish_completion_admits_production_snapshot_receipt");
  }
  writer.reset();
  io->stop();
  ring.drainStoppedIO();
  io.reset();
  (void)network.shutdown();
  store.close();
  ProdigyPersistentStateStore reopened(root.path);
  ProdigyPersistentBrainSnapshot persisted = {};
  String failure = {};
  suite.expect(reopened.loadBrainSnapshot(persisted, &failure) && persisted.brainConfig.clusterUUID == 0xA51EULL,
               "runtime_artifact_publish_receipt_reopens_production_snapshot");
  reopened.close();
}

static ClusterTopology runtimePersistenceTopology(uint64_t version, uint128_t uuid)
{
  ClusterTopology topology = {};
  topology.version = version;
  ClusterMachine machine = {};
  machine.uuid = uuid;
  machine.source = ClusterMachineSource::created;
  machine.backing = ClusterMachineBacking::cloud;
  machine.isBrain = true;
  ClusterMachineAddress privateAddress = {};
  privateAddress.address.assign("10.77.0.1"_ctv);
  privateAddress.cidr = 24;
  machine.addresses.privateAddresses.push_back(std::move(privateAddress));
  topology.machines.push_back(std::move(machine));
  prodigyNormalizeClusterTopologyPeerAddresses(topology);
  return topology;
}

static void testProductionTopologySnapshotOverlap(TestSuite& suite)
{
  for (int failureMode = 0; failureMode < 2; ++failureMode)
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    suite.expect(io != nullptr, "topology_snapshot_overlap_starts_writer");
    if (!io) continue;

    std::atomic<bool> firstEntered = false, releaseFirst = false, releaseSecond = false;
    std::atomic<uint32_t> snapshotWrites = 0;
    auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io,
        [&](auto& backing, auto& request) {
          if (!request.writeSnapshot) return;
          const uint32_t write = ++snapshotWrites;
          if (write == 1)
          {
            firstEntered = true;
            while (!releaseFirst.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (failureMode)
            {
              request.result.failure.assign("injected predecessor failure"_ctv);
              return;
            }
          }
          if (failureMode == 0 && write == 2)
            while (!releaseSecond.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
          request.result.snapshotDurable = backing.saveBrainSnapshot(request.snapshot, &request.result.failure);
          request.result.durable = request.result.snapshotDurable;
          if (request.result.snapshotDurable)
            request.result.bootStateDurable = backing.saveBootState(request.bootState, &request.result.failure);
        });

    const ClusterTopology baselineTopology = runtimePersistenceTopology(6, 0x7a00);
    const ClusterTopology firstTopology = runtimePersistenceTopology(7, 0x7a01);
    ClusterTopology secondTopology = {};
    secondTopology.version = 8;
    ProdigyPersistentBrainSnapshot baselineSnapshot = {};
    baselineSnapshot.topology = baselineTopology;
    baselineSnapshot.brainConfig.clusterUUID = 0x7a00;
    prodigyAppendClusterTopologyBrainPeers(baselineSnapshot.brainPeers, baselineSnapshot.topology);
    ProdigyPersistentBootState baselineBoot = runtimePersistenceBootState();
    baselineBoot.bootstrapConfig.bootstrapPeers = baselineSnapshot.brainPeers;
    String seedFailure = {};
    suite.expect(store.saveBrainSnapshot(baselineSnapshot, &seedFailure) &&
                     store.saveBootState(baselineBoot, &seedFailure),
                 "topology_snapshot_overlap_seeds_durable_baseline");
    persistentLocalBrainState = {};
    persistentBootState = baselineBoot;
    persistedBrainSnapshot = baselineSnapshot;
    havePersistedBrainSnapshot = true;
    ProdigyHostControlNetwork network;
    bool firstTopologyReceipt = false, firstTopologyDurable = false;
    bool replayReceipt = false, replayDurable = false;
    bool secondTopologyReceipt = false, secondTopologyDurable = false;
    bool ordinaryReceipt = false, ordinaryDurable = false;
    bool pendingReadDurableOnly = false;
    bool pendingSecondSubmitted = false, ordinarySubmitted = false;
    bool durableBaselineStaleRejected = false, durableBaselineConflictRejected = false;
    bool durableReplayReceipt = false, durableReplayDurable = false, durableReplayWasInline = false;
    {
      ProdigyBrain brain(network, writer);
      brain.brainConfig.clusterUUID = 0x7a00;
      brain.persistAuthoritativeClusterTopologyAsync(firstTopology, [&](bool durable) {
        firstTopologyReceipt = true;
        firstTopologyDurable = durable;
      });
      // This replay must share the outstanding durability receipt instead of
      // observing an invented synchronous success.
      brain.persistAuthoritativeClusterTopologyAsync(firstTopology, [&](bool durable) {
        replayReceipt = true;
        replayDurable = durable;
      });
      ClusterTopology durableRead = {};
      pendingReadDurableOnly = brain.loadAuthoritativeClusterTopology(durableRead) && durableRead == baselineTopology;
      ClusterTopology mutationBase = {};
      suite.expect(brain.loadAuthoritativeClusterTopologyForMutation(mutationBase) && mutationBase == firstTopology,
                   "topology_snapshot_overlap_dependent_mutation_retains_admitted_base");
      ClusterTopology stale = firstTopology;
      stale.version -= 1;
      brain.persistAuthoritativeClusterTopologyAsync(std::move(stale), [&](bool durable) {
        durableBaselineStaleRejected = !durable;
      });
      ClusterTopology conflict = firstTopology;
      conflict.machines[0].uuid = 0x7a02;
      brain.persistAuthoritativeClusterTopologyAsync(std::move(conflict), [&](bool durable) {
        durableBaselineConflictRejected = !durable;
      });
      suite.expect(!firstTopologyReceipt && !replayReceipt && pendingReadDurableOnly &&
                       durableBaselineStaleRejected && durableBaselineConflictRejected,
                   "topology_snapshot_overlap_pending_shadow_preserves_durable_reads_and_waits_for_identical_replay");

      ring.tickAction = [&] {
        if (failureMode == 0 && firstEntered.load() && !pendingSecondSubmitted)
        {
          pendingSecondSubmitted = true;
          brain.persistAuthoritativeClusterTopologyAsync(secondTopology, [&](bool durable) {
            secondTopologyReceipt = true;
            secondTopologyDurable = durable;
          });
          releaseFirst = true;
        }
        // The first callback must not clear the newer T2 shadow. Keep the T2
        // worker blocked until this ordinary snapshot has been constructed.
        if (failureMode == 0 && firstTopologyReceipt && !ordinarySubmitted)
        {
          ordinarySubmitted = true;
          brain.persistLocalRuntimeStateAsync([&](bool durable) {
            ordinaryReceipt = true;
            ordinaryDurable = durable;
            if (failureMode)
            {
              Ring::exit = true;
              return;
            }
            ClusterTopology staleDurable = firstTopology;
            brain.persistAuthoritativeClusterTopologyAsync(std::move(staleDurable), [&](bool result) {
              durableBaselineStaleRejected = !result;
            });
            ClusterTopology conflictDurable = secondTopology;
            conflictDurable.machines.push_back(runtimePersistenceTopology(8, 0x7a03).machines[0]);
            brain.persistAuthoritativeClusterTopologyAsync(std::move(conflictDurable), [&](bool result) {
              durableBaselineConflictRejected = !result;
            });
            brain.persistAuthoritativeClusterTopologyAsync(secondTopology, [&](bool result) {
              durableReplayReceipt = true;
              durableReplayDurable = result;
              Ring::exit = true;
            });
            durableReplayWasInline = durableReplayReceipt;
          });
          releaseSecond = true;
        }
        if (failureMode && firstEntered.load() && !ordinarySubmitted)
        {
          ordinarySubmitted = true;
          brain.persistLocalRuntimeStateAsync([&](bool durable) {
            ordinaryReceipt = true;
            ordinaryDurable = durable;
            Ring::exit = true;
          });
          releaseFirst = true;
        }
        if (!ordinaryReceipt || (failureMode == 0 && !durableReplayReceipt)) ring.armTick(1);
      };
      ring.armTick(1);
      ring.armDeadline(3000);
      Ring::start();
      releaseFirst = true;

      const bool expectedDurable = failureMode == 0;
      suite.expect(!ring.timedOut && pendingSecondSubmitted == expectedDurable && ordinarySubmitted &&
                       firstTopologyReceipt && replayReceipt && ordinaryReceipt &&
                       firstTopologyDurable == expectedDurable && replayDurable == expectedDurable &&
                       ordinaryDurable == expectedDurable &&
                       (failureMode || (secondTopologyReceipt && secondTopologyDurable && durableReplayReceipt &&
                                        durableReplayDurable && !durableReplayWasInline)) && writer->drainForExec(),
                   failureMode == 0 ? "topology_snapshot_overlap_receipts_follow_fifo_success" :
                                      "topology_snapshot_overlap_failed_predecessor_fences_fifo_successor");
    }
    writer.reset();
    io->stop();
    ring.drainStoppedIO();
    io.reset();
    (void)network.shutdown();
    store.close();

    ProdigyPersistentStateStore reopened(root.path);
    ProdigyPersistentBrainSnapshot stored = {};
    String failure = {};
    const bool loaded = reopened.loadBrainSnapshot(stored, &failure);
    ProdigyPersistentBootState storedBoot = {};
    const bool bootLoaded = reopened.loadBootState(storedBoot, &failure);
    suite.expect(failureMode == 0 ?
                     loaded && bootLoaded && stored.topology == secondTopology && stored.brainPeers.empty() &&
                         storedBoot.bootstrapConfig.bootstrapPeers.empty() && durableBaselineStaleRejected &&
                         durableBaselineConflictRejected :
                     loaded && stored.topology == baselineTopology,
                 failureMode == 0 ? "topology_snapshot_overlap_ordinary_snapshot_retains_admitted_topology_and_peers" :
                                    "topology_snapshot_overlap_failed_predecessor_preserves_durable_baseline");
    reopened.close();
    persistentLocalBrainState = {};
    persistentBootState = {};
    persistedBrainSnapshot = {};
    havePersistedBrainSnapshot = false;
  }
}

static void testProductionUpdateProgressDefersReentrantPersistenceUntilArtifactLeaseReleases(TestSuite& suite)
{
  // The first durable receipt begins bundle progress.  Its ArtifactIO slot is
  // intentionally still retained while the callback runs; seven queued jobs
  // fill the remaining slots.  A nested snapshot must therefore be deferred
  // until this receipt returns, rather than being synchronously rejected and
  // permanently fencing the update.
  for (int nestedMode = 0; nestedMode < 3; ++nestedMode)
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    suite.expect(io != nullptr, "runtime_reentrant_update_worker_starts");
    if (!io) continue;

    std::atomic<bool> firstCommitEntered = false;
    std::atomic<bool> allowFirstCommit = false;
    std::atomic<bool> releaseFillers = false;
    std::atomic<uint32_t> snapshotWrites = 0, bootWrites = 0;
    auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io,
        [&](auto& backing, auto& request) {
          if (!request.writeSnapshot) return;
          const uint32_t write = ++snapshotWrites;
          if (write == 1)
          {
            firstCommitEntered = true;
            while (!allowFirstCommit.load())
              std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
          if (nestedMode == 1 && write == 2)
          {
            request.result.failure.assign("injected nested durable failure"_ctv);
            return;
          }
          request.result.snapshotDurable = backing.saveBrainSnapshot(request.snapshot, &request.result.failure);
          request.result.durable = request.result.snapshotDurable;
          if (request.result.snapshotDurable)
          {
            request.result.bootStateDurable = backing.saveBootState(request.bootState, &request.result.failure);
            if (request.result.bootStateDurable) ++bootWrites;
          }
        });

    persistentLocalBrainState = {};
    persistentBootState = {};
    persistedBrainSnapshot = {};
    havePersistedBrainSnapshot = false;
    ProdigyHostControlNetwork network;
    uint32_t fillersCompleted = 0, ticks = 0;
    bool fillersQueued = false, firstReceipt = false, firstDurable = false;
    bool noEarlyBundleSend = true, releasedFillers = false, epochInvalidated = false;
    uint32_t settledAtTick = 0;
    {
      ProdigyBrain brain(network, writer);
      brain.brainConfig.clusterUUID = 0xA5510000ULL + nestedMode;
      brain.brainConfig.bootstrapSshUser.assign("reentrant-update"_ctv);
      brain.updateSelfUseStagedBundleOnly = true;
      BrainView peer = {};
      peer.uuid = 0xA5511000ULL + nestedMode;
      peer.boottimens = 1;
      // A known but inactive peer makes a later transition observable without
      // allowing this focused persistence fixture to queue a fake socket send.
      brain.brains.insert(&peer);

      brain.persistLocalRuntimeStateAsync([&](bool durable) {
        firstReceipt = true;
        firstDurable = durable;
        if (!durable) return;
        brain.beginUpdateSelfBundle(1);
        noEarlyBundleSend = peer.wBuffer.empty() && brain.updateSelfBundleIssuedPeerKeys.empty();
        // The deferred initiation must be fenced by the same authority epoch
        // that owns the staged update, even though the original receipt was
        // durable.  This mode verifies the stale request remains fail-closed.
        if (nestedMode == 2)
        {
          brain.advanceMasterAuthorityEpoch();
          epochInvalidated = true;
        }
      });

      ring.tickAction = [&] {
        ++ticks;
        if (!fillersQueued && firstCommitEntered.load())
        {
          for (uint32_t index = 0; index < ProdigyArtifactIO::maximumJobs - 1; ++index)
          {
            const bool admitted = io->submit(1,
                [&] {
                  while (!releaseFillers.load())
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                },
                [&] { ++fillersCompleted; },
                [&](std::exception_ptr) { Ring::exit = true; });
            suite.expect(admitted, "runtime_reentrant_update_fills_remaining_artifact_slots");
          }
          fillersQueued = true;
          allowFirstCommit = true;
        }
        // After the first callback returns, the fixed path can admit the
        // nested save as slot eight.  Releasing these jobs then lets it reach
        // the worker without relying on a large snapshot or a timing race.
        if (firstReceipt && fillersQueued && !releasedFillers &&
            (brain.updateSelfPersistencePending != 0 || brain.updateSelfPersistenceFailed || ticks > 20))
        {
          releasedFillers = true;
          releaseFillers = true;
        }
        const bool nestedDone = nestedMode == 1 ? brain.updateSelfPersistenceFailed :
            (nestedMode == 2 || (brain.masterAuthorityRuntimeStateDurable &&
             brain.durableMasterAuthorityRuntimeStateGeneration == brain.masterAuthorityRuntimeState.generation));
        if (fillersCompleted == ProdigyArtifactIO::maximumJobs - 1 && firstReceipt && nestedDone)
        {
          // Successful continuations are intentionally one more Ring turn
          // removed from the persistence receipt.  Keep pumping past the
          // observed state so their timer and any ready work cannot retain
          // Brain during this fixture's teardown.
          if (settledAtTick == 0) settledAtTick = ticks;
          if (ticks - settledAtTick >= 5)
          {
            Ring::exit = true;
            return;
          }
        }
        ring.armTick(1);
      };
      ring.armTick(1);
      ring.armDeadline(3000);
      Ring::start();
      releaseFillers = true;

      suite.expect(!ring.timedOut && ticks > 1 && fillersQueued && fillersCompleted == ProdigyArtifactIO::maximumJobs - 1,
                   "runtime_reentrant_update_ring_remains_responsive_under_full_artifact_slots");
      suite.expect(firstReceipt && firstDurable && noEarlyBundleSend &&
                       brain.updateSelfState == Brain::UpdateSelfState::waitingForBundleEchos,
                   "runtime_reentrant_update_does_not_send_bundle_before_nested_receipt");
      const bool expectedFailure = nestedMode == 1;
      const bool epochStale = nestedMode == 2;
      suite.expect(brain.updateSelfPersistenceFailed == (expectedFailure || epochStale) &&
                       brain.updateSelfPersistencePending == 0,
                   "runtime_reentrant_update_fences_failed_or_stale_nested_receipt");
      suite.expect(snapshotWrites.load() == (epochStale ? 1u : 2u) &&
                       bootWrites.load() == (expectedFailure || epochStale ? 1u : 2u),
                   "runtime_reentrant_update_nested_snapshot_admission_or_stale_suppression");
      suite.expect(epochStale ? epochInvalidated && peer.wBuffer.empty() && brain.updateSelfBundleIssuedPeerKeys.empty() :
                       (expectedFailure || (brain.masterAuthorityRuntimeStateDurable &&
                        brain.durableMasterAuthorityRuntimeStateGeneration == brain.masterAuthorityRuntimeState.generation)),
                   "runtime_reentrant_update_epoch_invalidated_request_cannot_send_stale_bundle");
      brain.brains.erase(&peer);
    }
    writer.reset();
    io->stop();
    ring.drainStoppedIO();
    io.reset();
    (void)network.shutdown();
    store.close();
    persistentLocalBrainState = {};
    persistentBootState = {};
    persistedBrainSnapshot = {};
    havePersistedBrainSnapshot = false;
  }
}

static void testFollowerMetricIngestionTrimsBeforePersistence(TestSuite& suite)
{
  PersistenceRing ring;
  ProdigyHostControlNetwork network;
  class Follower final : public ProdigyBrain {
  public:
    uint32_t receipts = 0;
    size_t capturedSamples = 0;
    explicit Follower(ProdigyHostControlNetwork& network) : ProdigyBrain(network, {}) {}
    void persistLocalRuntimeStateAsync(PersistenceCompletion completion = {}) override
    {
      ++receipts;
      capturedSamples = metrics.captureSnapshot()->sampleCount();
      if (completion) completion(true);
    }
  } brain(network);
  brain.weAreMaster = false;
  const int64_t nowMs = Time::now<TimeResolution::ms>();
  brain.metrics.record(7, 0xABC, 1, nowMs - BrainBase::metricRetentionMs - 60'000, 1);
  brain.metrics.record(7, 0xABC, 1, nowMs - 1'000, 2);
  brain.recordContainerMetric(7, 0xABC, 1, nowMs, 3);
  suite.expect(brain.deployments.empty() && brain.receipts == 1 && brain.capturedSamples == 2,
               "follower_metric_ingestion_expires_history_before_snapshot_without_autoscaling");
  suite.expect(brain.metrics.series.at(7).at(0xABC).at(1).size() == 2 &&
                   brain.metrics.fleetSeries.at(7).at(1).size() == 2,
               "follower_metric_retention_preserves_recent_instance_and_fleet_samples");
}

static void testLargeMetricHistoryUsesImmutableAsyncCapture(TestSuite& suite)
{
  PersistenceRing ring;
  ScopedPersistentRoot root;
  ProdigyPersistentStateStore store(root.path);
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "metric_capture_worker_starts");
  if (!io) return;
  constexpr uint32_t seriesCount = 128, perSeries = 12'500;
  constexpr uint64_t sampleCount = uint64_t(seriesCount) * perSeries;
  const auto ringThread = std::this_thread::get_id();
  std::atomic<bool> entered = false, release = false;
  bool workerThread = false;
  auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io,
      [&](auto& backing, auto& request) {
        workerThread = std::this_thread::get_id() != ringThread;
        entered = true;
        while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        request.result.snapshotDurable = backing.saveBrainSnapshot(request.snapshot, &request.result.failure);
        request.result.durable = request.result.snapshotDurable;
        if (request.result.snapshotDurable)
          request.result.bootStateDurable = backing.saveBootState(request.bootState, &request.result.failure);
      });
  persistentLocalBrainState = {};
  persistentBootState = {};
  persistedBrainSnapshot = {};
  havePersistedBrainSnapshot = false;
  ProdigyHostControlNetwork network;
  Vector<int64_t> captures, controls;
  uint32_t receipts = 0, heldTicks = 0;
  bool durable = false, allDeferred = true, allAdmissible = true;
  {
    ProdigyBrain brain(network, writer);
    brain.brainConfig.clusterUUID = 0xCA9701;
    for (uint64_t key = 1; key <= seriesCount; ++key)
      for (uint32_t i = 0; i < perSeries; ++i)
        brain.metrics.record(7, 0xABC, key, i, i);

    int64_t lastTick = 0;
    ring.tickAction = [&] {
      const auto now = std::chrono::steady_clock::now();
      const int64_t current = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
      if (lastTick) controls.push_back(current - lastTick);
      lastTick = current;
      if (captures.size() < 30)
      {
        {
          auto snapshot = brain.buildPersistentBrainSnapshot();
          const auto frozen = snapshot.metricCapture;
          auto copy = snapshot;
          allDeferred = allDeferred && frozen && frozen->sampleCount() == sampleCount &&
              copy.metricSamples.empty() && copy.metricCapture == frozen;
          allAdmissible = allAdmissible && ProdigyPersistentStateWriter::detach(copy) &&
              ProdigyPersistentStateWriter::retainedBytesFor(copy) > 0;
        }
        captures.push_back(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - now).count());
        ring.armTick(1);
        return;
      }
      if (!receipts && heldTicks == 0)
      {
        brain.persistLocalRuntimeStateAsync([&](bool result) {
          ++receipts;
          durable = result;
          Ring::exit = true;
        });
        suite.expect(receipts == 0, "metric_capture_no_inline_durable_ack");
        // An admitted snapshot must retain its exact samples through mutation,
        // expiry and destruction of all current live series.
        brain.metrics.record(7, 0xABC, 1, perSeries, -1);
        brain.metrics.trimRetention(perSeries + 1, 0);
        brain.metrics.clear();
        brain.metrics.record(9, 0xDEF, 2, 1, -2);
      }
      if (++heldTicks == 30) release = true;
      ring.armTick(5);
    };
    ring.armTick(1); ring.armDeadline(10'000);
    Ring::start();
    release = true;
    suite.expect(!ring.timedOut && captures.size() == 30 && controls.size() >= 30 &&
                     entered && workerThread && heldTicks >= 30 && receipts == 1 && durable && writer->drainForExec(),
                 "metric_capture_background_commit_progress_and_exact_receipt");
    suite.expect(allDeferred, "metric_capture_does_not_flatten_or_copy_history_on_ring");
    suite.expect(allAdmissible, "metric_capture_accounts_retained_graph_and_worker_encoding");
    auto sorted = captures;
    std::sort(sorted.begin(), sorted.end());
    const int64_t captureP95 = sorted.size() == 30 ? sorted[28] : INT64_MAX;
    suite.expect(captureP95 < 10'000, "metric_capture_submission_p95_under_10ms");
    auto controlSorted = controls;
    std::sort(controlSorted.begin(), controlSorted.end());
    const int64_t controlP95 = controlSorted.empty() ? INT64_MAX : controlSorted[(controlSorted.size() * 95 + 99) / 100 - 1];
    suite.expect(controlP95 < 10'000, "metric_capture_control_p95_under_10ms");
    std::printf("METRIC_CAPTURE samples=%llu captureP95Us=%lld controlP95Us=%lld captureUs=",
                (unsigned long long)sampleCount, (long long)captureP95, (long long)controlP95);
    for (auto us : captures) std::printf("%lld,", (long long)us);
    std::printf(" controlUs=");
    for (auto us : controls) std::printf("%lld,", (long long)us);
    std::printf("\n");
  }
  writer.reset(); io->stop(); ring.drainStoppedIO(); io.reset();
  (void)network.shutdown(); store.close();
  ProdigyPersistentStateStore reopened(root.path);
  ProdigyPersistentBrainSnapshot decoded;
  String failure;
  bool correct = reopened.loadBrainSnapshot(decoded, &failure) &&
      decoded.brainConfig.clusterUUID == 0xCA9701 && decoded.metricSamples.size() == sampleCount;
  std::array<uint32_t, seriesCount> counts = {};
  for (const auto& sample : decoded.metricSamples)
  {
    const bool valid = sample.deploymentID == 7 && sample.containerUUID == 0xABC &&
        sample.metricKey >= 1 && sample.metricKey <= seriesCount && sample.ms >= 0 &&
        sample.ms < perSeries && sample.value == float(sample.ms);
    correct = correct && valid;
    if (valid)
    {
      correct = correct && uint32_t(sample.ms) == counts[sample.metricKey - 1];
      ++counts[sample.metricKey - 1];
    }
  }
  for (auto count : counts) correct = correct && count == perSeries;
  suite.expect(correct, "metric_capture_reopens_exact_generation_after_live_mutation");
  reopened.close();
  persistedBrainSnapshot = {};
  havePersistedBrainSnapshot = false;
}

static void testDurableMaterializedRecoveryHistoricalCull(TestSuite& suite)
{
  PersistenceRing ring = {};
  ProdigyHostControlNetwork network;
  ProdigyBrain brain(network, {});
  BrainBase *savedBrain = thisBrain;
  thisBrain = &brain;

  constexpr uint16_t applicationID = 64001;
  auto *historical = new ApplicationDeployment();
  auto *active = new ApplicationDeployment();
  auto *successor = new ApplicationDeployment();
  active->plan.config.applicationID = applicationID;
  active->plan.config.versionID = 680001;
  successor->plan = active->plan;
  successor->plan.config.versionID = 680002;
  historical->plan = active->plan;
  historical->plan.config.versionID = 678302;
  historical->state = DeploymentState::none;
  historical->next = active;
  active->previous = historical;
  active->next = successor;
  successor->previous = active;

  const uint64_t historicalID = historical->plan.config.deploymentID();
  const uint64_t activeID = active->plan.config.deploymentID();
  const uint64_t successorID = successor->plan.config.deploymentID();
  brain.deployments.insert_or_assign(historicalID, historical);
  brain.deployments.insert_or_assign(activeID, active);
  brain.deployments.insert_or_assign(successorID, successor);
  ProdigyMaterializedStatefulRecoveryOperation operation = {};
  operation.activeDeploymentID = activeID;
  operation.successorDeploymentID = successorID;
  operation.accepted = operation.started = true;
  brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.push_back(operation);

  suite.expect(brain.cullMaterializedStatefulRecoveryHistoricalPredecessor(active, successor, activeID, successorID) == false &&
                   active->previous == historical && brain.deployments.contains(historicalID),
               "materialized_recovery_historical_cull_requires_durable_operation");
  brain.masterAuthorityRuntimeStateDurable = true;
  suite.expect(brain.cullMaterializedStatefulRecoveryHistoricalPredecessor(active, successor, activeID, successorID) &&
                   active->previous == nullptr && brain.deployments.contains(historicalID) == false,
               "materialized_recovery_historical_cull_detaches_empty_predecessor_after_durability");
  suite.expect(brain.cullMaterializedStatefulRecoveryHistoricalPredecessor(active, successor, activeID, successorID),
               "materialized_recovery_historical_cull_is_idempotent_after_restart");

  brain.deployments.erase(activeID);
  brain.deployments.erase(successorID);
  delete successor;
  delete active;
  thisBrain = savedBrain;
}

static void testNeuronTransportCredentialPeerProjectionDurabilityAndStreamFence(TestSuite& suite)
{
  constexpr uint128_t neuronUUID = uint128_t(0x7105);
  constexpr uint128_t brainUUID = uint128_t(0x7104);
  PersistenceRing ring = {};
  ProjectionReceiptTestNeuron neuron = {};
  NeuronBrainControlStream stream = {};
  ProdigyTransportTLSStream remote = {};
  const ProdigyTransportCredentialBootstrap original = projectionCredentialBootstrap(neuronUUID, brainUUID, 10);
  reserveProjectionTransport(stream);
  reserveProjectionTransport(remote);
  const bool authenticated = beginProjectionBrainControlTransport(neuron, stream, remote, original);
  suite.expect(authenticated, "runtime_persistence_projection_uses_authenticated_aegis_control_stream");
  if (!authenticated) return;
  stream.connected = true;
  stream.tlsPeerVerified = true;
  stream.tlsPeerUUID = brainUUID;
  stream.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  stream.isFixedFile = false;
  neuron.brain = &stream;

  ProdigyTransportCredentialBootstrap projection = original;
  OPENSSL_cleanse(projection.self.secret, sizeof(projection.self.secret));
  projection.committedAuthorityGeneration = 11;
  projection.authorizedPeers.push_back(projectionEnrollment(0x7106, uint128_t(0x7107), 11));
  neuron.controlTransportCredentials = original;
  auto hasAck = [&](uint128_t expectedNonce, bool expectedAcceptance) {
    if (stream.wBuffer.empty()) return false;
    auto *message = reinterpret_cast<Message *>(stream.wBuffer.data());
    if (message->topic != uint16_t(NeuronTopic::transportCredentialPeersAck) ||
        !ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal())) return false;
    uint8_t *args = message->args;
    uint128_t nonce = 0;
    uint64_t generation = 0;
    uint8_t accepted = 0;
    Message::extractArg<ArgumentNature::fixed>(args, nonce);
    Message::extractArg<ArgumentNature::fixed>(args, generation);
    Message::extractArg<ArgumentNature::fixed>(args, accepted);
    return nonce == expectedNonce && generation == projection.committedAuthorityGeneration &&
        accepted == uint8_t(expectedAcceptance);
  };

  neuron.receiveTransportCredentialPeerProjection(0x7108, projection);
  suite.expect(neuron.projectionPersistenceCalls == 1 && neuron.transportPeerProjectionPersistencePending &&
                   neuron.controlTransportCredentials.committedAuthorityGeneration == original.committedAuthorityGeneration &&
                   stream.wBuffer.size() == 0,
               "runtime_persistence_projection_waits_for_durable_receipt_before_install_or_ack");

  // Suppress actual send submission: the assertion is about the receiver's
  // exact ACK frame, and this fixture has no remote message owner.
  stream.pendingSend = true;
  neuron.finishProjectionPersistence(true);
  suite.expect(!neuron.transportPeerProjectionPersistencePending &&
                   neuron.controlTransportCredentials.committedAuthorityGeneration == projection.committedAuthorityGeneration &&
                   neuron.controlTransportCredentials.authorizedPeers.size() == projection.authorizedPeers.size() &&
                   std::memcmp(neuron.controlTransportCredentials.self.secret, original.self.secret,
                               sizeof(original.self.secret)) == 0 && hasAck(0x7108, true),
               "runtime_persistence_projection_installs_durable_public_revision_and_preserves_self_secret");

  stream.wBuffer.clear();
  stream.pendingSend = false;
  neuron.controlTransportCredentials = original;
  neuron.receiveTransportCredentialPeerProjection(0x7109, projection);
  stream.pendingSend = true;
  neuron.finishProjectionPersistence(false);
  suite.expect(neuron.controlTransportCredentials.committedAuthorityGeneration == original.committedAuthorityGeneration &&
                   std::memcmp(neuron.controlTransportCredentials.self.secret, original.self.secret,
                               sizeof(original.self.secret)) == 0 && hasAck(0x7109, false),
               "runtime_persistence_projection_failed_receipt_preserves_existing_credentials");

  stream.wBuffer.clear();
  stream.pendingSend = false;
  neuron.controlTransportCredentials = original;
  neuron.receiveTransportCredentialPeerProjection(0x7110, projection);
  stream.ioGeneration += 1;
  stream.pendingSend = true;
  neuron.finishProjectionPersistence(true);
  suite.expect(neuron.controlTransportCredentials.committedAuthorityGeneration == original.committedAuthorityGeneration &&
                   stream.wBuffer.size() == 0,
               "runtime_persistence_projection_replaced_authenticated_stream_cannot_install_or_ack");

  neuron.receiveTransportCredentialPeerProjection(0x7111, projection);
  stream.connectionLifetime = std::make_shared<uint8_t>(0);
  neuron.finishProjectionPersistence(true);
  suite.expect(neuron.controlTransportCredentials.committedAuthorityGeneration == original.committedAuthorityGeneration &&
                   stream.wBuffer.size() == 0,
               "runtime_persistence_projection_retired_stream_token_fences_same_address_and_generation");

  ::close(stream.fd);
  stream.fd = -1;
}

static void testNeuronTransportCredentialLifecycleProjectionDurabilityAndCandidateFence(TestSuite& suite)
{
  constexpr uint128_t neuronUUID = uint128_t(0x7135), brainUUID = uint128_t(0x7134);
  PersistenceRing ring = {};
  (void)ring;
  ProjectionReceiptTestNeuron neuron = {};
  NeuronBrainControlStream stream = {};
  ProdigyTransportTLSStream remote = {};
  const auto original = projectionCredentialBootstrap(neuronUUID, brainUUID, 10);
  const auto prepared = projectionCredentialRotation(original, 0x7140);
  auto active = prepared;
  active.operation.lifecyclePhase = ProdigyTransportCredentialLifecyclePhase::active;
  active.operation.predecessor.state = ProdigyTransportCredentialEnrollmentState::revoked;
  active.operation.successor.state = ProdigyTransportCredentialEnrollmentState::active;
  active.operation.activationGeneration = active.operation.transitionGeneration = prepared.operation.transitionGeneration + 1;
  active.committedAuthorityGeneration = active.target.committedAuthorityGeneration = active.operation.transitionGeneration;
  reserveProjectionTransport(stream);
  reserveProjectionTransport(remote);
  const bool authenticated = beginProjectionBrainControlTransport(neuron, stream, remote, original);
  suite.expect(authenticated, "runtime_transport_lifecycle_uses_scoped_current_control_stream");
  if (!authenticated) return;
  stream.connected = true;
  stream.tlsPeerVerified = true;
  stream.tlsPeerUUID = brainUUID;
  stream.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  neuron.brain = &stream;

  ProdigyTransportCredentialBootstrap unchanged = {};
  bool revoked = false;
  auto identityRewrite = prepared;
  ++identityRewrite.operation.predecessor.nodeUUID;
  auto operationRewrite = prepared;
  ++operationRewrite.operation.successor.operationUUID;
  suite.expect(!neuron.prepareTransportCredentialLifecycleProjection(active, unchanged, revoked) &&
      !neuron.prepareTransportCredentialLifecycleProjection(identityRewrite, unchanged, revoked) &&
      !neuron.prepareTransportCredentialLifecycleProjection(operationRewrite, unchanged, revoked),
      "runtime_transport_lifecycle_requires_exact_stage_identity_and_operation");

  neuron.receiveTransportCredentialLifecycleProjection(0x7141, prepared);
  const bool awaitingFailedReceipt = neuron.lifecycleProjectionPersistenceCalls == 1 &&
      neuron.transportPeerProjectionPersistencePending &&
      neuron.controlTransportCredentialLifecycleProjection.protocolVersion == 0 &&
      neuron.controlTransportCredentials.self.operationUUID == original.self.operationUUID;
  stream.pendingSend = true;
  neuron.finishLifecycleProjectionPersistence(false);
  suite.expect(awaitingFailedReceipt && projectionLifecycleAck(stream, 0x7141,
      prepared.committedAuthorityGeneration, false) &&
      neuron.controlTransportCredentialLifecycleProjection.protocolVersion == 0,
      "runtime_transport_lifecycle_failed_receipt_does_not_stage_or_install");
  stream.wBuffer.clear();

  neuron.receiveTransportCredentialLifecycleProjection(0x7142, prepared);
  ++stream.ioGeneration;
  stream.pendingSend = true;
  neuron.finishLifecycleProjectionPersistence(true);
  suite.expect(neuron.controlTransportCredentialLifecycleProjection.protocolVersion == 0 && stream.wBuffer.empty(),
      "runtime_transport_lifecycle_stale_io_receipt_cannot_stage_or_ack");

  neuron.receiveTransportCredentialLifecycleProjection(0x7143, prepared);
  stream.connectionLifetime = std::make_shared<uint8_t>(0);
  stream.pendingSend = true;
  neuron.finishLifecycleProjectionPersistence(true);
  suite.expect(neuron.controlTransportCredentialLifecycleProjection.protocolVersion == 0 && stream.wBuffer.empty(),
      "runtime_transport_lifecycle_retired_connection_receipt_cannot_stage_or_ack");

  neuron.receiveTransportCredentialLifecycleProjection(0x7144, prepared);
  const bool awaitingStage = neuron.transportPeerProjectionPersistencePending &&
      neuron.lifecycleProjectionPersistenceCalls == 4 && neuron.controlTransportCredentials.self.operationUUID == original.self.operationUUID;
  stream.pendingSend = true;
  neuron.finishLifecycleProjectionPersistence(true);
  suite.expect(awaitingStage && projectionLifecycleAck(stream, 0x7144, prepared.committedAuthorityGeneration, true) &&
      neuron.controlTransportCredentialLifecycleProjection.operation.lifecyclePhase == ProdigyTransportCredentialLifecyclePhase::prepared &&
      neuron.controlTransportCredentials.self.operationUUID == original.self.operationUUID,
      "runtime_transport_lifecycle_durable_stage_preserves_current_credential_until_activation");
  stream.wBuffer.clear();
  stream.pendingSend = false;

  auto secretRewrite = prepared;
  secretRewrite.target.self.secret[0] ^= 1;
  suite.expect(!neuron.prepareTransportCredentialLifecycleProjection(secretRewrite, unchanged, revoked),
      "runtime_transport_lifecycle_durable_stage_pins_exact_successor_secret");

  NeuronBrainControlStream alternating = {};
  ProdigyTransportTLSStream alternatingRemote = {};
  reserveProjectionTransport(alternating);
  reserveProjectionTransport(alternatingRemote);
  const bool oldAuthenticated = beginProjectionBrainControlTransport(neuron, alternating, alternatingRemote, original, false);
  alternating.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  suite.expect(oldAuthenticated && !alternating.transportLifecycleCandidate,
      "runtime_transport_lifecycle_first_staged_reconnect_retains_current_credential");

  NeuronBrainControlStream candidate = {};
  ProdigyTransportTLSStream candidateRemote = {};
  reserveProjectionTransport(candidate);
  reserveProjectionTransport(candidateRemote);
  const bool candidateAuthenticated = beginProjectionBrainControlTransport(neuron, candidate, candidateRemote,
      prepared.target, false);
  candidate.connected = candidateAuthenticated;
  candidate.tlsPeerVerified = candidateAuthenticated;
  candidate.tlsPeerUUID = brainUUID;
  candidate.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  neuron.brain = &candidate;
  ProdigyLocalClusterPairControlProjection ordinary = {};
  ordinary.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
  ordinary.localClusterUUID = original.self.clusterUUID;
  ordinary.nodeUUID = neuronUUID;
  ordinary.committedAuthorityGeneration = prepared.committedAuthorityGeneration;
  neuron.receiveClusterPairControlProjection(0x7145, ordinary);
  suite.expect(candidateAuthenticated && candidate.transportLifecycleCandidate &&
      neuron.pairProjectionPersistenceCalls == 0 && candidate.wBuffer.empty(),
      "runtime_transport_lifecycle_candidate_allows_only_lifecycle_before_activation");

  neuron.brain = &candidate;
  candidate.wBuffer.clear();
  neuron.receiveTransportCredentialLifecycleProjection(0x7146, active);
  const bool awaitingActivation = neuron.transportPeerProjectionPersistencePending &&
      neuron.lifecycleProjectionPersistenceCalls == 5;
  candidate.pendingSend = true;
  neuron.finishLifecycleProjectionPersistence(true);
  suite.expect(awaitingActivation && projectionLifecycleAck(candidate, 0x7146, active.committedAuthorityGeneration, true) &&
      !candidate.closeAfterTransportLifecycleAck && !candidate.transportLifecycleCandidate &&
      neuron.controlPeerCurrentlyAuthorized(brainUUID) &&
      neuron.controlTransportCredentials.self.operationUUID == active.operation.successor.operationUUID &&
      neuron.controlTransportCredentialLifecycleProjection.operation.lifecyclePhase == ProdigyTransportCredentialLifecyclePhase::active,
      "runtime_transport_lifecycle_candidate_activates_only_after_exact_durable_stage");

  const auto revocation = projectionCredentialRevocation(neuron.controlTransportCredentials, 0x7150);
  candidate.wBuffer.clear();
  candidate.pendingSend = false;
  neuron.receiveTransportCredentialLifecycleProjection(0x7151, revocation);
  candidate.pendingSend = true;
  neuron.finishLifecycleProjectionPersistence(true);
  NeuronBrainControlStream blocked = {};
  reserveProjectionTransport(blocked);
  suite.expect(projectionLifecycleAck(candidate, 0x7151, revocation.committedAuthorityGeneration, true) &&
      neuron.controlTransportCredentialLifecycleProjection.operation.lifecycleKind == ProdigyTransportCredentialLifecycleKind::revoke &&
      neuron.controlTransportCredentials.self.secretIsZero() &&
      !neuron.beginAcceptedBrainTransportTLS(&blocked) && !blocked.transportAEGISEnabled(),
      "runtime_transport_lifecycle_terminal_revocation_blocks_reconnect_without_tls_fallback");

  ::close(stream.fd);
  ::close(candidate.fd);
  ::close(alternating.fd);
  stream.fd = candidate.fd = alternating.fd = -1;
}

static void testNeuronClusterPairControlProjectionDurabilityAndStreamFence(TestSuite& suite)
{
  constexpr uint128_t neuronUUID = uint128_t(0x7205), brainUUID = uint128_t(0x7204);
  PersistenceRing ring = {}; ProjectionReceiptTestNeuron neuron = {};
  NeuronBrainControlStream stream = {}; ProdigyTransportTLSStream remote = {};
  const ProdigyTransportCredentialBootstrap credentials = projectionCredentialBootstrap(neuronUUID, brainUUID, 10);
  reserveProjectionTransport(stream); reserveProjectionTransport(remote);
  const bool authenticated = beginProjectionBrainControlTransport(neuron, stream, remote, credentials);
  suite.expect(authenticated, "runtime_pair_projection_uses_authenticated_control_stream");
  if (!authenticated) return;
  stream.connected = true; stream.tlsPeerVerified = true; stream.tlsPeerUUID = brainUUID;
  stream.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK); neuron.brain = &stream;
  ProdigyLocalClusterPairControlProjection projection = {};
  projection.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
  projection.localClusterUUID = neuron.controlTransportCredentials.self.clusterUUID;
  projection.nodeUUID = neuronUUID; projection.committedAuthorityGeneration = 12;
  neuron.receiveClusterPairControlProjection(0x7208, projection);
  suite.expect(neuron.pairProjectionPersistenceCalls == 1 && neuron.clusterPairControlProjectionPersistencePending &&
      neuron.clusterPairControlProjection.protocolVersion == 0 && stream.wBuffer.empty(),
      "runtime_pair_projection_waits_for_durable_receipt_before_install_or_ack");
  stream.pendingSend = true; neuron.finishPairProjectionPersistence(true);
  suite.expect(!neuron.clusterPairControlProjectionPersistencePending &&
      prodigyLocalClusterPairControlProjectionEqual(neuron.clusterPairControlProjection, projection) && !stream.wBuffer.empty(),
      "runtime_pair_projection_installs_durable_empty_revocation_projection");
  stream.wBuffer.clear(); stream.pendingSend = false; neuron.clusterPairControlProjection = {};
  neuron.receiveClusterPairControlProjection(0x7209, projection); stream.pendingSend = true; neuron.finishPairProjectionPersistence(false);
  bool failedAck = false;
  if (!stream.wBuffer.empty())
  {
    auto *message = reinterpret_cast<Message *>(stream.wBuffer.data());
    if (message->topic == uint16_t(NeuronTopic::clusterPairControlCredentialsAck) &&
        ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal()))
    {
      uint8_t *args = message->args; uint128_t nonce = 0; uint64_t generation = 0; uint8_t accepted = 1;
      Message::extractArg<ArgumentNature::fixed>(args, nonce);
      Message::extractArg<ArgumentNature::fixed>(args, generation);
      Message::extractArg<ArgumentNature::fixed>(args, accepted);
      failedAck = nonce == uint128_t(0x7209) && generation == projection.committedAuthorityGeneration && accepted == 0;
    }
  }
  suite.expect(neuron.clusterPairControlProjection.protocolVersion == 0 && failedAck,
      "runtime_pair_projection_failed_receipt_does_not_install");
  stream.wBuffer.clear(); stream.pendingSend = false;
  neuron.receiveClusterPairControlProjection(0x7210, projection); ++stream.ioGeneration; neuron.finishPairProjectionPersistence(true);
  suite.expect(neuron.clusterPairControlProjection.protocolVersion == 0 && stream.wBuffer.empty(),
      "runtime_pair_projection_stale_generation_cannot_install_or_ack");
  ProdigyLocalClusterPairControlProjection foreign = projection; ++foreign.nodeUUID;
  neuron.receiveClusterPairControlProjection(0x7211, foreign);
  suite.expect(neuron.pairProjectionPersistenceCalls == 3,
      "runtime_pair_projection_rejects_foreign_local_owner_before_persistence");
  neuron.controlTransportCredentials = projectionCredentialBootstrap(neuronUUID, brainUUID, 10);
  neuron.controlTransportCredentials.authorizedPeers.clear();
  neuron.receiveClusterPairControlProjection(0x7212, projection);
  suite.expect(neuron.pairProjectionPersistenceCalls == 3,
      "runtime_pair_projection_rejects_old_authenticated_stream_removed_from_roster");
  neuron.controlTransportCredentials = projectionCredentialBootstrap(neuronUUID, brainUUID, 10);
  neuron.receiveClusterPairControlProjection(0x7213, projection);
  neuron.controlTransportCredentials.authorizedPeers.clear();
  neuron.finishPairProjectionPersistence(true);
  suite.expect(neuron.clusterPairControlProjection.protocolVersion == 0 && stream.wBuffer.empty(),
      "runtime_pair_projection_revocation_before_receipt_cannot_install_or_ack");
  ::close(stream.fd); stream.fd = -1;
}

static void testLocalPairProjectionMarkerBindsProjectionVersion(TestSuite& suite)
{
  constexpr uint64_t pairMarkerV1 = 0x5041495250524a31ULL;
  constexpr uint64_t pairMarkerV2 = 0x5041495250524a32ULL;
  auto replaceMarker = [](String& encoded, uint64_t from, uint64_t to) {
    std::array<uint8_t, sizeof(from)> needle = {}, replacement = {};
    std::memcpy(needle.data(), &from, sizeof(from));
    std::memcpy(replacement.data(), &to, sizeof(to));
    for (uint32_t offset = 0; offset + needle.size() <= encoded.size(); ++offset)
      if (std::memcmp(encoded.data() + offset, needle.data(), needle.size()) == 0)
      {
        std::memcpy(encoded.data() + offset, replacement.data(), replacement.size());
        return true;
      }
    return false;
  };
  auto encode = [](uint32_t version) {
    ProdigyPersistentLocalBrainState state = {};
    state.uuid = 0x72f1; state.ownerClusterUUID = 0x72f2;
    state.clusterPairControlProjection.protocolVersion = version;
    state.clusterPairControlProjection.localClusterUUID = state.ownerClusterUUID;
    state.clusterPairControlProjection.nodeUUID = state.uuid;
    state.clusterPairControlProjection.committedAuthorityGeneration = 11;
    if (version == ProdigyLocalClusterPairControlProjection::version)
    {
      ProdigyClusterPairEpochStatus status = {};
      status.protocolVersion = ProdigyClusterPairEpochProtocolVersion;
      status.pairUUID = 0x72f3; status.rootGeneration = 1;
      status.sourceClusterUUID = state.ownerClusterUUID; status.peerClusterUUID = 0x72f4;
      status.agreedKeyEpoch = status.oldEpoch = 1; status.nextEpoch = 2;
      status.agreementUUID = 0x72f5; status.phase = ProdigyClusterPairEpochPhase::prepared;
      status.authorityGeneration = 11;
      (void)prodigyClusterPairEpochAgreementDigest(status.pairUUID, status.rootGeneration,
          status.sourceClusterUUID, status.peerClusterUUID, status.agreementUUID, status.oldEpoch,
          status.nextEpoch, status.agreementDigest);
      state.clusterPairControlProjection.epochStatuses.push_back(std::move(status));
    }
    String encoded = {}; BitseryEngine::serialize(encoded, state);
    return encoded;
  };

  String v2 = encode(2);
  ProdigyPersistentLocalBrainState restored = {};
  const bool v2RoundTrip = BitseryEngine::deserializeSafe(v2, restored) &&
      restored.clusterPairControlProjection.protocolVersion == 2 &&
      restored.clusterPairControlProjection.committedAuthorityGeneration == 11;
  const bool v2RelabeledV1Rejected = replaceMarker(v2, pairMarkerV2, pairMarkerV1) &&
      !BitseryEngine::deserializeSafe(v2, restored);

  String v1 = encode(1);
  const bool v1RelabeledV2Rejected = replaceMarker(v1, pairMarkerV1, pairMarkerV2) &&
      !BitseryEngine::deserializeSafe(v1, restored);
  ProdigyPersistentLocalBrainState emptyV2 = {};
  emptyV2.uuid = 0x72f6; emptyV2.ownerClusterUUID = 0x72f7;
  emptyV2.clusterPairControlProjection.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
  emptyV2.clusterPairControlProjection.localClusterUUID = emptyV2.ownerClusterUUID;
  emptyV2.clusterPairControlProjection.nodeUUID = emptyV2.uuid;
  emptyV2.clusterPairControlProjection.committedAuthorityGeneration = 11;
  String legacyShape = {}; BitseryEngine::serialize(legacyShape, emptyV2);
  const bool emptyV2UsesV1Layout = BitseryEngine::deserializeSafe(legacyShape, restored) &&
      restored.clusterPairControlProjection.protocolVersion == ProdigyLocalClusterPairControlProjection::legacyVersion1 &&
      restored.clusterPairControlProjection.epochStatuses.empty();
  suite.expect(v2RoundTrip && v2RelabeledV1Rejected && v1RelabeledV2Rejected && emptyV2UsesV1Layout,
      "runtime_pair_projection_marker_binds_v1_v2_public_layout");
}

static ProdigyLocalCousinServicePermission runtimePersistenceCousinPermission(
    uint128_t permissionUUID, uint128_t localClusterUUID, uint64_t acceptedAuthorityGeneration)
{
  ProdigyLocalCousinServicePermission permission = {};
  permission.permissionUUID = permissionUUID;
  permission.pairUUID = 0x73a1;
  permission.logicalWorkloadUUID = 0x73a2;
  permission.logicalServiceUUID = 0x73a3;
  permission.localClusterUUID = localClusterUUID;
  permission.peerClusterUUID = 0x73a4;
  permission.localHalf = CousinRouteHalf::source;
  permission.localApplicationID = 73;
  permission.peerApplicationID = 74;
  permission.localCousinServicePrefix = MeshServices::generateStatefulService(73, 3);
  permission.peerCousinServicePrefix = MeshServices::generateStatefulService(74, 3);
  permission.slots.insert(7);
  permission.localDeploymentID = (uint64_t(permission.localApplicationID) << 48) | 0x73a5;
  for (uint32_t index = 0; index < 64; ++index)
  {
    permission.canonicalPlanSHA256.append('a');
    permission.artifactSHA256.append('b');
  }
  permission.artifactBytes = 4096;
  permission.generation = 1;
  permission.acceptedAuthorityGeneration = acceptedAuthorityGeneration;
  permission.state = ProdigyLocalCousinServicePermissionState::active;
  return permission;
}

static void testPersistentLocalCousinServicePermissions(TestSuite& suite)
{
  constexpr uint128_t localClusterUUID = uint128_t(0x73b1);
  constexpr uint64_t authorityGeneration = 12;
  ProdigyPersistentBrainSnapshot snapshot = {};
  snapshot.brainConfig.clusterUUID = localClusterUUID;
  snapshot.masterAuthority.runtimeState.generation = authorityGeneration;
  snapshot.masterAuthority.runtimeState.localCousinServicePermissions.push_back(
      runtimePersistenceCousinPermission(0x73b2, localClusterUUID, authorityGeneration));

  String runtimeWire = {};
  ProdigyMasterAuthorityRuntimeState runtimeCopy = snapshot.masterAuthority.runtimeState;
  BitseryEngine::serialize(runtimeWire, runtimeCopy);
  ProdigyMasterAuthorityRuntimeState runtimeRestored = {};
  const bool runtimeRoundTrip = BitseryEngine::deserializeSafe(runtimeWire, runtimeRestored) &&
      prodigyLocalCousinServicePermissionsEqual(
          runtimeRestored.localCousinServicePermissions,
          snapshot.masterAuthority.runtimeState.localCousinServicePermissions);

  // Version fifteen's bounded policy tail must not be interpreted as a v14
  // epoch-operation tail.  The version marker immediately precedes v15.
  String relabeled = runtimeWire;
  uint64_t legacyVersion = 14;
  if (relabeled.size() >= 2 * sizeof(uint64_t))
    std::memcpy(relabeled.data() + sizeof(uint64_t), &legacyVersion, sizeof(legacyVersion));
  ProdigyMasterAuthorityRuntimeState relabeledState = {};
  const bool legacyRelabelRejected = relabeled.size() >= 2 * sizeof(uint64_t) &&
      !BitseryEngine::deserializeSafe(relabeled, relabeledState);

  // A legacy runtime record has no policy tail.  Decoding it into a reused
  // state must remove stale policy that was learned from a newer authority.
  ProdigyMasterAuthorityRuntimeState legacyRuntime = {};
  legacyRuntime.generation = authorityGeneration;
  String legacyWire = {};
  BitseryEngine::serialize(legacyWire, legacyRuntime);
  ProdigyMasterAuthorityRuntimeState reused = snapshot.masterAuthority.runtimeState;
  const bool legacyCatchupClearsPermissions = BitseryEngine::deserializeSafe(legacyWire, reused) &&
      reused.localCousinServicePermissions.empty();

  ScopedPersistentRoot root = {};
  ProdigyPersistentStateStore store(root.path);
  String failure = {};
  const bool saved = store.saveBrainSnapshot(snapshot, &failure);
  store.close();
  ProdigyPersistentStateStore reopened(root.path);
  ProdigyPersistentBrainSnapshot restored = {};
  const bool restartRoundTrip = saved && reopened.loadBrainSnapshot(restored, &failure) &&
      prodigyLocalCousinServicePermissionsEqual(
          restored.masterAuthority.runtimeState.localCousinServicePermissions,
          snapshot.masterAuthority.runtimeState.localCousinServicePermissions);
  reopened.close();

  ProdigyPersistentBrainSnapshot malformed = snapshot;
  malformed.masterAuthority.runtimeState.localCousinServicePermissions[0].acceptedAuthorityGeneration =
      authorityGeneration + 1;
  ProdigyPersistentBrainSnapshot publicSnapshot = {};
  ProdigyPersistentBrainSnapshotSecrets secrets = {};
  String malformedFailure = {};
  const bool malformedWriteRejected =
      !prodigyExtractPersistentBrainSnapshotSecrets(malformed, publicSnapshot, secrets, &malformedFailure) &&
      malformedFailure.equals("persistent brain snapshot local cousin service permission is malformed"_ctv);
  malformedFailure.clear();
  const bool malformedReadRejected =
      !prodigyApplyPersistentBrainSnapshotSecrets(malformed, secrets, &malformedFailure) &&
      malformedFailure.equals("persistent brain snapshot local cousin service permission is malformed"_ctv);
  secrets.clear();

  suite.expect(runtimeRoundTrip && legacyRelabelRejected && legacyCatchupClearsPermissions &&
                   restartRoundTrip && malformedWriteRejected && malformedReadRejected,
               "runtime_persistence_local_cousin_service_permissions_roundtrip_relabel_catchup_and_validation");
}

static void testNeuronForwardsFirstPairEpochProposalOnlyOnCurrentAuthorizedChannel(TestSuite& suite)
{
  constexpr uint128_t neuronUUID = uint128_t(0x72e1), brainUUID = uint128_t(0x72e2), remoteNodeUUID = uint128_t(0x72e3);
  ProjectionReceiptTestNeuron neuron = {};
  NeuronBrainControlStream stream = {}; ProdigyTransportTLSStream remote = {};
  const ProdigyTransportCredentialBootstrap credentials = projectionCredentialBootstrap(neuronUUID, brainUUID, 10);
  reserveProjectionTransport(stream); reserveProjectionTransport(remote);
  const bool authenticated = beginProjectionBrainControlTransport(neuron, stream, remote, credentials);
  suite.expect(authenticated, "runtime_pair_epoch_status_uses_authenticated_control_stream");
  if (!authenticated) return;
  stream.connected = true; stream.tlsPeerVerified = true; stream.tlsPeerUUID = brainUUID;
  stream.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK); neuron.brain = &stream;
  ProdigyLocalClusterPairControlProjection remoteProjection = {};
  const bool projectionBuilt = buildRuntimePairControlProjections(neuronUUID, remoteNodeUUID,
      neuron.clusterPairControlProjection, remoteProjection);
  // A newly proposed epoch must cross the existing v1 carrier before either
  // side can persist a v2 staged projection.
  neuron.clusterPairControlProjection.protocolVersion = ProdigyLocalClusterPairControlProjection::legacyVersion1;
  neuron.pairControlRuntime = std::make_unique<SwitchboardPairControlRuntime>();
  neuron.pairControlRuntime->onEpochStatus = [&neuron](const ProdigyClusterPairEpochReceipt& receipt) {
    neuron.forwardClusterPairEpochStatus(receipt);
  };

  ProdigyClusterPairEpochReceipt receipt = {};
  receipt.localEndpoint = runtimePairControlEndpoint(uint128_t(0x7101), neuronUUID, "fd00:ffff:1234::1");
  receipt.remoteEndpoint = runtimePairControlEndpoint(uint128_t(0x7201), remoteNodeUUID, "fd00:ffff:1234::2");
  receipt.wireEpoch = 1; receipt.projectionGeneration = 12;
  auto& status = receipt.status;
  status.protocolVersion = ProdigyClusterPairEpochProtocolVersion;
  status.pairUUID = uint128_t(0x72a1); status.rootGeneration = 1;
  status.sourceClusterUUID = receipt.remoteEndpoint.clusterUUID;
  status.peerClusterUUID = receipt.localEndpoint.clusterUUID;
  status.agreedKeyEpoch = 1; status.agreementUUID = uint128_t(0x72e5);
  status.oldEpoch = 1; status.nextEpoch = 2; status.phase = ProdigyClusterPairEpochPhase::prepared;
  status.authorityGeneration = 12;
  const bool digest = prodigyClusterPairEpochAgreementDigest(status.pairUUID, status.rootGeneration,
      status.sourceClusterUUID, status.peerClusterUUID, status.agreementUUID, status.oldEpoch,
      status.nextEpoch, status.agreementDigest);
  // This fixture observes the constructed frame only; a live Ring send is
  // neither needed nor valid without the production dispatcher.
  stream.pendingSend = true;
  if (digest) neuron.pairControlRuntime->onEpochStatus(receipt);
  bool forwarded = false;
  if (!stream.wBuffer.empty())
  {
    auto *message = reinterpret_cast<Message *>(stream.wBuffer.data());
    String serialized = {};
    if (message->topic == uint16_t(NeuronTopic::clusterPairEpochStatus) &&
        ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal()))
    {
      uint8_t *args = message->args; Message::extractToStringView(args, serialized);
      ProdigyClusterPairEpochReceipt decoded = {};
      forwarded = args == message->terminal() && BitseryEngine::deserializeSafe(serialized, decoded) &&
          decoded.projectionGeneration == receipt.projectionGeneration && decoded.wireEpoch == receipt.wireEpoch &&
          decoded.status.agreementUUID == receipt.status.agreementUUID;
    }
  }
  stream.wBuffer.clear();
  // A peer can finish its local staging before this side sees the prepared
  // status. Its ready status must still cross the old carrier to let the local
  // authority stage; only that authority may count next-epoch readiness.
  status.phase = ProdigyClusterPairEpochPhase::ready;
  neuron.pairControlRuntime->onEpochStatus(receipt);
  const bool readyOnOldForwarded = !stream.wBuffer.empty();
  stream.wBuffer.clear();
  receipt.wireEpoch = 2;
  neuron.pairControlRuntime->onEpochStatus(receipt);
  const bool unapprovedNextDropped = stream.wBuffer.empty();
  receipt.wireEpoch = 1;
  ++receipt.projectionGeneration;
  neuron.pairControlRuntime->onEpochStatus(receipt);
  const bool staleProjectionDropped = stream.wBuffer.empty();
  --receipt.projectionGeneration;
  neuron.controlTransportCredentials.authorizedPeers.clear();
  neuron.pairControlRuntime->onEpochStatus(receipt);
  const bool removedAuthorityDropped = stream.wBuffer.empty();
  neuron.controlTransportCredentials = projectionCredentialBootstrap(neuronUUID, brainUUID, 10);
  neuron.brain = nullptr;
  neuron.pairControlRuntime->onEpochStatus(receipt);
  suite.expect(projectionBuilt && digest && forwarded && readyOnOldForwarded && unapprovedNextDropped &&
      staleProjectionDropped && removedAuthorityDropped && stream.wBuffer.empty(),
      "runtime_pair_epoch_status_forwards_first_proposal_on_v1_only_to_current_authorized_brain_channel");
  neuron.pairControlRuntime.reset();
  ::close(stream.fd); stream.fd = -1;
}

static void testClusterPairRuntimeRequiresFreshDurableProjectionAfterRestart(TestSuite& suite)
{
  if (const char *enabled = std::getenv("PRODIGY_TEST_PAIR_CONTROL_RING");
      enabled == nullptr || std::strcmp(enabled, "1") != 0)
  {
    suite.expect(true, "runtime_pair_restart_activation_ring_subcase_skipped_without_provisioned_ipv6");
    return;
  }

  constexpr uint128_t neuronUUID = uint128_t(0x7215), brainUUID = uint128_t(0x7214), remoteNodeUUID = uint128_t(0x7216);
  PersistenceRing ring = {};
  ProjectionReceiptTestNeuron neuron = {};
  NeuronBrainControlStream stream = {};
  ProdigyTransportTLSStream remoteBrain = {};
  SwitchboardPairControlRuntime remoteCarrier = {};
  ProdigyLocalClusterPairControlProjection cached = {}, remoteProjection = {};
  const bool projectionsBuilt = buildRuntimePairControlProjections(neuronUUID, remoteNodeUUID, cached, remoteProjection);
  suite.expect(projectionsBuilt, "runtime_pair_restart_builds_complementary_cached_projection");
  if (!projectionsBuilt) return;

  reserveProjectionTransport(stream);
  reserveProjectionTransport(remoteBrain);
  const ProdigyTransportCredentialBootstrap credentials = projectionCredentialBootstrap(neuronUUID, brainUUID, 10);
  const bool authenticated = beginProjectionBrainControlTransport(neuron, stream, remoteBrain, credentials);
  suite.expect(authenticated, "runtime_pair_restart_fresh_master_control_stream_is_authenticated");
  if (!authenticated) return;

  stream.connected = true;
  stream.tlsPeerVerified = true;
  stream.tlsPeerUUID = brainUUID;
  stream.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  neuron.brain = &stream;
  neuron.clusterPairControlProjection = cached;

  const bool remoteInstalled = remoteCarrier.installProjection(remoteProjection);
  const bool remoteStarted = remoteInstalled && remoteCarrier.start();
  const bool localStarted = remoteStarted && neuron.startClusterPairControlRuntime();
  suite.expect(remoteInstalled && remoteStarted && localStarted,
               "runtime_pair_restart_starts_remote_carrier_and_empty_local_runtime");

  // A saved credential set may fence rollback, but it must not open a carrier
  // until the current authenticated Brain durably republishes it.
  const bool cachedStayedInactive = localStarted && runPairControlFor(ring, 1500) &&
      neuron.pairControlRuntime != nullptr && neuron.pairControlRuntime->readyCount() == 0 && remoteCarrier.readyCount() == 0;
  suite.expect(cachedStayedInactive, "runtime_pair_restart_cached_projection_does_not_activate_before_fresh_delivery");

  if (localStarted)
  {
    stream.pendingSend = true;
    neuron.receiveClusterPairControlProjection(0x7217, cached);
    const bool awaitingDurability = neuron.clusterPairControlProjectionPersistencePending &&
        neuron.pairProjectionPersistenceCalls == 1 && neuron.pairControlRuntime->readyCount() == 0;
    neuron.finishPairProjectionPersistence(true);
    const bool activated = awaitingDurability && runPairControlUntil(ring, [&] {
      return neuron.pairControlRuntime->readyCount() == 1 && remoteCarrier.readyCount() == 1;
    }, 4000);
    suite.expect(activated, "runtime_pair_restart_fresh_authenticated_durable_projection_activates_carrier");

    ProdigyLocalClusterPairControlProjection revoked = {};
    revoked.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
    revoked.localClusterUUID = cached.localClusterUUID;
    revoked.nodeUUID = cached.nodeUUID;
    revoked.committedAuthorityGeneration = cached.committedAuthorityGeneration + 1;
    stream.pendingSend = true;
    neuron.receiveClusterPairControlProjection(0x7218, revoked);
    const bool revocationAwaitingDurability = neuron.clusterPairControlProjectionPersistencePending &&
        neuron.pairProjectionPersistenceCalls == 2;
    neuron.finishPairProjectionPersistence(true);
    const bool revokedInactive = revocationAwaitingDurability && runPairControlUntil(ring, [&] {
      return neuron.pairControlRuntime->readyCount() == 0 && remoteCarrier.readyCount() == 0;
    }, 4000);
    suite.expect(revokedInactive, "runtime_pair_restart_durable_empty_revocation_stays_inactive");
  }

  const bool quiesced = runPairControlUntil(ring, [&] {
    const bool local = !neuron.pairControlRuntime || neuron.pairControlRuntime->quiesce();
    return local && remoteCarrier.quiesce();
  }, 3000);
  suite.expect(quiesced, "runtime_pair_restart_quiesces_all_started_carriers");
  ::close(stream.fd);
  stream.fd = -1;
}

static void testProductionPairProjectionWriterUsesColocatedNeuronAuthority(TestSuite& suite)
{
  PersistenceRing ring;
  ScopedPersistentRoot root;
  ProdigyPersistentStateStore store(root.path);
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "runtime_pair_colocated_writer_starts");
  if (!io) return;
  auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io);
  livePersistentWriter = writer;
  ProdigyTransportCredentialAuthorityRoot authority;
  authority.authorityEpoch = 7; authority.keyEpoch = 9; authority.authorityGeneration = 10;
  std::memset(authority.root, 0x63, sizeof(authority.root));
  Vector<ProdigyTransportCredentialEnrollment> ledger;
  auto ownBrain = projectionEnrollment(0x7303, 0x7301, 10);
  auto ownNeuron = ownBrain; ownNeuron.operationUUID = 0x7304;
  ownNeuron.role = ProdigyTransportCredentialNodeRole::neuron;
  auto otherBrain = ownBrain; otherBrain.operationUUID = 0x7305; otherBrain.nodeUUID = 0x7302;
  ledger.push_back(ownBrain); ledger.push_back(ownNeuron); ledger.push_back(otherBrain);
  persistentLocalBrainState = {};
  const bool built = prodigyBuildLocalTransportCredentialState(authority, ledger, ownBrain.nodeUUID,
      ProdigyTransportCredentialNodeRole::brain, persistentLocalBrainState, 10);
  suite.expect(built, "runtime_pair_colocated_writer_has_real_dual_role_state");
  bool ownDurable = false, revocationDurable = false, removedRejected = false;
  ProdigyHostControlNetwork network;
  if (built)
  {
    ProdigyNeuron neuron(network);
    ProdigyLocalClusterPairControlProjection projection;
    projection.protocolVersion = ProdigyLocalClusterPairControlProjection::version;
    projection.localClusterUUID = ownBrain.clusterUUID; projection.nodeUUID = ownBrain.nodeUUID;
    projection.committedAuthorityGeneration = 11;
    const bool admitted = neuron.persistClusterPairControlProjection(projection, ownBrain.nodeUUID, [&](bool durable) {
      ownDurable = durable;
      if (!durable) { Ring::exit = true; return; }
      auto revoke = neuron.controlTransportCredentials;
      OPENSSL_cleanse(revoke.self.secret, sizeof(revoke.self.secret));
      revoke.committedAuthorityGeneration = 12;
      revoke.authorizedPeers.erase(std::remove_if(revoke.authorizedPeers.begin(), revoke.authorizedPeers.end(),
          [&](const auto& peer) { return peer.nodeUUID == otherBrain.nodeUUID; }), revoke.authorizedPeers.end());
      if (!neuron.persistTransportCredentialPeerProjection(revoke, [&](bool removed) {
        revocationDurable = removed;
        auto forbidden = projection; forbidden.committedAuthorityGeneration = 13;
        removedRejected = !neuron.persistClusterPairControlProjection(forbidden, otherBrain.nodeUUID,
            [&](bool) { suite.expect(false, "runtime_pair_revoked_writer_must_not_persist"); });
        Ring::exit = true;
      })) Ring::exit = true;
    });
    suite.expect(admitted, "runtime_pair_colocated_master_writer_admits_own_neuron");
    if (admitted) { ring.armDeadline(3000); Ring::start(); }
    suite.expect(!ring.timedOut && ownDurable && revocationDurable && removedRejected &&
        persistentLocalBrainState.clusterPairControlProjection.committedAuthorityGeneration == 11,
        "runtime_pair_colocated_master_durable_and_revoked_foreign_sender_rejected");
  }
  suite.expect(writer->drainForExec(), "runtime_pair_colocated_writer_drains");
  writer.reset(); livePersistentWriter.reset();
  io->stop(); ring.drainStoppedIO(); io.reset();
  (void)network.shutdown(); store.close();
  ProdigyPersistentStateStore reopened(root.path);
  ProdigyPersistentLocalBrainState restored;
  suite.expect(reopened.loadLocalBrainState(restored) && restored.clusterPairControlProjection.committedAuthorityGeneration == 11,
      "runtime_pair_colocated_writer_cold_restore_preserves_only_authorized_projection");
  reopened.close(); persistentLocalBrainState = {};
}

int main(void)
{
  TestSuite suite;
  testProductionPairProjectionWriterUsesColocatedNeuronAuthority(suite);
  testNeuronClusterPairControlProjectionDurabilityAndStreamFence(suite);
  testClusterPairRuntimeRequiresFreshDurableProjectionAfterRestart(suite);
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY"); only != nullptr &&
      std::strcmp(only, "reentrant-update-persistence") == 0)
  {
    testProductionUpdateProgressDefersReentrantPersistenceUntilArtifactLeaseReleases(suite);
    std::printf("REENTRANT_UPDATE_PERSISTENCE_RESULT failed_assertions=%d\n", suite.failed);
    return suite.failed == 0 ? 0 : 1;
  }
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY"); only != nullptr &&
      std::strcmp(only, "materialized-recovery-historical-cull") == 0)
  {
    testDurableMaterializedRecoveryHistoricalCull(suite);
    return suite.failed == 0 ? 0 : 1;
  }
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY"); only != nullptr &&
      std::strcmp(only, "topology-snapshot-overlap") == 0)
  {
    testProductionTopologySnapshotOverlap(suite);
    return suite.failed == 0 ? 0 : 1;
  }
  testProductionUpdateProgressDefersReentrantPersistenceUntilArtifactLeaseReleases(suite);
  testFollowerMetricIngestionTrimsBeforePersistence(suite);
  testLargeMetricHistoryUsesImmutableAsyncCapture(suite);
  testProductionPersistenceAPI(suite);
  testPersistentWriterPreservesTransportLifecycleSchema(suite);
  testTerminalLocalBrainFenceOverridesOlderSnapshot(suite);
  testProductionPersistenceAdmissionFromArtifactCompletion(suite);
  testProductionTopologySnapshotOverlap(suite);
  testPersistentWriterDetachesViewBackedSchemaFields(suite);
  testPersistentWriterRetainedAccountingChargesManyShortStrings(suite);
  testNeuronOSUpdateUsesOwnedReceiptDrivenRequest(suite);
  testRuntimeAwareBrainActivatesOnlyTheAsyncPersistenceOwner(suite);
  testRuntimeAwareNeuronActivatesOnlyTheAsyncPersistenceOwner(suite);
  testBootPersistenceAdmissionRejectionHasNoReceipt(suite);
  testDurableMaterializedRecoveryHistoricalCull(suite);
  testNeuronTransportCredentialPeerProjectionDurabilityAndStreamFence(suite);
  testNeuronTransportCredentialLifecycleProjectionDurabilityAndCandidateFence(suite);
  testLocalPairProjectionMarkerBindsProjectionVersion(suite);
  testPersistentLocalCousinServicePermissions(suite);
  testNeuronForwardsFirstPairEpochProposalOnlyOnCurrentAuthorizedChannel(suite);
  return suite.failed == 0 ? 0 : 1;
}
