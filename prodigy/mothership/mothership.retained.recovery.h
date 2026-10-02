#pragma once

// Offline preparation for a deliberately retained fleet.  This owner only
// changes a private state/secrets copy; Mothership's command owner is solely
// responsible for fencing, atomic swaps, and activation.
#include <algorithm>
#include <limits>
#include <map>

#include <prodigy/persistent.state.h>
#include <prodigy/retained.container.recovery.h>

class MothershipRetainedRecoveryMachineInput {
public:
  uint128_t machineUUID = 0;
  uint32_t machineFragment = 0;
  Vector<ContainerParameters> parameters;
  Vector<int64_t> observedCreatedAtMs;
};

static inline bool mothershipRetainedRecoveryPlansEqual(const DeploymentPlan& lhs, const DeploymentPlan& rhs)
{
  String left = {}, right = {};
  DeploymentPlan leftCopy = lhs, rightCopy = rhs;
  // CID rotation is replicated runtime state, so stopped peers can retain
  // different key generations for the same declared deployment. Compare only
  // copies: recovery must preserve each peer's keys until normal replication
  // resumes. Rotation policy and every other declared field remain exact.
  auto clearCidRuntime = [](DeploymentPlan& plan) {
    for (Wormhole& wormhole : plan.wormholes)
    {
      const uint32_t rotationHours = wormhole.quicCidKeyState.rotationHours;
      wormhole.hasQuicCidKeyState = false;
      wormhole.quicCidKeyState = {};
      wormhole.quicCidKeyState.rotationHours = rotationHours;
    }
  };
  clearCidRuntime(leftCopy);
  clearCidRuntime(rightCopy);
  BitseryEngine::serialize(left, leftCopy);
  BitseryEngine::serialize(right, rightCopy);
  return left == right;
}

static inline bool mothershipRetainedRecoveryEnvelopeMatches(
    const ProdigyPersistentUpdateSelfState& update, const String& bundleSHA256)
{
  if (!prodigyIsSHA256HexDigest(bundleSHA256) || update.machineRecoveryWitnesses.empty()) return false;
  ProdigyPersistentUpdateSelfState envelope;
  envelope.workerExpectedBundleSHA256 = bundleSHA256;
  envelope.machineRecoveryWitnesses = update.machineRecoveryWitnesses;
  return update == envelope;
}

struct MothershipRetainedRecoveryMixedProof {
  uint32_t canonicalContainerCount = 0;
  uint32_t staleCoordinatorCanonicalContainerCount = 0;
  uint32_t interruptedExpectedEchos = 0;
  uint128_t staleExcludedContainerUUID = 0;
  bool validFor(const ProdigyPersistentBrainSnapshot& snapshot) const {
    return canonicalContainerCount > staleCoordinatorCanonicalContainerCount &&
        canonicalContainerCount <= 256 && staleCoordinatorCanonicalContainerCount > 0 &&
        interruptedExpectedEchos > 0 && interruptedExpectedEchos < snapshot.topology.machines.size() &&
        staleExcludedContainerUUID != 0;
  }
};

static inline uint32_t mothershipRetainedRecoveryWitnessContainerCount(
    const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& witnesses)
{
  uint32_t count=0; for (const auto& witness:witnesses) count+=witness.containerBootstraps.size(); return count;
}

static inline bool mothershipRetainedRecoveryPartialHandoffEqual(
    const ProdigyMaterializedStatefulRecoveryOperation& lhs,
    const ProdigyMaterializedStatefulRecoveryOperation& rhs)
{
  return lhs.operationID.equals(rhs.operationID) &&
         lhs.activeDeploymentID == rhs.activeDeploymentID &&
         lhs.successorDeploymentID == rhs.successorDeploymentID &&
         lhs.successorBlobSHA256.equals(rhs.successorBlobSHA256) &&
         lhs.accepted == rhs.accepted && lhs.started == rhs.started &&
         lhs.completed == rhs.completed && lhs.updatedAtMs == rhs.updatedAtMs;
}

// A deployed predecessor can outlive its deployment record after an accepted
// materialized handoff.  This descriptor does not create a replacement: it
// binds the one process that an already-started handoff may retire before the
// ordinary retained recovery resumes the surviving successor cohort.
struct MothershipRetainedRecoveryOrphanedStatefulPredecessor {
  ProdigyMaterializedStatefulRecoveryOperation operation;
  uint128_t machineUUID = 0;
  ContainerParameters parameters = {};
  // Immutable proof-only source. The prior request supplies the culled
  // deployment plan solely to normalize and bind this live predecessor; it is
  // never merged into the current recovery authority.
  String priorRequestSHA256 = {};
  String priorManifestSHA256 = {};
};

static inline bool mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(
    const MothershipRetainedRecoveryOrphanedStatefulPredecessor& orphan)
{
  return prodigyCanonicalOperationUUID(orphan.operation.operationID) &&
         orphan.operation.activeDeploymentID != 0 && orphan.operation.successorDeploymentID != 0 &&
         orphan.operation.activeDeploymentID != orphan.operation.successorDeploymentID &&
         prodigyIsSHA256HexDigest(orphan.operation.successorBlobSHA256) &&
         orphan.operation.accepted && orphan.operation.started && !orphan.operation.completed &&
         orphan.operation.updatedAtMs > 0 && orphan.machineUUID != 0 && orphan.parameters.uuid != 0 &&
         prodigyIsSHA256HexDigest(orphan.priorRequestSHA256) &&
         prodigyIsSHA256HexDigest(orphan.priorManifestSHA256) &&
         orphan.parameters.deploymentID == orphan.operation.activeDeploymentID &&
         orphan.parameters.statefulMeshRoles.client == 0 &&
         orphan.parameters.statefulTopology.shardGroup == 0 &&
         orphan.parameters.statefulTopology.bridgeMode == StatefulTopologyBridgeMode::none;
}

// A retained process can refresh credentials, CPU reservation, and dynamic mesh
// edges after the historical request was sealed.  These fields bind its durable
// stateful identity without treating those live observations as new authority.
static inline bool mothershipRetainedRecoveryOrphanedStatefulPredecessorParametersMatchHistorical(
    const ContainerParameters& observed, const ContainerParameters& historical)
{
  return observed.uuid == historical.uuid &&
         observed.deploymentID == historical.deploymentID &&
         observed.memoryMB == historical.memoryMB &&
         observed.storageMB == historical.storageMB &&
         observed.nLogicalCores == historical.nLogicalCores &&
         observed.private6.network.is6 == historical.private6.network.is6 &&
         observed.private6.cidr == historical.private6.cidr &&
         std::memcmp(observed.private6.network.v6, historical.private6.network.v6,
                     sizeof(observed.private6.network.v6)) == 0 &&
         observed.statefulMeshRoles.client == historical.statefulMeshRoles.client &&
         observed.statefulMeshRoles.sibling == historical.statefulMeshRoles.sibling &&
         observed.statefulMeshRoles.cousin == historical.statefulMeshRoles.cousin &&
         observed.statefulMeshRoles.seeding == historical.statefulMeshRoles.seeding &&
         observed.statefulMeshRoles.sharding == historical.statefulMeshRoles.sharding &&
         observed.statefulMeshRoles.topologyBridge == historical.statefulMeshRoles.topologyBridge &&
         observed.statefulTopology.shardGroup == historical.statefulTopology.shardGroup &&
         observed.statefulTopology.topologyEpoch == historical.statefulTopology.topologyEpoch &&
         observed.statefulTopology.workerCount == historical.statefulTopology.workerCount &&
         observed.statefulTopology.sourceEpoch == historical.statefulTopology.sourceEpoch &&
         observed.statefulTopology.targetEpoch == historical.statefulTopology.targetEpoch &&
         observed.statefulTopology.servingMode == historical.statefulTopology.servingMode &&
         observed.statefulTopology.bridgeMode == historical.statefulTopology.bridgeMode;
}

static inline bool mothershipRetainedRecoveryOrphanedStatefulPredecessorMatchesSnapshot(
    const ProdigyPersistentBrainSnapshot& snapshot,
    const MothershipRetainedRecoveryOrphanedStatefulPredecessor& orphan,
    String *failure = nullptr,
    bool requireAbsent = false)
{
  if (failure) failure->clear();
  if (!mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(orphan)) {
    if (failure) failure->assign("invalid orphaned stateful predecessor descriptor"_ctv);
    return false;
  }
  uint32_t matchingOperations = 0;
  for (const ProdigyMaterializedStatefulRecoveryOperation& current :
       snapshot.masterAuthority.runtimeState.materializedStatefulRecoveryOperations) {
    if (current.operationID.equals(orphan.operation.operationID)) {
      if (!mothershipRetainedRecoveryPartialHandoffEqual(current, orphan.operation)) {
        if (failure) failure->assign("orphaned stateful predecessor operation differs from durable authority"_ctv);
        return false;
      }
      ++matchingOperations;
    } else if (current.activeDeploymentID == orphan.operation.activeDeploymentID ||
               current.successorDeploymentID == orphan.operation.activeDeploymentID ||
               current.activeDeploymentID == orphan.operation.successorDeploymentID ||
               current.successorDeploymentID == orphan.operation.successorDeploymentID) {
      if (failure) failure->assign("orphaned stateful predecessor operation collides with durable authority"_ctv);
      return false;
    }
  }
  if (matchingOperations != 1) {
    if (failure) failure->assign("orphaned stateful predecessor operation is absent or duplicated"_ctv);
    return false;
  }
  for (const ProdigyMaterializedStatefulRecoveryRetry& retry :
       snapshot.masterAuthority.runtimeState.materializedStatefulRecoveryRetries) {
    if (retry.operationID.equals(orphan.operation.operationID) ||
        retry.activeDeploymentID == orphan.operation.activeDeploymentID ||
        retry.failedSuccessorDeploymentID == orphan.operation.successorDeploymentID ||
        retry.replacementSuccessorDeploymentID == orphan.operation.successorDeploymentID) {
      if (failure) failure->assign("orphaned stateful predecessor collides with durable recovery retry"_ctv);
      return false;
    }
  }
  uint32_t matchingRuntimeStates = 0;
  for (const BrainReplicatedContainerRuntimeState& state : snapshot.masterAuthority.containerRuntimeStates) {
    if (state.plan.uuid != orphan.parameters.uuid) continue;
    ++matchingRuntimeStates;
    if (state.machineUUID != orphan.machineUUID ||
        state.plan.config.deploymentID() != orphan.operation.activeDeploymentID || !state.plan.isStateful ||
        state.plan.lifetime != ApplicationLifetime::base || state.plan.shardGroup != 0 ||
        state.plan.statefulMeshRoles.client != 0 ||
        state.plan.statefulMeshRoles.sibling != orphan.parameters.statefulMeshRoles.sibling ||
        state.plan.statefulMeshRoles.cousin != orphan.parameters.statefulMeshRoles.cousin ||
        state.plan.statefulMeshRoles.seeding != orphan.parameters.statefulMeshRoles.seeding ||
        state.plan.statefulMeshRoles.sharding != orphan.parameters.statefulMeshRoles.sharding ||
        state.plan.statefulMeshRoles.topologyBridge != orphan.parameters.statefulMeshRoles.topologyBridge ||
        state.plan.statefulTopology.shardGroup != orphan.parameters.statefulTopology.shardGroup ||
        state.plan.statefulTopology.topologyEpoch != orphan.parameters.statefulTopology.topologyEpoch ||
        state.plan.statefulTopology.workerCount != orphan.parameters.statefulTopology.workerCount ||
        state.plan.statefulTopology.sourceEpoch != orphan.parameters.statefulTopology.sourceEpoch ||
        state.plan.statefulTopology.targetEpoch != orphan.parameters.statefulTopology.targetEpoch ||
        state.plan.statefulTopology.servingMode != orphan.parameters.statefulTopology.servingMode ||
        state.plan.statefulTopology.bridgeMode != orphan.parameters.statefulTopology.bridgeMode ||
        state.plan.addresses.empty() ||
        state.plan.addresses[0].network.is6 != orphan.parameters.private6.network.is6 ||
        state.plan.addresses[0].cidr != orphan.parameters.private6.cidr ||
        std::memcmp(state.plan.addresses[0].network.v6, orphan.parameters.private6.network.v6,
                    sizeof(orphan.parameters.private6.network.v6)) != 0) {
      if (failure) failure->assign("orphaned stateful predecessor runtime identity differs from durable authority"_ctv);
      return false;
    }
  }
  // A deployment that has been culled from authority is intentionally omitted
  // by the ordinary runtime capture owner. The sealed predecessor request is
  // authoritative in that case. A retained runtime record, if present, is an
  // additional identity check; an already-prepared retry requires it absent.
  if (matchingRuntimeStates > 1 || (requireAbsent && matchingRuntimeStates != 0)) {
    if (failure) failure->assign("orphaned stateful predecessor runtime identity is duplicated or unexpectedly retained"_ctv);
    return false;
  }
  return true;
}

// A fenced retained process may have advanced its in-memory lifecycle after the
// sealed parameters were captured.  Those observations are not recovery
// authority: only a scheduled or healthy process is admissible, and its
// readiness and live mesh edges must be rebuilt after recovery.  Every other
// bootstrap field, including credentials, services, subscriptions and
// advertisements, stays byte-equivalent under the persistent comparator.
static inline bool mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(
    const NeuronContainerBootstrap& observed,
    NeuronContainerBootstrap reconstructed)
{
  if ((observed.plan.state != ContainerState::scheduled && observed.plan.state != ContainerState::healthy) ||
      reconstructed.plan.state != ContainerState::scheduled || reconstructed.plan.runtimeReady)
    return false;
  reconstructed.plan.createdAtMs = observed.plan.createdAtMs;
  reconstructed.plan.state = observed.plan.state;
  reconstructed.plan.runtimeReady = observed.plan.runtimeReady;
  reconstructed.plan.subscriptionPairings.clear();
  reconstructed.plan.advertisementPairings.clear();
  auto normalizedObserved = observed;
  normalizedObserved.plan.subscriptionPairings.clear();
  normalizedObserved.plan.advertisementPairings.clear();
  return prodigyPersistentRetainedBootstrapEqual(normalizedObserved, reconstructed);
}

static inline bool mothershipRetainedRecoveryMixedWitnessesMatch(
    const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& actual,
    const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& expected,
    const Vector<uint128_t>& successorMachineUUIDs, bool successorsRegistered = true)
{
  if (actual.size() != expected.size()) return false;
  for (size_t index = 0; index < expected.size(); ++index)
  {
    const auto& left=actual[index]; const auto& right=expected[index];
    bool successor=false;
    for (uint128_t machine : successorMachineUUIDs) successor |= machine == right.machineUUID;
    if (left.machineUUID != right.machineUUID || left.bundleRegistered != (successor && successorsRegistered) ||
        left.containerBootstraps.size() != right.containerBootstraps.size()) return false;
    Vector<uint8_t> used(right.containerBootstraps.size());
    bytell_hash_set<uint128_t> observedContainers;
    for (const auto& bytes : left.containerBootstraps)
    {
      NeuronContainerBootstrap observed={}, reconstructed={};
      if (!BitseryEngine::deserializeSafe(bytes,observed) ||
          !observedContainers.insert(observed.plan.uuid).second) return false;
      bool matched=false;
      for (size_t bootstrap = 0; bootstrap < right.containerBootstraps.size(); ++bootstrap)
      {
        if (used[bootstrap]) continue;
        if (!BitseryEngine::deserializeSafe(right.containerBootstraps[bootstrap],reconstructed) ||
            reconstructed.plan.uuid != observed.plan.uuid) continue;
        // A retained process owns its original creation timestamp.  The
        // recovery inventory observes it later, so rebuilds with that later
        // observation by design.  Preserve the saved timestamp only after its
        // container UUID has bound the two otherwise complete bootstraps.
        if (!mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(observed,reconstructed)) return false;
        used[bootstrap]=1; matched=true; break;
      }
      if (!matched) return false;
    }
  }
  return true;
}

// A fenced fleet may have stopped while the normal updater was only collecting
// bundle echoes. Accept that transaction only for this exact successor or the
// sealed installed predecessor, before any exec or handoff evidence. The command
// owner proves the stopped runtime and retained process identities; this owner
// validates the saved transaction and its bundle bytes.
static inline bool mothershipRetainedRecoveryCanReplaceUpdate(
    const ProdigyPersistentBrainSnapshot& snapshot, const String& expectedBundleSHA256,
    const String& previousBundleSHA256 = {}, const String& interruptedBundleSHA256 = {})
{
  const auto& update = snapshot.masterAuthority.runtimeState.updateSelf;
  if (!update.active()) return true;
  // Admission may reject after retaining the candidate payload, before the
  // coordinator issues any work. Fenced recovery may consume that exact
  // candidate only when every progress, handoff and recovery field is empty.
  ProdigyPersistentUpdateSelfState unstarted;
  unstarted.bundleBlob = update.bundleBlob;
  unstarted.workerExpectedBundleSHA256 = update.workerExpectedBundleSHA256;
  unstarted.workerFailure = update.workerFailure;
  if (update == unstarted && !update.bundleBlob.empty() && !update.workerFailure.empty() &&
      update.workerExpectedBundleSHA256 == expectedBundleSHA256)
  {
    String digest;
    return prodigyComputeSHA256Hex(update.bundleBlob, digest) && digest == expectedBundleSHA256;
  }
  // Followers can still hold the previous recovery envelope when the master's
  // next update is contained. Only the sealed installed predecessor is allowed.
  const bool previousEnvelope = mothershipRetainedRecoveryEnvelopeMatches(update, previousBundleSHA256);
  // A failed ordinary same-bundle update retains the installed predecessor's
  // payload while waiting for echoes. Fenced repair can install a separately
  // approved successor without pretending that payload has the new digest.
  const bool normalBundleMatches = update.workerExpectedBundleSHA256 == expectedBundleSHA256 ||
      (prodigyIsSHA256HexDigest(previousBundleSHA256) &&
       update.workerExpectedBundleSHA256 == previousBundleSHA256 &&
       !update.machineRecoveryWitnesses.empty()) ||
      (prodigyIsSHA256HexDigest(interruptedBundleSHA256) &&
       interruptedBundleSHA256 != expectedBundleSHA256 &&
       interruptedBundleSHA256 != previousBundleSHA256 &&
       update.workerExpectedBundleSHA256 == interruptedBundleSHA256);
  if (!previousEnvelope && (update.state != uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForBundleEchos) ||
      update.expectedEchos == 0 || update.expectedEchos >= snapshot.topology.machines.size() ||
      update.bundleEchos > update.expectedEchos || update.bundleEchoPeerKeys.size() != update.bundleEchos ||
      update.relinquishEchos != 0 || update.plannedMasterPeerKey != 0 || update.pendingDesignatedMasterPeerKey != 0 ||
      update.useStagedBundleOnly || update.bundleBlob.empty() ||
      !update.relinquishEchoPeerKeys.empty() || !update.followerBootNsByPeerKey.empty() || !update.followerRebootedPeerKeys.empty() ||
      !normalBundleMatches || !update.workerFailure.empty() ||
      !update.workerMachineUUIDs.empty() || !update.workerStagedMachineUUIDs.empty() ||
      !update.workerTransitionIssuedMachineUUIDs.empty() || !update.workerRebootedMachineUUIDs.empty() ||
      !update.workerStateUploadedMachineUUIDs.empty() || update.localMachineUUID != 0 ||
      update.localBundleRegistered || !update.localContainerBootstraps.empty())) return false;
  bytell_hash_set<uint128_t> peers;
  for (uint128_t key : update.bundleEchoPeerKeys)
  {
    if (key == 0 || !peers.insert(key).second) return false;
    bool known = false;
    for (const auto& machine : snapshot.topology.machines) known |= machine.uuid == key;
    if (!known) return false;
  }
  if (!update.machineRecoveryWitnesses.empty()) {
    if (update.machineRecoveryWitnesses.size() != snapshot.topology.machines.size()) return false;
    bytell_hash_set<uint128_t> machines;
    for (const auto& witness : update.machineRecoveryWitnesses) {
      if (witness.bundleRegistered || !machines.insert(witness.machineUUID).second) return false;
      bool known = false;
      for (const auto& machine : snapshot.topology.machines) known |= machine.uuid == witness.machineUUID;
      if (!known) return false;
    }
  }
  if (previousEnvelope) return true;
  String digest;
  return prodigyComputeSHA256Hex(update.bundleBlob, digest) && digest == update.workerExpectedBundleSHA256;
}

// A successor can retain either the exact interrupted recovery envelope, or
// a later pre-exec echo collection. Schema four also admits the captured
// clean v13 echo collector; legacy recovery still requires the known digest
// failure. Both forms reconstruct every retained container before the generic
// updater guard is reused.
static inline bool mothershipRetainedRecoveryCanReplaceMixedInterruptedUpdate(
    const ProdigyPersistentBrainSnapshot& snapshot, const String& expectedBundleSHA256,
    const String& previousBundleSHA256, const String& interruptedBundleSHA256,
    const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& expectedWitnesses,
    const Vector<uint128_t>& successorMachineUUIDs, const MothershipRetainedRecoveryMixedProof *proof = nullptr)
{
  if (!prodigyIsSHA256HexDigest(interruptedBundleSHA256) || successorMachineUUIDs.empty() ||
      successorMachineUUIDs.size() >= snapshot.topology.machines.size() || successorMachineUUIDs[0] == 0 ||
      (proof ? (!proof->validFor(snapshot) || successorMachineUUIDs.size()!=1) : successorMachineUUIDs.size()!=2)) return false;
  for (size_t index=1; index<successorMachineUUIDs.size(); ++index)
    if (successorMachineUUIDs[index] == 0 || successorMachineUUIDs[index-1] >= successorMachineUUIDs[index]) return false;
  const auto& update=snapshot.masterAuthority.runtimeState.updateSelf;
  if (proof && mothershipRetainedRecoveryWitnessContainerCount(expectedWitnesses)!=proof->canonicalContainerCount) return false;
  if (mothershipRetainedRecoveryEnvelopeMatches(update,interruptedBundleSHA256))
  {
    if (!mothershipRetainedRecoveryMixedWitnessesMatch(
            update.machineRecoveryWitnesses,expectedWitnesses,successorMachineUUIDs,false)) return false;
    return mothershipRetainedRecoveryCanReplaceUpdate(
        snapshot,expectedBundleSHA256,interruptedBundleSHA256,interruptedBundleSHA256);
  }
  if (update.expectedEchos != (proof ? proof->interruptedExpectedEchos : successorMachineUUIDs.size()) || update.bundleEchos != update.expectedEchos ||
      update.workerExpectedBundleSHA256 != interruptedBundleSHA256 ||
      (proof ? !(update.workerFailure.empty() || update.workerFailure == "local post-exec bundle digest mismatch"_ctv)
             : update.workerFailure != "local post-exec bundle digest mismatch"_ctv) ||
      !mothershipRetainedRecoveryMixedWitnessesMatch(
          update.machineRecoveryWitnesses,expectedWitnesses,successorMachineUUIDs,true)) return false;
  auto comparable=snapshot;
  auto& recovered=comparable.masterAuthority.runtimeState.updateSelf;
  recovered.workerFailure.clear();
  for (auto& witness:recovered.machineRecoveryWitnesses) witness.bundleRegistered=false;
  return mothershipRetainedRecoveryCanReplaceUpdate(
      comparable,expectedBundleSHA256,previousBundleSHA256,interruptedBundleSHA256);
}

// A partially executed handoff is more restrictive than an ordinary interrupted
// update: its coordinator may already have asked the two approved successor
// machines to reboot.  It is replaceable only after the command owner has
// proven the machine/runtime mapping, and this owner can reconstruct the exact
// all-machine witness from the sealed retained inventory.  No worker, local
// exec, designation, or relinquish progress is accepted.
static inline bool mothershipRetainedRecoveryCanReplaceMixedHandoff(
    const ProdigyPersistentBrainSnapshot& snapshot, const String& interruptedBundleSHA256,
    const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& expectedWitnesses,
    const Vector<uint128_t>& successorMachineUUIDs, const MothershipRetainedRecoveryMixedProof *proof = nullptr)
{
  const auto& update = snapshot.masterAuthority.runtimeState.updateSelf;
  if (!prodigyIsSHA256HexDigest(interruptedBundleSHA256) ||
      (proof != nullptr || successorMachineUUIDs.size() != 2) || successorMachineUUIDs[0] == 0 ||
      update.state != uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForFollowerReboots) ||
      update.expectedEchos != successorMachineUUIDs.size() ||
      update.bundleEchos != update.expectedEchos || update.relinquishEchos != 0 ||
      update.plannedMasterPeerKey != 0 || update.pendingDesignatedMasterPeerKey != 0 ||
      update.useStagedBundleOnly || !update.bundleBlob.empty() ||
      update.workerExpectedBundleSHA256 != interruptedBundleSHA256 ||
      (update.workerFailure != "local post-exec bundle digest mismatch"_ctv) ||
      !update.relinquishEchoPeerKeys.empty() || !update.workerMachineUUIDs.empty() ||
      !update.workerStagedMachineUUIDs.empty() || !update.workerTransitionIssuedMachineUUIDs.empty() ||
      !update.workerRebootedMachineUUIDs.empty() || !update.workerStateUploadedMachineUUIDs.empty() ||
      update.localMachineUUID != 0 || update.localBundleRegistered || !update.localContainerBootstraps.empty() ||
      !mothershipRetainedRecoveryMixedWitnessesMatch(update.machineRecoveryWitnesses,expectedWitnesses,successorMachineUUIDs) ||
      update.bundleEchoPeerKeys != successorMachineUUIDs ||
      update.followerRebootedPeerKeys != successorMachineUUIDs ||
      update.followerBootNsByPeerKey.size() != successorMachineUUIDs.size())
  {
    return false;
  }
  for (size_t index = 0; index < successorMachineUUIDs.size(); ++index)
  {
    if (successorMachineUUIDs[index] == 0 || (index && successorMachineUUIDs[index-1] >= successorMachineUUIDs[index]) ||
        update.followerBootNsByPeerKey[index].peerKey != successorMachineUUIDs[index] ||
        update.followerBootNsByPeerKey[index].bootNs <= 0)
      return false;
  }
  return true;
}

// `approvedPlans` is read from the sealed seed copy.  Existing plans are never
// overwritten; a missing plan is admitted only if its supplied deployment ID
// and declared plan agree with every recovered bootstrap. Existing CID runtime
// state remains local; it is never replaced with the seed's key generation.
static inline bool mothershipPrepareRetainedRecoverySnapshot(
    ProdigyPersistentBrainSnapshot& snapshot,
    const bytell_hash_map<uint64_t, DeploymentPlan>& approvedPlans,
    const Vector<MothershipRetainedRecoveryMachineInput>& machines,
    const String& expectedBundleSHA256,
    String *failure = nullptr,
    const String& previousBundleSHA256 = {},
    const String& interruptedBundleSHA256 = {},
    uint128_t retiredConflictingClientUUID = 0,
    const MothershipRetainedRecoveryMixedProof *retirementProof = nullptr,
    bool retainRetiredConflictingClientForCoordinatorProof = false,
    bool validateCoordinator = true,
    uint128_t emptyRetainedInventoryMachineUUID = 0,
    const Vector<BrainReplicatedContainerRuntimeState>& coldCanonicalRuntimeStates = {},
    const ProdigyMaterializedStatefulRecoveryOperation *partialHandoff = nullptr)
{
  if (failure) failure->clear();
  if (snapshot.brainConfig.clusterUUID == 0 ||
      snapshot.brainConfig.datacenterFragment == 0 ||
      machines.size() != snapshot.topology.machines.size() ||
      machines.empty() ||
      prodigyIsSHA256HexDigest(expectedBundleSHA256) == false)
  {
    if (failure) failure->assign("invalid retained recovery authority input"_ctv);
    return false;
  }
  auto& runtime = snapshot.masterAuthority.runtimeState;
  if (runtime.generation == std::numeric_limits<uint64_t>::max() ||
      (validateCoordinator && !mothershipRetainedRecoveryCanReplaceUpdate(snapshot, expectedBundleSHA256, previousBundleSHA256,
                                                                           interruptedBundleSHA256)))
  {
    if (failure) failure->assign("retained recovery refuses an incompatible or exhausted update coordinator"_ctv);
    return false;
  }

  // This exception is deliberately not a generic recovery relaxation.  The
  // retained-command owner supplies it only after it has fenced and retired
  // the one schema-four process named by the immutable proof.  We still
  // reconstruct that record first, so a malformed replacement cannot turn an
  // arbitrary stateful process into an omitted witness.
  const bool retiringConflictingClient = retiredConflictingClientUUID != 0;
  if (retiringConflictingClient &&
      (retirementProof == nullptr ||
       retirementProof->staleExcludedContainerUUID != retiredConflictingClientUUID ||
       retirementProof->canonicalContainerCount != retirementProof->staleCoordinatorCanonicalContainerCount + 1 ||
       retirementProof->canonicalContainerCount == 0))
  {
    if (failure) failure->assign("invalid sealed conflicting-client retirement proof"_ctv);
    return false;
  }
  Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness> witnesses = {};
  witnesses.reserve(machines.size());
  bytell_hash_set<uint128_t> seenMachines = {};
  bytell_hash_set<uint128_t> seenContainers = {};
  bytell_hash_set<uint32_t> seenFragments = {};
  bytell_hash_map<uint64_t,uint32_t> statefulReplicas, statefulClientMasters;
  bytell_hash_map<uint64_t,uint32_t> fullStatefulReplicas, fullStatefulClientMasters;
  struct ObservedStatefulBootstrap {
    uint64_t deploymentID = 0;
    uint128_t machineUUID = 0;
    NeuronContainerBootstrap bootstrap;
  };
  Vector<ObservedStatefulBootstrap> observedStatefulBootstraps = {};
  uint64_t retiredDeploymentID = 0;
  uint32_t retiredShardGroup = 0;
  uint64_t retiredClientRole = 0;
  for (const auto& machine : machines)
    for (const auto& parameters : machine.parameters)
      if (parameters.uuid == retiredConflictingClientUUID) {
        if (retiredDeploymentID != 0) { if (failure) failure->assign("duplicate sealed conflicting-client target"_ctv); return false; }
        retiredDeploymentID=parameters.deploymentID; retiredShardGroup=parameters.statefulTopology.shardGroup;
        retiredClientRole=parameters.statefulMeshRoles.client;
      }
  if (retiringConflictingClient && (retiredDeploymentID == 0 || retiredClientRole == 0)) {
    if (failure) failure->assign("sealed conflicting-client target is absent or has no client role"_ctv);
    return false;
  }
  uint32_t fullRetiredCohort = 0, retainedRetiredCohort = 0, fullRetiredCohortClients = 0, retainedRetiredCohortClients = 0;
  bytell_hash_set<uint128_t> retiredCohortMachines = {};
  uint32_t fullRecords = 0, retainedRecords = 0;
  uint32_t emptyMachineInputs = 0;
  for (const MothershipRetainedRecoveryMachineInput& machine : machines)
  {
    const bool explicitlyEmpty = machine.machineUUID == emptyRetainedInventoryMachineUUID;
    if (machine.machineUUID == 0 || machine.machineFragment == 0 || machine.machineFragment > 0xffffff ||
        !seenFragments.insert(machine.machineFragment).second ||
        machine.parameters.size() != machine.observedCreatedAtMs.size() ||
        (machine.parameters.empty() && !explicitlyEmpty) ||
        (!machine.parameters.empty() && explicitlyEmpty) ||
        seenMachines.insert(machine.machineUUID).second == false)
    {
      if (failure) failure->assign("invalid or duplicate retained recovery machine input"_ctv);
      return false;
    }
    emptyMachineInputs += explicitlyEmpty;
    bool topologyMachine = false;
    for (const ClusterMachine& candidate : snapshot.topology.machines)
      if (candidate.uuid == machine.machineUUID) topologyMachine = true;
    if (!topologyMachine)
    {
      if (failure) failure->assign("retained recovery machine is absent from the frozen topology"_ctv);
      return false;
    }
    ProdigyPersistentUpdateSelfMachineRecoveryWitness witness = {};
    witness.machineUUID = machine.machineUUID;
    bytell_hash_set<uint8_t> containerFragments;
    for (uint32_t index = 0; index < machine.parameters.size(); ++index)
    {
      const ContainerParameters& parameters = machine.parameters[index];
      ++fullRecords;
      if (parameters.uuid == 0 || parameters.deploymentID == 0 ||
          seenContainers.insert(parameters.uuid).second == false ||
          !containerFragments.insert(parameters.private6.network.v6[15]).second)
      {
        if (failure) failure->assign("invalid or duplicate retained container identity"_ctv);
        return false;
      }
      auto existing = snapshot.masterAuthority.deploymentPlans.find(parameters.deploymentID);
      auto approved = approvedPlans.find(parameters.deploymentID);
      if (approved == approvedPlans.end())
      {
        if (failure) failure->assign("retained container deployment is absent from frozen authority"_ctv);
        return false;
      }
      if (existing == snapshot.masterAuthority.deploymentPlans.end())
      {
        snapshot.masterAuthority.deploymentPlans.insert_or_assign(parameters.deploymentID, approved->second);
        existing = snapshot.masterAuthority.deploymentPlans.find(parameters.deploymentID);
      }
      if (existing == snapshot.masterAuthority.deploymentPlans.end() ||
          mothershipRetainedRecoveryPlansEqual(existing->second, approved->second) == false)
      {
        if (failure) failure->assign("retained deployment differs from frozen authority"_ctv);
        return false;
      }
      NeuronContainerBootstrap bootstrap = {};
      String bootstrapFailure = {};
      if (prodigyBuildRetainedContainerBootstrap(
              existing->second, parameters, machine.machineFragment,
              snapshot.brainConfig.datacenterFragment, machine.observedCreatedAtMs[index],
              bootstrap, &bootstrapFailure) == false)
      {
        if (failure) failure->assign(bootstrapFailure);
        return false;
      }
      if (existing->second.isStateful) {
        ++fullStatefulReplicas[parameters.deploymentID];
        if (bootstrap.plan.statefulMeshRoles.client != 0) ++fullStatefulClientMasters[parameters.deploymentID];
        observedStatefulBootstraps.push_back({parameters.deploymentID, machine.machineUUID, bootstrap});
      }
      const bool retiredCohort = retiringConflictingClient && parameters.deploymentID == retiredDeploymentID &&
          parameters.statefulTopology.shardGroup == retiredShardGroup;
      if (retiredCohort) {
        ++fullRetiredCohort;
        if (bootstrap.plan.statefulMeshRoles.client == retiredClientRole) ++fullRetiredCohortClients;
        retiredCohortMachines.insert(machine.machineUUID);
      }
      if (parameters.uuid == retiredConflictingClientUUID) {
        if (!retiringConflictingClient || !existing->second.isStateful ||
            existing->second.stateful.allMasters || bootstrap.plan.statefulMeshRoles.client == 0 ||
            parameters.deploymentID != retiredDeploymentID ||
            parameters.statefulTopology.shardGroup != retiredShardGroup ||
            bootstrap.plan.statefulMeshRoles.client != retiredClientRole)
        {
          if (failure) failure->assign("sealed conflicting-client retirement target is not one non-all-master client replica"_ctv);
          return false;
        }
        if (!retainRetiredConflictingClientForCoordinatorProof) continue;
      }
      ++retainedRecords;
      if (retiredCohort) {
        ++retainedRetiredCohort;
        if (bootstrap.plan.statefulMeshRoles.client == retiredClientRole) ++retainedRetiredCohortClients;
      }
      if (existing->second.isStateful) {
        ++statefulReplicas[parameters.deploymentID];
        if (bootstrap.plan.statefulMeshRoles.client != 0) ++statefulClientMasters[parameters.deploymentID];
      }
      String serialized = {};
      BitseryEngine::serialize(serialized, bootstrap);
      witness.containerBootstraps.push_back(std::move(serialized));
    }
    witnesses.push_back(std::move(witness));
  }
  if ((emptyRetainedInventoryMachineUUID != 0 && emptyMachineInputs != 1) ||
      (emptyRetainedInventoryMachineUUID == 0 && emptyMachineInputs != 0) ||
      (coldCanonicalRuntimeStates.empty() == false &&
       (emptyRetainedInventoryMachineUUID == 0 || retiringConflictingClient)))
  {
    if (failure) failure->assign("invalid sealed empty retained inventory machine"_ctv);
    return false;
  }

  // An empty observed inventory is never permission to invent a replacement.
  // The command owner may provide only full canonical records decoded from its
  // adjacent sealed stopped snapshot.  This pure owner binds those records to
  // the one explicitly empty machine, then rebuilds ordinary state-upload
  // bootstraps and leaves the existing cardinality proof authoritative.
  Vector<BrainReplicatedContainerRuntimeState> coldStatesToPersist = {};
  if (coldCanonicalRuntimeStates.empty() == false)
  {
    ProdigyPersistentUpdateSelfMachineRecoveryWitness *emptyWitness = nullptr;
    uint32_t emptyMachineFragment = 0;
    for (ProdigyPersistentUpdateSelfMachineRecoveryWitness& witness : witnesses)
    {
      if (witness.machineUUID == emptyRetainedInventoryMachineUUID)
      {
        emptyWitness = &witness;
        break;
      }
    }
    for (const MothershipRetainedRecoveryMachineInput& machine : machines)
    {
      if (machine.machineUUID == emptyRetainedInventoryMachineUUID)
      {
        emptyMachineFragment = machine.machineFragment;
        break;
      }
    }
    if (emptyWitness == nullptr || emptyMachineFragment == 0 ||
        emptyWitness->containerBootstraps.empty() == false)
    {
      if (failure) failure->assign("cold canonical recovery does not bind one empty machine"_ctv);
      return false;
    }

    bytell_hash_set<uint8_t> selectedContainerFragments = {};
    for (const BrainReplicatedContainerRuntimeState& cold : coldCanonicalRuntimeStates)
    {
      const ContainerPlan& plan = cold.plan;
      const uint64_t deploymentID = plan.config.deploymentID();
      if (cold.machineUUID != emptyRetainedInventoryMachineUUID ||
          plan.uuid == 0 || deploymentID == 0 || plan.isStateful == false ||
          plan.fragment == 0 || !selectedContainerFragments.insert(plan.fragment).second ||
          plan.nShardGroups != 1 || plan.shardGroup != 0 ||
          plan.addresses.size() != 1 || plan.addresses[0].network.is6 == false ||
          plan.addresses[0].cidr != 128 ||
          std::memcmp(plan.addresses[0].network.v6, container_network_subnet6.value, 11) != 0 ||
          plan.addresses[0].network.v6[11] != snapshot.brainConfig.datacenterFragment ||
          plan.addresses[0].network.v6[12] != uint8_t((emptyMachineFragment >> 16) & 0xffu) ||
          plan.addresses[0].network.v6[13] != uint8_t((emptyMachineFragment >> 8) & 0xffu) ||
          plan.addresses[0].network.v6[14] != uint8_t(emptyMachineFragment & 0xffu) ||
          plan.addresses[0].network.v6[15] != plan.fragment ||
          seenContainers.insert(plan.uuid).second == false)
      {
        if (failure) failure->assign("cold canonical runtime identity is invalid or collides with retained inventory"_ctv);
        return false;
      }
      auto approved = approvedPlans.find(deploymentID);
      auto existing = snapshot.masterAuthority.deploymentPlans.find(deploymentID);
      if (approved == approvedPlans.end() || existing == snapshot.masterAuthority.deploymentPlans.end() ||
          mothershipRetainedRecoveryPlansEqual(existing->second, approved->second) == false ||
          existing->second.isStateful == false || existing->second.stateful.allMasters)
      {
        if (failure) failure->assign("cold canonical runtime deployment is not an approved non-all-master stateful plan"_ctv);
        return false;
      }
      ApplicationConfig leftConfig = plan.config, rightConfig = existing->second.config;
      String serializedLeft = {}, serializedRight = {};
      BitseryEngine::serialize(serializedLeft, leftConfig);
      BitseryEngine::serialize(serializedRight, rightConfig);
      const StatefulMeshRoles rawRoles = StatefulMeshRoles::forShardGroup(
          existing->second.stateful, existing->second.config.applicationID, 0);
      StatefulMeshRoles expectedRoles = {};
      if (prodigyRetainedRecoveryGeneratedStatefulRoles(
              existing->second, plan.statefulTopology,
              plan.advertisements.contains(rawRoles.client),
              plan.subscriptionPairings.map.contains(rawRoles.seeding),
              expectedRoles) == false ||
          serializedLeft != serializedRight || plan.statefulMeshRoles.client == 0 ||
          plan.statefulMeshRoles.client != expectedRoles.client ||
          plan.statefulMeshRoles.sibling != expectedRoles.sibling ||
          plan.statefulMeshRoles.seeding != expectedRoles.seeding ||
          plan.statefulMeshRoles.cousin != expectedRoles.cousin ||
          plan.statefulMeshRoles.sharding != expectedRoles.sharding ||
          plan.statefulMeshRoles.topologyBridge != expectedRoles.topologyBridge ||
          plan.networkAccess != existing->second.networkAccess || plan.useHostNetworkNamespace ||
          plan.lifetime != ApplicationLifetime::base ||
          plan.statefulTopology.configured() == false || plan.statefulTopology.operationID != 0 ||
          plan.statefulTopology.bridgeMode != StatefulTopologyBridgeMode::none ||
          plan.statefulTopology.shardGroup != 0 || plan.statefulTopology.workerCount !=
              prodigyStatefulWorkerCountForLogicalCores(existing->second.config.nLogicalCores))
      {
        if (failure) failure->assign("cold canonical runtime plan differs from approved stateful authority"_ctv);
        return false;
      }
      for (const BrainReplicatedContainerRuntimeState& current : snapshot.masterAuthority.containerRuntimeStates)
      {
        if (current.plan.uuid != plan.uuid) continue;
        // The selected stopped source is authoritative only for the declared
        // empty machine. A live peer may never be replaced by this path.
        if (current.machineUUID != emptyRetainedInventoryMachineUUID)
        {
          if (failure) failure->assign("cold canonical runtime conflicts with persistent authority"_ctv);
          return false;
        }
      }
      NeuronContainerBootstrap bootstrap = {};
      bootstrap.plan = plan;
      // State upload owns readiness. A cold canonical record must not claim a
      // serving process before the restored Neuron has recreated it.
      bootstrap.plan.state = ContainerState::scheduled;
      bootstrap.plan.runtimeReady = false;
      bootstrap.metricPolicy = prodigyNeuronMetricPolicyForDeployment(existing->second);
      String serializedBootstrap = {};
      BitseryEngine::serialize(serializedBootstrap, bootstrap);
      emptyWitness->containerBootstraps.push_back(std::move(serializedBootstrap));
      ++statefulReplicas[deploymentID];
      ++statefulClientMasters[deploymentID];
      coldStatesToPersist.push_back(cold);
    }
  }
  bool sealedPartialHandoff = false;
  bool partialHandoffAlreadyDurable = false;
  if (partialHandoff != nullptr)
  {
    const uint64_t activeID = partialHandoff->activeDeploymentID;
    const uint64_t successorID = partialHandoff->successorDeploymentID;
    auto active = approvedPlans.find(activeID);
    auto successor = approvedPlans.find(successorID);
    if (retiringConflictingClient || activeID == 0 || successorID == 0 || activeID >= successorID ||
        prodigyCanonicalOperationUUID(partialHandoff->operationID) == false ||
        prodigyIsSHA256HexDigest(partialHandoff->successorBlobSHA256) == false ||
        partialHandoff->accepted == false || partialHandoff->started == false || partialHandoff->completed ||
        partialHandoff->updatedAtMs <= 0 || active == approvedPlans.end() || successor == approvedPlans.end() ||
        active->second.stateful.allMasters || successor->second.stateful.allMasters ||
        prodigyMaterializedStatefulRecoveryPlansAreCompatible(active->second, successor->second) == false ||
        successor->second.config.containerBlobSHA256.equals(partialHandoff->successorBlobSHA256) == false ||
        statefulReplicas[activeID] != 2 || statefulClientMasters[activeID] != 1 ||
        statefulReplicas[successorID] != 1 || statefulClientMasters[successorID] != 0)
    {
      if (failure) failure->assign("sealed partial materialized handoff is not an exact 2+1 stateful lineage"_ctv);
      return false;
    }
    for (const ProdigyMaterializedStatefulRecoveryOperation& current : runtime.materializedStatefulRecoveryOperations)
    {
      if (mothershipRetainedRecoveryPartialHandoffEqual(current, *partialHandoff))
      {
        if (partialHandoffAlreadyDurable)
        {
          if (failure) failure->assign("sealed partial materialized handoff is duplicated in durable recovery authority"_ctv);
          return false;
        }
        partialHandoffAlreadyDurable = true;
        continue;
      }
      if (current.operationID.equals(partialHandoff->operationID) ||
          current.activeDeploymentID == activeID || current.activeDeploymentID == successorID ||
          current.successorDeploymentID == activeID || current.successorDeploymentID == successorID)
      {
        if (failure) failure->assign("sealed partial materialized handoff collides with durable recovery authority"_ctv);
        return false;
      }
    }
    for (const ProdigyMaterializedStatefulRecoveryRetry& current : runtime.materializedStatefulRecoveryRetries)
    {
      if (current.operationID.equals(partialHandoff->operationID) ||
          current.activeDeploymentID == activeID || current.activeDeploymentID == successorID ||
          current.failedSuccessorDeploymentID == activeID || current.failedSuccessorDeploymentID == successorID ||
          current.replacementSuccessorDeploymentID == activeID || current.replacementSuccessorDeploymentID == successorID)
      {
        if (failure) failure->assign("sealed partial materialized handoff collides with durable recovery retry"_ctv);
        return false;
      }
    }
    sealedPartialHandoff = true;
  }
  for (const auto& [id, count] : statefulReplicas) {
    const auto& deployment = approvedPlans.find(id)->second;
    if (retiringConflictingClient && retainRetiredConflictingClientForCoordinatorProof && id == retiredDeploymentID) continue;
    if (sealedPartialHandoff && id == partialHandoff->successorDeploymentID) continue;
    const uint32_t expected = deployment.stateful.allMasters ? count : 1;
    if (statefulClientMasters[id] != expected) {
      if (failure) failure->assign("retained stateful inventory has missing or conflicting client masters"_ctv);
      return false;
    }
  }
  if (retiringConflictingClient) {
    if (retiredDeploymentID == 0 || fullRecords != retirementProof->canonicalContainerCount ||
        (retainRetiredConflictingClientForCoordinatorProof ? retainedRecords != retirementProof->canonicalContainerCount : retainedRecords != retirementProof->staleCoordinatorCanonicalContainerCount) ||
        fullStatefulReplicas[retiredDeploymentID] != statefulReplicas[retiredDeploymentID] + (retainRetiredConflictingClientForCoordinatorProof ? 0 : 1) ||
        fullStatefulClientMasters[retiredDeploymentID] != 2 ||
        statefulClientMasters[retiredDeploymentID] != (retainRetiredConflictingClientForCoordinatorProof ? 2 : 1) ||
        statefulReplicas[retiredDeploymentID] == 0 ||
        fullRetiredCohort != 3 || retainedRetiredCohort != (retainRetiredConflictingClientForCoordinatorProof ? 3 : 2) ||
        fullRetiredCohortClients != 2 || retainedRetiredCohortClients != (retainRetiredConflictingClientForCoordinatorProof ? 2 : 1) ||
        retiredCohortMachines.size() != 3)
    {
      if (failure) failure->assign("sealed conflicting-client retirement does not reduce exactly one duplicate client master"_ctv);
      return false;
    }
  }
  if (coldCanonicalRuntimeStates.empty() == false)
  {
    // The explicit cold source is a complete authority only for its named
    // empty machine. Drop any old records for that machine before inserting
    // the selected set; otherwise an unobserved stateless scheduled record
    // would survive state upload and be replayed as a phantom launch.
    auto& runtimeStates = snapshot.masterAuthority.containerRuntimeStates;
    runtimeStates.erase(std::remove_if(runtimeStates.begin(), runtimeStates.end(),
        [emptyRetainedInventoryMachineUUID](const BrainReplicatedContainerRuntimeState& state) {
          return state.machineUUID == emptyRetainedInventoryMachineUUID;
        }), runtimeStates.end());
    for (const BrainReplicatedContainerRuntimeState& cold : coldStatesToPersist)
    {
      runtimeStates.push_back(cold);
    }
  }
  if (sealedPartialHandoff)
  {
    const uint64_t activeID = partialHandoff->activeDeploymentID;
    const uint64_t successorID = partialHandoff->successorDeploymentID;
    Vector<ObservedStatefulBootstrap> lineage = {};
    for (const ObservedStatefulBootstrap& observed : observedStatefulBootstraps)
      if (observed.deploymentID == activeID || observed.deploymentID == successorID)
      {
        const ContainerPlan& plan = observed.bootstrap.plan;
        if (plan.nShardGroups != 1 || plan.shardGroup != 0 ||
            plan.lifetime != ApplicationLifetime::base)
        {
          if (failure) failure->assign("sealed partial materialized handoff observed lineage is not one base shard"_ctv);
          return false;
        }
        lineage.push_back(observed);
      }
    if (lineage.size() != 3)
    {
      if (failure) failure->assign("sealed partial materialized handoff has incomplete observed lineage"_ctv);
      return false;
    }
    auto observedFor = [&](uint128_t uuid) -> const ObservedStatefulBootstrap * {
      for (const ObservedStatefulBootstrap& observed : lineage)
        if (observed.bootstrap.plan.uuid == uuid) return &observed;
      return nullptr;
    };
    // The sealed parameters are the authority for a partially completed
    // handoff.  A stopped Brain may retain an older scheduler projection
    // (notably a zero shard-count) for the same process, so it cannot be
    // compared as a complete bootstrap.  Bind the durable record only to its
    // immutable identity and declared network/configuration before replacing
    // it with the reconstructed scheduled bootstrap below.
    auto persistedIdentityMatchesObserved = [](const BrainReplicatedContainerRuntimeState& persisted,
                                                const ObservedStatefulBootstrap& observed) {
      if (persisted.machineUUID != observed.machineUUID ||
          persisted.plan.uuid != observed.bootstrap.plan.uuid ||
          persisted.plan.config.deploymentID() != observed.deploymentID ||
          persisted.plan.isStateful == false ||
          persisted.plan.statefulMeshRoles.client != observed.bootstrap.plan.statefulMeshRoles.client)
        return false;
      String persistedConfig = {}, observedConfig = {};
      ApplicationConfig left = persisted.plan.config, right = observed.bootstrap.plan.config;
      BitseryEngine::serialize(persistedConfig, left);
      BitseryEngine::serialize(observedConfig, right);
      if (persistedConfig != observedConfig) return false;
      String persistedAddresses = {}, observedAddresses = {};
      auto leftAddresses = persisted.plan.addresses, rightAddresses = observed.bootstrap.plan.addresses;
      BitseryEngine::serialize(persistedAddresses, leftAddresses);
      BitseryEngine::serialize(observedAddresses, rightAddresses);
      return persistedAddresses == observedAddresses;
    };
    auto& runtimeStates = snapshot.masterAuthority.containerRuntimeStates;
    for (const BrainReplicatedContainerRuntimeState& state : runtimeStates)
    {
      const uint64_t deploymentID = state.plan.config.deploymentID();
      if (deploymentID != activeID && deploymentID != successorID) continue;
      const ObservedStatefulBootstrap *observed = observedFor(state.plan.uuid);
      if (observed == nullptr)
      {
        if (state.plan.state != ContainerState::planned)
        {
          if (failure) failure->assign("sealed partial materialized handoff has an unobserved materialized runtime record"_ctv);
          return false;
        }
        continue;
      }
      if (persistedIdentityMatchesObserved(state, *observed) == false)
      {
        if (failure) failure->assign("sealed partial materialized handoff runtime record differs from observed authority"_ctv);
        return false;
      }
    }
    runtimeStates.erase(std::remove_if(runtimeStates.begin(), runtimeStates.end(),
        [activeID, successorID](const BrainReplicatedContainerRuntimeState& state) {
          const uint64_t deploymentID = state.plan.config.deploymentID();
          return deploymentID == activeID || deploymentID == successorID;
        }), runtimeStates.end());
    for (const ObservedStatefulBootstrap& observed : lineage)
    {
      BrainReplicatedContainerRuntimeState canonical = {};
      canonical.machineUUID = observed.machineUUID;
      canonical.plan = observed.bootstrap.plan;
      canonical.plan.state = ContainerState::scheduled;
      canonical.plan.runtimeReady = false;
      canonical.runtimeLogicalCores = uint16_t(applicationSharedCPUCoreHint(canonical.plan.config));
      canonical.runtimeMemoryMB = canonical.plan.config.totalMemoryMB();
      canonical.runtimeStorageMB = canonical.plan.config.totalStorageMB();
      runtimeStates.push_back(std::move(canonical));
    }
    if (partialHandoffAlreadyDurable == false)
      runtime.materializedStatefulRecoveryOperations.push_back(*partialHandoff);
  }
  std::sort(snapshot.masterAuthority.containerRuntimeStates.begin(),
            snapshot.masterAuthority.containerRuntimeStates.end(),
            [](const BrainReplicatedContainerRuntimeState& lhs,
               const BrainReplicatedContainerRuntimeState& rhs) {
              return lhs.plan.uuid < rhs.plan.uuid;
            });
  std::sort(witnesses.begin(), witnesses.end(), [](const auto& lhs, const auto& rhs) {
    return lhs.machineUUID < rhs.machineUUID;
  });
  runtime.generation += 1;
  runtime.updateSelf = {};
  runtime.updateSelf.workerExpectedBundleSHA256 = expectedBundleSHA256;
  runtime.updateSelf.machineRecoveryWitnesses = std::move(witnesses);
  return true;
}


// A superseded coordinator may have failed locally before it issued any
// work. This narrow schema-four proof accepts only its sealed older witness;
// it cannot admit a handoff, a running worker, or an unknown failure.
static inline bool mothershipRetainedRecoveryCanReplaceMixedFailedCoordinator(
    const ProdigyPersistentBrainSnapshot& snapshot, const String& interruptedBundleSHA256,
    const MothershipRetainedRecoveryMixedProof& proof,
    const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& currentWitnesses)
{
  if (!proof.validFor(snapshot) || !prodigyIsSHA256HexDigest(interruptedBundleSHA256)) return false;
  const auto& update=snapshot.masterAuthority.runtimeState.updateSelf;
  if (update.state != 0 || update.expectedEchos != 0 || update.bundleEchos != 0 ||
      update.relinquishEchos != 0 || update.plannedMasterPeerKey != 0 ||
      update.pendingDesignatedMasterPeerKey != 0 || update.useStagedBundleOnly ||
      !update.bundleBlob.empty() || update.workerExpectedBundleSHA256 != interruptedBundleSHA256 ||
      update.workerFailure != "local post-exec bundle digest mismatch"_ctv ||
      !update.bundleEchoPeerKeys.empty() || !update.relinquishEchoPeerKeys.empty() ||
      !update.followerBootNsByPeerKey.empty() || !update.followerRebootedPeerKeys.empty() ||
      !update.workerMachineUUIDs.empty() || !update.workerStagedMachineUUIDs.empty() ||
      !update.workerTransitionIssuedMachineUUIDs.empty() || !update.workerRebootedMachineUUIDs.empty() ||
      !update.workerStateUploadedMachineUUIDs.empty() || update.localMachineUUID != 0 ||
      update.localBundleRegistered || !update.localContainerBootstraps.empty() ||
      update.machineRecoveryWitnesses.size()!=snapshot.topology.machines.size()) return false;
  if (mothershipRetainedRecoveryWitnessContainerCount(currentWitnesses)!=proof.canonicalContainerCount) return false;
  struct BoundBootstrap { uint128_t machineUUID=0; NeuronContainerBootstrap bootstrap; };
  std::map<uint128_t,BoundBootstrap> current;
  for (const auto& witness:currentWitnesses) for (const auto& bytes:witness.containerBootstraps) {
    NeuronContainerBootstrap bootstrap={}; if(!BitseryEngine::deserializeSafe(bytes,bootstrap) ||
        !current.emplace(bootstrap.plan.uuid,BoundBootstrap{witness.machineUUID,std::move(bootstrap)}).second) return false;
  }
  if (!current.contains(proof.staleExcludedContainerUUID)) return false;
  uint32_t containers=0; bytell_hash_set<uint128_t> machines, seen;
  for (const auto& witness:update.machineRecoveryWitnesses) {
    if (witness.machineUUID==0 || witness.bundleRegistered || !machines.insert(witness.machineUUID).second) return false;
    bool known=false; for (const auto& machine:snapshot.topology.machines) known |= machine.uuid==witness.machineUUID;
    if (!known) return false;
    for (const auto& bytes:witness.containerBootstraps) {
      NeuronContainerBootstrap observed={}; if(!BitseryEngine::deserializeSafe(bytes,observed) ||
          observed.plan.uuid==proof.staleExcludedContainerUUID || !seen.insert(observed.plan.uuid).second) return false;
      const auto found=current.find(observed.plan.uuid); if(found==current.end()) return false;
      if (found->second.machineUUID!=witness.machineUUID) return false;
      if(!mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(observed,found->second.bootstrap)) return false;
      ++containers;
    }
  }
  return containers==proof.staleCoordinatorCanonicalContainerCount;
}

// The designated schema-four seed can be a clean v13 coordinator with its
// sealed, unregistered witnesses but before it requested echoes. Its nonempty
// expected digest is retained state, so admit it only with every progress,
// local, and payload field still empty.
static inline bool mothershipRetainedRecoveryCanReplaceMixedDormantCoordinator(
    const ProdigyPersistentBrainSnapshot& snapshot, const String& interruptedBundleSHA256,
    const MothershipRetainedRecoveryMixedProof& proof,
    const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& currentWitnesses)
{
  if (!proof.validFor(snapshot) || !prodigyIsSHA256HexDigest(interruptedBundleSHA256)) return false;
  const auto& update=snapshot.masterAuthority.runtimeState.updateSelf;
  return update.state==0 && update.expectedEchos==0 && update.bundleEchos==0 && update.relinquishEchos==0 &&
      update.plannedMasterPeerKey==0 && update.pendingDesignatedMasterPeerKey==0 && !update.useStagedBundleOnly &&
      update.bundleBlob.empty() && update.workerExpectedBundleSHA256==interruptedBundleSHA256 && update.workerFailure.empty() &&
      update.bundleEchoPeerKeys.empty() && update.relinquishEchoPeerKeys.empty() && update.followerBootNsByPeerKey.empty() &&
      update.followerRebootedPeerKeys.empty() && update.workerMachineUUIDs.empty() && update.workerStagedMachineUUIDs.empty() &&
      update.workerTransitionIssuedMachineUUIDs.empty() && update.workerRebootedMachineUUIDs.empty() &&
      update.workerStateUploadedMachineUUIDs.empty() && update.localMachineUUID==0 && !update.localBundleRegistered &&
      update.localContainerBootstraps.empty() &&
      mothershipRetainedRecoveryWitnessContainerCount(currentWitnesses)==proof.canonicalContainerCount &&
      mothershipRetainedRecoveryMixedWitnessesMatch(update.machineRecoveryWitnesses,currentWitnesses,{},false);
}

// The command owner invokes this only for its explicitly declared old-runtime
// coordinator after every private paired copy has been fenced.  Build the
// expected interrupted witness from the same sealed request before admitting a
// phase-two handoff, then discard that proven coordinator rather than carrying
// a partially executed update into the replacement generation.
static inline bool mothershipPrepareRetainedRecoveryMixedHandoffSnapshot(
    ProdigyPersistentBrainSnapshot& snapshot,
    const bytell_hash_map<uint64_t, DeploymentPlan>& approvedPlans,
    const Vector<MothershipRetainedRecoveryMachineInput>& machines,
    const String& expectedBundleSHA256, const String& previousBundleSHA256,
    const String& interruptedBundleSHA256, const Vector<uint128_t>& successorMachineUUIDs,
    String *failure = nullptr, const MothershipRetainedRecoveryMixedProof *proof = nullptr)
{
  if (failure) failure->clear();
  ProdigyPersistentBrainSnapshot witnessSnapshot = snapshot;
  witnessSnapshot.masterAuthority.runtimeState.updateSelf = {};
  String why;
  if (!mothershipPrepareRetainedRecoverySnapshot(witnessSnapshot, approvedPlans, machines,
                                                 interruptedBundleSHA256, &why))
  {
    if (failure) failure->assign(why);
    return false;
  }
  for (auto& witness : witnessSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)
  {
    witness.bundleRegistered = false;
    for (uint128_t successor : successorMachineUUIDs)
      witness.bundleRegistered |= witness.machineUUID == successor;
  }
  if (
      !mothershipRetainedRecoveryCanReplaceMixedHandoff(
          snapshot, interruptedBundleSHA256,
          witnessSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses,
          successorMachineUUIDs,proof))
  {
    if (failure) failure->assign("retained recovery refuses an unproven mixed handoff"_ctv);
    return false;
  }
  snapshot.masterAuthority.runtimeState.updateSelf = {};
  return mothershipPrepareRetainedRecoverySnapshot(snapshot, approvedPlans, machines,
                                                   expectedBundleSHA256, failure,
                                                   previousBundleSHA256, interruptedBundleSHA256);
}

static inline bool mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
    ProdigyPersistentBrainSnapshot& snapshot,
    const bytell_hash_map<uint64_t, DeploymentPlan>& approvedPlans,
    const Vector<MothershipRetainedRecoveryMachineInput>& machines,
    const String& expectedBundleSHA256, const String& previousBundleSHA256,
    const String& interruptedBundleSHA256, const Vector<uint128_t>& successorMachineUUIDs,
    String *failure = nullptr, const MothershipRetainedRecoveryMixedProof *proof = nullptr)
{
  if (failure) failure->clear();
  auto witnessSnapshot=snapshot;
  witnessSnapshot.masterAuthority.runtimeState.updateSelf={};
  String why;
  if (!mothershipPrepareRetainedRecoverySnapshot(witnessSnapshot,approvedPlans,machines,
                                                  interruptedBundleSHA256,&why))
  {
    if (failure) failure->assign(why);
    return false;
  }
  if (!mothershipRetainedRecoveryCanReplaceMixedInterruptedUpdate(
          snapshot,expectedBundleSHA256,previousBundleSHA256,interruptedBundleSHA256,
          witnessSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses,
          successorMachineUUIDs,proof))
  {
    if (failure) failure->assign("retained recovery refuses an unproven mixed interrupted update"_ctv);
    return false;
  }
  snapshot.masterAuthority.runtimeState.updateSelf={};
  return mothershipPrepareRetainedRecoverySnapshot(snapshot,approvedPlans,machines,
                                                   expectedBundleSHA256,failure,
                                                   previousBundleSHA256,interruptedBundleSHA256);
}

// Schema four has three explicitly sealed coordinator forms: the 24-container
// v13 echo collector, the dormant v13 seed with unregistered witnesses, and
// the obsolete inert 23-container v12 witness. All normalize into the same
// new recovery envelope before any state write.
static inline bool mothershipPrepareRetainedRecoverySchema4Snapshot(
    ProdigyPersistentBrainSnapshot& snapshot,
    const bytell_hash_map<uint64_t, DeploymentPlan>& approvedPlans,
    const Vector<MothershipRetainedRecoveryMachineInput>& machines,
    const String& expectedBundleSHA256, const String& previousBundleSHA256,
    const String& interruptedBundleSHA256, const Vector<uint128_t>& successorMachineUUIDs,
    const MothershipRetainedRecoveryMixedProof& proof, String *failure = nullptr)
{
  if (mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
          snapshot,approvedPlans,machines,expectedBundleSHA256,previousBundleSHA256,
          interruptedBundleSHA256,successorMachineUUIDs,failure,&proof)) return true;
  auto current=snapshot; current.masterAuthority.runtimeState.updateSelf={}; String why;
  if (!mothershipPrepareRetainedRecoverySnapshot(current,approvedPlans,machines,expectedBundleSHA256,&why)) {
    if (failure) failure->assign(why); return false;
  }
  auto interrupted=current; interrupted.masterAuthority.runtimeState.updateSelf={};
  if (!mothershipPrepareRetainedRecoverySnapshot(interrupted,approvedPlans,machines,interruptedBundleSHA256,&why)) {
    if (failure) failure->assign(why); return false;
  }
  if (mothershipRetainedRecoveryCanReplaceMixedDormantCoordinator(
          snapshot,interruptedBundleSHA256,proof,interrupted.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)) {
    snapshot=current; return true;
  }
  if (
      !mothershipRetainedRecoveryCanReplaceMixedFailedCoordinator(
          snapshot,previousBundleSHA256,proof,current.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)) {
    if (failure) failure->assign("retained recovery refuses an unproven schema-four coordinator"_ctv);
    return false;
  }
  snapshot.masterAuthority.runtimeState.updateSelf={};
  return mothershipPrepareRetainedRecoverySnapshot(snapshot,approvedPlans,machines,expectedBundleSHA256,
                                                   failure,previousBundleSHA256,interruptedBundleSHA256);
}

// Schema-four conflicting-client retirement is a one-record projection of an
// otherwise immutable 24-record proof.  First rebuild the complete witness
// with the only permitted duplicate role, then apply the existing three
// coordinator predicates to that full witness.  Only after that succeeds do
// we produce the ordinary strict 23-record envelope.
static inline bool mothershipPrepareRetiredConflictingClientSchema4Snapshot(
    ProdigyPersistentBrainSnapshot& snapshot,
    const bytell_hash_map<uint64_t, DeploymentPlan>& approvedPlans,
    const Vector<MothershipRetainedRecoveryMachineInput>& fullMachines,
    const String& expectedBundleSHA256, const String& previousBundleSHA256,
    const String& interruptedBundleSHA256, const Vector<uint128_t>& successorMachineUUIDs,
    const MothershipRetainedRecoveryMixedProof& proof, uint128_t retiredConflictingClientUUID,
    String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!proof.validFor(snapshot) || retiredConflictingClientUUID == 0 ||
      proof.staleExcludedContainerUUID != retiredConflictingClientUUID) {
    if (failure) failure->assign("retired conflicting-client proof differs from frozen coordinator"_ctv);
    return false;
  }
  auto fullCurrent=snapshot; fullCurrent.masterAuthority.runtimeState.updateSelf={}; String why;
  if (!mothershipPrepareRetainedRecoverySnapshot(fullCurrent,approvedPlans,fullMachines,expectedBundleSHA256,&why,
                                                  {},{},retiredConflictingClientUUID,&proof,true,false)) {
    if(failure)failure->assign(why); return false;
  }
  auto fullInterrupted=snapshot; fullInterrupted.masterAuthority.runtimeState.updateSelf={};
  if (!mothershipPrepareRetainedRecoverySnapshot(fullInterrupted,approvedPlans,fullMachines,interruptedBundleSHA256,&why,
                                                  {},{},retiredConflictingClientUUID,&proof,true,false)) {
    if(failure)failure->assign(why); return false;
  }
  const auto& currentWitnesses=fullCurrent.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  const auto& interruptedWitnesses=fullInterrupted.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  const bool admitted=
      mothershipRetainedRecoveryCanReplaceMixedInterruptedUpdate(snapshot,expectedBundleSHA256,previousBundleSHA256,
          interruptedBundleSHA256,interruptedWitnesses,successorMachineUUIDs,&proof) ||
      mothershipRetainedRecoveryCanReplaceMixedDormantCoordinator(snapshot,interruptedBundleSHA256,proof,interruptedWitnesses) ||
      mothershipRetainedRecoveryCanReplaceMixedFailedCoordinator(snapshot,previousBundleSHA256,proof,currentWitnesses);
  if (!admitted) { if(failure)failure->assign("retired conflicting-client proof has no admissible schema-four coordinator"_ctv); return false; }
  uint128_t retiredMachineUUID=0;
  for(const auto& machine:fullMachines) for(const auto& parameters:machine.parameters)
    if(parameters.uuid==retiredConflictingClientUUID) retiredMachineUUID=machine.machineUUID;
  if(retiredMachineUUID==0) { if(failure)failure->assign("retired conflicting-client target machine is absent"_ctv); return false; }
  const bool wasStale23=mothershipRetainedRecoveryWitnessContainerCount(
      snapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)==proof.staleCoordinatorCanonicalContainerCount;
  auto& runtimeContainers=snapshot.masterAuthority.containerRuntimeStates;
  const auto previousSize=runtimeContainers.size();
  runtimeContainers.erase(std::remove_if(runtimeContainers.begin(),runtimeContainers.end(),[&](const auto& state) {
    return state.plan.uuid==retiredConflictingClientUUID && state.machineUUID==retiredMachineUUID;
  }),runtimeContainers.end());
  if (runtimeContainers.size()+1 != previousSize && !(wasStale23 && runtimeContainers.size()==previousSize)) {
    if(failure)failure->assign("retired conflicting-client runtime identity is absent or duplicated"_ctv); return false;
  }
  snapshot.masterAuthority.runtimeState.updateSelf={};
  return mothershipPrepareRetainedRecoverySnapshot(snapshot,approvedPlans,fullMachines,expectedBundleSHA256,failure,
      previousBundleSHA256,interruptedBundleSHA256,retiredConflictingClientUUID,&proof,false,false);
}

// This is intentionally separate from the normal state-store constructor.
// Its caller supplies paths to private, stopped copies and must validate the
// paired v10 copies before their Mothership-owned atomic swap.
static inline bool mothershipPrepareRetainedRecoveryState(
    const String& privateStatePath,
    ProdigyPersistentBrainSnapshot& snapshot,
    const bytell_hash_map<uint64_t, DeploymentPlan>& approvedPlans,
    const Vector<MothershipRetainedRecoveryMachineInput>& machines,
    const String& expectedBundleSHA256,
    String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipPrepareRetainedRecoverySnapshot(snapshot, approvedPlans, machines, expectedBundleSHA256, failure)) return false;
  ProdigyPersistentStateStore store(privateStatePath);
  return store.saveBrainSnapshot(snapshot, failure);
}
