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
        reconstructed.plan.createdAtMs=observed.plan.createdAtMs;
        if (!prodigyPersistentRetainedBootstrapEqual(observed,reconstructed)) return false;
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
    bool validateCoordinator = true)
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
  for (const MothershipRetainedRecoveryMachineInput& machine : machines)
  {
    if (machine.machineUUID == 0 || machine.machineFragment == 0 || machine.machineFragment > 0xffffff ||
        !seenFragments.insert(machine.machineFragment).second ||
        machine.parameters.empty() || machine.parameters.size() != machine.observedCreatedAtMs.size() ||
        seenMachines.insert(machine.machineUUID).second == false)
    {
      if (failure) failure->assign("invalid or duplicate retained recovery machine input"_ctv);
      return false;
    }
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
  for (const auto& [id, count] : statefulReplicas) {
    const auto& deployment = approvedPlans.find(id)->second;
    if (retiringConflictingClient && retainRetiredConflictingClientForCoordinatorProof && id == retiredDeploymentID) continue;
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
      auto expected=found->second.bootstrap; expected.plan.createdAtMs=observed.plan.createdAtMs;
      if(!prodigyPersistentRetainedBootstrapEqual(observed,expected)) return false;
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
