#pragma once

// Offline preparation for a deliberately retained fleet.  This owner only
// changes a private state/secrets copy; Mothership's command owner is solely
// responsible for fencing, atomic swaps, and activation.
#include <algorithm>
#include <limits>

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
  BitseryEngine::serialize(left, leftCopy);
  BitseryEngine::serialize(right, rightCopy);
  return left == right;
}

// `approvedPlans` is read from the sealed seed copy.  Existing plans are never
// overwritten; a missing plan is admitted only if its supplied deployment ID
// and exact serialized plan agree with every recovered bootstrap.
static inline bool mothershipPrepareRetainedRecoverySnapshot(
    ProdigyPersistentBrainSnapshot& snapshot,
    const bytell_hash_map<uint64_t, DeploymentPlan>& approvedPlans,
    const Vector<MothershipRetainedRecoveryMachineInput>& machines,
    const String& expectedBundleSHA256,
    String *failure = nullptr)
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
  if (runtime.generation == std::numeric_limits<uint64_t>::max() || runtime.updateSelf.active())
  {
    if (failure) failure->assign("retained recovery refuses an active or exhausted update coordinator"_ctv);
    return false;
  }

  Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness> witnesses = {};
  witnesses.reserve(machines.size());
  bytell_hash_set<uint128_t> seenMachines = {};
  bytell_hash_set<uint128_t> seenContainers = {};
  bytell_hash_set<uint32_t> seenFragments = {};
  bytell_hash_map<uint64_t,uint32_t> statefulReplicas, statefulClientMasters;
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
    const uint32_t expected = deployment.stateful.allMasters ? count : 1;
    if (statefulClientMasters[id] != expected) {
      if (failure) failure->assign("retained stateful inventory has missing or conflicting client masters"_ctv);
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
