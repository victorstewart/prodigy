#pragma once

#include <prodigy/iaas/iaas.h>
#include <prodigy/brain/machine.h>

static inline void mothershipHardRebootProviderMachine(CoroutineStack *coro,
                                                        BrainIaaS& iaas,
                                                        const String& cloudID,
                                                        bool& rebooted,
                                                        String *failure = nullptr)
{
  rebooted = false;
  if (failure)
  {
    failure->clear();
  }

  if (cloudID.size() == 0)
  {
    if (failure)
    {
      failure->assign("cloudID required"_ctv);
    }
    co_return;
  }

  String operationFailure;
  if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
        iaas.hardRebootMachine(coro, cloudID, operationFailure);
      }))
  {
    co_await coro->suspendAtIndex(suspendIndex);
  }
  if (operationFailure.empty() == false)
  {
    if (failure)
    {
      *failure = std::move(operationFailure);
    }
    co_return;
  }

  rebooted = true;
}

// Precondition: the selected provider's hard reboot implementation completes inline.
static inline bool mothershipHardRebootProviderMachineInline(BrainIaaS& iaas,
                                                              const String& cloudID,
                                                              String *failure = nullptr)
{
  CoroutineStack coro;
  bool rebooted = false;
  mothershipHardRebootProviderMachine(&coro, iaas, cloudID, rebooted, failure);
  coro.co_consume();
  return rebooted;
}

static inline bool mothershipResolveCreatedCloudMachineID(const ClusterTopology& topology,
                                                           uint128_t machineUUID,
                                                           String& cloudID,
                                                           String *failure = nullptr)
{
  cloudID.clear();
  if (failure)
  {
    failure->clear();
  }
  if (machineUUID == 0)
  {
    if (failure) failure->assign("machineUUID required"_ctv);
    return false;
  }

  const ClusterMachine *matched = nullptr;
  for (const ClusterMachine& machine : topology.machines)
  {
    if (machine.uuid != machineUUID)
    {
      continue;
    }
    if (matched != nullptr)
    {
      if (failure) failure->assign("machineUUID is ambiguous in cluster topology"_ctv);
      return false;
    }
    matched = &machine;
  }
  if (matched == nullptr)
  {
    if (failure) failure->assign("machineUUID is not present in cluster topology"_ctv);
    return false;
  }
  if (matched->source != ClusterMachineSource::created ||
      matched->backing != ClusterMachineBacking::cloud ||
      matched->cloud.cloudID.empty())
  {
    if (failure) failure->assign("hard reboot requires a Mothership-created cloud machine"_ctv);
    return false;
  }

  cloudID = matched->cloud.cloudID;
  return true;
}

// A topology refresh may report runtime state, but it may not rewrite the
// Mothership-owned machine roster or any field that can later authorize a
// provider operation. Validate the entire projection before persisting it so
// agreement for one target cannot poison authorization for another target.
static inline bool mothershipValidateObservedMachineAuthorizationProjection(
    const ClusterTopology& durableTopology,
    const ClusterTopology& observedTopology,
    String *failure = nullptr)
{
  if (durableTopology.machines.size() != observedTopology.machines.size())
  {
    if (failure) failure->assign("durable and observed topology machine rosters disagree"_ctv);
    return false;
  }

  for (uint64_t durableIndex = 0; durableIndex < durableTopology.machines.size(); ++durableIndex)
  {
    const ClusterMachine& durable = durableTopology.machines[durableIndex];
    if (durable.uuid == 0)
    {
      if (failure) failure->assign("durable topology contains an invalid machine identity"_ctv);
      return false;
    }
    for (uint64_t priorIndex = 0; priorIndex < durableIndex; ++priorIndex)
    {
      if (durableTopology.machines[priorIndex].uuid == durable.uuid)
      {
        if (failure) failure->assign("durable topology contains an ambiguous machine identity"_ctv);
        return false;
      }
    }

    const ClusterMachine *matched = nullptr;
    for (const ClusterMachine& observed : observedTopology.machines)
    {
      if (observed.uuid != durable.uuid) continue;
      if (matched != nullptr)
      {
        if (failure) failure->assign("observed topology contains an ambiguous machine identity"_ctv);
        return false;
      }
      matched = &observed;
    }
    if (matched == nullptr)
    {
      if (failure) failure->assign("durable and observed topology machine rosters disagree"_ctv);
      return false;
    }
    if (matched->source != durable.source || matched->backing != durable.backing ||
        !matched->cloud.cloudID.equals(durable.cloud.cloudID))
    {
      if (failure) failure->assign("durable and observed topology machine authorization disagree"_ctv);
      return false;
    }
  }

  if (failure) failure->clear();
  return true;
}

// Provider faults are authorized by Mothership's last durable topology, never
// by a cloud ID supplied by a caller or learned only from the target cluster.
// A fresh cluster observation must independently agree before that durable ID
// can be used.
static inline bool mothershipResolveVerifiedCreatedCloudMachineID(
    const ClusterTopology& durableTopology,
    const ClusterTopology& observedTopology,
    uint128_t machineUUID,
    String& cloudID,
    String *failure = nullptr)
{
  cloudID.clear();
  String durableCloudID = {}, observedCloudID = {}, localFailure = {};
  if (!mothershipResolveCreatedCloudMachineID(
          durableTopology, machineUUID, durableCloudID, &localFailure))
  {
    if (failure)
    {
      failure->assign("durable Mothership topology does not authorize hard reboot: "_ctv);
      failure->append(localFailure);
    }
    return false;
  }
  if (!mothershipResolveCreatedCloudMachineID(
          observedTopology, machineUUID, observedCloudID, &localFailure))
  {
    if (failure)
    {
      failure->assign("observed cluster topology does not confirm hard reboot target: "_ctv);
      failure->append(localFailure);
    }
    return false;
  }
  if (!durableCloudID.equals(observedCloudID))
  {
    if (failure) failure->assign("durable and observed hard reboot cloud identities disagree"_ctv);
    return false;
  }
  if (!mothershipValidateObservedMachineAuthorizationProjection(
          durableTopology, observedTopology, failure))
  {
    return false;
  }
  cloudID = std::move(durableCloudID);
  if (failure) failure->clear();
  return true;
}

static inline void mothershipDestroyProviderMachines(CoroutineStack *coro,
                                                     BrainIaaS& iaas,
                                                     const Vector<String>& cloudIDs,
                                                     bool& destroyed,
                                                     String *failure = nullptr)
{
  destroyed = false;
  if (failure)
  {
    failure->clear();
  }

  for (const String& cloudID : cloudIDs)
  {
    if (cloudID.size() == 0)
    {
      if (failure)
      {
        failure->assign("cloudID required"_ctv);
      }
      co_return;
    }

    String operationFailure;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          iaas.destroyMachine(coro, cloudID, operationFailure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (operationFailure.empty() == false)
    {
      if (failure)
      {
        *failure = std::move(operationFailure);
      }
      co_return;
    }
  }

  destroyed = true;
}

// Precondition: the selected provider's machine lifecycle implementation completes inline.
static inline bool mothershipDestroyProviderMachinesInline(BrainIaaS& iaas,
                                                           const Vector<String>& cloudIDs,
                                                           String *failure = nullptr)
{
  CoroutineStack coro;
  bool destroyed = false;
  mothershipDestroyProviderMachines(&coro, iaas, cloudIDs, destroyed, failure);
  coro.co_consume();
  return destroyed;
}

static inline void mothershipDestroyProviderClusterMachines(CoroutineStack *coro,
                                                            BrainIaaS& iaas,
                                                            const String& clusterUUID,
                                                            uint32_t& destroyed,
                                                            bool& completed,
                                                            String *failure = nullptr)
{
  completed = false;
  if (failure)
  {
    failure->clear();
  }
  destroyed = 0;

  if (clusterUUID.size() == 0)
  {
    if (failure)
    {
      failure->assign("clusterUUID required"_ctv);
    }
    co_return;
  }

  String error = {};
  if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
        iaas.destroyClusterMachines(coro, clusterUUID, destroyed, error);
      }))
  {
    co_await coro->suspendAtIndex(suspendIndex);
  }
  if (error.size() > 0)
  {
    if (failure)
    {
      *failure = error;
    }
    co_return;
  }

  completed = true;
}

// Precondition: the selected provider's cluster lifecycle implementation completes inline.
static inline bool mothershipDestroyProviderClusterMachinesInline(BrainIaaS& iaas,
                                                                  const String& clusterUUID,
                                                                  uint32_t& destroyed,
                                                                  String *failure = nullptr)
{
  CoroutineStack coro;
  bool completed = false;
  mothershipDestroyProviderClusterMachines(&coro, iaas, clusterUUID, destroyed, completed, failure);
  coro.co_consume();
  return completed;
}
