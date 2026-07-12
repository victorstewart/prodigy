#pragma once

#include <prodigy/mothership/mothership.provider.credentials.h>
#include <prodigy/mothership/mothership.provider.machine.destroy.h>
#include <prodigy/mothership/mothership.ring.runtime.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/iaas/runtime/runtime.h>

static inline bool mothershipRunGcpMachineDestroyJob(
    MothershipHostRingRuntime& runtime,
    const MothershipProviderCredential& credential,
    const ProdigyRuntimeEnvironmentConfig& sourceEnvironment,
    const Vector<String>& cloudIDs,
    String& failure,
    MultiCurlClient::TimePoint deadline)
{
  failure.clear();
  if (sourceEnvironment.kind != ProdigyEnvironmentKind::gcp || cloudIDs.empty())
  {
    failure.assign("gcp machine destroy job requires provider scope and cloud IDs"_ctv);
    return false;
  }

  ProdigyRuntimeEnvironmentConfig jobEnvironment;
  if (MothershipProviderCredentialRegistry::prepareGcpRingRuntimeEnvironment(
          credential,
          sourceEnvironment,
          jobEnvironment,
          &failure,
          deadline) == false)
  {
    return false;
  }

  bool providerCreated = false;
  bool destroyed = false;
  const bool ran = runtime.run([&](ProdigyProviderServices services, CoroutineStack *coro) -> void {
    services.operationDeadline = deadline;
    std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(jobEnvironment, services);
    providerCreated = provider != nullptr;
    if (providerCreated == false)
    {
      failure.assign("failed to construct GCP provider for machine destroy"_ctv);
      co_return;
    }
    provider->configureRuntimeEnvironment(jobEnvironment);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          mothershipDestroyProviderMachines(coro, *provider, cloudIDs, destroyed, &failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  });
  if (ran == false && failure.empty())
  {
    failure.assign("GCP machine destroy host Ring unavailable"_ctv);
  }
  return ran && providerCreated && destroyed && failure.empty();
}

static inline bool mothershipRunGcpClusterDestroyJob(
    MothershipHostRingRuntime& runtime,
    const MothershipProviderCredential& credential,
    const ProdigyRuntimeEnvironmentConfig& sourceEnvironment,
    const String& clusterUUID,
    uint32_t& destroyed,
    String& failure,
    MultiCurlClient::TimePoint deadline)
{
  String targetClusterUUID;
  targetClusterUUID.assign(clusterUUID);
  destroyed = 0;
  failure.clear();
  if (sourceEnvironment.kind != ProdigyEnvironmentKind::gcp || targetClusterUUID.empty())
  {
    failure.assign("gcp cluster destroy job requires provider scope and cluster UUID"_ctv);
    return false;
  }

  ProdigyRuntimeEnvironmentConfig jobEnvironment;
  if (MothershipProviderCredentialRegistry::prepareGcpRingRuntimeEnvironment(
          credential,
          sourceEnvironment,
          jobEnvironment,
          &failure,
          deadline) == false)
  {
    return false;
  }

  bool providerCreated = false;
  bool completed = false;
  const bool ran = runtime.run([&](ProdigyProviderServices services, CoroutineStack *coro) -> void {
    services.operationDeadline = deadline;
    std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(jobEnvironment, services);
    providerCreated = provider != nullptr;
    if (providerCreated == false)
    {
      failure.assign("failed to construct GCP provider for cluster destroy"_ctv);
      co_return;
    }
    provider->configureRuntimeEnvironment(jobEnvironment);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          mothershipDestroyProviderClusterMachines(coro,
                                                   *provider,
                                                   targetClusterUUID,
                                                   destroyed,
                                                   completed,
                                                   &failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  });
  if (ran == false && failure.empty())
  {
    failure.assign("GCP cluster destroy host Ring unavailable"_ctv);
  }
  return ran && providerCreated && completed && failure.empty();
}

static inline bool mothershipRunGcpMachineTagJob(
    MothershipHostRingRuntime& runtime,
    const MothershipProviderCredential& credential,
    const ProdigyRuntimeEnvironmentConfig& sourceEnvironment,
    uint128_t clusterUUID,
    const Vector<ClusterMachine>& machines,
    String& failure,
    MultiCurlClient::TimePoint deadline)
{
  failure.clear();
  if (sourceEnvironment.kind != ProdigyEnvironmentKind::gcp || clusterUUID == 0)
  {
    failure.assign("gcp machine tag job requires provider scope and cluster UUID"_ctv);
    return false;
  }

  ProdigyRuntimeEnvironmentConfig jobEnvironment;
  if (MothershipProviderCredentialRegistry::prepareGcpRingRuntimeEnvironment(
          credential,
          sourceEnvironment,
          jobEnvironment,
          &failure,
          deadline) == false)
  {
    return false;
  }

  bool providerCreated = false;
  bool tagged = false;
  const bool ran = runtime.run([&](ProdigyProviderServices services, CoroutineStack *coro) -> void {
    services.operationDeadline = deadline;
    std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(jobEnvironment, services);
    providerCreated = provider != nullptr;
    if (providerCreated == false)
    {
      failure.assign("failed to construct GCP provider for machine tagging"_ctv);
      co_return;
    }
    provider->configureRuntimeEnvironment(jobEnvironment);
    tagged = true;
    for (const ClusterMachine& machine : machines)
    {
      tagged = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            prodigyEnsureCloudMachineTagged(coro,
                                            *provider,
                                            clusterUUID,
                                            machine,
                                            tagged,
                                            &failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (tagged == false)
      {
        co_return;
      }
    }
  });
  if (ran == false && failure.empty())
  {
    failure.assign("GCP machine tag host Ring unavailable"_ctv);
  }
  return ran && providerCreated && tagged && failure.empty();
}
