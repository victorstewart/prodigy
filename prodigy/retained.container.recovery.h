#pragma once

// Rebuilds a bootstrap for a proven retained base process.  This is deliberately
// non-healthy: the replacement Neuron must reconnect and receive normal runtime
// readiness and health signals before the Brain counts it as serving. Pairings
// are only the launch snapshot; normal mesh re-attachment reconciles them.

#include <cstring>
#include <ebpf/common/structs.h>
#include <prodigy/wire.h>

#include <prodigy/container.services.h>

// The compact startup wire format omits CPU mode and requested millis. Its
// default values are not observations; the sealed deployment remains their owner.
static inline void prodigyRestoreRetainedStartupCPUFields(const String& raw,
    const DeploymentPlan& deployment, ContainerParameters& parameters)
{
  if (ProdigyWire::containerParametersUsesWireHeader(raw)) {
    parameters.cpuMode = deployment.config.cpuMode;
    parameters.requestedCPUMillis = applicationRequestedCPUMillis(deployment.config);
  }
}

static inline bool prodigyRetainedRecoveryFail(String *failure, const char *reason)
{
  if (failure)
  {
    failure->assign(reason);
  }
  return false;
}

// The caller establishes canonical base membership and binds parameters to the
// selected machine before calling this pure reconstruction. observedCreatedAtMs
// is the recovery observation time; it is deliberately not the original start.
static inline bool prodigyBuildRetainedContainerBootstrap(
    const DeploymentPlan& deployment,
    const ContainerParameters& parameters,
    uint32_t expectedMachineFragment,
    uint8_t expectedDatacenterFragment,
    int64_t observedCreatedAtMs,
    NeuronContainerBootstrap& bootstrap,
    String *failure)
{
  if (failure) failure->clear();
  bootstrap = {};
  if (expectedDatacenterFragment == 0 || expectedMachineFragment == 0 || observedCreatedAtMs <= 0 ||
      parameters.uuid == 0 || parameters.deploymentID == 0 || parameters.deploymentID != deployment.config.deploymentID())
  {
    return prodigyRetainedRecoveryFail(failure, "retained recovery identity or deployment evidence is invalid");
  }
  if ((deployment.isStateful && deployment.config.type != ApplicationType::stateful) ||
      (deployment.isStateful == false && deployment.config.type != ApplicationType::stateless) ||
      deployment.useHostNetworkNamespace ||
      deployment.config.minGPUs != 0 || deployment.config.gpuMemoryGB != 0)
  {
    return prodigyRetainedRecoveryFail(failure, "retained recovery supports only ordinary non-task non-GPU non-host-network containers");
  }
  if (parameters.private6.network.is6 == false || parameters.private6.cidr != 128 ||
      std::memcmp(parameters.private6.network.v6, container_network_subnet6.value, 11) != 0 ||
      parameters.private6.network.v6[11] != expectedDatacenterFragment ||
      parameters.private6.network.v6[12] != uint8_t((expectedMachineFragment >> 16) & 0xffu) ||
      parameters.private6.network.v6[13] != uint8_t((expectedMachineFragment >> 8) & 0xffu) ||
      parameters.private6.network.v6[14] != uint8_t(expectedMachineFragment & 0xffu) ||
      parameters.private6.network.v6[15] == 0)
  {
    return prodigyRetainedRecoveryFail(failure, "retained recovery IPv6 does not prove the selected machine and container fragment");
  }
  const ApplicationConfig config = deployment.config;
  if (parameters.memoryMB != config.memoryMB || parameters.storageMB != config.storageMB ||
      parameters.nLogicalCores != uint16_t(applicationSharedCPUCoreHint(config)) ||
      parameters.cpuMode != config.cpuMode || parameters.requestedCPUMillis != applicationRequestedCPUMillis(config))
  {
    return prodigyRetainedRecoveryFail(failure, "retained recovery resource snapshot differs from authoritative deployment");
  }
  const StatefulMeshRoles expectedRoles = deployment.isStateful
      ? StatefulMeshRoles::forShardGroup(deployment.stateful, deployment.config.applicationID, 0)
      : StatefulMeshRoles{};
  if (deployment.isStateful &&
      (parameters.statefulTopology.configured() == false ||
       parameters.statefulTopology.operationID != 0 ||
       parameters.statefulTopology.bridgeMode != StatefulTopologyBridgeMode::none ||
       parameters.statefulTopology.shardGroup != 0 ||
       parameters.statefulTopology.topologyEpoch == 0 ||
       parameters.statefulTopology.sourceEpoch != parameters.statefulTopology.topologyEpoch ||
       parameters.statefulTopology.targetEpoch != parameters.statefulTopology.topologyEpoch ||
       parameters.statefulTopology.workerCount != prodigyStatefulWorkerCountForLogicalCores(config.nLogicalCores) ||
       parameters.statefulTopology.servingMode != StatefulTopologyServingMode::serve ||
       expectedRoles.client == 0 || expectedRoles.sibling == 0 || expectedRoles.seeding == 0))
  {
    return prodigyRetainedRecoveryFail(failure, "retained recovery permits only one-shard non-transitioning stateful deployment");
  }
  ProdigyContainerServiceDefinitionContext serviceContext = {};
  serviceContext.isStateful = deployment.isStateful;
  serviceContext.roles = expectedRoles;
  serviceContext.topology = parameters.statefulTopology;
  serviceContext.advertiseClient = deployment.isStateful && parameters.advertisesOnPorts.contains(expectedRoles.client);
  if (deployment.isStateful && deployment.stateful.allMasters && !serviceContext.advertiseClient)
    return prodigyRetainedRecoveryFail(failure, "retained all-master replica is missing its client service");
  serviceContext.seedingAlways = deployment.stateful.seedingAlways;
  serviceContext.dataStrategy = parameters.subscriptionPairings.map.contains(expectedRoles.seeding) ? DataStrategy::seeding : DataStrategy::genesis;
  serviceContext.nShardGroups = deployment.isStateful ? 1 : 0;
  ProdigyContainerServiceDefinitions definitions = {};
  if (prodigyBuildContainerServiceDefinitions(deployment, serviceContext, definitions) == false)
  {
    return prodigyRetainedRecoveryFail(failure, "retained recovery service definition is ambiguous");
  }

  // ContainerView::generatePlan retains a stateful role only when the final
  // plan advertises or subscribes to it. In particular neverShard omits the
  // cousin and sharding services from launch parameters.
  StatefulMeshRoles expectedRetainedRoles = expectedRoles;
  auto pruneRole = [&](uint64_t& service) -> void {
    if (service == 0)
    {
      return;
    }
    for (const Advertisement& advertisement : definitions.advertisements)
    {
      if (advertisement.service == service)
      {
        return;
      }
    }
    for (const Subscription& subscription : definitions.subscriptions)
    {
      if (subscription.service == service)
      {
        return;
      }
    }
    service = 0;
  };
  pruneRole(expectedRetainedRoles.client);
  pruneRole(expectedRetainedRoles.sibling);
  pruneRole(expectedRetainedRoles.cousin);
  pruneRole(expectedRetainedRoles.seeding);
  pruneRole(expectedRetainedRoles.sharding);
  pruneRole(expectedRetainedRoles.topologyBridge);
  if (deployment.isStateful &&
      (parameters.statefulMeshRoles.client != expectedRetainedRoles.client ||
       parameters.statefulMeshRoles.sibling != expectedRetainedRoles.sibling ||
       parameters.statefulMeshRoles.cousin != expectedRetainedRoles.cousin ||
       parameters.statefulMeshRoles.seeding != expectedRetainedRoles.seeding ||
       parameters.statefulMeshRoles.sharding != expectedRetainedRoles.sharding ||
       parameters.statefulMeshRoles.topologyBridge != expectedRetainedRoles.topologyBridge))
  {
    return prodigyRetainedRecoveryFail(failure, "retained recovery stateful roles differ from generated launch services");
  }

  ContainerPlan& plan = bootstrap.plan;
  plan.uuid = parameters.uuid;
  plan.config = config;
  for (const Subscription& subscription : definitions.subscriptions)
  {
    plan.subscriptions.emplace(subscription.service, subscription);
  }
  for (const Advertisement& definition : definitions.advertisements)
  {
    auto port = parameters.advertisesOnPorts.find(definition.service);
    if (port == parameters.advertisesOnPorts.end() || port->second == 0)
    {
      return prodigyRetainedRecoveryFail(failure, "retained recovery advertised ports do not match authoritative services");
    }
    Advertisement advertisement = definition;
    advertisement.port = port->second;
    plan.advertisements.emplace(advertisement.service, advertisement);
  }
  if (plan.advertisements.size() != parameters.advertisesOnPorts.size())
  {
    return prodigyRetainedRecoveryFail(failure, "retained recovery parameters contain an unknown advertised service");
  }

  plan.subscriptionPairings = parameters.subscriptionPairings;
  plan.advertisementPairings = parameters.advertisementPairings;
  plan.restartOnFailure = true;
  plan.taskAttemptNumber = parameters.taskAttemptNumber;
  plan.fragment = parameters.private6.network.v6[15];
  plan.wormholes = parameters.wormholes;
  plan.whiteholes = parameters.whiteholes;
  plan.networkAccess = deployment.networkAccess;
  plan.useHostNetworkNamespace = false;
  plan.addresses.emplace_back(parameters.private6);
  plan.lifetime = ApplicationLifetime::base;
  plan.state = ContainerState::scheduled;
  plan.runtimeReady = false;
  plan.createdAtMs = observedCreatedAtMs;
  plan.shardGroup = 0;
  plan.nShardGroups = deployment.isStateful ? 1 : 0;
  plan.requiresDatacenterUniqueTag = deployment.requiresDatacenterUniqueTag;
  plan.isStateful = deployment.isStateful;
  plan.statefulMeshRoles = parameters.statefulMeshRoles;
  plan.statefulTopology = parameters.statefulTopology;
  plan.hasCredentialBundle = parameters.hasCredentialBundle;
  plan.credentialBundle = parameters.credentialBundle;
  bootstrap.metricPolicy = prodigyNeuronMetricPolicyForDeployment(deployment);
  return true;
}
