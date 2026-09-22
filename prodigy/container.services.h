#pragma once

// Pure service-definition construction shared by normal scheduling and
// retained-container recovery.  Callers still own port allocation, mesh
// activation, and any mutable deployment bookkeeping.

#include <cstring>

#include <prodigy/types.h>

enum class DataStrategy : uint8_t {
  none = 0,
  genesis,
  changelog,
  seeding,
  sharding
};

static inline bool prodigyMetricNameMatchesLiteral(const String& metricName, const char *literal)
{
  if (literal == nullptr)
  {
    return false;
  }
  size_t literalLength = std::strlen(literal);
  return metricName.size() == literalLength &&
         (literalLength == 0 || std::memcmp(metricName.data(), literal, literalLength) == 0);
}

static inline bool prodigyIsNeuronCollectableScalingDimension(ScalingDimension dimension)
{
  switch (dimension)
  {
    case ScalingDimension::cpu:
    case ScalingDimension::memory:
    case ScalingDimension::storage:
      return true;
    case ScalingDimension::runtimeIngressQueueWaitComposite:
    case ScalingDimension::runtimeIngressHandlerComposite:
    default:
      return false;
  }
}

static inline bool prodigyScalingDimensionForMetricName(const String& metricName, ScalingDimension& dimension)
{
  for (ScalingDimension candidate : {
           ScalingDimension::cpu,
           ScalingDimension::memory,
           ScalingDimension::storage,
           ScalingDimension::runtimeIngressQueueWaitComposite,
           ScalingDimension::runtimeIngressHandlerComposite})
  {
    if (prodigyMetricNameMatchesLiteral(metricName, ProdigyMetrics::nameForScalingDimension(candidate)))
    {
      dimension = candidate;
      return true;
    }
  }
  return false;
}

struct ProdigyContainerServiceDefinitions {
  Vector<Subscription> subscriptions = {};
  Vector<Advertisement> advertisements = {};
};

struct ProdigyContainerServiceDefinitionContext {
  bool isStateful = false;
  StatefulMeshRoles roles = {};
  StatefulTopology topology = {};
  bool advertiseClient = false;
  bool seedingAlways = false;
  DataStrategy dataStrategy = DataStrategy::none;
  uint32_t nShardGroups = 0;
  Vector<StatefulMeshRoles> priorShardRoles = {};
};

static inline NeuronContainerMetricPolicy prodigyNeuronMetricPolicyForDeployment(const DeploymentPlan& plan)
{
  NeuronContainerMetricPolicy policy;
  auto includeDimension = [&](ScalingDimension dimension) -> void {
    if (prodigyIsNeuronCollectableScalingDimension(dimension))
    {
      policy.scalingDimensionsMask |= ProdigyMetrics::maskForScalingDimension(dimension);
    }
  };
  for (const HorizontalScaler& scaler : plan.horizontalScalers)
  {
    ScalingDimension dimension = ScalingDimension::cpu;
    if (prodigyScalingDimensionForMetricName(scaler.name, dimension))
    {
      includeDimension(dimension);
    }
  }
  for (const VerticalScaler& scaler : plan.verticalScalers)
  {
    includeDimension(scaler.resource);
  }
  if (policy.scalingDimensionsMask > 0)
  {
    policy.metricsCadenceMs = ProdigyMetrics::defaultNeuronCollectionCadenceMs;
  }
  return policy;
}

static inline bool prodigyBuildContainerServiceDefinitions(
    const DeploymentPlan& deployment,
    const ProdigyContainerServiceDefinitionContext& context,
    ProdigyContainerServiceDefinitions& definitions)
{
  definitions = {};
  definitions.subscriptions = deployment.subscriptions;
  definitions.advertisements = deployment.advertisements;

  if (context.isStateful == false)
  {
    return true;
  }
  if (deployment.isStateful == false)
  {
    return false;
  }

  auto addAdvertisement = [&](uint64_t service, ContainerState startAt) {
    definitions.advertisements.emplace_back(service, startAt, ContainerState::destroying, 0);
  };
  auto addSubscription = [&](uint64_t service, ContainerState startAt, ContainerState stopAt) {
    definitions.subscriptions.emplace_back(service, startAt, stopAt, SubscriptionNature::all);
  };
  addAdvertisement(context.roles.sibling, ContainerState::scheduled);
  addAdvertisement(context.roles.seeding, ContainerState::healthy);
  if (context.roles.topologyBridge != 0 && prodigyStatefulTopologyShouldAdvertiseBridge(context.topology))
    addAdvertisement(context.roles.topologyBridge, ContainerState::scheduled);
  if (context.advertiseClient && prodigyStatefulTopologyServesClients(context.topology))
    addAdvertisement(context.roles.client, ContainerState::healthy);
  if (!deployment.stateful.neverShard) {
    addAdvertisement(context.roles.cousin, ContainerState::scheduled);
    addAdvertisement(context.roles.sharding, ContainerState::healthy);
  }
  addSubscription(context.roles.sibling, ContainerState::scheduled, ContainerState::destroying);
  if (context.roles.topologyBridge != 0 && prodigyStatefulTopologyShouldSubscribeBridge(context.topology))
    addSubscription(context.roles.topologyBridge, ContainerState::scheduled, ContainerState::destroying);
  if (context.seedingAlways)
    addSubscription(context.roles.seeding, ContainerState::scheduled, ContainerState::destroying);
  switch (context.dataStrategy) {
    case DataStrategy::genesis:
    case DataStrategy::none:
      break;
    case DataStrategy::changelog: // Keep seeding available for a full recovery.
    case DataStrategy::seeding:
      if (!context.seedingAlways)
        addSubscription(context.roles.seeding, ContainerState::scheduled, ContainerState::destroying);
      break;
    case DataStrategy::sharding:
      if (context.nShardGroups == 0 || context.priorShardRoles.size() + 1 != context.nShardGroups) return false;
      // Feed from every prior shard group; lifecycle removes these subscriptions
      // only after the new shards are healthy and their clients have connected.
      for (const StatefulMeshRoles& roles : context.priorShardRoles) {
        addSubscription(roles.sharding, ContainerState::scheduled, ContainerState::none);
        addSubscription(roles.cousin, ContainerState::scheduled, ContainerState::none);
      }
      break;
  }
  return true;
}
