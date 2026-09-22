#include <cassert>
#include <cstdio>
#include <cstring>

#include <prodigy/persistent.state.h>
#include <prodigy/retained.container.recovery.h>

static DeploymentPlan deployment(bool stateful)
{
  DeploymentPlan plan = {};
  plan.config.type = stateful ? ApplicationType::stateful : ApplicationType::stateless;
  plan.config.applicationID = 77;
  plan.config.versionID = 9;
  plan.config.memoryMB = 256;
  plan.config.storageMB = 128;
  plan.config.nLogicalCores = 1;
  plan.isStateful = stateful;
  if (stateful)
  {
    plan.stateful.clientPrefix = 0x1100000000000000ULL;
    plan.stateful.siblingPrefix = 0x1200000000000000ULL;
    plan.stateful.cousinPrefix = 0x1300000000000000ULL;
    plan.stateful.seedingPrefix = 0x1400000000000000ULL;
    plan.stateful.shardingPrefix = 0x1500000000000000ULL;
    plan.stateful.neverShard = true;
    plan.stateful.allMasters = true;
  }
  return plan;
}

static ContainerParameters parametersFor(const DeploymentPlan& deployment)
{
  ContainerParameters parameters = {};
  parameters.uuid = 0x7711;
  parameters.deploymentID = deployment.config.deploymentID();
  parameters.memoryMB = deployment.config.memoryMB;
  parameters.storageMB = deployment.config.storageMB;
  parameters.nLogicalCores = uint16_t(applicationSharedCPUCoreHint(deployment.config));
  parameters.cpuMode = deployment.config.cpuMode;
  parameters.requestedCPUMillis = applicationRequestedCPUMillis(deployment.config);
  parameters.private6.network.is6 = true;
  parameters.private6.cidr = 128;
  std::memcpy(parameters.private6.network.v6, container_network_subnet6.value, 11);
  parameters.private6.network.v6[11] = 7;
  parameters.private6.network.v6[12] = 0x01;
  parameters.private6.network.v6[13] = 0x02;
  parameters.private6.network.v6[14] = 0x03;
  parameters.private6.network.v6[15] = 4;
  if (deployment.isStateful)
  {
    parameters.statefulMeshRoles = StatefulMeshRoles::forShardGroup(deployment.stateful, deployment.config.applicationID, 0);
    parameters.statefulMeshRoles.cousin = 0;
    parameters.statefulMeshRoles.sharding = 0;
    parameters.statefulMeshRoles.topologyBridge = 0;
    parameters.statefulTopology.shardGroup = 0;
    parameters.statefulTopology.workerCount = prodigyStatefulWorkerCountForLogicalCores(deployment.config.nLogicalCores);
    parameters.statefulTopology.topologyEpoch = parameters.statefulTopology.workerCount;
    parameters.statefulTopology.sourceEpoch = parameters.statefulTopology.workerCount;
    parameters.statefulTopology.targetEpoch = parameters.statefulTopology.workerCount;
    parameters.statefulTopology.servingMode = StatefulTopologyServingMode::serve;
    parameters.advertisesOnPorts[parameters.statefulMeshRoles.sibling] = 12001;
    parameters.advertisesOnPorts[parameters.statefulMeshRoles.seeding] = 12002;
    parameters.advertisesOnPorts[parameters.statefulMeshRoles.client] = 12003;
  }
  return parameters;
}

static constexpr uint8_t datacenterFragment = 7;
static constexpr uint32_t machineFragment = 0x010203;
static constexpr int64_t observedCreatedAtMs = 1790039900000LL;

static void expectValidStateless(void)
{
  DeploymentPlan plan = deployment(false);
  ContainerParameters parameters = parametersFor(plan);
  NeuronContainerBootstrap bootstrap = {};
  String failure = {};
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure));
  assert(bootstrap.plan.uuid == parameters.uuid);
  assert(bootstrap.plan.config.deploymentID() == parameters.deploymentID);
  assert(bootstrap.plan.lifetime == ApplicationLifetime::base);
  assert(bootstrap.plan.state == ContainerState::scheduled && bootstrap.plan.runtimeReady == false);
  assert(bootstrap.plan.createdAtMs == observedCreatedAtMs);
  assert(bootstrap.plan.addresses.size() == 1 && bootstrap.plan.fragment == 4);
}

static void expectValidStateful(void)
{
  DeploymentPlan plan = deployment(true);
  ContainerParameters parameters = parametersFor(plan);
  NeuronContainerBootstrap bootstrap = {};
  String failure = {};
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure));
  assert(bootstrap.plan.isStateful && bootstrap.plan.nShardGroups == 1 && bootstrap.plan.shardGroup == 0);
  assert(bootstrap.plan.advertisements.size() == 3);
  assert(bootstrap.plan.statefulMeshRoles.cousin == 0 && bootstrap.plan.statefulMeshRoles.sharding == 0);
}

static void expectReplicaAndShardableRecovery()
{
  DeploymentPlan plan=deployment(true);plan.stateful.allMasters=false;plan.stateful.neverShard=false;
  auto parameters=parametersFor(plan);
  const auto roles=StatefulMeshRoles::forShardGroup(plan.stateful,plan.config.applicationID,0);
  parameters.statefulMeshRoles=roles;parameters.statefulMeshRoles.client=0;parameters.statefulMeshRoles.topologyBridge=0;
  parameters.advertisesOnPorts.erase(roles.client);
  parameters.advertisesOnPorts[roles.cousin]=12004;parameters.advertisesOnPorts[roles.sharding]=12005;
  NeuronContainerBootstrap bootstrap;String failure;
  const bool okay=prodigyBuildRetainedContainerBootstrap(plan,parameters,machineFragment,datacenterFragment,observedCreatedAtMs,bootstrap,&failure);
  if (!okay) std::fprintf(stderr,"replica reconstruction: %s\n",failure.c_str());
  assert(okay);
  assert(bootstrap.plan.statefulMeshRoles.client==0 && bootstrap.plan.advertisements.size()==4);
  parameters.statefulTopology.operationID=99;
  assert(!prodigyBuildRetainedContainerBootstrap(plan,parameters,machineFragment,datacenterFragment,observedCreatedAtMs,bootstrap,&failure));
}
static void expectCompactStartupCPURecovery()
{
  DeploymentPlan plan=deployment(false);plan.config.cpuMode=ApplicationCPUMode::shared;plan.config.sharedCPUMillis=250;
  auto parameters=parametersFor(plan);String raw;assert(ProdigyWire::serializeContainerParameters(raw,parameters));
  ContainerParameters decoded;assert(ProdigyWire::deserializeStartupContainerParameters(raw,decoded));
  assert(decoded.requestedCPUMillis==0);
  prodigyRestoreRetainedStartupCPUFields(raw,plan,decoded);
  NeuronContainerBootstrap bootstrap;String failure;
  assert(prodigyBuildRetainedContainerBootstrap(plan,decoded,machineFragment,datacenterFragment,observedCreatedAtMs,bootstrap,&failure));
}

int main()
{
  expectCompactStartupCPURecovery();
  expectReplicaAndShardableRecovery();
  expectValidStateless();
  expectValidStateful();

  DeploymentPlan plan = deployment(false);
  ContainerParameters parameters = parametersFor(plan);
  NeuronContainerBootstrap bootstrap = {};
  String failure = {};

  parameters.deploymentID += 1;
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);
  parameters = parametersFor(plan);
  parameters.memoryMB += 1;
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);
  parameters = parametersFor(plan);
  parameters.private6.network.v6[14] ^= 1;
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);

  DeploymentPlan stateful = deployment(true);
  parameters = parametersFor(stateful);
  parameters.statefulMeshRoles.cousin = StatefulMeshRoles::forShardGroup(stateful.stateful, stateful.config.applicationID, 0).cousin;
  assert(prodigyBuildRetainedContainerBootstrap(stateful, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);
  parameters = parametersFor(stateful);
  parameters.advertisesOnPorts[0xbeef] = 12345;
  assert(prodigyBuildRetainedContainerBootstrap(stateful, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);
}
