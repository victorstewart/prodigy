// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

enum class ReservedPorts : uint16_t {
  neuron = 312,
  brain = 313,
  mothership = 314
};

enum class ApplicationLifetime : uint8_t {
  base,
  canary,
  surge
};

enum class MothershipTopic : uint16_t {
  configure,
  upsertMachineSchemas,
  deltaMachineBudget,
  deleteMachineSchema,
  addMachines,
  spinApplication,
  destroyApplication,
  measureApplication,
  pullClusterReport,
  pullApplicationReport,
  updateProdigy,
  reserveApplicationID,
  reserveServiceID,
  upsertTlsVaultFactory,
  upsertApiCredentialSet,
  mintClientTlsIdentity,
  registerRoutableSubnet,
  unregisterRoutableSubnet,
  pullRoutableSubnets,
  pullRoutableResourceLeases,
  upsertDNSBinding,
  deleteDNSBinding,
  pullDNSBindings,
  teardownDNSBindings,
  presentACMEDNS01Challenge,
  cleanupACMEDNS01Challenge,
  importACMELineage,
  configureMothershipTunnelProvider,
  pullTaskReport,
  pullContainerLogs
};

constexpr static const char *prodigyMothershipTopicName(MothershipTopic topic)
{
  switch (topic)
  {
    case MothershipTopic::configure:
      return "configure";
    case MothershipTopic::upsertMachineSchemas:
      return "upsertMachineSchemas";
    case MothershipTopic::deltaMachineBudget:
      return "deltaMachineBudget";
    case MothershipTopic::deleteMachineSchema:
      return "deleteMachineSchema";
    case MothershipTopic::addMachines:
      return "addMachines";
    case MothershipTopic::spinApplication:
      return "spinApplication";
    case MothershipTopic::destroyApplication:
      return "destroyApplication";
    case MothershipTopic::measureApplication:
      return "measureApplication";
    case MothershipTopic::pullClusterReport:
      return "pullClusterReport";
    case MothershipTopic::pullApplicationReport:
      return "pullApplicationReport";
    case MothershipTopic::updateProdigy:
      return "updateProdigy";
    case MothershipTopic::reserveApplicationID:
      return "reserveApplicationID";
    case MothershipTopic::reserveServiceID:
      return "reserveServiceID";
    case MothershipTopic::upsertTlsVaultFactory:
      return "upsertTlsVaultFactory";
    case MothershipTopic::upsertApiCredentialSet:
      return "upsertApiCredentialSet";
    case MothershipTopic::mintClientTlsIdentity:
      return "mintClientTlsIdentity";
    case MothershipTopic::registerRoutableSubnet:
      return "registerRoutableSubnet";
    case MothershipTopic::unregisterRoutableSubnet:
      return "unregisterRoutableSubnet";
    case MothershipTopic::pullRoutableSubnets:
      return "pullRoutableSubnets";
    case MothershipTopic::pullRoutableResourceLeases:
      return "pullRoutableResourceLeases";
    case MothershipTopic::upsertDNSBinding:
      return "upsertDNSBinding";
    case MothershipTopic::deleteDNSBinding:
      return "deleteDNSBinding";
    case MothershipTopic::pullDNSBindings:
      return "pullDNSBindings";
    case MothershipTopic::teardownDNSBindings:
      return "teardownDNSBindings";
    case MothershipTopic::presentACMEDNS01Challenge:
      return "presentACMEDNS01Challenge";
    case MothershipTopic::cleanupACMEDNS01Challenge:
      return "cleanupACMEDNS01Challenge";
    case MothershipTopic::importACMELineage:
      return "importACMELineage";
    case MothershipTopic::configureMothershipTunnelProvider:
      return "configureMothershipTunnelProvider";
    case MothershipTopic::pullTaskReport:
      return "pullTaskReport";
    case MothershipTopic::pullContainerLogs:
      return "pullContainerLogs";
  }

  return "unknown";
}

enum class BrainTopic : uint16_t {
  cullDeployment,
  reconcileState,
  registration,
  peerAddressCandidates,
  masterMissing,
  peerHeartbeat,
  updateBundle,
  transitionToNewBundle,
  relinquishMasterStatus,
  replicateDeployment,
  replicateBrainConfig,
  replicateClusterTopology,
  replicateApplicationIDReservation,
  replicateApplicationServiceReservation,
  replicateTlsVaultFactory,
  replicateApiCredentialSet,
  replicateMasterAuthorityState,
  replicateMetricsSnapshot,
  reconcileMetrics,
  replicateMetricsAppend,
  reconcileTd,
  replicateTdAppend,
  replicateContainerHealthy,
  replicateContainerRuntimeReady,
  replicateContainerRuntimeState,
  replicateSystemContainerArtifact
};

enum class NeuronTopic : uint16_t {
  spinContainer,
  killContainer,
  advertisementPairing,
  subscriptionPairing,
  adjustContainerResources,
  containerHealthy,
  containerFailed,
  registration,
  machineHardwareProfile,
  requestContainerBlob,
  assignFragment,
  changeContainerLifetime,
  containerResourcesAdjusted,
  ping,
  pong,
  stateUpload,
  hardwareFailure,
  updateOS,
  replicateDeployment,
  spotTerminationImminent,
  containerStatistics,
  containerRuntimeReady,
  refreshContainerCredentials,
  refreshContainerWormholes,
  configureRuntimeEnvironment,
  resetSwitchboardState,
  configureSwitchboardRoutableSubnets,
  configureSwitchboardHostedIngressPrefixes,
  configureSwitchboardOverlayRoutes,
  openSwitchboardWormholes,
  closeSwitchboardWormholesToContainer,
  openSwitchboardWhiteholes,
  closeSwitchboardWhiteholesToContainer,
  taskAttemptTerminal,
  taskAttemptTerminalAck,
  pullContainerLogs
};

enum class ContainerTopic : uint16_t {
  none = 0,
  ping,
  pong,
  stop,
  advertisementPairing,
  subscriptionPairing,
  healthy,
  message,
  resourceDelta,
  datacenterUniqueTag,
  statistics,
  resourceDeltaAck,
  credentialsRefresh,
  wormholesRefresh,
  runtimeReady,
  taskResult,
};

enum class PulseTopic : uint16_t {
  matrix,
  push,
  sum_matrix,
  avg_matrix,
  sum_row,
  avg_row,
  percentile_matrix,
  percentile_row
};

enum class ApplicationType : uint64_t {
  stateless = 0,
  stateful,
  tunnel,
  task
};

enum class TaskExecutionPolicy : uint8_t {
  runOnce = 0,
  untilSucceeded
};

enum class TaskExecutionState : uint8_t {
  accepted = 0,
  assigned,
  running,
  retrying,
  succeeded,
  failed,
  cancelled,
  lost
};

enum class TaskAttemptJournalState : uint8_t {
  accepted = 0,
  running,
  terminal,
  acknowledged
};

enum class TaskTerminationKind : uint8_t {
  none = 0,
  exited,
  signaled,
  oomKilled,
  startupFailed,
  placementFailed,
  cancelled,
  lost
};

enum class MachineLifetime : uint8_t {
  spot,
  ondemand,
  reserved,
  owned
};

enum class SpinApplicationResponseCode : uint8_t {
  invalidPlan,
  okay,
  progress,
  failed,
  finished
};

enum class ContainerState : uint8_t {
  none = 0,
  planned,
  scheduled,
  healthy,
  crashedRestarting,
  aboutToDestroy,
  destroying,
  destroyed
};

enum class SubscriptionNature : uint8_t {
  none,
  any,
  exclusiveSome,
  all
};

enum class DeploymentState : uint8_t {
  none,
  waitingToDeploy,
  canaries,
  deploying,
  running,
  decommissioning,
  failed
};

enum class ScalingDimension : uint8_t {
  cpu,
  memory,
  storage,
  runtimeIngressQueueWaitComposite,
  runtimeIngressHandlerComposite
};

using ResourceType = ScalingDimension;
