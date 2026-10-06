// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

enum class ReservedPorts : uint16_t {
  neuron = 312,
  brain = 313,
  mothership = 314,
  clusterPairControl = 315
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
  pullContainerLogs,
  // Version-scoped recovery for a non-serving stateless rollout head.  Keep
  // this appended: MothershipTopic is a wire enum.
  cancelDeployment,
  recoverMaterializedStatefulDeployment,
  credentialExpiryNotices,
  // Versioned separately from ClusterStatusReport so old fixed-order report
  // decoders fail closed instead of accepting shifted fields.
  pullUpgradeAdmissionReport,
  // Durable placement-policy admission is independently framed so unsupported
  // controllers cannot silently accept a shifted deployment request.
  commitDeploymentPlacementPolicy,
  updateProdigyAdmitted,
  // Versioned identity receipt for cross-cluster coordinators.  Appended so
  // older controllers reject the request rather than decoding a shifted frame.
  pullDeploymentIdentity,
  // Opt-in, versioned durable admission for the restricted cross-cluster
  // stateless target profile.  Legacy spinApplication remains unchanged.
  admitStatelessDeployment,
  pullStatelessDeploymentAdmission,
  // Source-side retirement sealing is independently framed so legacy
  // controllers reject it instead of interpreting an admission payload.
  preparePairedSourceRetirement,
  pullPairedSourceRetirement,
  enrollClusterPair,
  pullClusterPairEnrollment,
  revokeClusterPair,
  pullClusterPairRevocation,
  rotateClusterPairEpoch,
  pullClusterPairEpochRotation,
  // Deployment permissions are installed once; ordinary route eligibility is
  // evaluated locally without a Mothership request.
  commitLocalCousinServicePermission,
  pullLocalCousinServicePermission,
  // Observation of ephemeral, locally filtered counterpart candidates only.
  pullCousinCounterparts
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
    case MothershipTopic::cancelDeployment:
      return "cancelDeployment";
    case MothershipTopic::recoverMaterializedStatefulDeployment:
      return "recoverMaterializedStatefulDeployment";
    case MothershipTopic::credentialExpiryNotices:
      return "credentialExpiryNotices";
    case MothershipTopic::pullUpgradeAdmissionReport:
      return "pullUpgradeAdmissionReport";
    case MothershipTopic::commitDeploymentPlacementPolicy:
      return "commitDeploymentPlacementPolicy";
    case MothershipTopic::updateProdigyAdmitted:
      return "updateProdigyAdmitted";
    case MothershipTopic::pullDeploymentIdentity:
      return "pullDeploymentIdentity";
    case MothershipTopic::admitStatelessDeployment:
      return "admitStatelessDeployment";
    case MothershipTopic::pullStatelessDeploymentAdmission:
      return "pullStatelessDeploymentAdmission";
    case MothershipTopic::preparePairedSourceRetirement:
      return "preparePairedSourceRetirement";
    case MothershipTopic::pullPairedSourceRetirement:
      return "pullPairedSourceRetirement";
    case MothershipTopic::enrollClusterPair:
      return "enrollClusterPair";
    case MothershipTopic::pullClusterPairEnrollment:
      return "pullClusterPairEnrollment";
    case MothershipTopic::revokeClusterPair:
      return "revokeClusterPair";
    case MothershipTopic::pullClusterPairRevocation:
      return "pullClusterPairRevocation";
    case MothershipTopic::rotateClusterPairEpoch:
      return "rotateClusterPairEpoch";
    case MothershipTopic::pullClusterPairEpochRotation:
      return "pullClusterPairEpochRotation";
    case MothershipTopic::commitLocalCousinServicePermission:
      return "commitLocalCousinServicePermission";
    case MothershipTopic::pullLocalCousinServicePermission:
      return "pullLocalCousinServicePermission";
    case MothershipTopic::pullCousinCounterparts:
      return "pullCousinCounterparts";
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
  replicateSystemContainerArtifact,
  // Append-only durable operator-cancellation replication and acknowledgement.
  replicateDeploymentCancellation,
  acknowledgeDeploymentCancellation,
  // Explicit authenticated peer capability acknowledgement; appended to
  // preserve all existing topic values.
  advertiseCapabilities,
  acknowledgeCapabilities,
  // Read-only, generation-fenced release-admission observation exchange.
  observeUpgradeAdmission,
  observeUpgradeAdmissionResponse
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
  pullContainerLogs,
  // Brain -> Neuron bundle staging command; Neuron echoes only after the
  // exact requested digest has been staged.
  updateBundle,
  transitionToNewBundle,
  transportCredentialPeers,
  transportCredentialPeersAck,
  clusterPairControlCredentials,
  clusterPairControlCredentialsAck,
  clusterPairEpochStatus,
  cousinDiscoverySnapshot,
  cousinDiscoveryReceipt,
  cousinSessionRequest,
  cousinSessionCommand,
  cousinSessionAck,
  cousinSessionControlSend,
  cousinSessionControlReceipt,
  cousinAdmissionCommand,
  cousinAdmissionAck
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
  cousinSessionRequest,
  cousinSessionCommand,
  cousinSessionAck,
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

enum class CancelDeploymentResult : uint8_t {
  rejected = 0,
  accepted = 1,
  alreadyAccepted = 2,
  completed = 3
};

enum class CancelDeploymentPhase : uint8_t {
  none = 0,
  accepted = 1,
  containersTerminated = 2,
  successorStarted = 3,
  completed = 4
};

constexpr static const char *prodigyCancelDeploymentResultName(CancelDeploymentResult result)
{
  switch (result)
  {
    case CancelDeploymentResult::rejected: return "rejected";
    case CancelDeploymentResult::accepted: return "accepted";
    case CancelDeploymentResult::alreadyAccepted: return "alreadyAccepted";
    case CancelDeploymentResult::completed: return "completed";
  }
  return "rejected";
}

constexpr static const char *prodigyCancelDeploymentPhaseName(CancelDeploymentPhase phase)
{
  switch (phase)
  {
    case CancelDeploymentPhase::none: return "none";
    case CancelDeploymentPhase::accepted: return "accepted";
    case CancelDeploymentPhase::containersTerminated: return "containersTerminated";
    case CancelDeploymentPhase::successorStarted: return "successorStarted";
    case CancelDeploymentPhase::completed: return "completed";
  }
  return "none";
}

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
