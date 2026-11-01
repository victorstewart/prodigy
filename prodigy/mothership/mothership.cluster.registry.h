#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <networking/includes.h>
#include <types/types.containers.h>
#include <databases/embedded/tidesdb.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/cousin.route.h>
#include <prodigy/cluster.pair.authority.h>
#include <prodigy/mothership/mothership.cluster.reconcile.h>
#include <prodigy/mothership/mothership.cluster.test.h>
#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/mothership/mothership.tunnel.auth.h>
#include <prodigy/mothership/mothership.tunnel.policy.h>
#include <prodigy/mothership/mothership.virtual.datacenter.h>
#include <prodigy/mothership/mothership.pair.control.boundary.h>
#include <prodigy/mothership/mothership.production.pair.h>
#include <prodigy/mothership/mothership.nametag.all.masters.h>
#include <prodigy/mothership/mothership.physical.fault.h>
#include <prodigy/mothership/mothership.nametag.qualification.h>
#include <prodigy/pair.private.bgp.secret.h>
#include <prodigy/cross.cluster.path.fault.h>
#include <prodigy/retained.container.recovery.h>

// Provider BGP is a public-origin plane.  ULA prefixes are reserved for
// authenticated private BGP carried inside MASQUE and must never be persisted
// or admitted as provider origins.
static inline bool mothershipProviderBGPOriginPrefixAllowed(const IPPrefix& prefix)
{
  return prefix.network.is6 == false || (prefix.network.v6[0] & 0xfeu) != 0xfcu;
}

// Local endpoint qualification is an operation of the test provider, not a
// migration receipt. In particular, selecting the target does not authorize
// retirement of either application or cluster.
class MothershipTestPairTargetReadinessIntent {
public:
  uint32_t version = 1;
  Vector<uint128_t> commissionedBrainUUIDs;
  uint128_t endpointMachineUUID = 0;
  uint32_t commissionedBrainCount = 0;
  uint32_t declaredStatelessWorkloadCount = 0;
  // Version two is the first final-transport fixture.  Its whole-destination
  // barrier includes the independently deployed COUSIN transport workload;
  // the stateless successor is never considered the whole cluster by itself.
  uint64_t cousinTransportDeploymentID = 0;
  uint32_t cousinTransportReplicaCount = 0;
  uint32_t declaredCousinTransportWorkloadCount = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipTestPairTargetReadinessIntent& intent)
{
  serializer.value4b(intent.version);
  serializer.container(intent.commissionedBrainUUIDs, 3, [](S& serializer, uint128_t& uuid) { serializer.value16b(uuid); });
  serializer.value16b(intent.endpointMachineUUID);
  serializer.value4b(intent.commissionedBrainCount);
  serializer.value4b(intent.declaredStatelessWorkloadCount);
  if (intent.version >= 2)
  {
    serializer.value8b(intent.cousinTransportDeploymentID);
    serializer.value4b(intent.cousinTransportReplicaCount);
    serializer.value4b(intent.declaredCousinTransportWorkloadCount);
  }
}

static inline bool mothershipBuildTestPairTargetReadinessIntent(const ClusterTopology& topology,
                                                                 const String& endpointIPv4,
                                                                 MothershipTestPairTargetReadinessIntent& intent,
                                                                 uint64_t cousinTransportDeploymentID = 0,
                                                                 uint32_t cousinTransportReplicaCount = 0)
{
  intent = {};
  if (topology.machines.size() != 3 || endpointIPv4.empty()) return false;
  for (uint32_t index = 0; index < topology.machines.size(); ++index)
  {
    if (!topology.machines[index].isBrain || topology.machines[index].uuid == 0) return false;
    for (uint32_t other = index + 1; other < topology.machines.size(); ++other)
      if (topology.machines[index].uuid == topology.machines[other].uuid) return false;
    intent.commissionedBrainUUIDs.push_back(topology.machines[index].uuid);
    for (const ClusterMachineAddress& address : topology.machines[index].addresses.privateAddresses)
      if (address.address == endpointIPv4) intent.endpointMachineUUID = topology.machines[index].uuid;
  }
  if (intent.endpointMachineUUID == 0) return false;
  std::sort(intent.commissionedBrainUUIDs.begin(), intent.commissionedBrainUUIDs.end());
  intent.commissionedBrainCount = 3;
  intent.declaredStatelessWorkloadCount = 1;
  if (cousinTransportDeploymentID != 0 || cousinTransportReplicaCount != 0)
  {
    if (cousinTransportDeploymentID == 0 || cousinTransportReplicaCount == 0) return false;
    intent.version = 2;
    intent.cousinTransportDeploymentID = cousinTransportDeploymentID;
    intent.cousinTransportReplicaCount = cousinTransportReplicaCount;
    intent.declaredCousinTransportWorkloadCount = 1;
  }
  return true;
}

static inline bool mothershipTestPairTargetReadinessIntentMatchesTopology(
    const MothershipTestPairTargetReadinessIntent& intent, const ClusterTopology& topology, const String& endpointIPv4)
{
  MothershipTestPairTargetReadinessIntent observed = {};
  return mothershipBuildTestPairTargetReadinessIntent(topology, endpointIPv4, observed) &&
         observed.commissionedBrainUUIDs == intent.commissionedBrainUUIDs &&
         observed.endpointMachineUUID == intent.endpointMachineUUID;
}

// G5 does not invent another route or workload authority.  This immutable
// intent is a receipt-bound reference to the exact active COUSIN generation
// and the two existing Brain-owned service permissions used while the narrow
// stateless transfer is in progress.
class MothershipTestPairCousinTransportIntent {
public:
  uint32_t version = 1;
  CousinRouteRecord route;
  ProdigyLocalCousinServicePermission sourcePermission;
  ProdigyLocalCousinServicePermission destinationPermission;
  CousinRouteApplyReceipt sourceApplyReceipt;
  CousinRouteApplyReceipt destinationApplyReceipt;
};

template <typename S>
static void serialize(S&& serializer, MothershipTestPairCousinTransportIntent& intent)
{
  serializer.value4b(intent.version);
  serializer.object(intent.route);
  serializer.object(intent.sourcePermission);
  serializer.object(intent.destinationPermission);
  serializer.object(intent.sourceApplyReceipt);
  serializer.object(intent.destinationApplyReceipt);
}

class MothershipTestPairBoundaryRecord {
public:
  uint32_t version = 1;
  MothershipVirtualDatacenterPairBoundaryDescriptor boundary;
  uint64_t sourceDeploymentID = 0;
  uint64_t targetDeploymentID = 0;
  String sourcePlanSHA256;
  String targetPlanSHA256;
  String sourceBlobSHA256;
  String targetBlobSHA256;
  uint64_t selectorGeneration = 0; // 0=source, 1=target; persist before effect
  bool closed = false;
  // Version two reserves the same pair owner before destination admission.
  // These request bytes contain only the supported secret-free stateless profile.
  String targetRequestPlan;
  String targetRequestPlanSHA256;
  uint64_t targetBlobBytes = 0;
  // The first accepted receipt is immutable. Health/current-master observations
  // from later queries never replace the original acceptance identity.
  String targetAdmissionReceipt;
  // Version three binds the pair to the commissioned target topology and the
  // fixed P6 stateless fixture shape. It deliberately stores no health receipt:
  // selection must obtain a fresh observation.
  MothershipTestPairTargetReadinessIntent targetReadinessIntent;
  // The first observed zero-source-flow drain is durable audit evidence only.
  // Target flow counts are live diagnostics and may change on a valid retry.
  String sourceDrainObservation;
  // Version four arms a one-way guest-reset fence before external lifecycle work.
  MothershipVirtualDatacenterPairGuestResetFence guestResetFence;
  // Written only after the lifecycle owner observes a different boot.
  String guestResetCompletedBootID;
  // Version five binds the local stateless lifecycle to the final COUSIN
  // transport. Version six is the corresponding armed guest-reset state.
  MothershipTestPairCousinTransportIntent cousinTransport;
};

template <typename S>
static void serialize(S&& serializer, MothershipTestPairBoundaryRecord& record)
{
  serializer.value4b(record.version);
  serializer.object(record.boundary);
  serializer.value8b(record.sourceDeploymentID);
  serializer.value8b(record.targetDeploymentID);
  serializer.text1b(record.sourcePlanSHA256, 64);
  serializer.text1b(record.targetPlanSHA256, 64);
  serializer.text1b(record.sourceBlobSHA256, 64);
  serializer.text1b(record.targetBlobSHA256, 64);
  serializer.value8b(record.selectorGeneration);
  serializer.value1b(record.closed);
  if (record.version >= 2)
  {
    serializer.text1b(record.targetRequestPlan, 1024 * 1024);
    serializer.text1b(record.targetRequestPlanSHA256, 64);
    serializer.value8b(record.targetBlobBytes);
    serializer.text1b(record.targetAdmissionReceipt, 64 * 1024);
  }
  if (record.version >= 3)
  {
    serializer.object(record.targetReadinessIntent);
    serializer.text1b(record.sourceDrainObservation, 64 * 1024);
  }
  if (record.version >= 4)
  {
    serializer.object(record.guestResetFence);
    serializer.text1b(record.guestResetCompletedBootID, 128);
  }
  if (record.version >= 5) serializer.object(record.cousinTransport);
}

// Keep the V2 wire shape explicit instead of attempting to decode it through
// the evolving runtime cluster codec. In particular, V2's tunnel egress
// policy predated the versioned IPv6-capable policy used today.
class MothershipProdigyClusterRecordV2EgressPolicy {
public:
  uint32_t address4 = 0;
  uint16_t port = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV2EgressPolicy& policy)
{
  serializer.value4b(policy.address4);
  serializer.value2b(policy.port);
}

class MothershipProdigyClusterRecordV2TunnelProvider {
public:
  String artifactSHA256;
  uint64_t artifactBytes = 0;
  String dialEndpoint;
  MothershipProdigyClusterRecordV2EgressPolicy egress;
  MothershipTunnelGatewayClientAuth clientAuth;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV2TunnelProvider& provider)
{
  serializer.text1b(provider.artifactSHA256, 64);
  serializer.value8b(provider.artifactBytes);
  serializer.text1b(provider.dialEndpoint, UINT32_MAX);
  serializer.object(provider.egress);
  serializer.object(provider.clientAuth);
}

class MothershipProdigyClusterRecordV2Connectivity {
public:
  MothershipConnectivityKind kind = MothershipConnectivityKind::ssh;
  MothershipProdigyClusterRecordV2TunnelProvider tunnelProvider;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV2Connectivity& connectivity)
{
  serializer.value1b(connectivity.kind);
  serializer.object(connectivity.tunnelProvider);
}

class MothershipProdigyClusterRecordV2 {
public:
  MothershipProdigyCluster cluster;
  MothershipProdigyClusterRecordV2Connectivity connectivity;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV2& record)
{
  MothershipProdigyCluster& cluster = record.cluster;
  serializer.text1b(cluster.name, UINT32_MAX);
  serializer.value16b(cluster.clusterUUID);
  serializer.value1b(cluster.deploymentMode);
  serializer.value1b(cluster.includeLocalMachine);
  serializer.value1b(cluster.provider);
  serializer.value1b(cluster.architecture);
  serializer.text1b(cluster.providerScope, UINT32_MAX);
  serializer.text1b(cluster.providerCredentialName, UINT32_MAX);
  serializer.value1b(cluster.propagateProviderCredentialToProdigy);
  serializer.value1b(cluster.dnsProvider);
  serializer.text1b(cluster.dnsProviderCredentialName, UINT32_MAX);
  serializer.object(cluster.acme);
  serializer.object(cluster.aws);
  serializer.object(cluster.gcp);
  serializer.object(cluster.azure);
  serializer.container(cluster.controls, UINT32_MAX);
  serializer.object(record.connectivity);
  serializer.value1b(cluster.datacenterFragment);
  serializer.value4b(cluster.autoscaleIntervalSeconds);
  serializer.value4b(cluster.nBrains);
  serializer.container(cluster.machineSchemas, UINT32_MAX);
  serializer.container(cluster.machines, UINT32_MAX);
  serializer.object(cluster.topology);
  serializer.text1b(cluster.bootstrapSshUser, UINT32_MAX);
  serializer.object(cluster.bootstrapSshKeyPackage);
  serializer.object(cluster.bootstrapSshHostKeyPackage);
  serializer.text1b(cluster.bootstrapSshPrivateKeyPath, UINT32_MAX);
  serializer.text1b(cluster.remoteProdigyPath, UINT32_MAX);
  serializer.value2b(cluster.sharedCPUOvercommitPermille);
  serializer.object(cluster.machineReservedResources);
  serializer.value1b(cluster.osUpdatesEnabled);
  serializer.container(cluster.osUpdatePolicies, UINT32_MAX);
  serializer.value4b(cluster.maxOSDrains);
  serializer.value4b(cluster.machineUpdateCadenceMins);
  serializer.object(cluster.bgp);
  serializer.object(cluster.test);
  serializer.value1b(cluster.desiredEnvironment);
  serializer.value1b(cluster.environmentConfigured);
  serializer.value8b(cluster.lastRefreshMs);
  serializer.text1b(cluster.lastRefreshFailure, UINT32_MAX);
}

class MothershipProdigyClusterRecordV3 {
public:

  MothershipProdigyCluster cluster;
  Vector<uint32_t> adoptedMachineRackUUIDs;
};

class MothershipProdigyClusterRecordV4 {
public:

  MothershipProdigyCluster cluster;
  Vector<uint32_t> adoptedMachineRackUUIDs;
  Vector<uint128_t> adoptedMachineUUIDs;
};

class MothershipProdigyClusterRecordV5 {
public:
  MothershipProdigyCluster cluster;
  Vector<uint32_t> adoptedMachineRackUUIDs;
  Vector<uint128_t> adoptedMachineUUIDs;
  MothershipInternalTransportProfile internalTransportProfile = MothershipInternalTransportProfile::tls;
};

class MothershipProdigyClusterRecordV6 {
public:
  MothershipProdigyCluster cluster;
  Vector<uint32_t> adoptedMachineRackUUIDs;
  Vector<uint128_t> adoptedMachineUUIDs;
  MothershipInternalTransportProfile internalTransportProfile = MothershipInternalTransportProfile::tls;
  uint32_t spareMachineCount = 0;
};

class MothershipProdigyClusterRecordV7 {
public:
  MothershipProdigyCluster cluster;
  Vector<uint32_t> adoptedMachineRackUUIDs;
  Vector<uint128_t> adoptedMachineUUIDs;
  MothershipInternalTransportProfile internalTransportProfile = MothershipInternalTransportProfile::tls;
  uint32_t spareMachineCount = 0;
  Vector<IPPrefix> bgpAuthorizedOriginPrefixes;
};

class MothershipProdigyClusterRecordV8 {
public:
  MothershipProdigyCluster cluster;
  Vector<uint32_t> adoptedMachineRackUUIDs;
  Vector<uint128_t> adoptedMachineUUIDs;
  MothershipInternalTransportProfile internalTransportProfile = MothershipInternalTransportProfile::tls;
  uint32_t spareMachineCount = 0;
  Vector<IPPrefix> bgpAuthorizedOriginPrefixes;
  bool providerManagedBGP = false;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV8& record)
{
  serializer.object(record.cluster);
  serializer.container4b(record.adoptedMachineRackUUIDs, UINT32_MAX);
  serializer.object(record.adoptedMachineUUIDs);
  serializer.value1b(record.internalTransportProfile);
  serializer.value4b(record.spareMachineCount);
  serializer.container(record.bgpAuthorizedOriginPrefixes, 256);
  serializer.value1b(record.providerManagedBGP);
}

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV7& record)
{
  serializer.object(record.cluster);
  serializer.container4b(record.adoptedMachineRackUUIDs, UINT32_MAX);
  serializer.object(record.adoptedMachineUUIDs);
  serializer.value1b(record.internalTransportProfile);
  serializer.value4b(record.spareMachineCount);
  serializer.container(record.bgpAuthorizedOriginPrefixes, 256);
}

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV6& record)
{
  serializer.object(record.cluster);
  serializer.container4b(record.adoptedMachineRackUUIDs, UINT32_MAX);
  serializer.object(record.adoptedMachineUUIDs);
  serializer.value1b(record.internalTransportProfile);
  serializer.value4b(record.spareMachineCount);
}

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV5& record)
{
  serializer.object(record.cluster);
  serializer.container4b(record.adoptedMachineRackUUIDs, UINT32_MAX);
  serializer.object(record.adoptedMachineUUIDs);
  serializer.value1b(record.internalTransportProfile);
}

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV4& record)
{
  serializer.object(record.cluster);
  serializer.container4b(record.adoptedMachineRackUUIDs, UINT32_MAX);
  serializer.object(record.adoptedMachineUUIDs);
}

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterRecordV3& record)
{
  serializer.object(record.cluster);
  serializer.container4b(record.adoptedMachineRackUUIDs, UINT32_MAX);
}

class MothershipUpgradeRejectedObservation {
public:
  uint64_t receiptVersion = 0;
  String reportSHA256 = {};
  String plannerInputSHA256 = {};
  String firstStopGate = {};
};

template <typename S>
static void serialize(S&& serializer, MothershipUpgradeRejectedObservation& observation)
{
  serializer.value8b(observation.receiptVersion);
  serializer.text1b(observation.reportSHA256, UINT32_MAX);
  serializer.text1b(observation.plannerInputSHA256, UINT32_MAX);
  serializer.text1b(observation.firstStopGate, UINT32_MAX);
}

// Version three adds a semantic, generation-fenced observation binding.  The
// report receipt itself changes on each request, so it remains audit data rather
// than the authorization identity consumed by updateProdigy.
class MothershipUpgradeAdmissionRecord {
public:
  uint32_t version = 3;
  uint128_t clusterUUID = 0;
  uint128_t operationID = 0;
  // These approved identities never change for a cluster/operation key.
  String sourceBundleSHA256 = {};
  String sourceContractSHA256 = {};
  String sourceReleaseID = {};
  String sourceProdigySHA256 = {};
  String sourceMothershipSHA256 = {};
  String targetBundleSHA256 = {};
  String targetContractSHA256 = {};
  // Semantic binding is stable across a fresh report only while authority and
  // all authenticated peer observations remain equivalent.
  uint64_t authorityGeneration = 0;
  uint128_t masterUUID = 0;
  int64_t masterBootNs = 0;
  String semanticObservationSHA256 = {};
  uint8_t approvedPath = 0;
  // Observation receipt data is deliberately separate from the immutable
  // request identity, so a fresh retry can replace a rejected observation.
  uint64_t observationReceiptVersion = 0;
  String observationReportSHA256 = {};
  String plannerInputSHA256 = {};
  bool eligible = false;
  String firstStopGate = {};
  Vector<MothershipUpgradeRejectedObservation> rejectedObservations = {};
};

// The unready-VM repair uses the cluster report to prove which registered peer
// needs its sealed reboot and the admission report to bind current authority,
// artifact, topology, inventory, and capacity.  The reboot necessarily
// advances that peer's transport generation, so the completed report is checked
// against those immutable fields instead of the pre-reboot semantic digest.  A
// normal fresh admission is still required before any deployment can consume
// the completed report.
static inline bool mothershipLocalVMUnreadyUpgradeReportValid(
    const MothershipUpgradeAdmissionReport& report,
    const MothershipUpgradeAdmissionRecord& admission,
    const MothershipProdigyCluster& cluster, uint128_t machineUUID,
    bool completed, uint64_t minimumReceiptVersion, String *failure = nullptr)
{
  auto fail = [&](const char *message) {
    if (failure != nullptr) failure->assign(message);
    return false;
  };
  auto failPeer = [&](const char *field, uint128_t peerUUID) {
    if (failure != nullptr)
    {
      String fieldName(field), peer = {};
      peer.assignItoh(peerUUID);
      failure->snprintf<"unready local VM recovery peer proof field={} peer={}"_ctv>(fieldName, peer);
    }
    return false;
  };
  auto failAuthority = [&](const char *field) {
    if (failure != nullptr)
    {
      String fieldName(field);
      failure->snprintf<"unready local VM recovery authority proof field={}"_ctv>(fieldName);
    }
    return false;
  };
  String operationID = {};
  operationID.assignItoh(admission.operationID);
  if (report.version != 4) return failAuthority("version");
  if (report.clusterUUID != cluster.clusterUUID) return failAuthority("cluster");
  if (report.operationID != operationID) return failAuthority("operation");
  if (report.targetBundleSHA256 != admission.targetBundleSHA256) return failAuthority("target-bundle");
  if (report.targetContractSHA256 != admission.targetContractSHA256) return failAuthority("target-contract");
  if (report.authorityGeneration != admission.authorityGeneration) return failAuthority("generation");
  if (report.masterUUID != admission.masterUUID) return failAuthority("master-uuid");
  if (report.masterBootNs != admission.masterBootNs) return failAuthority("master-boot");
  if (!report.master) return failAuthority("master-role");
  if (!report.authorityQuorumHealthy) return failAuthority("quorum");
  if (!report.authorityAcknowledged) return failAuthority("authority-acknowledgement");
  if (!report.recoveryWitnessAcknowledged) return failAuthority("recovery-witness");
  if (!report.currentUpdaterSupportsSerialFollowers) return failAuthority("serial-followers");
  if (!report.commissionedPeerTransportVerified) return failAuthority("peer-transport");
  if (report.masterApprovedBundleSHA256 != admission.sourceBundleSHA256)
    return failAuthority("approved-source-bundle");
  if (!report.stagingCapacityResponsesComplete) return failAuthority("staging-responses");
  if (!report.stagingCapacityComplete) return failAuthority("staging-capacity");
  if (report.commissionedBrainCount != 3) return failAuthority("brain-count");
  if (report.peers.size() != 3) return failAuthority("peer-count");
  if (report.observationComplete != completed) return failAuthority("observation-complete");
  if (completed)
  {
    if (report.observationReceiptVersion <= minimumReceiptVersion)
      return failAuthority("receipt-version");
    if (report.healthyCommissionedBrainCount != 3) return failAuthority("healthy-count");
    if (!report.fleetInventoriesFresh) return failAuthority("fleet-inventories");
    if (!report.fleetBundleDigestsFresh) return failAuthority("fleet-bundle-digests");
  }
  else if (report.healthyCommissionedBrainCount != 2)
    return failAuthority("healthy-count");
  uint32_t targetMatches = 0;
  for (uint32_t index = 0; index < report.peers.size(); ++index)
  {
    const auto& peer = report.peers[index];
    const bool masterSelf = peer.machineUUID == report.masterUUID;
    const char *invalidField = nullptr;
    if (peer.brainUUID != peer.machineUUID) invalidField = "brain-machine";
    else if (peer.authorityGeneration != admission.authorityGeneration) invalidField = "authority-generation";
    else if (masterSelf &&
             (peer.masterUUID != 0 || peer.masterBootNs != 0 || peer.requesterTransportGeneration != 0))
      invalidField = "master-self-echo";
    else if (!masterSelf &&
             (peer.masterUUID != admission.masterUUID || peer.masterBootNs != admission.masterBootNs))
      invalidField = "follower-master-echo";
    else if (!peer.codeSupportsSerialFollowers) invalidField = "serial-followers";
    else if (!peer.localInstalledBundleVerified) invalidField = "installed-bundle-attestation";
    else if (!peer.authorityAcknowledged) invalidField = "authority-acknowledgement";
    else if (!peer.recoveryWitnessAcknowledged) invalidField = "recovery-witness";
    else if (peer.operationID != report.operationID) invalidField = "operation";
    else if (peer.targetBundleSHA256 != report.targetBundleSHA256) invalidField = "target-bundle";
    else if (peer.targetContractSHA256 != report.targetContractSHA256) invalidField = "target-contract";
    else if (peer.requiredStagingBytes != report.requiredStagingBytes) invalidField = "staging-bytes";
    else if (!peer.stagingCapacityProbeComplete) invalidField = "staging-probe";
    else if (!peer.stagingCapacityVerified) invalidField = "staging-capacity";
    else if (peer.installedBundleSHA256 != admission.sourceBundleSHA256) invalidField = "source-bundle";
    if (invalidField != nullptr) return failPeer(invalidField, peer.machineUUID);
    uint32_t topologyMatches = 0;
    for (const auto& machine : cluster.topology.machines)
      if (machine.uuid == peer.machineUUID && machine.isBrain) ++topologyMatches;
    for (uint32_t prior = 0; prior < index; ++prior)
      if (report.peers[prior].machineUUID == peer.machineUUID) ++topologyMatches;
    if (topologyMatches != 1)
      return failPeer("topology", peer.machineUUID);
    if (peer.machineUUID == machineUUID)
    {
      ++targetMatches;
      if (peer.stateUploadFresh != completed)
        return fail("unready local VM recovery target upload state is not the required transition");
    }
    else if (!peer.stateUploadFresh)
      return fail("unready local VM recovery has another stale peer upload");
  }
  if (targetMatches != 1)
    return fail("unready local VM recovery target is absent from the authenticated peer proof");
  return true;
}

// The cluster report separately proves that the exact target Brain is
// currently missing readiness.  Its authenticated state upload can briefly
// complete while the failing control carrier reconnects, so the adjacent
// admission snapshot may be either phase.  Accept only a wholly valid phase:
// two healthy peers with the target upload absent, or all three healthy with
// every inventory and bundle digest fresh.  A partial hybrid remains closed.
static inline bool mothershipLocalVMUnreadyUpgradePreRecoveryReportValid(
    const MothershipUpgradeAdmissionReport& report,
    const MothershipUpgradeAdmissionRecord& admission,
    const MothershipProdigyCluster& cluster, uint128_t machineUUID,
    String *failure = nullptr)
{
  return mothershipLocalVMUnreadyUpgradeReportValid(
      report, admission, cluster, machineUUID, report.observationComplete, 0, failure);
}

template <typename S>
static void serialize(S&& serializer, MothershipUpgradeAdmissionRecord& record)
{
  serializer.value4b(record.version);
  serializer.value16b(record.clusterUUID);
  serializer.value16b(record.operationID);
  serializer.text1b(record.sourceBundleSHA256, UINT32_MAX);
  serializer.text1b(record.sourceContractSHA256, UINT32_MAX);
  serializer.text1b(record.sourceReleaseID, UINT32_MAX);
  serializer.text1b(record.sourceProdigySHA256, UINT32_MAX);
  serializer.text1b(record.sourceMothershipSHA256, UINT32_MAX);
  serializer.text1b(record.targetBundleSHA256, UINT32_MAX);
  serializer.text1b(record.targetContractSHA256, UINT32_MAX);
  serializer.value8b(record.authorityGeneration);
  serializer.value16b(record.masterUUID);
  serializer.value8b(record.masterBootNs);
  serializer.text1b(record.semanticObservationSHA256, UINT32_MAX);
  serializer.value1b(record.approvedPath);
  serializer.value8b(record.observationReceiptVersion);
  serializer.text1b(record.observationReportSHA256, UINT32_MAX);
  serializer.text1b(record.plannerInputSHA256, UINT32_MAX);
  serializer.value1b(record.eligible);
  serializer.text1b(record.firstStopGate, UINT32_MAX);
  serializer.object(record.rejectedObservations);
}

// Private Mothership intent.  It is deliberately separate from a Brain's
// replicated enrollment: this record makes the one-time root and pair identity
// retry-safe while each Brain remains the sole runtime authority owner.
class MothershipClusterPairEnrollmentIntent {
public:
  static constexpr uint32_t version = 6;
  uint32_t protocolVersion = version;
  uint128_t pairUUID = 0;
  uint128_t operationUUID = 0;
  uint128_t firstClusterUUID = 0;
  uint128_t secondClusterUUID = 0;
  uint64_t rootGeneration = 1;
  uint64_t keyEpoch = 1;
  // Audit observations only.  They are not part of the immutable operation
  // scope because a retry may legitimately observe a newer authority epoch.
  uint64_t firstObservedAuthorityGeneration = 0;
  uint64_t secondObservedAuthorityGeneration = 0;
  // Written after the corresponding Brain admits the immutable descriptor.
  // A retry uses this exact value rather than a later current authority view.
  uint64_t firstEnrolledAuthorityGeneration = 0;
  uint64_t secondEnrolledAuthorityGeneration = 0;
  uint8_t root[ProdigyClusterPairEnrollmentRootBytes] = {};
  Vector<ClusterPairControlEndpoint> firstEndpoints;
  Vector<ClusterPairControlEndpoint> secondEndpoints;
  bool firstInitialProjectionDelivered = false;
  bool secondInitialProjectionDelivered = false;
  bool firstQualified = false;
  bool secondQualified = false;
  // Admission is the durable permission/cleanup intent, written before any
  // provider mutation. Only a fresh provider receipt proves it is prepared.
  bool testControlBoundaryAdmitted = false;
  bool testControlBoundaryClosed = false;
  MothershipPairControlBoundaryDescriptor testControlBoundary;
  // At most one exact application tuple per direction, owned by this pair.
  Vector<MothershipPairControlServiceTransit> testControlServiceTransits;
  // Ciphertext/tag/nonce only. The AES key is re-derived from `root`, which is
  // the pre-existing private enrollment master key; this never enters a Brain
  // authority projection or a public registry record.
  Vector<MothershipPairPrivateBGPVault::Record> privateBGPSecrets;

  ~MothershipClusterPairEnrollmentIntent()
  {
    OPENSSL_cleanse(root, sizeof(root));
  }
};

static inline bool mothershipClusterPairEnrollmentIntentRootValid(const MothershipClusterPairEnrollmentIntent& intent)
{
  uint8_t nonzero = 0;
  for (uint8_t byte : intent.root) nonzero |= byte;
  return nonzero != 0;
}

static inline bool mothershipClusterPairEnrollmentIntentValid(const MothershipClusterPairEnrollmentIntent& intent)
{
  const auto& boundary = intent.testControlBoundary;
  const bool validBoundary = !intent.testControlBoundaryAdmitted ? !intent.testControlBoundaryClosed :
      intent.protocolVersion >= 2 && intent.firstQualified && intent.secondQualified &&
      intent.firstInitialProjectionDelivered && intent.secondInitialProjectionDelivered &&
      mothershipPairControlBoundaryValid(boundary) && boundary.operationUUID == intent.operationUUID &&
      boundary.firstClusterUUID == intent.firstClusterUUID && boundary.secondClusterUUID == intent.secondClusterUUID &&
      boundary.firstEndpoints == intent.firstEndpoints && boundary.secondEndpoints == intent.secondEndpoints;
  const bool validServiceTransit = intent.testControlServiceTransits.empty() ||
      (intent.protocolVersion >= 3 && intent.testControlBoundaryAdmitted && validBoundary &&
       (intent.protocolVersion >= 4 || intent.testControlServiceTransits.size() == 1) &&
       mothershipPairControlServiceTransitsValid(intent.testControlServiceTransits,
                                                 intent.firstClusterUUID, intent.secondClusterUUID));
  return (intent.protocolVersion >= 1 && intent.protocolVersion <= MothershipClusterPairEnrollmentIntent::version) &&
      validBoundary && validServiceTransit && intent.pairUUID != 0 &&
      intent.operationUUID != 0 && intent.firstClusterUUID != 0 && intent.secondClusterUUID != 0 &&
      intent.firstClusterUUID < intent.secondClusterUUID && intent.rootGeneration != 0 && intent.keyEpoch != 0 &&
      intent.firstObservedAuthorityGeneration != 0 && intent.secondObservedAuthorityGeneration != 0 &&
      mothershipClusterPairEnrollmentIntentRootValid(intent) &&
      prodigyClusterPairEndpointsValid(intent.firstEndpoints, intent.firstClusterUUID) &&
      prodigyClusterPairEndpointsValid(intent.secondEndpoints, intent.secondClusterUUID);
}

static inline bool mothershipClusterPairEnrollmentIntentScopeMatches(
    const MothershipClusterPairEnrollmentIntent& left, const MothershipClusterPairEnrollmentIntent& right)
{
  return left.operationUUID == right.operationUUID &&
      left.firstClusterUUID == right.firstClusterUUID && left.secondClusterUUID == right.secondClusterUUID &&
      left.rootGeneration == right.rootGeneration && left.keyEpoch == right.keyEpoch &&
      left.firstEndpoints == right.firstEndpoints && left.secondEndpoints == right.secondEndpoints;
}

template <typename S>
static void serialize(S&& serializer, MothershipClusterPairEnrollmentIntent& intent)
{
  serializer.value4b(intent.protocolVersion);
  serializer.value16b(intent.pairUUID);
  serializer.value16b(intent.operationUUID);
  serializer.value16b(intent.firstClusterUUID);
  serializer.value16b(intent.secondClusterUUID);
  serializer.value8b(intent.rootGeneration);
  serializer.value8b(intent.keyEpoch);
  serializer.value8b(intent.firstObservedAuthorityGeneration);
  serializer.value8b(intent.secondObservedAuthorityGeneration);
  serializer.value8b(intent.firstEnrolledAuthorityGeneration);
  serializer.value8b(intent.secondEnrolledAuthorityGeneration);
  for (uint8_t& byte : intent.root) serializer.value1b(byte);
  serializer.container(intent.firstEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints,
      [](auto& nested, auto& endpoint) { nested.object(endpoint); });
  serializer.container(intent.secondEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints,
      [](auto& nested, auto& endpoint) { nested.object(endpoint); });
  serializer.value1b(intent.firstInitialProjectionDelivered);
  serializer.value1b(intent.secondInitialProjectionDelivered);
  serializer.value1b(intent.firstQualified);
  serializer.value1b(intent.secondQualified);
  if (intent.protocolVersion >= 2)
  {
    serializer.value1b(intent.testControlBoundaryAdmitted);
    serializer.value1b(intent.testControlBoundaryClosed);
    serializer.object(intent.testControlBoundary);
  }
  if (intent.protocolVersion == 3)
  {
    // Preserve the original single-transit wire shape. Legacy records acquire
    // only that one direction; a reverse direction requires new admission.
    bool admitted = !intent.testControlServiceTransits.empty();
    MothershipPairControlServiceTransit transit = admitted ? intent.testControlServiceTransits[0] : MothershipPairControlServiceTransit {};
    serializer.value1b(admitted);
    serializer.object(transit);
    intent.testControlServiceTransits.clear();
    if (admitted) intent.testControlServiceTransits.push_back(std::move(transit));
  }
  else if (intent.protocolVersion >= 4)
  {
    serializer.container(intent.testControlServiceTransits, MothershipPairControlMaximumServiceTransits,
        [](auto& nested, auto& transit) { nested.object(transit); });
  }
  if (intent.protocolVersion == 5)
  {
    // Consume legacy encrypted BGP-only records, but deliberately do not
    // promote them: v5 has no authenticated gateway TLS bundle to deliver.
    Vector<MothershipPairPrivateBGPVault::LegacyRecord> legacyPrivateBGPSecrets;
    serializer.container(legacyPrivateBGPSecrets, 3, [](auto& nested, auto& record) { nested.object(record); });
    intent.privateBGPSecrets.clear();
  }
  else if (intent.protocolVersion >= 6)
    serializer.container(intent.privateBGPSecrets, 3, [](auto& nested, auto& record) { nested.object(record); });
  else intent.privateBGPSecrets.clear();
}

class MothershipLocalMembershipCleanupMachine {
public:
  MothershipProdigyClusterMachine machine = {};
  bool cleaned = false;
};

template <typename S>
static void serialize(S&& serializer, MothershipLocalMembershipCleanupMachine& entry)
{
  // MothershipProdigyClusterMachine deliberately omits the adopted UUID and
  // rack from its ordinary wire shape.  A cleanup journal must retain both:
  // they are part of the exact machine identity that crossed the Brain
  // membership boundary.
  serializer.object(entry.machine);
  serializer.value16b(entry.machine.uuid);
  serializer.value4b(entry.machine.rackUUID);
  serializer.value1b(entry.cleaned);
}

class MothershipLocalMembershipCleanupRecord {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t clusterUUID = 0;
  String desiredSpecSHA256 = {};
  bool membershipCommitted = false;
  Vector<MothershipLocalMembershipCleanupMachine> machines = {};
};
template <typename S>
static void serialize(S&& serializer, MothershipLocalMembershipCleanupRecord& record)
{
  serializer.value4b(record.protocolVersion); serializer.value16b(record.clusterUUID);
  serializer.text1b(record.desiredSpecSHA256, 64); serializer.value1b(record.membershipCommitted);
  serializer.object(record.machines);
}

static inline bool mothershipLocalMembershipCleanupRecordValid(
    const MothershipLocalMembershipCleanupRecord& record)
{
  if (record.protocolVersion != MothershipLocalMembershipCleanupRecord::version ||
      record.clusterUUID == 0 || !prodigyIsSHA256HexDigest(record.desiredSpecSHA256) ||
      record.machines.empty()) return false;
  for (uint32_t index = 0; index < record.machines.size(); ++index)
  {
    const auto& entry = record.machines[index];
    if (entry.machine.source != MothershipClusterMachineSource::adopted ||
        entry.machine.backing != ClusterMachineBacking::owned || entry.machine.uuid == 0 ||
        entry.machine.ssh.address.empty() || entry.machine.ssh.user.empty()) return false;
    for (uint32_t other = index + 1; other < record.machines.size(); ++other)
      if (entry.machine.uuid == record.machines[other].machine.uuid) return false;
  }
  return true;
}

static inline bool mothershipLocalMembershipCleanupIntentEqual(
    MothershipLocalMembershipCleanupRecord left,
    MothershipLocalMembershipCleanupRecord right)
{
  if (!mothershipLocalMembershipCleanupRecordValid(left) ||
      !mothershipLocalMembershipCleanupRecordValid(right) ||
      left.clusterUUID != right.clusterUUID || left.desiredSpecSHA256 != right.desiredSpecSHA256 ||
      left.machines.size() != right.machines.size()) return false;
  left.membershipCommitted = right.membershipCommitted = false;
  for (auto& entry : left.machines) entry.cleaned = false;
  for (auto& entry : right.machines) entry.cleaned = false;
  String leftBytes = {}, rightBytes = {};
  BitseryEngine::serialize(leftBytes, left); BitseryEngine::serialize(rightBytes, right);
  return leftBytes == rightBytes;
}

static inline bool mothershipApplicationPlacementRequired(uint16_t applicationID)
{ return applicationID == 2 || applicationID == 5 || applicationID == 10; }

class MothershipGraphReplicaPlacement {
public:
  uint128_t clusterUUID = 0;
  uint64_t deploymentID = 0;
  uint64_t membershipGeneration = 0;
  uint64_t topologyVersion = 0;
  String topologySHA256;
  String canonicalPlanSHA256;
  String artifactSHA256;
  uint64_t artifactBytes = 0;
  String observationReceiptSHA256;
};

// This is an observation bundle, not a second route registry.  The route
// records and their half receipts remain owned by the existing COUSIN columns;
// graph admission only names the two exact retained graph services it needs.
class MothershipGraphReplicaRouteBinding {
public:
  ProdigyCousinServicePurpose purpose = ProdigyCousinServicePurpose::sibling;
  CousinRouteRecord route;
  CousinRouteApplyReceipt ownerReceipt;
  CousinRouteApplyReceipt replicaReceipt;
};

template <typename S>
static void serialize(S&& serializer, MothershipGraphReplicaPlacement& member)
{
  serializer.value16b(member.clusterUUID); serializer.value8b(member.deploymentID);
  serializer.value8b(member.membershipGeneration); serializer.value8b(member.topologyVersion);
  serializer.text1b(member.topologySHA256, 64); serializer.text1b(member.canonicalPlanSHA256, 64);
  serializer.text1b(member.artifactSHA256, 64); serializer.value8b(member.artifactBytes);
  serializer.text1b(member.observationReceiptSHA256, 64);
}

static inline bool mothershipGraphReplicaPlacementSame(
    MothershipGraphReplicaPlacement left, MothershipGraphReplicaPlacement right)
{
  String a, b;
  BitseryEngine::serialize(a, left); BitseryEngine::serialize(b, right);
  return a == b;
}

class MothershipGraphReplicaRetirement {
public:
  MothershipGraphReplicaPlacement member;
  uint64_t startedGeneration = 0;
  uint64_t completedGeneration = 0;
  String cleanupReceiptSHA256;
};

template <typename S>
static void serialize(S&& serializer, MothershipGraphReplicaRetirement& retirement)
{
  serializer.object(retirement.member);
  serializer.value8b(retirement.startedGeneration); serializer.value8b(retirement.completedGeneration);
  serializer.text1b(retirement.cleanupReceiptSHA256, 64);
}

class MothershipApplicationPlacement {
public:
  enum class Policy : uint8_t { hardSingleton = 1, retainedSource = 2 };
  uint32_t version = 3;
  uint16_t applicationID = 10;
  uint128_t ownerClusterUUID = 0;
  uint64_t generation = 1;
  String observationReceiptSHA256;
  Policy policy = Policy::hardSingleton;
  Vector<MothershipGraphReplicaPlacement> graphReplicas;
  Vector<MothershipGraphReplicaRetirement> graphReplicaRetirements;
  uint128_t truthRetirementOwnerClusterUUID = 0;
  uint64_t truthRetirementExpectedGeneration = 0;
  uint64_t truthRetirementStartedGeneration = 0;
  uint64_t truthRetirementCompletedGeneration = 0;
  String truthRetirementClusterName;
  String truthRetirementInventorySHA256;
  String truthRetirementCleanupSHA256;
};

template <typename S>
static void serialize(S&& serializer, MothershipApplicationPlacement& placement)
{
  serializer.value4b(placement.version);
  serializer.value2b(placement.applicationID);
  serializer.value16b(placement.ownerClusterUUID);
  serializer.value8b(placement.generation);
  serializer.text1b(placement.observationReceiptSHA256, 64);
  serializer.value1b(placement.policy);
  // Version one is the existing retained-owner/singleton record, byte for byte.
  if (placement.version >= 2) serializer.container(placement.graphReplicas, 256);
  if (placement.version >= 3) serializer.container(placement.graphReplicaRetirements, 256);
  if (placement.version >= 4) {
    serializer.value16b(placement.truthRetirementOwnerClusterUUID);
    serializer.value8b(placement.truthRetirementExpectedGeneration);
    serializer.value8b(placement.truthRetirementStartedGeneration);
    serializer.value8b(placement.truthRetirementCompletedGeneration);
    serializer.text1b(placement.truthRetirementClusterName, UINT32_MAX);
    serializer.text1b(placement.truthRetirementInventorySHA256, 64);
    serializer.text1b(placement.truthRetirementCleanupSHA256, 64);
  }
}

class MothershipTruthLifecycleLock {
  int fd = -1;
public:
  MothershipTruthLifecycleLock() = default;
  MothershipTruthLifecycleLock(const MothershipTruthLifecycleLock&) = delete;
  MothershipTruthLifecycleLock& operator=(const MothershipTruthLifecycleLock&) = delete;
  ~MothershipTruthLifecycleLock() { if (fd >= 0) ::close(fd); }
  bool acquire(const String& registryPath, String *failure = nullptr)
  {
    if (fd >= 0 || registryPath.empty()) {
      if (failure) failure->assign("Truth lifecycle lock unavailable"_ctv);
      return false;
    }
    String path = registryPath; path.append(".truth-lifecycle.lock"_ctv);
    fd = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || ::flock(fd, LOCK_EX | LOCK_NB) != 0) {
      if (fd >= 0) { ::close(fd); fd = -1; }
      if (failure) failure->assign("Truth lifecycle lock unavailable"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }
};

class MothershipTruthRetirementMachineIdentity {
public:
  uint128_t uuid = 0;
  String cloudID;
  bool isBrain = false;
};
template <typename S>
static void serialize(S&& serializer, MothershipTruthRetirementMachineIdentity& machine)
{
  serializer.value16b(machine.uuid);
  serializer.text1b(machine.cloudID, UINT32_MAX);
  serializer.value1b(machine.isBrain);
}
class MothershipTruthRetirementInventory {
public:
  uint128_t clusterUUID = 0;
  String clusterName;
  String providerScope;
  String providerCredentialName;
  Vector<MothershipTruthRetirementMachineIdentity> machines;
};
template <typename S>
static void serialize(S&& serializer, MothershipTruthRetirementInventory& inventory)
{
  serializer.value16b(inventory.clusterUUID);
  serializer.text1b(inventory.clusterName, UINT32_MAX);
  serializer.text1b(inventory.providerScope, UINT32_MAX);
  serializer.text1b(inventory.providerCredentialName, UINT32_MAX);
  serializer.container(inventory.machines, 65536);
}

// Test clusters have no created-Vultr inventory.  Bind their complete durable
// virtual-datacenter request and observed topology under a separate domain so
// they can use the same Truth retirement transaction without weakening the
// remote-cloud inventory rule.
class MothershipTruthRetirementTestInventory {
public:
  String domain;
  uint128_t clusterUUID = 0;
  String clusterName;
  uint32_t nBrains = 0;
  MothershipProdigyClusterTestConfig test;
  uint32_t spareMachineCount = 0;
  ClusterTopology topology;
};
template <typename S>
static void serialize(S&& serializer, MothershipTruthRetirementTestInventory& inventory)
{
  serializer.text1b(inventory.domain, UINT32_MAX);
  serializer.value16b(inventory.clusterUUID);
  serializer.text1b(inventory.clusterName, UINT32_MAX);
  serializer.value4b(inventory.nBrains);
  serializer.object(inventory.test);
  serializer.value4b(inventory.spareMachineCount);
  serializer.object(inventory.topology);
}
static inline bool mothershipTruthRetirementInventoryDigest(const MothershipProdigyCluster& cluster, String& digest)
{
  digest.clear();
  if (cluster.deploymentMode == MothershipClusterDeploymentMode::remote) {
    if (cluster.clusterUUID == 0 || cluster.name.empty() || cluster.providerCredentialName.empty() ||
        cluster.provider != MothershipClusterProvider::vultr || cluster.includeLocalMachine ||
        cluster.nBrains == 0 || cluster.topology.machines.empty() || cluster.topology.machines.size() > 65536) return false;
    MothershipTruthRetirementInventory inventory;
    inventory.clusterUUID = cluster.clusterUUID; inventory.clusterName = cluster.name;
    inventory.providerScope = cluster.providerScope; inventory.providerCredentialName = cluster.providerCredentialName;
    uint32_t brains = 0;
    for (const auto& machine : cluster.topology.machines) {
      if (machine.source != ClusterMachineSource::created || machine.backing != ClusterMachineBacking::cloud ||
          machine.kind != MachineConfig::MachineKind::vm || machine.uuid == 0 || machine.cloud.cloudID.empty()) return false;
      if (machine.isBrain) ++brains;
      MothershipTruthRetirementMachineIdentity identity;
      identity.uuid = machine.uuid; identity.cloudID = machine.cloud.cloudID; identity.isBrain = machine.isBrain;
      for (const auto& prior : inventory.machines)
        if (prior.uuid == identity.uuid || prior.cloudID == identity.cloudID) return false;
      inventory.machines.push_back(std::move(identity));
    }
    if (brains != cluster.nBrains) return false;
    std::sort(inventory.machines.begin(), inventory.machines.end(),
        [](const auto& a, const auto& b) { return a.uuid < b.uuid; });
    String bytes; BitseryEngine::serialize(bytes, inventory);
    return prodigyComputeSHA256Hex(bytes, digest);
  }
  if (cluster.deploymentMode != MothershipClusterDeploymentMode::test || cluster.clusterUUID == 0 ||
      cluster.name.empty() || !cluster.test.specified || cluster.test.workspaceRoot.empty() ||
      cluster.test.machineCount == 0 || cluster.nBrains == 0 || cluster.topology.machines.empty() ||
      cluster.topology.machines.size() > 65536) return false;
  MothershipTruthRetirementTestInventory inventory;
  inventory.domain = "mothership-truth-retirement-test-inventory-v1"_ctv;
  inventory.clusterUUID = cluster.clusterUUID;
  inventory.clusterName = cluster.name;
  inventory.nBrains = cluster.nBrains;
  inventory.test = cluster.test;
  inventory.spareMachineCount = cluster.test.spareMachineCount;
  inventory.topology = cluster.topology;
  String bytes; BitseryEngine::serialize(bytes, inventory);
  return prodigyComputeSHA256Hex(bytes, digest);
}

class MothershipClusterRegistry {
private:

  TidesDB db;
  // The Vault owns clear pair BGP material.  Public TidesDB records remain
  // authority descriptors containing its SHA-256 reference only.
  MothershipPairPrivateBGPVault privateBGPVault;

  constexpr static auto clustersColumnFamily = "clusters"_ctv;
  constexpr static auto clustersByUUIDColumnFamily = "clusters_by_uuid"_ctv;
  constexpr static auto upgradeAdmissionsColumnFamily = "upgrade_admissions"_ctv;
  constexpr static auto testPairBoundariesColumnFamily = "test_pair_boundaries"_ctv;
  constexpr static auto cousinRoutesColumnFamily = "cousin_routes"_ctv;
  constexpr static auto cousinRouteReceiptsColumnFamily = "cousin_route_receipts"_ctv;
  constexpr static auto clusterPairEnrollmentsColumnFamily = "cluster_pair_enrollments"_ctv;
  constexpr static auto crossClusterMasqueGatewaysColumnFamily = "cross_cluster_masque_gateways"_ctv;
  constexpr static auto crossClusterPathFaultLifecyclesColumnFamily = "cross_cluster_path_fault_lifecycles"_ctv;
  constexpr static auto crossClusterPathFaultLifecycleHistoryColumnFamily = "cross_cluster_path_fault_lifecycle_history"_ctv;
  constexpr static auto productionPairsColumnFamily = "production_pairs"_ctv;
  constexpr static auto nametagStatefulPreparationsColumnFamily = "nametag_stateful_preparations"_ctv;
  constexpr static auto nametagAllMastersColumnFamily = "nametag_all_masters"_ctv;
  constexpr static auto applicationPlacementsColumnFamily = "application_placements"_ctv;
  constexpr static auto physicalTransitBoundariesColumnFamily = "physical_transit_boundaries"_ctv;
  constexpr static auto physicalNetworkFaultsColumnFamily = "physical_network_faults"_ctv;
  constexpr static auto localVMBoundariesColumnFamily = "local_vm_boundaries"_ctv;
  constexpr static auto localVMFaultsColumnFamily = "local_vm_faults"_ctv;
  constexpr static auto localAuthorityRecoveryCohortsColumnFamily = "local_authority_recovery_cohorts"_ctv;
  constexpr static auto localMembershipCleanupColumnFamily = "local_membership_cleanup"_ctv;
  constexpr static auto nametagQualificationReceiptsColumnFamily = "nametag_qualification_receipts"_ctv;
  constexpr static auto nametagQualificationIntentsColumnFamily = "nametag_qualification_intents"_ctv;
  constexpr static auto nametagQualificationExecutionsColumnFamily = "nametag_qualification_executions"_ctv;
  constexpr static auto nametagSourceBaselineRecordsColumnFamily = "nametag_source_baseline_records"_ctv;
  constexpr static auto nametagSourceBaselineIntentsColumnFamily = "nametag_source_baseline_intents"_ctv;
  constexpr static auto clusterRecordV2Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=2\n\n"_ctv;
  constexpr static auto clusterRecordV3Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=3\n\n"_ctv;
  constexpr static auto clusterRecordV4Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=4\n\n"_ctv;
  constexpr static auto clusterRecordV5Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=5\n\n"_ctv;
  constexpr static auto clusterRecordV6Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=6\n\n"_ctv;
  constexpr static auto clusterRecordV7Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=7\n\n"_ctv;
  constexpr static auto clusterRecordV8Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=8\n\n"_ctv;

  static void resolveDefaultDBPath(String& path)
  {
    if (const char *overridePath = getenv("PRODIGY_MOTHERSHIP_TIDESDB_PATH"); overridePath && overridePath[0] != '\0')
    {
      path.snprintf<"{}/clusters"_ctv>(String(overridePath));
      return;
    }

    if (const char *home = getenv("HOME"); home && home[0] != '\0')
    {
      path.snprintf<"{}/.prodigy/mothership/clusters"_ctv>(String(home));
      return;
    }

    path.assign("/tmp/prodigy-mothership/clusters"_ctv);
  }

  static bool localVMBoundaryPublicKeySafeForInspection(
      const MothershipLocalVMBoundaryDescriptor& descriptor)
  {
    for (char byte : descriptor.hostPublicKeyOpenSSH)
      if (static_cast<unsigned char>(byte) < 0x20 || static_cast<unsigned char>(byte) == 0x7f) return false;
    return true;
  }

  struct ClusterPairEnrollmentLock {
    int fd = -1;
    ~ClusterPairEnrollmentLock() { if (fd >= 0) ::close(fd); }
  };

  struct CousinRouteLock {
    int fd = -1;
    ~CousinRouteLock() { if (fd >= 0) ::close(fd); }
  };

  struct G6OperationLock {
    int fd = -1;
    ~G6OperationLock() { if (fd >= 0) ::close(fd); }
  };

  bool lockClusterPairEnrollment(ClusterPairEnrollmentLock& lock, String *failure) const
  {
    String path = db.path();
    path.append(".cluster-pair-enrollment.lock"_ctv);
    lock.fd = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock.fd < 0 || ::flock(lock.fd, LOCK_EX) != 0)
    {
      if (failure) failure->assign("cluster pair enrollment registry lock unavailable"_ctv);
      return false;
    }
    return true;
  }

  bool lockCousinRoutes(CousinRouteLock& lock, String *failure) const
  {
    String path = db.path();
    path.append(".cousin-route.lock"_ctv);
    lock.fd = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock.fd < 0 || ::flock(lock.fd, LOCK_EX) != 0)
    {
      if (failure) failure->assign("cousin route registry lock unavailable"_ctv);
      return false;
    }
    return true;
  }

  bool lockG6Operations(G6OperationLock& lock, String *failure) const
  {
    String path = db.path();
    path.append(".g6-operation.lock"_ctv);
    lock.fd = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock.fd < 0 || ::flock(lock.fd, LOCK_EX) != 0)
    {
      if (failure) failure->assign("G6 operation registry lock unavailable"_ctv);
      return false;
    }
    return true;
  }

  static bool nametagQualificationAdapterFrozen(const MothershipNametagQualificationAdapter& adapter)
  {
    if (adapter.operation == nullptr || adapter.rowID == nullptr) return false;
    const auto *frozen = mothershipNametagQualificationAdapter(adapter.operation);
    return frozen != nullptr && frozen->row == adapter.row && frozen->direction == adapter.direction &&
        std::strcmp(frozen->rowID, adapter.rowID) == 0 &&
        frozen->deadlineSeconds == adapter.deadlineSeconds && frozen->convergenceSeconds == adapter.convergenceSeconds;
  }

  static bool nametagQualificationKey(const MothershipNametagQualificationAdapter& adapter,
                                      uint128_t runUUID, String& key)
  {
    if (!nametagQualificationAdapterFrozen(adapter) || runUUID == 0) return false;
    key.assign(adapter.operation);
    key.append('/');
    String run = {};
    run.assignItoh(runUUID);
    key.append(run);
    return true;
  }

  static bool nametagSourceBaselineKey(uint128_t operationUUID, String& key)
  { if (operationUUID == 0) return false; key.assignItoh(operationUUID); return true; }

  static bool nametagQualificationAllMastersMatches(
      const MothershipNametagQualificationIntent& intent,
      const MothershipNametagAllMastersRecord& allMasters)
  {
    if (!mothershipNametagQualificationIntentValid(intent) ||
        !mothershipNametagAllMastersRecordValid(allMasters) ||
        intent.allMastersOperationUUID != allMasters.intent.operationUUID ||
        intent.probeTargets.size() != allMasters.intent.sites.size()) return false;
    // The all-masters record fixes the canonical EWR/ORD/LAN order. A
    // qualification intent cannot reinterpret those sites by reordering its
    // three probe targets.
    for (uint32_t site = 0; site < intent.probeTargets.size(); ++site)
      if (intent.probeTargets[site].clusterUUID != allMasters.intent.sites[site].clusterUUID) return false;
    return true;
  }

  static bool nametagQualificationReceiptMatchesIntent(
      const MothershipNametagQualificationReceipt& receipt,
      const MothershipNametagQualificationIntent& intent)
  {
    if (!mothershipNametagQualificationReceiptValid(receipt) ||
        !mothershipNametagQualificationIntentValid(intent) ||
        receipt.runUUID != intent.runUUID || receipt.row != intent.row ||
        receipt.direction != intent.direction || !receipt.rowID.equal(intent.rowID) ||
        receipt.allMastersOperationUUID != intent.allMastersOperationUUID ||
        receipt.startedAtMilliseconds != intent.startedAtMilliseconds ||
        receipt.deadlineAtMilliseconds != intent.deadlineAtMilliseconds ||
        receipt.convergenceDeadlineAtMilliseconds != intent.convergenceDeadlineAtMilliseconds ||
        receipt.applicationReceipts.size() != intent.probeTargets.size()) return false;
    for (uint32_t site = 0; site < intent.probeTargets.size(); ++site) {
      const auto& application = receipt.applicationReceipts[site];
      const auto& target = intent.probeTargets[site];
      if (application.localClusterUUID != target.clusterUUID ||
          application.deploymentID != target.probeDeploymentID) return false;
    }
    return true;
  }

  static bool nametagQualificationIntentExact(const MothershipNametagQualificationIntent& left,
                                              const MothershipNametagQualificationIntent& right)
  {
    String leftEncoded = {}, rightEncoded = {}; auto leftCopy = left; auto rightCopy = right;
    return BitseryEngine::serialize(leftEncoded, leftCopy) && BitseryEngine::serialize(rightEncoded, rightCopy) &&
        leftEncoded.equal(rightEncoded);
  }

  static bool cousinRouteReceiptKey(uint128_t routeUUID, CousinRouteHalf half, String& key)
  {
    if (routeUUID == 0 || !cousinRouteHalfValid(half)) return false;
    key.assignItoh(routeUUID);
    if (half == CousinRouteHalf::source) key.append('S');
    else key.append('D');
    return true;
  }

  static bool requireRootBootstrapSSHUser(const MothershipProdigyCluster& cluster, String *failure = nullptr)
  {
    if (cluster.bootstrapSshUser.equals(defaultMothershipClusterSSHUser()))
    {
      if (failure)
      {
        failure->clear();
      }
      return true;
    }

    if (failure)
    {
      failure->assign("automatic bootstrap requires bootstrapSshUser=root"_ctv);
    }
    return false;
  }

  static bool resolveBootstrapSSHKeyPackage(MothershipProdigyCluster& cluster, bool generateIfMissing, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }

    String generatedComment = {};
    if (cluster.clusterUUID != 0)
    {
      generatedComment.snprintf<"prodigy-bootstrap-{itoh}"_ctv>(cluster.clusterUUID);
    }
    else if (cluster.name.size() > 0)
    {
      generatedComment.snprintf<"prodigy-bootstrap-{}"_ctv>(cluster.name);
    }
    else
    {
      generatedComment.assign("prodigy-bootstrap"_ctv);
    }

    Vault::SSHKeyPackage package = {};
    if (prodigyResolveBootstrapSSHKeyPackage(
            cluster.bootstrapSshKeyPackage,
            cluster.bootstrapSshPrivateKeyPath,
            generatedComment,
            generateIfMissing,
            package,
            failure) == false)
    {
      return false;
    }

    cluster.bootstrapSshKeyPackage = std::move(package);
    if (prodigyBootstrapSSHKeyPackageConfigured(cluster.bootstrapSshKeyPackage) && cluster.bootstrapSshPrivateKeyPath.size() == 0)
    {
      cluster.bootstrapSshPrivateKeyPath.assign(prodigyDefaultBootstrapSSHPrivateKeyPath());
    }

    return true;
  }

  static bool resolveBootstrapSSHHostKeyPackage(MothershipProdigyCluster& cluster, bool generateIfMissing, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }

    String generatedComment = {};
    if (cluster.clusterUUID != 0)
    {
      generatedComment.snprintf<"prodigy-host-{itoh}"_ctv>(cluster.clusterUUID);
    }
    else if (cluster.name.size() > 0)
    {
      generatedComment.snprintf<"prodigy-host-{}"_ctv>(cluster.name);
    }
    else
    {
      generatedComment.assign("prodigy-host"_ctv);
    }

    Vault::SSHKeyPackage package = {};
    if (prodigyResolveBootstrapSSHKeyPackage(
            cluster.bootstrapSshHostKeyPackage,
            {} /* privateKeyPath */,
            generatedComment,
            generateIfMissing,
            package,
            failure) == false)
    {
      return false;
    }

    cluster.bootstrapSshHostKeyPackage = std::move(package);
    return true;
  }

  static bool recordHasHeader(const String& serialized, const auto& header)
  {
    if (serialized.size() < header.size())
    {
      return false;
    }

    for (uint64_t index = 0; index < header.size(); ++index)
    {
      if (serialized[index] != header[index])
      {
        return false;
      }
    }

    return true;
  }

  static bool deserializeClusterValue(const uint8_t *value, size_t valueSize, MothershipProdigyCluster& cluster)
  {
    cluster = {};
    String serialized;
    serialized.append(value, valueSize);

    if (recordHasHeader(serialized, clusterRecordV8Header))
    {
      String payload = {};
      payload.assign(serialized.substr(clusterRecordV8Header.size(), serialized.size() - clusterRecordV8Header.size(), Copy::yes));
      MothershipProdigyClusterRecordV8 record = {};
      if (BitseryEngine::deserializeSafe(payload, record) == false ||
          record.providerManagedBGP == false ||
          record.adoptedMachineRackUUIDs.size() != record.cluster.machines.size() ||
          record.adoptedMachineUUIDs.size() != record.cluster.machines.size() ||
          record.bgpAuthorizedOriginPrefixes.size() > 256 ||
          (record.spareMachineCount > 0 &&
           (record.cluster.deploymentMode != MothershipClusterDeploymentMode::test ||
            record.cluster.test.specified == false || record.spareMachineCount != 1 ||
            record.cluster.test.storageDeviceCount != 0 || record.cluster.test.enableFakeIpv4Boundary ||
            record.cluster.test.machineCount <= record.spareMachineCount || record.cluster.nBrains == 0 ||
           record.cluster.nBrains > record.cluster.test.machineCount - record.spareMachineCount)) ||
          (record.internalTransportProfile != MothershipInternalTransportProfile::tls &&
           record.internalTransportProfile != MothershipInternalTransportProfile::aegisX25519V1)) return false;
      record.cluster.providerManagedBGP = record.providerManagedBGP;
      if (record.bgpAuthorizedOriginPrefixes.empty() == false && !mothershipClusterBGPEnabled(record.cluster)) return false;
      for (uint32_t index = 0; index < record.cluster.machines.size(); ++index)
      {
        record.cluster.machines[index].rackUUID = record.adoptedMachineRackUUIDs[index];
        record.cluster.machines[index].uuid = record.adoptedMachineUUIDs[index];
      }
      for (uint32_t index = 0; index < record.bgpAuthorizedOriginPrefixes.size(); ++index)
      {
        const IPPrefix& prefix = record.bgpAuthorizedOriginPrefixes[index];
        if (prefix.cidr > (prefix.network.is6 ? 128 : 32) || !prefix.equals(prefix.canonicalized()) ||
            !mothershipProviderBGPOriginPrefixAllowed(prefix)) return false;
        for (uint32_t other = 0; other < index; ++other)
          if (prefix.equals(record.bgpAuthorizedOriginPrefixes[other])) return false;
      }
      if (validateClusterEnvironmentBGP(record.cluster, nullptr) == false) return false;
      record.cluster.internalTransportProfile = record.internalTransportProfile;
      record.cluster.test.spareMachineCount = record.spareMachineCount;
      record.cluster.bgpAuthorizedOriginPrefixes = std::move(record.bgpAuthorizedOriginPrefixes);
      cluster = std::move(record.cluster);
      return true;
    }

    if (recordHasHeader(serialized, clusterRecordV7Header))
    {
      String payload = {};
      payload.assign(serialized.substr(clusterRecordV7Header.size(), serialized.size() - clusterRecordV7Header.size(), Copy::yes));
      MothershipProdigyClusterRecordV7 record = {};
      if (BitseryEngine::deserializeSafe(payload, record) == false ||
          record.adoptedMachineRackUUIDs.size() != record.cluster.machines.size() ||
          record.adoptedMachineUUIDs.size() != record.cluster.machines.size() ||
          record.bgpAuthorizedOriginPrefixes.size() > 256 ||
          (record.bgpAuthorizedOriginPrefixes.empty() == false && !mothershipClusterBGPEnabled(record.cluster)) ||
          (record.spareMachineCount > 0 &&
           (record.cluster.deploymentMode != MothershipClusterDeploymentMode::test ||
            record.cluster.test.specified == false || record.spareMachineCount != 1 ||
            record.cluster.test.storageDeviceCount != 0 || record.cluster.test.enableFakeIpv4Boundary ||
            record.cluster.test.machineCount <= record.spareMachineCount || record.cluster.nBrains == 0 ||
            record.cluster.nBrains > record.cluster.test.machineCount - record.spareMachineCount)) ||
          (record.internalTransportProfile != MothershipInternalTransportProfile::tls &&
           record.internalTransportProfile != MothershipInternalTransportProfile::aegisX25519V1)) return false;
      for (uint32_t index = 0; index < record.cluster.machines.size(); ++index)
      {
        record.cluster.machines[index].rackUUID = record.adoptedMachineRackUUIDs[index];
        record.cluster.machines[index].uuid = record.adoptedMachineUUIDs[index];
      }
      for (uint32_t index = 0; index < record.bgpAuthorizedOriginPrefixes.size(); ++index)
      {
        const IPPrefix& prefix = record.bgpAuthorizedOriginPrefixes[index];
        if (prefix.cidr > (prefix.network.is6 ? 128 : 32) || !prefix.equals(prefix.canonicalized()) ||
            !mothershipProviderBGPOriginPrefixAllowed(prefix)) return false;
        for (uint32_t other = 0; other < index; ++other)
          if (prefix.equals(record.bgpAuthorizedOriginPrefixes[other])) return false;
      }
      record.cluster.internalTransportProfile = record.internalTransportProfile;
      record.cluster.test.spareMachineCount = record.spareMachineCount;
      record.cluster.providerManagedBGP = false;
      record.cluster.bgpAuthorizedOriginPrefixes = std::move(record.bgpAuthorizedOriginPrefixes);
      cluster = std::move(record.cluster);
      return true;
    }

    if (recordHasHeader(serialized, clusterRecordV6Header))
    {
      String payload = {};
      payload.assign(serialized.substr(clusterRecordV6Header.size(), serialized.size() - clusterRecordV6Header.size(), Copy::yes));
      MothershipProdigyClusterRecordV6 record = {};
      if (BitseryEngine::deserializeSafe(payload, record) == false ||
          record.cluster.deploymentMode != MothershipClusterDeploymentMode::test ||
          record.cluster.test.specified == false ||
          record.spareMachineCount != 1 ||
          record.cluster.test.storageDeviceCount != 0 || record.cluster.test.enableFakeIpv4Boundary ||
          record.cluster.test.machineCount <= record.spareMachineCount ||
          record.cluster.nBrains == 0 ||
          record.cluster.nBrains > record.cluster.test.machineCount - record.spareMachineCount ||
          record.adoptedMachineRackUUIDs.size() != record.cluster.machines.size() ||
          record.adoptedMachineUUIDs.size() != record.cluster.machines.size() ||
          (record.internalTransportProfile != MothershipInternalTransportProfile::tls &&
           record.internalTransportProfile != MothershipInternalTransportProfile::aegisX25519V1)) return false;
      for (uint32_t index = 0; index < record.cluster.machines.size(); ++index)
      {
        record.cluster.machines[index].rackUUID = record.adoptedMachineRackUUIDs[index];
        record.cluster.machines[index].uuid = record.adoptedMachineUUIDs[index];
      }
      record.cluster.internalTransportProfile = record.internalTransportProfile;
      record.cluster.test.spareMachineCount = record.spareMachineCount;
      record.cluster.providerManagedBGP = false;
      cluster = std::move(record.cluster);
      return true;
    }

    if (recordHasHeader(serialized, clusterRecordV5Header))
    {
      String payload = {};
      payload.assign(serialized.substr(clusterRecordV5Header.size(), serialized.size() - clusterRecordV5Header.size(), Copy::yes));
      MothershipProdigyClusterRecordV5 record = {};
      if (BitseryEngine::deserializeSafe(payload, record) == false ||
          record.adoptedMachineRackUUIDs.size() != record.cluster.machines.size() ||
          record.adoptedMachineUUIDs.size() != record.cluster.machines.size() ||
          (record.internalTransportProfile != MothershipInternalTransportProfile::tls &&
           record.internalTransportProfile != MothershipInternalTransportProfile::aegisX25519V1)) return false;
      for (uint32_t index = 0; index < record.cluster.machines.size(); ++index)
      {
        record.cluster.machines[index].rackUUID = record.adoptedMachineRackUUIDs[index];
        record.cluster.machines[index].uuid = record.adoptedMachineUUIDs[index];
      }
      record.cluster.internalTransportProfile = record.internalTransportProfile;
      record.cluster.providerManagedBGP = false;
      cluster = std::move(record.cluster);
      return true;
    }

    if (recordHasHeader(serialized, clusterRecordV4Header))
    {
      String payload = {};
      payload.assign(serialized.substr(clusterRecordV4Header.size(), serialized.size() - clusterRecordV4Header.size(), Copy::yes));
      MothershipProdigyClusterRecordV4 record = {};
      if (BitseryEngine::deserializeSafe(payload, record) == false ||
          record.adoptedMachineRackUUIDs.size() != record.cluster.machines.size() ||
          record.adoptedMachineUUIDs.size() != record.cluster.machines.size())
      {
        return false;
      }

      for (uint32_t index = 0; index < record.cluster.machines.size(); ++index)
      {
        record.cluster.machines[index].rackUUID = record.adoptedMachineRackUUIDs[index];
        record.cluster.machines[index].uuid = record.adoptedMachineUUIDs[index];
      }
      cluster = std::move(record.cluster);
      cluster.internalTransportProfile = MothershipInternalTransportProfile::tls;
      cluster.providerManagedBGP = false;
      return true;
    }

    if (recordHasHeader(serialized, clusterRecordV3Header))
    {
      String payload = {};
      payload.assign(serialized.substr(clusterRecordV3Header.size(), serialized.size() - clusterRecordV3Header.size(), Copy::yes));
      MothershipProdigyClusterRecordV3 record = {};
      if (BitseryEngine::deserializeSafe(payload, record) == false ||
          record.adoptedMachineRackUUIDs.size() != record.cluster.machines.size())
      {
        return false;
      }

      for (uint32_t index = 0; index < record.cluster.machines.size(); ++index)
      {
        record.cluster.machines[index].rackUUID = record.adoptedMachineRackUUIDs[index];
      }
      cluster = std::move(record.cluster);
      cluster.providerManagedBGP = false;
      return true;
    }

    if (recordHasHeader(serialized, clusterRecordV2Header))
    {
      String payload = {};
      payload.assign(serialized.substr(clusterRecordV2Header.size(), serialized.size() - clusterRecordV2Header.size(), Copy::yes));
      MothershipProdigyClusterRecordV2 record = {};
      if (BitseryEngine::deserializeSafe(payload, record) == false) return false;
      // V2 predates adopted machine identity tails. A successful historic
      // decode therefore retains the default zero rack/UUID semantics.
      cluster = std::move(record.cluster);
      cluster.mothershipConnectivity.kind = record.connectivity.kind;
      cluster.mothershipConnectivity.tunnelProvider.artifactSha256 =
          std::move(record.connectivity.tunnelProvider.artifactSHA256);
      cluster.mothershipConnectivity.tunnelProvider.artifactBytes =
          record.connectivity.tunnelProvider.artifactBytes;
      cluster.mothershipConnectivity.tunnelProvider.dialEndpoint =
          std::move(record.connectivity.tunnelProvider.dialEndpoint);
      cluster.mothershipConnectivity.tunnelProvider.egress.address4 =
          record.connectivity.tunnelProvider.egress.address4;
      cluster.mothershipConnectivity.tunnelProvider.egress.port =
          record.connectivity.tunnelProvider.egress.port;
      cluster.mothershipConnectivity.tunnelProvider.clientAuth =
          std::move(record.connectivity.tunnelProvider.clientAuth);
      cluster.providerManagedBGP = false;
      return true;
    }

    return false;
  }

  static void serializeClusterValue(const MothershipProdigyCluster& cluster, String& serialized)
  {
    MothershipProdigyClusterRecordV5 record = {};
    record.cluster = cluster;
    record.internalTransportProfile = cluster.internalTransportProfile;
    record.adoptedMachineRackUUIDs.reserve(cluster.machines.size());
    record.adoptedMachineUUIDs.reserve(cluster.machines.size());
    for (const MothershipProdigyClusterMachine& machine : cluster.machines)
    {
      record.adoptedMachineRackUUIDs.push_back(machine.rackUUID);
      record.adoptedMachineUUIDs.push_back(machine.uuid);
    }

    String payload = {};
    if (cluster.providerManagedBGP)
    {
      MothershipProdigyClusterRecordV8 recordV8 = {};
      recordV8.cluster = std::move(record.cluster);
      recordV8.adoptedMachineRackUUIDs = std::move(record.adoptedMachineRackUUIDs);
      recordV8.adoptedMachineUUIDs = std::move(record.adoptedMachineUUIDs);
      recordV8.internalTransportProfile = record.internalTransportProfile;
      recordV8.spareMachineCount = cluster.test.spareMachineCount;
      recordV8.bgpAuthorizedOriginPrefixes = cluster.bgpAuthorizedOriginPrefixes;
      recordV8.providerManagedBGP = true;
      BitseryEngine::serialize(payload, recordV8);
      serialized.assign(clusterRecordV8Header);
    }
    else if (cluster.bgpAuthorizedOriginPrefixes.empty() == false)
    {
      MothershipProdigyClusterRecordV7 recordV7 = {};
      recordV7.cluster = std::move(record.cluster);
      recordV7.adoptedMachineRackUUIDs = std::move(record.adoptedMachineRackUUIDs);
      recordV7.adoptedMachineUUIDs = std::move(record.adoptedMachineUUIDs);
      recordV7.internalTransportProfile = record.internalTransportProfile;
      recordV7.spareMachineCount = cluster.test.spareMachineCount;
      recordV7.bgpAuthorizedOriginPrefixes = cluster.bgpAuthorizedOriginPrefixes;
      BitseryEngine::serialize(payload, recordV7);
      serialized.assign(clusterRecordV7Header);
    }
    else if (cluster.test.spareMachineCount > 0)
    {
      MothershipProdigyClusterRecordV6 spareRecord = {};
      spareRecord.cluster = std::move(record.cluster);
      spareRecord.adoptedMachineRackUUIDs = std::move(record.adoptedMachineRackUUIDs);
      spareRecord.adoptedMachineUUIDs = std::move(record.adoptedMachineUUIDs);
      spareRecord.internalTransportProfile = record.internalTransportProfile;
      spareRecord.spareMachineCount = cluster.test.spareMachineCount;
      BitseryEngine::serialize(payload, spareRecord);
      serialized.assign(clusterRecordV6Header);
    }
    else if (cluster.internalTransportProfile == MothershipInternalTransportProfile::tls)
    {
      // Ordinary TLS clusters retain the record understood by older binaries.
      MothershipProdigyClusterRecordV4 legacy;
      legacy.cluster = std::move(record.cluster);
      legacy.adoptedMachineRackUUIDs = std::move(record.adoptedMachineRackUUIDs);
      legacy.adoptedMachineUUIDs = std::move(record.adoptedMachineUUIDs);
      BitseryEngine::serialize(payload, legacy);
      serialized.assign(clusterRecordV4Header);
    }
    else
    {
      BitseryEngine::serialize(payload, record);
      serialized.assign(clusterRecordV5Header);
    }
    serialized.append(payload);
  }

  static void ensureClusterUUID(MothershipProdigyCluster& cluster)
  {
    if (cluster.clusterUUID != 0)
    {
      return;
    }

    do
    {
      cluster.clusterUUID = Random::generateNumberWithNBits<128, uint128_t>();
    } while (cluster.clusterUUID == 0);
  }

  static void renderClusterUUIDKey(uint128_t clusterUUID, String& key)
  {
    key.assignItoh(clusterUUID);
  }

  // The datacenter fragment is part of every container-network IPv6 address.
  // Keep its lease in the cluster record rather than introducing a second
  // registry: one TidesDB record set is the authority for test, local, and
  // remote clusters alike.
  bool allocateDatacenterFragment(MothershipProdigyCluster& cluster, bool preserveExisting, String *failure = nullptr)
  {
    bool used[256] = {};
    Vector<String> serializedClusters = {};
    if (db.listValues(clustersColumnFamily, serializedClusters, failure) == false)
    {
      return false;
    }

    for (const String& serialized : serializedClusters)
    {
      MothershipProdigyCluster existing = {};
      if (deserializeClusterValue(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), existing) == false)
      {
        if (failure) failure->assign("cluster record decode failed while allocating datacenter fragment"_ctv);
        return false;
      }
      if (existing.clusterUUID == cluster.clusterUUID) continue;
      used[existing.datacenterFragment] = true;
      if (mothershipClusterUsesVirtualDatacenter(cluster) &&
          mothershipClusterUsesVirtualDatacenter(existing))
      {
        const String& existingRoot = existing.test.workspaceRoot;
        const String& requestedRoot = cluster.test.workspaceRoot;
        const auto containsWorkspace = [](const String& parent, const String& child) {
          return child.size() > parent.size() && child[parent.size()] == '/' &&
                 std::memcmp(parent.data(), child.data(), parent.size()) == 0;
        };
        if (existingRoot == requestedRoot || containsWorkspace(existingRoot, requestedRoot) ||
            containsWorkspace(requestedRoot, existingRoot))
        {
          if (failure) failure->assign("test workspace overlaps another cluster"_ctv);
          return false;
        }
        if (cluster.test.enableFakeIpv4Boundary || existing.test.enableFakeIpv4Boundary)
        {
          if (failure) failure->assign("test fake IPv4 boundary is single-tenant until its public boundary domain is virtualized"_ctv);
          return false;
        }
      }
    }

    if (preserveExisting)
    {
      if (cluster.datacenterFragment == 0 || used[cluster.datacenterFragment])
      {
        if (failure) failure->assign("existing cluster datacenter fragment is invalid or conflicts"_ctv);
        return false;
      }
      if (failure) failure->clear();
      return true;
    }

    // The serialized field predates an explicit "unset" marker and defaults
    // to one. Treat a colliding one as that legacy/default request so new
    // callers remain source- and wire-compatible; any other colliding value
    // is an explicit lease request and must fail closed.
    if (cluster.datacenterFragment != 0 &&
        !(cluster.datacenterFragment == 1 && used[cluster.datacenterFragment]))
    {
      if (used[cluster.datacenterFragment])
      {
        if (failure) failure->assign("cluster datacenter fragment already leased"_ctv);
        return false;
      }
      if (failure) failure->clear();
      return true;
    }

    for (uint16_t candidate = 1; candidate <= UINT8_MAX; ++candidate)
    {
      if (used[candidate] == false)
      {
        cluster.datacenterFragment = uint8_t(candidate);
        if (failure) failure->clear();
        return true;
      }
    }

    if (failure) failure->assign("datacenter fragment capacity exhausted"_ctv);
    return false;
  }

  static uint32_t implicitBrainMachineCapacity(const MothershipProdigyCluster& cluster)
  {
    if (mothershipClusterIncludesLocalMachine(cluster))
    {
      return 1;
    }

    if (cluster.deploymentMode == MothershipClusterDeploymentMode::test)
    {
      return cluster.test.initialMachineCount();
    }

    return 0;
  }

  static uint32_t effectiveBrainMachineCapacity(const MothershipProdigyCluster& cluster)
  {
    uint64_t capacity = implicitBrainMachineCapacity(cluster);

    for (const MothershipProdigyClusterMachine& machine : cluster.machines)
    {
      if (machine.isBrain)
      {
        capacity += 1;
      }
    }

    for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
    {
      capacity += managedSchema.budget;
    }

    if (capacity > UINT32_MAX)
    {
      return UINT32_MAX;
    }

    return uint32_t(capacity);
  }

  static bool clusterRequiresProdigyProviderCredential(const MothershipProdigyCluster& cluster)
  {
    if (cluster.deploymentMode != MothershipClusterDeploymentMode::remote)
    {
      return false;
    }

    if (cluster.provider == MothershipClusterProvider::gcp)
    {
      return false;
    }

    if (cluster.provider == MothershipClusterProvider::aws && cluster.aws.configured())
    {
      return false;
    }

    if (cluster.provider == MothershipClusterProvider::azure && cluster.azure.managedIdentityResourceID.size() > 0)
    {
      return false;
    }

    for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
    {
      if (managedSchema.budget > 0)
      {
        return true;
      }
    }

    return false;
  }

  static bool normalizeClusterACME(MothershipProdigyCluster& cluster, String *failure)
  {
    if (cluster.acme.configured() == false)
    {
      return true;
    }
    if (cluster.acme.accountEmail.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster ACME requires acme.accountEmail");
      }
      return false;
    }
    if (cluster.acme.termsAgreed == false)
    {
      if (failure)
      {
        failure->assign("cluster ACME requires acme.termsAgreed=true");
      }
      return false;
    }
    if (cluster.dnsProvider == MothershipClusterProvider::unknown)
    {
      if (failure)
      {
        failure->assign("cluster ACME requires cluster DNS");
      }
      return false;
    }

    if (cluster.acme.certbotInstall.size() == 0)
    {
      cluster.acme.certbotInstall.assign(prodigyCertbotManagedInstall);
    }
    if (cluster.acme.certbotPath.size() == 0)
    {
      cluster.acme.certbotPath.assign(prodigyCertbotManagedPath);
    }
    if (cluster.acme.certbotVersion.size() == 0)
    {
      cluster.acme.certbotVersion.assign(prodigyCertbotManagedVersion);
    }
    if (cluster.acme.certbotInstall.equals("bundle"_ctv) == false)
    {
      if (failure)
      {
        failure->assign("cluster ACME certbotInstall must be bundle");
      }
      return false;
    }
    if (cluster.acme.certbotPath.equals("/opt/prodigy/certbot/bin/certbot"_ctv) == false)
    {
      if (failure)
      {
        failure->assign("cluster ACME certbotPath must be /opt/prodigy/certbot/bin/certbot");
      }
      return false;
    }
    if (cluster.acme.certbotVersion.equals("5.6.0"_ctv) == false)
    {
      if (failure)
      {
        failure->assign("cluster ACME certbotVersion must be 5.6.0");
      }
      return false;
    }
    return true;
  }

  static bool parseAzureScopeTriplet(const String& scope, String& subscriptionID, String& resourceGroup, String& location)
  {
    subscriptionID.clear();
    resourceGroup.clear();
    location.clear();
    if (scope.size() == 0)
    {
      return false;
    }

    auto assignSegment = [&](const char *key, String& out) -> bool {
      String needle = {};
      needle.snprintf<"{}/"_ctv>(String(key));
      int64_t offset = -1;
      for (uint64_t index = 0; index + needle.size() <= scope.size(); ++index)
      {
        if (memcmp(scope.data() + index, needle.data(), needle.size()) == 0)
        {
          offset = int64_t(index + needle.size());
          break;
        }
      }

      if (offset < 0)
      {
        return false;
      }

      uint64_t end = scope.size();
      int64_t slash = -1;
      for (uint64_t index = uint64_t(offset); index < scope.size(); ++index)
      {
        if (scope[index] == '/')
        {
          slash = int64_t(index);
          break;
        }
      }
      if (slash >= 0)
      {
        end = uint64_t(slash);
      }

      if (end <= uint64_t(offset))
      {
        return false;
      }

      out.assign(scope.substr(uint64_t(offset), end - uint64_t(offset), Copy::yes));
      return out.size() > 0;
    };

    if (assignSegment("subscriptions", subscriptionID) && assignSegment("resourceGroups", resourceGroup))
    {
      if (assignSegment("locations", location) == false)
      {
        int64_t slash = scope.rfindChar('/');
        if (slash >= 0 && uint64_t(slash + 1) < scope.size())
        {
          location.assign(scope.substr(uint64_t(slash + 1), scope.size() - uint64_t(slash + 1), Copy::yes));
        }
      }
    }

    if (subscriptionID.size() == 0 || resourceGroup.size() == 0 || location.size() == 0)
    {
      Vector<String> parts;
      uint64_t start = 0;
      for (uint64_t index = 0; index <= scope.size(); ++index)
      {
        if (index == scope.size() || scope[index] == '/')
        {
          if (index > start)
          {
            parts.push_back(scope.substr(start, index - start, Copy::yes));
          }
          start = index + 1;
        }
      }

      if (parts.size() >= 3)
      {
        subscriptionID = parts[0];
        resourceGroup = parts[1];
        location = parts[2];
      }
    }

    return subscriptionID.size() > 0 && resourceGroup.size() > 0 && location.size() > 0;
  }

  static bool clusterHasManagedMachineSchemas(const MothershipProdigyCluster& cluster)
  {
    for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
    {
      if (managedSchema.budget > 0)
      {
        return true;
      }
    }

    return false;
  }

  static void renderManagedGcpTemplateBase(const MothershipProdigyCluster& cluster, String& templateBase)
  {
    templateBase.snprintf<"prodigy-{itoa}-gcp-template"_ctv>(uint64_t(cluster.clusterUUID));
  }

  static void renderManagedAzureIdentityBase(const MothershipProdigyCluster& cluster, String& identityBase)
  {
    identityBase.snprintf<"prodigy-{itoa}-azure-mi"_ctv>(uint64_t(cluster.clusterUUID));
  }

  static bool deriveAwsInstanceProfileNameFromArn(const String& arn, String& profileName)
  {
    profileName.clear();
    int64_t slash = arn.rfindChar('/');
    if (slash < 0 || uint64_t(slash + 1) >= arn.size())
    {
      return false;
    }

    profileName.assign(arn.substr(uint64_t(slash + 1), arn.size() - uint64_t(slash + 1), Copy::yes));
    return profileName.size() > 0;
  }

  static bool deriveAzureManagedIdentityNameFromResourceID(const String& resourceID, String& identityName)
  {
    identityName.clear();
    int64_t slash = resourceID.rfindChar('/');
    if (slash < 0 || uint64_t(slash + 1) >= resourceID.size())
    {
      return false;
    }

    identityName.assign(resourceID.substr(uint64_t(slash + 1), resourceID.size() - uint64_t(slash + 1), Copy::yes));
    return identityName.size() > 0;
  }

  static bool normalizeRemoteAzureManagedIdentityContract(MothershipProdigyCluster& cluster, String *failure)
  {
    if (cluster.provider != MothershipClusterProvider::azure)
    {
      if (cluster.azure.configured())
      {
        if (failure)
        {
          failure->assign("non-azure clusters must not include azure config"_ctv);
        }
        return false;
      }

      return true;
    }

    bool hasManagedSchemas = clusterHasManagedMachineSchemas(cluster);
    if (hasManagedSchemas == false)
    {
      return true;
    }

    if (cluster.propagateProviderCredentialToProdigy)
    {
      if (failure)
      {
        failure->assign("azure remote clusters must not propagate provider credentials to Prodigy"_ctv);
      }
      return false;
    }

    String subscriptionID = {};
    String resourceGroup = {};
    String location = {};
    if (parseAzureScopeTriplet(cluster.providerScope, subscriptionID, resourceGroup, location) == false)
    {
      if (failure)
      {
        failure->assign("azure providerScope requires subscription/resourceGroup/location"_ctv);
      }
      return false;
    }

    if (cluster.azure.managedIdentityName.size() == 0 && cluster.azure.managedIdentityResourceID.size() > 0)
    {
      if (deriveAzureManagedIdentityNameFromResourceID(cluster.azure.managedIdentityResourceID, cluster.azure.managedIdentityName) == false)
      {
        if (failure)
        {
          failure->assign("azure.managedIdentityResourceID must end with an identity name"_ctv);
        }
        return false;
      }
    }

    if (cluster.azure.managedIdentityName.size() == 0)
    {
      renderManagedAzureIdentityBase(cluster, cluster.azure.managedIdentityName);
    }

    if (cluster.azure.managedIdentityResourceID.size() == 0)
    {
      cluster.azure.managedIdentityResourceID.snprintf<
          "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{}"_ctv>(
          subscriptionID,
          resourceGroup,
          cluster.azure.managedIdentityName);
    }

    return true;
  }

  static bool normalizeRemoteAwsInstanceProfileContract(MothershipProdigyCluster& cluster, String *failure)
  {
    if (cluster.provider != MothershipClusterProvider::aws)
    {
      if (cluster.aws.configured())
      {
        if (failure)
        {
          failure->assign("non-aws clusters must not include aws config"_ctv);
        }
        return false;
      }

      return true;
    }

    if (clusterHasManagedMachineSchemas(cluster) == false)
    {
      return true;
    }

    if (cluster.propagateProviderCredentialToProdigy)
    {
      if (failure)
      {
        failure->assign("aws remote clusters must not propagate provider credentials to Prodigy"_ctv);
      }
      return false;
    }

    if (cluster.aws.instanceProfileName.size() == 0 && cluster.aws.instanceProfileArn.size() == 0)
    {
      if (failure)
      {
        failure->assign("aws remote machineSchemas require aws.instanceProfileName or aws.instanceProfileArn"_ctv);
      }
      return false;
    }

    if (cluster.aws.instanceProfileName.size() == 0 && cluster.aws.instanceProfileArn.size() > 0)
    {
      if (deriveAwsInstanceProfileNameFromArn(cluster.aws.instanceProfileArn, cluster.aws.instanceProfileName) == false)
      {
        if (failure)
        {
          failure->assign("aws.instanceProfileArn must end with an instance profile name"_ctv);
        }
        return false;
      }
    }

    return true;
  }

  static bool normalizeRemoteGcpManagedTemplateContract(MothershipProdigyCluster& cluster, String *failure)
  {
    if (cluster.provider != MothershipClusterProvider::gcp)
    {
      if (cluster.gcp.configured())
      {
        if (failure)
        {
          failure->assign("non-gcp clusters must not include gcp config"_ctv);
        }
        return false;
      }

      return true;
    }

    bool hasManagedSchemas = clusterHasManagedMachineSchemas(cluster);
    if (hasManagedSchemas == false)
    {
      if (cluster.propagateProviderCredentialToProdigy)
      {
        if (failure)
        {
          failure->assign("gcp remote clusters must not propagate provider credentials to Prodigy"_ctv);
        }
        return false;
      }

      return true;
    }

    if (cluster.gcp.serviceAccountEmail.size() == 0)
    {
      if (failure)
      {
        failure->assign("gcp remote machineSchemas require gcp.serviceAccountEmail"_ctv);
      }
      return false;
    }

    if (cluster.propagateProviderCredentialToProdigy)
    {
      if (failure)
      {
        failure->assign("gcp remote clusters must not propagate provider credentials to Prodigy"_ctv);
      }
      return false;
    }

    if (cluster.gcp.network.size() == 0)
    {
      cluster.gcp.network.assign("global/networks/default"_ctv);
    }

    String templateBase = {};
    renderManagedGcpTemplateBase(cluster, templateBase);
    String sharedTemplate = {};
    sharedTemplate.snprintf<"{}-standard"_ctv>(templateBase);
    String sharedSpotTemplate = {};
    sharedSpotTemplate.snprintf<"{}-spot"_ctv>(templateBase);

    String expectedTemplate = {};
    String expectedSpotTemplate = {};

    for (MothershipProdigyClusterMachineSchema& schema : cluster.machineSchemas)
    {
      if (schema.budget == 0)
      {
        continue;
      }

      if (schema.kind != MachineConfig::MachineKind::vm)
      {
        if (failure)
        {
          failure->assign("gcp remote machineSchemas currently require kind=vm"_ctv);
        }
        return false;
      }

      if (schema.vmImageURI.size() == 0)
      {
        if (failure)
        {
          failure->assign("gcp remote machineSchemas require vmImageURI"_ctv);
        }
        return false;
      }

      if (schema.providerMachineType.size() == 0)
      {
        if (failure)
        {
          failure->assign("gcp remote machineSchemas require providerMachineType"_ctv);
        }
        return false;
      }

      if (schema.lifetime == MachineLifetime::spot)
      {
        if (schema.gcpInstanceTemplateSpot.size() == 0)
        {
          schema.gcpInstanceTemplateSpot = sharedSpotTemplate;
        }

        if (expectedSpotTemplate.size() == 0)
        {
          expectedSpotTemplate = schema.gcpInstanceTemplateSpot;
        }
        else if (schema.gcpInstanceTemplateSpot.equals(expectedSpotTemplate) == false)
        {
          if (failure)
          {
            failure->assign("gcp remote machineSchemas must share one gcpInstanceTemplateSpot"_ctv);
          }
          return false;
        }
      }
      else
      {
        if (schema.gcpInstanceTemplate.size() == 0)
        {
          schema.gcpInstanceTemplate = sharedTemplate;
        }

        if (expectedTemplate.size() == 0)
        {
          expectedTemplate = schema.gcpInstanceTemplate;
        }
        else if (schema.gcpInstanceTemplate.equals(expectedTemplate) == false)
        {
          if (failure)
          {
            failure->assign("gcp remote machineSchemas must share one gcpInstanceTemplate"_ctv);
          }
          return false;
        }
      }
    }

    if (expectedTemplate.size() > 0 && expectedSpotTemplate.size() > 0 &&
        expectedTemplate.equals(expectedSpotTemplate))
    {
      if (failure)
      {
        failure->assign("gcp standard and spot machineSchemas require distinct template names"_ctv);
      }
      return false;
    }

    return true;
  }

  static bool findClusterMachineSchema(
      const Vector<MothershipProdigyClusterMachineSchema>& machineSchemas,
      const String& schemaKey,
      MothershipProdigyClusterMachineSchema *schemaOut = nullptr)
  {
    for (const MothershipProdigyClusterMachineSchema& schema : machineSchemas)
    {
      if (schema.schema.equals(schemaKey))
      {
        if (schemaOut != nullptr)
        {
          *schemaOut = schema;
        }

        return true;
      }
    }

    return false;
  }

  static bool validateUniqueClusterMachineIdentities(const MothershipProdigyCluster& cluster, String *failure = nullptr)
  {
    for (uint32_t index = 0; index < cluster.machines.size(); ++index)
    {
      ClusterMachine machine = {};
      mothershipFillAdoptedClusterMachine(cluster.machines[index], machine);

      for (uint32_t other = index + 1; other < cluster.machines.size(); ++other)
      {
        ClusterMachine otherMachine = {};
        mothershipFillAdoptedClusterMachine(cluster.machines[other], otherMachine);
        if (machine.sameIdentityAs(otherMachine) == false)
        {
          continue;
        }

        String label = {};
        machine.renderIdentityLabel(label);
        if (failure)
        {
          failure->snprintf<"cluster machines contain duplicate identity '{}'"_ctv>(label);
        }
        return false;
      }
    }

    return true;
  }

  static void collectClaimedClusterMachines(const MothershipProdigyCluster& cluster, Vector<ClusterMachine>& claimedMachines)
  {
    claimedMachines.clear();

    auto appendUnique = [&](const ClusterMachine& claimedMachine) -> void {
      for (const ClusterMachine& existingMachine : claimedMachines)
      {
        if (existingMachine.sameIdentityAs(claimedMachine))
        {
          return;
        }
      }

      claimedMachines.push_back(claimedMachine);
    };

    for (const MothershipProdigyClusterMachine& machine : cluster.machines)
    {
      ClusterMachine claimedMachine = {};
      mothershipFillAdoptedClusterMachine(machine, claimedMachine);
      appendUnique(claimedMachine);
    }

    for (const ClusterMachine& machine : cluster.topology.machines)
    {
      appendUnique(machine);
    }
  }

  static bool validateClusterMachineSchemaCoverage(const MothershipProdigyCluster& cluster, String *failure = nullptr)
  {
    for (uint32_t index = 0; index < cluster.machineSchemas.size(); ++index)
    {
      const MothershipProdigyClusterMachineSchema& schema = cluster.machineSchemas[index];
      if (schema.schema.size() == 0)
      {
        if (failure)
        {
          failure->assign("cluster machineSchemas require schema"_ctv);
        }
        return false;
      }

      for (uint32_t other = index + 1; other < cluster.machineSchemas.size(); ++other)
      {
        if (cluster.machineSchemas[other].schema.equals(schema.schema))
        {
          if (failure)
          {
            failure->snprintf<"cluster machineSchemas contain duplicate schema '{}'"_ctv>(schema.schema);
          }
          return false;
        }
      }
    }

    auto requireSchema = [&](const String& schemaKey, MachineConfig::MachineKind kind, const char *what) -> bool {
      if (schemaKey.size() == 0)
      {
        if (failure)
        {
          failure->snprintf<"cluster {} requires cloud.schema"_ctv>(String(what));
        }
        return false;
      }

      MothershipProdigyClusterMachineSchema schema = {};
      if (findClusterMachineSchema(cluster.machineSchemas, schemaKey, &schema) == false)
      {
        if (failure)
        {
          failure->snprintf<"cluster {} references unknown machineSchema '{}'"_ctv>(String(what), schemaKey);
        }
        return false;
      }

      if (schema.kind != kind)
      {
        if (failure)
        {
          failure->snprintf<"cluster {} kind mismatch for machineSchema '{}'"_ctv>(String(what), schemaKey);
        }
        return false;
      }

      return true;
    };

    for (const MothershipProdigyClusterMachine& machine : cluster.machines)
    {
      if (machine.backing == ClusterMachineBacking::cloud && requireSchema(machine.cloud.schema, machine.kind, "machine") == false)
      {
        return false;
      }
    }

    for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
    {
      if (requireSchema(managedSchema.schema, managedSchema.kind, "schema") == false)
      {
        return false;
      }
    }

    return true;
  }

  static bool normalizeMachineForStorage(MothershipProdigyClusterMachine& machine, const MothershipProdigyCluster& cluster, String *failure)
  {
    Vector<ClusterMachineAddress> normalizedPrivateAddresses = {};
    Vector<ClusterMachineAddress> normalizedPublicAddresses = {};
    for (const ClusterMachineAddress& address : machine.addresses.privateAddresses)
    {
      prodigyAppendUniqueClusterMachineAddress(normalizedPrivateAddresses, address);
    }
    for (const ClusterMachineAddress& address : machine.addresses.publicAddresses)
    {
      prodigyAppendUniqueClusterMachineAddress(normalizedPublicAddresses, address);
    }
    machine.addresses.privateAddresses = std::move(normalizedPrivateAddresses);
    machine.addresses.publicAddresses = std::move(normalizedPublicAddresses);

    if (machine.source != MothershipClusterMachineSource::adopted)
    {
      if (failure)
      {
        failure->assign("cluster machines must be adopted");
      }
      return false;
    }

    if (machine.ssh.address.size() == 0)
    {
      if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(machine.addresses.privateAddresses); privateAddress != nullptr)
      {
        machine.ssh.address = privateAddress->address;
      }
      else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(machine.addresses.publicAddresses); publicAddress != nullptr)
      {
        machine.ssh.address = publicAddress->address;
      }
    }

    if (machine.ssh.address.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster machines require sshAddress");
      }
      return false;
    }

    if (machine.ssh.port == 0)
    {
      machine.ssh.port = 22;
    }

    if (machine.ssh.user.size() == 0)
    {
      if (cluster.bootstrapSshUser.size() > 0)
      {
        machine.ssh.user = cluster.bootstrapSshUser;
      }
      else
      {
        machine.ssh.user.assign(defaultMothershipClusterSSHUser());
      }
    }

    if (machine.ssh.privateKeyPath.size() == 0)
    {
      machine.ssh.privateKeyPath = cluster.bootstrapSshPrivateKeyPath;
    }

    if (machine.ssh.privateKeyPath.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster machines require sshPrivateKeyPath");
      }
      return false;
    }

    if (machine.ssh.hostPublicKeyOpenSSH.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster machines require ssh.hostPublicKeyOpenSSH");
      }
      return false;
    }

    if (machine.backing == ClusterMachineBacking::cloud)
    {
      if (machine.cloudPresent() == false)
      {
        if (failure)
        {
          failure->assign("cloud cluster machines require cloud");
        }
        return false;
      }

      if (machine.lifetime == MachineLifetime::owned)
      {
        if (failure)
        {
          failure->assign("cloud cluster machines must not use lifetime=owned");
        }
        return false;
      }

      if (machine.cloud.schema.size() == 0)
      {
        if (failure)
        {
          failure->assign("cloud cluster machines require cloud.schema");
        }
        return false;
      }

      if (machine.cloud.providerMachineType.size() == 0)
      {
        if (failure)
        {
          failure->assign("cloud cluster machines require cloud.providerMachineType");
        }
        return false;
      }

      if (machine.cloud.cloudID.size() == 0)
      {
        if (failure)
        {
          failure->assign("cloud cluster machines require cloud.cloudID");
        }
        return false;
      }
    }
    else
    {
      if (machine.cloudPresent())
      {
        if (failure)
        {
          failure->assign("owned cluster machines must not include cloud fields");
        }
        return false;
      }
    }

    return true;
  }

  static bool validateClusterEnvironmentBGP(const MothershipProdigyCluster& cluster, String *failure)
  {
    const ProdigyEnvironmentBGPConfig& bgp = cluster.bgp;
    if (cluster.providerManagedBGP)
    {
      if (mothershipClusterUsesProviderManagedBGP(cluster)) return true;
      if (failure) failure->assign("invalid provider-managed bgp intent"_ctv);
      return false;
    }
    if (bgp.configured() == false)
    {
      return true;
    }

    const NeuronBGPConfig& config = bgp.config;
    if (config.enabled == false)
    {
      if (config.ourBGPID != 0 || config.community != 0 || config.nextHop4.isNull() == false || config.nextHop6.isNull() == false || config.peers.empty() == false)
      {
        if (failure)
        {
          failure->assign("disabled bgp must not include peer or nextHop settings");
        }
        return false;
      }

      return true;
    }

    if (config.nextHop4.isNull() == false && config.nextHop4.is6)
    {
      if (failure)
      {
        failure->assign("bgp.nextHop4 must be ipv4");
      }
      return false;
    }

    if (config.nextHop6.isNull() == false && config.nextHop6.is6 == false)
    {
      if (failure)
      {
        failure->assign("bgp.nextHop6 must be ipv6");
      }
      return false;
    }

    if (config.peers.empty())
    {
      if (failure)
      {
        failure->assign("bgp.enabled requires peers");
      }
      return false;
    }

    if (config.nextHop4.isNull() && config.nextHop6.isNull())
    {
      if (failure)
      {
        failure->assign("bgp.enabled requires nextHop4 or nextHop6");
      }
      return false;
    }

    for (const NeuronBGPPeerConfig& peer : config.peers)
    {
      if (peer.peerASN == 0)
      {
        if (failure)
        {
          failure->assign("bgp.peers require peerASN");
        }
        return false;
      }

      if (peer.peerAddress.isNull())
      {
        if (failure)
        {
          failure->assign("bgp.peers require peerAddress");
        }
        return false;
      }

      if (peer.sourceAddress.isNull())
      {
        if (failure)
        {
          failure->assign("bgp.peers require sourceAddress");
        }
        return false;
      }
    }

    return true;
  }

  static bool validateOSUpdatePoliciesForStorage(const Vector<OperatingSystemUpdatePolicy>& policies, String *failure)
  {
    for (uint32_t index = 0; index < policies.size(); ++index)
    {
      const OperatingSystemUpdatePolicy& policy = policies[index];
      if (policy.osID.size() == 0)
      {
        if (failure)
        {
          failure->assign("osUpdatePolicies require osID");
        }
        return false;
      }

      if (policy.targetVersionID.size() == 0)
      {
        if (failure)
        {
          failure->assign("osUpdatePolicies require targetVersionID");
        }
        return false;
      }

      if (policy.command.size() == 0)
      {
        if (failure)
        {
          failure->assign("osUpdatePolicies require command");
        }
        return false;
      }

      for (uint32_t other = index + 1; other < policies.size(); ++other)
      {
        if (policies[other].osID.equals(policy.osID))
        {
          if (failure)
          {
            failure->assign("osUpdatePolicies contain duplicate osID");
          }
          return false;
        }
      }
    }

    return true;
  }

  static bool normalizeMothershipConnectivityForStorage(MothershipProdigyCluster& cluster, String *failure)
  {
    if (cluster.mothershipConnectivity.kind == MothershipConnectivityKind::ssh)
    {
      cluster.mothershipConnectivity.tunnelProvider = {};
      return true;
    }

    if (cluster.mothershipConnectivity.kind != MothershipConnectivityKind::tunnelProvider)
    {
      if (failure)
      {
        failure->assign("mothershipConnectivity.kind invalid");
      }
      return false;
    }

    MothershipTunnelProviderSpec& spec = cluster.mothershipConnectivity.tunnelProvider;
    if (mothershipTunnelProviderSpecValid(spec, failure) == false)
    {
      return false;
    }

    MothershipTunnelGatewayTLSContext clientTLS = {};
    if (clientTLS.configure(spec.clientAuth) == false)
    {
      if (failure)
      {
        failure->assign("tunnelProvider.clientAuth certificate material invalid");
      }
      return false;
    }

    return true;
  }

  static bool normalizeClusterForStorage(MothershipProdigyCluster& cluster, String *failure)
  {
    if (cluster.name.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster name required");
      }
      return false;
    }

    ensureClusterUUID(cluster);

    if (cluster.nBrains == 0)
    {
      cluster.nBrains = 1;
    }

    if (cluster.deploymentMode == MothershipClusterDeploymentMode::local || mothershipClusterUsesVirtualDatacenter(cluster))
    {
      MachineCpuArchitecture localArchitecture = nametagCurrentBuildMachineArchitecture();
      if (cluster.architecture == MachineCpuArchitecture::unknown)
      {
        cluster.architecture = localArchitecture;
      }
      else if (cluster.architecture != localArchitecture)
      {
        if (failure)
        {
          failure->assign("local and test cluster architecture must match Mothership"_ctv);
        }
        return false;
      }
    }

    if (cluster.sharedCPUOvercommitPermille < prodigySharedCPUOvercommitMinPermille || cluster.sharedCPUOvercommitPermille > prodigySharedCPUOvercommitMaxPermille)
    {
      if (failure)
      {
        failure->assign("sharedCpuOvercommit must be in 1.0..2.0");
      }
      return false;
    }

    if (mothershipClusterUsesVirtualDatacenter(cluster))
    {
      if (cluster.test.specified == false)
      {
        if (failure)
        {
          failure->assign("test clusters require test config");
        }
        return false;
      }

      if (cluster.provider != MothershipClusterProvider::unknown)
      {
        if (failure)
        {
          failure->assign("test clusters must not include provider");
        }
        return false;
      }

      if (cluster.providerCredentialName.size() > 0)
      {
        if (failure)
        {
          failure->assign("test clusters must not include providerCredentialName");
        }
        return false;
      }

      if (cluster.providerScope.size() > 0)
      {
        if (failure)
        {
          failure->assign("test clusters must not include providerScope");
        }
        return false;
      }

      if (cluster.propagateProviderCredentialToProdigy)
      {
        if (failure)
        {
          failure->assign("test clusters must not include propagateProviderCredentialToProdigy");
        }
        return false;
      }

      if (cluster.gcp.configured())
      {
        if (failure)
        {
          failure->assign("test clusters must not include gcp config"_ctv);
        }
        return false;
      }

      if (cluster.azure.configured())
      {
        if (failure)
        {
          failure->assign("test clusters must not include azure config"_ctv);
        }
        return false;
      }

      if (mothershipTestClusterWorkspaceRootValid(cluster.test.workspaceRoot) == false)
      {
        if (failure)
        {
          failure->assign("test clusters require absolute test.workspaceRoot");
        }
        return false;
      }

      if (cluster.test.machineCount == 0)
      {
        if (failure)
        {
          failure->assign("test clusters require test.machineCount");
        }
        return false;
      }

      if (cluster.test.machineLogicalCores == 0 || cluster.test.machineLogicalCores > mothershipTestClusterMachineLogicalCoresMax ||
          cluster.test.machineMemoryMB == 0 || cluster.test.machineMemoryMB > mothershipTestClusterMachineMemoryMBMax ||
          cluster.test.machineStorageMB == 0 || cluster.test.machineStorageMB > mothershipTestClusterMachineStorageMBMax ||
          cluster.test.storageDeviceCount > mothershipTestClusterStorageDeviceCountMax ||
          (cluster.test.storageDeviceCount > 0 && (cluster.test.storageDeviceMB == 0 || cluster.test.storageDeviceMB > mothershipTestClusterMachineStorageMBMax)))
      {
        if (failure)
        {
          failure->assign("test machine resources are outside supported bounds"_ctv);
        }
        return false;
      }

      if (cluster.test.interContainerMTU != 0 && (cluster.test.interContainerMTU < prodigyRuntimeTestInterContainerMTUMin || cluster.test.interContainerMTU > prodigyRuntimeTestInterContainerMTUMax))
      {
        if (failure)
        {
          failure->assign("test.interContainerMTU must be 0 or between 1280 and 65535");
        }
        return false;
      }

      if (cluster.test.spareMachineCount > 1)
      {
        if (failure)
        {
          failure->assign("test.spareMachineCount must be 0 or 1");
        }
        return false;
      }

      if (cluster.test.spareMachineCount != 0 &&
          (cluster.test.storageDeviceCount != 0 || cluster.test.enableFakeIpv4Boundary))
      {
        if (failure) failure->assign("test SSH spare requires no additional storage devices and no fake IPv4 boundary"_ctv);
        return false;
      }

      const uint32_t initialMachineCount = cluster.test.initialMachineCount();
      if (initialMachineCount == 0 || cluster.nBrains > initialMachineCount)
      {
        if (failure)
        {
          failure->assign("test.machineCount minus spareMachineCount is below nBrains");
        }
        return false;
      }

      if (cluster.test.spareMachineCount == 0)
      {
        cluster.remoteProdigyPath.clear();
      }
      else
      {
        if (cluster.bootstrapSshUser.size() == 0)
        {
          cluster.bootstrapSshUser.assign(defaultMothershipClusterSSHUser());
        }
        if (requireRootBootstrapSSHUser(cluster, failure) == false ||
            resolveBootstrapSSHKeyPackage(cluster, true, failure) == false ||
            resolveBootstrapSSHHostKeyPackage(cluster, true, failure) == false)
        {
          return false;
        }
        if (cluster.remoteProdigyPath.size() == 0)
        {
          cluster.remoteProdigyPath.assign(defaultMothershipRemoteProdigyPath());
        }
      }

      if (cluster.controls.empty() == false)
      {
        if (failure)
        {
          failure->assign("test clusters manage controls automatically");
        }
        return false;
      }

      if (cluster.machines.empty() == false)
      {
        if (failure)
        {
          failure->assign("test clusters must not include machines");
        }
        return false;
      }

      if (cluster.test.spareMachineCount == 0)
      {
        cluster.bootstrapSshUser.clear();
        cluster.bootstrapSshKeyPackage.clear();
        cluster.bootstrapSshHostKeyPackage.clear();
        cluster.bootstrapSshPrivateKeyPath.clear();
      }
      mothershipResolveTestClusterControlRecord(cluster.controls, cluster);
    }
    else if (cluster.test.specified)
    {
      if (failure)
      {
        failure->assign("non-test clusters must not include test config");
      }
      return false;
    }

    if (cluster.controls.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster controls required");
      }
      return false;
    }

    for (MothershipProdigyClusterControl& control : cluster.controls)
    {
      if (control.kind == MothershipClusterControlKind::unixSocket)
      {
        if (control.path.size() == 0)
        {
          if (failure)
          {
            failure->assign("unixSocket control requires path");
          }
          return false;
        }
      }
      else
      {
        if (failure)
        {
          failure->assign("unsupported cluster control kind");
        }
        return false;
      }
    }

    if (validateClusterEnvironmentBGP(cluster, failure) == false)
    {
      return false;
    }

    if (normalizeMothershipConnectivityForStorage(cluster, failure) == false)
    {
      return false;
    }

    if (cluster.datacenterFragment == 0)
    {
      if (failure)
      {
        failure->assign("cluster datacenterFragment must be in 1..255");
      }
      return false;
    }

    if (cluster.autoscaleIntervalSeconds == 0 || cluster.autoscaleIntervalSeconds > 86'400)
    {
      if (failure)
      {
        failure->assign("cluster autoscaleIntervalSeconds must be in 1..86400");
      }
      return false;
    }

    if ((cluster.dnsProvider == MothershipClusterProvider::unknown) != (cluster.dnsProviderCredentialName.size() == 0))
    {
      if (failure)
      {
        failure->assign("cluster DNS requires both dnsProvider and dnsProviderCredentialName");
      }
      return false;
    }

    if (cluster.dnsProvider != MothershipClusterProvider::unknown && mothershipClusterProviderIsDNS(cluster.dnsProvider) == false)
    {
      if (failure)
      {
        failure->assign("cluster dnsProvider must be cloudflare, route53, gcp-cloud-dns, azure-dns, or vultr-dns");
      }
      return false;
    }

    if (normalizeClusterACME(cluster, failure) == false)
    {
      return false;
    }

    if (validateOSUpdatePoliciesForStorage(cluster.osUpdatePolicies, failure) == false)
    {
      return false;
    }

    if (cluster.osUpdatesEnabled && cluster.osUpdatePolicies.empty())
    {
      if (failure)
      {
        failure->assign("osUpdatesEnabled requires osUpdatePolicies");
      }
      return false;
    }

    if (cluster.deploymentMode != MothershipClusterDeploymentMode::local)
    {
      cluster.includeLocalMachine = false;
    }

    if (cluster.deploymentMode == MothershipClusterDeploymentMode::local)
    {
      if (cluster.provider != MothershipClusterProvider::unknown)
      {
        if (failure)
        {
          failure->assign("local clusters must not include provider");
        }
        return false;
      }

      if (cluster.providerCredentialName.size() > 0)
      {
        if (failure)
        {
          failure->assign("local clusters must not include providerCredentialName");
        }
        return false;
      }

      if (cluster.providerScope.size() > 0)
      {
        if (failure)
        {
          failure->assign("local clusters must not include providerScope");
        }
        return false;
      }

      if (cluster.propagateProviderCredentialToProdigy)
      {
        if (failure)
        {
          failure->assign("local clusters must not include propagateProviderCredentialToProdigy");
        }
        return false;
      }

      if (cluster.gcp.configured())
      {
        if (failure)
        {
          failure->assign("local clusters must not include gcp config"_ctv);
        }
        return false;
      }

      if (cluster.azure.configured())
      {
        if (failure)
        {
          failure->assign("local clusters must not include azure config"_ctv);
        }
        return false;
      }

      uint32_t adoptedMachines = 0;
      for (MothershipProdigyClusterMachine& machine : cluster.machines)
      {
        if (normalizeMachineForStorage(machine, cluster, failure) == false)
        {
          return false;
        }

        adoptedMachines += 1;
      }

      if (cluster.includeLocalMachine == false && adoptedMachines == 0)
      {
        if (failure)
        {
          failure->assign("local clusters without includeLocalMachine require adopted machines");
        }
        return false;
      }

      if (adoptedMachines == 0)
      {
        cluster.bootstrapSshUser.clear();
        cluster.bootstrapSshKeyPackage.clear();
        cluster.bootstrapSshHostKeyPackage.clear();
        cluster.bootstrapSshPrivateKeyPath.clear();
        cluster.remoteProdigyPath.clear();
      }
      else
      {
        if (cluster.bootstrapSshUser.size() == 0)
        {
          cluster.bootstrapSshUser.assign(defaultMothershipClusterSSHUser());
        }

        if (requireRootBootstrapSSHUser(cluster, failure) == false)
        {
          return false;
        }

        if (cluster.bootstrapSshPrivateKeyPath.size() == 0)
        {
          if (failure)
          {
            failure->assign("local clusters with adopted machines require bootstrapSshPrivateKeyPath");
          }
          return false;
        }

        // Seed-only local clusters intentionally scrub unused bootstrap
        // credentials.  When adopted machines are added later, restore the
        // typed package from the explicitly supplied path before reconciliation
        // so SSH never falls back to an unvalidated path-only identity.
        if (resolveBootstrapSSHKeyPackage(cluster, false, failure) == false)
        {
          return false;
        }

        if (cluster.remoteProdigyPath.size() == 0)
        {
          cluster.remoteProdigyPath.assign(defaultMothershipRemoteProdigyPath());
        }
      }

      if (effectiveBrainMachineCapacity(cluster) < cluster.nBrains)
      {
        if (failure)
        {
          failure->assign("brain capacity is below nBrains");
        }
        return false;
      }
    }
    else if (cluster.deploymentMode == MothershipClusterDeploymentMode::test)
    {
      if (effectiveBrainMachineCapacity(cluster) < cluster.nBrains)
      {
        if (failure)
        {
          failure->assign("brain capacity is below nBrains");
        }
        return false;
      }
    }
    else
    {
      if (cluster.bgp.configured())
      {
        if (mothershipClusterProviderSupportsManagedBGP(cluster.provider) == false)
        {
          if (failure)
          {
            failure->assign("remote cluster provider does not support bgp");
          }
          return false;
        }
      }

      if (cluster.provider == MothershipClusterProvider::unknown)
      {
        if (failure)
        {
          failure->assign("remote clusters require provider");
        }
        return false;
      }

      if (mothershipClusterProviderIsIaaS(cluster.provider) == false)
      {
        if (failure)
        {
          failure->assign("remote cluster provider must be gcp, aws, azure, or vultr");
        }
        return false;
      }

      if (prodigyMachineCpuArchitectureSupportedTarget(cluster.architecture) == false)
      {
        if (failure)
        {
          failure->assign("remote clusters require architecture=x86_64|aarch64");
        }
        return false;
      }

      if (cluster.providerCredentialName.size() == 0)
      {
        if (failure)
        {
          failure->assign("remote clusters require providerCredentialName");
        }
        return false;
      }

      if (cluster.bootstrapSshUser.size() == 0)
      {
        cluster.bootstrapSshUser.assign(defaultMothershipClusterSSHUser());
      }

      if (requireRootBootstrapSSHUser(cluster, failure) == false)
      {
        return false;
      }

      if (resolveBootstrapSSHKeyPackage(cluster, true, failure) == false)
      {
        return false;
      }

      if (resolveBootstrapSSHHostKeyPackage(cluster, true, failure) == false)
      {
        return false;
      }

      if (cluster.bootstrapSshPrivateKeyPath.size() == 0)
      {
        if (failure)
        {
          failure->assign("remote clusters require bootstrap ssh private key install path");
        }
        return false;
      }

      if (cluster.remoteProdigyPath.size() == 0)
      {
        cluster.remoteProdigyPath.assign(defaultMothershipRemoteProdigyPath());
      }

      if (normalizeRemoteAwsInstanceProfileContract(cluster, failure) == false)
      {
        return false;
      }

      if (normalizeRemoteGcpManagedTemplateContract(cluster, failure) == false)
      {
        return false;
      }

      if (normalizeRemoteAzureManagedIdentityContract(cluster, failure) == false)
      {
        return false;
      }

      for (uint32_t index = 0; index < cluster.machineSchemas.size(); ++index)
      {
        MothershipProdigyClusterMachineSchema& schema = cluster.machineSchemas[index];

        if (schema.schema.size() == 0)
        {
          if (failure)
          {
            failure->assign("cluster machineSchemas require schema");
          }
          return false;
        }

        if (schema.lifetime == MachineLifetime::owned)
        {
          if (failure)
          {
            failure->assign("cluster machineSchemas must not use lifetime=owned");
          }
          return false;
        }

        if (schema.providerMachineType.size() == 0)
        {
          if (failure)
          {
            failure->assign("cluster machineSchemas require providerMachineType");
          }
          return false;
        }

        if (schema.cpu.architecture == MachineCpuArchitecture::unknown)
        {
          if (failure)
          {
            failure->snprintf<"cluster machineSchema '{}' is missing inferred cpu architecture"_ctv>(schema.schema);
          }
          return false;
        }

        if (schema.cpu.architecture != cluster.architecture)
        {
          if (failure)
          {
            failure->snprintf<"cluster machineSchema '{}' architecture '{}' does not match cluster architecture '{}'"_ctv>(
                schema.schema,
                String(machineCpuArchitectureName(schema.cpu.architecture)),
                String(machineCpuArchitectureName(cluster.architecture)));
          }
          return false;
        }

        for (uint32_t other = index + 1; other < cluster.machineSchemas.size(); ++other)
        {
          if (cluster.machineSchemas[other].schema.equals(schema.schema))
          {
            if (failure)
            {
              failure->snprintf<"cluster machineSchemas contain duplicate schema '{}'"_ctv>(schema.schema);
            }
            return false;
          }
        }
      }

      if (clusterRequiresProdigyProviderCredential(cluster) && cluster.propagateProviderCredentialToProdigy == false)
      {
        if (failure)
        {
          failure->assign("clusters with machineSchemas require propagateProviderCredentialToProdigy");
        }
        return false;
      }

      uint32_t adoptedMachines = 0;
      for (MothershipProdigyClusterMachine& machine : cluster.machines)
      {
        if (normalizeMachineForStorage(machine, cluster, failure) == false)
        {
          return false;
        }

        if (machine.source == MothershipClusterMachineSource::adopted)
        {
          adoptedMachines += 1;
        }
      }

      if (adoptedMachines == 0 && cluster.machineSchemas.size() == 0)
      {
        if (failure)
        {
          failure->assign("remote clusters require adopted machines or machineSchemas");
        }
        return false;
      }

      if (effectiveBrainMachineCapacity(cluster) < cluster.nBrains)
      {
        if (failure)
        {
          failure->assign("brain capacity is below nBrains");
        }
        return false;
      }
    }

    if (validateUniqueClusterMachineIdentities(cluster, failure) == false)
    {
      return false;
    }

    if (validateClusterMachineSchemaCoverage(cluster, failure) == false)
    {
      return false;
    }

    if (cluster.desiredEnvironment == ProdigyEnvironmentKind::unknown && (cluster.deploymentMode == MothershipClusterDeploymentMode::local || cluster.deploymentMode == MothershipClusterDeploymentMode::test))
    {
      cluster.desiredEnvironment = ProdigyEnvironmentKind::dev;
    }

    if (cluster.environmentConfigured && cluster.desiredEnvironment == ProdigyEnvironmentKind::unknown)
    {
      if (failure)
      {
        failure->assign("environmentConfigured requires desiredEnvironment");
      }
      return false;
    }

    return true;
  }

public:

  // Serializes the registry authorization decision with the corresponding
  // Brain registration RPC.  This is intentionally a process-shared lock:
  // Mothership commands are separate processes, so a process-local mutex
  // would allow a revoke to race an already-authorized registration.
  struct BGPOriginPolicyLock {
    int fd = -1;
    BGPOriginPolicyLock() = default;
    BGPOriginPolicyLock(const BGPOriginPolicyLock&) = delete;
    BGPOriginPolicyLock& operator=(const BGPOriginPolicyLock&) = delete;
    ~BGPOriginPolicyLock() { if (fd >= 0) ::close(fd); }
  };

  bool lockBGPOriginPolicy(BGPOriginPolicyLock& lock, String *failure = nullptr) const
  {
    String path = db.path();
    path.append(".bgp-origin-policy.lock"_ctv);
    lock.fd = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock.fd < 0 || ::flock(lock.fd, LOCK_EX) != 0)
    {
      if (failure) failure->assign("BGP origin policy registry lock unavailable"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  static bool validateClusterForStorage(const MothershipProdigyCluster& cluster, MothershipProdigyCluster& normalizedCluster, String *failure = nullptr)
  {
    MothershipProdigyCluster candidate = cluster;
    if (normalizeClusterForStorage(candidate, failure) == false)
    {
      return false;
    }

    normalizedCluster = std::move(candidate);
    return true;
  }

  explicit MothershipClusterRegistry(const String& path = ""_ctv)
      : db(path.size() > 0 ? path : []() -> String {
          String resolved;
          resolveDefaultDBPath(resolved);
          return resolved;
        }(), TidesDB::Durability::full)
  {
  }

  const String& path(void)
  {
    return db.path();
  }

  bool loadLocalMembershipCleanup(uint128_t clusterUUID, MothershipLocalMembershipCleanupRecord& record, String *failure = nullptr)
  {
    record = {}; String key = {}, encoded = {}; key.assignItoh(clusterUUID);
    if (!db.read(localMembershipCleanupColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, record) ||
        !mothershipLocalMembershipCleanupRecordValid(record) || record.clusterUUID != clusterUUID)
    {
      record = {};
      if (failure) failure->assign("local membership cleanup record is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool admitLocalMembershipCleanup(const MothershipLocalMembershipCleanupRecord& requested,
                                   MothershipLocalMembershipCleanupRecord& recorded,
                                   bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipLocalMembershipCleanupRecordValid(requested) || requested.membershipCommitted)
    {
      if (failure) failure->assign("local membership cleanup admission is invalid"_ctv);
      return false;
    }
    for (const auto& entry : requested.machines) if (entry.cleaned)
    {
      if (failure) failure->assign("local membership cleanup admission cannot start completed"_ctv);
      return false;
    }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}, readFailure = {}; key.assignItoh(requested.clusterUUID);
    if (db.read(localMembershipCleanupColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !mothershipLocalMembershipCleanupRecordValid(recorded) ||
          !mothershipLocalMembershipCleanupIntentEqual(recorded, requested))
      {
        recorded = {};
        if (failure) failure->assign("local membership cleanup conflicts with the open operation"_ctv);
        return false;
      }
      resumed = true;
      if (failure) failure->clear();
      return true;
    }
    if (!readFailure.equal("record not found"_ctv))
    { if (failure) *failure = readFailure; return false; }
    recorded = requested;
    auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(localMembershipCleanupColumnFamily, key, encoded, failure))
    { recorded = {}; return false; }
    if (failure) failure->clear();
    return true;
  }

  bool commitLocalMembershipCleanup(uint128_t clusterUUID, const String& desiredSpecSHA256,
                                    MothershipLocalMembershipCleanupRecord& recorded,
                                    bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) ||
        !loadLocalMembershipCleanup(clusterUUID, recorded, failure)) return false;
    if (recorded.desiredSpecSHA256 != desiredSpecSHA256)
    { if (failure) failure->assign("local membership cleanup desired specification conflicts"_ctv); return false; }
    if (recorded.membershipCommitted)
    { resumed = true; if (failure) failure->clear(); return true; }
    recorded.membershipCommitted = true;
    String key = {}, encoded = {}; key.assignItoh(clusterUUID);
    auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(localMembershipCleanupColumnFamily, key, encoded, failure)) return false;
    if (failure) failure->clear();
    return true;
  }

  bool completeLocalMembershipCleanupMachine(uint128_t clusterUUID, const String& desiredSpecSHA256,
                                             uint32_t machineIndex,
                                             MothershipLocalMembershipCleanupRecord& recorded,
                                             bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) ||
        !loadLocalMembershipCleanup(clusterUUID, recorded, failure)) return false;
    if (recorded.desiredSpecSHA256 != desiredSpecSHA256 || !recorded.membershipCommitted ||
        machineIndex >= recorded.machines.size())
    { if (failure) failure->assign("local membership cleanup progress conflicts"_ctv); return false; }
    if (recorded.machines[machineIndex].cleaned)
    { resumed = true; if (failure) failure->clear(); return true; }
    recorded.machines[machineIndex].cleaned = true;
    String key = {}, encoded = {}; key.assignItoh(clusterUUID);
    auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(localMembershipCleanupColumnFamily, key, encoded, failure)) return false;
    if (failure) failure->clear();
    return true;
  }

  bool clearCompletedLocalMembershipCleanup(uint128_t clusterUUID,
                                            const String& desiredSpecSHA256,
                                            String *failure = nullptr)
  {
    G6OperationLock lock;
    MothershipLocalMembershipCleanupRecord record = {};
    if (!lockG6Operations(lock, failure) ||
        !loadLocalMembershipCleanup(clusterUUID, record, failure)) return false;
    if (record.desiredSpecSHA256 != desiredSpecSHA256 || !record.membershipCommitted)
    { if (failure) failure->assign("local membership cleanup completion conflicts"_ctv); return false; }
    for (const auto& entry : record.machines) if (!entry.cleaned)
    { if (failure) failure->assign("local membership cleanup is incomplete"_ctv); return false; }
    String key = {}; key.assignItoh(clusterUUID);
    return db.remove(localMembershipCleanupColumnFamily, key, failure);
  }

  static bool testPairBoundaryIdentityMatches(MothershipTestPairBoundaryRecord lhs,
                                             MothershipTestPairBoundaryRecord rhs)
  {
    lhs.selectorGeneration = rhs.selectorGeneration = 0;
    lhs.closed = rhs.closed = false;
    if (lhs.version >= 2 && rhs.version >= 2)
    {
      lhs.targetPlanSHA256.clear(); rhs.targetPlanSHA256.clear();
      lhs.targetAdmissionReceipt.clear(); rhs.targetAdmissionReceipt.clear();
    }
    if (lhs.version >= 3 && rhs.version >= 3)
    {
      lhs.sourceDrainObservation.clear(); rhs.sourceDrainObservation.clear();
      // Reset arms are immutable transitions over their corresponding base
      // identity: v3->v4 for P6 and v5->v6 for the final-transport profile.
      // Normal callers separately reject an armed record.
      if (lhs.version == 4) { lhs.version = 3; lhs.guestResetFence = {}; lhs.guestResetCompletedBootID.clear(); }
      if (rhs.version == 4) { rhs.version = 3; rhs.guestResetFence = {}; rhs.guestResetCompletedBootID.clear(); }
      if (lhs.version == 6) { lhs.version = 5; lhs.guestResetFence = {}; lhs.guestResetCompletedBootID.clear(); }
      if (rhs.version == 6) { rhs.version = 5; rhs.guestResetFence = {}; rhs.guestResetCompletedBootID.clear(); }
    }
    String left = {}, right = {};
    BitseryEngine::serialize(left, lhs);
    BitseryEngine::serialize(right, rhs);
    return left == right;
  }

  static bool testPairTargetAdmissionIdentityMatches(const MothershipTestPairBoundaryRecord& record,
                                                     const StatelessDeploymentAdmissionReceipt& receipt)
  {
    uint128_t operation = 0, targetCluster = 0;
    return record.version >= 2 &&
           prodigyParseCanonicalHex128(record.boundary.operationID, operation) &&
           prodigyParseCanonicalHex128(record.boundary.targetClusterUUID, targetCluster) &&
           receipt.version == 2 &&
           receipt.admission.operationID == operation && receipt.admission.clusterUUID == targetCluster &&
           receipt.admission.deploymentID == record.targetDeploymentID &&
           receipt.admission.applicationID == ApplicationConfig::extractApplicationID(record.targetDeploymentID) &&
           receipt.admission.versionID == (record.targetDeploymentID & ((uint64_t(1) << 48) - 1)) &&
           receipt.admission.requestPlanSHA256 == record.targetRequestPlanSHA256 &&
           receipt.admission.artifactSHA256 == record.targetBlobSHA256 && receipt.admission.artifactBytes == record.targetBlobBytes &&
           prodigyIsSHA256HexDigest(receipt.admission.normalizedPlanSHA256) &&
           receipt.admission.acceptedAuthorityGeneration != 0 && receipt.admission.acceptedMasterUUID != 0 && receipt.admission.acceptedMasterBootNs > 0 &&
           (record.targetPlanSHA256.empty() || record.targetPlanSHA256 == receipt.admission.normalizedPlanSHA256);
  }

  static bool testPairTargetAdmissionMatches(const MothershipTestPairBoundaryRecord& record,
                                             const StatelessDeploymentAdmissionReceipt& receipt)
  {
    return receipt.accepted && receipt.supported && receipt.peersCapable && receipt.failure.empty() &&
           receipt.currentAuthorityGeneration >= receipt.admission.acceptedAuthorityGeneration &&
           receipt.currentMasterUUID != 0 && receipt.currentMasterBootNs > 0 &&
           testPairTargetAdmissionIdentityMatches(record, receipt);
  }

  static bool testPairTargetReadinessIntentValid(const MothershipTestPairTargetReadinessIntent& intent)
  {
    if ((intent.version != 1 && intent.version != 2) || intent.commissionedBrainCount != 3 ||
        intent.declaredStatelessWorkloadCount != 1 || intent.commissionedBrainUUIDs.size() != 3 ||
        intent.endpointMachineUUID == 0 || intent.commissionedBrainUUIDs[0] == 0 ||
        intent.commissionedBrainUUIDs[0] >= intent.commissionedBrainUUIDs[1] ||
        intent.commissionedBrainUUIDs[1] >= intent.commissionedBrainUUIDs[2]) return false;
    if (intent.version == 1)
      return intent.cousinTransportDeploymentID == 0 && intent.cousinTransportReplicaCount == 0 &&
             intent.declaredCousinTransportWorkloadCount == 0;
    return intent.cousinTransportDeploymentID != 0 && intent.cousinTransportReplicaCount != 0 &&
           intent.declaredCousinTransportWorkloadCount == 1;
  }

  static bool testPairCousinTransportIntentEmpty(const MothershipTestPairCousinTransportIntent& intent)
  {
    MothershipTestPairCousinTransportIntent copy = intent, empty = {};
    String encoded = {}, emptyEncoded = {};
    BitseryEngine::serialize(encoded, copy);
    BitseryEngine::serialize(emptyEncoded, empty);
    return encoded == emptyEncoded;
  }

  static bool testPairCousinTransportIntentValid(const MothershipTestPairBoundaryRecord& record)
  {
    const auto& intent = record.cousinTransport;
    const auto& route = intent.route;
    const auto& source = intent.sourcePermission;
    const auto& destination = intent.destinationPermission;
    uint128_t sourceClusterUUID = 0, destinationClusterUUID = 0;
    if (intent.version != 1 || !prodigyParseCanonicalHex128(record.boundary.sourceClusterUUID, sourceClusterUUID) ||
        !prodigyParseCanonicalHex128(record.boundary.targetClusterUUID, destinationClusterUUID) ||
        !cousinRouteCurrentContract(route) || !cousinRouteStructurallyValid(route) ||
        route.state != CousinRouteState::active || route.sourceClusterUUID != sourceClusterUUID ||
        route.destinationClusterUUID != destinationClusterUUID ||
        !prodigyLocalCousinServicePermissionValid(source) ||
        !prodigyLocalCousinServicePermissionValid(destination) ||
        source.state != ProdigyLocalCousinServicePermissionState::active ||
        destination.state != ProdigyLocalCousinServicePermissionState::active ||
        source.localHalf != CousinRouteHalf::source || destination.localHalf != CousinRouteHalf::destination ||
        source.localClusterUUID != sourceClusterUUID || source.peerClusterUUID != destinationClusterUUID ||
        destination.localClusterUUID != destinationClusterUUID || destination.peerClusterUUID != sourceClusterUUID ||
        source.permissionUUID != route.sourcePermissionUUID ||
        destination.permissionUUID != route.destinationPermissionUUID ||
        source.pairUUID != route.pairUUID || destination.pairUUID != route.pairUUID ||
        source.logicalWorkloadUUID != route.logicalWorkloadUUID ||
        destination.logicalWorkloadUUID != route.logicalWorkloadUUID ||
        source.logicalServiceUUID != route.logicalServiceUUID ||
        destination.logicalServiceUUID != route.logicalServiceUUID ||
        source.localApplicationID != route.sourceApplicationID ||
        source.peerApplicationID != route.destinationApplicationID ||
        destination.localApplicationID != route.destinationApplicationID ||
        destination.peerApplicationID != route.sourceApplicationID ||
        source.localCousinServicePrefix != route.sourceCousinServicePrefix ||
        source.peerCousinServicePrefix != route.destinationCousinServicePrefix ||
        destination.localCousinServicePrefix != route.destinationCousinServicePrefix ||
        destination.peerCousinServicePrefix != route.sourceCousinServicePrefix ||
        source.slots != route.slots || destination.slots != route.slots ||
        source.localDeploymentID == record.sourceDeploymentID ||
        destination.localDeploymentID == record.targetDeploymentID ||
        source.localApplicationID == ApplicationConfig::extractApplicationID(record.sourceDeploymentID) ||
        destination.localApplicationID == ApplicationConfig::extractApplicationID(record.targetDeploymentID) ||
        record.targetReadinessIntent.version != 2 ||
        record.targetReadinessIntent.cousinTransportDeploymentID != destination.localDeploymentID ||
        !cousinRouteApplyReceiptMatchesCurrentRoute(intent.sourceApplyReceipt, route) ||
        !cousinRouteApplyReceiptMatchesCurrentRoute(intent.destinationApplyReceipt, route) ||
        intent.sourceApplyReceipt.localHalf != CousinRouteHalf::source ||
        intent.destinationApplyReceipt.localHalf != CousinRouteHalf::destination)
      return false;
    return true;
  }

  static bool testPairSourceDrainObservationValid(const MothershipTestPairBoundaryRecord& record,
                                                  const String& encoded)
  {
    MothershipVirtualDatacenterPairDrainObservation observation = {};
    return record.version >= 3 && record.selectorGeneration == 1 && !record.targetAdmissionReceipt.empty() &&
           BitseryEngine::deserializeSafe(encoded, observation) &&
           mothershipVirtualDatacenterPairDrainObservationBoundValid(record.boundary, observation) &&
           observation.selectedTarget && observation.drainCapability && observation.sourceFlows == 0;
  }

  // The caller must obtain every report freshly immediately before handoff or
  // retirement; none is persisted as an admission or health receipt.  V3 is
  // the one-workload P6 fixture. V5 additionally requires the exact live
  // destination-side COUSIN workload that carries the final transport.
  static bool testPairWholeDestinationReady(const MothershipTestPairBoundaryRecord& record,
                                            const ClusterStatusReport& clusterReport,
                                            const DeploymentIdentityReport& deploymentReport,
                                            String *failure = nullptr,
                                            const DeploymentIdentityReport *cousinTransportReport = nullptr)
  {
    auto reject = [&](auto message) -> bool { if (failure) failure->assign(message); return false; };
    if (record.version < 3 || !testPairBoundaryRecordValid(record) || record.targetAdmissionReceipt.empty())
      return reject("paired destination readiness requires a recorded v3 admission"_ctv);
    const bool finalTransport = record.version >= 5;
    if (!clusterReport.hasTopology || !mothershipTestPairTargetReadinessIntentMatchesTopology(
            record.targetReadinessIntent, clusterReport.topology, record.boundary.targetMachinePrivate4) || clusterReport.nMachines != 3 ||
        clusterReport.machineReports.size() != 3) return reject("paired destination commissioned topology differs from intent"_ctv);
    uint32_t masters = 0;
    uint128_t masterUUID = 0, endpointMachineUUID = 0;
    for (const ClusterMachine& expected : clusterReport.topology.machines)
      for (const ClusterMachineAddress& address : expected.addresses.privateAddresses)
        if (address.address == record.boundary.targetMachinePrivate4) endpointMachineUUID = expected.uuid;
    if (endpointMachineUUID == 0) return reject("paired destination endpoint machine is absent from topology"_ctv);
    for (const MachineStatusReport& machine : clusterReport.machineReports)
    {
      uint128_t uuid = 0;
      if (!machine.isBrain || machine.state != "healthy"_ctv || !machine.controlPlaneReachable || !machine.runtimeReady ||
          machine.decommissioning || machine.rebooting || machine.updatingOS || machine.hardwareFailure ||
          !prodigyParseCanonicalHex128(machine.machineUUID, uuid) || uuid == 0) return reject("paired destination Brain is not commissioned and healthy"_ctv);
      bool found = false;
      for (const ClusterMachine& expected : clusterReport.topology.machines) if (expected.uuid == uuid) found = true;
      if (!found) return reject("paired destination Brain identity differs from topology"_ctv);
      for (const MachineStatusReport& other : clusterReport.machineReports)
        if (&machine != &other && other.machineUUID == machine.machineUUID)
          return reject("paired destination Brain identity is duplicated"_ctv);
      if (machine.currentMaster) { ++masters; masterUUID = uuid; }
    }
    const uint32_t expectedApplications = finalTransport ? 2 : 1;
    if (masters != 1 || clusterReport.nApplications != expectedApplications ||
        clusterReport.applicationReports.size() != expectedApplications)
      return reject("paired destination fixture does not have one current master and its complete declared workload set"_ctv);
    const uint16_t targetApplicationID = ApplicationConfig::extractApplicationID(record.targetDeploymentID);
    const ApplicationStatusReport *application = nullptr;
    for (const ApplicationStatusReport& candidate : clusterReport.applicationReports)
      if (candidate.applicationID == targetApplicationID) application = &candidate;
    const uint64_t versionID = record.targetDeploymentID & ((uint64_t(1) << 48) - 1);
    if (application == nullptr || application->deploymentReports.size() != 1)
      return reject("paired destination workload identity differs from admission"_ctv);
    const DeploymentStatusReport& deployment = application->deploymentReports[0];
    if (deployment.versionID != versionID || deployment.state != DeploymentState::running || deployment.isStateful ||
        deployment.nTarget != 1 || deployment.nDeployed != 1 || deployment.nHealthy != 1)
      return reject("paired destination workload is not the declared healthy stateless fixture"_ctv);
    StatelessDeploymentAdmissionReceipt receipt = {};
    if (!BitseryEngine::deserializeSafe(record.targetAdmissionReceipt, receipt) ||
        !testPairTargetAdmissionMatches(record, receipt) || !prodigyDeploymentIdentityReportVersionSupported(deploymentReport.version) ||
        !deploymentReport.found || !deploymentReport.live ||
        deploymentReport.clusterUUID == 0 || deploymentReport.clusterUUID != receipt.admission.clusterUUID ||
        deploymentReport.applicationID != ApplicationConfig::extractApplicationID(record.targetDeploymentID) ||
        deploymentReport.versionID != versionID || deploymentReport.deploymentID != record.targetDeploymentID ||
        deploymentReport.state != DeploymentState::running || !deploymentReport.profileEligible || deploymentReport.isStateful ||
        deploymentReport.canonicalPlanSHA256 != record.targetPlanSHA256 || deploymentReport.containerBlobSHA256 != record.targetBlobSHA256 ||
        deploymentReport.containerBlobBytes != record.targetBlobBytes || deploymentReport.nTarget != 1 ||
        deploymentReport.nDeployed != 1 || deploymentReport.nHealthy != 1 ||
        deploymentReport.observedEndpointIPv4 != record.boundary.endpointIPv4 ||
        deploymentReport.observedEndpointPort != record.boundary.endpointPort ||
        deploymentReport.observedEndpointMachineUUID != endpointMachineUUID || deploymentReport.authorityGeneration == 0 ||
        deploymentReport.masterUUID != masterUUID || deploymentReport.masterBootNs <= 0)
      return reject("paired destination live deployment identity differs from admission"_ctv);
    if (finalTransport)
    {
      const auto& permission = record.cousinTransport.destinationPermission;
      const uint64_t transportVersionID = permission.localDeploymentID & ((uint64_t(1) << 48) - 1);
      const ApplicationStatusReport *transportApplication = nullptr;
      for (const ApplicationStatusReport& candidate : clusterReport.applicationReports)
        if (candidate.applicationID == permission.localApplicationID) transportApplication = &candidate;
      if (transportApplication == nullptr || transportApplication == application ||
          transportApplication->deploymentReports.size() != 1 || cousinTransportReport == nullptr)
        return reject("paired destination COUSIN transport workload is missing or ambiguous"_ctv);
      const DeploymentStatusReport& transport = transportApplication->deploymentReports[0];
      if (transport.versionID != transportVersionID || transport.state != DeploymentState::running ||
          !transport.isStateful || transport.nTarget != record.targetReadinessIntent.cousinTransportReplicaCount ||
          transport.nDeployed != transport.nTarget || transport.nHealthy != transport.nTarget)
        return reject("paired destination COUSIN transport workload is not wholly healthy"_ctv);
      const DeploymentIdentityReport& identity = *cousinTransportReport;
      if (!prodigyDeploymentIdentityReportVersionSupported(identity.version) || !identity.found || !identity.live ||
          identity.clusterUUID != receipt.admission.clusterUUID ||
          identity.applicationID != permission.localApplicationID || identity.versionID != transportVersionID ||
          identity.deploymentID != permission.localDeploymentID || identity.state != DeploymentState::running ||
          !identity.isStateful || identity.canonicalPlanSHA256 != permission.canonicalPlanSHA256 ||
          identity.containerBlobSHA256 != permission.artifactSHA256 ||
          identity.containerBlobBytes != permission.artifactBytes ||
          identity.nTarget != record.targetReadinessIntent.cousinTransportReplicaCount ||
          identity.nDeployed != identity.nTarget || identity.nHealthy != identity.nTarget ||
          identity.authorityGeneration == 0 || identity.masterUUID != masterUUID || identity.masterBootNs <= 0)
        return reject("paired destination live COUSIN transport identity differs from its bound permission"_ctv);
    }
    if (failure) failure->clear();
    return true;
  }

  static bool testPairBoundaryRecordValid(const MothershipTestPairBoundaryRecord& record)
  {
    if ((record.version < 1 || record.version > 6) || record.selectorGeneration > 1 ||
        !mothershipVirtualDatacenterPairBoundaryDescriptorValid(record.boundary) ||
        record.sourceDeploymentID == 0 || record.targetDeploymentID == 0 ||
        !prodigyIsSHA256HexDigest(record.sourcePlanSHA256) ||
        !prodigyIsSHA256HexDigest(record.sourceBlobSHA256) ||
        !prodigyIsSHA256HexDigest(record.targetBlobSHA256)) return false;
    if (record.version == 1)
      return prodigyIsSHA256HexDigest(record.targetPlanSHA256) && record.targetRequestPlan.empty() &&
             record.targetRequestPlanSHA256.empty() && record.targetBlobBytes == 0 && record.targetAdmissionReceipt.empty() &&
             record.targetReadinessIntent.version == 1 && record.targetReadinessIntent.commissionedBrainUUIDs.empty() &&
             record.targetReadinessIntent.endpointMachineUUID == 0 && record.targetReadinessIntent.commissionedBrainCount == 0 && record.targetReadinessIntent.declaredStatelessWorkloadCount == 0 &&
             record.targetReadinessIntent.cousinTransportDeploymentID == 0 && record.targetReadinessIntent.cousinTransportReplicaCount == 0 &&
             record.targetReadinessIntent.declaredCousinTransportWorkloadCount == 0 &&
             record.sourceDrainObservation.empty() && record.guestResetFence.operationID.empty() &&
             record.guestResetFence.descriptorSHA256.empty() && record.guestResetFence.bootID.empty() &&
             record.guestResetFence.guestID.empty() && record.guestResetCompletedBootID.empty() &&
             testPairCousinTransportIntentEmpty(record.cousinTransport);
    DeploymentPlan request = {};
    String requestSHA = {};
    if (record.targetRequestPlan.empty() || record.targetRequestPlan.size() > 1024 * 1024 ||
        !BitseryEngine::deserializeSafe(record.targetRequestPlan, request) ||
        !prodigyStatelessDeploymentAdmissionPlanEligible(request) || request.config.deploymentID() != record.targetDeploymentID ||
        !prodigyComputeSHA256Hex(record.targetRequestPlan, requestSHA) || requestSHA != record.targetRequestPlanSHA256 ||
        record.targetBlobBytes == 0 ||
        (record.version == 2 && (!record.targetReadinessIntent.commissionedBrainUUIDs.empty() || record.targetReadinessIntent.endpointMachineUUID != 0 ||
                                 record.targetReadinessIntent.commissionedBrainCount != 0 ||
                                 record.targetReadinessIntent.declaredStatelessWorkloadCount != 0 ||
                                 record.targetReadinessIntent.cousinTransportDeploymentID != 0 ||
                                 record.targetReadinessIntent.cousinTransportReplicaCount != 0 ||
                                 record.targetReadinessIntent.declaredCousinTransportWorkloadCount != 0 ||
                                 !record.sourceDrainObservation.empty() ||
                                 !record.guestResetFence.operationID.empty() || !record.guestResetFence.descriptorSHA256.empty() ||
                                 !record.guestResetFence.bootID.empty() || !record.guestResetFence.guestID.empty() ||
                                 !record.guestResetCompletedBootID.empty())) ||
        ((record.version == 3 || record.version == 5) &&
                                (!record.guestResetFence.operationID.empty() || !record.guestResetFence.descriptorSHA256.empty() ||
                                 !record.guestResetFence.bootID.empty() || !record.guestResetFence.guestID.empty() ||
                                 !record.guestResetCompletedBootID.empty())) ||
        (record.version >= 3 && !testPairTargetReadinessIntentValid(record.targetReadinessIntent))) return false;
    if ((record.version <= 4 && !testPairCousinTransportIntentEmpty(record.cousinTransport)) ||
        (record.version >= 5 && !testPairCousinTransportIntentValid(record))) return false;
    if ((record.version == 4 || record.version == 6) &&
        (!mothershipVirtualDatacenterPairGuestResetFenceValid(record.guestResetFence, record.boundary) ||
         (!record.guestResetCompletedBootID.empty() &&
          (!mothershipVirtualDatacenterBootIDValid(record.guestResetCompletedBootID) ||
           record.guestResetCompletedBootID == record.guestResetFence.bootID)))) return false;
    if (record.targetAdmissionReceipt.empty())
      return record.targetPlanSHA256.empty() && record.selectorGeneration == 0;
    StatelessDeploymentAdmissionReceipt receipt = {};
    return BitseryEngine::deserializeSafe(record.targetAdmissionReceipt, receipt) &&
           testPairTargetAdmissionMatches(record, receipt) && record.targetPlanSHA256 == receipt.admission.normalizedPlanSHA256 &&
           (record.sourceDrainObservation.empty() || testPairSourceDrainObservationValid(record, record.sourceDrainObservation));
  }

  bool recordTestPairTargetAdmission(const MothershipTestPairBoundaryRecord& expected,
                                     const StatelessDeploymentAdmissionReceipt& receipt,
                                     MothershipTestPairBoundaryRecord& recorded, String *failure = nullptr)
  {
    if (!loadTestPairBoundary(expected.boundary.operationID, recorded, failure)) return false;
    if (recorded.closed || !recorded.guestResetFence.operationID.empty() || !testPairBoundaryIdentityMatches(recorded, expected) ||
        !testPairTargetAdmissionMatches(recorded, receipt))
    {
      if (failure) failure->assign("target admission receipt conflicts with the paired request"_ctv);
      return false;
    }
    if (!recorded.targetAdmissionReceipt.empty())
    {
      StatelessDeploymentAdmissionReceipt prior = {};
      if (!BitseryEngine::deserializeSafe(recorded.targetAdmissionReceipt, prior) ||
          prior.admission.acceptedAuthorityGeneration != receipt.admission.acceptedAuthorityGeneration ||
          prior.admission.acceptedMasterUUID != receipt.admission.acceptedMasterUUID || prior.admission.acceptedMasterBootNs != receipt.admission.acceptedMasterBootNs)
      {
        if (failure) failure->assign("target admission original authority identity changed"_ctv);
        return false;
      }
      if (failure) failure->clear();
      return true;
    }
    recorded.targetPlanSHA256 = receipt.admission.normalizedPlanSHA256;
    auto copy = receipt;
    BitseryEngine::serialize(recorded.targetAdmissionReceipt, copy);
    if (!testPairBoundaryRecordValid(recorded)) return false;
    String encoded = {};
    BitseryEngine::serialize(encoded, recorded);
    return db.write(testPairBoundariesColumnFamily, recorded.boundary.operationID, encoded, failure);
  }

  bool recordTestPairSourceDrain(const MothershipTestPairBoundaryRecord& expected,
                                 const MothershipVirtualDatacenterPairDrainObservation& observation,
                                 MothershipTestPairBoundaryRecord& recorded, String *failure = nullptr)
  {
    if (!loadTestPairBoundary(expected.boundary.operationID, recorded, failure)) return false;
    if (recorded.closed || !testPairBoundaryIdentityMatches(recorded, expected) ||
        recorded.selectorGeneration != expected.selectorGeneration || recorded.sourceDrainObservation != expected.sourceDrainObservation ||
        recorded.version < 3 || !recorded.guestResetFence.operationID.empty() || recorded.selectorGeneration != 1 || recorded.targetAdmissionReceipt.empty() ||
        !mothershipVirtualDatacenterPairDrainObservationBoundValid(recorded.boundary, observation) ||
        !observation.selectedTarget || !observation.drainCapability || observation.sourceFlows != 0)
    {
      if (failure) failure->assign("source drain observation conflicts with the paired boundary"_ctv);
      return false;
    }
    if (!recorded.sourceDrainObservation.empty()) { if (failure) failure->clear(); return true; }
    auto copy = observation;
    BitseryEngine::serialize(recorded.sourceDrainObservation, copy);
    if (!testPairBoundaryRecordValid(recorded)) return false;
    String encoded = {};
    BitseryEngine::serialize(encoded, recorded);
    return db.write(testPairBoundariesColumnFamily, recorded.boundary.operationID, encoded, failure);
  }

  bool recordTestPairGuestResetFence(const MothershipTestPairBoundaryRecord& expected,
                                       const MothershipVirtualDatacenterPairGuestResetFence& fence,
                                       MothershipTestPairBoundaryRecord& recorded, String *failure = nullptr)
  {
    if (!loadTestPairBoundary(expected.boundary.operationID, recorded, failure)) return false;
    const bool expectedIsBase = (expected.version == 3 || expected.version == 5) &&
                                expected.guestResetFence.operationID.empty() && expected.guestResetCompletedBootID.empty();
    const bool expectedIsArmed = (expected.version == 4 || expected.version == 6) &&
                                 expected.guestResetFence.operationID == fence.operationID &&
                                 expected.guestResetFence.descriptorSHA256 == fence.descriptorSHA256 &&
                                 expected.guestResetFence.bootID == fence.bootID && expected.guestResetFence.guestID == fence.guestID &&
                                 expected.guestResetCompletedBootID.empty();
    if (recorded.closed || (recorded.version != 3 && recorded.version != 4 && recorded.version != 5 && recorded.version != 6) ||
        !mothershipVirtualDatacenterPairGuestResetFenceValid(fence, recorded.boundary) ||
        !testPairBoundaryIdentityMatches(recorded, expected) ||
        recorded.selectorGeneration != expected.selectorGeneration ||
        recorded.targetPlanSHA256 != expected.targetPlanSHA256 || recorded.targetAdmissionReceipt != expected.targetAdmissionReceipt ||
        recorded.sourceDrainObservation != expected.sourceDrainObservation || (!expectedIsBase && !expectedIsArmed))
    {
      if (failure) failure->assign("guest reset fence conflicts with the paired boundary"_ctv);
      return false;
    }
    if (recorded.version == 4 || recorded.version == 6)
    {
      if (recorded.guestResetFence.operationID != fence.operationID ||
          recorded.guestResetFence.descriptorSHA256 != fence.descriptorSHA256 ||
          recorded.guestResetFence.bootID != fence.bootID || recorded.guestResetFence.guestID != fence.guestID ||
          !recorded.guestResetCompletedBootID.empty())
      {
        if (failure) failure->assign("guest reset fence conflicts with the paired boundary"_ctv);
        return false;
      }
      if (failure) failure->clear();
      return true;
    }
    recorded.version = recorded.version == 3 ? 4 : 6;
    recorded.guestResetFence = fence;
    recorded.guestResetCompletedBootID.clear();
    if (!testPairBoundaryRecordValid(recorded)) return false;
    String encoded = {};
    BitseryEngine::serialize(encoded, recorded);
    return db.write(testPairBoundariesColumnFamily, recorded.boundary.operationID, encoded, failure);
  }

  bool recordTestPairGuestResetCompletion(const MothershipTestPairBoundaryRecord& expected,
                                          const String& completedBootID,
                                          MothershipTestPairBoundaryRecord& recorded, String *failure = nullptr)
  {
    if (!loadTestPairBoundary(expected.boundary.operationID, recorded, failure)) return false;
    if (recorded.closed || (recorded.version != 4 && recorded.version != 6) || recorded.guestResetFence.operationID.empty() ||
        !testPairBoundaryIdentityMatches(recorded, expected) || recorded.selectorGeneration != expected.selectorGeneration ||
        recorded.targetPlanSHA256 != expected.targetPlanSHA256 || recorded.targetAdmissionReceipt != expected.targetAdmissionReceipt ||
        recorded.sourceDrainObservation != expected.sourceDrainObservation ||
        recorded.guestResetFence.operationID != expected.guestResetFence.operationID ||
        recorded.guestResetFence.descriptorSHA256 != expected.guestResetFence.descriptorSHA256 ||
        recorded.guestResetFence.bootID != expected.guestResetFence.bootID || recorded.guestResetFence.guestID != expected.guestResetFence.guestID ||
        !mothershipVirtualDatacenterBootIDValid(completedBootID) || completedBootID == recorded.guestResetFence.bootID)
    {
      if (failure) failure->assign("guest reset completion conflicts with the armed paired boundary"_ctv);
      return false;
    }
    if (!recorded.guestResetCompletedBootID.empty())
    {
      if (recorded.guestResetCompletedBootID != completedBootID)
      {
        if (failure) failure->assign("guest reset completion conflicts with the armed paired boundary"_ctv);
        return false;
      }
      if (failure) failure->clear();
      return true;
    }
    recorded.guestResetCompletedBootID = completedBootID;
    if (!testPairBoundaryRecordValid(recorded)) return false;
    String encoded = {};
    BitseryEngine::serialize(encoded, recorded);
    return db.write(testPairBoundariesColumnFamily, recorded.boundary.operationID, encoded, failure);
  }

  bool loadTestPairBoundary(const String& operationID, MothershipTestPairBoundaryRecord& record,
                           String *failure = nullptr)
  {
    record = {};
    String encoded = {};
    if (!db.read(testPairBoundariesColumnFamily, operationID, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, record) || !testPairBoundaryRecordValid(record) ||
        record.boundary.operationID != operationID)
    {
      record = {};
      if (failure) failure->assign("test pair boundary record is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool clusterHasOpenTestPairBoundary(uint128_t clusterUUID, bool& found, String *failure = nullptr)
  {
    found = false;
    if (clusterUUID == 0)
    {
      if (failure) failure->assign("test pair boundary cluster UUID is required"_ctv);
      return false;
    }
    String uuid = {};
    renderClusterUUIDKey(clusterUUID, uuid);
    Vector<String> values = {};
    if (!db.listValues(testPairBoundariesColumnFamily, values, failure)) return false;
    for (const String& encoded : values)
    {
      MothershipTestPairBoundaryRecord record = {};
      if (!BitseryEngine::deserializeSafe(encoded, record) || !testPairBoundaryRecordValid(record))
      {
        if (failure) failure->assign("test pair boundary record is corrupt or unsupported"_ctv);
        return false;
      }
      if (!record.closed && (record.boundary.sourceClusterUUID == uuid || record.boundary.targetClusterUUID == uuid))
        found = true;
    }
    bool controlBoundary = false;
    if (!clusterHasOpenTestPairControlBoundary(clusterUUID, controlBoundary, failure)) return false;
    found |= controlBoundary;
    if (failure) failure->clear();
    return true;
  }

  bool admitTestPairBoundary(const MothershipTestPairBoundaryRecord& requested,
                            MothershipTestPairBoundaryRecord& recorded, String *failure = nullptr)
  {
    recorded = {};
    if (!testPairBoundaryRecordValid(requested) || requested.selectorGeneration != 0 || requested.closed ||
        (requested.version >= 2 && !requested.targetAdmissionReceipt.empty()) || requested.version == 4 || requested.version == 6)
    {
      if (failure) failure->assign("invalid initial test pair boundary identity"_ctv);
      return false;
    }
    // TidesDB owns the process-exclusive registry lock for this entire short
    // operation. A single record is the conflict index and admission commit;
    // there is no second key that can be lost between commits after a crash.
    Vector<String> values = {};
    if (!db.listValues(testPairBoundariesColumnFamily, values, failure)) return false;
    bool exists = false;
    for (const String& encoded : values)
    {
      MothershipTestPairBoundaryRecord prior = {};
      if (!BitseryEngine::deserializeSafe(encoded, prior) || !testPairBoundaryRecordValid(prior))
      {
        if (failure) failure->assign("test pair boundary record is corrupt or unsupported"_ctv);
        return false;
      }
      if (prior.boundary.operationID == requested.boundary.operationID)
      {
        if (!testPairBoundaryIdentityMatches(prior, requested) || prior.closed)
        {
          if (failure) failure->assign("test pair boundary operation identity conflicts or is closed"_ctv);
          return false;
        }
        recorded = prior;
        exists = true;
        continue;
      }
      const auto& a = prior.boundary;
      const auto& b = requested.boundary;
      if (!prior.closed && (a.sourceClusterUUID == b.sourceClusterUUID || a.sourceClusterUUID == b.targetClusterUUID ||
                            a.targetClusterUUID == b.sourceClusterUUID || a.targetClusterUUID == b.targetClusterUUID))
      {
        if (failure) failure->assign("a test cluster already owns an open pair boundary"_ctv);
        return false;
      }
    }
    if (exists) { if (failure) failure->clear(); return true; }
    String encoded = {};
    MothershipTestPairBoundaryRecord copy = requested;
    BitseryEngine::serialize(encoded, copy);
    if (!db.write(testPairBoundariesColumnFamily, requested.boundary.operationID, encoded, failure)) return false;
    recorded = requested;
    return true;
  }

  bool advanceTestPairBoundary(const MothershipTestPairBoundaryRecord& expected,
                              uint64_t nextSelectorGeneration, bool closed,
                              MothershipTestPairBoundaryRecord& recorded, String *failure = nullptr)
  {
    if (!loadTestPairBoundary(expected.boundary.operationID, recorded, failure)) return false;
    if (!testPairBoundaryIdentityMatches(recorded, expected) ||
        recorded.selectorGeneration != expected.selectorGeneration || recorded.closed != expected.closed ||
        recorded.targetPlanSHA256 != expected.targetPlanSHA256 || recorded.targetAdmissionReceipt != expected.targetAdmissionReceipt ||
        recorded.sourceDrainObservation != expected.sourceDrainObservation ||
        recorded.guestResetFence.operationID != expected.guestResetFence.operationID ||
        recorded.guestResetFence.descriptorSHA256 != expected.guestResetFence.descriptorSHA256 ||
        recorded.guestResetFence.bootID != expected.guestResetFence.bootID ||
        recorded.guestResetFence.guestID != expected.guestResetFence.guestID ||
        recorded.guestResetCompletedBootID != expected.guestResetCompletedBootID ||
        (recorded.version >= 2 && nextSelectorGeneration != 0 && recorded.targetAdmissionReceipt.empty()) ||
        nextSelectorGeneration < recorded.selectorGeneration || nextSelectorGeneration > 1 ||
        ((recorded.version == 4 || recorded.version == 6) &&
         (nextSelectorGeneration != recorded.selectorGeneration || !closed || recorded.guestResetCompletedBootID.empty())) ||
        (recorded.closed && !closed))
    {
      if (failure) failure->assign("test pair boundary transition is stale or regresses ownership"_ctv);
      return false;
    }
    recorded.selectorGeneration = nextSelectorGeneration;
    recorded.closed = closed;
    String encoded = {};
    BitseryEngine::serialize(encoded, recorded);
    return db.write(testPairBoundariesColumnFamily, recorded.boundary.operationID, encoded, failure);
  }

  static bool upgradeAdmissionRequestIdentityMatches(const MothershipUpgradeAdmissionRecord& lhs,
                                                     const MothershipUpgradeAdmissionRecord& rhs)
  {
    return lhs.version == 3 && rhs.version == 3 && lhs.clusterUUID == rhs.clusterUUID &&
           lhs.operationID == rhs.operationID && lhs.sourceBundleSHA256 == rhs.sourceBundleSHA256 &&
           lhs.sourceContractSHA256 == rhs.sourceContractSHA256 && lhs.sourceReleaseID == rhs.sourceReleaseID &&
           lhs.sourceProdigySHA256 == rhs.sourceProdigySHA256 && lhs.sourceMothershipSHA256 == rhs.sourceMothershipSHA256 &&
           lhs.targetBundleSHA256 == rhs.targetBundleSHA256 && lhs.targetContractSHA256 == rhs.targetContractSHA256;
  }

  bool recordUpgradeAdmission(const MothershipUpgradeAdmissionRecord& requested,
                              MothershipUpgradeAdmissionRecord& recorded,
                              bool& resumed,
                              String *failure = nullptr)
  {
    resumed = false;
    recorded = {};
    if (requested.version != 3 || requested.clusterUUID == 0 || requested.operationID == 0 ||
        requested.authorityGeneration == 0 || requested.masterUUID == 0 || requested.masterBootNs <= 0 ||
        requested.observationReceiptVersion == 0 || requested.sourceReleaseID.empty() ||
        !prodigyIsSHA256HexDigest(requested.sourceBundleSHA256) ||
        !prodigyIsSHA256HexDigest(requested.sourceContractSHA256) ||
        !prodigyIsSHA256HexDigest(requested.sourceProdigySHA256) ||
        !prodigyIsSHA256HexDigest(requested.sourceMothershipSHA256) ||
        !prodigyIsSHA256HexDigest(requested.targetBundleSHA256) ||
        !prodigyIsSHA256HexDigest(requested.targetContractSHA256) ||
        !prodigyIsSHA256HexDigest(requested.semanticObservationSHA256) ||
        !prodigyIsSHA256HexDigest(requested.observationReportSHA256) ||
        !prodigyIsSHA256HexDigest(requested.plannerInputSHA256) ||
        requested.approvedPath > 3 || (requested.eligible && requested.approvedPath == 0))
    {
      if (failure) failure->assign("upgrade admission record is invalid"_ctv);
      return false;
    }
    String clusterKey = {}; clusterKey.assignItoh(requested.clusterUUID);
    String operationKey = {}; operationKey.assignItoh(requested.operationID);
    String key = {}; key.append(clusterKey); key.append('/'); key.append(operationKey);
    String encoded = {}, readFailure = {};
    if (db.read(upgradeAdmissionsColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !upgradeAdmissionRequestIdentityMatches(recorded, requested))
      {
        if (failure) failure->assign("upgrade admission operation identity conflicts with existing immutable record"_ctv);
        return false;
      }
      if (recorded.observationReceiptVersion == requested.observationReceiptVersion &&
          recorded.observationReportSHA256 == requested.observationReportSHA256 &&
          recorded.plannerInputSHA256 == requested.plannerInputSHA256)
      {
        resumed = true;
        if (failure) failure->clear();
        return true;
      }
      MothershipUpgradeAdmissionRecord replacement = requested;
      replacement.rejectedObservations = recorded.rejectedObservations;
      if (!recorded.eligible)
      {
        MothershipUpgradeRejectedObservation prior = {};
        prior.receiptVersion = recorded.observationReceiptVersion;
        prior.reportSHA256 = recorded.observationReportSHA256;
        prior.plannerInputSHA256 = recorded.plannerInputSHA256;
        prior.firstStopGate = recorded.firstStopGate;
        replacement.rejectedObservations.push_back(std::move(prior));
        constexpr size_t maximumRejectedObservations = 16;
        if (replacement.rejectedObservations.size() > maximumRejectedObservations)
          replacement.rejectedObservations.erase(replacement.rejectedObservations.begin());
      }
      BitseryEngine::serialize(encoded, replacement);
      if (!db.write(upgradeAdmissionsColumnFamily, key, encoded, failure)) return false;
      recorded = std::move(replacement);
      if (failure) failure->clear();
      return true;
    }
    if (!readFailure.equal("record not found"_ctv))
    {
      if (failure) *failure = readFailure;
      return false;
    }
    BitseryEngine::serialize(encoded, requested);
    if (!db.write(upgradeAdmissionsColumnFamily, key, encoded, failure)) return false;
    recorded = requested;
    if (failure) failure->clear();
    return true;
  }

  bool loadUpgradeAdmission(uint128_t clusterUUID,
                            uint128_t operationID,
                            MothershipUpgradeAdmissionRecord& record,
                            String *failure = nullptr)
  {
    record = {};
    if (clusterUUID == 0 || operationID == 0)
    {
      if (failure) failure->assign("upgrade admission cluster and operation IDs are required"_ctv);
      return false;
    }
    String clusterKey = {}, operationKey = {}, key = {}, encoded = {};
    clusterKey.assignItoh(clusterUUID); operationKey.assignItoh(operationID);
    key.append(clusterKey); key.append('/'); key.append(operationKey);
    if (!db.read(upgradeAdmissionsColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, record) || record.version != 3 ||
        record.clusterUUID != clusterUUID || record.operationID != operationID)
    {
      record = {};
      if (failure) failure->assign("upgrade admission record is stale or predates semantic binding; re-plan with a new operation ID"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  // The flock spans lookup and write, unlike TidesDB's per-call transactions.
  // This prevents two Mothership processes from allocating different roots for
  // one operation before either durable record is visible.
  bool recordClusterPairEnrollmentIntent(const MothershipClusterPairEnrollmentIntent& requested,
                                          MothershipClusterPairEnrollmentIntent& recorded,
                                          bool& resumed, String *failure = nullptr)
  {
    // `recorded` may deliberately alias `requested` at the call site.  Own the
    // secret-bearing candidate before clearing the output.
    MothershipClusterPairEnrollmentIntent candidate = requested;
    recorded = {};
    resumed = false;
    if (!mothershipClusterPairEnrollmentIntentValid(candidate))
    {
      if (failure) failure->assign("cluster pair enrollment intent is invalid"_ctv);
      return false;
    }
    ClusterPairEnrollmentLock lock;
    if (!lockClusterPairEnrollment(lock, failure)) return false;

    Vector<String> values = {};
    struct ClearValues {
      Vector<String>& values;
      ~ClearValues()
      {
        for (String& value : values) Vault::secureClearString(value);
        values.clear();
      }
    } clearValues {values};
    if (!db.listValues(clusterPairEnrollmentsColumnFamily, values, failure)) return false;
    for (const String& encoded : values)
    {
      MothershipClusterPairEnrollmentIntent prior = {};
      if (!BitseryEngine::deserializeSafe(encoded, prior) || !mothershipClusterPairEnrollmentIntentValid(prior))
      {
        if (failure) failure->assign("cluster pair enrollment intent is corrupt or unsupported"_ctv);
        return false;
      }
      if (prior.operationUUID == candidate.operationUUID)
      {
        if (!mothershipClusterPairEnrollmentIntentScopeMatches(prior, candidate))
        {
          if (failure) failure->assign("cluster pair enrollment operation conflicts with immutable scope"_ctv);
          return false;
        }
        recorded = std::move(prior);
        resumed = true;
        if (failure) failure->clear();
        return true;
      }
      if (prior.firstClusterUUID == candidate.firstClusterUUID && prior.secondClusterUUID == candidate.secondClusterUUID)
      {
        if (failure) failure->assign("cluster pair already has an immutable enrollment operation"_ctv);
        return false;
      }
      if (prior.pairUUID == candidate.pairUUID)
      {
        if (failure) failure->assign("cluster pair UUID already belongs to another enrollment operation"_ctv);
        return false;
      }
    }

    String key = {}, encoded = {};
    key.assignItoh(candidate.operationUUID);
    BitseryEngine::serialize(encoded, candidate);
    const bool written = db.write(clusterPairEnrollmentsColumnFamily, key, encoded, failure);
    Vault::secureClearString(encoded);
    if (!written) return false;
    recorded = std::move(candidate);
    if (failure) failure->clear();
    return true;
  }

  bool loadClusterPairEnrollmentIntent(uint128_t operationUUID,
                                       MothershipClusterPairEnrollmentIntent& intent,
                                       String *failure = nullptr)
  {
    intent = {};
    if (operationUUID == 0)
    {
      if (failure) failure->assign("cluster pair enrollment operation UUID is required"_ctv);
      return false;
    }
    String key = {}, encoded = {};
    key.assignItoh(operationUUID);
    const bool read = db.read(clusterPairEnrollmentsColumnFamily, key, encoded, failure);
    if (!read) { Vault::secureClearString(encoded); return false; }
    const bool valid = BitseryEngine::deserializeSafe(encoded, intent) &&
        mothershipClusterPairEnrollmentIntentValid(intent) && intent.operationUUID == operationUUID;
    Vault::secureClearString(encoded);
    if (!valid)
    {
      intent = {};
      if (failure) failure->assign("cluster pair enrollment intent is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool recordClusterPairEnrollmentCompletion(uint128_t operationUUID,
                                              uint64_t firstEnrolledAuthorityGeneration,
                                              uint64_t secondEnrolledAuthorityGeneration,
                                              bool firstInitialProjectionDelivered,
                                              bool secondInitialProjectionDelivered,
                                              bool firstQualified, bool secondQualified,
                                              MothershipClusterPairEnrollmentIntent& recorded,
                                              String *failure = nullptr)
  {
    ClusterPairEnrollmentLock lock;
    if (!lockClusterPairEnrollment(lock, failure)) return false;
    MothershipClusterPairEnrollmentIntent current = {};
    String key = {}, encoded = {};
    key.assignItoh(operationUUID);
    const bool read = db.read(clusterPairEnrollmentsColumnFamily, key, encoded, failure);
    const bool decoded = read && BitseryEngine::deserializeSafe(encoded, current) &&
        mothershipClusterPairEnrollmentIntentValid(current) && current.operationUUID == operationUUID;
    if (!decoded)
    {
      Vault::secureClearString(encoded);
      if (read && failure) failure->assign("cluster pair enrollment intent is corrupt or unsupported"_ctv);
      return false;
    }
    Vault::secureClearString(encoded);
    auto advanceEnrollmentGeneration = [](uint64_t& currentGeneration, uint64_t observedGeneration) {
      if (observedGeneration == 0) return true;
      if (currentGeneration != 0 && currentGeneration != observedGeneration) return false;
      currentGeneration = observedGeneration;
      return true;
    };
    if (!advanceEnrollmentGeneration(current.firstEnrolledAuthorityGeneration, firstEnrolledAuthorityGeneration) ||
        !advanceEnrollmentGeneration(current.secondEnrolledAuthorityGeneration, secondEnrolledAuthorityGeneration))
    {
      if (failure) failure->assign("cluster pair enrollment authority generation conflicts with durable admission"_ctv);
      return false;
    }
    current.firstInitialProjectionDelivered |= firstInitialProjectionDelivered;
    current.secondInitialProjectionDelivered |= secondInitialProjectionDelivered;
    current.firstQualified |= firstQualified;
    current.secondQualified |= secondQualified;
    BitseryEngine::serialize(encoded, current);
    const bool written = db.write(clusterPairEnrollmentsColumnFamily, key, encoded, failure);
    Vault::secureClearString(encoded);
    if (!written) return false;
    recorded = std::move(current);
    if (failure) failure->clear();
    return true;
  }

  bool recordClusterPairTestControlBoundary(const MothershipPairControlBoundaryDescriptor& boundary,
                                            bool closed, MothershipClusterPairEnrollmentIntent& recorded,
                                            String *failure = nullptr)
  {
    if (!mothershipPairControlBoundaryValid(boundary, failure)) return false;
    ClusterPairEnrollmentLock lock;
    if (!lockClusterPairEnrollment(lock, failure)) return false;
    MothershipClusterPairEnrollmentIntent current;
    if (!loadClusterPairEnrollmentIntent(boundary.operationUUID, current, failure)) return false;
    if ((closed && !current.testControlBoundaryAdmitted) ||
        (!closed && current.testControlBoundaryClosed) ||
        (current.testControlBoundaryAdmitted && !mothershipPairControlBoundaryEqual(current.testControlBoundary, boundary)))
    {
      if (failure) failure->assign("pair-control boundary conflicts with its durable lifecycle"_ctv);
      return false;
    }
    current.protocolVersion = MothershipClusterPairEnrollmentIntent::version;
    current.testControlBoundary = boundary;
    current.testControlBoundaryAdmitted = true;
    current.testControlBoundaryClosed = closed;
    if (!mothershipClusterPairEnrollmentIntentValid(current))
    {
      if (failure) failure->assign("pair-control boundary requires the exact qualified enrollment and delivered rosters"_ctv);
      return false;
    }
    String key, encoded;
    key.assignItoh(current.operationUUID);
    BitseryEngine::serialize(encoded, current);
    const bool written = db.write(clusterPairEnrollmentsColumnFamily, key, encoded, failure);
    Vault::secureClearString(encoded);
    if (!written) return false;
    recorded = std::move(current);
    if (failure) failure->clear();
    return true;
  }

  bool recordClusterPairTestControlServiceTransit(uint128_t operationUUID,
                                                  const MothershipPairControlServiceTransit& transit,
                                                  MothershipClusterPairEnrollmentIntent& recorded,
                                                  String *failure = nullptr)
  {
    if (operationUUID == 0)
    {
      if (failure) failure->assign("cluster pair enrollment operation UUID is required"_ctv);
      return false;
    }
    ClusterPairEnrollmentLock lock;
    if (!lockClusterPairEnrollment(lock, failure)) return false;
    MothershipClusterPairEnrollmentIntent current = {};
    if (!loadClusterPairEnrollmentIntent(operationUUID, current, failure)) return false;
    if (!current.testControlBoundaryAdmitted || current.testControlBoundaryClosed ||
        !mothershipPairControlServiceTransitValid(transit, current.firstClusterUUID, current.secondClusterUUID))
    {
      if (failure) failure->assign("pair-control service transit requires an open exact enrolled boundary"_ctv);
      return false;
    }
    bool alreadyAdmitted = false;
    for (const auto& existing : current.testControlServiceTransits)
    {
      if (existing.sourceClusterUUID != transit.sourceClusterUUID) continue;
      if (!mothershipPairControlServiceTransitEqual(existing, transit))
      {
        if (failure) failure->assign("pair-control service transit conflicts with its immutable direction tuple"_ctv);
        return false;
      }
      alreadyAdmitted = true;
    }
    current.protocolVersion = MothershipClusterPairEnrollmentIntent::version;
    if (!alreadyAdmitted)
    {
      if (current.testControlServiceTransits.size() >= MothershipPairControlMaximumServiceTransits)
      {
        if (failure) failure->assign("pair-control service transit direction capacity exceeded"_ctv);
        return false;
      }
      current.testControlServiceTransits.push_back(transit);
      if (current.testControlServiceTransits.size() == 2 &&
          current.testControlServiceTransits[0].sourceClusterUUID > current.testControlServiceTransits[1].sourceClusterUUID)
        std::swap(current.testControlServiceTransits[0], current.testControlServiceTransits[1]);
    }
    if (!mothershipClusterPairEnrollmentIntentValid(current))
    {
      if (failure) failure->assign("pair-control service transit conflicts with durable enrollment state"_ctv);
      return false;
    }
    String key = {}, encoded = {};
    key.assignItoh(operationUUID);
    BitseryEngine::serialize(encoded, current);
    const bool written = db.write(clusterPairEnrollmentsColumnFamily, key, encoded, failure);
    Vault::secureClearString(encoded);
    if (!written) return false;
    recorded = std::move(current);
    if (failure) failure->clear();
    return true;
  }

  bool clusterHasOpenTestPairControlBoundary(uint128_t clusterUUID, bool& found, String *failure = nullptr)
  {
    found = false;
    Vector<String> values;
    struct ClearValues {
      Vector<String>& values;
      ~ClearValues() { for (auto& value : values) Vault::secureClearString(value); }
    } clear {values};
    if (!db.listValues(clusterPairEnrollmentsColumnFamily, values, failure)) return false;
    for (const auto& encoded : values)
    {
      MothershipClusterPairEnrollmentIntent intent;
      if (!BitseryEngine::deserializeSafe(encoded, intent) || !mothershipClusterPairEnrollmentIntentValid(intent))
      {
        if (failure) failure->assign("cluster pair enrollment intent is corrupt or unsupported"_ctv);
        return false;
      }
      if (intent.testControlBoundaryAdmitted && !intent.testControlBoundaryClosed &&
          (intent.firstClusterUUID == clusterUUID || intent.secondClusterUUID == clusterUUID)) found = true;
    }
    if (failure) failure->clear();
    return true;
  }

  bool loadApplicationPlacement(uint16_t applicationID, MothershipApplicationPlacement& placement, String *failure = nullptr)
  {
    placement = {};
    String encoded, key;
    key.assignItoa(applicationID);
    if (!db.read(applicationPlacementsColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, placement) || placement.version < 1 || placement.version > 4 ||
        placement.applicationID != applicationID || !mothershipApplicationPlacementRequired(applicationID) ||
        placement.ownerClusterUUID == 0 || placement.generation == 0 ||
        placement.policy != (applicationID == 10 ? MothershipApplicationPlacement::Policy::hardSingleton : MothershipApplicationPlacement::Policy::retainedSource) ||
        !prodigyIsSHA256HexDigest(placement.observationReceiptSHA256)) {
      placement = {};
      if (failure) failure->assign("retained application placement is corrupt"_ctv);
      return false;
    }
    if (placement.version == 4 &&
        (applicationID != 10 || placement.truthRetirementOwnerClusterUUID == 0 ||
         placement.truthRetirementExpectedGeneration == 0 ||
         placement.truthRetirementExpectedGeneration == UINT64_MAX ||
         placement.truthRetirementStartedGeneration != placement.truthRetirementExpectedGeneration + 1 ||
         placement.truthRetirementClusterName.empty() ||
         !prodigyIsSHA256HexDigest(placement.truthRetirementInventorySHA256) ||
         (placement.truthRetirementCompletedGeneration == 0 ?
             (!placement.truthRetirementCleanupSHA256.empty() ||
              placement.ownerClusterUUID != placement.truthRetirementOwnerClusterUUID ||
              placement.generation != placement.truthRetirementStartedGeneration) :
             (placement.truthRetirementStartedGeneration == UINT64_MAX ||
              placement.truthRetirementCompletedGeneration != placement.truthRetirementStartedGeneration + 1 ||
              !prodigyIsSHA256HexDigest(placement.truthRetirementCleanupSHA256) ||
              placement.generation < placement.truthRetirementCompletedGeneration ||
              (placement.ownerClusterUUID == placement.truthRetirementOwnerClusterUUID &&
               placement.generation != placement.truthRetirementCompletedGeneration) ||
              (placement.ownerClusterUUID != placement.truthRetirementOwnerClusterUUID &&
               (placement.truthRetirementCompletedGeneration == UINT64_MAX ||
                placement.generation != placement.truthRetirementCompletedGeneration + 1)))))) {
      placement = {};
      if (failure) failure->assign("Truth retirement placement is corrupt"_ctv);
      return false;
    }
    uint128_t previous = 0;
    bytell_hash_set<uint64_t> generations;
    for (const auto& member : placement.graphReplicas) {
      if (placement.version < 2 || applicationID == 10 || member.clusterUUID <= previous ||
          member.clusterUUID == placement.ownerClusterUUID ||
          uint16_t(member.deploymentID >> 48) != applicationID || member.membershipGeneration <= 1 ||
          member.membershipGeneration > placement.generation || !generations.insert(member.membershipGeneration).second ||
          member.topologyVersion == 0 || !prodigyIsSHA256HexDigest(member.topologySHA256) ||
          !prodigyIsSHA256HexDigest(member.canonicalPlanSHA256) || !prodigyIsSHA256HexDigest(member.artifactSHA256) ||
          member.artifactBytes == 0 || !prodigyIsSHA256HexDigest(member.observationReceiptSHA256)) {
        placement = {};
        if (failure) failure->assign("graph replica placement is corrupt"_ctv);
        return false;
      }
      previous = member.clusterUUID;
    }
    previous = 0;
    for (const auto& retirement : placement.graphReplicaRetirements) {
      const auto& member = retirement.member;
      if (placement.version != 3 || applicationID == 10 || member.clusterUUID <= previous ||
          member.clusterUUID == placement.ownerClusterUUID || uint16_t(member.deploymentID >> 48) != applicationID ||
          member.membershipGeneration <= 1 || retirement.startedGeneration <= member.membershipGeneration ||
          retirement.startedGeneration > placement.generation ||
          !generations.insert(retirement.startedGeneration).second || member.topologyVersion == 0 ||
          (retirement.completedGeneration != 0 && !generations.insert(member.membershipGeneration).second) ||
          !prodigyIsSHA256HexDigest(member.topologySHA256) || !prodigyIsSHA256HexDigest(member.canonicalPlanSHA256) ||
          !prodigyIsSHA256HexDigest(member.artifactSHA256) || member.artifactBytes == 0 ||
          !prodigyIsSHA256HexDigest(member.observationReceiptSHA256) ||
          (retirement.completedGeneration == 0 ? !retirement.cleanupReceiptSHA256.empty() :
              (retirement.completedGeneration <= retirement.startedGeneration || retirement.completedGeneration > placement.generation ||
               !generations.insert(retirement.completedGeneration).second || !prodigyIsSHA256HexDigest(retirement.cleanupReceiptSHA256)))) {
        placement = {};
        if (failure) failure->assign("graph replica retirement is corrupt"_ctv);
        return false;
      }
      const auto active = std::find_if(placement.graphReplicas.begin(), placement.graphReplicas.end(),
          [&](const auto& candidate) { return candidate.clusterUUID == member.clusterUUID; });
      if ((retirement.completedGeneration == 0 && (active == placement.graphReplicas.end() ||
              !mothershipGraphReplicaPlacementSame(*active, member))) ||
          (retirement.completedGeneration != 0 && active != placement.graphReplicas.end())) {
        placement = {};
        if (failure) failure->assign("graph replica retirement conflicts with active membership"_ctv);
        return false;
      }
      previous = member.clusterUUID;
    }
    return true;
  }

  // Mothership supplies a fresh complete registered-cluster observation before
  // first admission. No absence, deploy UUID or completed migration removes
  // this ownership. A future reassignment needs its own fenced transfer.
  bool admitApplicationPlacement(uint16_t applicationID, uint128_t clusterUUID, const String& observationReceiptSHA256,
      MothershipApplicationPlacement& placement, bool& resumed, String *failure = nullptr)
  {
    resumed = false;
    if (!mothershipApplicationPlacementRequired(applicationID) ||
        clusterUUID == 0 || !prodigyIsSHA256HexDigest(observationReceiptSHA256)) return false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String readFailure;
    if (loadApplicationPlacement(applicationID, placement, &readFailure)) {
      if (applicationID == 10 && placement.version == 4) {
        if (placement.truthRetirementCompletedGeneration == 0) {
          if (failure) failure->assign("Truth owner retirement is pending"_ctv);
          return false;
        }
        if (placement.ownerClusterUUID == placement.truthRetirementOwnerClusterUUID) {
          if (clusterUUID == placement.ownerClusterUUID || placement.generation == UINT64_MAX ||
              observationReceiptSHA256 == placement.observationReceiptSHA256) {
            if (failure) failure->assign("retired Truth owner cannot be readmitted"_ctv);
            return false;
          }
          String oldValue, oldName, oldUUIDKey, lookupFailure;
          oldUUIDKey.assignItoh(placement.truthRetirementOwnerClusterUUID);
          if (db.read(clustersColumnFamily, placement.truthRetirementClusterName, oldValue, &lookupFailure)) {
            MothershipProdigyCluster named;
            if (!deserializeClusterValue(reinterpret_cast<const uint8_t *>(oldValue.data()), oldValue.size(), named) ||
                named.clusterUUID == placement.truthRetirementOwnerClusterUUID) {
              if (failure) failure->assign("retired Truth cluster record remains or is corrupt"_ctv);
              return false;
            }
          } else if (lookupFailure != "record not found"_ctv) {
            if (failure) *failure = lookupFailure;
            return false;
          }
          if (db.read(clustersByUUIDColumnFamily, oldUUIDKey, oldName, &lookupFailure) ||
              lookupFailure != "record not found"_ctv) {
            if (failure) failure->assign("retired Truth cluster index remains"_ctv);
            return false;
          }
          String identity, candidateName; identity.assignItoh(clusterUUID);
          MothershipProdigyCluster candidate;
          if (!db.read(clustersByUUIDColumnFamily, identity, candidateName, failure) ||
              !getCluster(candidateName, candidate, failure) || candidate.clusterUUID != clusterUUID ||
              candidate.name != candidateName) return false;
          placement.ownerClusterUUID = clusterUUID;
          placement.observationReceiptSHA256 = observationReceiptSHA256;
          ++placement.generation;
          String key, bytes; key.assignItoa(applicationID); BitseryEngine::serialize(bytes, placement);
          return db.write(applicationPlacementsColumnFamily, key, bytes, failure);
        }
      }
      if (placement.ownerClusterUUID != clusterUUID) {
        if (failure) failure->assign("Truth may be admitted only on its durable owner cluster"_ctv);
        return false;
      }
      resumed = true;
      return true;
    }
    if (readFailure != "record not found"_ctv) { if (failure) *failure = readFailure; return false; }
    placement = {};
    placement.applicationID = applicationID;
    placement.policy = applicationID == 10 ? MothershipApplicationPlacement::Policy::hardSingleton : MothershipApplicationPlacement::Policy::retainedSource;
    placement.ownerClusterUUID = clusterUUID;
    placement.observationReceiptSHA256 = observationReceiptSHA256;
    String encoded, key;
    key.assignItoa(applicationID);
    BitseryEngine::serialize(encoded, placement);
    return db.write(applicationPlacementsColumnFamily, key, encoded, failure);
  }

  bool loadTruthPlacement(MothershipApplicationPlacement& placement, String *failure = nullptr)
  { return loadApplicationPlacement(10, placement, failure); }

  bool beginTruthOwnerRetirement(const MothershipProdigyCluster& cluster,
      MothershipApplicationPlacement& out, String *failure = nullptr)
  {
    out = {};
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    MothershipApplicationPlacement placement; String readFailure;
    if (!loadTruthPlacement(placement, &readFailure)) {
      if (readFailure == "record not found"_ctv) { if (failure) failure->clear(); return true; }
      if (failure) *failure = readFailure;
      return false;
    }
    if (placement.ownerClusterUUID != cluster.clusterUUID) { if (failure) failure->clear(); return true; }
    String digest, storedDigest, identity, registeredName; identity.assignItoh(cluster.clusterUUID);
    MothershipProdigyCluster stored;
    if (!mothershipTruthRetirementInventoryDigest(cluster, digest) ||
        !db.read(clustersByUUIDColumnFamily, identity, registeredName, failure) || registeredName != cluster.name ||
        !getCluster(registeredName, stored, failure) || stored.clusterUUID != cluster.clusterUUID ||
        !mothershipTruthRetirementInventoryDigest(stored, storedDigest) || digest != storedDigest) {
      if (failure) failure->assign("Truth retirement requires exact registered created-Vultr inventory"_ctv);
      return false;
    }
    if (placement.version == 4 && placement.truthRetirementOwnerClusterUUID == cluster.clusterUUID) {
      if (placement.truthRetirementInventorySHA256 != digest) {
        if (failure) failure->assign("Truth retirement inventory changed"_ctv);
        return false;
      }
      out = placement; if (failure) failure->clear(); return true;
    }
    if (placement.generation >= UINT64_MAX - 2) {
      if (failure) failure->assign("Truth retirement generation exhausted"_ctv);
      return false;
    }
    placement.version = 4;
    placement.truthRetirementOwnerClusterUUID = cluster.clusterUUID;
    placement.truthRetirementExpectedGeneration = placement.generation;
    placement.truthRetirementStartedGeneration = ++placement.generation;
    placement.truthRetirementCompletedGeneration = 0;
    placement.truthRetirementClusterName = cluster.name;
    placement.truthRetirementInventorySHA256 = digest;
    placement.truthRetirementCleanupSHA256.clear();
    String key, bytes; key.assignItoa(10); BitseryEngine::serialize(bytes, placement);
    if (!db.write(applicationPlacementsColumnFamily, key, bytes, failure)) return false;
    out = placement; if (failure) failure->clear(); return true;
  }

  bool completeTruthOwnerRetirement(const MothershipProdigyCluster& cluster,
      const MothershipApplicationPlacement& expected, const String& verifiedCleanupReceipt,
      String *failure = nullptr)
  {
    if (!prodigyIsSHA256HexDigest(verifiedCleanupReceipt)) {
      if (failure) failure->assign("Truth retirement cleanup receipt is invalid"_ctv);
      return false;
    }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    MothershipApplicationPlacement current;
    String digest;
    if (!loadTruthPlacement(current, failure) || current.version != 4 || expected.version != 4 ||
        current.ownerClusterUUID != cluster.clusterUUID || expected.ownerClusterUUID != cluster.clusterUUID ||
        current.truthRetirementOwnerClusterUUID != cluster.clusterUUID ||
        expected.truthRetirementOwnerClusterUUID != cluster.clusterUUID ||
        expected.truthRetirementExpectedGeneration != current.truthRetirementExpectedGeneration ||
        expected.truthRetirementStartedGeneration != current.truthRetirementStartedGeneration ||
        expected.truthRetirementClusterName != current.truthRetirementClusterName ||
        expected.truthRetirementInventorySHA256 != current.truthRetirementInventorySHA256 ||
        expected.observationReceiptSHA256 != current.observationReceiptSHA256 ||
        expected.applicationID != 10 || expected.policy != MothershipApplicationPlacement::Policy::hardSingleton ||
        !((expected.generation == current.truthRetirementStartedGeneration &&
           expected.truthRetirementCompletedGeneration == 0 && expected.truthRetirementCleanupSHA256.empty()) ||
          (current.truthRetirementCompletedGeneration != 0 &&
           expected.generation == current.truthRetirementCompletedGeneration &&
           expected.truthRetirementCompletedGeneration == current.truthRetirementCompletedGeneration &&
           expected.truthRetirementCleanupSHA256 == current.truthRetirementCleanupSHA256)) ||
        !mothershipTruthRetirementInventoryDigest(cluster, digest) ||
        digest != current.truthRetirementInventorySHA256) {
      if (failure) failure->assign("Truth retirement identity or generation mismatch"_ctv);
      return false;
    }
    if (current.truthRetirementCompletedGeneration != 0) {
      String identity, registeredName, readFailure; identity.assignItoh(cluster.clusterUUID);
      if (db.read(clustersByUUIDColumnFamily, identity, registeredName, &readFailure)) {
        MothershipProdigyCluster registered; String registeredDigest;
        if (registeredName != cluster.name || !getCluster(registeredName, registered, failure) ||
            registered.clusterUUID != cluster.clusterUUID ||
            !mothershipTruthRetirementInventoryDigest(registered, registeredDigest) || registeredDigest != digest) {
          if (failure) failure->assign("Truth retirement registered inventory changed"_ctv);
          return false;
        }
      } else if (readFailure != "record not found"_ctv) {
        if (failure) *failure = readFailure;
        return false;
      } else {
        MothershipProdigyCluster named;
        if (getCluster(current.truthRetirementClusterName, named, &readFailure)) {
          if (named.clusterUUID == cluster.clusterUUID) {
            if (failure) failure->assign("Truth retirement cluster index missing"_ctv);
            return false;
          }
        } else if (readFailure != "record not found"_ctv) {
          if (failure) *failure = readFailure;
          return false;
        }
      }
      const bool same = current.truthRetirementCleanupSHA256 == verifiedCleanupReceipt;
      if (failure) { if (same) failure->clear(); else failure->assign("Truth retirement cleanup receipt conflicts"_ctv); }
      return same;
    }
    String identity, registeredName; identity.assignItoh(cluster.clusterUUID);
    MothershipProdigyCluster stored; String storedDigest;
    if (!db.read(clustersByUUIDColumnFamily, identity, registeredName, failure) || registeredName != cluster.name ||
        !getCluster(registeredName, stored, failure) || stored.clusterUUID != cluster.clusterUUID ||
        !mothershipTruthRetirementInventoryDigest(stored, storedDigest) || storedDigest != digest) {
      if (failure) failure->assign("Truth retirement registered inventory changed"_ctv);
      return false;
    }
    current.truthRetirementCompletedGeneration = ++current.generation;
    current.truthRetirementCleanupSHA256 = verifiedCleanupReceipt;
    String key, bytes; key.assignItoa(10); BitseryEngine::serialize(bytes, current);
    return db.write(applicationPlacementsColumnFamily, key, bytes, failure);
  }

  bool admitApplicationPlacement(const DeploymentPlan& plan, uint128_t clusterUUID, const String& receipt,
      MothershipApplicationPlacement& placement, bool& resumed, String *failure = nullptr)
  {
    // Application identity, not a caller's stateless/stateful declaration,
    // selects the retained-placement policy on every admission transport.
    if (!mothershipApplicationPlacementRequired(plan.config.applicationID)) { placement = {}; resumed = false; return true; }
    const bool graph = plan.config.applicationID == 2 || plan.config.applicationID == 5;
    if (graph && !prodigyGraphDeploymentPlanCanonical(plan, false)) {
      if (failure) failure->assign("graph owner admission requires a canonical one-group writer; replicas require authenticated membership"_ctv);
      return false;
    }
    // Every current Radar/Pulse member is a local writer.  It has no durable
    // retained-source owner, so never create or consult the singleton placement
    // record that only protects Truth and the legacy graph recovery profile.
    if (graph && plan.stateful.allMasters) { placement = {}; resumed = false; return true; }
    return admitApplicationPlacement(plan.config.applicationID, clusterUUID, receipt, placement, resumed, failure);
  }

  // Find the only two COUSIN paths through which a graph replica subscribes to
  // its retained owner. Their purpose-specific permissions are authenticated live by
  // Mothership immediately before it calls admission; this durable half makes
  // route loss or a stale generation fail closed during both new and resumed
  // admission without creating graph-local route state.
  bool loadGraphReplicaRouteBindings(uint16_t applicationID, uint128_t ownerClusterUUID,
      uint128_t replicaClusterUUID, int64_t nowMs, Vector<MothershipGraphReplicaRouteBinding>& bindings,
      String *failure = nullptr)
  {
    bindings.clear();
    if ((applicationID != 2 && applicationID != 5) || ownerClusterUUID == 0 || replicaClusterUUID == 0 ||
        ownerClusterUUID == replicaClusterUUID || nowMs <= 0) {
      if (failure) failure->assign("graph replica route binding requires distinct Radar/Pulse owner and replica clusters"_ctv);
      return false;
    }
    Vector<String> encodedRoutes;
    if (!db.listValues(cousinRoutesColumnFamily, encodedRoutes, failure)) return false;
    for (const auto purpose : {ProdigyCousinServicePurpose::sibling, ProdigyCousinServicePurpose::seeding}) {
      const uint64_t service = prodigyRuntimeStatefulServicePrefix(applicationID,
          purpose == ProdigyCousinServicePurpose::sibling ? 2 : 4);
      MothershipGraphReplicaRouteBinding binding = {};
      bool found = false;
      for (const auto& encoded : encodedRoutes) {
        CousinRouteRecord route = {};
        if (!BitseryEngine::deserializeSafe(encoded, route) || !cousinRouteStructurallyValid(route)) {
          if (failure) failure->assign("graph replica route registry contains a corrupt record"_ctv);
          return false;
        }
        // The route has its own bitmap; inspect it directly rather than
        // borrowing the similarly-shaped permission validator.
        uint32_t routeSlots = 0; uint16_t routeSlot = 0;
        for (uint16_t candidate = 0; candidate < CousinRouteSlotBitmap::slotCount; ++candidate)
          if (route.slots.contains(candidate)) { ++routeSlots; routeSlot = candidate; }
        if (!cousinRouteUsableAt(route, nowMs) || route.state != CousinRouteState::active ||
            route.sourceClusterUUID != replicaClusterUUID || route.destinationClusterUUID != ownerClusterUUID ||
            route.sourceApplicationID != applicationID || route.destinationApplicationID != applicationID ||
            route.sourceCousinServicePrefix != service || route.destinationCousinServicePrefix != service ||
            routeSlots != 1 || routeSlot != 0) continue;
        if (found) {
          if (failure) failure->assign("graph replica route binding is ambiguous for a required service"_ctv);
          return false;
        }
        CousinRouteApplyReceipt ownerReceipt = {}, replicaReceipt = {};
        String receiptFailure;
        if (!loadCurrentCousinRouteApplyReceipt(route.routeUUID, CousinRouteHalf::source, replicaReceipt, &receiptFailure) ||
            !loadCurrentCousinRouteApplyReceipt(route.routeUUID, CousinRouteHalf::destination, ownerReceipt, &receiptFailure)) {
          if (failure) failure->assign("graph replica route lacks an exact current owner/replica receipt"_ctv);
          return false;
        }
        binding.purpose = purpose; binding.route = std::move(route);
        binding.ownerReceipt = std::move(ownerReceipt); binding.replicaReceipt = std::move(replicaReceipt);
        found = true;
      }
      if (!found) {
        if (failure) failure->assign("graph replica admission requires active sibling and seeding COUSIN routes"_ctv);
        return false;
      }
      bindings.push_back(std::move(binding));
    }
    if (failure) failure->clear();
    return true;
  }

  // Only the authenticated Mothership admission path supplies this observation.
  // A replica never reassigns the writer; membership changes are CAS-bound to
  // the retained placement and exact registered target topology. A deployment
  // identity is immutable for this phase, including across process restarts.
  bool admitGraphReplicaPlacement(const DeploymentPlan& plan, uint128_t clusterUUID,
      uint128_t expectedOwnerClusterUUID, uint64_t expectedGeneration,
      uint64_t topologyVersion, const String& topologySHA256, const String& receipt,
      MothershipApplicationPlacement& placement, bool& resumed, String *failure = nullptr)
  {
    placement = {}; resumed = false;
    auto reject = [&](const char *reason) { if (failure) failure->assign(reason); return false; };
    if (!prodigyGraphDeploymentPlanCanonical(plan, true) || clusterUUID == 0 ||
        clusterUUID == expectedOwnerClusterUUID || expectedGeneration == 0 ||
        !prodigyIsSHA256HexDigest(receipt) || !prodigyIsSHA256HexDigest(topologySHA256) ||
        topologyVersion == 0 || !prodigyIsSHA256HexDigest(plan.config.containerBlobSHA256) ||
        plan.config.containerBlobBytes == 0)
      return reject("graph replica admission requires an exact non-writer plan and authenticated membership");
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadApplicationPlacement(plan.config.applicationID, placement, failure)) return false;
    if (placement.ownerClusterUUID != expectedOwnerClusterUUID || placement.generation != expectedGeneration)
      return reject("graph replica admission has stale owner or membership generation");
    Vector<MothershipGraphReplicaRouteBinding> routeBindings;
    if (!loadGraphReplicaRouteBindings(plan.config.applicationID, expectedOwnerClusterUUID, clusterUUID,
            Time::now<TimeResolution::ms>(), routeBindings, failure)) return false;
    for (const auto& retirement : placement.graphReplicaRetirements)
      if (retirement.member.clusterUUID == clusterUUID)
        return reject("graph replica cluster membership is retiring or terminally retired");
    MothershipProdigyCluster target, owner;
    String identity; identity.assignItoh(clusterUUID);
    if (!getClusterByIdentity(identity, target, failure)) return false;
    identity.assignItoh(expectedOwnerClusterUUID);
    if (!getClusterByIdentity(identity, owner, failure)) return false;
    String bytes, registeredDigest;
    BitseryEngine::serialize(bytes, target.topology);
    if (target.topology.version != topologyVersion || target.topology.machines.empty() ||
        !prodigyComputeSHA256Hex(bytes, registeredDigest) || registeredDigest != topologySHA256)
      return reject("graph replica admission has stale registered cluster membership");
    auto copy = plan;
    String planBytes, planDigest;
    BitseryEngine::serialize(planBytes, copy);
    if (!prodigyComputeSHA256Hex(planBytes, planDigest)) return false;
    for (const auto& member : placement.graphReplicas) if (member.clusterUUID == clusterUUID) {
      if (member.deploymentID != plan.config.deploymentID() || member.canonicalPlanSHA256 != planDigest ||
          member.artifactSHA256 != plan.config.containerBlobSHA256 || member.artifactBytes != plan.config.containerBlobBytes ||
          member.topologyVersion != topologyVersion || member.topologySHA256 != topologySHA256)
        return reject("graph replica admission conflicts with its durable plan or cluster membership");
      resumed = true;
      return true;
    }
    if (placement.graphReplicas.size() >= 256 || placement.generation == UINT64_MAX)
      return reject("graph replica membership capacity or generation exhausted");
    MothershipGraphReplicaPlacement member;
    member.clusterUUID = clusterUUID; member.deploymentID = plan.config.deploymentID();
    member.membershipGeneration = ++placement.generation; member.topologyVersion = topologyVersion;
    member.topologySHA256 = topologySHA256; member.canonicalPlanSHA256 = planDigest;
    member.artifactSHA256 = plan.config.containerBlobSHA256; member.artifactBytes = plan.config.containerBlobBytes;
    member.observationReceiptSHA256 = receipt;
    placement.version = 3; placement.graphReplicas.push_back(std::move(member));
    std::sort(placement.graphReplicas.begin(), placement.graphReplicas.end(),
        [](const auto& a, const auto& b) { return a.clusterUUID < b.clusterUUID; });
    String key; key.assignItoa(plan.config.applicationID);
    BitseryEngine::serialize(bytes, placement);
    return db.write(applicationPlacementsColumnFamily, key, bytes, failure);
  }

  // The existing cluster-removal owner checkpoints this fence before runtime
  // teardown, then completes it only after that owner proves cleanup. The
  // immutable admitted member scopes both phases; neither phase moves a writer.
  bool retireGraphReplicaPlacement(uint16_t applicationID, const MothershipGraphReplicaPlacement& expectedMember,
      uint128_t expectedOwnerClusterUUID, uint64_t expectedGeneration, bool complete,
      const String& cleanupReceiptSHA256, MothershipApplicationPlacement& placement, bool& resumed,
      String *failure = nullptr)
  {
    placement = {}; resumed = false;
    auto reject = [&](const char *reason) { if (failure) failure->assign(reason); return false; };
    if ((applicationID != 2 && applicationID != 5) || expectedMember.clusterUUID == 0 ||
        expectedMember.clusterUUID == expectedOwnerClusterUUID ||
        uint16_t(expectedMember.deploymentID >> 48) != applicationID || expectedGeneration == 0 ||
        (complete ? !prodigyIsSHA256HexDigest(cleanupReceiptSHA256) : !cleanupReceiptSHA256.empty()))
      return reject("graph replica retirement requires its exact admitted member and cleanup phase");
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadApplicationPlacement(applicationID, placement, failure)) return false;
    if (placement.ownerClusterUUID != expectedOwnerClusterUUID || placement.generation != expectedGeneration)
      return reject("graph replica retirement has stale owner or membership generation");
    auto retirement = std::find_if(placement.graphReplicaRetirements.begin(), placement.graphReplicaRetirements.end(),
        [&](const auto& candidate) { return candidate.member.clusterUUID == expectedMember.clusterUUID; });
    if (retirement != placement.graphReplicaRetirements.end()) {
      if (!mothershipGraphReplicaPlacementSame(retirement->member, expectedMember))
        return reject("graph replica retirement conflicts with its admitted member");
      if (!complete || retirement->completedGeneration != 0) {
        if (complete && retirement->cleanupReceiptSHA256 != cleanupReceiptSHA256)
          return reject("graph replica retirement cleanup receipt conflicts");
        resumed = true; return true;
      }
    } else if (complete) return reject("graph replica retirement was not durably fenced before cleanup");
    auto active = std::find_if(placement.graphReplicas.begin(), placement.graphReplicas.end(),
        [&](const auto& candidate) { return candidate.clusterUUID == expectedMember.clusterUUID; });
    if (active == placement.graphReplicas.end() || !mothershipGraphReplicaPlacementSame(*active, expectedMember))
      return reject("graph replica retirement does not match active membership");
    if (placement.generation == UINT64_MAX || (!complete && placement.graphReplicaRetirements.size() >= 256))
      return reject("graph replica retirement capacity or generation exhausted");
    if (complete) {
      retirement->completedGeneration = ++placement.generation;
      retirement->cleanupReceiptSHA256 = cleanupReceiptSHA256;
      placement.graphReplicas.erase(active);
    } else {
      MothershipGraphReplicaRetirement pending;
      pending.member = expectedMember; pending.startedGeneration = ++placement.generation;
      placement.graphReplicaRetirements.push_back(std::move(pending));
      std::sort(placement.graphReplicaRetirements.begin(), placement.graphReplicaRetirements.end(),
          [](const auto& a, const auto& b) { return a.member.clusterUUID < b.member.clusterUUID; });
    }
    placement.version = 3;
    String key, bytes; key.assignItoa(applicationID); BitseryEngine::serialize(bytes, placement);
    return db.write(applicationPlacementsColumnFamily, key, bytes, failure);
  }

  bool admitTruthPlacement(uint128_t clusterUUID, const String& receipt,
      MothershipApplicationPlacement& placement, bool& resumed, String *failure = nullptr)
  { return admitApplicationPlacement(10, clusterUUID, receipt, placement, resumed, failure); }

  bool loadProductionPair(uint128_t operationUUID, MothershipProductionPairRecord& record,
                          String *failure = nullptr)
  {
    record = {};
    if (operationUUID == 0)
    {
      if (failure) failure->assign("production pair operation UUID is required"_ctv);
      return false;
    }
    String key = {}, encoded = {};
    key.assignItoh(operationUUID);
    if (!db.read(productionPairsColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, record) ||
        !mothershipProductionPairRecordValid(record) || record.intent.operationUUID != operationUUID)
    {
      record = {};
      if (failure) failure->assign("production pair record is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool persistNametagStatefulPreparation(const MothershipNametagStatefulPreparationRecord& proposed,
                                         MothershipNametagStatefulPreparationRecord& recorded,
                                         bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagStatefulPreparationRecordValid(proposed)) {
      if (failure) failure->assign("Nametag stateful preparation record is invalid"_ctv);
      return false;
    }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String key, encoded, readFailure; key.assignItoh(proposed.intent.operationUUID);
    if (db.read(nametagStatefulPreparationsColumnFamily, key, encoded, &readFailure)) {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !mothershipNametagStatefulPreparationRecordValid(recorded) ||
          recorded.intent.operationUUID != proposed.intent.operationUUID ||
          recorded.requestSHA256 != proposed.requestSHA256) {
        recorded = {};
        if (failure) failure->assign("Nametag stateful preparation conflicts with its durable request"_ctv);
        return false;
      }
      resumed = true;
      if (failure) failure->clear();
      return true;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded = proposed;
    MothershipNametagStatefulPreparationRecord copy = recorded;
    BitseryEngine::serialize(encoded, copy);
    if (!db.write(nametagStatefulPreparationsColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear();
    return true;
  }

  bool loadNametagStatefulPreparation(uint128_t operationUUID, MothershipNametagStatefulPreparationRecord& record,
                                      String *failure = nullptr)
  {
    record = {}; String key, encoded; key.assignItoh(operationUUID);
    if (operationUUID == 0 || !db.read(nametagStatefulPreparationsColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, record) || !mothershipNametagStatefulPreparationRecordValid(record) ||
        record.intent.operationUUID != operationUUID) {
      record = {}; if (failure) failure->assign("Nametag stateful preparation record is corrupt or unsupported"_ctv); return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool loadNametagExpiredCutRecoveryPreparation(uint128_t predecessorOperationUUID,
      MothershipNametagAllMastersIntent& intent, bool& found, String *failure = nullptr) {
    intent = {}; found = false; String key, op, bytes, readFailure;
    key.assign("expired-cut-successor:"_ctv); op.assignItoh(predecessorOperationUUID); key.append(op);
    if (!predecessorOperationUUID) return false;
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, &readFailure)) {
      if (readFailure.equal("record not found"_ctv)) { if (failure) failure->clear(); return true; }
      if (failure) *failure = readFailure; return false;
    }
    if (!BitseryEngine::deserializeSafe(bytes, intent) || !mothershipNametagAllMastersIntentValid(intent) ||
        !intent.isExpiredCutRecovery() || intent.predecessorOperationUUID != predecessorOperationUUID) {
      if (failure) failure->assign("expired-cut recovery preparation is corrupt"_ctv); return false;
    }
    found = true; if (failure) failure->clear(); return true;
  }

  bool validateNametagExpiredCutRecovery(const MothershipNametagAllMastersIntent& intent,
      MothershipNametagAllMastersRecord& prior, MothershipNametagInitialSeedRecord& bootstrap,
      String *failure = nullptr) {
    String bytes, digest; MothershipNametagSourceBaselineRecord baseline; bool found = false;
    const auto matchesDigest = [&](auto& value, const String& expected) {
      bytes.clear(); digest.clear();
      return BitseryEngine::serialize(bytes, value) && prodigyComputeSHA256Hex(bytes, digest, failure) && digest == expected;
    };
    if (!loadNametagAllMasters(intent.predecessorOperationUUID, prior, failure) ||
        !loadNametagInitialSeed(intent.predecessorOperationUUID, bootstrap, failure) ||
        !mothershipNametagExpiredCutRecoveryMatches(intent, prior, bootstrap, Time::now<TimeResolution::ms>()) ||
        !matchesDigest(prior, intent.predecessorRecordSHA256) || !matchesDigest(bootstrap, intent.initialSeedRecordSHA256) ||
        !loadNametagSourceBaseline(prior.intent.sourceBaselineOperationUUID, baseline, found, failure) || !found ||
        !matchesDigest(baseline, intent.predecessorBaselineSHA256)) {
      if (failure && failure->empty()) failure->assign("expired-cut recovery does not match its immutable expired predecessor and completed bootstrap"_ctv);
      return false;
    }
    return true;
  }

  // Claim the single exact recovery before normal source deployment. A crash
  // before its run row exists can only resume this immutable preparation.
  bool persistNametagExpiredCutRecoveryPreparation(const MothershipNametagAllMastersIntent& intent,
      bool& resumed, String *failure = nullptr) {
    resumed = false; G6OperationLock lock;
    MothershipNametagAllMastersRecord prior; MothershipNametagInitialSeedRecord bootstrap;
    if (!lockG6Operations(lock, failure) || !validateNametagExpiredCutRecovery(intent, prior, bootstrap, failure)) return false;
    MothershipNametagAllMastersIntent existing; bool found = false;
    if (!loadNametagExpiredCutRecoveryPreparation(intent.predecessorOperationUUID, existing, found, failure)) return false;
    String bytes, previous; auto copy = intent;
    if (!BitseryEngine::serialize(bytes, copy)) return false;
    if (found) {
      resumed = BitseryEngine::serialize(previous, existing) && previous == bytes;
      if (!resumed && failure) failure->assign("expired-cut predecessor already has a different immutable successor"_ctv);
      return resumed;
    }
    String runKey, runBytes, readFailure; runKey.assignItoh(intent.operationUUID);
    if (db.read(nametagAllMastersColumnFamily, runKey, runBytes, &readFailure) || !readFailure.equal("record not found"_ctv)) {
      if (failure) failure->assign("expired-cut recovery requires an unused management operation UUID"_ctv); return false;
    }
    String key, op; key.assign("expired-cut-successor:"_ctv); op.assignItoh(intent.predecessorOperationUUID); key.append(op);
    return db.write(nametagAllMastersColumnFamily, key, bytes, failure);
  }

  bool persistNametagAllMasters(const MothershipNametagAllMastersRecord& proposed,
                                MothershipNametagAllMastersRecord& recorded, bool& resumed,
                                String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagAllMastersRecordValid(proposed)) {
      if (failure) failure->assign("Nametag all-masters record is invalid"_ctv);
      return false;
    }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    if (proposed.intent.isExpiredCutRecovery()) {
      MothershipNametagAllMastersRecord prior; MothershipNametagInitialSeedRecord bootstrap;
      MothershipNametagAllMastersIntent claim; bool found = false; String a, b; auto intent = proposed.intent;
      if (!validateNametagExpiredCutRecovery(intent, prior, bootstrap, failure) ||
          !loadNametagExpiredCutRecoveryPreparation(intent.predecessorOperationUUID, claim, found, failure) || !found ||
          !BitseryEngine::serialize(a, intent) || !BitseryEngine::serialize(b, claim) || a != b) return false;
      MothershipNametagSourceBaselineRecord baseline, oldBaseline; bool baselineFound = false, oldFound = false;
      const auto& source = intent.sites[0];
      if (!loadNametagSourceBaseline(intent.sourceBaselineOperationUUID, baseline, baselineFound, failure) || !baselineFound ||
          !loadNametagSourceBaseline(prior.intent.sourceBaselineOperationUUID, oldBaseline, oldFound, failure) || !oldFound ||
          baseline.command.ewrClusterUUID != source.clusterUUID || baseline.command.hotDeploymentID != source.hotDeploymentID ||
          baseline.command.coldDeploymentID != source.coldDeploymentID || baseline.command.pulseDeploymentID != source.pulseDeploymentID ||
          baseline.command.radarDeploymentID != source.radarDeploymentID || baseline.command.truthDeploymentID != source.truthDeploymentID ||
          baseline.command.probeDeploymentID != oldBaseline.command.probeDeploymentID) return false;
      for (size_t i = 0; i < proposed.sourceCuts.size(); ++i) {
        const auto& cut = proposed.sourceCuts[i];
        for (const auto& old : prior.sourceCuts) if (cut.request.requestUUID == old.request.requestUUID) return false;
        for (size_t j = 0; j < i; ++j) if (cut.request.requestUUID == proposed.sourceCuts[j].request.requestUUID) return false;
      }
    }
    String key = {}, encoded = {}, readFailure = {}; key.assignItoh(proposed.intent.operationUUID);
    if (db.read(nametagAllMastersColumnFamily, key, encoded, &readFailure)) {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagAllMastersRecordValid(recorded) ||
          recorded.intent.operationUUID != proposed.intent.operationUUID) {
        recorded = {}; if (failure) failure->assign("Nametag all-masters intent conflicts with its durable request"_ctv); return false;
      }
      // The EWR receipt baseline and per-target progress are immutable once
      // admitted. A restart may observe a newer live report, but must resume
      // the persisted baseline rather than silently replacing it.
      String existingIntent = {}, requestedIntent = {};
      auto existingIntentCopy = recorded.intent; auto requestedIntentCopy = proposed.intent;
      resumed = recorded.requestSHA256 == proposed.requestSHA256 &&
          BitseryEngine::serialize(existingIntent, existingIntentCopy) &&
          BitseryEngine::serialize(requestedIntent, requestedIntentCopy) && existingIntent == requestedIntent;
      if (!resumed && failure) failure->assign("Nametag all-masters request conflicts with immutable durable baseline"_ctv);
      return resumed;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded = proposed; auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(nametagAllMastersColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear(); return true;
  }

  // Persist the exact bounded qualification marker before delivering the
  // marked authority. Retries must preserve the original challenge and cut.
  bool recordNametagAllMastersSeedFault(uint128_t operationUUID, uint32_t index,
      const ProdigyNametagQualificationSeedFault& request,
      MothershipNametagAllMastersRecord& recorded, String *failure = nullptr)
  {
    recorded = {}; G6OperationLock lock;
    if (!operationUUID || request.response || request.stage != ProdigyNametagQualificationSeedFaultStage::arm ||
        !prodigyNametagQualificationSeedFaultValid(request) || !lockG6Operations(lock, failure)) return false;
    String key, encoded; key.assignItoh(operationUUID);
    if (!db.read(nametagAllMastersColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagAllMastersRecordValid(recorded) ||
        recorded.protocolVersion < MothershipNametagAllMastersRecord::sourceCutVersion ||
        recorded.intent.operationUUID != operationUUID || index >= recorded.seedPlacements.size()) return false;
    auto& row = recorded.seedPlacements[index];
    const auto cut = std::find_if(recorded.sourceCuts.begin(), recorded.sourceCuts.end(), [&](const auto& value) {
      return value.request.applicationID == row.applicationID && value.request.shardGroup == row.shardGroup;
    });
    if (cut == recorded.sourceCuts.end() || cut->released || !cut->proof.ready ||
        cut->request.retainUntilMilliseconds <= Time::now<TimeResolution::ms>()) return false;
    if (request.authority.operationUUID != mothershipNametagSeedOperationUUID(recorded)) return false;
    const bool alreadyMarked = row.qualificationChallengeUUID != 0;
    if (!alreadyMarked && (row.deliveryDispatched || row.deliveryApplied || row.catchupObserved ||
        request.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>())) return false;
    if (row.qualificationChallengeUUID &&
        (row.qualificationRunUUID != request.runUUID || row.qualificationChallengeUUID != request.challengeUUID ||
         row.qualificationExecutionGeneration != request.executionGeneration ||
         row.qualificationDeadlineAtMilliseconds != request.deadlineAtMilliseconds)) return false;
    row.qualificationRunUUID = request.runUUID; row.qualificationChallengeUUID = request.challengeUUID;
    row.qualificationExecutionGeneration = request.executionGeneration;
    row.qualificationDeadlineAtMilliseconds = request.deadlineAtMilliseconds;
    if (recorded.protocolVersion < MothershipNametagAllMastersRecord::qualificationSeedFaultVersion)
      for (auto& placement : recorded.seedPlacements) placement.deliveryDispatched = placement.deliveryApplied;
    recorded.protocolVersion = MothershipNametagAllMastersRecord::qualificationSeedFaultVersion;
    ProdigyStatefulStoreSeedAuthority expected = {}; String a, b; auto observed = request.authority;
    if (!mothershipNametagSourceCutAuthority(recorded, row, expected) ||
        !BitseryEngine::serialize(a, expected) || !BitseryEngine::serialize(b, observed) || a != b ||
        !mothershipNametagAllMastersRecordValid(recorded)) return false;
    if (alreadyMarked) { if (failure) failure->clear(); return true; }
    auto copy = recorded; encoded.clear();
    if (!BitseryEngine::serialize(encoded, copy) || !db.write(nametagAllMastersColumnFamily, key, encoded, failure)) return false;
    if (failure) failure->clear(); return true;
  }

  // Update one source-cut checkpoint in the existing operation row. The
  // dispatch marker precedes the network request, so an interrupted first
  // challenge with an unknown outcome is never silently reissued.
  bool updateNametagAllMastersSourceCut(uint128_t operationUUID, uint32_t index,
      bool markDispatch, const ProdigyStatefulStoreSourceCut *reply,
      MothershipNametagAllMastersRecord& recorded, String *failure = nullptr)
  {
    recorded = {}; G6OperationLock lock;
    if (operationUUID == 0 || !lockG6Operations(lock, failure)) return false;
    String key, encoded; key.assignItoh(operationUUID);
    if (!db.read(nametagAllMastersColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagAllMastersRecordValid(recorded) ||
        recorded.protocolVersion < MothershipNametagAllMastersRecord::sourceCutVersion ||
        recorded.intent.operationUUID != operationUUID || index >= recorded.sourceCuts.size()) return false;
    auto& cut = recorded.sourceCuts[index];
    MothershipNametagAllMastersIntent recovery; bool recoveryClaimed = false;
    if (!loadNametagExpiredCutRecoveryPreparation(operationUUID, recovery, recoveryClaimed, failure) || recoveryClaimed) return false;
    if (markDispatch) {
      if (reply || cut.dispatched || cut.request.memberRequestUUID != 0) return false;
      cut.dispatched = true;
    } else {
      if (!reply || !cut.dispatched || !prodigyStatefulStoreSourceCutValid(*reply) || !reply->response ||
          reply->memberRequestUUID == 0) return false;
      if (reply->action == ProdigyStatefulStoreSourceCutAction::prepare) {
        auto expected = cut.request;
        if (expected.memberRequestUUID == 0) expected.memberRequestUUID = reply->memberRequestUUID;
        if (!prodigyStatefulStoreSourceCutResponseMatches(expected, *reply) || !reply->failure.empty() ||
            (cut.request.memberRequestUUID != 0 && cut.request.memberRequestUUID != reply->memberRequestUUID)) return false;
        cut.request.memberRequestUUID = reply->memberRequestUUID;
        if (reply->ready) {
          if (cut.proof.ready) {
            String before, after; auto a = cut.proof; auto b = *reply;
            if (!BitseryEngine::serialize(before, a) || !BitseryEngine::serialize(after, b) || before != after) return false;
          } else cut.proof = *reply;
        }
      } else if (reply->action == ProdigyStatefulStoreSourceCutAction::release) {
        auto expected = cut.request; expected.action = ProdigyStatefulStoreSourceCutAction::release;
        expected.cutUUID = cut.proof.cutUUID; expected.cutGeneration = cut.proof.cutGeneration;
        if (recorded.phase != MothershipNametagAllMastersRecord::Phase::remoteSeeded || !cut.proof.ready ||
            !reply->released || !prodigyStatefulStoreSourceCutResponseMatches(expected, *reply)) return false;
        cut.released = true;
      } else return false;
    }
    if (!mothershipNametagAllMastersRecordValid(recorded)) return false;
    auto copy = recorded; encoded.clear();
    return BitseryEngine::serialize(encoded, copy) && db.write(nametagAllMastersColumnFamily, key, encoded, failure);
  }

  bool installNametagAllMastersSourceCutPlacements(uint128_t operationUUID,
      const Vector<DeploymentIdentityReport>& pulse, const Vector<DeploymentIdentityReport>& hot,
      const Vector<DeploymentIdentityReport>& cold, const Vector<DeploymentIdentityReport>& radar,
      const String& fixture, MothershipNametagAllMastersRecord& recorded, String *failure = nullptr)
  {
    recorded = {}; G6OperationLock lock;
    if (!operationUUID || !lockG6Operations(lock, failure)) return false;
    String key, encoded; key.assignItoh(operationUUID);
    if (!db.read(nametagAllMastersColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagAllMastersRecordValid(recorded) ||
        recorded.intent.operationUUID != operationUUID || recorded.protocolVersion < MothershipNametagAllMastersRecord::sourceCutVersion) return false;
    if (recorded.phase != MothershipNametagAllMastersRecord::Phase::sourceCutsPreparing) return true;
    MothershipNametagAllMastersIntent recovery; bool recoveryClaimed = false;
    if (!loadNametagExpiredCutRecoveryPreparation(operationUUID, recovery, recoveryClaimed, failure) || recoveryClaimed) return false;
    if (!mothershipNametagSourceCutPlacementsSynthesize(recorded, pulse, hot, cold, radar, fixture) ||
        !mothershipNametagAllMastersRecordValid(recorded)) return false;
    auto copy = recorded; encoded.clear();
    return BitseryEngine::serialize(encoded, copy) && db.write(nametagAllMastersColumnFamily, key, encoded, failure);
  }

  // Claim the immutable row before sending its authority. This serializes
  // delivery with qualification-marker installation across Mothership retries.
  bool claimNametagAllMastersSeedDelivery(uint128_t operationUUID, uint32_t index,
      MothershipNametagAllMastersRecord& recorded, String *failure = nullptr)
  {
    recorded = {}; G6OperationLock lock;
    if (!operationUUID || !lockG6Operations(lock, failure)) return false;
    String key, encoded; key.assignItoh(operationUUID);
    if (!db.read(nametagAllMastersColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagAllMastersRecordValid(recorded) ||
        recorded.intent.operationUUID != operationUUID || index >= recorded.seedPlacements.size()) return false;
    if (recorded.protocolVersion < MothershipNametagAllMastersRecord::sourceCutVersion) return true;
    if (recorded.protocolVersion < MothershipNametagAllMastersRecord::qualificationSeedFaultVersion) {
      for (auto& placement : recorded.seedPlacements) placement.deliveryDispatched = placement.deliveryApplied;
      recorded.protocolVersion = MothershipNametagAllMastersRecord::qualificationSeedFaultVersion;
    }
    auto& row = recorded.seedPlacements[index];
    if (row.deliveryDispatched) return true;
    row.deliveryDispatched = true;
    if (!mothershipNametagAllMastersRecordValid(recorded)) return false;
    auto copy = recorded; encoded.clear();
    return BitseryEngine::serialize(encoded, copy) && db.write(nametagAllMastersColumnFamily, key, encoded, failure);
  }

  bool markNametagAllMastersSeedDelivered(uint128_t operationUUID,
      const MothershipNametagAllMastersSeedPlacement& expected,
      MothershipNametagAllMastersRecord& recorded, String *failure = nullptr)
  {
    recorded = {}; G6OperationLock lock;
    if (operationUUID == 0 || !lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    if (!db.read(nametagAllMastersColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagAllMastersRecordValid(recorded) ||
        recorded.intent.operationUUID != operationUUID) {
      recorded = {}; if (failure && failure->empty()) failure->assign("Nametag all-masters delivery has no durable baseline"_ctv); return false;
    }
    auto found = std::find_if(recorded.seedPlacements.begin(), recorded.seedPlacements.end(), [&](const auto& row) {
      return row.site == expected.site && row.applicationID == expected.applicationID && row.shardGroup == expected.shardGroup &&
          row.targetClusterUUID == expected.targetClusterUUID && row.targetDeploymentID == expected.targetDeploymentID &&
          row.targetContainerUUID == expected.targetContainerUUID;
    });
    if (found == recorded.seedPlacements.end() || found->sourceClusterUUID != expected.sourceClusterUUID ||
        found->sourceDeploymentID != expected.sourceDeploymentID || found->sourceContainerUUID != expected.sourceContainerUUID ||
        found->fixtureSHA256 != expected.fixtureSHA256 || found->expectedCatchupWatermarkSHA256 != expected.expectedCatchupWatermarkSHA256 ||
        found->sourceContentWatermarkSHA256 != expected.sourceContentWatermarkSHA256 ||
        found->sourceCatchupWatermarkSHA256 != expected.sourceCatchupWatermarkSHA256 || found->seedGeneration != expected.seedGeneration ||
        found->qualificationRunUUID != expected.qualificationRunUUID ||
        found->qualificationChallengeUUID != expected.qualificationChallengeUUID ||
        found->qualificationExecutionGeneration != expected.qualificationExecutionGeneration ||
        found->qualificationDeadlineAtMilliseconds != expected.qualificationDeadlineAtMilliseconds) {
      recorded = {}; if (failure) failure->assign("Nametag all-masters delivery target does not match its durable EWR baseline"_ctv); return false;
    }
    if (!found->deliveryApplied) {
      found->deliveryApplied = true;
      recorded.phase = MothershipNametagAllMastersRecord::Phase::remoteSeeding;
      if (!mothershipNametagAllMastersRecordValid(recorded)) {
        recorded = {}; if (failure) failure->assign("Nametag all-masters delivery would violate durable lifecycle"_ctv); return false;
      }
      auto copy = recorded; BitseryEngine::serialize(encoded, copy);
      if (!db.write(nametagAllMastersColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    }
    if (failure) failure->clear();
    return true;
  }

  bool recordNametagAllMastersSeedObservations(uint128_t operationUUID,
      const Vector<DeploymentIdentityReport>& pulse, const Vector<DeploymentIdentityReport>& hot,
      const Vector<DeploymentIdentityReport>& cold, const Vector<DeploymentIdentityReport>& radar,
      MothershipNametagAllMastersRecord& recorded, String *failure = nullptr)
  {
    recorded = {}; G6OperationLock lock;
    if (operationUUID == 0 || !lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    if (!db.read(nametagAllMastersColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagAllMastersRecordValid(recorded) ||
        recorded.intent.operationUUID != operationUUID) {
      recorded = {}; if (failure && failure->empty()) failure->assign("Nametag all-masters observation has no durable baseline"_ctv); return false;
    }
    bool changed = false, complete = true;
    for (auto& row : recorded.seedPlacements) {
      bool observed = false;
      ProdigyStatefulStoreReceipt nativeProof = {};
      if (recorded.protocolVersion >= MothershipNametagAllMastersRecord::sourceCutVersion) {
        const Vector<DeploymentIdentityReport> *reports = row.applicationID == MeshRegistry::Pulse::applicationID ? &pulse :
            (row.applicationID == MeshRegistry::Hot::applicationID ? &hot :
             (row.applicationID == MeshRegistry::Cold::applicationID ? &cold : &radar));
        ProdigyStatefulStoreSeedAuthority authority = {};
        if (row.site < reports->size() && (*reports)[row.site].version >= 5 &&
            mothershipNametagSourceCutAuthority(recorded, row, authority)) {
          const auto& report = (*reports)[row.site];
          for (const auto& member : report.statefulRuntimeCohort)
            if (member.containerUUID == row.targetContainerUUID && member.shardGroup == row.shardGroup &&
                report.clusterUUID == row.targetClusterUUID && report.deploymentID == row.targetDeploymentID &&
                prodigyStatefulStoreReceiptMatchesSourceCutAuthority(member.nativeSourceCutReceipt, authority)) {
              nativeProof = member.nativeSourceCutReceipt; observed = true; break;
            }
        }
      } else observed = mothershipNametagAllMastersSeedPlacementObserved(row, pulse, hot, cold, radar);
      if (observed && !row.deliveryApplied) {
        recorded = {}; if (failure) failure->assign("Nametag all-masters receipt arrived before its durable delivery record"_ctv); return false;
      }
      if (observed && !row.catchupObserved) {
        row.catchupObserved = true;
        if (recorded.protocolVersion >= MothershipNametagAllMastersRecord::sourceCutVersion) row.nativeSourceCutReceipt = nativeProof;
        changed = true;
      }
      complete = complete && row.catchupObserved;
    }
    if (complete && recorded.phase != MothershipNametagAllMastersRecord::Phase::remoteSeeded) {
      recorded.phase = MothershipNametagAllMastersRecord::Phase::remoteSeeded; changed = true;
    }
    if (changed) {
      if (!mothershipNametagAllMastersRecordValid(recorded)) {
        recorded = {}; if (failure) failure->assign("Nametag all-masters receipt would violate durable lifecycle"_ctv); return false;
      }
      auto copy = recorded; BitseryEngine::serialize(encoded, copy);
      if (!db.write(nametagAllMastersColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    }
    if (failure) failure->clear();
    return true;
  }

  bool loadNametagInitialSeed(uint128_t operationUUID, MothershipNametagInitialSeedRecord& record, String *failure = nullptr) {
    record = {}; if (!operationUUID) return false;
    String key, op, bytes; key.assign("initial-seed-bootstrap:"_ctv); op.assignItoh(operationUUID); key.append(op);
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure) || !BitseryEngine::deserializeSafe(bytes, record) ||
        record.operationUUID != operationUUID || !mothershipNametagInitialSeedRecordValid(record)) { record = {}; return false; }
    if (failure) failure->clear(); return true;
  }

  bool persistNametagInitialSeed(const MothershipNametagInitialSeedRecord& proposed, bool& resumed, String *failure = nullptr) {
    resumed = false; G6OperationLock lock; if (!lockG6Operations(lock, failure) || !mothershipNametagInitialSeedRecordValid(proposed) ||
        proposed.dispatchMask || proposed.completedMask) return false;
    MothershipNametagSourceBaselineRecord baseline = {}; bool found = false;
    MothershipNametagAllMastersIntent intent = {}; String bytes, digest;
    if (!BitseryEngine::deserializeSafe(proposed.intentBytes, intent) ||
        !loadNametagSourceBaseline(proposed.baselineOperationUUID, baseline, found, failure) || !found ||
        !prodigyNametagSourceBaselineReceiptValid(baseline.receipt) ||
        baseline.receipt.ewrClusterUUID != intent.sites[0].clusterUUID ||
        baseline.command.ewrClusterUUID != intent.sites[0].clusterUUID || baseline.command.pulseDeploymentID != intent.sites[0].pulseDeploymentID ||
        baseline.command.hotDeploymentID != intent.sites[0].hotDeploymentID || baseline.command.coldDeploymentID != intent.sites[0].coldDeploymentID ||
        baseline.command.radarDeploymentID != intent.sites[0].radarDeploymentID || baseline.command.truthDeploymentID != intent.sites[0].truthDeploymentID ||
        !BitseryEngine::serialize(bytes, baseline.receipt) || !prodigyComputeSHA256Hex(bytes, digest, failure) || digest != proposed.baselineReceiptSHA256) return false;
    String key, op, encoded, existing, readFailure; key.assign("initial-seed-bootstrap:"_ctv); op.assignItoh(proposed.operationUUID); key.append(op);
    auto copy = proposed; if (!BitseryEngine::serialize(encoded, copy)) return false;
    if (db.read(nametagAllMastersColumnFamily, key, existing, &readFailure)) {
      MothershipNametagInitialSeedRecord current = {};
      if (!BitseryEngine::deserializeSafe(existing, current) || !mothershipNametagInitialSeedRecordValid(current)) return false;
      current.dispatchMask = current.completedMask = 0; String initial;
      if (!BitseryEngine::serialize(initial, current) || initial != encoded) return false;
      resumed = true; if (failure) failure->clear(); return true;
    }
    if (!readFailure.equal("record not found"_ctv) || !db.write(nametagAllMastersColumnFamily, key, encoded, failure)) return false;
    if (failure) failure->clear(); return true;
  }

  bool updateNametagInitialSeedProgress(uint128_t operationUUID, uint32_t index, bool completed, String *failure = nullptr) {
    G6OperationLock lock; if (index >= 8 || !lockG6Operations(lock, failure)) return false;
    MothershipNametagInitialSeedRecord record = {};
    if (!loadNametagInitialSeed(operationUUID, record, failure)) return false;
    const uint8_t bit = uint8_t(1u << index);
    if (completed) { if (!(record.dispatchMask & bit)) return false; record.completedMask |= bit; }
    else record.dispatchMask |= bit;
    String key, op, bytes; key.assign("initial-seed-bootstrap:"_ctv); op.assignItoh(operationUUID); key.append(op);
    if (!mothershipNametagInitialSeedRecordValid(record) || !BitseryEngine::serialize(bytes, record) ||
        !db.write(nametagAllMastersColumnFamily, key, bytes, failure)) return false;
    if (failure) failure->clear(); return true;
  }

  bool loadNametagAllMasters(uint128_t operationUUID, MothershipNametagAllMastersRecord& record,
                             String *failure = nullptr)
  {
    record = {};
    if (operationUUID == 0) {
      if (failure) failure->assign("Nametag all-masters operation UUID is required"_ctv);
      return false;
    }
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    if (!db.read(nametagAllMastersColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, record) ||
        !mothershipNametagAllMastersRecordValid(record) ||
        record.intent.operationUUID != operationUUID) {
      record = {};
      if (failure) failure->assign("Nametag all-masters record is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  // Resolve a bounded, hash-linked chain into a transient current-cohort view.
  // The original all-masters bytes remain the authority for the baseline;
  // completed successor receipts supply only their actual replacement cohort.
  bool loadNametagSeedSuccessorPrior(uint128_t rootOperation, const String& rootSHA256,
      uint128_t predecessorSuccessor, const String& predecessorSHA256,
      MothershipNametagAllMastersRecord& current, String *failure = nullptr, uint32_t *lineageDepth = nullptr) {
    if (lineageDepth) *lineageDepth = 0;
    current = {}; String key, bytes, digest; key.assignItoh(rootOperation);
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure) ||
        !BitseryEngine::deserializeSafe(bytes, current) || !mothershipNametagAllMastersRecordValid(current) ||
        current.intent.operationUUID != rootOperation || current.phase != MothershipNametagAllMastersRecord::Phase::remoteSeeded ||
        !prodigyComputeSHA256Hex(bytes, digest, failure) || digest != rootSHA256 ||
        (predecessorSuccessor ? !prodigyIsSHA256HexDigest(predecessorSHA256) : !predecessorSHA256.empty())) return false;
    Vector<MothershipNametagSeedSuccessor> chain; auto operation = predecessorSuccessor; auto expected = predecessorSHA256;
    while (operation) {
      if (chain.size() >= 8 || std::any_of(chain.begin(), chain.end(), [&](const auto& link) { return link.operationUUID == operation; })) return false;
      key.assign("seed-successor:"_ctv); String op; op.assignItoh(operation); key.append(op);
      MothershipNametagSeedSuccessor link = {};
      if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure) ||
          !BitseryEngine::deserializeSafe(bytes, link) || link.operationUUID != operation ||
          link.predecessorOperationUUID != rootOperation || link.predecessorSHA256 != rootSHA256 ||
          link.stage != MothershipNametagSeedSuccessorStage::complete ||
          !prodigyComputeSHA256Hex(bytes, digest, failure) || digest != expected) return false;
      operation = link.predecessorSuccessorUUID; expected = link.predecessorSuccessorSHA256;
      chain.push_back(std::move(link));
    }
    if (!expected.empty()) return false;
    if (lineageDepth) *lineageDepth = uint32_t(chain.size());
    Vector<uint128_t> historicalContainers;
    for (const auto& row : current.seedPlacements) historicalContainers.push_back(row.targetContainerUUID);
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
      for (const auto& target : it->targets)
        if (std::find(historicalContainers.begin(), historicalContainers.end(), target.containerUUID) != historicalContainers.end()) return false;
      if (!mothershipNametagSeedSuccessorProject(*it, current)) return false;
      for (const auto& target : it->targets) historicalContainers.push_back(target.containerUUID);
    }
    if (failure) failure->clear(); return true;
  }

  // An unfinished head deliberately blocks later qualification rows. A caller
  // resuming that operation uses its explicit predecessor view instead.
  bool loadNametagAllMastersCurrentView(uint128_t rootOperation, MothershipNametagAllMastersRecord& current,
      uint128_t& latestSuccessor, String& latestSHA256, String *failure = nullptr) {
    latestSuccessor = 0; latestSHA256.clear();
    if (!loadNametagAllMasters(rootOperation, current, failure)) return false;
    String rootBytes, rootDigest; auto original = current;
    if (!BitseryEngine::serialize(rootBytes, original) || !prodigyComputeSHA256Hex(rootBytes, rootDigest, failure)) return false;
    String key, op, bytes, readFailure; key.assign("seed-successor-head:"_ctv); op.assignItoh(rootOperation); key.append(op);
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, &readFailure)) {
      if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
      if (failure) failure->clear(); return true;
    }
    MothershipNametagSeedSuccessorPlacementIntent head = {};
    if (!BitseryEngine::deserializeSafe(bytes, head) || head.predecessorOperationUUID != rootOperation ||
        head.predecessorSHA256 != rootDigest || !head.operationUUID) return false;
    key.assign("seed-successor:"_ctv); op.assignItoh(head.operationUUID); key.append(op);
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure) || !prodigyComputeSHA256Hex(bytes, latestSHA256, failure)) return false;
    latestSuccessor = head.operationUUID;
    return loadNametagSeedSuccessorPrior(rootOperation, rootDigest, latestSuccessor, latestSHA256, current, failure);
  }

  // Store successors in the existing all-masters registry while preserving the
  // predecessor bytes and all 48 native receipts unchanged.
  // Persist the exact disposable-site plan before any cancellation is sent.
  bool persistNametagSeedSuccessorPlacementIntent(const MothershipNametagSeedSuccessorPlacementIntent& proposed,
      bool& resumed, String *failure = nullptr) {
    resumed = false; G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    String priorKey, priorBytes, digest; priorKey.assignItoh(proposed.predecessorOperationUUID);
    MothershipNametagAllMastersRecord prior = {}; uint32_t lineageDepth = 0;
    if (!loadNametagSeedSuccessorPrior(proposed.predecessorOperationUUID, proposed.predecessorSHA256,
            proposed.predecessorSuccessorUUID, proposed.predecessorSuccessorSHA256, prior, failure, &lineageDepth) ||
        lineageDepth >= 8 ||
        !mothershipNametagSeedSuccessorPlacementIntentValid(proposed, prior)) return false;
    const MothershipNametagQualificationAdapter *adapter = nullptr;
    for (const auto& candidate : mothershipNametagQualificationAdapters)
      if (uint8_t(candidate.row) == proposed.qualificationRow &&
          candidate.direction == MothershipNametagQualificationDirection::injection) adapter = &candidate;
    MothershipNametagQualificationIntent qualification = {}; bool found = false;
    if (!adapter || !loadNametagQualificationIntent(*adapter, proposed.qualificationRunUUID, qualification, found, failure) || !found ||
        qualification.allMastersOperationUUID != proposed.predecessorOperationUUID ||
        qualification.executionGeneration != proposed.executionGeneration) return false;
    String key, op, encoded, existing, readFailure; key.assign("seed-successor-placement:"_ctv);
    op.assignItoh(proposed.operationUUID); key.append(op); auto copy = proposed;
    if (!BitseryEngine::serialize(encoded, copy)) return false;
    if (proposed.cancellationDispatchedMask || proposed.cancellationCompletedMask || !proposed.cancellationReceipts.empty() || !proposed.routePlan.empty()) return false;
    // An expired run cannot begin another replacement, but an exact retry may
    // repair the gap between a durable head claim and its operation record.
    if (qualification.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>()) {
      String headKey, headOp, headBytes; headKey.assign("seed-successor-head:"_ctv);
      headOp.assignItoh(proposed.predecessorOperationUUID); headKey.append(headOp);
      if (!db.read(nametagAllMastersColumnFamily, headKey, headBytes, failure) || headBytes != encoded) return false;
    }
    if (db.read(nametagAllMastersColumnFamily, key, existing, &readFailure)) {
      MothershipNametagSeedSuccessorPlacementIntent current = {};
      if (!BitseryEngine::deserializeSafe(existing, current) || !mothershipNametagSeedSuccessorPlacementIntentValid(current, prior)) return false;
      current.cancellationDispatchedMask = current.cancellationCompletedMask = 0; current.cancellationReceipts.clear();
      current.routePlan.clear();
      String initial; if (!BitseryEngine::serialize(initial, current) || initial != encoded) return false;
      if (!claimNametagSeedSuccessorHead(proposed, encoded, failure)) return false;
      resumed = true; if (failure) failure->clear(); return true;
    }
    if (!readFailure.equal("record not found"_ctv) || !claimNametagSeedSuccessorHead(proposed, encoded, failure) || !db.write(nametagAllMastersColumnFamily, key, encoded, failure)) return false;
    if (failure) failure->clear(); return true;
  }

  bool loadNametagSeedSuccessorPlacementIntent(uint128_t operationUUID,
      MothershipNametagSeedSuccessorPlacementIntent& recorded, String *failure = nullptr) {
    recorded = {}; String key, op, bytes, priorKey, priorBytes, digest;
    key.assign("seed-successor-placement:"_ctv); op.assignItoh(operationUUID); key.append(op);
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure) ||
        !BitseryEngine::deserializeSafe(bytes, recorded) || recorded.operationUUID != operationUUID) return false;
    MothershipNametagAllMastersRecord prior = {}; priorKey.assignItoh(recorded.predecessorOperationUUID);
    if (!loadNametagSeedSuccessorPrior(recorded.predecessorOperationUUID, recorded.predecessorSHA256,
            recorded.predecessorSuccessorUUID, recorded.predecessorSuccessorSHA256, prior, failure) ||
        !mothershipNametagSeedSuccessorPlacementIntentValid(recorded, prior)) { recorded = {}; return false; }
    if (failure) failure->clear(); return true;
  }

  // This is a candidate scan, not a deployment identity assertion: the
  // caller must authenticate both permission bodies against their Brains.
  bool listNametagSeedSuccessorRouteCandidates(uint128_t site, const Vector<uint16_t>& applications,
      int64_t nowMs, Vector<CousinRouteRecord>& routes, String *failure = nullptr) {
    routes.clear(); if (!site || applications.empty() || nowMs <= 0) return false;
    CousinRouteLock lock; if (!lockCousinRoutes(lock, failure)) return false;
    Vector<String> entries; if (!db.listValues(cousinRoutesColumnFamily, entries, failure)) return false;
    for (const auto& bytes : entries) {
      CousinRouteRecord route = {};
      if (!BitseryEngine::deserializeSafe(bytes, route) || !cousinRouteStructurallyValid(route)) return false;
      if (cousinRouteTerminal(route) || (route.sourceClusterUUID != site && route.destinationClusterUUID != site) ||
          std::find(applications.begin(), applications.end(), route.sourceApplicationID) == applications.end()) continue;
      // Historical routes can remain until expiry after their deployment is
      // replaced. Only the authenticated permission bodies identify the DID;
      // the caller checks admission and both receipts after that exact filter.
      if (!cousinRouteCurrentContract(route)) return false;
      routes.push_back(std::move(route));
    }
    if (failure) failure->clear(); return true;
  }

  // Persist the complete immutable plan before a permission commit. Exact
  // retries are harmless; a different plan for the same placement is refused.
  bool installNametagSeedSuccessorRoutePlan(uint128_t operationUUID,
      const Vector<MothershipNametagSeedSuccessorRoutePlan>& plan, String *failure = nullptr) {
    CousinRouteLock routesLock; G6OperationLock lock;
    if (plan.empty() || !lockCousinRoutes(routesLock, failure) || !lockG6Operations(lock, failure)) return false;
    String key, op, bytes; key.assign("seed-successor-placement:"_ctv); op.assignItoh(operationUUID); key.append(op);
    MothershipNametagSeedSuccessorPlacementIntent current = {};
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure) || !BitseryEngine::deserializeSafe(bytes, current) ||
        current.operationUUID != operationUUID || current.protocolVersion != current.version) return false;
    MothershipNametagAllMastersRecord prior = {};
    if (!loadNametagSeedSuccessorPrior(current.predecessorOperationUUID, current.predecessorSHA256,
        current.predecessorSuccessorUUID, current.predecessorSuccessorSHA256, prior, failure) ||
        !mothershipNametagSeedSuccessorPlacementIntentValid(current, prior)) return false;
    if (!current.routePlan.empty()) {
      auto requested = current; requested.routePlan = plan; String desired;
      return BitseryEngine::serialize(desired, requested) && desired == bytes;
    }
    if (current.cancellationDispatchedMask || current.cancellationCompletedMask ||
        std::any_of(plan.begin(), plan.end(), [](const auto& entry) { return entry.routeReady; })) return false;
    for (const auto& entry : plan) {
      CousinRouteRecord route = {}; CousinRouteApplyReceipt a = {}, b = {};
      if (!loadCousinRoute(entry.previousRoute.routeUUID, route, failure) || !cousinRouteExactMatches(route, entry.previousRoute) ||
          !loadCousinRouteApplyReceipt(route.routeUUID, CousinRouteHalf::source, a, failure) ||
          !loadCousinRouteApplyReceipt(route.routeUUID, CousinRouteHalf::destination, b, failure) ||
          !cousinRouteApplyReceiptExactMatches(a, entry.previousSourceReceipt) ||
          !cousinRouteApplyReceiptExactMatches(b, entry.previousDestinationReceipt) ||
          !cousinRouteReceiptsAcknowledgedAt(route, a, b, Time::now<TimeResolution::ms>())) return false;
    }
    current.routePlan = plan;
    if (!mothershipNametagSeedSuccessorPlacementIntentValid(current, prior) || !BitseryEngine::serialize(bytes, current) ||
        !db.write(nametagAllMastersColumnFamily, key, bytes, failure)) return false;
    if (failure) failure->clear(); return true;
  }

  // Called only after the caller has authenticated discovery under the exact
  // committed permissions. All entries become ready in one durable update.
  bool finalizeNametagSeedSuccessorRoutes(uint128_t operationUUID,
      const Vector<MothershipNametagSeedSuccessorRoutePlan>& ready, String *failure = nullptr) {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    String key, op, bytes; key.assign("seed-successor-placement:"_ctv); op.assignItoh(operationUUID); key.append(op);
    MothershipNametagSeedSuccessorPlacementIntent current = {};
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure) || !BitseryEngine::deserializeSafe(bytes, current) ||
        current.operationUUID != operationUUID || current.protocolVersion != current.version || current.cancellationCompletedMask != 0x0f || current.routePlan.empty() ||
        current.routePlan.size() != ready.size()) return false;
    MothershipNametagAllMastersRecord prior = {};
    if (!loadNametagSeedSuccessorPrior(current.predecessorOperationUUID, current.predecessorSHA256,
        current.predecessorSuccessorUUID, current.predecessorSuccessorSHA256, prior, failure) ||
        !mothershipNametagSeedSuccessorPlacementIntentValid(current, prior)) return false;
    auto requested = current; requested.routePlan = ready;
    if (!mothershipNametagSeedSuccessorPlacementIntentValid(requested, prior) ||
        std::any_of(ready.begin(), ready.end(), [](const auto& entry) { return !entry.routeReady; })) return false;
    if (std::all_of(current.routePlan.begin(), current.routePlan.end(), [](const auto& entry) { return entry.routeReady; })) {
      String desired; return BitseryEngine::serialize(desired, requested) && desired == bytes;
    }
    if (std::any_of(current.routePlan.begin(), current.routePlan.end(), [](const auto& entry) { return entry.routeReady; })) return false;
    auto normalized = requested;
    for (size_t i = 0; i < normalized.routePlan.size(); ++i) {
      auto& value = normalized.routePlan[i]; const auto& old = current.routePlan[i];
      value.routeReady = false; value.sourceContainerUUID = value.sourceMachineUUID = 0;
      value.desiredRoute.destinationPublicAddress = old.desiredRoute.destinationPublicAddress;
      value.desiredRoute.destinationTCPPort = old.desiredRoute.destinationTCPPort;
    }
    String priorBytes;
    if (!BitseryEngine::serialize(priorBytes, normalized) || priorBytes != bytes ||
        !BitseryEngine::serialize(bytes, requested) || !db.write(nametagAllMastersColumnFamily, key, bytes, failure)) return false;
    if (failure) failure->clear(); return true;
  }

  // The caller must pass a response received from the authenticated current
  // Brain control connection. A dispatch is journaled before sending it.
  bool updateNametagSeedSuccessorCancellation(uint128_t operationUUID, uint32_t index,
      bool markDispatch, const CancelDeploymentResponse *response, String *failure = nullptr) {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) || index >= 4) return false;
    String key, op, bytes, priorKey, priorBytes, digest;
    key.assign("seed-successor-placement:"_ctv); op.assignItoh(operationUUID); key.append(op);
    MothershipNametagSeedSuccessorPlacementIntent current = {};
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure) ||
        !BitseryEngine::deserializeSafe(bytes, current) || current.operationUUID != operationUUID) return false;
    MothershipNametagAllMastersRecord prior = {}; priorKey.assignItoh(current.predecessorOperationUUID);
    if (!loadNametagSeedSuccessorPrior(current.predecessorOperationUUID, current.predecessorSHA256,
            current.predecessorSuccessorUUID, current.predecessorSuccessorSHA256, prior, failure) ||
        !mothershipNametagSeedSuccessorPlacementIntentValid(current, prior)) return false;
    const uint8_t bit = uint8_t(1u << index); const auto& plan = current.plans[index];
    if (markDispatch) {
      if (response || (current.cancellationDispatchedMask & bit)) return false;
      current.cancellationDispatchedMask |= bit;
    } else {
      if (!(current.cancellationDispatchedMask & bit) || !response || !response->success ||
          response->result != CancelDeploymentResult::completed || response->phase != CancelDeploymentPhase::completed ||
          !response->durableGeneration || !prodigyCanonicalOperationUUID(response->operationID) ||
          response->applicationID != plan.applicationID || response->cancelledDeploymentID != plan.previousDeploymentID ||
          response->successorDeploymentID != plan.successorDeploymentID ||
          response->activeVersionID != (plan.previousDeploymentID & ((uint64_t(1) << 48) - 1)) ||
          response->successorVersionID != (plan.successorDeploymentID & ((uint64_t(1) << 48) - 1))) return false;
      uint128_t parsed = 0;
      for (uint32_t i = 0; i < response->operationID.size(); ++i) {
        const char c = response->operationID[i]; if (c == '-') continue;
        parsed = (parsed << 4) | uint128_t(c <= '9' ? c - '0' : c - 'a' + 10);
      }
      if (parsed != plan.cancellationOperationUUID) return false;
      if (current.cancellationCompletedMask & bit) {
        const auto saved = std::find_if(current.cancellationReceipts.begin(), current.cancellationReceipts.end(), [&](const auto& receipt) {
          return receipt.operationID == response->operationID;
        });
        if (saved == current.cancellationReceipts.end()) return false;
        auto oldReceipt = *saved, newReceipt = *response; String oldBytes, newBytes;
        if (!BitseryEngine::serialize(oldBytes, oldReceipt) || !BitseryEngine::serialize(newBytes, newReceipt) || oldBytes != newBytes) return false;
        if (failure) failure->clear(); return true;
      }
      current.cancellationCompletedMask |= bit;
      current.cancellationReceipts.push_back(*response);
    }
    if (!mothershipNametagSeedSuccessorPlacementIntentValid(current, prior)) return false;
    String updated; if (!BitseryEngine::serialize(updated, current) ||
        !db.write(nametagAllMastersColumnFamily, key, updated, failure)) return false;
    if (failure) failure->clear(); return true;
  }

  bool persistNametagSeedSuccessor(const MothershipNametagSeedSuccessor& proposed,
      const Vector<DeploymentIdentityReport>& reports, MothershipNametagSeedSuccessor& recorded,
      bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false; G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String priorKey, priorBytes, digest; priorKey.assignItoh(proposed.predecessorOperationUUID);
    MothershipNametagAllMastersRecord prior = {};
    if (!loadNametagSeedSuccessorPrior(proposed.predecessorOperationUUID, proposed.predecessorSHA256,
            proposed.predecessorSuccessorUUID, proposed.predecessorSuccessorSHA256, prior, failure) ||
        proposed.stage != MothershipNametagSeedSuccessorStage::prepared ||
        proposed.sourceReboot.dispatched || proposed.destinationReboot.dispatched ||
        !mothershipNametagSeedSuccessorValid(proposed, prior, reports)) return false;
    const auto row = static_cast<MothershipNametagQualificationRow>(proposed.qualificationRow);
    if (row != MothershipNametagQualificationRow::brainHardRebootCatchup &&
        row != MothershipNametagQualificationRow::seedInterruptionResume) return false;
    const MothershipNametagQualificationAdapter *adapter = nullptr;
    for (const auto& candidate : mothershipNametagQualificationAdapters)
      if (candidate.row == row && candidate.direction == MothershipNametagQualificationDirection::injection) adapter = &candidate;
    MothershipNametagQualificationIntent qualification = {}; bool found = false;
    if (!adapter || !loadNametagQualificationIntent(*adapter, proposed.qualificationRunUUID, qualification, found, failure) || !found ||
        qualification.allMastersOperationUUID != proposed.predecessorOperationUUID ||
        qualification.executionGeneration != proposed.executionGeneration) return false;
    String placementKey, placementOp, placementBytes; placementKey.assign("seed-successor-placement:"_ctv);
    placementOp.assignItoh(proposed.operationUUID); placementKey.append(placementOp);
    MothershipNametagSeedSuccessorPlacementIntent placement = {};
    if (!db.read(nametagAllMastersColumnFamily, placementKey, placementBytes, failure) ||
        !BitseryEngine::deserializeSafe(placementBytes, placement) ||
        !mothershipNametagSeedSuccessorPlacementIntentValid(placement, prior) ||
        placement.operationUUID != proposed.operationUUID || placement.predecessorOperationUUID != proposed.predecessorOperationUUID ||
        placement.qualificationRunUUID != proposed.qualificationRunUUID || placement.qualificationRow != proposed.qualificationRow ||
        placement.executionGeneration != proposed.executionGeneration || placement.site != proposed.site ||
        placement.predecessorSHA256 != proposed.predecessorSHA256 ||
        placement.predecessorSuccessorUUID != proposed.predecessorSuccessorUUID ||
        placement.predecessorSuccessorSHA256 != proposed.predecessorSuccessorSHA256 || placement.cancellationCompletedMask != 0x0f) return false;
    String key = {}, op = {}, bytes = {}, existing = {}, readFailure = {};
    key.assign("seed-successor:"_ctv); op.assignItoh(proposed.operationUUID); key.append(op);
    auto copy = proposed;
    if (!BitseryEngine::serialize(bytes, copy)) return false;
    if (db.read(nametagAllMastersColumnFamily, key, existing, &readFailure)) {
      if (!BitseryEngine::deserializeSafe(existing, recorded) || !mothershipNametagSeedSuccessorValid(recorded, prior, reports)) return false;
      auto initial = recorded; initial.stage = MothershipNametagSeedSuccessorStage::prepared; initial.heldReceipt = {}; initial.releaseReceipt = {}; initial.releaseDispatched = false;
      initial.sourceCutReleaseDispatchedMask = 0; initial.sourceCutReleaseReceipts.clear();
      for (auto& target : initial.targets) { target.authority = {.protocolVersion = 0};
        target.deliveryDispatched = target.deliveryApplied = false; target.nativeReceipt = {.protocolVersion = 0}; }
      // A fence can be populated after admission once the current Brain and
      // its authenticated boot identity are observed. Preserve that progress
      // while comparing a retry with the original unpopulated proposal.
      if (!proposed.sourceReboot.dispatchUUID) initial.sourceReboot = {};
      else { initial.sourceReboot.dispatched = initial.sourceReboot.providerAccepted = initial.sourceReboot.observed = false; initial.sourceReboot.afterBootID.clear(); }
      if (!proposed.destinationReboot.dispatchUUID) initial.destinationReboot = {};
      else { initial.destinationReboot.dispatched = initial.destinationReboot.providerAccepted = initial.destinationReboot.observed = false; initial.destinationReboot.afterBootID.clear(); }
      for (auto& cut : initial.sourceCuts) { cut.dispatched = cut.released = false; cut.request.memberRequestUUID = 0; cut.proof = {}; }
      String initialBytes; if (!BitseryEngine::serialize(initialBytes, initial) || initialBytes != bytes) return false;
      resumed = true; if (failure) failure->clear(); return true;
    }
    const auto now = Time::now<TimeResolution::ms>();
    if (qualification.deadlineAtMilliseconds <= now) return false;
    for (const auto& target : proposed.targets) {
      const auto& old = prior.seedPlacements[target.predecessorIndex];
      if (std::find(placement.predecessorIndices.begin(), placement.predecessorIndices.end(), target.predecessorIndex) == placement.predecessorIndices.end() ||
          std::none_of(placement.plans.begin(), placement.plans.end(), [&](const auto& plan) {
            return plan.applicationID == old.applicationID && plan.previousDeploymentID == old.targetDeploymentID &&
                plan.successorDeploymentID == target.targetDeploymentID;
          })) return false;
      const auto cut = std::find_if(proposed.sourceCuts.begin(), proposed.sourceCuts.end(), [&](const auto& c) {
        return c.request.applicationID == old.applicationID && c.request.shardGroup == old.shardGroup;
      });
      CousinRouteRecord route = {}; CousinRouteApplyReceipt left = {}, right = {};
      if (cut == proposed.sourceCuts.end() || cut->request.retainUntilMilliseconds <= now ||
          !loadUsableCousinRoute(target.routeUUID, now, route, failure) ||
          !loadCurrentCousinRouteApplyReceipt(target.routeUUID, CousinRouteHalf::source, left, failure) ||
          !loadCurrentCousinRouteApplyReceipt(target.routeUUID, CousinRouteHalf::destination, right, failure) ||
          route.sourceClusterUUID != old.targetClusterUUID || route.destinationClusterUUID != old.sourceClusterUUID ||
          route.sourceApplicationID != old.applicationID || route.destinationApplicationID != old.applicationID ||
          route.sourceCousinServicePrefix != prodigyRuntimeStatefulServicePrefix(old.applicationID, 4) ||
          route.destinationCousinServicePrefix != prodigyRuntimeStatefulServicePrefix(old.applicationID, 4) ||
          route.expiresAtMs < cut->request.retainUntilMilliseconds ||
          std::none_of(prior.intent.directGatewayAuthorities.begin(), prior.intent.directGatewayAuthorities.end(), [&](const auto& gateway) {
            return gateway.pairUUID == route.pairUUID && gateway.localClusterUUID == old.targetClusterUUID &&
                gateway.peerClusterUUID == old.sourceClusterUUID && gateway.state == CrossClusterMasqueGatewayState::active;
          })) return false;
    }
    for (const auto& target : proposed.targets)
      if (target.authority.protocolVersion || target.deliveryDispatched || target.deliveryApplied || target.nativeReceipt.protocolVersion) return false;
    for (const auto& cut : proposed.sourceCuts)
      if (cut.dispatched || cut.released || cut.request.memberRequestUUID || cut.proof.response) return false;
    if (!readFailure.equal("record not found"_ctv) || !db.write(nametagAllMastersColumnFamily, key, bytes, failure)) return false;
    recorded = proposed; if (failure) failure->clear(); return true;
  }

  bool updateNametagSeedSuccessorCut(uint128_t operationUUID, uint32_t index, bool markDispatch,
      const ProdigyStatefulStoreSourceCut *reply, const Vector<DeploymentIdentityReport>& reports,
      MothershipNametagSeedSuccessor& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) ||
        !loadNametagSeedSuccessor(operationUUID, reports, recorded, failure) ||
        recorded.stage != MothershipNametagSeedSuccessorStage::prepared || index >= recorded.sourceCuts.size()) return false;
    auto& cut = recorded.sourceCuts[index];
    if (markDispatch) {
      if (reply || cut.dispatched || cut.request.memberRequestUUID) return false;
      cut.dispatched = true;
    } else {
      if (!reply || !cut.dispatched || !reply->response || !reply->memberRequestUUID || !reply->failure.empty() ||
          reply->action != ProdigyStatefulStoreSourceCutAction::prepare) return false;
      auto expected = cut.request;
      if (!expected.memberRequestUUID) expected.memberRequestUUID = reply->memberRequestUUID;
      if (!prodigyStatefulStoreSourceCutResponseMatches(expected, *reply)) return false;
      cut.request.memberRequestUUID = reply->memberRequestUUID;
      if (reply->ready) {
        if (cut.proof.ready) {
          String a, b; auto before = cut.proof, after = *reply;
          if (!BitseryEngine::serialize(a, before) || !BitseryEngine::serialize(b, after) || a != b) return false;
        } else cut.proof = *reply;
      }
    }
    String priorKey, priorBytes, key, op, encoded; priorKey.assignItoh(recorded.predecessorOperationUUID);
    MothershipNametagAllMastersRecord prior = {};
    if (!loadNametagSeedSuccessorPrior(recorded.predecessorOperationUUID, recorded.predecessorSHA256,
            recorded.predecessorSuccessorUUID, recorded.predecessorSuccessorSHA256, prior, failure) ||
        !mothershipNametagSeedSuccessorValid(recorded, prior, reports)) return false;
    key.assign("seed-successor:"_ctv); op.assignItoh(operationUUID); key.append(op);
    auto copy = recorded;
    return BitseryEngine::serialize(encoded, copy) && db.write(nametagAllMastersColumnFamily, key, encoded, failure);
  }

  bool recordNametagSeedSuccessorHeld(uint128_t operationUUID, const ProdigyNametagQualificationSeedFault& receipt,
      const Vector<DeploymentIdentityReport>& reports, MothershipNametagSeedSuccessor& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) ||
        !loadNametagSeedSuccessor(operationUUID, reports, recorded, failure) || !receipt.held) return false;
    if (recorded.stage != MothershipNametagSeedSuccessorStage::prepared) {
      String a, b; auto prior = recorded.heldReceipt, observed = receipt;
      return BitseryEngine::serialize(a, prior) && BitseryEngine::serialize(b, observed) && a == b;
    }
    if (receipt.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>()) return false;
    recorded.heldReceipt = receipt; recorded.stage = MothershipNametagSeedSuccessorStage::held;
    return writeNametagSeedSuccessorChecked(recorded, reports, failure);
  }

  // The caller supplies the authenticated boot observation from the existing
  // machine owner. The durable dispatch bit is written before reboot is sent.
  bool updateNametagSeedSuccessorReboot(uint128_t operationUUID, bool source,
      const MothershipNametagSeedRebootFence& requested, const Vector<DeploymentIdentityReport>& reports,
      MothershipNametagSeedSuccessor& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) ||
        !loadNametagSeedSuccessor(operationUUID, reports, recorded, failure) ||
        recorded.qualificationRow != uint8_t(ProdigyNametagQualificationRow::brainHardRebootCatchup) ||
        recorded.stage < MothershipNametagSeedSuccessorStage::held ||
        recorded.stage > MothershipNametagSeedSuccessorStage::rebootObserved ||
        !requested.clusterUUID || !requested.machineUUID || !requested.dispatchUUID || requested.beforeBootID.empty()) return false;
    MothershipProdigyCluster cluster = {}; String clusterIdentity = {}; clusterIdentity.assignItoh(requested.clusterUUID);
    if (!getClusterByIdentity(clusterIdentity, cluster, failure) || cluster.deploymentMode != MothershipClusterDeploymentMode::remote ||
        cluster.provider != MothershipClusterProvider::vultr ||
        std::count_if(cluster.topology.machines.begin(), cluster.topology.machines.end(), [&](const auto& machine) {
          return machine.uuid == requested.machineUUID && machine.isBrain && machine.source == ClusterMachineSource::created && machine.hasCloud;
        }) != 1) return false;
    auto& fence = source ? recorded.sourceReboot : recorded.destinationReboot;
    if (!fence.dispatchUUID) {
      if (requested.dispatched || requested.providerAccepted || requested.observed || !requested.afterBootID.empty()) return false;
      fence = requested;
    } else {
      if (fence.clusterUUID != requested.clusterUUID || fence.machineUUID != requested.machineUUID ||
          fence.dispatchUUID != requested.dispatchUUID || fence.beforeBootID != requested.beforeBootID ||
          (fence.dispatched && !requested.dispatched) || (fence.providerAccepted && !requested.providerAccepted) || (fence.observed && !requested.observed) ||
          (fence.observed && fence.afterBootID != requested.afterBootID) ||
          (!fence.dispatched && requested.observed)) return false;
      fence = requested;
    }
    if (recorded.sourceReboot.observed && recorded.destinationReboot.observed)
      recorded.stage = MothershipNametagSeedSuccessorStage::rebootObserved;
    else if (recorded.sourceReboot.dispatched && recorded.destinationReboot.dispatched)
      recorded.stage = MothershipNametagSeedSuccessorStage::rebootDispatched;
    return writeNametagSeedSuccessorChecked(recorded, reports, failure);
  }

  bool installNametagSeedSuccessorAuthority(uint128_t operationUUID, uint32_t index,
      const ProdigyStatefulStoreSeedAuthority& authority, const Vector<DeploymentIdentityReport>& reports,
      MothershipNametagSeedSuccessor& recorded, String *failure = nullptr) {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) ||
        !loadNametagSeedSuccessor(operationUUID, reports, recorded, failure) || index >= recorded.targets.size()) return false;
    auto& target = recorded.targets[index];
    if (target.authority.protocolVersion) {
      auto a = target.authority, b = authority; String x, y;
      return BitseryEngine::serialize(x, a) && BitseryEngine::serialize(y, b) && x == y;
    }
    if (recorded.stage != MothershipNametagSeedSuccessorStage::prepared || target.deliveryDispatched) return false;
    target.authority = authority;
    return writeNametagSeedSuccessorChecked(recorded, reports, failure);
  }

  // The exact authority is frozen before dispatch; markDispatch=false records
  // the authenticated delivery acknowledgment, never merely a queued send.
  bool updateNametagSeedSuccessorDelivery(uint128_t operationUUID, uint32_t index, bool markDispatch,
      const Vector<DeploymentIdentityReport>& reports, MothershipNametagSeedSuccessor& recorded, String *failure = nullptr) {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) ||
        !loadNametagSeedSuccessor(operationUUID, reports, recorded, failure) || index >= recorded.targets.size()) return false;
    auto& target = recorded.targets[index];
    if (!target.authority.protocolVersion || (!markDispatch && !target.deliveryDispatched)) return false;
    if (markDispatch ? target.deliveryDispatched : target.deliveryApplied) return true;
    if (recorded.stage == MothershipNametagSeedSuccessorStage::complete) return false;
    if (markDispatch) target.deliveryDispatched = true; else target.deliveryApplied = true;
    return writeNametagSeedSuccessorChecked(recorded, reports, failure);
  }

  bool recordNametagSeedSuccessorNative(uint128_t operationUUID, const Vector<DeploymentIdentityReport>& reports,
      MothershipNametagSeedSuccessor& recorded, String *failure = nullptr) {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) ||
        !loadNametagSeedSuccessor(operationUUID, reports, recorded, failure)) return false;
    if (recorded.stage == MothershipNametagSeedSuccessorStage::complete) return true;
    bool changed = false;
    for (auto& target : recorded.targets) {
      if (!target.deliveryApplied || target.nativeReceipt.protocolVersion) continue;
      for (const auto& report : reports) {
        if (!report.found || !report.live || report.version < 5 || report.deploymentID != target.targetDeploymentID ||
            report.clusterUUID != target.authority.targetClusterUUID || report.applicationID != target.authority.applicationID) continue;
        for (const auto& member : report.statefulRuntimeCohort) {
          const auto& receipt = member.nativeSourceCutReceipt;
          if (member.containerUUID == target.containerUUID && member.machineUUID == target.machineUUID &&
              receipt.state == ProdigyStatefulStoreReceiptState::active &&
              prodigyStatefulStoreReceiptMatchesSourceCutAuthority(receipt, target.authority)) {
            target.nativeReceipt = receipt; changed = true; break;
          }
        }
      }
    }
    return !changed || writeNametagSeedSuccessorChecked(recorded, reports, failure);
  }

  bool updateNametagSeedSuccessorRelease(uint128_t operationUUID, bool markDispatch,
      const ProdigyNametagQualificationSeedFault *response, const Vector<DeploymentIdentityReport>& reports,
      MothershipNametagSeedSuccessor& recorded, String *failure = nullptr) {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) ||
        !loadNametagSeedSuccessor(operationUUID, reports, recorded, failure) ||
        recorded.stage < MothershipNametagSeedSuccessorStage::held ||
        (recorded.qualificationRow == uint8_t(ProdigyNametagQualificationRow::brainHardRebootCatchup) &&
         recorded.stage < MothershipNametagSeedSuccessorStage::rebootObserved)) return false;
    if (markDispatch) {
      if (response) return false;
      if (recorded.releaseDispatched) return true;
      recorded.releaseDispatched = true;
    } else {
      if (!recorded.releaseDispatched || !response) return false;
      if (recorded.stage >= MothershipNametagSeedSuccessorStage::resumed) {
        auto a = recorded.releaseReceipt, b = *response; String x, y;
        return BitseryEngine::serialize(x, a) && BitseryEngine::serialize(y, b) && x == y;
      }
      recorded.releaseReceipt = *response; recorded.stage = MothershipNametagSeedSuccessorStage::resumed;
    }
    return writeNametagSeedSuccessorChecked(recorded, reports, failure);
  }

  bool updateNametagSeedSuccessorCutRelease(uint128_t operationUUID, uint32_t index, bool markDispatch,
      const ProdigyStatefulStoreSourceCut *response, const Vector<DeploymentIdentityReport>& reports,
      MothershipNametagSeedSuccessor& recorded, String *failure = nullptr) {
    G6OperationLock lock; if (!lockG6Operations(lock, failure) ||
        !loadNametagSeedSuccessor(operationUUID, reports, recorded, failure) || index >= recorded.sourceCuts.size() ||
        recorded.stage < MothershipNametagSeedSuccessorStage::resumed || !mothershipNametagSeedSuccessorNativeComplete(recorded)) return false;
    auto& cut = recorded.sourceCuts[index]; const auto bit = uint8_t(1u << index);
    if (markDispatch) {
      if (response) return false;
      if (recorded.sourceCutReleaseDispatchedMask & bit) return true;
      recorded.sourceCutReleaseDispatchedMask |= bit;
    } else {
      if (!response || !(recorded.sourceCutReleaseDispatchedMask & bit)) return false;
      if (cut.released) {
        const auto old = std::find_if(recorded.sourceCutReleaseReceipts.begin(), recorded.sourceCutReleaseReceipts.end(),
            [&](const auto& r) { return r.requestUUID == cut.request.requestUUID; });
        if (old == recorded.sourceCutReleaseReceipts.end()) return false;
        auto a = *old, b = *response; String x, y;
        return BitseryEngine::serialize(x, a) && BitseryEngine::serialize(y, b) && x == y;
      }
      cut.released = true; recorded.sourceCutReleaseReceipts.push_back(*response);
      if (std::all_of(recorded.sourceCuts.begin(), recorded.sourceCuts.end(), [](const auto& c) { return c.released; }))
        recorded.stage = MothershipNametagSeedSuccessorStage::complete;
    }
    return writeNametagSeedSuccessorChecked(recorded, reports, failure);
  }

private:
  // The single head contains the entire initial placement intent. Writing it
  // before the operation record makes a crash between writes repairable only
  // by an exact retry, while preventing another branch from being admitted.
  bool claimNametagSeedSuccessorHead(const MothershipNametagSeedSuccessorPlacementIntent& proposed,
      const String& initialBytes, String *failure) {
    String key, op, existing, readFailure; key.assign("seed-successor-head:"_ctv);
    op.assignItoh(proposed.predecessorOperationUUID); key.append(op);
    if (db.read(nametagAllMastersColumnFamily, key, existing, &readFailure)) {
      MothershipNametagSeedSuccessorPlacementIntent head = {};
      if (!BitseryEngine::deserializeSafe(existing, head) || head.predecessorOperationUUID != proposed.predecessorOperationUUID ||
          head.predecessorSHA256 != proposed.predecessorSHA256) return false;
      if (head.operationUUID == proposed.operationUUID) return existing == initialBytes;
      if (head.operationUUID != proposed.predecessorSuccessorUUID) return false;
      String previousKey, previousBytes, digest; previousKey.assign("seed-successor:"_ctv);
      op.assignItoh(head.operationUUID); previousKey.append(op);
      MothershipNametagSeedSuccessor previous = {};
      if (!db.read(nametagAllMastersColumnFamily, previousKey, previousBytes, failure) ||
          !BitseryEngine::deserializeSafe(previousBytes, previous) || previous.operationUUID != head.operationUUID ||
          previous.stage != MothershipNametagSeedSuccessorStage::complete ||
          !prodigyComputeSHA256Hex(previousBytes, digest, failure) || digest != proposed.predecessorSuccessorSHA256) return false;
    } else if (!readFailure.equal("record not found"_ctv) || proposed.predecessorSuccessorUUID) return false;
    return db.write(nametagAllMastersColumnFamily, key, initialBytes, failure);
  }

  bool writeNametagSeedSuccessorChecked(const MothershipNametagSeedSuccessor& requested,
      const Vector<DeploymentIdentityReport>& reports, String *failure = nullptr)
  {
    String priorKey, priorBytes, digest, key, op, encoded; priorKey.assignItoh(requested.predecessorOperationUUID);
    MothershipNametagAllMastersRecord prior = {};
    if (!loadNametagSeedSuccessorPrior(requested.predecessorOperationUUID, requested.predecessorSHA256,
            requested.predecessorSuccessorUUID, requested.predecessorSuccessorSHA256, prior, failure) ||
        !mothershipNametagSeedSuccessorValid(requested, prior, reports)) return false;
    key.assign("seed-successor:"_ctv); op.assignItoh(requested.operationUUID); key.append(op);
    auto copy = requested; if (!BitseryEngine::serialize(encoded, copy)) return false;
    String oldBytes; MothershipNametagSeedSuccessor old = {};
    if (!db.read(nametagAllMastersColumnFamily, key, oldBytes, failure) || !BitseryEngine::deserializeSafe(oldBytes, old)) return false;
    if (old.stage == MothershipNametagSeedSuccessorStage::complete) return oldBytes == encoded;
    String headKey, headBytes; headKey.assign("seed-successor-head:"_ctv); op.assignItoh(requested.predecessorOperationUUID); headKey.append(op);
    MothershipNametagSeedSuccessorPlacementIntent head = {};
    if (!db.read(nametagAllMastersColumnFamily, headKey, headBytes, failure) ||
        !BitseryEngine::deserializeSafe(headBytes, head) || head.operationUUID != requested.operationUUID) return false;
    return db.write(nametagAllMastersColumnFamily, key, encoded, failure);
  }

public:
  // Recover immutable completion before consulting deadlines or live members.
  // This closes the gap between the final source-cut ACK and the execution ref.
  bool loadCompletedNametagSeedSuccessor(uint128_t operationUUID,
      MothershipNametagSeedSuccessor& recorded, String& digest, bool& found, String *failure = nullptr)
  {
    recorded = {}; digest.clear(); found = false;
    if (!operationUUID) return false;
    String key, op, bytes, readFailure; key.assign("seed-successor:"_ctv); op.assignItoh(operationUUID); key.append(op);
    if (!db.read(nametagAllMastersColumnFamily, key, bytes, &readFailure)) {
      if (readFailure.equal("record not found"_ctv)) { if (failure) failure->clear(); return true; }
      if (failure) *failure = readFailure; return false;
    }
    if (!BitseryEngine::deserializeSafe(bytes, recorded) || recorded.protocolVersion != recorded.version ||
        recorded.operationUUID != operationUUID || recorded.stage < MothershipNametagSeedSuccessorStage::prepared ||
        recorded.stage > MothershipNametagSeedSuccessorStage::complete) return false;
    // An unfinished record is not admitted by this completion-only lookup.
    // The ordinary resume owner must validate it with current live reports.
    if (recorded.stage != MothershipNametagSeedSuccessorStage::complete) { recorded = {}; if (failure) failure->clear(); return true; }
    MothershipNametagAllMastersRecord prior; Vector<DeploymentIdentityReport> none;
    if (!loadNametagSeedSuccessorPrior(recorded.predecessorOperationUUID, recorded.predecessorSHA256,
            recorded.predecessorSuccessorUUID, recorded.predecessorSuccessorSHA256, prior, failure) ||
        !mothershipNametagSeedSuccessorValid(recorded, prior, none, false)) return false;
    MothershipNametagAllMastersRecord projected;
    if (!prodigyComputeSHA256Hex(bytes, digest, failure) ||
        !loadNametagSeedSuccessorPrior(recorded.predecessorOperationUUID, recorded.predecessorSHA256,
            operationUUID, digest, projected, failure)) return false;
    found = true; if (failure) failure->clear(); return true;
  }

  bool loadNametagSeedSuccessor(uint128_t operationUUID, const Vector<DeploymentIdentityReport>& reports,
      MothershipNametagSeedSuccessor& recorded, String *failure = nullptr)
  {
    recorded = {}; if (!operationUUID) return false;
    String key = {}, op = {}, encoded = {}; key.assign("seed-successor:"_ctv);
    op.assignItoh(operationUUID); key.append(op);
    if (!db.read(nametagAllMastersColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) || recorded.protocolVersion != MothershipNametagSeedSuccessor::version ||
        recorded.operationUUID != operationUUID) { recorded = {}; return false; }
    String priorKey = {}, priorBytes = {}, digest = {}; priorKey.assignItoh(recorded.predecessorOperationUUID);
    MothershipNametagAllMastersRecord prior = {};
    if (!loadNametagSeedSuccessorPrior(recorded.predecessorOperationUUID, recorded.predecessorSHA256,
            recorded.predecessorSuccessorUUID, recorded.predecessorSuccessorSHA256, prior, failure) ||
        !mothershipNametagSeedSuccessorValid(recorded, prior, reports)) { recorded = {}; return false; }
    if (failure) failure->clear(); return true;
  }

  bool admitProductionPair(const MothershipProductionPairIntent& intent, int64_t nowMs,
                           MothershipProductionPairRecord& recorded, bool& resumed,
                           String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipProductionPairIntentValid(intent, failure) || nowMs <= 0) return false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;

    CousinRouteRecord route = {};
    CousinRouteApplyReceipt sourceReceipt = {}, destinationReceipt = {};
    if (!loadCousinRoute(intent.route.routeUUID, route, failure) ||
        route.priorOperationUUIDs != intent.route.priorOperationUUIDs ||
        !cousinRouteExactMatches(route, intent.route) ||
        !loadCurrentCousinRouteApplyReceipt(route.routeUUID, CousinRouteHalf::source, sourceReceipt, failure) ||
        !loadCurrentCousinRouteApplyReceipt(route.routeUUID, CousinRouteHalf::destination, destinationReceipt, failure) ||
        !cousinRouteApplyReceiptExactMatches(sourceReceipt, intent.sourceRouteReceipt) ||
        !cousinRouteApplyReceiptExactMatches(destinationReceipt, intent.destinationRouteReceipt))
    {
      if (failure && failure->empty()) failure->assign("production pair requires the exact durable active route and receipts"_ctv);
      return false;
    }

    String key = {}, encoded = {}, readFailure = {};
    key.assignItoh(intent.operationUUID);
    if (db.read(productionPairsColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !mothershipProductionPairRecordMatchesIntent(recorded, intent))
      {
        recorded = {};
        if (failure) failure->assign("production pair operation conflicts with its immutable intent"_ctv);
        return false;
      }
      resumed = true;
      if (failure) failure->clear();
      return true;
    }
    if (!readFailure.equal("record not found"_ctv))
    {
      if (failure) *failure = readFailure;
      return false;
    }

    Vector<String> values = {};
    if (!db.listValues(productionPairsColumnFamily, values, failure)) return false;
    MothershipProductionPairRecord latestStateful;
    bool hasStatefulHistory = false;
    for (const auto& value : values)
    {
      MothershipProductionPairRecord prior = {};
      if (!BitseryEngine::deserializeSafe(value, prior) || !mothershipProductionPairRecordValid(prior))
      {
        if (failure) failure->assign("production pair registry contains a corrupt record"_ctv);
        return false;
      }
      if (!mothershipProductionPairTerminal(prior.phase) &&
          (prior.intent.route.routeUUID == intent.route.routeUUID ||
           ((prior.intent.protocolVersion == MothershipProductionPairIntent::statefulVersion ||
             intent.protocolVersion == MothershipProductionPairIntent::statefulVersion) &&
            prior.intent.sourceWorkload.applicationID == intent.sourceWorkload.applicationID &&
            prior.intent.stateful.shardGroup == intent.stateful.shardGroup) ||
           (prior.intent.route.sourceClusterUUID == intent.route.sourceClusterUUID &&
            prior.intent.route.destinationClusterUUID == intent.route.destinationClusterUUID &&
            prior.intent.route.logicalWorkloadUUID == intent.route.logicalWorkloadUUID)))
      {
        if (failure) failure->assign("production pair route or workload scope already has an open coordinator"_ctv);
        return false;
      }
      if (prior.intent.protocolVersion == MothershipProductionPairIntent::statefulVersion &&
          prior.intent.sourceWorkload.applicationID == intent.sourceWorkload.applicationID &&
          prior.intent.stateful.shardGroup == intent.stateful.shardGroup &&
          (prior.phase == MothershipProductionPairPhase::cleanupComplete ||
           prior.phase == MothershipProductionPairPhase::statefulAbortedBeforeFence) &&
          (!hasStatefulHistory ||
           (prior.phase == MothershipProductionPairPhase::statefulAbortedBeforeFence ? prior.intent.stateful.sourceRetainedEpoch : prior.intent.stateful.targetOwnershipEpoch) >
           (latestStateful.phase == MothershipProductionPairPhase::statefulAbortedBeforeFence ? latestStateful.intent.stateful.sourceRetainedEpoch : latestStateful.intent.stateful.targetOwnershipEpoch)))
      {
        latestStateful = prior;
        hasStatefulHistory = true;
      }
    }
    const bool priorAborted = hasStatefulHistory && latestStateful.phase == MothershipProductionPairPhase::statefulAbortedBeforeFence;
    if (hasStatefulHistory &&
        (intent.protocolVersion != MothershipProductionPairIntent::statefulVersion ||
         intent.stateful.previousOperationUUID != latestStateful.intent.operationUUID ||
         intent.stateful.previousAuthorityEpoch != (priorAborted ? latestStateful.intent.stateful.sourceRetainedEpoch : latestStateful.intent.stateful.targetOwnershipEpoch) ||
         intent.sourceWorkload.clusterUUID != (priorAborted ? latestStateful.intent.sourceWorkload.clusterUUID : latestStateful.intent.targetWorkload.clusterUUID) ||
         intent.targetWorkload.clusterUUID != (priorAborted ? latestStateful.intent.targetWorkload.clusterUUID : latestStateful.intent.sourceWorkload.clusterUUID) ||
         intent.stateful.datasetUUID != latestStateful.intent.stateful.datasetUUID ||
         intent.stateful.contractSHA256 != latestStateful.intent.stateful.contractSHA256 ||
         intent.stateful.shardManifestSHA256 != latestStateful.intent.stateful.shardManifestSHA256 ||
         intent.stateful.sourceFenceEpoch < latestStateful.intent.stateful.targetOwnershipEpoch ||
         intent.stateful.targetOwnershipEpoch <= latestStateful.intent.stateful.targetOwnershipEpoch ||
         intent.stateful.sourceDurableWatermark < latestStateful.intent.stateful.sourceDurableWatermark))
    {
      if (failure) failure->assign("stateful ownership transfer requires the latest owner, exact reverse lineage, newer epochs and no watermark regression"_ctv);
      return false;
    }
    if (!hasStatefulHistory && intent.protocolVersion == MothershipProductionPairIntent::statefulVersion &&
        intent.stateful.previousOperationUUID != 0)
    {
      if (failure) failure->assign("stateful pair predecessor is absent from durable ownership history"_ctv);
      return false;
    }

    if (!mothershipProductionPairBegin(intent, nowMs, recorded, failure)) return false;
    MothershipProductionPairRecord copy = recorded;
    BitseryEngine::serialize(encoded, copy);
    if (!db.write(productionPairsColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear();
    return true;
  }

  bool prepareProductionPairStatefulCommand(uint128_t operationUUID, MothershipProductionPairPhase phase,
      int64_t nowMs, MothershipProductionPairRecord& record, String *failure = nullptr)
  {
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, record, failure)) return false;
    StatefulDataAuthorityOperation command;
    if (!mothershipProductionPairStatefulCommand(record, phase, command) ||
        mothershipProductionPairPhaseOrder(record.intent, phase) != mothershipProductionPairPhaseOrder(record.intent, record.phase) + 1 ||
        (record.hasPendingStatefulCommand && record.pendingStatefulPhase != phase)) return false;
    if (record.hasPendingStatefulCommand) return true;
    record.hasPendingStatefulCommand = true; record.pendingStatefulPhase = phase;
    record.transitionedAtMs = nowMs; ++record.transitionGeneration;
    String key, encoded; key.assignItoh(operationUUID); BitseryEngine::serialize(encoded, record);
    return mothershipProductionPairRecordValid(record, failure) && db.write(productionPairsColumnFamily, key, encoded, failure);
  }

  bool applyProductionPairStatefulReceipt(uint128_t operationUUID,
      const MothershipProductionStatefulReceipt& proof, int64_t nowMs,
      MothershipProductionPairRecord& recorded, bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, recorded, failure)) return false;
    auto updated = recorded;
    if (!mothershipProductionPairApplyStatefulReceipt(updated, proof, nowMs, failure)) return false;
    resumed = updated.transitionGeneration == recorded.transitionGeneration;
    if (!resumed) {
      String key, encoded;
      key.assignItoh(operationUUID);
      BitseryEngine::serialize(encoded, updated);
      if (!db.write(productionPairsColumnFamily, key, encoded, failure)) return false;
    }
    recorded = std::move(updated);
    return true;
  }

  bool abortProductionPairStatefulBeforeFence(uint128_t operationUUID, const String& receiptSHA256,
      int64_t nowMs, bool completed, MothershipProductionPairRecord& record, String *failure = nullptr,
      const MothershipProductionStatefulReceipt *cleanup = nullptr, const String *targetCompensation = nullptr)
  {
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, record, failure)) return false;
    if (!mothershipProductionPairAbortStatefulBeforeFence(record, receiptSHA256, nowMs, completed, failure, cleanup, targetCompensation)) return false;
    String key, encoded; key.assignItoh(operationUUID); BitseryEngine::serialize(encoded, record);
    return db.write(productionPairsColumnFamily, key, encoded, failure);
  }

  bool observeProductionPairStatefulAbort(uint128_t operationUUID, const MothershipProductionStatefulReceipt& proof,
      int64_t nowMs, MothershipProductionPairRecord& record, String *failure = nullptr)
  {
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, record, failure) ||
        !mothershipProductionPairObserveStatefulAbort(record, proof, nowMs, failure)) return false;
    String key, encoded; key.assignItoh(operationUUID); BitseryEngine::serialize(encoded, record);
    return db.write(productionPairsColumnFamily, key, encoded, failure);
  }

  bool observeProductionPairStatefulTargetCompensation(uint128_t operationUUID, const String& receiptSHA256,
      int64_t nowMs, MothershipProductionPairRecord& record, String *failure = nullptr)
  {
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, record, failure) ||
        !mothershipProductionPairObserveStatefulTargetCompensation(record, receiptSHA256, nowMs, failure)) return false;
    String key, encoded; key.assignItoh(operationUUID); BitseryEngine::serialize(encoded, record);
    return db.write(productionPairsColumnFamily, key, encoded, failure);
  }

  bool advanceProductionPair(uint128_t operationUUID, MothershipProductionPairPhase phase,
                             const String& receiptSHA256, int64_t nowMs,
                             MothershipProductionPairRecord& recorded, bool& resumed,
                             String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (operationUUID == 0 || !mothershipProductionPairPhaseValid(phase) ||
        phase == MothershipProductionPairPhase::prepared)
    {
      if (failure) failure->assign("production pair advance requires a receipt-bearing phase"_ctv);
      return false;
    }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, recorded, failure)) return false;
    MothershipProductionPairRecord updated = recorded;
    const bool wasSamePhase = updated.phase == phase;
    const bool advanced = phase == MothershipProductionPairPhase::transitApplied ?
        mothershipProductionPairMarkTransitApplied(updated, receiptSHA256, nowMs, failure) :
        mothershipProductionPairAdvance(updated, phase, receiptSHA256, nowMs, failure);
    if (!advanced) return false;
    resumed = wasSamePhase;
    if (resumed)
    {
      if (failure) failure->clear();
      return true;
    }
    String key = {}, encoded = {};
    key.assignItoh(operationUUID);
    BitseryEngine::serialize(encoded, updated);
    if (!db.write(productionPairsColumnFamily, key, encoded, failure)) return false;
    recorded = std::move(updated);
    if (failure) failure->clear();
    return true;
  }

  bool abortProductionPairBeforeTransit(uint128_t operationUUID, const String& receiptSHA256,
                                        int64_t nowMs, MothershipProductionPairRecord& recorded,
                                        bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (operationUUID == 0 || !mothershipProductionPairReceiptValid(receiptSHA256) || nowMs <= 0)
    { if (failure) failure->assign("production pair abort requires an operation, receipt, and timestamp"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, recorded, failure)) return false;
    MothershipProductionPairRecord updated = recorded;
    const bool wasAborted = updated.phase == MothershipProductionPairPhase::abortedBeforeTransit;
    if (!mothershipProductionPairAbortBeforeTransit(updated, receiptSHA256, nowMs, failure)) return false;
    resumed = wasAborted;
    if (resumed) { if (failure) failure->clear(); return true; }
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    BitseryEngine::serialize(encoded, updated);
    if (!db.write(productionPairsColumnFamily, key, encoded, failure)) return false;
    recorded = std::move(updated);
    if (failure) failure->clear();
    return true;
  }

  bool abortProductionPairBeforeCutover(uint128_t operationUUID, const String& receiptSHA256,
                                        int64_t nowMs, MothershipProductionPairRecord& recorded,
                                        bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (operationUUID == 0 || !mothershipProductionPairReceiptValid(receiptSHA256) || nowMs <= 0)
    { if (failure) failure->assign("production pair pre-cutover abort requires an operation, receipt, and timestamp"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, recorded, failure)) return false;
    MothershipProductionPairRecord updated = recorded;
    const bool wasAborted = updated.phase == MothershipProductionPairPhase::abortedBeforeCutover;
    if (!mothershipProductionPairAbortBeforeCutover(updated, receiptSHA256, nowMs, failure)) return false;
    resumed = wasAborted;
    if (resumed) { if (failure) failure->clear(); return true; }
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    BitseryEngine::serialize(encoded, updated);
    if (!db.write(productionPairsColumnFamily, key, encoded, failure)) return false;
    recorded = std::move(updated);
    if (failure) failure->clear();
    return true;
  }

  bool prepareProductionPairAbortBeforeCutover(uint128_t operationUUID, const String& receiptSHA256,
                                               int64_t nowMs, MothershipProductionPairRecord& recorded,
                                               bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (operationUUID == 0 || !mothershipProductionPairReceiptValid(receiptSHA256) || nowMs <= 0)
    { if (failure) failure->assign("production pair pending pre-cutover abort requires an operation, receipt, and timestamp"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadProductionPair(operationUUID, recorded, failure)) return false;
    MothershipProductionPairRecord updated = recorded;
    const bool wasPending = updated.phase == MothershipProductionPairPhase::abortBeforeCutoverPending;
    if (!mothershipProductionPairPrepareAbortBeforeCutover(updated, receiptSHA256, nowMs, failure)) return false;
    resumed = wasPending;
    if (resumed) { if (failure) failure->clear(); return true; }
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    BitseryEngine::serialize(encoded, updated);
    if (!db.write(productionPairsColumnFamily, key, encoded, failure)) return false;
    recorded = std::move(updated);
    if (failure) failure->clear();
    return true;
  }

  bool loadPhysicalServiceTransitBoundary(uint128_t boundaryUUID,
                                          MothershipPhysicalServiceTransitBoundary& boundary,
                                          String *failure = nullptr)
  {
    boundary = {};
    if (boundaryUUID == 0)
    {
      if (failure) failure->assign("physical service transit boundary UUID is required"_ctv);
      return false;
    }
    String key = {}, encoded = {}; key.assignItoh(boundaryUUID);
    if (!db.read(physicalTransitBoundariesColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, boundary) ||
        !mothershipPhysicalServiceTransitBoundaryValid(boundary) || boundary.boundaryUUID != boundaryUUID)
    {
      boundary = {};
      if (failure) failure->assign("physical service transit boundary is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool admitPhysicalServiceTransitBoundary(const MothershipPhysicalServiceTransitBoundary& requested,
                                            MothershipPhysicalServiceTransitBoundary& recorded,
                                            bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipPhysicalServiceTransitBoundaryValid(requested, failure) || requested.closed) return false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    MothershipProductionPairRecord pair = {};
    if (!loadProductionPair(requested.pairOperationUUID, pair, failure) ||
        pair.intent.protocolVersion != MothershipProductionPairIntent::version ||
        pair.phase < MothershipProductionPairPhase::targetAdmitted ||
        pair.phase >= MothershipProductionPairPhase::cleanupComplete ||
        pair.intent.physicalBoundaryUUID != requested.boundaryUUID ||
        pair.intent.route.routeUUID != requested.routeUUID || pair.intent.route.generation != requested.routeGeneration ||
        pair.intent.route.sourceClusterUUID != requested.sourceClusterUUID ||
        pair.intent.route.destinationClusterUUID != requested.targetClusterUUID ||
        pair.intent.selectorMachineUUID != requested.sourceMachineUUID ||
        pair.intent.targetWorkload.endpointMachineUUID != requested.targetMachineUUID ||
        pair.intent.selectorAddress != requested.sourceAddress ||
        pair.intent.targetWorkload.endpointIPv4 != requested.targetAddress ||
        pair.intent.selectorTCPPort != requested.sourceTCPPort ||
        pair.intent.targetWorkload.endpointTCPPort != requested.targetTCPPort)
    {
      if (failure && failure->empty()) failure->assign("physical service transit requires the exact target-admitted production pair"_ctv);
      return false;
    }
    String authorization = {};
    if (!cousinRouteAuthorizationDigest(pair.intent.route, authorization) ||
        authorization != requested.routeAuthorizationSHA256)
    {
      if (failure) failure->assign("physical service transit route authorization digest conflicts"_ctv);
      return false;
    }
    const auto executorBoundaryMatches = [&](uint128_t clusterUUID, uint128_t machineUUID,
                                             MothershipPhysicalFaultExecutorKind kind,
                                             uint128_t localVMBoundaryUUID,
                                             const String& cloudID) {
      if (kind == MothershipPhysicalFaultExecutorKind::localVM)
      {
        MothershipLocalVMBoundaryDescriptor boundary = {};
        return loadLocalVMBoundary(localVMBoundaryUUID, boundary, failure) && !boundary.retired &&
            boundary.clusterUUID == clusterUUID && boundary.machineUUID == machineUUID;
      }
      String identity = {}; identity.assignItoh(clusterUUID);
      MothershipProdigyCluster cluster = {};
      if (kind != MothershipPhysicalFaultExecutorKind::providerCloudVM ||
          !getClusterByIdentity(identity, cluster, failure) ||
          cluster.deploymentMode != MothershipClusterDeploymentMode::remote ||
          !mothershipClusterProviderIsIaaS(cluster.provider)) return false;
      uint32_t matches = 0;
      for (const auto& machine : cluster.topology.machines)
        if (machine.uuid == machineUUID && machine.kind == MachineConfig::MachineKind::vm &&
            machine.backing == ClusterMachineBacking::cloud && machine.cloud.cloudID == cloudID)
          ++matches;
      return matches == 1;
    };
    if (!executorBoundaryMatches(requested.sourceClusterUUID, requested.sourceMachineUUID,
                                 requested.sourceExecutorKind, requested.sourceLocalVMBoundaryUUID,
                                 requested.sourceCloudID) ||
        !executorBoundaryMatches(requested.targetClusterUUID, requested.targetMachineUUID,
                                 requested.targetExecutorKind, requested.targetLocalVMBoundaryUUID,
                                 requested.targetCloudID))
    {
      if (failure && failure->empty())
        failure->assign("physical service transit endpoints lack exact registered VM isolation boundaries"_ctv);
      return false;
    }
    String key = {}, encoded = {}, readFailure = {}; key.assignItoh(requested.boundaryUUID);
    if (db.read(physicalTransitBoundariesColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !mothershipPhysicalServiceTransitBoundaryValid(recorded) ||
          !mothershipPhysicalServiceTransitBoundaryEqual(recorded, requested))
      {
        recorded = {};
        if (failure) failure->assign("physical service transit boundary UUID conflicts with its immutable record"_ctv);
        return false;
      }
      resumed = true;
      if (failure) failure->clear();
      return true;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    Vector<String> values = {};
    if (!db.listValues(physicalTransitBoundariesColumnFamily, values, failure)) return false;
    for (const auto& value : values)
    {
      MothershipPhysicalServiceTransitBoundary prior = {};
      if (!BitseryEngine::deserializeSafe(value, prior) || !mothershipPhysicalServiceTransitBoundaryValid(prior))
      { if (failure) failure->assign("physical service transit registry contains a corrupt record"_ctv); return false; }
      if (!prior.closed && (prior.pairOperationUUID == requested.pairOperationUUID ||
          prior.routeUUID == requested.routeUUID))
      { if (failure) failure->assign("production pair already owns an open physical service transit"_ctv); return false; }
    }
    if (pair.phase != MothershipProductionPairPhase::targetAdmitted)
    {
      if (failure) failure->assign("new physical service transit admission requires the target-admitted production phase"_ctv);
      return false;
    }
    recorded = requested;
    auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(physicalTransitBoundariesColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear();
    return true;
  }

  bool closePhysicalServiceTransitBoundary(uint128_t boundaryUUID, const String& cleanupReceiptSHA256,
                                           MothershipPhysicalServiceTransitBoundary& recorded,
                                           bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipPhysicalFaultDigestValid(cleanupReceiptSHA256))
    { if (failure) failure->assign("physical service transit cleanup receipt is invalid"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadPhysicalServiceTransitBoundary(boundaryUUID, recorded, failure)) return false;
    MothershipProductionPairRecord pair = {};
    if (!loadProductionPair(recorded.pairOperationUUID, pair, failure) ||
        (pair.phase != MothershipProductionPairPhase::cleanupComplete &&
         pair.phase != MothershipProductionPairPhase::abortedBeforeCutover) ||
        pair.cleanupReceiptSHA256 != cleanupReceiptSHA256)
    {
      if (failure && failure->empty()) failure->assign("physical transit closure requires the exact completed or pre-cutover-aborted production pair receipt"_ctv);
      return false;
    }
    if (recorded.closed)
    {
      resumed = recorded.cleanupReceiptSHA256 == cleanupReceiptSHA256;
      if (!resumed && failure) failure->assign("physical transit cleanup receipt conflicts with the durable receipt"_ctv);
      return resumed;
    }
    recorded.closed = true; recorded.cleanupReceiptSHA256 = cleanupReceiptSHA256;
    String key = {}, encoded = {}; key.assignItoh(boundaryUUID); auto copy = recorded;
    BitseryEngine::serialize(encoded, copy);
    return db.write(physicalTransitBoundariesColumnFamily, key, encoded, failure);
  }

  // A boundary admitted while selector launch was still provisional must be
  // closable before the pair abort becomes durable.  This avoids making an
  // uncommitted transit permanently block the exact route after a crash.
  bool closePhysicalServiceTransitBoundaryBeforeTransit(
      uint128_t boundaryUUID, const String& abortReceiptSHA256,
      MothershipPhysicalServiceTransitBoundary& recorded, bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipPhysicalFaultDigestValid(abortReceiptSHA256))
    { if (failure) failure->assign("physical service transit abort receipt is invalid"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadPhysicalServiceTransitBoundary(boundaryUUID, recorded, failure)) return false;
    MothershipProductionPairRecord pair = {};
    if (!loadProductionPair(recorded.pairOperationUUID, pair, failure) ||
        (pair.phase != MothershipProductionPairPhase::targetAdmitted &&
         pair.phase != MothershipProductionPairPhase::abortedBeforeTransit) ||
        (pair.phase == MothershipProductionPairPhase::abortedBeforeTransit &&
         pair.cleanupReceiptSHA256 != abortReceiptSHA256) ||
        pair.intent.physicalBoundaryUUID != recorded.boundaryUUID ||
        pair.intent.route.routeUUID != recorded.routeUUID ||
        pair.intent.route.generation != recorded.routeGeneration)
    {
      if (failure && failure->empty()) failure->assign("physical transit abort requires the exact pre-transit production pair"_ctv);
      return false;
    }
    if (recorded.closed)
    {
      resumed = recorded.cleanupReceiptSHA256 == abortReceiptSHA256;
      if (!resumed && failure) failure->assign("physical transit abort receipt conflicts with the durable receipt"_ctv);
      return resumed;
    }
    recorded.closed = true; recorded.cleanupReceiptSHA256 = abortReceiptSHA256;
    String key = {}, encoded = {}; key.assignItoh(boundaryUUID); auto copy = recorded;
    BitseryEngine::serialize(encoded, copy);
    return db.write(physicalTransitBoundariesColumnFamily, key, encoded, failure);
  }

  bool loadLocalVMBoundary(uint128_t vmBoundaryUUID, MothershipLocalVMBoundaryDescriptor& descriptor,
                           String *failure = nullptr)
  {
    descriptor = {};
    if (vmBoundaryUUID == 0) { if (failure) failure->assign("local VM boundary UUID is required"_ctv); return false; }
    String key = {}, encoded = {}; key.assignItoh(vmBoundaryUUID);
    if (!db.read(localVMBoundariesColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, descriptor) ||
        !mothershipLocalVMBoundaryDescriptorValid(descriptor) || descriptor.vmBoundaryUUID != vmBoundaryUUID)
    { descriptor = {}; if (failure) failure->assign("local VM boundary is corrupt or unsupported"_ctv); return false; }
    if (failure) failure->clear(); return true;
  }

  // This is deliberately a registry-only listing primitive.  Callers which
  // need to prove that the external VM still matches the recorded descriptor
  // must separately use the sealed executor query.
  bool listLocalVMBoundaries(uint128_t clusterUUID,
                             Vector<MothershipLocalVMBoundaryDescriptor>& descriptors,
                             String *failure = nullptr)
  {
    descriptors.clear();
    if (clusterUUID == 0)
    { if (failure) failure->assign("local VM boundary listing requires a cluster UUID"_ctv); return false; }
    Vector<String> values = {};
    if (!db.listValues(localVMBoundariesColumnFamily, values, failure)) return false;
    for (const auto& value : values)
    {
      MothershipLocalVMBoundaryDescriptor candidate = {};
      if (!BitseryEngine::deserializeSafe(value, candidate) ||
          !mothershipLocalVMBoundaryDescriptorValid(candidate) ||
          !localVMBoundaryPublicKeySafeForInspection(candidate))
      { if (failure) failure->assign("local VM boundary registry contains a corrupt record"_ctv); return false; }
      if (candidate.clusterUUID == clusterUUID) descriptors.push_back(std::move(candidate));
    }
    if (failure) failure->clear();
    return true;
  }

  // Inspection accepts only the exact active set for the current three-machine
  // local topology.  Retired records remain useful audit history and are not
  // part of that live set.
  static bool activeLocalVMBoundariesExactForMachines(
      uint128_t clusterUUID, const Vector<uint128_t>& expectedMachineUUIDs,
      const Vector<MothershipLocalVMBoundaryDescriptor>& descriptors, String *failure = nullptr)
  {
    if (clusterUUID == 0 || expectedMachineUUIDs.size() != 3)
    { if (failure) failure->assign("local VM boundary inspection requires exactly three machine identities"_ctv); return false; }
    Vector<uint32_t> matches = {};
    Vector<uint128_t> activeBoundaryUUIDs = {};
    for (uint32_t index = 0; index < expectedMachineUUIDs.size(); ++index)
    {
      if (expectedMachineUUIDs[index] == 0)
      { if (failure) failure->assign("local VM boundary inspection requires nonzero machine identities"_ctv); return false; }
      for (uint32_t prior = 0; prior < index; ++prior)
        if (expectedMachineUUIDs[prior] == expectedMachineUUIDs[index])
        { if (failure) failure->assign("local VM boundary inspection topology contains duplicate machine identities"_ctv); return false; }
      matches.push_back(0);
    }
    for (const auto& descriptor : descriptors)
    {
      if (descriptor.clusterUUID != clusterUUID)
      { if (failure) failure->assign("local VM boundary inspection received a boundary from another cluster"_ctv); return false; }
      if (descriptor.retired) continue;
      for (uint128_t activeBoundaryUUID : activeBoundaryUUIDs)
        if (activeBoundaryUUID == descriptor.vmBoundaryUUID)
        { if (failure) failure->assign("local VM boundary inspection found duplicate active boundary identities"_ctv); return false; }
      activeBoundaryUUIDs.push_back(descriptor.vmBoundaryUUID);
      uint32_t index = 0;
      for (; index < expectedMachineUUIDs.size(); ++index)
        if (expectedMachineUUIDs[index] == descriptor.machineUUID) break;
      if (index == expectedMachineUUIDs.size())
      { if (failure) failure->assign("local VM boundary inspection found an active orphan boundary"_ctv); return false; }
      if (++matches[index] != 1)
      { if (failure) failure->assign("local VM boundary inspection found duplicate active boundaries"_ctv); return false; }
    }
    for (uint32_t count : matches)
      if (count != 1)
      { if (failure) failure->assign("local VM boundary inspection found a machine without one active boundary"_ctv); return false; }
    if (failure) failure->clear();
    return true;
  }

  bool findActiveLocalVMBoundary(uint128_t clusterUUID, uint128_t machineUUID,
                                 MothershipLocalVMBoundaryDescriptor& descriptor,
                                 String *failure = nullptr)
  {
    descriptor = {};
    if (clusterUUID == 0 || machineUUID == 0)
    { if (failure) failure->assign("local VM boundary lookup requires exact cluster and machine identities"_ctv); return false; }
    Vector<String> values = {};
    if (!db.listValues(localVMBoundariesColumnFamily, values, failure)) return false;
    uint32_t matches = 0;
    for (const auto& value : values)
    {
      MothershipLocalVMBoundaryDescriptor candidate = {};
      if (!BitseryEngine::deserializeSafe(value, candidate) ||
          !mothershipLocalVMBoundaryDescriptorValid(candidate))
      { if (failure) failure->assign("local VM boundary registry contains a corrupt record"_ctv); return false; }
      if (!candidate.retired && candidate.clusterUUID == clusterUUID && candidate.machineUUID == machineUUID)
      { descriptor = std::move(candidate); ++matches; }
    }
    if (matches != 1)
    {
      descriptor = {};
      if (failure) failure->assign("cluster machine does not have one exact active local VM boundary"_ctv);
      return false;
    }
    if (failure) failure->clear(); return true;
  }

  bool registerLocalVMBoundary(const MothershipLocalVMBoundaryDescriptor& requested,
                               MothershipLocalVMBoundaryDescriptor& recorded, bool& resumed,
                               String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipLocalVMBoundaryDescriptorValid(requested, failure) || requested.retired) return false;
    if (!localVMBoundaryPublicKeySafeForInspection(requested))
    { if (failure) failure->assign("local VM boundary host public key contains a control character"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}, readFailure = {}; key.assignItoh(requested.vmBoundaryUUID);
    if (db.read(localVMBoundariesColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !mothershipLocalVMBoundaryDescriptorValid(recorded) ||
          !mothershipLocalVMBoundaryDescriptorEqual(recorded, requested))
      { recorded = {}; if (failure) failure->assign("local VM boundary UUID conflicts with its immutable record"_ctv); return false; }
      resumed = true; if (failure) failure->clear(); return true;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    Vector<String> values = {};
    if (!db.listValues(localVMBoundariesColumnFamily, values, failure)) return false;
    for (const auto& value : values)
    {
      MothershipLocalVMBoundaryDescriptor prior = {};
      if (!BitseryEngine::deserializeSafe(value, prior) || !mothershipLocalVMBoundaryDescriptorValid(prior))
      { if (failure) failure->assign("local VM boundary registry contains a corrupt record"_ctv); return false; }
      if (!prior.retired && prior.clusterUUID == requested.clusterUUID && prior.machineUUID == requested.machineUUID)
      { if (failure) failure->assign("local cluster machine already has an active VM boundary"_ctv); return false; }
    }
    recorded = requested; auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(localVMBoundariesColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear(); return true;
  }

  // Refreshing a sealed launcher is not boundary re-registration.  The lock
  // makes the read/compare/write replacement atomic, and the comparison pins
  // every identity and provider-state proof while allowing only a new proven
  // executor digest.
  bool refreshLocalVMBoundaryExecutor(const MothershipLocalVMBoundaryDescriptor& expected,
                                      const MothershipLocalVMBoundaryDescriptor& requested,
                                      MothershipLocalVMBoundaryDescriptor& recorded,
                                      bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipLocalVMBoundaryDescriptorValid(expected, failure) || expected.retired ||
        !mothershipLocalVMBoundaryDescriptorValid(requested, failure) || requested.retired ||
        !mothershipLocalVMBoundaryDescriptorSameIdentityAndState(expected, requested) ||
        expected.executorSHA256 == requested.executorSHA256)
    {
      if (failure && failure->empty())
        failure->assign("local VM boundary refresh requires one exact executor-only compare-and-swap"_ctv);
      return false;
    }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}; key.assignItoh(requested.vmBoundaryUUID);
    if (!db.read(localVMBoundariesColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) ||
        !mothershipLocalVMBoundaryDescriptorValid(recorded) || recorded.retired)
    {
      recorded = {};
      if (failure && failure->empty()) failure->assign("local VM boundary refresh requires one active durable boundary"_ctv);
      return false;
    }
    if (mothershipLocalVMBoundaryDescriptorEqual(recorded, requested))
    {
      resumed = true;
      if (failure) failure->clear();
      return true;
    }
    if (!mothershipLocalVMBoundaryDescriptorEqual(recorded, expected))
    {
      recorded = {};
      if (failure) failure->assign("local VM boundary changed since its executor refresh proof"_ctv);
      return false;
    }
    recorded = requested;
    auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(localVMBoundariesColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear();
    return true;
  }

  bool admitPhysicalClusterNetworkFault(const MothershipPhysicalClusterNetworkFaultRequest& requested,
                                        const MothershipPhysicalFaultMachineObservation& sourceAdmission,
                                        const MothershipPhysicalFaultMachineObservation& targetAdmission,
                                        MothershipPhysicalClusterNetworkFaultRecord& recorded,
                                        bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipPhysicalClusterNetworkFaultRequestValid(requested, failure)) return false;
    if (!mothershipPhysicalFaultMachineObservationValid(sourceAdmission) ||
        !mothershipPhysicalFaultMachineObservationValid(targetAdmission) ||
        sourceAdmission.clusterUUID != requested.sourceClusterUUID ||
        sourceAdmission.machineUUID != requested.sourceMachineUUID ||
        targetAdmission.clusterUUID != requested.targetClusterUUID ||
        targetAdmission.machineUUID != requested.targetMachineUUID)
    { if (failure) failure->assign("network fault admission observations do not bind the exact request"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    MothershipPhysicalServiceTransitBoundary boundary = {};
    if (!loadPhysicalServiceTransitBoundary(requested.boundaryUUID, boundary, failure) || boundary.closed ||
        boundary.sourceClusterUUID != requested.sourceClusterUUID || boundary.targetClusterUUID != requested.targetClusterUUID ||
        boundary.sourceMachineUUID != requested.sourceMachineUUID || boundary.targetMachineUUID != requested.targetMachineUUID)
    { if (failure && failure->empty()) failure->assign("network fault does not bind an open exact physical transit boundary"_ctv); return false; }
    String key = {}, encoded = {}, readFailure = {}; key.assignItoh(requested.operationUUID);
    if (db.read(physicalNetworkFaultsColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !mothershipPhysicalClusterNetworkFaultRecordValid(recorded) ||
          !mothershipPhysicalClusterNetworkFaultReplayAdmissible(recorded.request, requested) ||
          !mothershipPhysicalFaultMachineObservationEqual(recorded.sourceAdmission, sourceAdmission) ||
          !mothershipPhysicalFaultMachineObservationEqual(recorded.targetAdmission, targetAdmission))
      { recorded = {}; if (failure) failure->assign("network fault operation conflicts with its immutable request"_ctv); return false; }
      resumed = true; if (failure) failure->clear(); return true;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded.request = requested; recorded.sourceAdmission = sourceAdmission;
    recorded.targetAdmission = targetAdmission; auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(physicalNetworkFaultsColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear(); return true;
  }

  bool loadPhysicalClusterNetworkFault(uint128_t operationUUID,
                                       MothershipPhysicalClusterNetworkFaultRecord& recorded,
                                       String *failure = nullptr)
  {
    recorded = {};
    if (operationUUID == 0) { if (failure) failure->assign("network fault operation UUID is required"_ctv); return false; }
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    if (!db.read(physicalNetworkFaultsColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
        !mothershipPhysicalClusterNetworkFaultRecordValid(recorded) || recorded.request.operationUUID != operationUUID)
    { recorded = {}; if (failure) failure->assign("network fault record is corrupt or unsupported"_ctv); return false; }
    if (failure) failure->clear(); return true;
  }

  bool recordPhysicalClusterNetworkFaultReceipt(const MothershipPhysicalClusterNetworkFaultRequest& request,
                                                const MothershipPhysicalClusterNetworkFaultReceipt& receipt,
                                                MothershipPhysicalClusterNetworkFaultRecord& recorded,
                                                bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipPhysicalClusterNetworkFaultReceiptValid(request, receipt, failure)) return false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}; key.assignItoh(request.operationUUID);
    if (!db.read(physicalNetworkFaultsColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) ||
        !mothershipPhysicalClusterNetworkFaultRecordValid(recorded) ||
        !mothershipPhysicalClusterNetworkFaultRequestEqual(recorded.request, request) ||
        !mothershipPhysicalFaultMachineObservationEqual(recorded.sourceAdmission, receipt.sourceBefore) ||
        !mothershipPhysicalFaultMachineObservationEqual(recorded.targetAdmission, receipt.targetBefore))
    { if (failure && failure->empty()) failure->assign("network fault receipt has no exact durable request"_ctv); return false; }
    if (recorded.hasReceipt)
    {
      resumed = mothershipPhysicalFaultExactSerializedEqual(recorded.receipt, receipt);
      if (!resumed && failure) failure->assign("network fault receipt conflicts with the durable receipt"_ctv);
      return resumed;
    }
    recorded.hasReceipt = true; recorded.receipt = receipt; auto copy = recorded;
    BitseryEngine::serialize(encoded, copy);
    return db.write(physicalNetworkFaultsColumnFamily, key, encoded, failure);
  }

  // Recover an incomplete immutable tuple before any caller can mint a new
  // generation. A completed row is loaded separately through its receipt.
  bool loadNametagQualificationExecution(const MothershipNametagQualificationAdapter& adapter,
                                         const MothershipNametagQualificationIntent& intent,
                                         MothershipNametagQualificationExecutionRecord& recorded,
                                         bool& found, String *failure = nullptr)
  {
    recorded = {}; found = false;
    if (!nametagQualificationAdapterFrozen(adapter) || !mothershipNametagQualificationIntentValid(intent) ||
        intent.row != adapter.row || intent.direction != adapter.direction) {
      if (failure) failure->assign("qualification execution identity is invalid"_ctv); return false;
    }
    String key = {}, encoded = {}, readFailure = {};
    if (!nametagQualificationKey(adapter, intent.runUUID, key)) {
      if (failure) failure->assign("qualification execution run identity is invalid"_ctv); return false;
    }
    if (!db.read(nametagQualificationExecutionsColumnFamily, key, encoded, &readFailure)) {
      if (readFailure.equal("record not found"_ctv)) { if (failure) failure->clear(); return true; }
      if (failure) *failure = readFailure; return false;
    }
    if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
        !mothershipNametagQualificationExecutionRecordValid(recorded) ||
        !nametagQualificationIntentExact(recorded.intent, intent) ||
        !nametagQualificationSeedReferencesValid(recorded, failure)) {
      recorded = {}; if (failure && failure->empty()) failure->assign("qualification execution is corrupt or mismatched"_ctv); return false;
    }
    found = true; if (failure) failure->clear(); return true;
  }

  // Seed execution stores references to the existing immutable successor
  // records. Resolve those records here rather than trusting a caller's digest
  // or duplicating their native evidence in a second journal.
  bool nametagQualificationSeedReferencesValid(
      const MothershipNametagQualificationExecutionRecord& execution, String *failure = nullptr)
  {
    if (execution.protocolVersion != execution.seedVersion) return true;
    auto reject = [&](const char* reason) { if (failure) failure->assign(reason); return false; };
    if (!mothershipNametagQualificationExecutionRecordValid(execution)) return reject("seed execution is invalid");
    auto injection = execution.intent;
    if (execution.intent.direction == MothershipNametagQualificationDirection::observation) {
      const auto *adapter = mothershipNametagQualificationAdapterForTuple(execution.intent.row,
          MothershipNametagQualificationDirection::injection, execution.intent.rowID,
          execution.intent.deadlineSeconds, execution.intent.convergenceSeconds);
      bool found = false;
      MothershipNametagQualificationReceipt receipt;
      String digest;
      if (!adapter || !loadNametagQualificationIntent(*adapter, execution.intent.priorInjectionRunUUID,
            injection, found, failure) || !found ||
          !loadNametagQualificationReceipt(*adapter, execution.intent.priorInjectionRunUUID, receipt, found, failure) || !found ||
          !mothershipNametagQualificationReceiptDigest(receipt, digest) ||
          digest != execution.intent.priorInjectionReceiptDigest ||
          injection.allMastersOperationUUID != execution.intent.allMastersOperationUUID ||
          injection.seedInputSHA256 != execution.intent.seedInputSHA256 ||
          injection.seedSuccessorOperationUUIDs != execution.intent.seedSuccessorOperationUUIDs ||
          injection.seedChallengeUUIDs != execution.intent.seedChallengeUUIDs) return reject("seed observation does not match its durable injection");
    }
    MothershipNametagAllMastersRecord original, current;
    if (!loadNametagAllMasters(execution.intent.allMastersOperationUUID, original, failure)) return false;
    String originalBytes, originalDigest; auto copy = original;
    if (!BitseryEngine::serialize(originalBytes, copy) ||
        !prodigyComputeSHA256Hex(originalBytes, originalDigest, failure)) return false;
    for (uint32_t i = 0; i < execution.seedSuccessors.size(); ++i) {
      const auto& ref = execution.seedSuccessors[i];
      String key, operation, bytes, digest; key.assign("seed-successor:"_ctv);
      operation.assignItoh(ref.operationUUID); key.append(operation);
      MothershipNametagSeedSuccessor successor;
      if (!db.read(nametagAllMastersColumnFamily, key, bytes, failure)) return false;
      if (!prodigyComputeSHA256Hex(bytes, digest, failure) || digest != ref.sha256)
        return reject("seed successor reference hash mismatch");
      if (!BitseryEngine::deserializeSafe(bytes, successor)) return reject("seed successor cannot be decoded");
      if (successor.operationUUID != ref.operationUUID ||
          successor.predecessorOperationUUID != execution.intent.allMastersOperationUUID ||
          successor.predecessorSHA256 != originalDigest) return reject("seed successor root identity mismatch");
      if (successor.qualificationRunUUID != injection.runUUID ||
          successor.executionGeneration != injection.executionGeneration ||
          successor.qualificationRow != uint8_t(execution.intent.row) || successor.site != 1)
        return reject("seed successor qualification identity mismatch");
      if (successor.stage != MothershipNametagSeedSuccessorStage::complete ||
          successor.heldReceipt.challengeUUID != execution.intent.seedChallengeUUIDs[i] ||
          successor.kind != (execution.intent.row == MothershipNametagQualificationRow::seedInterruptionResume && i == 0 ?
              MothershipNametagSeedSuccessorKind::replica : MothershipNametagSeedSuccessorKind::site))
        return reject("seed successor stage, challenge or kind mismatch");
      if (i && (successor.predecessorSuccessorUUID != execution.seedSuccessors[i - 1].operationUUID ||
                successor.predecessorSuccessorSHA256 != execution.seedSuccessors[i - 1].sha256))
        return reject("seed successor predecessor link mismatch");
      if (!loadNametagSeedSuccessorPrior(execution.intent.allMastersOperationUUID, originalDigest,
              ref.operationUUID, ref.sha256, current, failure))
        return reject("seed successor chain failed validation");
    }
    if (!execution.seedControlWitnessDigest.empty() || !execution.seedFinalReadbacks.empty()) {
      if (execution.seedSuccessors.size() != execution.intent.seedSuccessorOperationUUIDs.size()) return reject("seed successor set incomplete");
      MothershipNametagSourceBaselineRecord baseline; bool found = false;
      if (!loadNametagSourceBaseline(original.intent.sourceBaselineOperationUUID, baseline, found, failure) || !found ||
          !prodigyNametagSourceBaselineReceiptValid(baseline.receipt) ||
          execution.seedBaselineOperationUUID != original.intent.sourceBaselineOperationUUID ||
          execution.seedBaselineFixtureSHA256 != baseline.receipt.fixtureManifestSHA256 ||
          execution.seedBaselineReadbackSHA256 != baseline.receipt.canonicalReadbackDigest) return reject("seed source baseline mismatch or missing");
      for (uint32_t site = 0; site < 3; ++site) {
        const auto& observed = current.intent.sites[site];
        const std::array<uint64_t, 5> expected = {observed.hotDeploymentID, observed.coldDeploymentID,
            observed.radarDeploymentID, observed.pulseDeploymentID, current.intent.sites[0].truthDeploymentID};
        if (execution.seedStoreDeploymentIDs[site] != expected) return reject("seed projected store deployment mismatch");
      }
    }
    return true;
  }

  // Creation happens before any externally-visible qualification command.  A
  // missing record is therefore safe to create; a malformed or conflicting
  // one is never treated as a fresh run.
  bool persistNametagQualificationExecutionPrepared(const MothershipNametagQualificationAdapter& adapter,
                                                     const MothershipNametagQualificationIntent& intent,
                                                     MothershipNametagQualificationExecutionRecord& recorded,
                                                     bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagQualificationIntentValid(intent)) {
      if (failure) failure->assign("qualification execution has invalid immutable intent"_ctv); return false;
    }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure)) return false;
    if (found) {
      resumed = recorded.phase == MothershipNametagQualificationExecutionPhase::prepared;
      if (!resumed && failure) failure->assign("qualification execution is already beyond prepared"_ctv);
      return resumed;
    }
    String key = {}, durableEncoded = {}, encoded = {};
    if (!nametagQualificationKey(adapter, intent.runUUID, key) ||
        !db.read(nametagQualificationIntentsColumnFamily, key, durableEncoded, failure)) {
      if (failure && failure->empty()) failure->assign("qualification execution has no durable v4 intent"_ctv);
      return false;
    }
    MothershipNametagQualificationIntent durable = {};
    if (!BitseryEngine::deserializeSafe(durableEncoded, durable) ||
        !mothershipNametagQualificationIntentValid(durable) || !nametagQualificationIntentExact(durable, intent)) {
      if (failure) failure->assign("qualification execution intent conflicts with durable v4 intent"_ctv); return false;
    }
    recorded.intent = intent;
    if (intent.protocolVersion == intent.seedVersion) recorded.protocolVersion = recorded.seedVersion;
    auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    return db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool updateNametagQualificationSeedExecution(
      const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationExecutionRecord& proposed,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (proposed.protocolVersion != proposed.seedVersion ||
        !mothershipNametagQualificationExecutionRecordValid(proposed) ||
        !loadNametagQualificationExecution(adapter, proposed.intent, recorded, found, failure) || !found ||
        recorded.protocolVersion != recorded.seedVersion ||
        proposed.seedSuccessors.size() < recorded.seedSuccessors.size() ||
        proposed.seedFinalReadbacks.size() < recorded.seedFinalReadbacks.size() ||
        !nametagQualificationSeedReferencesValid(proposed, failure)) return false;
    for (uint32_t i = 0; i < recorded.seedSuccessors.size(); ++i)
      if (proposed.seedSuccessors[i].operationUUID != recorded.seedSuccessors[i].operationUUID ||
          proposed.seedSuccessors[i].sha256 != recorded.seedSuccessors[i].sha256) return false;
    for (uint32_t i = 0; i < recorded.seedFinalReadbacks.size(); ++i) {
      auto before = recorded.seedFinalReadbacks[i], after = proposed.seedFinalReadbacks[i]; String a, b;
      if (!BitseryEngine::serialize(a, before) || !BitseryEngine::serialize(b, after) || a != b) return false;
    }
    if (!recorded.seedControlWitnessDigest.empty() &&
        (recorded.seedControlWitnessDigest != proposed.seedControlWitnessDigest ||
         recorded.seedBaselineOperationUUID != proposed.seedBaselineOperationUUID ||
         recorded.seedBaselineFixtureSHA256 != proposed.seedBaselineFixtureSHA256 ||
         recorded.seedBaselineReadbackSHA256 != proposed.seedBaselineReadbackSHA256 ||
         recorded.seedStoreDeploymentIDs != proposed.seedStoreDeploymentIDs)) return false;
    const bool samePhase = proposed.phase == recorded.phase;
    const bool converged = recorded.phase == MothershipNametagQualificationExecutionPhase::prepared &&
        proposed.phase == MothershipNametagQualificationExecutionPhase::converging &&
        mothershipNametagQualificationSeedExecutionComplete(proposed);
    if (!samePhase && !converged) return false;
    auto copy = proposed; String encoded, key;
    if (!nametagQualificationKey(adapter, proposed.intent.runUUID, key) ||
        !BitseryEngine::serialize(encoded, copy)) return false;
    if (recorded.phase == MothershipNametagQualificationExecutionPhase::verified) {
      auto old = recorded; String previous;
      return BitseryEngine::serialize(previous, old) && previous == encoded;
    }
    if (!db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure)) return false;
    recorded = proposed; return true;
  }

  // Row 17 records its write and the two exact process incarnations in the
  // existing operation record; no driver marker is accepted as registry proof.
  bool recordNametagQualificationRestart(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent, uint128_t nonce,
      const MothershipNametagQualificationExecutionRecord::RestartProcess& process,
      const ProdigyNametagQualificationApplicationReceipt *localReceipt,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.phase != MothershipNametagQualificationExecutionPhase::prepared || !nonce) return false;
    if (localReceipt) {
      if (recorded.protocolVersion == MothershipNametagQualificationExecutionRecord::restartVersion) return false;
      recorded.protocolVersion = MothershipNametagQualificationExecutionRecord::restartVersion;
      recorded.restartNonce = nonce; recorded.restartBefore = process; recorded.restartLocalWorkReceipt = *localReceipt;
    } else {
      if (recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::restartVersion ||
          recorded.restartNonce != nonce || recorded.restartAfter.pid) return false;
      recorded.restartAfter = process;
    }
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) && nametagQualificationKey(adapter, intent.runUUID, key) &&
        BitseryEngine::serialize(encoded, copy) && db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool advanceNametagQualificationExecution(const MothershipNametagQualificationAdapter& adapter,
                                            const MothershipNametagQualificationIntent& intent,
                                            MothershipNametagQualificationExecutionPhase expected,
                                            MothershipNametagQualificationExecutionPhase next,
                                            MothershipNametagQualificationExecutionRecord& recorded,
                                            bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found) {
      if (found == false && failure && failure->empty()) failure->assign("qualification execution phase is absent"_ctv);
      return false;
    }
    if (recorded.phase == next) { resumed = true; if (failure) failure->clear(); return true; }
    if (prodigyNametagQualificationPathRow(uint8_t(intent.row)) &&
        intent.direction == MothershipNametagQualificationDirection::injection &&
        next != MothershipNametagQualificationExecutionPhase::failed &&
        !mothershipNametagQualificationPathExecutionComplete(recorded)) {
      if (failure) failure->assign("qualification path lacks the complete durable fault and application witnesses"_ctv);
      return false;
    }
    if (prodigyNametagQualificationPathRow(uint8_t(intent.row)) &&
        intent.direction == MothershipNametagQualificationDirection::injection &&
        next == MothershipNametagQualificationExecutionPhase::failed &&
        std::any_of(recorded.pathFaults.begin(), recorded.pathFaults.end(), [](const auto& fault) {
          return !fault.restored.response;
        })) return false;
    if (intent.row == MothershipNametagQualificationRow::truthClaimPartition &&
        intent.direction == MothershipNametagQualificationDirection::injection &&
        ((next != MothershipNametagQualificationExecutionPhase::failed && !mothershipNametagQualificationClaimExecutionComplete(recorded)) ||
         (next == MothershipNametagQualificationExecutionPhase::failed &&
          std::any_of(recorded.pathFaults.begin(), recorded.pathFaults.end(), [](const auto& f) { return !f.restored.response; })))) return false;
    if (intent.row == MothershipNametagQualificationRow::graphKvReplayReorder &&
        intent.direction == MothershipNametagQualificationDirection::injection &&
        next != MothershipNametagQualificationExecutionPhase::failed &&
        !mothershipNametagQualificationReplayExecutionComplete(recorded)) {
      if (failure) failure->assign("qualification replay lacks durable native and independent readback witnesses"_ctv);
      return false;
    }
    if (intent.row == MothershipNametagQualificationRow::localWriterIsolation &&
        intent.direction == MothershipNametagQualificationDirection::injection) {
      const auto& w = recorded.writerIsolation;
      if (recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::writerIsolationVersion ||
          (next == MothershipNametagQualificationExecutionPhase::faultApplied &&
           (!w.arm.ready || !w.localArm.runUUID || !w.isolated.ready || !w.isolated.isolated)) ||
          (next == MothershipNametagQualificationExecutionPhase::workloadIssued &&
           (!w.localWork.runUUID || !w.queried.ready || !w.queried.isolated)) ||
          (next == MothershipNametagQualificationExecutionPhase::faultRestored && !w.released.ready)) {
        if (failure) failure->assign("writer isolation lacks the exact durable phase witness"_ctv);
        return false;
      }
    }
    if (intent.row == MothershipNametagQualificationRow::mothershipRestartResume &&
        intent.direction == MothershipNametagQualificationDirection::injection &&
        (recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::restartVersion || !recorded.restartAfter.pid)) {
      if (failure) failure->assign("qualification restart lacks a durable new process incarnation"_ctv); return false;
    }
    if (intent.protocolVersion == MothershipNametagQualificationIntent::cousinRecoveryVersion &&
        recorded.protocolVersion < MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion) {
      if (failure) failure->assign("cousin recovery requires durable pre-fault bindings"_ctv); return false;
    }
    if (intent.protocolVersion == MothershipNametagQualificationIntent::cousinRecoveryVersion &&
        !recorded.cousinRecoveryAborting &&
        recorded.protocolVersion == MothershipNametagQualificationExecutionRecord::cousinTransportVersion) {
      const bool complete = recorded.cousinNativeWitnesses.size() == intent.cousinRecoveries.size() &&
          std::all_of(recorded.cousinNativeWitnesses.begin(), recorded.cousinNativeWitnesses.end(), [&](const auto& w) {
            return expected == MothershipNametagQualificationExecutionPhase::prepared ? w.arm.ready :
                expected == MothershipNametagQualificationExecutionPhase::faultApplied ? w.fault.ready :
                expected == MothershipNametagQualificationExecutionPhase::faultRestored ? w.final.ready : true;
          });
      if (!complete) { if (failure) failure->assign("qualification cousin phase lacks native transport proof"_ctv); return false; }
      if (expected == MothershipNametagQualificationExecutionPhase::faultApplied && !recorded.cousinLocalWorkReceipt.runUUID) {
        if (failure) failure->assign("qualification cousin phase lacks EWR local-work proof"_ctv); return false;
      }
    }
    if (intent.protocolVersion == MothershipNametagQualificationIntent::cousinRecoveryVersion &&
        !recorded.cousinRecoveryAborting &&
        recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::cousinTransportVersion) {
      if (failure) failure->assign("qualification cousin phase lacks native transport proof"_ctv); return false;
    }
    if (recorded.phase != expected || !mothershipNametagQualificationExecutionPhaseTransitionValid(expected, next, intent)) {
      if (failure) failure->assign("qualification execution phase transition is unsafe"_ctv); return false;
    }
    recorded.phase = next; String key = {}, encoded = {}; auto copy = recorded;
    if (!nametagQualificationKey(adapter, intent.runUUID, key) || !BitseryEngine::serialize(encoded, copy)) return false;
    return db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationCousinLocalWork(
      const MothershipNametagQualificationAdapter& adapter, const MothershipNametagQualificationIntent& intent,
      const ProdigyNametagQualificationApplicationReceipt& receipt,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::cousinTransportVersion ||
        recorded.phase != MothershipNametagQualificationExecutionPhase::faultApplied || recorded.cousinRecoveryAborting) return false;
    if (recorded.cousinLocalWorkReceipt.runUUID) {
      auto left = recorded.cousinLocalWorkReceipt, right = receipt; String a = {}, b = {};
      return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
    }
    recorded.cousinLocalWorkReceipt = receipt;
    if (!mothershipNametagQualificationExecutionRecordValid(recorded)) return false;
    String key = {}, encoded = {}; auto copy = recorded;
    return nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationWriterIsolationLocalWork(
      const MothershipNametagQualificationAdapter& adapter, const MothershipNametagQualificationIntent& intent,
      const ProdigyNametagQualificationApplicationReceipt& receipt,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::writerIsolationVersion ||
        !prodigyNametagQualificationApplicationReceiptValid(receipt) ||
        receipt.protocolVersion != ProdigyNametagQualificationApplicationReceipt::writerStageVersion ||
        receipt.runUUID != intent.runUUID || receipt.executionGeneration != intent.executionGeneration ||
        receipt.row != uint8_t(intent.row) || receipt.direction != uint8_t(intent.direction) || receipt.rowID != intent.rowID ||
        receipt.localClusterUUID != recorded.writerIsolation.challenge.clusterUUID ||
        receipt.writerChallengeUUID != recorded.writerIsolation.challenge.challengeUUID) return false;
    auto& w = recorded.writerIsolation;
    auto *slot = receipt.writerStage == ProdigyNametagQualificationWriterStage::arm ? &w.localArm : &w.localWork;
    if ((receipt.writerStage == ProdigyNametagQualificationWriterStage::arm &&
         (recorded.phase != MothershipNametagQualificationExecutionPhase::prepared || !w.arm.ready)) ||
        (receipt.writerStage == ProdigyNametagQualificationWriterStage::survivorWrites &&
         (recorded.phase != MothershipNametagQualificationExecutionPhase::faultApplied || !w.isolated.ready)) ||
        (receipt.writerStage != ProdigyNametagQualificationWriterStage::arm &&
         receipt.writerStage != ProdigyNametagQualificationWriterStage::survivorWrites)) return false;
    if (slot->runUUID) { auto left = *slot, right = receipt; String a = {}, b = {};
      return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b; }
    *slot = receipt;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationWriterIsolationWitness(
      const MothershipNametagQualificationAdapter& adapter, const MothershipNametagQualificationIntent& intent,
      const ProdigyNametagQualificationWriterIsolation& value,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        intent.row != MothershipNametagQualificationRow::localWriterIsolation ||
        intent.direction != MothershipNametagQualificationDirection::injection) return false;
    auto& w = recorded.writerIsolation;
    auto identical = [](auto left, auto right) {
      String a = {}, b = {}; return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
    };
    if (!value.response) {
      if (recorded.phase != MothershipNametagQualificationExecutionPhase::prepared ||
          value.stage != ProdigyNametagQualificationWriterIsolationStage::arm) return false;
      if (w.challenge.challengeUUID) return identical(w.challenge, value);
      w.challenge = value;
    } else {
      if (!value.ready || !w.challenge.challengeUUID) return false;
      auto *slot = value.stage == ProdigyNametagQualificationWriterIsolationStage::arm ? &w.arm :
          value.stage == ProdigyNametagQualificationWriterIsolationStage::isolate ? &w.isolated :
          value.stage == ProdigyNametagQualificationWriterIsolationStage::query ? &w.queried : &w.released;
      if (slot->response) return identical(*slot, value);
      if ((value.stage == ProdigyNametagQualificationWriterIsolationStage::arm &&
           recorded.phase != MothershipNametagQualificationExecutionPhase::prepared) ||
          (value.stage == ProdigyNametagQualificationWriterIsolationStage::isolate &&
           (recorded.phase != MothershipNametagQualificationExecutionPhase::prepared || !w.localArm.runUUID)) ||
          (value.stage == ProdigyNametagQualificationWriterIsolationStage::query &&
           recorded.phase != MothershipNametagQualificationExecutionPhase::faultApplied) ||
          (value.stage == ProdigyNametagQualificationWriterIsolationStage::release &&
           recorded.phase != MothershipNametagQualificationExecutionPhase::workloadIssued && !w.aborting)) return false;
      *slot = value;
    }
    recorded.protocolVersion = MothershipNametagQualificationExecutionRecord::writerIsolationVersion;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationClaimReceipt(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent, const ProdigyNametagQualificationApplicationReceipt& receipt,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        intent.row != MothershipNametagQualificationRow::truthClaimPartition ||
        intent.direction != MothershipNametagQualificationDirection::injection || recorded.pathAborting ||
        (recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::version &&
         recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::claimVersion)) return false;
    for (const auto& previous : recorded.claimReceipts)
      if (previous.localClusterUUID == receipt.localClusterUUID && previous.claimStage == receipt.claimStage) {
        auto a = previous, b = receipt; String left = {}, right = {};
        return BitseryEngine::serialize(left, a) && BitseryEngine::serialize(right, b) && left == right;
      }
    const auto stage = receipt.claimStage;
    if (recorded.phase != MothershipNametagQualificationExecutionPhase::prepared ||
        !mothershipNametagQualificationClaimStageMayRecord(recorded, stage)) return false;
    recorded.claimReceipts.push_back(receipt);
    if (stage == ProdigyNametagQualificationClaimStage::contend) {
      size_t count = 0; for (const auto& r : recorded.claimReceipts) if (r.claimStage == stage) ++count;
      if (count == 3) {
        for (size_t claim = 0; claim < 3; ++claim) {
          size_t winners = 0; uint128_t site = 0;
          for (const auto& r : recorded.claimReceipts) if (r.claimStage == stage && r.claimResults[claim].accepted) {
            if (!r.claimResults[claim].observed || r.localClusterUUID == intent.probeTargets[1].clusterUUID) return false;
            ++winners; site = r.localClusterUUID;
          }
          if (winners != 1) return false;
          recorded.claimWinnerSites[claim] = site;
        }
      }
    }
    recorded.protocolVersion = MothershipNametagQualificationExecutionRecord::claimVersion;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  // Persist the complete selected batch before sending any pause. Replays may
  // only reuse the exact retained requests, including their original deadline.
  bool recordNametagQualificationPathBatch(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent, uint8_t batch,
      const Vector<MothershipNametagQualificationExecutionRecord::PathFaultWitness>& proposed,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false; MothershipNametagAllMastersRecord allMasters = {};
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        intent.direction != MothershipNametagQualificationDirection::injection ||
        !(prodigyNametagQualificationPathRow(uint8_t(intent.row)) ||
          intent.row == MothershipNametagQualificationRow::truthClaimPartition) ||
        !loadNametagAllMasters(intent.allMastersOperationUUID, allMasters, failure) ||
        !mothershipNametagAllMastersRecordValid(allMasters) || allMasters.intent.sites.size() != 3) return false;
    const auto ewr = allMasters.intent.sites[0].clusterUUID, ord = allMasters.intent.sites[1].clusterUUID;
    const bool row11 = intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery;
    if (batch > (row11 ? 1 : 0)) return false;
    auto selected = [&](const CrossClusterMasqueGatewayAuthority& a) {
      if (intent.row == MothershipNametagQualificationRow::ewrOrdPathLoss)
        return a.localClusterUUID == ewr && a.peerClusterUUID == ord;
      return a.localClusterUUID == ord && (!row11 || batch == 1 ||
          (a.peerClusterUUID == ewr && a.tunnelSlot == 0));
    };
    Vector<CrossClusterMasqueGatewayAuthority> expected = {};
    for (const auto& authority : allMasters.intent.directGatewayAuthorities)
      if (selected(authority)) expected.push_back(authority);
    const size_t count = intent.row == MothershipNametagQualificationRow::ewrOrdPathLoss ? 3 :
        (row11 && batch == 0 ? 1 : 6);
    if (expected.size() != count || proposed.size() != count) return false;
    auto identical = [](auto left, auto right) {
      String a = {}, b = {}; return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
    };
    Vector<MothershipNametagQualificationExecutionRecord::PathFaultWitness> existing = {};
    for (const auto& witness : recorded.pathFaults) if (witness.batch == batch) existing.push_back(witness);
    if (!existing.empty()) {
      if (existing.size() != proposed.size()) return false;
      for (size_t i = 0; i < existing.size(); ++i)
        if (!identical(existing[i].request, proposed[i].request)) return false;
      return true;
    }
    if (recorded.pathAborting || recorded.phase != MothershipNametagQualificationExecutionPhase::prepared ||
        (batch == 1 && (recorded.pathFaults.size() != 1 || !recorded.pathFaults[0].restored.response))) return false;
    if (intent.row == MothershipNametagQualificationRow::truthClaimPartition) {
      size_t armed = 0; for (const auto& r : recorded.claimReceipts)
        if (r.claimStage == ProdigyNametagQualificationClaimStage::arm) ++armed;
      if (recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::claimVersion || armed != 3) return false;
    }
    uint64_t expiry = 0;
    for (const auto& witness : proposed) {
      if (witness.batch != batch || witness.paused.response || witness.restored.response ||
          witness.request.request.protocolVersion != ProdigyCrossClusterPathFaultRequest::leaseVersion ||
          (expiry && expiry != witness.request.request.expiresAtMilliseconds)) return false;
      expiry = witness.request.request.expiresAtMilliseconds;
      size_t matches = 0;
      for (const auto& authority : expected) if (identical(authority, witness.request.request.authority)) ++matches;
      if (matches != 1) return false;
      recorded.pathFaults.push_back(witness);
    }
    const auto now = Time::now<TimeResolution::ms>();
    if (now <= 0 || expiry <= uint64_t(now) || expiry - uint64_t(now) > 60000) return false;
    recorded.protocolVersion = intent.row == MothershipNametagQualificationRow::truthClaimPartition ?
        MothershipNametagQualificationExecutionRecord::claimVersion : MothershipNametagQualificationExecutionRecord::pathVersion;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationPathObservation(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent, uint8_t batch,
      const ProdigyCrossClusterPathFaultControl& observation,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        (recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::pathVersion &&
         recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::claimVersion) ||
        !observation.response || !observation.accepted || !prodigyCrossClusterPathFaultControlValid(observation) ||
        (observation.action != ProdigyCrossClusterPathFaultGatewayAction::pause &&
         observation.action != ProdigyCrossClusterPathFaultGatewayAction::resume)) return false;
    for (auto& witness : recorded.pathFaults) {
      if (witness.batch != batch ||
          !prodigyCrossClusterPathFaultRequestEqual(witness.request.request, observation.request)) continue;
      auto& slot = observation.action == ProdigyCrossClusterPathFaultGatewayAction::pause ? witness.paused : witness.restored;
      if (slot.response) {
        auto a = slot, b = observation; String left = {}, right = {};
        return BitseryEngine::serialize(left, a) && BitseryEngine::serialize(right, b) && left == right;
      }
      slot = observation;
      String key = {}, encoded = {}; auto copy = recorded;
      return mothershipNametagQualificationExecutionRecordValid(recorded) &&
          nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
          db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
    }
    return false;
  }

  bool recordNametagQualificationPathReceipt(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent,
      const ProdigyNametagQualificationApplicationReceipt& receipt,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::pathVersion || recorded.pathAborting) return false;
    for (const auto& previous : recorded.pathWorkReceipts) {
      if (previous.localClusterUUID != receipt.localClusterUUID || previous.pathBatch != receipt.pathBatch ||
          previous.pathStage != receipt.pathStage) continue;
      auto a = previous, b = receipt; String left = {}, right = {};
      return BitseryEngine::serialize(left, a) && BitseryEngine::serialize(right, b) && left == right;
    }
    if (!mothershipNametagQualificationPathStageMayRecord(recorded, receipt.pathBatch, receipt.pathStage)) return false;
    bool haveFault = false;
    for (const auto& witness : recorded.pathFaults) if (witness.batch == receipt.pathBatch) {
      haveFault = true;
      if (!witness.paused.response ||
          (receipt.pathStage == ProdigyNametagQualificationPathStage::final ? !witness.restored.response : witness.restored.response)) return false;
    }
    if (!haveFault) return false;
    recorded.pathWorkReceipts.push_back(receipt);
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationPathSurvivors(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent, bool during,
      const MothershipNametagQualificationExecutionRecord::PathSurvivorStage& proposed,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false; MothershipNametagAllMastersRecord allMasters = {};
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::pathVersion || recorded.pathAborting ||
        intent.row != MothershipNametagQualificationRow::ewrOrdPathLoss || proposed.receipts.size() != 12 ||
        !loadNametagAllMasters(intent.allMastersOperationUUID, allMasters, failure) ||
        !mothershipNametagAllMastersRecordValid(allMasters) || allMasters.intent.sites.size() != 3 ||
        recorded.pathFaults.size() != 3 || proposed.observedAtMilliseconds < intent.startedAtMilliseconds ||
        proposed.observedAtMilliseconds >= int64_t(recorded.pathFaults[0].request.request.expiresAtMilliseconds)) return false;
    auto& slot = during ? recorded.pathSurvivorsDuring : recorded.pathSurvivorsBefore;
    if (slot.observedAtMilliseconds) {
      auto a = slot, b = proposed; String left = {}, right = {};
      return BitseryEngine::serialize(left, a) && BitseryEngine::serialize(right, b) && left == right;
    }
    if (during && (!recorded.pathSurvivorsBefore.observedAtMilliseconds ||
        proposed.observedAtMilliseconds < recorded.pathSurvivorsBefore.observedAtMilliseconds)) return false;
    for (const auto& fault : recorded.pathFaults)
      if (fault.restored.response || (during ? !fault.paused.response : fault.paused.response)) return false;
    const auto lan = allMasters.intent.sites[2].clusterUUID; size_t count = 0;
    for (const auto& authority : allMasters.intent.directGatewayAuthorities) {
      if (authority.localClusterUUID != lan && authority.peerClusterUUID != lan) continue;
      const auto scope = prodigyCrossClusterPathFaultScope(authority); size_t matches = 0;
      for (const auto& survivor : proposed.receipts)
        if (prodigyCrossClusterPathFaultScopeEqual(scope, survivor.scope) &&
            prodigyCrossClusterMasqueGatewayReady(authority, &survivor.masque) &&
            prodigyCrossClusterPrivateBGPReadinessMatchesAuthority(survivor.privateBGP, authority) &&
            prodigyCrossClusterPrivateBGPReady(survivor.privateBGP)) ++matches;
      if (matches != 1) return false;
      ++count;
    }
    if (count != 12) return false;
    slot = proposed;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool markNametagQualificationPathRestoring(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent, uint8_t batch,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        (recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::pathVersion &&
         recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::claimVersion) || recorded.pathAborting ||
        batch > (intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ? 1 : 0)) return false;
    const uint8_t flag = uint8_t(1) << batch;
    if (recorded.pathRestoringBatches & flag) return true;
    if (!mothershipNametagQualificationPathMayBeginRestore(recorded, batch)) return false;
    recorded.pathRestoringBatches |= flag;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool markNametagQualificationPathAbort(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        (recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::pathVersion &&
         recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::claimVersion) ||
        recorded.phase == MothershipNametagQualificationExecutionPhase::verified) return false;
    if (recorded.pathAborting) return true;
    recorded.pathAborting = true;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool markNametagQualificationWriterIsolationAbort(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent, bool complete,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::writerIsolationVersion ||
        recorded.phase == MothershipNametagQualificationExecutionPhase::verified) return false;
    auto& w = recorded.writerIsolation; w.aborting = true;
    if (complete) {
      if (w.arm.ready && !w.released.ready) return false;
      recorded.phase = MothershipNametagQualificationExecutionPhase::failed;
    }
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool markNametagQualificationReplayAbort(const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent, MothershipNametagQualificationExecutionRecord& recorded,
      String *failure = nullptr) {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::replayVersion ||
        recorded.phase == MothershipNametagQualificationExecutionPhase::verified) return false;
    if (recorded.replayAborting) return true;
    recorded.replayAborting = true; auto copy = recorded; String key = {}, encoded = {};
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationReplayReadback(
      const MothershipNametagQualificationAdapter& adapter, const MothershipNametagQualificationIntent& intent,
      const ProdigyNametagQualificationApplicationReceipt& receipt,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.protocolVersion != MothershipNametagQualificationExecutionRecord::replayVersion ||
        recorded.phase == MothershipNametagQualificationExecutionPhase::verified ||
        recorded.phase == MothershipNametagQualificationExecutionPhase::failed ||
        !prodigyNametagQualificationApplicationReceiptValid(receipt) ||
        receipt.protocolVersion != ProdigyNametagQualificationApplicationReceipt::replayStageVersion) return false;
    auto identical = [](auto left, auto right) {
      String a = {}, b = {}; return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
    };
    if (receipt.replayStage == ProdigyNametagQualificationReplayWorkStage::workload) {
      if (recorded.replayLocalWork.runUUID) return identical(recorded.replayLocalWork, receipt);
      recorded.replayLocalWork = receipt;
    } else if (receipt.replayStage == ProdigyNametagQualificationReplayWorkStage::final) {
      if (!recorded.replayLocalWork.runUUID) return false;
      for (const auto& prior : recorded.replayFinalReadbacks)
        if (prior.localClusterUUID == receipt.localClusterUUID) return identical(prior, receipt);
      if (recorded.replayFinalReadbacks.size() >= 3) return false;
      recorded.replayFinalReadbacks.push_back(receipt);
    } else return false;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationReplayWitness(
      const MothershipNametagQualificationAdapter& adapter, const MothershipNametagQualificationIntent& intent,
      size_t index, const ProdigyNametagQualificationReplay& value,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        intent.row != MothershipNametagQualificationRow::graphKvReplayReorder ||
        intent.direction != MothershipNametagQualificationDirection::injection || index >= 2 ||
        index > recorded.replayWitnesses.size() || recorded.phase == MothershipNametagQualificationExecutionPhase::verified ||
        recorded.phase == MothershipNametagQualificationExecutionPhase::failed ||
        (recorded.replayAborting && value.stage != ProdigyNametagQualificationReplayStage::release) ||
        !prodigyNametagQualificationReplayValid(value)) return false;
    auto identical = [](auto left, auto right) {
      String a = {}, b = {}; return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
    };
    if (index == recorded.replayWitnesses.size()) {
      if (value.response || value.targetSide || value.stage != ProdigyNametagQualificationReplayStage::arm ||
          value.store != (index == 0 ? ProdigyNametagQualificationReplayStore::kv : ProdigyNametagQualificationReplayStore::graph)) return false;
      recorded.replayWitnesses.emplace_back().sourceChallenge = value;
    } else {
      auto& w = recorded.replayWitnesses[index];
      if (!value.response) {
        if (value.stage != ProdigyNametagQualificationReplayStage::arm &&
            !(value.targetSide && value.stage == ProdigyNametagQualificationReplayStage::prearm)) return false;
        auto& slot = !value.targetSide ? w.sourceChallenge :
            value.stage == ProdigyNametagQualificationReplayStage::prearm ? w.targetPrearmChallenge : w.targetChallenge;
        if (slot.challengeUUID) return identical(slot, value);
        if (!value.targetSide || (value.stage == ProdigyNametagQualificationReplayStage::arm &&
            (!w.targetPrearm.ready || !w.sourceCapture.ready))) return false;
        slot = value;
      } else {
        if (!value.ready) return false;
        auto releasePrearm = w.targetPrearmChallenge; releasePrearm.stage = ProdigyNametagQualificationReplayStage::release;
        const bool matchesPrearmRelease = value.targetSide && value.stage == ProdigyNametagQualificationReplayStage::release &&
            prodigyNametagQualificationReplayResponseMatches(releasePrearm, value);
        auto& challenge = !value.targetSide ? w.sourceChallenge :
            (value.stage == ProdigyNametagQualificationReplayStage::prearm || matchesPrearmRelease) ?
            w.targetPrearmChallenge : w.targetChallenge;
        if (!challenge.challengeUUID) return false;
        auto request = challenge; request.stage = value.stage;
        if (!prodigyNametagQualificationReplayResponseMatches(request, value)) return false;
        auto *slot = value.stage == ProdigyNametagQualificationReplayStage::prearm ? &w.targetPrearm :
            value.stage == ProdigyNametagQualificationReplayStage::arm ?
            (value.targetSide ? &w.targetArm : &w.sourceArm) :
            value.stage == ProdigyNametagQualificationReplayStage::replay ?
            (value.targetSide ? &w.targetReplay : &w.sourceReplay) :
            value.stage == ProdigyNametagQualificationReplayStage::query ?
            (value.targetSide ? &w.targetQuery : (w.sourceReplay.ready ? &w.sourceQuery : &w.sourceCapture)) :
            (value.targetSide ? &w.targetRelease : &w.sourceRelease);
        if (slot->response) return identical(*slot, value);
        if (value.stage != ProdigyNametagQualificationReplayStage::prearm &&
            value.stage != ProdigyNametagQualificationReplayStage::arm &&
            value.stage != ProdigyNametagQualificationReplayStage::release &&
            !(value.targetSide ? w.targetArm.ready : (value.stage == ProdigyNametagQualificationReplayStage::query && !w.sourceReplay.ready ? w.sourceArm.ready : w.sourceCapture.ready))) return false;
        if (value.stage == ProdigyNametagQualificationReplayStage::query && value.targetSide && !w.targetReplay.ready) return false;
        if (value.stage == ProdigyNametagQualificationReplayStage::replay && !value.targetSide && !w.targetReplay.ready) return false;
        *slot = value;
        if (value.stage == ProdigyNametagQualificationReplayStage::query && recorded.replayWitnesses.size() == 2 &&
            std::all_of(recorded.replayWitnesses.begin(), recorded.replayWitnesses.end(), [](const auto& item) {
              return item.sourceQuery.ready && item.targetQuery.ready;
            }) && !recorded.replayQueriesCompletedAtMilliseconds)
          recorded.replayQueriesCompletedAtMilliseconds = Time::now<TimeResolution::ms>();
      }
    }
    recorded.protocolVersion = MothershipNametagQualificationExecutionRecord::replayVersion;
    String key = {}, encoded = {}; auto copy = recorded;
    return mothershipNametagQualificationExecutionRecordValid(recorded) &&
        nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool recordNametagQualificationCousinNativeWitness(
      const MothershipNametagQualificationAdapter& adapter, const MothershipNametagQualificationIntent& intent,
      size_t index, const ProdigyNametagQualificationCousinTransport& value,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.cousinRecoveryAborting || index >= intent.cousinRecoveries.size() ||
        recorded.protocolVersion < MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion) return false;
    if (!value.response) {
      if (recorded.phase != MothershipNametagQualificationExecutionPhase::prepared || index > recorded.cousinNativeWitnesses.size()) return false;
      if (index == recorded.cousinNativeWitnesses.size()) {
        MothershipNametagQualificationExecutionRecord::CousinNativeWitness witness = {}; witness.challenge = value;
        recorded.cousinNativeWitnesses.push_back(std::move(witness));
      } else {
        auto left = recorded.cousinNativeWitnesses[index].challenge, right = value; String a = {}, b = {};
        return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
      }
    } else {
      if (index >= recorded.cousinNativeWitnesses.size() || !value.ready) return false;
      auto& witness = recorded.cousinNativeWitnesses[index];
      auto *slot = value.stage == ProdigyNametagQualificationCousinStage::arm ? &witness.arm :
          value.stage == ProdigyNametagQualificationCousinStage::faultObserved ? &witness.fault : &witness.final;
      if ((value.stage == ProdigyNametagQualificationCousinStage::arm && recorded.phase != MothershipNametagQualificationExecutionPhase::prepared) ||
          (value.stage == ProdigyNametagQualificationCousinStage::faultObserved && recorded.phase != MothershipNametagQualificationExecutionPhase::faultApplied) ||
          (value.stage == ProdigyNametagQualificationCousinStage::final && recorded.phase != MothershipNametagQualificationExecutionPhase::faultRestored)) return false;
      if (slot->response) { auto left = *slot, right = value; String a = {}, b = {};
        return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b; }
      *slot = value;
    }
    recorded.protocolVersion = MothershipNametagQualificationExecutionRecord::cousinTransportVersion;
    if (!mothershipNametagQualificationExecutionRecordValid(recorded)) return false;
    String key = {}, encoded = {}; auto copy = recorded;
    return nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool markNametagQualificationCousinRecoveryAborting(
      const MothershipNametagQualificationAdapter& adapter, const MothershipNametagQualificationIntent& intent,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        recorded.protocolVersion < MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion ||
        mothershipNametagQualificationExecutionPhaseTerminal(recorded.phase, intent)) return false;
    if (recorded.cousinRecoveryAborting) return true;
    recorded.cousinRecoveryAborting = true;
    String key = {}, encoded = {}; auto copy = recorded;
    return nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool finishNametagQualificationCousinRecoveryAbort(
      const MothershipNametagQualificationAdapter& adapter, const MothershipNametagQualificationIntent& intent,
      MothershipNametagQualificationExecutionRecord& recorded, String *failure = nullptr)
  {
    CousinRouteLock routeLock; G6OperationLock operationLock;
    if (!lockCousinRoutes(routeLock, failure) || !lockG6Operations(operationLock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found ||
        !recorded.cousinRecoveryAborting || recorded.protocolVersion < MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion)
      return false;
    if (recorded.phase == MothershipNametagQualificationExecutionPhase::failed) return true;
    for (size_t i = 0; i < recorded.cousinRecoveryBindings.size(); ++i) {
      const auto& binding = recorded.cousinRecoveryBindings[i]; const auto& reference = intent.cousinRecoveries[i];
      CousinRouteRecord original = {}, successor = {};
      if (!loadCousinRoute(binding.route.routeUUID, original, failure)) return false;
      if (cousinRouteExactMatches(original, binding.route)) continue;
      CousinRouteApplyReceipt first = {}, second = {}, withdrawnSource = {}, withdrawnDestination = {};
      if (!loadCousinRouteApplyReceipt(original.routeUUID, CousinRouteHalf::source, withdrawnSource, failure) ||
          !loadCousinRouteApplyReceipt(original.routeUUID, CousinRouteHalf::destination, withdrawnDestination, failure) ||
          !cousinRouteApplyReceiptMatchesCurrentRoute(withdrawnSource, original) ||
          !cousinRouteApplyReceiptMatchesCurrentRoute(withdrawnDestination, original) ||
          !loadCousinRoute(reference.successorRouteUUID, successor, failure)) return false;
      auto expectedWithdrawal = binding.route;
      if (expectedWithdrawal.generation == UINT64_MAX) return false;
      expectedWithdrawal.operationUUID = reference.withdrawOperationUUID; expectedWithdrawal.generation++;
      expectedWithdrawal.state = CousinRouteState::withdrawn;
      expectedWithdrawal.withdrawalGeneration = expectedWithdrawal.generation;
      expectedWithdrawal.withdrawnAtMs = intent.startedAtMilliseconds;
      auto expected = binding.route; expected.routeUUID = reference.successorRouteUUID;
      expected.operationUUID = reference.successorRouteOperationUUID; expected.sourcePermissionUUID = successor.sourcePermissionUUID;
      expected.generation = 1; expected.state = CousinRouteState::active;
      expected.withdrawalGeneration = 0; expected.withdrawnAtMs = 0; expected.priorOperationUUIDs.clear();
      if (!cousinRouteExactMatches(original, expectedWithdrawal) ||
          !cousinRouteExactMatches(successor, expected) ||
          successor.operationUUID != reference.successorRouteOperationUUID ||
          successor.state != CousinRouteState::active ||
          (successor.sourcePermissionUUID != binding.sourcePermission.permissionUUID &&
           successor.sourcePermissionUUID != reference.successorPermissionUUID) ||
          !loadCousinRouteApplyReceipt(successor.routeUUID, CousinRouteHalf::source, first, failure) ||
          !loadCousinRouteApplyReceipt(successor.routeUUID, CousinRouteHalf::destination, second, failure) ||
          !cousinRouteApplyReceiptMatchesCurrentRoute(first, successor) ||
          !cousinRouteApplyReceiptMatchesCurrentRoute(second, successor)) {
        if (failure && failure->empty()) failure->assign("qualification abort awaits exact restored route receipts"_ctv); return false;
      }
    }
    recorded.phase = MothershipNametagQualificationExecutionPhase::failed;
    String key = {}, encoded = {}; auto copy = recorded;
    return nametagQualificationKey(adapter, intent.runUUID, key) && BitseryEngine::serialize(encoded, copy) &&
        db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  // Persist the exact pre-fault records before any cousin route mutation. A
  // retry may only reuse the same bytes, including both acknowledged halves.
  bool recordNametagQualificationCousinRecoveryBindings(
      const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent,
      const Vector<MothershipNametagQualificationExecutionRecord::CousinRecoveryBinding>& bindings,
      MothershipNametagQualificationExecutionRecord& recorded, bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagQualificationIntentValid(intent) ||
        intent.protocolVersion != MothershipNametagQualificationIntent::cousinRecoveryVersion ||
        bindings.size() != intent.cousinRecoveries.size()) {
      if (failure) failure->assign("cousin recovery bindings do not match the immutable intent"_ctv); return false;
    }
    for (uint32_t i = 0; i < bindings.size(); ++i)
      if (!mothershipNametagQualificationCousinRecoveryBindingValid(intent, i, bindings[i])) {
        if (failure) failure->assign("invalid exact cousin recovery binding"_ctv); return false;
      }
    CousinRouteLock routeLock; G6OperationLock operationLock;
    if (!lockCousinRoutes(routeLock, failure) || !lockG6Operations(operationLock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found) return false;
    if (!recorded.cousinRecoveryBindings.empty()) {
      String before = {}, after = {}; auto a = recorded; auto b = recorded;
      b.cousinRecoveryBindings = bindings;
      resumed = BitseryEngine::serialize(before, a) && BitseryEngine::serialize(after, b) && before == after;
      if (!resumed && failure) failure->assign("cousin recovery binding conflicts with its durable snapshot"_ctv);
      if (resumed && failure) failure->clear();
      return resumed;
    }
    if (recorded.phase != MothershipNametagQualificationExecutionPhase::prepared) {
      if (failure) failure->assign("cousin recovery binding must precede the fault"_ctv); return false;
    }
    MothershipNametagAllMastersRecord allMasters = {};
    if (!loadNametagAllMasters(intent.allMastersOperationUUID, allMasters, failure)) return false;
    for (const auto& binding : bindings) {
      if (std::any_of(allMasters.intent.seedRoutes.begin(), allMasters.intent.seedRoutes.end(),
          [&](const auto& seed) { return seed.routeUUID == binding.route.routeUUID; })) {
        if (failure) failure->assign("qualification may not replace a retained seed route"_ctv); return false;
      }
      CousinRouteRecord current = {}; CousinRouteApplyReceipt source = {}, destination = {};
      if (!loadCousinRoute(binding.route.routeUUID, current, failure) ||
          !cousinRouteAllowsNewAdmissionAt(current, Time::now<TimeResolution::ms>()) ||
          !cousinRouteExactMatches(current, binding.route) ||
          current.priorOperationUUIDs != binding.route.priorOperationUUIDs ||
          !loadCousinRouteApplyReceipt(current.routeUUID, CousinRouteHalf::source, source, failure) ||
          !loadCousinRouteApplyReceipt(current.routeUUID, CousinRouteHalf::destination, destination, failure) ||
          !cousinRouteApplyReceiptExactMatches(source, binding.sourceReceipt) ||
          !cousinRouteApplyReceiptExactMatches(destination, binding.destinationReceipt)) {
        if (failure && failure->empty()) failure->assign("cousin recovery route changed before durable binding"_ctv); return false;
      }
    }
    if (intent.row == MothershipNametagQualificationRow::permissionRevokeReinstall) {
      // A permission cannot be revoked while any of its routes remains live.
      // Do not admit a fault that would knowingly strand an unrelated route.
      Vector<String> routeValues = {};
      if (!db.listValues(cousinRoutesColumnFamily, routeValues, failure)) return false;
      for (const auto& binding : bindings) {
        for (const auto& other : bindings)
          if (other.route.routeUUID != binding.route.routeUUID &&
              other.sourcePermission.permissionUUID == binding.sourcePermission.permissionUUID) {
            if (failure) failure->assign("qualification routes must have independent source permissions"_ctv); return false;
          }
        for (const auto& encodedRoute : routeValues) {
          CousinRouteRecord current = {};
          if (!BitseryEngine::deserializeSafe(encodedRoute, current) || !cousinRouteStructurallyValid(current)) {
            if (failure) failure->assign("qualification found a corrupt cousin route"_ctv); return false;
          }
          if (current.routeUUID != binding.route.routeUUID && !cousinRouteTerminal(current) &&
              (current.sourcePermissionUUID == binding.sourcePermission.permissionUUID ||
               current.destinationPermissionUUID == binding.sourcePermission.permissionUUID)) {
            if (failure) failure->assign("qualification source permission has another nonterminal route"_ctv); return false;
          }
        }
      }
    }
    recorded.protocolVersion = MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion;
    recorded.cousinRecoveryBindings = bindings;
    if (!mothershipNametagQualificationExecutionRecordValid(recorded)) return false;
    String key = {}, encoded = {}; auto copy = recorded;
    if (!nametagQualificationKey(adapter, intent.runUUID, key) || !BitseryEngine::serialize(encoded, copy) ||
        !db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure)) return false;
    if (failure) failure->clear(); return true;
  }

  bool recordNametagQualificationSecondTruthWriterAdmission(
      const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent,
      const MothershipNametagQualificationExecutionRecord::SecondTruthWriterAdmissionReceipt& receipt,
      MothershipNametagQualificationExecutionRecord& recorded, bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagQualificationSecondTruthWriterAdmissionMatchesIntent(intent, receipt)) {
      if (failure) failure->assign("second Truth-writer admission receipt is invalid"_ctv);
      return false;
    }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, recorded, found, failure) || !found) {
      if (!found && failure && failure->empty()) failure->assign("qualification execution phase is absent"_ctv);
      return false;
    }
    const auto& existing = recorded.secondTruthWriterAdmission;
    const bool empty = existing.sourceClusterUUID == 0 && existing.candidateClusterUUID == 0 &&
        existing.retainedOwnerClusterUUID == 0 && existing.retainedPlacementGeneration == 0 &&
        existing.candidatePlanSHA256.empty() && !existing.fenced;
    if (!empty) {
      resumed = existing.sourceClusterUUID == receipt.sourceClusterUUID &&
          existing.candidateClusterUUID == receipt.candidateClusterUUID &&
          existing.retainedOwnerClusterUUID == receipt.retainedOwnerClusterUUID &&
          existing.retainedPlacementGeneration == receipt.retainedPlacementGeneration &&
          existing.candidatePlanSHA256 == receipt.candidatePlanSHA256 && existing.fenced == receipt.fenced;
      if (!resumed && failure) failure->assign("second Truth-writer admission receipt conflicts with durable receipt"_ctv);
      if (resumed && failure) failure->clear();
      return resumed;
    }
    recorded.secondTruthWriterAdmission = receipt;
    // v1 execution records predate this receipt tail.  Promote only after a
    // fully validated immutable row-sixteen receipt is ready to persist.
    recorded.protocolVersion = MothershipNametagQualificationExecutionRecord::version;
    String key = {}, encoded = {}; auto copy = recorded;
    if (!nametagQualificationKey(adapter, intent.runUUID, key) || !BitseryEngine::serialize(encoded, copy)) return false;
    return db.write(nametagQualificationExecutionsColumnFamily, key, encoded, failure);
  }

  bool loadNametagQualificationIntent(const MothershipNametagQualificationAdapter& adapter,
                                      uint128_t runUUID,
                                      MothershipNametagQualificationIntent& recorded,
                                      bool& found, String *failure = nullptr)
  {
    recorded = {}; found = false;
    if (!nametagQualificationAdapterFrozen(adapter) || runUUID == 0)
    { if (failure) failure->assign("qualification intent identity is invalid"_ctv); return false; }
    String key = {}, encoded = {}, readFailure = {};
    if (!nametagQualificationKey(adapter, runUUID, key))
    { if (failure) failure->assign("qualification intent run identity is invalid"_ctv); return false; }
    if (!db.read(nametagQualificationIntentsColumnFamily, key, encoded, &readFailure))
    {
      if (readFailure.equal("record not found"_ctv)) { if (failure) failure->clear(); return true; }
      if (failure) *failure = readFailure;
      return false;
    }
    if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagQualificationIntentValid(recorded) ||
        recorded.runUUID != runUUID || recorded.row != adapter.row || recorded.direction != adapter.direction ||
        !recorded.rowID.equal(String(adapter.rowID)) ||
        mothershipNametagQualificationAdapterForTuple(recorded.row, recorded.direction, recorded.rowID,
            recorded.deadlineSeconds, recorded.convergenceSeconds) != &adapter)
    { recorded = {}; if (failure) failure->assign("qualification intent is corrupt or mismatched"_ctv); return false; }
    MothershipNametagAllMastersRecord allMasters = {};
    if (!loadNametagAllMasters(recorded.allMastersOperationUUID, allMasters, failure) ||
        !nametagQualificationAllMastersMatches(recorded, allMasters))
    {
      recorded = {};
      if (failure && failure->empty()) failure->assign("qualification intent does not match durable three-site authority"_ctv);
      return false;
    }
    found = true;
    if (failure) failure->clear();
    return true;
  }

  // Rebuild the seed receipt from its durable execution and immutable successor
  // chain; the receipt's own digest only authenticates its bytes, not their origin.
  bool nametagQualificationSeedReceiptMatchesExecution(
      const MothershipNametagQualificationAdapter& adapter,
      const MothershipNametagQualificationIntent& intent,
      const MothershipNametagQualificationReceipt& receipt, String *failure = nullptr)
  {
    if (intent.protocolVersion != MothershipNametagQualificationIntent::seedVersion ||
        !prodigyNametagQualificationSeedReadbackRow(uint8_t(intent.row))) return true;
    MothershipNametagQualificationExecutionRecord execution; bool found = false;
    if (!loadNametagQualificationExecution(adapter, intent, execution, found, failure) || !found ||
        !mothershipNametagQualificationSeedExecutionComplete(execution) ||
        (execution.phase != MothershipNametagQualificationExecutionPhase::converging &&
         execution.phase != MothershipNametagQualificationExecutionPhase::verified)) {
      if (failure && failure->empty()) failure->assign("seed receipt lacks a complete durable execution"_ctv);
      return false;
    }
    String prefix; prefix.assign("nametag-qualification-v4:"_ctv); prefix.append(intent.rowID); prefix.append(":"_ctv);
    const auto& witness = receipt.canonicalConvergenceWitness;
    const size_t offset = prefix.size() + 64;
    if (witness.size() <= offset + 1 || std::memcmp(witness.data(), prefix.data(), prefix.size()) != 0 ||
        witness.data()[offset] != ':') return false;
    String topology; topology.append(witness.data() + offset + 1, witness.size() - offset - 1);
    auto requested = receipt; String expected;
    if (!BitseryEngine::serialize(expected, requested)) return false;
    // A receipt can be written before the normal converging -> verified journal
    // transition, so verify both valid encodings against the same durable proof.
    for (auto phase : {MothershipNametagQualificationExecutionPhase::converging,
                       MothershipNametagQualificationExecutionPhase::verified}) {
      if (phase == MothershipNametagQualificationExecutionPhase::verified && execution.phase != phase) continue;
      auto proof = execution; proof.phase = phase;
      MothershipNametagQualificationReceipt rebuilt; String actual;
      if (mothershipNametagQualificationBuildReceipt(intent, receipt.applicationReceipts, topology,
            receipt.observedAtMilliseconds, rebuilt, nullptr, &proof) &&
          BitseryEngine::serialize(actual, rebuilt) && actual == expected) return true;
    }
    if (failure) failure->assign("seed receipt does not commit to its durable execution"_ctv);
    return false;
  }

  bool loadNametagQualificationReceipt(const MothershipNametagQualificationAdapter& adapter,
                                        uint128_t runUUID,
                                        MothershipNametagQualificationReceipt& recorded,
                                        bool& found, String *failure = nullptr)
  {
    recorded = {}; found = false;
    if (!nametagQualificationAdapterFrozen(adapter) || runUUID == 0)
    { if (failure) failure->assign("qualification receipt identity is invalid"_ctv); return false; }
    String key = {}, encoded = {}, readFailure = {};
    if (!nametagQualificationKey(adapter, runUUID, key))
    { if (failure) failure->assign("qualification receipt run identity is invalid"_ctv); return false; }
    if (!db.read(nametagQualificationReceiptsColumnFamily, key, encoded, &readFailure))
    {
      if (readFailure.equal("record not found"_ctv)) { if (failure) failure->clear(); return true; }
      if (failure) *failure = readFailure;
      return false;
    }
    if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagQualificationReceiptValid(recorded) ||
        recorded.runUUID != runUUID || recorded.row != adapter.row || recorded.direction != adapter.direction ||
        !recorded.rowID.equal(String(adapter.rowID)) ||
        mothershipNametagQualificationAdapterForTuple(recorded.row, recorded.direction, recorded.rowID,
            uint32_t((recorded.deadlineAtMilliseconds - recorded.startedAtMilliseconds) / 1000),
            uint32_t((recorded.convergenceDeadlineAtMilliseconds - recorded.startedAtMilliseconds) / 1000)) != &adapter)
    { recorded = {}; if (failure) failure->assign("qualification receipt is corrupt or mismatched"_ctv); return false; }
    MothershipNametagQualificationIntent intent = {};
    String intentEncoded = {};
    if (!db.read(nametagQualificationIntentsColumnFamily, key, intentEncoded, failure) ||
        !BitseryEngine::deserializeSafe(intentEncoded, intent) ||
        !mothershipNametagQualificationIntentValid(intent)) {
      recorded = {};
      if (failure && failure->empty()) failure->assign("qualification receipt has no durable v4 intent"_ctv);
      return false;
    }
    MothershipNametagAllMastersRecord allMasters = {};
    if (!loadNametagAllMasters(intent.allMastersOperationUUID, allMasters, failure) ||
        !nametagQualificationAllMastersMatches(intent, allMasters) ||
        !nametagQualificationReceiptMatchesIntent(recorded, intent) ||
        !nametagQualificationSeedReceiptMatchesExecution(adapter, intent, recorded, failure)) {
      recorded = {};
      if (failure && failure->empty()) failure->assign("qualification receipt does not match durable three-site authority"_ctv);
      return false;
    }
    found = true;
    if (failure) failure->clear();
    return true;
  }

  bool recordNametagQualificationReceipt(const MothershipNametagQualificationAdapter& adapter,
                                         const MothershipNametagQualificationReceipt& requested,
                                         MothershipNametagQualificationReceipt& recorded,
                                         bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagQualificationReceiptValid(requested) ||
        !nametagQualificationAdapterFrozen(adapter) || requested.row != adapter.row ||
        requested.direction != adapter.direction || !requested.rowID.equals(String(adapter.rowID)) ||
        mothershipNametagQualificationAdapterForTuple(requested.row, requested.direction, requested.rowID,
            uint32_t((requested.deadlineAtMilliseconds - requested.startedAtMilliseconds) / 1000),
            uint32_t((requested.convergenceDeadlineAtMilliseconds - requested.startedAtMilliseconds) / 1000)) != &adapter)
    { if (failure) failure->assign("qualification receipt does not bind its exact manifest row"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String key = {}, intentEncoded = {}, encoded = {}, readFailure = {};
    if (!nametagQualificationKey(adapter, requested.runUUID, key))
    { if (failure) failure->assign("qualification receipt run identity is invalid"_ctv); return false; }
    MothershipNametagQualificationIntent intent = {};
    if (!db.read(nametagQualificationIntentsColumnFamily, key, intentEncoded, &readFailure) ||
        !BitseryEngine::deserializeSafe(intentEncoded, intent) || !mothershipNametagQualificationIntentValid(intent))
    { if (failure) failure->assign("qualification receipt has no exact durable intent"_ctv); return false; }
    MothershipNametagAllMastersRecord allMasters = {};
    if (!loadNametagAllMasters(intent.allMastersOperationUUID, allMasters, failure) ||
        !nametagQualificationAllMastersMatches(intent, allMasters) ||
        !nametagQualificationReceiptMatchesIntent(requested, intent) ||
        !nametagQualificationSeedReceiptMatchesExecution(adapter, intent, requested, failure))
    { if (failure && failure->empty()) failure->assign("qualification receipt does not match durable three-site authority"_ctv); return false; }
    if (db.read(nametagQualificationReceiptsColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagQualificationReceiptValid(recorded))
      { recorded = {}; if (failure) failure->assign("qualification receipt is corrupt or unsupported"_ctv); return false; }
      String existing = {}, proposed = {}; auto existingCopy = recorded; auto proposedCopy = requested;
      BitseryEngine::serialize(existing, existingCopy); BitseryEngine::serialize(proposed, proposedCopy);
      resumed = existing.equal(proposed);
      if (!resumed && failure) failure->assign("qualification receipt conflicts with immutable durable receipt"_ctv);
      return resumed;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded = requested; auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    return db.write(nametagQualificationReceiptsColumnFamily, key, encoded, failure);
  }

  bool loadNametagSourceBaseline(uint128_t operationUUID, MothershipNametagSourceBaselineRecord& recorded,
                                 bool& found, String *failure = nullptr)
  {
    recorded = {}; found = false; String key = {}, encoded = {}, readFailure = {};
    if (!nametagSourceBaselineKey(operationUUID, key)) { if (failure) failure->assign("source baseline operation identity is invalid"_ctv); return false; }
    if (!db.read(nametagSourceBaselineRecordsColumnFamily, key, encoded, &readFailure)) {
      if (readFailure.equal("record not found"_ctv)) { if (failure) failure->clear(); return true; }
      if (failure) *failure = readFailure; return false;
    }
    if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagSourceBaselineRecordValid(recorded) ||
        recorded.command.operationUUID != operationUUID) {
      recorded = {}; if (failure) failure->assign("source baseline record is corrupt or unsupported"_ctv); return false;
    }
    found = true; if (failure) failure->clear(); return true;
  }

  bool persistNametagSourceBaselineIntent(const MothershipNametagSourceBaselineIntent& proposed,
      MothershipNametagSourceBaselineIntent& recorded,
      bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagSourceBaselineIntentValid(proposed)) { if (failure) failure->assign("source baseline intent is invalid"_ctv); return false; }
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}, readFailure = {};
    if (!nametagSourceBaselineKey(proposed.command.operationUUID, key)) return false;
    if (db.read(nametagSourceBaselineIntentsColumnFamily, key, encoded, &readFailure)) {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagSourceBaselineIntentValid(recorded)) {
        recorded = {}; if (failure) failure->assign("source baseline intent is corrupt"_ctv); return false;
      }
      String oldBytes = {}, newBytes = {}; auto oldCopy = recorded; auto newCopy = proposed;
      resumed = BitseryEngine::serialize(oldBytes, oldCopy) && BitseryEngine::serialize(newBytes, newCopy) && oldBytes.equal(newBytes);
      if (!resumed && failure) failure->assign("source baseline intent conflicts with durable operation"_ctv);
      return resumed;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded = proposed; auto copy = recorded;
    return BitseryEngine::serialize(encoded, copy) && db.write(nametagSourceBaselineIntentsColumnFamily, key, encoded, failure);
  }

  bool loadNametagSourceBaselineIntent(uint128_t operationUUID, MothershipNametagSourceBaselineIntent& recorded,
      bool& found, String *failure = nullptr)
  {
    recorded = {}; found = false; String key = {}, encoded = {}, readFailure = {};
    if (!nametagSourceBaselineKey(operationUUID, key)) return false;
    if (!db.read(nametagSourceBaselineIntentsColumnFamily, key, encoded, &readFailure)) {
      if (readFailure.equal("record not found"_ctv)) { if (failure) failure->clear(); return true; }
      if (failure) *failure = readFailure; return false;
    }
    if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagSourceBaselineIntentValid(recorded) ||
        recorded.command.operationUUID != operationUUID) { recorded = {}; if (failure) failure->assign("source baseline intent is corrupt"_ctv); return false; }
    found = true; if (failure) failure->clear(); return true;
  }

  bool recordNametagSourceBaseline(const MothershipNametagSourceBaselineRecord& requested,
                                   MothershipNametagSourceBaselineRecord& recorded, bool& resumed,
                                   String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagSourceBaselineRecordValid(requested)) {
      if (failure) failure->assign("source baseline record does not bind an exact completed EWR command"_ctv); return false;
    }
    G6OperationLock lock; if (!lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}, readFailure = {};
    if (!nametagSourceBaselineKey(requested.command.operationUUID, key)) return false;
    if (db.read(nametagSourceBaselineRecordsColumnFamily, key, encoded, &readFailure)) {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagSourceBaselineRecordValid(recorded)) {
        recorded = {}; if (failure) failure->assign("source baseline durable record is corrupt"_ctv); return false;
      }
      String oldBytes = {}, newBytes = {}; auto oldCopy = recorded; auto newCopy = requested;
      resumed = BitseryEngine::serialize(oldBytes, oldCopy) && BitseryEngine::serialize(newBytes, newCopy) && oldBytes.equal(newBytes);
      if (!resumed && failure) failure->assign("source baseline operation conflicts with immutable completed receipt"_ctv);
      return resumed;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded = requested; auto copy = recorded;
    return BitseryEngine::serialize(encoded, copy) && db.write(nametagSourceBaselineRecordsColumnFamily, key, encoded, failure);
  }

  // Intent is persisted before dispatch.  This keeps a retry bound to the
  // original target and deadlines even when the process dies between request
  // transmission and receipt persistence.
  bool persistNametagQualificationIntent(const MothershipNametagQualificationAdapter& adapter,
                                         const MothershipNametagQualificationIntent& proposed,
                                         MothershipNametagQualificationIntent& recorded,
                                         bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipNametagQualificationIntentValid(proposed) || !nametagQualificationAdapterFrozen(adapter) || proposed.row != adapter.row ||
        proposed.direction != adapter.direction || !proposed.rowID.equal(String(adapter.rowID)) ||
        proposed.deadlineSeconds != adapter.deadlineSeconds || proposed.convergenceSeconds != adapter.convergenceSeconds ||
        mothershipNametagQualificationAdapterForTuple(proposed.row, proposed.direction, proposed.rowID,
            proposed.deadlineSeconds, proposed.convergenceSeconds) != &adapter)
    { if (failure) failure->assign("qualification intent does not bind its exact manifest row"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}, readFailure = {};
    if (!nametagQualificationKey(adapter, proposed.runUUID, key))
    { if (failure) failure->assign("qualification intent run identity is invalid"_ctv); return false; }
    MothershipNametagAllMastersRecord allMasters = {};
    if (!loadNametagAllMasters(proposed.allMastersOperationUUID, allMasters, failure) ||
        !nametagQualificationAllMastersMatches(proposed, allMasters))
    { if (failure && failure->empty()) failure->assign("qualification intent has no exact durable all-masters topology"_ctv); return false; }
    if (db.read(nametagQualificationIntentsColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) || !mothershipNametagQualificationIntentValid(recorded))
      { recorded = {}; if (failure) failure->assign("qualification intent is corrupt or unsupported"_ctv); return false; }
      String existing = {}, requested = {}; auto existingCopy = recorded; auto requestedCopy = proposed;
      BitseryEngine::serialize(existing, existingCopy); BitseryEngine::serialize(requested, requestedCopy);
      resumed = existing.equal(requested);
      if (!resumed && failure) failure->assign("qualification intent conflicts with durable target or deadline"_ctv);
      return resumed;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded = proposed; auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    return db.write(nametagQualificationIntentsColumnFamily, key, encoded, failure);
  }

  bool admitLocalVMMachineFault(const MothershipLocalVMMachineFaultRequest& requested,
                                const MothershipPhysicalFaultMachineObservation& admission,
                                MothershipLocalVMMachineFaultRecord& recorded,
                                bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipLocalVMMachineFaultRequestValid(requested, failure)) return false;
    if (!mothershipPhysicalFaultMachineObservationValid(admission) ||
        admission.clusterUUID != requested.clusterUUID || admission.machineUUID != requested.machineUUID ||
        admission.stateSHA256 != requested.expectedBootSHA256)
    { if (failure) failure->assign("local VM fault admission observation does not bind the exact request"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    MothershipLocalVMBoundaryDescriptor boundary = {};
    if (!loadLocalVMBoundary(requested.vmBoundaryUUID, boundary, failure) || boundary.retired ||
        boundary.clusterUUID != requested.clusterUUID || boundary.machineUUID != requested.machineUUID ||
        (requested.protocolVersion >= MothershipLocalVMMachineFaultRequest::unreadyUpgradeRecoveryVersion &&
         boundary.immutableStateSHA256 != requested.expectedBoundarySHA256))
    { if (failure && failure->empty()) failure->assign("local VM fault does not bind an active exact VM boundary"_ctv); return false; }
    String key = {}, encoded = {}, readFailure = {}; key.assignItoh(requested.operationUUID);
    if (db.read(localVMFaultsColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !mothershipLocalVMMachineFaultRecordValid(recorded) ||
          !mothershipLocalVMMachineFaultReplayAdmissible(recorded.request, requested) ||
          !mothershipPhysicalFaultMachineObservationEqual(recorded.admission, admission))
      { recorded = {}; if (failure) failure->assign("local VM fault operation conflicts with its immutable request"_ctv); return false; }
      resumed = true; if (failure) failure->clear(); return true;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded.request = requested; recorded.admission = admission;
    auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(localVMFaultsColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear(); return true;
  }

  bool loadLocalVMMachineFault(uint128_t operationUUID, MothershipLocalVMMachineFaultRecord& recorded,
                               String *failure = nullptr)
  {
    recorded = {};
    if (operationUUID == 0) { if (failure) failure->assign("local VM fault operation UUID is required"_ctv); return false; }
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    if (!db.read(localVMFaultsColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
        !mothershipLocalVMMachineFaultRecordValid(recorded) || recorded.request.operationUUID != operationUUID)
    { recorded = {}; if (failure) failure->assign("local VM fault record is corrupt or unsupported"_ctv); return false; }
    if (failure) failure->clear(); return true;
  }

  bool recordLocalVMMachineFaultReceipt(const MothershipLocalVMMachineFaultRequest& request,
                                        const MothershipLocalVMMachineFaultReceipt& receipt,
                                        MothershipLocalVMMachineFaultRecord& recorded,
                                        bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipLocalVMMachineFaultReceiptValid(request, receipt, failure)) return false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    String key = {}, encoded = {}; key.assignItoh(request.operationUUID);
    if (!db.read(localVMFaultsColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, recorded) ||
        !mothershipLocalVMMachineFaultRecordValid(recorded) ||
        !mothershipLocalVMMachineFaultRequestEqual(recorded.request, request) ||
        !mothershipPhysicalFaultMachineObservationEqual(recorded.admission, receipt.before))
    { if (failure && failure->empty()) failure->assign("local VM fault receipt has no exact durable request"_ctv); return false; }
    if (recorded.hasReceipt)
    {
      resumed = mothershipPhysicalFaultExactSerializedEqual(recorded.receipt, receipt);
      if (!resumed && failure) failure->assign("local VM fault receipt conflicts with the durable receipt"_ctv);
      return resumed;
    }
    recorded.hasReceipt = true; recorded.receipt = receipt; auto copy = recorded;
    BitseryEngine::serialize(encoded, copy);
    return db.write(localVMFaultsColumnFamily, key, encoded, failure);
  }

  bool loadLocalAuthorityRecoveryCohort(uint128_t operationUUID,
                                         MothershipLocalAuthorityRecoveryCohortRecord& recorded,
                                         String *failure = nullptr)
  {
    recorded = {};
    if (operationUUID == 0)
    { if (failure) failure->assign("local authority recovery operation UUID is required"_ctv); return false; }
    String key = {}, encoded = {}; key.assignItoh(operationUUID);
    if (!db.read(localAuthorityRecoveryCohortsColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
        !mothershipLocalAuthorityRecoveryCohortRecordValid(recorded) ||
        recorded.request.operationUUID != operationUUID)
    {
      recorded = {};
      if (failure) failure->assign("local authority recovery cohort is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool admitLocalAuthorityRecoveryCohort(const MothershipLocalAuthorityRecoveryCohortRequest& requested,
                                         MothershipLocalAuthorityRecoveryCohortRecord& recorded,
                                         bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (!mothershipLocalAuthorityRecoveryCohortRequestValid(requested, failure)) return false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    if (requested.protocolVersion >= MothershipLocalAuthorityRecoveryCohortRequest::interruptedUpgradeVersion &&
        !localRecoveryRuntimeAuthorityMatches(requested, failure)) return false;
    String key = {}, encoded = {}, readFailure = {}; key.assignItoh(requested.operationUUID);
    if (db.read(localAuthorityRecoveryCohortsColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, recorded) ||
          !mothershipLocalAuthorityRecoveryCohortRecordValid(recorded) ||
          !mothershipPhysicalFaultExactSerializedEqual(recorded.request, requested))
      {
        recorded = {};
        if (failure) failure->assign("local authority recovery operation UUID conflicts with immutable cohort"_ctv);
        return false;
      }
      resumed = true;
      if (failure) failure->clear();
      return true;
    }
    if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    recorded.protocolVersion = requested.protocolVersion;
    recorded.request = requested;
    recorded.phase = MothershipLocalAuthorityRecoveryPhase::admitted;
    for (const auto& executor : requested.executors)
    {
      MothershipLocalAuthorityRecoveryBoundaryProgress progress = {};
      progress.boundaryUUID = executor.boundaryUUID;
      recorded.boundaries.push_back(std::move(progress));
      if (requested.protocolVersion >= MothershipLocalAuthorityRecoveryCohortRequest::interruptedUpgradeVersion) {
        MothershipLocalRecoveryRuntimeProgress runtime;
        runtime.boundaryUUID=executor.boundaryUUID; recorded.runtimeProgress.push_back(std::move(runtime));
      }
    }
    auto copy = recorded; BitseryEngine::serialize(encoded, copy);
    if (!db.write(localAuthorityRecoveryCohortsColumnFamily, key, encoded, failure)) { recorded = {}; return false; }
    if (failure) failure->clear();
    return true;
  }

  bool localRecoveryRuntimeAuthorityMatches(const MothershipLocalAuthorityRecoveryCohortRequest& requested,
                                            String *failure=nullptr)
  {
    if (!mothershipLocalRecoveryRuntimeIntentValid(requested)) return false;
    const auto& runtime=requested.runtime;
    MothershipUpgradeAdmissionRecord admission;
    if (!loadUpgradeAdmission(requested.clusterUUID,runtime.upgradeOperationUUID,admission,failure)) return false;
    String encoded,admissionSHA;
    if (!BitseryEngine::serialize(encoded,admission) || !prodigyComputeSHA256Hex(encoded,admissionSHA,failure) ||
        !admission.eligible || admission.approvedPath!=1 || admission.clusterUUID!=requested.clusterUUID ||
        admission.operationID!=runtime.upgradeOperationUUID || admissionSHA!=runtime.admissionSHA256 ||
        admission.targetContractSHA256!=runtime.targetContractSHA256) {
      if (failure) failure->assign("local runtime recovery differs from its admitted upgrade"_ctv);
      return false;
    }
    if (requested.protocolVersion == MothershipLocalAuthorityRecoveryCohortRequest::interruptedUpgradeVersion) {
      MothershipLocalAuthorityRecoveryCohortRecord predecessor;
      String predecessorSHA;
      if (!loadLocalAuthorityRecoveryCohort(runtime.predecessorRecoveryUUID,predecessor,failure) ||
          !BitseryEngine::serialize(encoded,predecessor) || !prodigyComputeSHA256Hex(encoded,predecessorSHA,failure) ||
          admission.sourceBundleSHA256!=mothershipLocalInterruptedUpgradeSourceBundle ||
          admission.sourceProdigySHA256!=mothershipLocalInterruptedUpgradeSourceRuntime ||
          admission.targetBundleSHA256!=mothershipLocalInterruptedUpgradeTargetBundle ||
          predecessorSHA!=runtime.predecessorRecoverySHA256 ||
          predecessor.phase!=MothershipLocalAuthorityRecoveryPhase::recovered ||
          predecessor.request.clusterUUID!=requested.clusterUUID || predecessor.request.executors.size()!=3) {
        if (failure) failure->assign("local runtime recovery differs from its admitted upgrade or completed predecessor"_ctv);
        return false;
      }
      for (uint32_t i=0;i<3;++i) {
        const auto& before=predecessor.request.executors[i]; const auto& after=requested.executors[i];
        if (before.machineUUID!=after.machineUUID || before.boundaryUUID!=after.boundaryUUID ||
            before.immutableBoundarySHA256!=after.immutableBoundarySHA256) {
          if(failure) failure->assign("local runtime recovery substituted a registered predecessor boundary"_ctv);
          return false;
        }
      }
    } else {
      const auto& identity=requested.admittedRuntime;
      if (admission.sourceBundleSHA256!=identity.sourceBundleSHA256 ||
          admission.sourceContractSHA256!=identity.sourceContractSHA256 ||
          admission.sourceReleaseID!=identity.sourceReleaseID ||
          admission.sourceProdigySHA256!=identity.sourceProdigySHA256 ||
          admission.sourceMothershipSHA256!=identity.sourceMothershipSHA256 ||
          admission.targetBundleSHA256!=identity.targetBundleSHA256 ||
          admission.authorityGeneration!=identity.authorityGeneration ||
          admission.masterUUID!=identity.masterUUID || admission.masterBootNs!=identity.masterBootNs ||
          admission.semanticObservationSHA256!=identity.semanticObservationSHA256) {
        if (failure) failure->assign("local runtime recovery changed its immutable admitted runtime identity"_ctv);
        return false;
      }
    }
    Vector<String> values;
    if (!db.listValues(localAuthorityRecoveryCohortsColumnFamily,values,failure)) return false;
    for (const auto& bytes:values) {
      MothershipLocalAuthorityRecoveryCohortRecord other;
      if (!BitseryEngine::deserializeSafe(bytes,other) || !mothershipLocalAuthorityRecoveryCohortRecordValid(other)) return false;
      if (other.request.clusterUUID==requested.clusterUUID && other.request.operationUUID!=requested.operationUUID &&
          other.phase!=MothershipLocalAuthorityRecoveryPhase::recovered) {
        if(failure) failure->assign("local runtime recovery has an unresolved prior cohort"_ctv);
        return false;
      }
    }
    return true;
  }

  bool checkpointLocalRecoveryRuntime(uint128_t operationUUID,const MothershipLocalRecoveryRuntimeProgress& next,
      MothershipLocalAuthorityRecoveryCohortRecord& recorded,String *failure=nullptr)
  {
    G6OperationLock lock;
    if (!lockG6Operations(lock,failure) || !loadLocalAuthorityRecoveryCohort(operationUUID,recorded,failure) ||
        recorded.protocolVersion<MothershipLocalAuthorityRecoveryCohortRecord::interruptedUpgradeVersion) return false;
    for (uint32_t i=0;i<recorded.runtimeProgress.size();++i) {
      auto& prior=recorded.runtimeProgress[i]; if (prior.boundaryUUID!=next.boundaryUUID) continue;
      if (mothershipPhysicalFaultExactSerializedEqual(prior,next)) return true;
      if (recorded.phase==MothershipLocalAuthorityRecoveryPhase::recovered ||
          recorded.boundaries[i].phase<MothershipLocalAuthorityRecoveryPhase::armed ||
          (prior.installDispatched && !next.installDispatched) ||
          (!prior.stateSHA256.empty() && prior.stateSHA256!=next.stateSHA256) ||
          (!prior.secretsSHA256.empty() && prior.secretsSHA256!=next.secretsSHA256) ||
          (!prior.activationBootID.empty() && prior.activationBootID!=next.activationBootID) ||
          (!next.activationBootID.empty() && recorded.boundaries[i].phase<MothershipLocalAuthorityRecoveryPhase::released)) {
        if(failure)failure->assign("local runtime recovery checkpoint changed or skipped durable evidence"_ctv);
        return false;
      }
      prior=next;
      if(!mothershipLocalAuthorityRecoveryCohortRecordValid(recorded,failure))return false;
      String key,bytes;key.assignItoh(operationUUID);BitseryEngine::serialize(bytes,recorded);
      return db.write(localAuthorityRecoveryCohortsColumnFamily,key,bytes,failure);
    }
    if(failure)failure->assign("local runtime recovery checkpoint has no admitted boundary"_ctv);
    return false;
  }

  bool loadLocalRecoveryGateways(uint128_t clusterUUID,Vector<CrossClusterMasqueGatewayAuthority>& gateways,
                                String *failure=nullptr)
  {
    gateways.clear();Vector<String> values;
    if(!db.listValues(crossClusterMasqueGatewaysColumnFamily,values,failure))return false;
    for(const auto& bytes:values) {
      CrossClusterMasqueGatewayAuthority authority;
      if(!BitseryEngine::deserializeSafe(bytes,authority) || !prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority))return false;
      if(authority.localClusterUUID==clusterUUID && authority.state==CrossClusterMasqueGatewayState::active)
        gateways.push_back(std::move(authority));
    }
    std::sort(gateways.begin(),gateways.end(),[](const auto& a,const auto& b) {
      return a.pairUUID==b.pairUUID ? a.localMachineUUID<b.localMachineUUID : a.pairUUID<b.pairUUID;
    });
    return true;
  }

  // Each boundary advances independently.  The cohort phase is the minimum
  // durable boundary phase, which makes a crash between executor receipts
  // resumable without authorizing a skipped cohort transition.
  bool advanceLocalAuthorityRecoveryCohort(uint128_t operationUUID, uint128_t boundaryUUID,
                                           MothershipLocalAuthorityRecoveryPhase phase,
                                           const String& receiptSHA256,
                                           MothershipLocalAuthorityRecoveryCohortRecord& recorded,
                                           bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    if (operationUUID == 0 || boundaryUUID == 0 ||
        !mothershipLocalAuthorityRecoveryPhaseValid(phase) ||
        phase == MothershipLocalAuthorityRecoveryPhase::admitted ||
        !mothershipPhysicalFaultDigestValid(receiptSHA256))
    { if (failure) failure->assign("local authority recovery advance requires one receipt-bearing boundary phase"_ctv); return false; }
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure) || !loadLocalAuthorityRecoveryCohort(operationUUID, recorded, failure)) return false;
    uint32_t index = recorded.boundaries.size();
    for (uint32_t candidate = 0; candidate < recorded.boundaries.size(); ++candidate)
      if (recorded.boundaries[candidate].boundaryUUID == boundaryUUID) { index = candidate; break; }
    if (index == recorded.boundaries.size())
    { if (failure) failure->assign("local authority recovery boundary is not in this cohort"_ctv); return false; }
    auto& progress = recorded.boundaries[index];
    if (recorded.phase == MothershipLocalAuthorityRecoveryPhase::recovered)
    {
      resumed = progress.phase == phase && progress.receiptSHA256 == receiptSHA256;
      if (!resumed && failure) failure->assign("recovered local authority recovery cohort is immutable"_ctv);
      return resumed;
    }
    if (progress.phase == phase)
    {
      resumed = progress.receiptSHA256 == receiptSHA256;
      if (!resumed && failure) failure->assign("local authority recovery boundary receipt conflicts with durable progress"_ctv);
      return resumed;
    }
    if (uint8_t(phase) != uint8_t(progress.phase) + 1)
    { if (failure) failure->assign("local authority recovery boundary phase is stale or skips durable progress"_ctv); return false; }
    if (phase > MothershipLocalAuthorityRecoveryPhase::armed &&
        uint8_t(recorded.phase) + 1 != uint8_t(phase))
    {
      if (failure) failure->assign("local authority recovery cannot cross a cohort barrier before every boundary"_ctv);
      return false;
    }
    progress.phase = phase; progress.receiptSHA256 = receiptSHA256;
    MothershipLocalAuthorityRecoveryPhase common = MothershipLocalAuthorityRecoveryPhase::recovered;
    for (const auto& candidate : recorded.boundaries)
      if (uint8_t(candidate.phase) < uint8_t(common)) common = candidate.phase;
    recorded.phase = common;
    if (!mothershipLocalAuthorityRecoveryCohortRecordValid(recorded, failure)) return false;
    String key = {}, encoded = {}; key.assignItoh(operationUUID); auto copy = recorded;
    BitseryEngine::serialize(encoded, copy);
    if (!db.write(localAuthorityRecoveryCohortsColumnFamily, key, encoded, failure)) return false;
    if (failure) failure->clear();
    return true;
  }

  bool recordCousinRoute(const CousinRouteRecord& requested,
                         CousinRouteRecord& recorded,
                         bool& resumed,
                         String *failure = nullptr)
  {
    recorded = {};
    resumed = false;
    if (!cousinRouteStructurallyValid(requested) || !cousinRouteCurrentContract(requested))
    {
      if (failure) failure->assign("cousin route record is invalid or not current"_ctv);
      return false;
    }
    CousinRouteLock lock;
    if (!lockCousinRoutes(lock, failure)) return false;
    if (!requested.priorOperationUUIDs.empty())
    {
      if (failure) failure->assign("cousin route operation history is registry-owned"_ctv);
      return false;
    }

    String key = {};
    key.assignItoh(requested.routeUUID);
    String encoded = {}, readFailure = {};
    CousinRouteRecord prior = {};
    bool replacing = false;

    // A route UUID identifies its generation history.  The permission-bound
    // peer/range identity below identifies one live path, so reject a second
    // UUID which would make that path's owner ambiguous while still allowing
    // distinct peers or ranges for the same workload.
    Vector<String> existingRoutes = {};
    if (!db.listValues(cousinRoutesColumnFamily, existingRoutes, failure)) return false;
    for (const auto& existing : existingRoutes)
    {
      CousinRouteRecord candidate = {};
      if (!BitseryEngine::deserializeSafe(existing, candidate) || !cousinRouteStructurallyValid(candidate))
      {
        if (failure) failure->assign("cousin route record is corrupt or unsupported"_ctv);
        return false;
      }
      if (candidate.routeUUID != requested.routeUUID && !cousinRouteTerminal(candidate) &&
          !cousinRouteTerminal(requested) &&
          cousinRoutePeerRangeScopeMatches(candidate, requested))
      {
        if (failure) failure->assign("cousin route peer/range scope is already owned by another route UUID"_ctv);
        return false;
      }
    }
    if (db.read(cousinRoutesColumnFamily, key, encoded, &readFailure))
    {
      if (!BitseryEngine::deserializeSafe(encoded, prior) || !cousinRouteStructurallyValid(prior) ||
          prior.routeUUID != requested.routeUUID)
      {
        if (failure) failure->assign("cousin route record is corrupt or unsupported"_ctv);
        return false;
      }
      if (cousinRouteOperationUUIDWasUsed(prior, requested.operationUUID))
      {
        if (requested.operationUUID != prior.operationUUID)
        {
          if (failure) failure->assign("cousin route operation UUID was already consumed by a superseded generation"_ctv);
          return false;
        }
        if (!cousinRouteExactMatches(prior, requested))
        {
          if (failure) failure->assign("cousin route operation identity conflicts with immutable record"_ctv);
          return false;
        }
        recorded = prior;
        resumed = true;
        if (failure) failure->clear();
        return true;
      }
      if (requested.generation < prior.generation)
      {
        if (failure) failure->assign("cousin route generation is stale"_ctv);
        return false;
      }
      if (requested.generation == prior.generation)
      {
        if (failure) failure->assign("cousin route generation conflicts with existing record"_ctv);
        return false;
      }
      if (!cousinRouteTransitionAllowed(prior, requested))
      {
        if (failure) failure->assign("cousin route transition regresses scope or terminal tombstone"_ctv);
        return false;
      }
      // A new desired generation may not overtake an unacknowledged current
      // generation.  Keep both receipt reads under the route lock so a second
      // coordinator cannot observe a partial handoff and publish ahead of it.
      CousinRouteApplyReceipt sourceReceipt = {}, destinationReceipt = {};
      String receiptFailure = {};
      if (!loadCousinRouteApplyReceipt(prior.routeUUID, CousinRouteHalf::source, sourceReceipt, &receiptFailure) ||
          !cousinRouteApplyReceiptMatchesCurrentRoute(sourceReceipt, prior) ||
          !loadCousinRouteApplyReceipt(prior.routeUUID, CousinRouteHalf::destination, destinationReceipt, &receiptFailure) ||
          !cousinRouteApplyReceiptMatchesCurrentRoute(destinationReceipt, prior))
      {
        if (failure) failure->assign("cousin route transition awaits exact durable receipts for the current generation"_ctv);
        return false;
      }
      if (prior.priorOperationUUIDs.size() >= cousinRouteMaximumPriorOperationUUIDs)
      {
        if (failure) failure->assign("cousin route operation history reached its generation cap"_ctv);
        return false;
      }
      replacing = true;
    }
    else if (!readFailure.equal("record not found"_ctv))
    {
      if (failure) *failure = readFailure;
      return false;
    }
    else if (requested.generation != 1 || requested.state != CousinRouteState::active)
    {
      if (failure) failure->assign("initial cousin route must be active generation one"_ctv);
      return false;
    }

    CousinRouteRecord copy = requested;
    if (replacing)
    {
      copy.priorOperationUUIDs = prior.priorOperationUUIDs;
      if (!cousinRouteRememberPriorOperationUUID(copy, prior.operationUUID))
      {
        if (failure) failure->assign("cousin route operation history cannot accept a prior operation UUID"_ctv);
        return false;
      }
    }
    BitseryEngine::serialize(encoded, copy);
    if (!db.write(cousinRoutesColumnFamily, key, encoded, failure)) return false;
    recorded = std::move(copy);
    if (failure) failure->clear();
    return true;
  }

  bool loadCousinRoute(uint128_t routeUUID, CousinRouteRecord& route, String *failure = nullptr)
  {
    route = {};
    if (routeUUID == 0)
    {
      if (failure) failure->assign("cousin route UUID is required"_ctv);
      return false;
    }
    String key = {}, encoded = {};
    key.assignItoh(routeUUID);
    if (!db.read(cousinRoutesColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, route) || !cousinRouteStructurallyValid(route) || route.routeUUID != routeUUID)
    {
      route = {};
      if (failure) failure->assign("cousin route record is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool loadUsableCousinRoute(uint128_t routeUUID, int64_t nowMs, CousinRouteRecord& route, String *failure = nullptr)
  {
    if (!loadCousinRoute(routeUUID, route, failure)) return false;
    if (!cousinRouteUsableAt(route, nowMs))
    {
      route = {};
      if (failure) failure->assign("cousin route is expired, unavailable, or terminal"_ctv);
      return false;
    }
    return true;
  }

  bool recordCousinRouteApplyReceipt(const CousinRouteApplyReceipt& requested,
                                     CousinRouteApplyReceipt& recorded,
                                     bool& resumed,
                                     String *failure = nullptr)
  {
    recorded = {};
    resumed = false;
    if (!cousinRouteApplyReceiptStructurallyValid(requested))
    {
      if (failure) failure->assign("cousin route receipt is structurally invalid"_ctv);
      return false;
    }
    CousinRouteLock lock;
    if (!lockCousinRoutes(lock, failure)) return false;
    CousinRouteRecord route = {};
    if (!loadCousinRoute(requested.routeUUID, route, failure)) return false;
    if (!cousinRouteApplyReceiptMatchesCurrentRoute(requested, route))
    {
      if (failure) failure->assign("cousin route receipt does not bind the current route"_ctv);
      return false;
    }
    String key = {}, encoded = {}, readFailure = {};
    if (!cousinRouteReceiptKey(requested.routeUUID, requested.localHalf, key))
    {
      if (failure) failure->assign("cousin route receipt key is invalid"_ctv);
      return false;
    }
    if (db.read(cousinRouteReceiptsColumnFamily, key, encoded, &readFailure))
    {
      CousinRouteApplyReceipt prior = {};
      if (!BitseryEngine::deserializeSafe(encoded, prior) || !cousinRouteApplyReceiptStructurallyValid(prior) ||
          prior.routeUUID != requested.routeUUID || prior.localHalf != requested.localHalf)
      {
        if (failure) failure->assign("cousin route receipt is corrupt or unsupported"_ctv);
        return false;
      }
      if (requested.localRuntimeRevision < prior.localRuntimeRevision)
      {
        if (failure) failure->assign("cousin route receipt local runtime revision is stale"_ctv);
        return false;
      }
      if (requested.localRuntimeRevision == prior.localRuntimeRevision)
      {
        if (!cousinRouteApplyReceiptExactMatches(prior, requested))
        {
          if (failure) failure->assign("cousin route receipt local runtime revision conflicts"_ctv);
          return false;
        }
        recorded = prior;
        resumed = true;
        if (failure) failure->clear();
        return true;
      }
    }
    else if (!readFailure.equal("record not found"_ctv))
    {
      if (failure) *failure = readFailure;
      return false;
    }
    CousinRouteApplyReceipt copy = requested;
    BitseryEngine::serialize(encoded, copy);
    if (!db.write(cousinRouteReceiptsColumnFamily, key, encoded, failure)) return false;
    recorded = std::move(copy);
    if (failure) failure->clear();
    return true;
  }

  bool loadCousinRouteApplyReceipt(uint128_t routeUUID,
                                   CousinRouteHalf half,
                                   CousinRouteApplyReceipt& receipt,
                                   String *failure = nullptr)
  {
    receipt = {};
    String key = {}, encoded = {};
    if (!cousinRouteReceiptKey(routeUUID, half, key))
    {
      if (failure) failure->assign("cousin route receipt key is invalid"_ctv);
      return false;
    }
    if (!db.read(cousinRouteReceiptsColumnFamily, key, encoded, failure)) return false;
    if (!BitseryEngine::deserializeSafe(encoded, receipt) || !cousinRouteApplyReceiptStructurallyValid(receipt) ||
        receipt.routeUUID != routeUUID || receipt.localHalf != half)
    {
      receipt = {};
      if (failure) failure->assign("cousin route receipt is corrupt or unsupported"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  bool loadCurrentCousinRouteApplyReceipt(uint128_t routeUUID,
                                          CousinRouteHalf half,
                                          CousinRouteApplyReceipt& receipt,
                                          String *failure = nullptr)
  {
    CousinRouteRecord route = {};
    if (!loadCousinRoute(routeUUID, route, failure) || !loadCousinRouteApplyReceipt(routeUUID, half, receipt, failure))
      return false;
    if (!cousinRouteApplyReceiptMatchesCurrentRoute(receipt, route))
    {
      receipt = {};
      if (failure) failure->assign("cousin route receipt is stale for the current route"_ctv);
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  // This is persisted acknowledgement only. Live runtime health requires a
  // later authenticated observation from the applicable runtime owner.
  bool cousinRouteAcknowledgedAt(uint128_t routeUUID, int64_t nowMs, bool& acknowledged, String *failure = nullptr)
  {
    acknowledged = false;
    CousinRouteRecord route = {};
    if (!loadCousinRoute(routeUUID, route, failure)) return false;
    CousinRouteApplyReceipt source = {}, destination = {};
    String receiptFailure = {};
    if (!loadCousinRouteApplyReceipt(routeUUID, CousinRouteHalf::source, source, &receiptFailure))
    {
      if (receiptFailure.equal("record not found"_ctv))
      {
        if (failure) failure->clear();
        return true;
      }
      if (failure) *failure = receiptFailure;
      return false;
    }
    if (!loadCousinRouteApplyReceipt(routeUUID, CousinRouteHalf::destination, destination, &receiptFailure))
    {
      if (receiptFailure.equal("record not found"_ctv))
      {
        if (failure) failure->clear();
        return true;
      }
      if (failure) *failure = receiptFailure;
      return false;
    }
    acknowledged = cousinRouteReceiptsAcknowledgedAt(route, source, destination, nowMs);
    if (failure) failure->clear();
    return true;
  }

  bool clusterExists(const String& name, bool& exists, String *failure = nullptr)
  {
    exists = false;

    if (name.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster name required");
      }
      return false;
    }

    String serialized;
    String readFailure;
    if (db.read(clustersColumnFamily, name, serialized, &readFailure))
    {
      exists = true;
      if (failure)
      {
        failure->clear();
      }
      return true;
    }

    if (readFailure.equal("record not found"_ctv))
    {
      if (failure)
      {
        failure->clear();
      }
      return true;
    }

    if (failure)
    {
      *failure = readFailure;
    }
    return false;
  }

  bool getClusterNameByUUID(uint128_t clusterUUID, String& name, String *failure = nullptr)
  {
    name.clear();

    if (clusterUUID == 0)
    {
      if (failure)
      {
        failure->assign("clusterUUID required");
      }
      return false;
    }

    String clusterUUIDKey = {};
    renderClusterUUIDKey(clusterUUID, clusterUUIDKey);
    return db.read(clustersByUUIDColumnFamily, clusterUUIDKey, name, failure);
  }

  bool validateClusterForUpsert(const MothershipProdigyCluster& cluster, MothershipProdigyCluster& normalizedCluster, String *failure = nullptr)
  {
    if (cluster.internalTransportProfile != MothershipInternalTransportProfile::tls &&
        cluster.internalTransportProfile != MothershipInternalTransportProfile::aegisX25519V1)
    {
      if (failure) failure->assign("invalid internal transport profile"_ctv);
      return false;
    }
    MothershipProdigyCluster candidate = cluster;
    if (candidate.bgpAuthorizedOriginPrefixes.size() > 256 ||
        (candidate.bgpAuthorizedOriginPrefixes.empty() == false && !mothershipClusterBGPEnabled(candidate)))
    {
      if (failure) failure->assign("BGP origin authorization requires an enabled BGP configuration and at most 256 prefixes"_ctv);
      return false;
    }
    for (uint32_t index = 0; index < candidate.bgpAuthorizedOriginPrefixes.size(); ++index)
    {
      const IPPrefix& prefix = candidate.bgpAuthorizedOriginPrefixes[index];
      if (prefix.cidr > (prefix.network.is6 ? 128 : 32) || !prefix.equals(prefix.canonicalized()))
      {
        if (failure) failure->assign("BGP origin authorization prefixes must be canonical"_ctv);
        return false;
      }
      if (!mothershipProviderBGPOriginPrefixAllowed(prefix))
      {
        if (failure) failure->assign("BGP origin authorization prefixes must not be ULA"_ctv);
        return false;
      }
      for (uint32_t other = 0; other < index; ++other)
        if (prefix.equals(candidate.bgpAuthorizedOriginPrefixes[other]))
        {
          if (failure) failure->assign("BGP origin authorization prefixes must be unique"_ctv);
          return false;
        }
    }
    if (normalizeClusterForStorage(candidate, failure) == false)
    {
      return false;
    }

    Vector<ClusterMachine> candidateClaims = {};
    collectClaimedClusterMachines(candidate, candidateClaims);
    if (candidateClaims.empty())
    {
      normalizedCluster = std::move(candidate);
      if (failure)
      {
        failure->clear();
      }
      return true;
    }

    Vector<MothershipProdigyCluster> clusters = {};
    if (listClusters(clusters, failure) == false)
    {
      return false;
    }

    for (const MothershipProdigyCluster& existingCluster : clusters)
    {
      if (existingCluster.name.equals(candidate.name) || (candidate.clusterUUID != 0 && existingCluster.clusterUUID == candidate.clusterUUID))
      {
        continue;
      }

      Vector<ClusterMachine> existingClaims = {};
      collectClaimedClusterMachines(existingCluster, existingClaims);
      for (const ClusterMachine& candidateMachine : candidateClaims)
      {
        for (const ClusterMachine& existingMachine : existingClaims)
        {
          if (candidateMachine.sameIdentityAs(existingMachine) == false)
          {
            continue;
          }

          String label = {};
          candidateMachine.renderIdentityLabel(label);
          if (failure)
          {
            failure->snprintf<"machine '{}' already belongs to cluster '{}'"_ctv>(label, existingCluster.name);
          }
          return false;
        }
      }
    }

    normalizedCluster = std::move(candidate);
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  bool upsertCluster(const MothershipProdigyCluster& cluster, MothershipProdigyCluster *storedCluster = nullptr, String *failure = nullptr)
  {
    return upsertClusterWithBGPOriginPolicyMode(cluster, false, nullptr, storedCluster, failure);
  }

  // Ordinary cluster writers do not own BGP origin policy. Serialize every
  // full-record update with the policy lock and retain the durable policy from
  // the latest record so a stale unrelated update cannot silently erase it.
  bool upsertClusterWithBGPOriginPolicyMode(const MothershipProdigyCluster& cluster,
                                             bool replaceBGPOriginPolicy,
                                             const BGPOriginPolicyLock *heldPolicyLock,
                                             MothershipProdigyCluster *storedCluster = nullptr,
                                             String *failure = nullptr)
  {
    BGPOriginPolicyLock ownedPolicyLock = {};
    if (heldPolicyLock == nullptr)
    {
      if (lockBGPOriginPolicy(ownedPolicyLock, failure) == false)
      {
        return false;
      }
    }
    else if (heldPolicyLock->fd < 0)
    {
      if (failure) failure->assign("BGP origin policy lock required"_ctv);
      return false;
    }

    String serialized;
    MothershipProdigyCluster stored = cluster;

    MothershipProdigyCluster existingCluster = {};
    String existingFailure = {};
    bool hadExistingCluster = getCluster(cluster.name, existingCluster, &existingFailure);
    if (hadExistingCluster == false && existingFailure.equal("record not found"_ctv) == false)
    {
      if (failure)
      {
        *failure = existingFailure;
      }
      return false;
    }

    if (hadExistingCluster && stored.clusterUUID == 0)
    {
      stored.clusterUUID = existingCluster.clusterUUID;
    }

    if (hadExistingCluster && replaceBGPOriginPolicy == false)
    {
      stored.bgpAuthorizedOriginPrefixes = existingCluster.bgpAuthorizedOriginPrefixes;
    }

    if (hadExistingCluster && mothershipClusterUsesVirtualDatacenter(stored))
    {
      // Existing callers carry a synthesized control path.  Validate the rest
      // of the update normally, then regenerate this derived field below.
      stored.controls.clear();
    }

    // Preserve the established configuration-error ordering.  Fragment
    // allocation scans the registry and also enforces virtual-datacenter
    // tenancy; malformed cluster requests must still fail their own schema
    // validation before either of those cross-record checks.  Zero is the
    // new-cluster "allocate for me" value, so give only this validation copy
    // a nonzero placeholder and validate the final allocated record again
    // below.
    MothershipProdigyCluster preflight = stored;
    if (preflight.datacenterFragment == 0) preflight.datacenterFragment = 1;
    if (validateClusterForUpsert(preflight, preflight, failure) == false)
    {
      return false;
    }

    // An existing record owns its mesh prefix permanently. A new record gets
    // a globally unique prefix before validation/configuration can publish it.
    if (hadExistingCluster)
    {
      stored.datacenterFragment = existingCluster.datacenterFragment;
    }
    if (allocateDatacenterFragment(stored, hadExistingCluster, failure) == false)
    {
      return false;
    }

    if (validateClusterForUpsert(stored, stored, failure) == false)
    {
      return false;
    }

    if (mothershipClusterUsesVirtualDatacenter(stored))
    {
      // The final fragment changes the derived control socket domain; regenerate
      // controls after validation has accepted the finalized record.
      mothershipResolveTestClusterControlRecord(stored.controls, stored);
    }

    if (hadExistingCluster && existingCluster.clusterUUID != 0 && stored.clusterUUID != existingCluster.clusterUUID)
    {
      if (failure)
      {
        failure->assign("clusterUUID is immutable for an existing cluster");
      }
      return false;
    }

    if (hadExistingCluster && stored.dnsProvider != existingCluster.dnsProvider)
    {
      if (failure)
      {
        failure->assign("dnsProvider is immutable for an existing cluster");
      }
      return false;
    }

    if (hadExistingCluster &&
        (stored.acme == existingCluster.acme) == false)
    {
      if (failure)
      {
        failure->assign("acme config is immutable for an existing cluster");
      }
      return false;
    }

    String existingUUIDOwner = {};
    String uuidIndexFailure = {};
    bool uuidMapped = getClusterNameByUUID(stored.clusterUUID, existingUUIDOwner, &uuidIndexFailure);
    if (uuidMapped)
    {
      if (existingUUIDOwner.equals(stored.name) == false)
      {
        if (failure)
        {
          failure->assign("clusterUUID already exists");
        }
        return false;
      }
    }
    else if (uuidIndexFailure.equal("record not found"_ctv) == false)
    {
      if (failure)
      {
        *failure = uuidIndexFailure;
      }
      return false;
    }

    serializeClusterValue(stored, serialized);
    if (db.write(clustersColumnFamily, stored.name, serialized, failure) == false)
    {
      return false;
    }

    String clusterUUIDKey = {};
    renderClusterUUIDKey(stored.clusterUUID, clusterUUIDKey);
    if (db.write(clustersByUUIDColumnFamily, clusterUUIDKey, stored.name, failure) == false)
    {
      if (hadExistingCluster)
      {
        String rollbackSerialized = {};
        serializeClusterValue(existingCluster, rollbackSerialized);
        String rollbackFailure = {};
        (void)db.write(clustersColumnFamily, existingCluster.name, rollbackSerialized, &rollbackFailure);
      }
      else
      {
        String rollbackFailure = {};
        (void)db.remove(clustersColumnFamily, stored.name, &rollbackFailure);
      }

      return false;
    }

    if (storedCluster != nullptr)
    {
      *storedCluster = stored;
    }

    return true;
  }

  // The authorize/revoke commands hold this lock across their registry decision
  // and any dependent Brain RPC. They are the only callers permitted to replace
  // the durable policy vector.
  bool upsertClusterBGPOriginPolicy(const MothershipProdigyCluster& cluster,
                                    const BGPOriginPolicyLock& heldPolicyLock,
                                    MothershipProdigyCluster *storedCluster = nullptr,
                                    String *failure = nullptr)
  {
    return upsertClusterWithBGPOriginPolicyMode(cluster, true, &heldPolicyLock, storedCluster, failure);
  }

  bool createCluster(const MothershipProdigyCluster& cluster, MothershipProdigyCluster *storedCluster = nullptr, String *failure = nullptr)
  {
    bool exists = false;
    if (clusterExists(cluster.name, exists, failure) == false)
    {
      return false;
    }

    if (exists)
    {
      if (failure)
      {
        failure->assign("cluster already exists");
      }
      return false;
    }

    return upsertCluster(cluster, storedCluster, failure);
  }

  bool getCluster(const String& name, MothershipProdigyCluster& cluster, String *failure = nullptr)
  {
    if (name.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster name required");
      }
      return false;
    }

    String serialized;
    if (db.read(clustersColumnFamily, name, serialized, failure) == false)
    {
      return false;
    }

    if (deserializeClusterValue(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), cluster) == false)
    {
      if (failure)
      {
        failure->assign("cluster record decode failed");
      }
      return false;
    }

    return true;
  }

  bool getClusterByIdentity(const String& identity, MothershipProdigyCluster& cluster, String *failure = nullptr)
  {
    if (identity.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster identity required");
      }
      return false;
    }

    String getFailure = {};
    if (getCluster(identity, cluster, &getFailure))
    {
      if (failure)
      {
        failure->clear();
      }
      return true;
    }

    if (getFailure.equal("record not found"_ctv) == false)
    {
      if (failure)
      {
        *failure = getFailure;
      }
      return false;
    }

    String clusterName = {};
    if (db.read(clustersByUUIDColumnFamily, identity, clusterName, &getFailure))
    {
      return getCluster(clusterName, cluster, failure);
    }

    if (getFailure.equal("record not found"_ctv) == false)
    {
      if (failure)
      {
        *failure = getFailure;
      }
      return false;
    }

    if (failure)
    {
      failure->assign("record not found"_ctv);
    }
    return false;
  }

  bool removeClusterByIdentity(const String& identity, String *failure = nullptr)
  {
    MothershipProdigyCluster cluster = {};
    if (getClusterByIdentity(identity, cluster, failure) == false)
    {
      return false;
    }

    return removeCluster(cluster.name, failure);
  }

  bool removeCluster(const String& name, String *failure = nullptr)
  {
    if (name.size() == 0)
    {
      if (failure)
      {
        failure->assign("cluster name required");
      }
      return false;
    }

    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;

    MothershipProdigyCluster cluster = {};
    if (getCluster(name, cluster, failure) == false)
    {
      return false;
    }

    MothershipApplicationPlacement truth; String truthFailure;
    if (loadTruthPlacement(truth, &truthFailure)) {
      if (truth.ownerClusterUUID == cluster.clusterUUID) {
        String inventory, identity, indexedName; identity.assignItoh(cluster.clusterUUID);
        if (truth.version != 4 || truth.truthRetirementCompletedGeneration == 0 ||
            truth.truthRetirementOwnerClusterUUID != cluster.clusterUUID ||
            !db.read(clustersByUUIDColumnFamily, identity, indexedName, nullptr) || indexedName != cluster.name ||
            !mothershipTruthRetirementInventoryDigest(cluster, inventory) ||
            inventory != truth.truthRetirementInventorySHA256) {
          if (failure) failure->assign("cluster removal requires completed exact Truth retirement"_ctv);
          return false;
        }
      }
    } else if (truthFailure != "record not found"_ctv) {
      if (failure) *failure = truthFailure;
      return false;
    }

    for (uint16_t applicationID : {uint16_t(2), uint16_t(5)}) {
      MothershipApplicationPlacement placement; String readFailure;
      if (!loadApplicationPlacement(applicationID, placement, &readFailure)) {
        if (readFailure == "record not found"_ctv) continue;
        if (failure) *failure = readFailure;
        return false;
      }
      for (const auto& member : placement.graphReplicas) if (member.clusterUUID == cluster.clusterUUID) {
        if (failure) failure->assign("cluster removal requires completed graph replica retirement"_ctv);
        return false;
      }
    }

    String serializedCluster = {};
    serializeClusterValue(cluster, serializedCluster);

    if (db.remove(clustersColumnFamily, name, failure) == false)
    {
      return false;
    }

    if (cluster.clusterUUID != 0)
    {
      String clusterUUIDKey = {};
      renderClusterUUIDKey(cluster.clusterUUID, clusterUUIDKey);

      String removeIndexFailure = {};
      if (db.remove(clustersByUUIDColumnFamily, clusterUUIDKey, &removeIndexFailure) == false && removeIndexFailure.equal("record not found"_ctv) == false)
      {
        String rollbackFailure = {};
        (void)db.write(clustersColumnFamily, cluster.name, serializedCluster, &rollbackFailure);

        if (failure)
        {
          *failure = removeIndexFailure;
        }
        return false;
      }
    }

    return true;
  }

  bool listClusters(Vector<MothershipProdigyCluster>& clusters, String *failure = nullptr)
  {
    clusters.clear();

    Vector<String> serializedClusters;
    if (db.listValues(clustersColumnFamily, serializedClusters, failure) == false)
    {
      return false;
    }

    for (const String& serialized : serializedClusters)
    {
      MothershipProdigyCluster cluster = {};
      if (deserializeClusterValue(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), cluster) == false)
      {
        if (failure)
        {
          failure->assign("cluster record decode failed");
        }
        return false;
      }

      clusters.push_back(cluster);
    }

    return true;
  }

  static bool crossClusterMasqueGatewayMachineRegistered(
      const MothershipProdigyCluster& cluster, uint128_t machineUUID,
      const IPAddress *requiredPublicEndpoint = nullptr)
  {
    uint32_t matches = 0;
    bool endpointMatches = requiredPublicEndpoint == nullptr;
    for (const ClusterMachine& machine : cluster.topology.machines)
    {
      if (machine.uuid != machineUUID) continue;
      ++matches;
      if (requiredPublicEndpoint == nullptr) continue;
      for (const ClusterMachineAddress& candidate : machine.addresses.publicAddresses)
      {
        IPAddress parsed = {};
        if (ClusterMachine::parseIPAddressLiteral(candidate.address, parsed) &&
            parsed.equals(*requiredPublicEndpoint))
        {
          endpointMatches = true;
        }
      }
    }
    return matches == 1 && endpointMatches;
  }

  bool putCrossClusterMasqueGateway(CrossClusterMasqueGatewayAuthority requested,
                                    const ProdigyClusterPairEnrollment& enrollment,
                                    const MothershipProdigyCluster& localCluster,
                                    const MothershipProdigyCluster& peerCluster,
                                    CrossClusterMasqueGatewayAuthority& recorded,
                                    bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    const IPPrefix localPrefix = prodigyContainerDatacenterSitePrefix(localCluster.datacenterFragment);
    const IPPrefix peerPrefix = prodigyContainerDatacenterSitePrefix(peerCluster.datacenterFragment);
    const bool derivedFieldsAgree =
        (requested.pairUUID == 0 || requested.pairUUID == enrollment.pairUUID) &&
        (requested.pairOperationUUID == 0 || requested.pairOperationUUID == enrollment.operationUUID) &&
        (requested.localClusterUUID == 0 || requested.localClusterUUID == localCluster.clusterUUID) &&
        (requested.peerClusterUUID == 0 || requested.peerClusterUUID == peerCluster.clusterUUID) &&
        (requested.localDatacenterFragment == 0 ||
         requested.localDatacenterFragment == localCluster.datacenterFragment) &&
        (requested.peerDatacenterFragment == 0 ||
         requested.peerDatacenterFragment == peerCluster.datacenterFragment) &&
        (requested.localSitePrefix.cidr == 0 || requested.localSitePrefix.equals(localPrefix)) &&
        (requested.peerSitePrefix.cidr == 0 || requested.peerSitePrefix.equals(peerPrefix)) &&
        (requested.pairAuthorityGeneration == 0 ||
         requested.pairAuthorityGeneration == enrollment.localAuthorityGeneration) &&
        (requested.keyGeneration == 0 || requested.keyGeneration == enrollment.agreedKeyEpoch);
    const MothershipProdigyCluster& listenerCluster =
        requested.localRole == CrossClusterMasqueGatewayRole::listener ? localCluster : peerCluster;
    const uint128_t listenerMachineUUID =
        requested.localRole == CrossClusterMasqueGatewayRole::listener ?
            requested.localMachineUUID : requested.peerMachineUUID;
    if (!derivedFieldsAgree || requested.protocolVersion != CrossClusterMasqueGatewayAuthority::version ||
        requested.localMachineUUID == 0 || requested.peerMachineUUID == 0 ||
        requested.localMachineUUID == requested.peerMachineUUID ||
        !prodigyIsSHA256HexDigest(requested.artifactSHA256) || requested.artifactBytes == 0 ||
        (!prodigyIsSHA256HexDigest(requested.localIdentitySHA256) && requested.localIdentitySHA256 != "-"_ctv) ||
        (!prodigyIsSHA256HexDigest(requested.peerIdentitySHA256) && requested.peerIdentitySHA256 != "-"_ctv) ||
        (!prodigyIsSHA256HexDigest(requested.peerTrustSHA256) && requested.peerTrustSHA256 != "-"_ctv) ||
        requested.listenerPublicUDPEndpoint.isNull() || requested.listenerPublicUDPPort == 0 ||
        requested.generation == 0 ||
        (requested.localRole != CrossClusterMasqueGatewayRole::listener &&
         requested.localRole != CrossClusterMasqueGatewayRole::connector) ||
        requested.state != CrossClusterMasqueGatewayState::active ||
        !prodigyClusterPairEnrollmentDescriptorValid(enrollment) ||
        enrollment.state != ProdigyClusterPairEnrollmentState::active ||
        enrollment.localClusterUUID != localCluster.clusterUUID ||
        enrollment.peerClusterUUID != peerCluster.clusterUUID ||
        localCluster.clusterUUID == 0 || peerCluster.clusterUUID == 0 ||
        localCluster.clusterUUID == peerCluster.clusterUUID ||
        localCluster.datacenterFragment == 0 || peerCluster.datacenterFragment == 0 ||
        localCluster.datacenterFragment == peerCluster.datacenterFragment ||
        !crossClusterMasqueGatewayMachineRegistered(localCluster, requested.localMachineUUID) ||
        !crossClusterMasqueGatewayMachineRegistered(peerCluster, requested.peerMachineUUID) ||
        !crossClusterMasqueGatewayMachineRegistered(
            listenerCluster, listenerMachineUUID, &requested.listenerPublicUDPEndpoint))
    { if (failure) failure->assign("cross-cluster MASQUE gateway authority is invalid or stale"_ctv); return false; }

    // The registry, not an operator or a route payload, owns every address
    // component.  Pair enrollment selects the two clusters; their registered
    // records supply the globally leased datacenter byte and canonical /96.
    requested.pairUUID = enrollment.pairUUID;
    requested.pairOperationUUID = enrollment.operationUUID;
    requested.localClusterUUID = localCluster.clusterUUID;
    requested.peerClusterUUID = peerCluster.clusterUUID;
    requested.localDatacenterFragment = localCluster.datacenterFragment;
    requested.peerDatacenterFragment = peerCluster.datacenterFragment;
    requested.localSitePrefix = localPrefix;
    requested.peerSitePrefix = peerPrefix;
    requested.pairAuthorityGeneration = enrollment.localAuthorityGeneration;
    requested.keyGeneration = enrollment.agreedKeyEpoch;
    if (!prodigyDeriveCrossClusterMasquePrivateBGPTuple(requested))
    { if (failure) failure->assign("cross-cluster MASQUE private BGP tuple derivation failed"_ctv); return false; }
    // A retired peer can be replaced only after its withdrawn local authority
    // has lost the retired topology identity.  Check before touching the
    // in-memory Vault so a rejected replacement cannot mint even transient
    // credential material.
    String predecessorKey = {}, predecessorEncoded = {}, predecessorFailure = {};
    predecessorKey.snprintf<"{itoa}-{itoa}"_ctv>(requested.pairUUID, requested.localMachineUUID);
    if (db.read(crossClusterMasqueGatewaysColumnFamily, predecessorKey, predecessorEncoded, &predecessorFailure))
    {
      CrossClusterMasqueGatewayAuthority predecessor = {};
      if (!BitseryEngine::deserializeSafe(predecessorEncoded, predecessor) ||
          predecessor.protocolVersion != CrossClusterMasqueGatewayAuthority::version)
      {
        if (failure) failure->assign("cross-cluster MASQUE gateway record is corrupt"_ctv);
        return false;
      }
      const bool retiredPeerPresent = std::any_of(peerCluster.topology.machines.begin(),
          peerCluster.topology.machines.end(), [&](const ClusterMachine& machine) {
            return machine.uuid == predecessor.peerMachineUUID;
          });
      if (predecessor.state == CrossClusterMasqueGatewayState::withdrawn &&
          requested.state == CrossClusterMasqueGatewayState::active &&
          predecessor.peerMachineUUID != requested.peerMachineUUID && retiredPeerPresent)
      {
        if (failure) failure->assign("cross-cluster MASQUE gateway replacement peer remains commissioned"_ctv);
        return false;
      }
    }
    else if (!predecessorFailure.equal("record not found"_ctv))
    {
      if (failure) *failure = predecessorFailure;
      return false;
    }
    ProdigyPairPrivateBGPSecretScope secretScope = {};
    secretScope.pairUUID = requested.pairUUID; secretScope.operationUUID = requested.pairOperationUUID;
    secretScope.keyEpoch = requested.keyGeneration; secretScope.tunnelSlot = requested.tunnelSlot;
    secretScope.clusterUUID = requested.localClusterUUID; secretScope.machineUUID = requested.localMachineUUID;
    secretScope.authorityGeneration = requested.pairAuthorityGeneration; secretScope.gatewayGeneration = requested.generation;
    MothershipClusterPairEnrollmentIntent privateIntent = {};
    if (!loadClusterPairEnrollmentIntent(requested.pairOperationUUID, privateIntent, failure) ||
        privateIntent.pairUUID != requested.pairUUID || privateIntent.keyEpoch != requested.keyGeneration ||
        !privateBGPVault.configurePairRoot(privateIntent.root) || !privateBGPVault.importRecords(privateIntent.privateBGPSecrets))
    { if (failure && failure->empty()) failure->assign("cross-cluster MASQUE private BGP vault cannot hydrate enrolled pair root"_ctv); return false; }
    // v5 records are decoded above into an otherwise intact enrollment but its
    // BGP-only entries are intentionally discarded.  Any new gateway commit
    // upgrades the durable envelope before storing the TLS-bearing record.
    privateIntent.protocolVersion = MothershipClusterPairEnrollmentIntent::version;
    String derivedLocalIdentity = {}, derivedPeerIdentity = {}, derivedTrust = {};
    if (!privateBGPVault.mintAfterActiveEnrollment(secretScope, requested.peerMachineUUID, listenerMachineUUID,
        requested.listenerPublicUDPEndpoint, requested.privateSessionCredentialSHA256, derivedLocalIdentity,
        derivedPeerIdentity, derivedTrust, failure))
    { if (failure && failure->empty()) failure->assign("cross-cluster MASQUE private BGP vault mint failed"_ctv); return false; }
    if ((requested.localIdentitySHA256 != "-"_ctv && requested.localIdentitySHA256 != derivedLocalIdentity) ||
        (requested.peerIdentitySHA256 != "-"_ctv && requested.peerIdentitySHA256 != derivedPeerIdentity) ||
        (requested.peerTrustSHA256 != "-"_ctv && requested.peerTrustSHA256 != derivedTrust))
    { if (failure) failure->assign("cross-cluster MASQUE gateway TLS identity digest does not match Vault material"_ctv); return false; }
    requested.localIdentitySHA256 = std::move(derivedLocalIdentity);
    requested.peerIdentitySHA256 = std::move(derivedPeerIdentity);
    requested.peerTrustSHA256 = std::move(derivedTrust);
    if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(requested))
    { if (failure) failure->assign("cross-cluster MASQUE gateway authority derivation failed"_ctv); return false; }
    String key = {}; key.snprintf<"{itoa}-{itoa}"_ctv>(requested.pairUUID, requested.localMachineUUID);
    String encoded = {}, readFailure = {};
    if (db.read(crossClusterMasqueGatewaysColumnFamily, key, encoded, &readFailure)) {
      CrossClusterMasqueGatewayAuthority prior = {};
      if (!BitseryEngine::deserializeSafe(encoded, prior) || prior.protocolVersion != CrossClusterMasqueGatewayAuthority::version) { if (failure) failure->assign("cross-cluster MASQUE gateway record is corrupt"_ctv); return false; }
      if (requested.generation < prior.generation) { if (failure) failure->assign("cross-cluster MASQUE gateway generation is stale"_ctv); return false; }
      if (requested.generation == prior.generation) { String requestedEncoded = {}, priorEncoded = {}; CrossClusterMasqueGatewayAuthority requestedCopy = requested, priorCopy = prior; BitseryEngine::serialize(requestedEncoded, requestedCopy); BitseryEngine::serialize(priorEncoded, priorCopy); if (requestedEncoded != priorEncoded) { if (failure) failure->assign("cross-cluster MASQUE gateway generation conflicts"_ctv); return false; } recorded = prior; resumed = true; return true; }
      if (!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(prior, requested)) { if (failure) failure->assign("cross-cluster MASQUE gateway transition is invalid"_ctv); return false; }
    } else if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    // All rejection/conflict checks above precede exporting the authorization.
    // A rejected request must not leave a new delivery scope durable.  The
    // enrollment record is written before the authority so a recovered
    // authority can always resolve its digest to encrypted credential bytes.
    privateBGPVault.exportRecords(privateIntent.privateBGPSecrets);
    String privateIntentKey = {}, privateIntentEncoded = {};
    privateIntentKey.assignItoh(privateIntent.operationUUID); BitseryEngine::serialize(privateIntentEncoded, privateIntent);
    const bool privateIntentWritten = db.write(clusterPairEnrollmentsColumnFamily, privateIntentKey, privateIntentEncoded, failure);
    Vault::secureClearString(privateIntentEncoded);
    if (!privateIntentWritten) return false;
    CrossClusterMasqueGatewayAuthority copy = requested; BitseryEngine::serialize(encoded, copy);
    if (!db.write(crossClusterMasqueGatewaysColumnFamily, key, encoded, failure)) return false;
    recorded = requested; return true;
  }

  bool loadCrossClusterMasqueGateway(uint128_t pairUUID, uint128_t localMachineUUID, CrossClusterMasqueGatewayAuthority& record, String *failure = nullptr)
  { record = {}; String key = {}; key.snprintf<"{itoa}-{itoa}"_ctv>(pairUUID, localMachineUUID); String encoded = {}; if (!db.read(crossClusterMasqueGatewaysColumnFamily, key, encoded, failure)) return false; if (!BitseryEngine::deserializeSafe(encoded, record) || !prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(record) || record.pairUUID != pairUUID || record.localMachineUUID != localMachineUUID) { if (failure) failure->assign("cross-cluster MASQUE gateway record is corrupt"_ctv); return false; } return true; }

  bool withdrawCrossClusterMasqueGateway(uint128_t pairUUID, uint128_t localMachineUUID, uint64_t generation, CrossClusterMasqueGatewayAuthority& record, String *failure = nullptr)
  {
    if (!loadCrossClusterMasqueGateway(pairUUID, localMachineUUID, record, failure)) return false;
    if (generation == record.generation && record.state == CrossClusterMasqueGatewayState::withdrawn)
    {
      if (failure) failure->clear();
      return true;
    }
    if (generation <= record.generation || record.state != CrossClusterMasqueGatewayState::active)
    {
      if (failure) failure->assign("cross-cluster MASQUE gateway withdrawal generation is stale"_ctv);
      return false;
    }
    CrossClusterMasqueGatewayAuthority withdrawn = record;
    withdrawn.generation = generation;
    withdrawn.state = CrossClusterMasqueGatewayState::withdrawn;
    if (!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(record, withdrawn))
    {
      if (failure) failure->assign("cross-cluster MASQUE gateway withdrawal is invalid"_ctv);
      return false;
    }
    record = std::move(withdrawn);
    String key = {}; key.snprintf<"{itoa}-{itoa}"_ctv>(pairUUID, localMachineUUID);
    String encoded = {}; BitseryEngine::serialize(encoded, record);
    return db.write(crossClusterMasqueGatewaysColumnFamily, key, encoded, failure);
  }

  // The caller has already authenticated the mTLS control peer.  Re-load the
  // public descriptor here instead of trusting a relay-provided scope: this
  // binds delivery to the exact selected Neuron and every live generation.
  bool deliverCrossClusterPrivateBGPSecret(const ProdigyPairPrivateBGPSecretDeliveryRequest& request,
                                            const String& authenticatedControlIdentitySHA256,
                                            ProdigyPairPrivateBGPSecretDeliveryResponse& response,
                                            String *failure = nullptr)
  {
    response.accepted = false;
    if (request.controlIdentitySHA256 != authenticatedControlIdentitySHA256 ||
        !prodigyPairPrivateBGPSecretScopeValid(request.scope)) return false;
    MothershipClusterPairEnrollmentIntent privateIntent = {};
    if (!loadClusterPairEnrollmentIntent(request.scope.operationUUID, privateIntent, failure) ||
        privateIntent.pairUUID != request.scope.pairUUID || privateIntent.keyEpoch != request.scope.keyEpoch ||
        !privateBGPVault.configurePairRoot(privateIntent.root) || !privateBGPVault.importRecords(privateIntent.privateBGPSecrets)) return false;
    CrossClusterMasqueGatewayAuthority authority = {};
    if (!loadCrossClusterMasqueGateway(request.scope.pairUUID, request.scope.machineUUID, authority, failure) ||
        authority.state != CrossClusterMasqueGatewayState::active || authority.pairOperationUUID != request.scope.operationUUID ||
        authority.keyGeneration != request.scope.keyEpoch || authority.tunnelSlot != request.scope.tunnelSlot ||
        authority.localClusterUUID != request.scope.clusterUUID || authority.localMachineUUID != request.scope.machineUUID ||
        authority.pairAuthorityGeneration != request.scope.authorityGeneration || authority.generation != request.scope.gatewayGeneration)
      return false;
    return privateBGPVault.deliver(request, authenticatedControlIdentitySHA256,
        authority.privateSessionCredentialSHA256, response, failure);
  }

  // Withdrawal/rotation is terminal only after both enrolled halves have
  // confirmed their local BGP hub/cache was closed. Repeated ACKs and a
  // resumed delete are harmless, which makes crash recovery idempotent.
  bool acknowledgeCrossClusterPrivateBGPSecretRevocation(const ProdigyPairPrivateBGPSecretScope& scope,
                                                           bool& deleted)
  {
    deleted = false;
    MothershipClusterPairEnrollmentIntent privateIntent = {};
    if (!prodigyPairPrivateBGPSecretScopeValid(scope) || !loadClusterPairEnrollmentIntent(scope.operationUUID, privateIntent) ||
        privateIntent.pairUUID != scope.pairUUID || !privateBGPVault.configurePairRoot(privateIntent.root) ||
        !privateBGPVault.importRecords(privateIntent.privateBGPSecrets) || !privateBGPVault.acknowledgeRevocation(scope)) return false;
    deleted = privateBGPVault.deleteAfterBothRevocationAcknowledgements(scope);
    privateBGPVault.exportRecords(privateIntent.privateBGPSecrets);
    String key = {}, encoded = {}; key.assignItoh(privateIntent.operationUUID); BitseryEngine::serialize(encoded, privateIntent);
    const bool written = db.write(clusterPairEnrollmentsColumnFamily, key, encoded); Vault::secureClearString(encoded);
    if (!written) { deleted = false; return false; }
    return true;
  }

  // The encrypted enrollment record is the restart-safe withdrawal phase.
  // It is intentionally a Boolean acknowledgement, never a replayable secret
  // or a copied Neuron receipt.
  bool crossClusterPrivateBGPSecretRevocationAcknowledged(const ProdigyPairPrivateBGPSecretScope& scope)
  {
    MothershipClusterPairEnrollmentIntent privateIntent = {};
    return prodigyPairPrivateBGPSecretScopeValid(scope) && loadClusterPairEnrollmentIntent(scope.operationUUID, privateIntent) &&
        privateIntent.pairUUID == scope.pairUUID && privateBGPVault.configurePairRoot(privateIntent.root) &&
        privateBGPVault.importRecords(privateIntent.privateBGPSecrets) && privateBGPVault.revocationAcknowledged(scope);
  }

  // The scope key is intentionally independent of the qualification operation
  // UUID: that lets the registry reject a second active fault against the same
  // gateway even when a caller supplies a different operation.  The operation
  // remains part of the persisted request and is checked on every load.
  static void crossClusterPathFaultLifecycleScopeKey(
      const ProdigyPairPrivateBGPSecretScope& scope, String& key)
  {
    key.clear(); key.append("v1/"_ctv); String field = {};
    const auto append128 = [&](uint128_t value) { field.clear(); field.assignItoh(value); key.append(field); key.append('/'); };
    const auto append64 = [&](uint64_t value) { field.clear(); field.assignItoh(value); key.append(field); key.append('/'); };
    append128(scope.pairUUID); append128(scope.operationUUID); append64(scope.keyEpoch);
    field.clear(); field.assignItoa(scope.tunnelSlot); key.append(field); key.append('/');
    append128(scope.clusterUUID); append128(scope.machineUUID); append64(scope.authorityGeneration);
    field.clear(); field.assignItoh(scope.gatewayGeneration); key.append(field);
  }

  static void crossClusterPathFaultLifecycleHistoryKey(
      const ProdigyCrossClusterPathFaultRequest& request, String& key)
  { crossClusterPathFaultLifecycleScopeKey(request.scope, key); key.append("/"_ctv); String operation = {}; operation.assignItoh(request.operationUUID); key.append(operation); }

  static bool crossClusterPathFaultLifecycleEqual(
      const ProdigyCrossClusterPathFaultGatewayLifecycleRecord& left,
      const ProdigyCrossClusterPathFaultGatewayLifecycleRecord& right)
  {
    String a = {}, b = {}; auto ac = left, bc = right;
    return BitseryEngine::serialize(a, ac) && BitseryEngine::serialize(b, bc) && a == b;
  }

  static bool crossClusterPathFaultLifecycleImmutableEqual(
      const ProdigyCrossClusterPathFaultGatewayLifecycleRecord& left,
      const ProdigyCrossClusterPathFaultGatewayLifecycleRecord& right)
  {
    auto a = left, b = right;
    a.phase = b.phase = ProdigyCrossClusterPathFaultGatewayLifecyclePhase::prepared;
    a.replacementContainerUUID = b.replacementContainerUUID = 0;
    return crossClusterPathFaultLifecycleEqual(a, b);
  }

  bool loadCrossClusterPathFaultLifecycle(
      const ProdigyCrossClusterPathFaultRequest& request,
      ProdigyCrossClusterPathFaultGatewayLifecycleRecord& record, String *failure = nullptr)
  {
    record = {};
    if (!prodigyCrossClusterPathFaultRequestValid(request)) return false;
    String key = {}, encoded = {}; crossClusterPathFaultLifecycleHistoryKey(request, key);
    if (!db.read(crossClusterPathFaultLifecycleHistoryColumnFamily, key, encoded, failure) ||
        !BitseryEngine::deserializeSafe(encoded, record) ||
        !prodigyCrossClusterPathFaultGatewayLifecycleRecordValid(record) ||
        !prodigyCrossClusterPathFaultRequestEqual(record.request, request))
    { record = {}; if (failure && failure->empty()) failure->assign("cross-cluster path-fault lifecycle record is absent or corrupt"_ctv); return false; }
    return true;
  }

  bool putCrossClusterPathFaultLifecycle(
      const ProdigyCrossClusterPathFaultGatewayLifecycleRecord& requested,
      ProdigyCrossClusterPathFaultGatewayLifecycleRecord& recorded, bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    if (!prodigyCrossClusterPathFaultGatewayLifecycleRecordValid(requested) ||
        requested.phase != ProdigyCrossClusterPathFaultGatewayLifecyclePhase::prepared) return false;
    CrossClusterMasqueGatewayAuthority authority = {};
    if (!loadCrossClusterMasqueGateway(requested.request.authority.pairUUID,
            requested.request.authority.localMachineUUID, authority, failure)) return false;
    String expected = {}, observed = {}; auto expectedCopy = requested.request.authority, observedCopy = authority;
    if (!BitseryEngine::serialize(expected, expectedCopy) || !BitseryEngine::serialize(observed, observedCopy) || expected != observed)
    { if (failure) failure->assign("cross-cluster path-fault authority is stale"_ctv); return false; }
    String key = {}, encoded = {}, readFailure = {};
    crossClusterPathFaultLifecycleScopeKey(requested.request.scope, key);
    if (db.read(crossClusterPathFaultLifecyclesColumnFamily, key, encoded, &readFailure)) {
      ProdigyCrossClusterPathFaultGatewayLifecycleRecord prior = {};
      if (!BitseryEngine::deserializeSafe(encoded, prior) || !prodigyCrossClusterPathFaultGatewayLifecycleRecordValid(prior))
      { if (failure) failure->assign("cross-cluster path-fault lifecycle record is corrupt"_ctv); return false; }
      if (crossClusterPathFaultLifecycleEqual(prior, requested)) { recorded = prior; resumed = true; return true; }
      if (prior.phase != ProdigyCrossClusterPathFaultGatewayLifecyclePhase::restored)
      { if (failure) failure->assign("cross-cluster path-fault scope already has an active lifecycle"_ctv); return false; }
    } else if (!readFailure.equal("record not found"_ctv)) { if (failure) *failure = readFailure; return false; }
    auto copy = requested; BitseryEngine::serialize(encoded, copy);
    if (!db.write(crossClusterPathFaultLifecyclesColumnFamily, key, encoded, failure)) return false;
    String historyKey = {}; crossClusterPathFaultLifecycleHistoryKey(requested.request, historyKey);
    if (!db.write(crossClusterPathFaultLifecycleHistoryColumnFamily, historyKey, encoded, failure)) return false;
    recorded = requested; return true;
  }

  bool advanceCrossClusterPathFaultLifecycle(
      const ProdigyCrossClusterPathFaultGatewayLifecycleRecord& requested,
      ProdigyCrossClusterPathFaultGatewayLifecycleRecord& recorded, bool& resumed, String *failure = nullptr)
  {
    recorded = {}; resumed = false;
    G6OperationLock lock;
    if (!lockG6Operations(lock, failure)) return false;
    if (!prodigyCrossClusterPathFaultGatewayLifecycleRecordValid(requested) ||
        requested.phase == ProdigyCrossClusterPathFaultGatewayLifecyclePhase::prepared) return false;
    CrossClusterMasqueGatewayAuthority authority = {};
    if (!loadCrossClusterMasqueGateway(requested.request.authority.pairUUID,
            requested.request.authority.localMachineUUID, authority, failure)) return false;
    String current = {}, expected = {}; auto currentCopy = authority, expectedCopy = requested.request.authority;
    if (!BitseryEngine::serialize(current, currentCopy) || !BitseryEngine::serialize(expected, expectedCopy) || current != expected)
    { if (failure) failure->assign("cross-cluster path-fault authority changed during lifecycle"_ctv); return false; }
    ProdigyCrossClusterPathFaultGatewayLifecycleRecord prior = {};
    if (!loadCrossClusterPathFaultLifecycle(requested.request, prior, failure) ||
        !crossClusterPathFaultLifecycleImmutableEqual(prior, requested))
    { if (failure && failure->empty()) failure->assign("cross-cluster path-fault lifecycle immutable identity changed"_ctv); return false; }
    if (crossClusterPathFaultLifecycleEqual(prior, requested)) { recorded = prior; resumed = true; return true; }
    const bool transition =
        (prior.phase == ProdigyCrossClusterPathFaultGatewayLifecyclePhase::prepared &&
         requested.phase == ProdigyCrossClusterPathFaultGatewayLifecyclePhase::suspended) ||
        ((prior.phase == ProdigyCrossClusterPathFaultGatewayLifecyclePhase::suspended ||
          prior.phase == ProdigyCrossClusterPathFaultGatewayLifecyclePhase::restoreNeeded) &&
         requested.phase == ProdigyCrossClusterPathFaultGatewayLifecyclePhase::restored) ||
        (prior.phase == ProdigyCrossClusterPathFaultGatewayLifecyclePhase::suspended &&
         requested.phase == ProdigyCrossClusterPathFaultGatewayLifecyclePhase::restoreNeeded);
    if (!transition) { if (failure) failure->assign("cross-cluster path-fault lifecycle transition is invalid"_ctv); return false; }
    String key = {}, encoded = {}; crossClusterPathFaultLifecycleScopeKey(requested.request.scope, key);
    auto copy = requested; BitseryEngine::serialize(encoded, copy);
    if (!db.write(crossClusterPathFaultLifecyclesColumnFamily, key, encoded, failure)) return false;
    String historyKey = {}; crossClusterPathFaultLifecycleHistoryKey(requested.request, historyKey);
    if (!db.write(crossClusterPathFaultLifecycleHistoryColumnFamily, historyKey, encoded, failure)) return false;
    recorded = requested; return true;
  }
};
