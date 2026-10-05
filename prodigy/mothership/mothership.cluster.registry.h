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
};

template <typename S>
static void serialize(S&& serializer, MothershipTestPairTargetReadinessIntent& intent)
{
  serializer.value4b(intent.version);
  serializer.container(intent.commissionedBrainUUIDs, 3, [](S& serializer, uint128_t& uuid) { serializer.value16b(uuid); });
  serializer.value16b(intent.endpointMachineUUID);
  serializer.value4b(intent.commissionedBrainCount);
  serializer.value4b(intent.declaredStatelessWorkloadCount);
}

static inline bool mothershipBuildTestPairTargetReadinessIntent(const ClusterTopology& topology,
                                                                 const String& endpointIPv4,
                                                                 MothershipTestPairTargetReadinessIntent& intent)
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
  static constexpr uint32_t version = 1;
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
  return intent.protocolVersion == MothershipClusterPairEnrollmentIntent::version && intent.pairUUID != 0 &&
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
  return left.protocolVersion == right.protocolVersion && left.operationUUID == right.operationUUID &&
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
}

class MothershipClusterRegistry {
private:

  TidesDB db;

  constexpr static auto clustersColumnFamily = "clusters"_ctv;
  constexpr static auto clustersByUUIDColumnFamily = "clusters_by_uuid"_ctv;
  constexpr static auto upgradeAdmissionsColumnFamily = "upgrade_admissions"_ctv;
  constexpr static auto testPairBoundariesColumnFamily = "test_pair_boundaries"_ctv;
  constexpr static auto cousinRoutesColumnFamily = "cousin_routes"_ctv;
  constexpr static auto cousinRouteReceiptsColumnFamily = "cousin_route_receipts"_ctv;
  constexpr static auto clusterPairEnrollmentsColumnFamily = "cluster_pair_enrollments"_ctv;
  constexpr static auto clusterRecordV2Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=2\n\n"_ctv;
  constexpr static auto clusterRecordV3Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=3\n\n"_ctv;
  constexpr static auto clusterRecordV4Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=4\n\n"_ctv;
  constexpr static auto clusterRecordV5Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=5\n\n"_ctv;

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

  struct ClusterPairEnrollmentLock {
    int fd = -1;
    ~ClusterPairEnrollmentLock() { if (fd >= 0) ::close(fd); }
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
      return true;
    }

    if (recordHasHeader(serialized, clusterRecordV2Header))
    {
      String payload = {};
      payload.assign(serialized.substr(clusterRecordV2Header.size(), serialized.size() - clusterRecordV2Header.size(), Copy::yes));
      // V2 serialized the unchanged cluster object directly, so all adopted rack
      // identifiers retain the legacy zero/default semantics after decoding.
      return BitseryEngine::deserializeSafe(payload, cluster);
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
    if (cluster.internalTransportProfile == MothershipInternalTransportProfile::tls)
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

  bool allocateTestDatacenterFragment(MothershipProdigyCluster& cluster, bool preserveExisting, String *failure = nullptr)
  {
    if (mothershipClusterUsesVirtualDatacenter(cluster) == false)
    {
      return true;
    }

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
        if (failure) failure->assign("cluster record decode failed while allocating test datacenter fragment"_ctv);
        return false;
      }
      if (mothershipClusterUsesVirtualDatacenter(existing) == false)
      {
        continue;
      }
      if (existing.clusterUUID == cluster.clusterUUID) continue;
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
      used[existing.datacenterFragment] = true;
      if (cluster.test.enableFakeIpv4Boundary || existing.test.enableFakeIpv4Boundary)
      {
        if (failure) failure->assign("test fake IPv4 boundary is single-tenant until its public boundary domain is virtualized"_ctv);
        return false;
      }
    }

    if (preserveExisting)
    {
      if (cluster.datacenterFragment == 0 || used[cluster.datacenterFragment])
      {
        if (failure) failure->assign("existing test datacenter fragment is invalid or conflicts"_ctv);
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

    if (failure) failure->assign("test datacenter fragment capacity exhausted"_ctv);
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
      return cluster.test.machineCount;
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

  static bool validateClusterEnvironmentBGP(const ProdigyEnvironmentBGPConfig& bgp, String *failure)
  {
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

      if (cluster.nBrains > cluster.test.machineCount)
      {
        if (failure)
        {
          failure->assign("test.machineCount is below nBrains");
        }
        return false;
      }

      cluster.remoteProdigyPath.clear();

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

      cluster.bootstrapSshUser.clear();
      cluster.bootstrapSshKeyPackage.clear();
      cluster.bootstrapSshHostKeyPackage.clear();
      cluster.bootstrapSshPrivateKeyPath.clear();
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

    if (validateClusterEnvironmentBGP(cluster.bgp, failure) == false)
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
        }())
  {
  }

  const String& path(void)
  {
    return db.path();
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
      // A v4 reset arm is an immutable transition over the v3 identity.
      // Normal callers separately reject an armed record.
      if (lhs.version == 4) { lhs.version = 3; lhs.guestResetFence = {}; lhs.guestResetCompletedBootID.clear(); }
      if (rhs.version == 4) { rhs.version = 3; rhs.guestResetFence = {}; rhs.guestResetCompletedBootID.clear(); }
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
    return intent.version == 1 && intent.commissionedBrainCount == 3 &&
           intent.declaredStatelessWorkloadCount == 1 && intent.commissionedBrainUUIDs.size() == 3 &&
           intent.endpointMachineUUID != 0 && intent.commissionedBrainUUIDs[0] != 0 &&
           intent.commissionedBrainUUIDs[0] < intent.commissionedBrainUUIDs[1] &&
           intent.commissionedBrainUUIDs[1] < intent.commissionedBrainUUIDs[2];
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

  // This is a pure P6 fixture predicate. The caller must obtain both reports
  // freshly immediately before handoff or retirement; neither observation is
  // persisted as an admission or health receipt.
  static bool testPairWholeDestinationReady(const MothershipTestPairBoundaryRecord& record,
                                            const ClusterStatusReport& clusterReport,
                                            const DeploymentIdentityReport& deploymentReport,
                                            String *failure = nullptr)
  {
    auto reject = [&](auto message) -> bool { if (failure) failure->assign(message); return false; };
    if (record.version < 3 || !testPairBoundaryRecordValid(record) || record.targetAdmissionReceipt.empty())
      return reject("paired destination readiness requires a recorded v3 admission"_ctv);
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
    if (masters != 1 || clusterReport.nApplications != 1 || clusterReport.applicationReports.size() != 1)
      return reject("paired destination fixture does not have one current master and one workload"_ctv);
    const ApplicationStatusReport& application = clusterReport.applicationReports[0];
    const uint64_t versionID = record.targetDeploymentID & ((uint64_t(1) << 48) - 1);
    if (application.applicationID != ApplicationConfig::extractApplicationID(record.targetDeploymentID) ||
        application.deploymentReports.size() != 1) return reject("paired destination workload identity differs from admission"_ctv);
    const DeploymentStatusReport& deployment = application.deploymentReports[0];
    if (deployment.versionID != versionID || deployment.state != DeploymentState::running || deployment.isStateful ||
        deployment.nTarget != 1 || deployment.nDeployed != 1 || deployment.nHealthy != 1)
      return reject("paired destination workload is not the declared healthy stateless fixture"_ctv);
    StatelessDeploymentAdmissionReceipt receipt = {};
    if (!BitseryEngine::deserializeSafe(record.targetAdmissionReceipt, receipt) ||
        !testPairTargetAdmissionMatches(record, receipt) || deploymentReport.version != 1 ||
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
    if (failure) failure->clear();
    return true;
  }

  static bool testPairBoundaryRecordValid(const MothershipTestPairBoundaryRecord& record)
  {
    if ((record.version != 1 && record.version != 2 && record.version != 3 && record.version != 4) || record.selectorGeneration > 1 ||
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
             record.sourceDrainObservation.empty() && record.guestResetFence.operationID.empty() &&
             record.guestResetFence.descriptorSHA256.empty() && record.guestResetFence.bootID.empty() &&
             record.guestResetFence.guestID.empty() && record.guestResetCompletedBootID.empty();
    DeploymentPlan request = {};
    String requestSHA = {};
    if (record.targetRequestPlan.empty() || record.targetRequestPlan.size() > 1024 * 1024 ||
        !BitseryEngine::deserializeSafe(record.targetRequestPlan, request) ||
        !prodigyStatelessDeploymentAdmissionPlanEligible(request) || request.config.deploymentID() != record.targetDeploymentID ||
        !prodigyComputeSHA256Hex(record.targetRequestPlan, requestSHA) || requestSHA != record.targetRequestPlanSHA256 ||
        record.targetBlobBytes == 0 ||
        (record.version == 2 && (!record.targetReadinessIntent.commissionedBrainUUIDs.empty() || record.targetReadinessIntent.endpointMachineUUID != 0 ||
                                 record.targetReadinessIntent.commissionedBrainCount != 0 ||
                                 record.targetReadinessIntent.declaredStatelessWorkloadCount != 0 || !record.sourceDrainObservation.empty() ||
                                 !record.guestResetFence.operationID.empty() || !record.guestResetFence.descriptorSHA256.empty() ||
                                 !record.guestResetFence.bootID.empty() || !record.guestResetFence.guestID.empty() ||
                                 !record.guestResetCompletedBootID.empty())) ||
        (record.version == 3 && (!record.guestResetFence.operationID.empty() || !record.guestResetFence.descriptorSHA256.empty() ||
                                 !record.guestResetFence.bootID.empty() || !record.guestResetFence.guestID.empty() ||
                                 !record.guestResetCompletedBootID.empty())) ||
        (record.version >= 3 && !testPairTargetReadinessIntentValid(record.targetReadinessIntent))) return false;
    if (record.version == 4 &&
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
    const bool expectedIsBase = expected.version == 3 && expected.guestResetFence.operationID.empty() && expected.guestResetCompletedBootID.empty();
    const bool expectedIsArmed = expected.version == 4 && expected.guestResetFence.operationID == fence.operationID &&
                                 expected.guestResetFence.descriptorSHA256 == fence.descriptorSHA256 &&
                                 expected.guestResetFence.bootID == fence.bootID && expected.guestResetFence.guestID == fence.guestID &&
                                 expected.guestResetCompletedBootID.empty();
    if (recorded.closed || (recorded.version != 3 && recorded.version != 4) ||
        !mothershipVirtualDatacenterPairGuestResetFenceValid(fence, recorded.boundary) ||
        !testPairBoundaryIdentityMatches(recorded, expected) ||
        recorded.selectorGeneration != expected.selectorGeneration ||
        recorded.targetPlanSHA256 != expected.targetPlanSHA256 || recorded.targetAdmissionReceipt != expected.targetAdmissionReceipt ||
        recorded.sourceDrainObservation != expected.sourceDrainObservation || (!expectedIsBase && !expectedIsArmed))
    {
      if (failure) failure->assign("guest reset fence conflicts with the paired boundary"_ctv);
      return false;
    }
    if (recorded.version == 4)
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
    recorded.version = 4;
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
    if (recorded.closed || recorded.version != 4 || recorded.guestResetFence.operationID.empty() ||
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
    if (failure) failure->clear();
    return true;
  }

  bool admitTestPairBoundary(const MothershipTestPairBoundaryRecord& requested,
                            MothershipTestPairBoundaryRecord& recorded, String *failure = nullptr)
  {
    recorded = {};
    if (!testPairBoundaryRecordValid(requested) || requested.selectorGeneration != 0 || requested.closed ||
        (requested.version >= 2 && !requested.targetAdmissionReceipt.empty()) || requested.version == 4)
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
        (recorded.version == 4 && (nextSelectorGeneration != recorded.selectorGeneration || !closed || recorded.guestResetCompletedBootID.empty())) ||
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

  static bool cousinRouteTransitionAllowed(const CousinRouteRecord& prior, const CousinRouteRecord& next)
  {
    if (prior.routeUUID != next.routeUUID || next.generation <= prior.generation ||
        cousinRouteScopeMatches(prior, next) == false || cousinRouteTerminal(prior) ||
        cousinRouteKeyEpochTransitionValid(prior, next) == false)
    {
      return false;
    }
    if (cousinRouteTerminal(next)) return true;
    if (prior.state == CousinRouteState::draining && next.state == CousinRouteState::active) return false;
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

  bool recordCousinRoute(const CousinRouteRecord& requested,
                         CousinRouteRecord& recorded,
                         bool& resumed,
                         String *failure = nullptr)
  {
    recorded = {};
    resumed = false;
    if (!cousinRouteStructurallyValid(requested))
    {
      if (failure) failure->assign("cousin route record is invalid"_ctv);
      return false;
    }
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

    if (hadExistingCluster && mothershipClusterUsesVirtualDatacenter(stored))
    {
      // Existing callers carry a synthesized control path.  Validate the rest
      // of the update normally, then regenerate this derived field below.
      stored.controls.clear();
    }

    if (validateClusterForUpsert(stored, stored, failure) == false)
    {
      return false;
    }

    if (mothershipClusterUsesVirtualDatacenter(stored))
    {
      if (hadExistingCluster)
      {
        stored.datacenterFragment = existingCluster.datacenterFragment;
      }
      if (allocateTestDatacenterFragment(stored, hadExistingCluster, failure) == false)
      {
        return false;
      }
      // Fragment allocation follows ordinary configuration validation.  It
      // changes the derived control socket domain, so regenerate controls only
      // after the final fragment is known.
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

    MothershipProdigyCluster cluster = {};
    if (getCluster(name, cluster, failure) == false)
    {
      return false;
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
};
