#pragma once

#include <array>
#include <cstdint>

#include <basics/includes.h>
#include <services/bitsery.h>
#include <services/prodigy.h>

#include <prodigy/sha256.digest.h>

// Shared logical-slot selection used by routes and deployment permissions.  It
// deliberately describes logical service slots, never a local group number.
class CousinRouteSlotBitmap {
public:
  static constexpr uint32_t slotCount = nStatefulServiceGroupSlots;
  static constexpr uint32_t wordCount = slotCount / 64;
  static_assert(slotCount % 64 == 0);

  std::array<uint64_t, wordCount> words = {};

  bool empty(void) const
  {
    for (uint64_t word : words)
      if (word != 0) return false;
    return true;
  }

  bool contains(uint16_t slot) const
  {
    return slot < slotCount && (words[slot / 64] & (uint64_t(1) << (slot % 64))) != 0;
  }

  void insert(uint16_t slot)
  {
    if (slot < slotCount) words[slot / 64] |= uint64_t(1) << (slot % 64);
  }

  bool operator==(const CousinRouteSlotBitmap& other) const { return words == other.words; }
  bool operator!=(const CousinRouteSlotBitmap& other) const { return !(*this == other); }
};

template <typename S>
static void serialize(S&& serializer, CousinRouteSlotBitmap& bitmap)
{
  for (uint64_t& word : bitmap.words) serializer.value8b(word);
}

enum class CousinRouteHalf : uint8_t {
  source = 1,
  destination = 2
};

static inline bool cousinRouteHalfValid(CousinRouteHalf half)
{
  return half == CousinRouteHalf::source || half == CousinRouteHalf::destination;
}

static inline uint16_t cousinRouteServiceApplicationID(uint64_t service)
{
  return uint16_t(service >> 48);
}

enum class ProdigyLocalCousinServicePermissionState : uint8_t {
  active = 1,
  revoked = 2
};

enum class ProdigyCousinServicePurpose : uint8_t {
  statefulCousin = 0,
  clientAuthority = 1,
  sibling = 2,
  seeding = 3
};

enum class ProdigyCousinTransportSourcePolicy : uint8_t {
  exact = 0,
  authenticatedNAT = 1
};

static inline const char *prodigyCousinServicePurposeName(ProdigyCousinServicePurpose purpose)
{
  switch (purpose) {
    case ProdigyCousinServicePurpose::statefulCousin: return "stateful-cousin";
    case ProdigyCousinServicePurpose::clientAuthority: return "client-authority";
    case ProdigyCousinServicePurpose::sibling: return "sibling";
    case ProdigyCousinServicePurpose::seeding: return "seeding";
  }
  return "invalid";
}

constexpr inline uint32_t ProdigyLocalCousinServicePermissionMaximumRecords = 256;

class ProdigyLocalCousinServicePermission {
public:
  static constexpr uint32_t version = 3;
  static constexpr uint32_t baselineVersion = 2;
  static constexpr uint32_t purposeVersion = 3;

  uint32_t protocolVersion = 1;
  uint128_t permissionUUID = 0;
  uint128_t pairUUID = 0;
  uint128_t logicalWorkloadUUID = 0;
  uint128_t logicalServiceUUID = 0;
  uint128_t localClusterUUID = 0;
  uint128_t peerClusterUUID = 0;
  CousinRouteHalf localHalf = CousinRouteHalf::source;
  uint16_t localApplicationID = 0;
  uint16_t peerApplicationID = 0;
  uint64_t localCousinServicePrefix = 0;
  uint64_t peerCousinServicePrefix = 0;
  CousinRouteSlotBitmap slots = {};
  uint64_t localDeploymentID = 0;
  String canonicalPlanSHA256 = {};
  String artifactSHA256 = {};
  uint64_t artifactBytes = 0;
  uint64_t generation = 0;
  uint64_t acceptedAuthorityGeneration = 0;
  ProdigyLocalCousinServicePermissionState state = ProdigyLocalCousinServicePermissionState::active;
  // v2+: immutable resources from the full plan that the Brain verified.
  uint32_t baselineLogicalCores = 0;
  uint32_t baselineMemoryMB = 0;
  uint32_t baselineStorageMB = 0;
  // v3: exact peer deployment and one remote service, never a wildcard grant.
  ProdigyCousinServicePurpose purpose = ProdigyCousinServicePurpose::statefulCousin;
  uint64_t peerDeploymentID = 0;
  String peerCanonicalPlanSHA256 = {};
  String peerArtifactSHA256 = {};
  uint64_t peerArtifactBytes = 0;
  uint64_t authorizedService = 0;
  ProdigyCousinTransportSourcePolicy transportSourcePolicy = ProdigyCousinTransportSourcePolicy::exact;
  uint16_t destinationShardGroup = 0;
  uint16_t destinationShardGroups = 0;
};

class ProdigyLocalCousinServicePermissionRequest {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  ProdigyLocalCousinServicePermission permission = {};
};

class ProdigyLocalCousinServicePermissionQuery {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
  uint128_t permissionUUID = 0;
};

class ProdigyLocalCousinServicePermissionResponse {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
  bool success = false;
  bool found = false;
  bool qualified = false;
  uint128_t localClusterUUID = 0;
  uint64_t currentAuthorityGeneration = 0;
  uint128_t currentMasterUUID = 0;
  int64_t currentMasterBootNs = 0;
  ProdigyLocalCousinServicePermission permission = {};
  String failure = {};
};

template <typename S>
static void serialize(S&& serializer, ProdigyLocalCousinServicePermission& permission)
{
  serializer.value4b(permission.protocolVersion);
  serializer.value16b(permission.permissionUUID);
  serializer.value16b(permission.pairUUID);
  serializer.value16b(permission.logicalWorkloadUUID);
  serializer.value16b(permission.logicalServiceUUID);
  serializer.value16b(permission.localClusterUUID);
  serializer.value16b(permission.peerClusterUUID);
  serializer.value1b(permission.localHalf);
  serializer.value2b(permission.localApplicationID);
  serializer.value2b(permission.peerApplicationID);
  serializer.value8b(permission.localCousinServicePrefix);
  serializer.value8b(permission.peerCousinServicePrefix);
  serializer.object(permission.slots);
  serializer.value8b(permission.localDeploymentID);
  serializer.text1b(permission.canonicalPlanSHA256, 64);
  serializer.text1b(permission.artifactSHA256, 64);
  serializer.value8b(permission.artifactBytes);
  serializer.value8b(permission.generation);
  serializer.value8b(permission.acceptedAuthorityGeneration);
  serializer.value1b(permission.state);
  // Keep the v1 byte layout exact: old records have no trailing resource baseline.
  if (permission.protocolVersion >= ProdigyLocalCousinServicePermission::baselineVersion) {
    serializer.value4b(permission.baselineLogicalCores);
    serializer.value4b(permission.baselineMemoryMB);
    serializer.value4b(permission.baselineStorageMB);
  }
  // v1 and v2 end above, byte-for-byte unchanged.
  if (permission.protocolVersion >= ProdigyLocalCousinServicePermission::purposeVersion) {
    serializer.value1b(permission.purpose);
    serializer.value8b(permission.peerDeploymentID);
    serializer.text1b(permission.peerCanonicalPlanSHA256, 64);
    serializer.text1b(permission.peerArtifactSHA256, 64);
    serializer.value8b(permission.peerArtifactBytes);
    serializer.value8b(permission.authorizedService);
    serializer.value1b(permission.transportSourcePolicy);
    serializer.value2b(permission.destinationShardGroup);
    serializer.value2b(permission.destinationShardGroups);
  }
}

template <typename S>
static void serialize(S&& serializer, ProdigyLocalCousinServicePermissionRequest& request)
{
  serializer.value4b(request.protocolVersion);
  serializer.value8b(request.expectedAuthorityGeneration);
  serializer.value16b(request.expectedMasterUUID);
  serializer.value8b(request.expectedMasterBootNs);
  serializer.object(request.permission);
}

template <typename S>
static void serialize(S&& serializer, ProdigyLocalCousinServicePermissionQuery& query)
{
  serializer.value4b(query.protocolVersion);
  serializer.value16b(query.permissionUUID);
}

template <typename S>
static void serialize(S&& serializer, ProdigyLocalCousinServicePermissionResponse& response)
{
  serializer.value4b(response.protocolVersion);
  serializer.value1b(response.success);
  serializer.value1b(response.found);
  serializer.value1b(response.qualified);
  serializer.value16b(response.localClusterUUID);
  serializer.value8b(response.currentAuthorityGeneration);
  serializer.value16b(response.currentMasterUUID);
  serializer.value8b(response.currentMasterBootNs);
  serializer.object(response.permission);
  serializer.text1b(response.failure, 4096);
}

static inline bool prodigyLocalCousinServicePermissionStateValid(
    ProdigyLocalCousinServicePermissionState state)
{
  return state == ProdigyLocalCousinServicePermissionState::active ||
         state == ProdigyLocalCousinServicePermissionState::revoked;
}

static inline uint64_t prodigyCousinClientAuthorityPrefix(uint16_t applicationID)
{
  switch (applicationID) {
    case 2: return MeshRegistry::Pulse::clients;
    case 3: return MeshRegistry::Hot::clients;
    case 4: return MeshRegistry::Cold::clients;
    case 5: return MeshRegistry::Radar::clients;
    case 10: return MeshRegistry::Truth::clients;
  }
  return 0;
}

static inline bool prodigyCousinServicePermissionSingleSlot(
    const ProdigyLocalCousinServicePermission& permission, uint16_t& slot)
{
  bool found = false;
  for (uint16_t candidate = 0; candidate < CousinRouteSlotBitmap::slotCount; ++candidate) {
    if (!permission.slots.contains(candidate)) continue;
    if (found) return false;
    found = true; slot = candidate;
  }
  return found;
}

static inline bool prodigyCousinServicePermissionPurposeValid(
    const ProdigyLocalCousinServicePermission& permission)
{
  if (permission.protocolVersion < ProdigyLocalCousinServicePermission::purposeVersion)
    return permission.purpose == ProdigyCousinServicePurpose::statefulCousin &&
        permission.peerDeploymentID == 0 && permission.peerCanonicalPlanSHA256.empty() &&
        permission.peerArtifactSHA256.empty() && permission.peerArtifactBytes == 0 && permission.authorizedService == 0 &&
        permission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::exact &&
        permission.destinationShardGroup == 0 && permission.destinationShardGroups == 0;
  if (uint8_t(permission.purpose) > uint8_t(ProdigyCousinServicePurpose::seeding) ||
      permission.peerDeploymentID == 0 || uint16_t(permission.peerDeploymentID >> 48) != permission.peerApplicationID ||
      (permission.peerDeploymentID & UINT64_C(0x0000ffffffffffff)) == 0 ||
      !prodigyIsSHA256HexDigest(permission.peerCanonicalPlanSHA256) ||
      !prodigyIsSHA256HexDigest(permission.peerArtifactSHA256) || permission.peerArtifactBytes == 0 ||
      !MeshServices::isShard(permission.authorizedService) ||
      uint8_t(permission.transportSourcePolicy) > uint8_t(ProdigyCousinTransportSourcePolicy::authenticatedNAT)) return false;
  const bool source = permission.localHalf == CousinRouteHalf::source;
  const uint16_t sourceApp = source ? permission.localApplicationID : permission.peerApplicationID;
  const uint16_t destinationApp = source ? permission.peerApplicationID : permission.localApplicationID;
  const uint64_t sourcePrefix = source ? permission.localCousinServicePrefix : permission.peerCousinServicePrefix;
  const uint64_t destinationPrefix = source ? permission.peerCousinServicePrefix : permission.localCousinServicePrefix;
  if (MeshServices::convertShardToPrefix(permission.authorizedService) != destinationPrefix) return false;
  if (permission.purpose == ProdigyCousinServicePurpose::statefulCousin)
    return (permission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::exact ||
            permission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::authenticatedNAT) &&
        permission.destinationShardGroup == 0 && permission.destinationShardGroups == 0;
  if (permission.destinationShardGroups == 0 || permission.destinationShardGroups > nStatefulServiceGroupSlots ||
      permission.destinationShardGroup >= permission.destinationShardGroups ||
      permission.authorizedService != MeshServices::constrainPrefixToGroup(destinationPrefix, permission.destinationShardGroup)) return false;
  uint16_t slot = 0;
  if (!prodigyCousinServicePermissionSingleSlot(permission, slot) ||
      statefulServiceGroupOwnerForSlot(slot, permission.destinationShardGroups) != permission.destinationShardGroup) return false;
  if (permission.purpose == ProdigyCousinServicePurpose::clientAuthority) {
    // The source prefix is an authentication identity only, not an advertisement.
    const bool sharded = destinationApp == 3 || destinationApp == 4;
    return (sourceApp == 6 || sourceApp == 11) && prodigyCousinClientAuthorityPrefix(destinationApp) != 0 &&
        sourcePrefix == (sourceApp == 6 ? MeshServices::generateStatefulService(6, 1) :
                         MeshServices::generateStatefulService(11, 1)) &&
        destinationPrefix == prodigyCousinClientAuthorityPrefix(destinationApp) &&
        (sharded || (permission.destinationShardGroup == 0 && permission.destinationShardGroups == 1));
  }
  // KV seeding is a same-group pull from the retained source's seeding role.
  if (permission.purpose == ProdigyCousinServicePurpose::seeding && (sourceApp == 3 || sourceApp == 4)) {
    const uint64_t expected = sourceApp == 3 ? MeshRegistry::Hot::seeding : MeshRegistry::Cold::seeding;
    return sourceApp == destinationApp && sourcePrefix == expected && destinationPrefix == expected;
  }
  // Retained graph peers are one-group, same-application, non-client roles.
  if (sourceApp != destinationApp || (sourceApp != 2 && sourceApp != 5) || sourcePrefix != destinationPrefix ||
      permission.destinationShardGroup != 0 || permission.destinationShardGroups != 1 || slot != 0) return false;
  const uint64_t expected = permission.purpose == ProdigyCousinServicePurpose::sibling ?
      (sourceApp == 2 ? MeshRegistry::Pulse::siblings : MeshRegistry::Radar::siblings) :
      (sourceApp == 2 ? MeshRegistry::Pulse::seeding : MeshRegistry::Radar::seeding);
  return sourcePrefix == expected;
}

static inline bool prodigyCousinServicePermissionGroupValid(
    const ProdigyLocalCousinServicePermission& permission, uint32_t group, uint32_t groups)
{
  if (permission.purpose == ProdigyCousinServicePurpose::statefulCousin) return true;
  if (permission.purpose == ProdigyCousinServicePurpose::seeding &&
      (permission.localApplicationID == 3 || permission.localApplicationID == 4))
    return group == permission.destinationShardGroup && groups == permission.destinationShardGroups;
  if (permission.localHalf == CousinRouteHalf::source) return group == 0 && groups == 1;
  return group == permission.destinationShardGroup && groups == permission.destinationShardGroups;
}

static inline bool prodigyCousinServicePermissionPeerScopeMatches(
    const ProdigyLocalCousinServicePermission& source, const ProdigyLocalCousinServicePermission& destination)
{
  if (source.protocolVersion < ProdigyLocalCousinServicePermission::purposeVersion &&
      destination.protocolVersion < ProdigyLocalCousinServicePermission::purposeVersion) return true;
  return source.protocolVersion == ProdigyLocalCousinServicePermission::purposeVersion &&
      destination.protocolVersion == source.protocolVersion && source.purpose == destination.purpose &&
      source.authorizedService == destination.authorizedService && source.transportSourcePolicy == destination.transportSourcePolicy &&
      source.destinationShardGroup == destination.destinationShardGroup && source.destinationShardGroups == destination.destinationShardGroups &&
      source.peerDeploymentID == destination.localDeploymentID && destination.peerDeploymentID == source.localDeploymentID &&
      source.peerCanonicalPlanSHA256 == destination.canonicalPlanSHA256 && destination.peerCanonicalPlanSHA256 == source.canonicalPlanSHA256 &&
      source.peerArtifactSHA256 == destination.artifactSHA256 && destination.peerArtifactSHA256 == source.artifactSHA256 &&
      source.peerArtifactBytes == destination.artifactBytes && destination.peerArtifactBytes == source.artifactBytes;
}

// One source binding may serve distinct exact nonlegacy services, but changing
// the permission UUID must not create two leases for the same remote service.
static inline bool prodigyCousinSourcePermissionsConflict(
    const ProdigyLocalCousinServicePermission& left, const ProdigyLocalCousinServicePermission& right)
{
  return left.purpose == ProdigyCousinServicePurpose::statefulCousin ||
      right.purpose == ProdigyCousinServicePurpose::statefulCousin || left.permissionUUID == right.permissionUUID ||
      (left.peerClusterUUID == right.peerClusterUUID && left.authorizedService == right.authorizedService);
}

// A caller submits an unassigned permission (acceptedAuthorityGeneration == 0).
// A durable owner record must instead carry the nonzero authority generation
// that accepted it.  The rest of the scope is identical in both forms.
static inline bool prodigyLocalCousinServicePermissionValid(
    const ProdigyLocalCousinServicePermission& permission,
    bool requireAcceptedAuthorityGeneration = true)
{
  if ((permission.protocolVersion < 1 || permission.protocolVersion > ProdigyLocalCousinServicePermission::version) ||
      permission.permissionUUID == 0 || permission.pairUUID == 0 ||
      permission.logicalWorkloadUUID == 0 || permission.logicalServiceUUID == 0 ||
      permission.localClusterUUID == 0 || permission.peerClusterUUID == 0 ||
      permission.localClusterUUID == permission.peerClusterUUID ||
      !cousinRouteHalfValid(permission.localHalf) || permission.localApplicationID == 0 ||
      permission.peerApplicationID == 0 ||
      !MeshServices::isPrefix(permission.localCousinServicePrefix) ||
      !MeshServices::isPrefix(permission.peerCousinServicePrefix) ||
      cousinRouteServiceApplicationID(permission.localCousinServicePrefix) != permission.localApplicationID ||
      cousinRouteServiceApplicationID(permission.peerCousinServicePrefix) != permission.peerApplicationID ||
      permission.slots.empty() || permission.localDeploymentID == 0 ||
      uint16_t(permission.localDeploymentID >> 48) != permission.localApplicationID ||
      (permission.localDeploymentID & UINT64_C(0x0000ffffffffffff)) == 0 ||
      !prodigyIsSHA256HexDigest(permission.canonicalPlanSHA256) ||
      !prodigyIsSHA256HexDigest(permission.artifactSHA256) || permission.artifactBytes == 0 ||
      !prodigyLocalCousinServicePermissionStateValid(permission.state) ||
      !prodigyCousinServicePermissionPurposeValid(permission))
  {
    return false;
  }
  if ((permission.protocolVersion == 1 && (permission.baselineLogicalCores != 0 || permission.baselineMemoryMB != 0 || permission.baselineStorageMB != 0)) ||
      (permission.protocolVersion >= ProdigyLocalCousinServicePermission::baselineVersion &&
       !(permission.protocolVersion == ProdigyLocalCousinServicePermission::purposeVersion && !requireAcceptedAuthorityGeneration &&
         permission.baselineLogicalCores == 0 && permission.baselineMemoryMB == 0 && permission.baselineStorageMB == 0) &&
       (permission.baselineLogicalCores == 0 || permission.baselineLogicalCores > UINT16_MAX ||
        permission.baselineMemoryMB == 0 || permission.baselineStorageMB == 0))) return false;
  if (permission.state == ProdigyLocalCousinServicePermissionState::active) {
    if (permission.generation != 1) return false;
  } else if (permission.generation != 2) {
    return false;
  }
  return requireAcceptedAuthorityGeneration ? permission.acceptedAuthorityGeneration != 0 :
      permission.acceptedAuthorityGeneration == 0;
}

static inline bool prodigyLocalCousinServicePermissionIdentityScopeMatches(
    const ProdigyLocalCousinServicePermission& left, const ProdigyLocalCousinServicePermission& right)
{
  return left.permissionUUID == right.permissionUUID && left.pairUUID == right.pairUUID &&
         left.logicalWorkloadUUID == right.logicalWorkloadUUID && left.logicalServiceUUID == right.logicalServiceUUID &&
         left.localClusterUUID == right.localClusterUUID && left.peerClusterUUID == right.peerClusterUUID &&
         left.localHalf == right.localHalf && left.localApplicationID == right.localApplicationID &&
         left.peerApplicationID == right.peerApplicationID && left.localCousinServicePrefix == right.localCousinServicePrefix &&
         left.peerCousinServicePrefix == right.peerCousinServicePrefix && left.slots == right.slots &&
         left.localDeploymentID == right.localDeploymentID && left.canonicalPlanSHA256 == right.canonicalPlanSHA256 &&
         left.artifactSHA256 == right.artifactSHA256 && left.artifactBytes == right.artifactBytes &&
         left.purpose == right.purpose && left.peerDeploymentID == right.peerDeploymentID &&
         left.peerCanonicalPlanSHA256 == right.peerCanonicalPlanSHA256 && left.peerArtifactSHA256 == right.peerArtifactSHA256 &&
         left.peerArtifactBytes == right.peerArtifactBytes && left.authorizedService == right.authorizedService &&
         left.transportSourcePolicy == right.transportSourcePolicy &&
         left.destinationShardGroup == right.destinationShardGroup && left.destinationShardGroups == right.destinationShardGroups;
}

static inline bool prodigyLocalCousinServicePermissionScopeMatches(
    const ProdigyLocalCousinServicePermission& left,
    const ProdigyLocalCousinServicePermission& right)
{
  return left.protocolVersion == right.protocolVersion &&
         left.baselineLogicalCores == right.baselineLogicalCores &&
         left.baselineMemoryMB == right.baselineMemoryMB &&
         left.baselineStorageMB == right.baselineStorageMB &&
         prodigyLocalCousinServicePermissionIdentityScopeMatches(left, right);
}

static inline bool prodigyLocalCousinServicePermissionEqual(
    const ProdigyLocalCousinServicePermission& left,
    const ProdigyLocalCousinServicePermission& right)
{
  return prodigyLocalCousinServicePermissionScopeMatches(left, right) &&
         left.generation == right.generation &&
         left.acceptedAuthorityGeneration == right.acceptedAuthorityGeneration && left.state == right.state;
}

// A controller request has no acceptance generation.  The only permitted
// owner enrichment supplies verified resource baselines: legacy v1 becomes v2,
// while an explicitly purpose-bound v3 request retains its exact v3 identity.
static inline bool prodigyLocalCousinServicePermissionRequestAccepted(
    const ProdigyLocalCousinServicePermission& requested,
    const ProdigyLocalCousinServicePermission& observed)
{
  if (!prodigyLocalCousinServicePermissionValid(requested, false) ||
      !prodigyLocalCousinServicePermissionValid(observed) ||
      !prodigyLocalCousinServicePermissionIdentityScopeMatches(requested, observed) ||
      requested.state != observed.state || requested.generation != observed.generation) return false;
  if (requested.protocolVersion == 1)
  {
    if (observed.protocolVersion == 1) return prodigyLocalCousinServicePermissionScopeMatches(requested, observed);
    return observed.protocolVersion == ProdigyLocalCousinServicePermission::baselineVersion;
  }
  if (requested.protocolVersion == ProdigyLocalCousinServicePermission::purposeVersion &&
      observed.protocolVersion == requested.protocolVersion && requested.baselineLogicalCores == 0 &&
      requested.baselineMemoryMB == 0 && requested.baselineStorageMB == 0) return true;
  return prodigyLocalCousinServicePermissionScopeMatches(requested, observed);
}

static inline bool prodigyLocalCousinServicePermissionsValid(
    const Vector<ProdigyLocalCousinServicePermission>& permissions,
    uint128_t localClusterUUID, uint64_t authorityGeneration)
{
  if (permissions.empty()) return true;
  if (localClusterUUID == 0 || authorityGeneration == 0 ||
      permissions.size() > ProdigyLocalCousinServicePermissionMaximumRecords) return false;
  for (uint32_t index = 0; index < permissions.size(); ++index)
  {
    const auto& permission = permissions[index];
    if (!prodigyLocalCousinServicePermissionValid(permission) ||
        permission.localClusterUUID != localClusterUUID ||
        permission.acceptedAuthorityGeneration > authorityGeneration ||
        (index != 0 && permissions[index - 1].permissionUUID >= permission.permissionUUID)) return false;
  }
  return true;
}

static inline bool prodigyLocalCousinServicePermissionsEqual(
    const Vector<ProdigyLocalCousinServicePermission>& left,
    const Vector<ProdigyLocalCousinServicePermission>& right)
{
  if (left.size() != right.size()) return false;
  for (uint32_t index = 0; index < left.size(); ++index)
    if (!prodigyLocalCousinServicePermissionEqual(left[index], right[index])) return false;
  return true;
}

static inline bool prodigyLocalCousinServicePermissionRequestValid(
    const ProdigyLocalCousinServicePermissionRequest& request)
{
  return request.protocolVersion == ProdigyLocalCousinServicePermissionRequest::version &&
         request.expectedAuthorityGeneration != 0 && request.expectedMasterUUID != 0 &&
         request.expectedMasterBootNs > 0 &&
         prodigyLocalCousinServicePermissionValid(request.permission, false);
}

static inline bool prodigyLocalCousinServicePermissionQueryValid(
    const ProdigyLocalCousinServicePermissionQuery& query)
{
  return query.protocolVersion == ProdigyLocalCousinServicePermissionQuery::version &&
         query.permissionUUID != 0;
}
