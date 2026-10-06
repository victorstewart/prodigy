#pragma once

#include <array>
#include <cstdint>

#include <networking/includes.h>
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

constexpr inline uint32_t ProdigyLocalCousinServicePermissionMaximumRecords = 256;

class ProdigyLocalCousinServicePermission {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
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

// A caller submits an unassigned permission (acceptedAuthorityGeneration == 0).
// A durable owner record must instead carry the nonzero authority generation
// that accepted it.  The rest of the scope is identical in both forms.
static inline bool prodigyLocalCousinServicePermissionValid(
    const ProdigyLocalCousinServicePermission& permission,
    bool requireAcceptedAuthorityGeneration = true)
{
  if (permission.protocolVersion != ProdigyLocalCousinServicePermission::version ||
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
      !prodigyLocalCousinServicePermissionStateValid(permission.state))
  {
    return false;
  }
  if (permission.state == ProdigyLocalCousinServicePermissionState::active) {
    if (permission.generation != 1) return false;
  } else if (permission.generation != 2) {
    return false;
  }
  return requireAcceptedAuthorityGeneration ? permission.acceptedAuthorityGeneration != 0 :
      permission.acceptedAuthorityGeneration == 0;
}

static inline bool prodigyLocalCousinServicePermissionScopeMatches(
    const ProdigyLocalCousinServicePermission& left,
    const ProdigyLocalCousinServicePermission& right)
{
  return left.protocolVersion == right.protocolVersion && left.permissionUUID == right.permissionUUID &&
         left.pairUUID == right.pairUUID && left.logicalWorkloadUUID == right.logicalWorkloadUUID &&
         left.logicalServiceUUID == right.logicalServiceUUID && left.localClusterUUID == right.localClusterUUID &&
         left.peerClusterUUID == right.peerClusterUUID && left.localHalf == right.localHalf &&
         left.localApplicationID == right.localApplicationID && left.peerApplicationID == right.peerApplicationID &&
         left.localCousinServicePrefix == right.localCousinServicePrefix &&
         left.peerCousinServicePrefix == right.peerCousinServicePrefix && left.slots == right.slots &&
         left.localDeploymentID == right.localDeploymentID &&
         left.canonicalPlanSHA256 == right.canonicalPlanSHA256 && left.artifactSHA256 == right.artifactSHA256 &&
         left.artifactBytes == right.artifactBytes;
}

static inline bool prodigyLocalCousinServicePermissionEqual(
    const ProdigyLocalCousinServicePermission& left,
    const ProdigyLocalCousinServicePermission& right)
{
  return prodigyLocalCousinServicePermissionScopeMatches(left, right) &&
         left.generation == right.generation &&
         left.acceptedAuthorityGeneration == right.acceptedAuthorityGeneration && left.state == right.state;
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
