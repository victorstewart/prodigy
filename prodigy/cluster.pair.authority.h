#pragma once

#include <algorithm>
#include <prodigy/persistent.codec.h>
#include <prodigy/cluster.pair.enrollment.h>
#include <prodigy/cluster.pair.endpoint.h>
#include <prodigy/transport.credentials.h>

constexpr inline uint32_t ProdigyClusterPairEnrollmentOperationMaximumEndpoints = 16;

class ProdigyClusterPairEnrollmentOperation {
public:
  static constexpr uint32_t version = 2;
  static constexpr uint32_t legacyVersion = 1;
  uint32_t protocolVersion = legacyVersion;
  uint128_t pairUUID = 0;
  uint128_t operationUUID = 0;
  uint64_t localAuthorityGeneration = 0;
  uint64_t transitionGeneration = 0;
  uint64_t pinnedMasterAuthorityEpoch = 0;
  bool initialProjectionDelivered = false;
  // v2 only.  Enrollment voters remain immutable; revocation separately
  // captures the live electorate that authorized its first admission.
  bool revocationRequested = false;
  bool projectionsWithdrawn = false;
  uint64_t revocationTransitionGeneration = 0;
  uint64_t revocationPinnedMasterAuthorityEpoch = 0;
  Vector<uint128_t> frozenElectorate;
  Vector<uint128_t> revocationFrozenElectorate;
  Vector<ClusterPairControlEndpoint> localEndpoints;
  Vector<ClusterPairControlEndpoint> peerEndpoints;
};

static inline bool prodigyClusterPairEndpointsValid(const Vector<ClusterPairControlEndpoint>& endpoints,
                                                     uint128_t clusterUUID)
{
  if (clusterUUID == 0 || endpoints.empty() || endpoints.size() > ProdigyClusterPairEnrollmentOperationMaximumEndpoints) return false;
  for (uint32_t left = 0; left < endpoints.size(); ++left)
  {
    if (!clusterPairControlEndpointValid(endpoints[left]) || endpoints[left].clusterUUID != clusterUUID) return false;
    if (left != 0) {
      const auto& prior = endpoints[left - 1]; const auto& current = endpoints[left];
      if (prior.nodeUUID > current.nodeUUID ||
          (prior.nodeUUID == current.nodeUUID && (prior.port > current.port ||
           (prior.port == current.port && std::memcmp(prior.address.v6, current.address.v6, sizeof(prior.address.v6)) >= 0)))) return false;
    }
    for (uint32_t right = 0; right < left; ++right)
      if (endpoints[left].nodeUUID == endpoints[right].nodeUUID ||
          clusterPairControlEndpointEquals(endpoints[left], endpoints[right])) return false;
  }
  return true;
}

static inline bool prodigyClusterPairEnrollmentOperationValid(
    const ProdigyClusterPairEnrollmentOperation& operation,
    const ProdigyClusterPairEnrollment& enrollment, uint64_t runtimeGeneration)
{
  if ((operation.protocolVersion != ProdigyClusterPairEnrollmentOperation::legacyVersion &&
       operation.protocolVersion != ProdigyClusterPairEnrollmentOperation::version) ||
      operation.pairUUID != enrollment.pairUUID || operation.operationUUID != enrollment.operationUUID ||
      operation.localAuthorityGeneration != enrollment.localAuthorityGeneration ||
      operation.localAuthorityGeneration == 0 || operation.transitionGeneration < operation.localAuthorityGeneration ||
      operation.transitionGeneration > runtimeGeneration ||
      operation.pinnedMasterAuthorityEpoch == 0 || operation.frozenElectorate.empty() ||
      operation.frozenElectorate.size() > ProdigyTransportCredentialEnrollmentMaximumRecords ||
      (enrollment.state == ProdigyClusterPairEnrollmentState::pending && operation.initialProjectionDelivered) ||
      !prodigyClusterPairEndpointsValid(operation.localEndpoints, enrollment.localClusterUUID) ||
      !prodigyClusterPairEndpointsValid(operation.peerEndpoints, enrollment.peerClusterUUID)) return false;
  for (uint32_t left = 0; left < operation.frozenElectorate.size(); ++left)
  {
    if (operation.frozenElectorate[left] == 0 || (left && operation.frozenElectorate[left - 1] >= operation.frozenElectorate[left])) return false;
  }
  if (operation.protocolVersion == ProdigyClusterPairEnrollmentOperation::legacyVersion)
    return !operation.revocationRequested && !operation.projectionsWithdrawn &&
        operation.revocationTransitionGeneration == 0 && operation.revocationPinnedMasterAuthorityEpoch == 0 &&
        operation.revocationFrozenElectorate.empty();
  if (!operation.revocationRequested)
    return !operation.projectionsWithdrawn && operation.revocationTransitionGeneration == 0 &&
        operation.revocationPinnedMasterAuthorityEpoch == 0 && operation.revocationFrozenElectorate.empty() &&
        enrollment.state != ProdigyClusterPairEnrollmentState::revoked;
  if (operation.revocationPinnedMasterAuthorityEpoch == 0 ||
      operation.revocationTransitionGeneration < operation.localAuthorityGeneration ||
      operation.revocationTransitionGeneration > runtimeGeneration || operation.revocationFrozenElectorate.empty() ||
      operation.revocationFrozenElectorate.size() > ProdigyTransportCredentialEnrollmentMaximumRecords ||
      (operation.projectionsWithdrawn && enrollment.state != ProdigyClusterPairEnrollmentState::revoked)) return false;
  for (uint32_t left = 0; left < operation.revocationFrozenElectorate.size(); ++left)
    if (operation.revocationFrozenElectorate[left] == 0 ||
        (left && operation.revocationFrozenElectorate[left - 1] >= operation.revocationFrozenElectorate[left])) return false;
  return true;
}

template <typename S>
static void serialize(S&& serializer, ProdigyClusterPairEnrollmentOperation& operation)
{
  serializer.value4b(operation.protocolVersion); serializer.value16b(operation.pairUUID);
  serializer.value16b(operation.operationUUID); serializer.value8b(operation.localAuthorityGeneration);
  serializer.value8b(operation.transitionGeneration); serializer.value8b(operation.pinnedMasterAuthorityEpoch);
  serializer.value1b(operation.initialProjectionDelivered);
  if (operation.protocolVersion >= ProdigyClusterPairEnrollmentOperation::version) {
    serializer.value1b(operation.revocationRequested); serializer.value1b(operation.projectionsWithdrawn);
    serializer.value8b(operation.revocationTransitionGeneration); serializer.value8b(operation.revocationPinnedMasterAuthorityEpoch);
  } else {
    operation.revocationRequested = false; operation.projectionsWithdrawn = false;
    operation.revocationTransitionGeneration = 0; operation.revocationPinnedMasterAuthorityEpoch = 0;
    operation.revocationFrozenElectorate.clear();
  }
  serializer.container(operation.frozenElectorate, ProdigyTransportCredentialEnrollmentMaximumRecords,
      [](auto& nested, uint128_t& voter) { nested.value16b(voter); });
  if (operation.protocolVersion >= ProdigyClusterPairEnrollmentOperation::version)
    serializer.container(operation.revocationFrozenElectorate, ProdigyTransportCredentialEnrollmentMaximumRecords,
        [](auto& nested, uint128_t& voter) { nested.value16b(voter); });
  serializer.container(operation.localEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints,
      [](auto& nested, auto& endpoint) { nested.object(endpoint); });
  serializer.container(operation.peerEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints,
      [](auto& nested, auto& endpoint) { nested.object(endpoint); });
}

static inline bool prodigyValidateClusterPairEnrollmentOperations(
    const Vector<ProdigyClusterPairEnrollment>& enrollments,
    const Vector<ProdigyClusterPairEnrollmentOperation>& operations, uint64_t runtimeGeneration,
    const Vector<ProdigyTransportCredentialEnrollment> *olderBrainLedger = nullptr)
{
  if (operations.empty()) return true;
  if (operations.size() != enrollments.size() || operations.size() > ProdigyClusterPairEnrollmentMaximumRecords) return false;
  for (const auto& enrollment : enrollments)
  {
    uint32_t matches = 0;
    for (const auto& operation : operations)
      if (operation.pairUUID == enrollment.pairUUID && operation.operationUUID == enrollment.operationUUID &&
          prodigyClusterPairEnrollmentOperationValid(operation, enrollment, runtimeGeneration)) ++matches;
    if (matches != 1) return false;
    const auto& operation = *std::find_if(operations.begin(), operations.end(), [&](const auto& value) { return value.pairUUID == enrollment.pairUUID; });
    if (olderBrainLedger != nullptr && enrollment.state != ProdigyClusterPairEnrollmentState::revoked && !operation.initialProjectionDelivered)
      for (uint128_t voter : operation.frozenElectorate) {
        const bool known = std::any_of(olderBrainLedger->begin(), olderBrainLedger->end(), [&](const auto& member) {
          return member.nodeUUID == voter && member.clusterUUID == enrollment.localClusterUUID &&
              member.role == ProdigyTransportCredentialNodeRole::brain && member.authorityGeneration < enrollment.localAuthorityGeneration &&
              (member.state == ProdigyTransportCredentialEnrollmentState::active || member.state == ProdigyTransportCredentialEnrollmentState::revoked);
        });
        if (!known) return false;
      }
  }
  return true;
}

class ProdigyClusterPairAuthorityRevokeRequest {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t pairUUID = 0;
  uint128_t operationUUID = 0;
};
class ProdigyClusterPairAuthorityRevokeQuery {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0;
};
class ProdigyClusterPairAuthorityRevokeResponse {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  bool success = false, found = false, qualifiedRevoked = false, projectionsWithdrawn = false;
  uint128_t localClusterUUID = 0;
  uint64_t currentAuthorityGeneration = 0;
  ProdigyClusterPairEnrollment enrollment;
  Vector<ClusterPairControlEndpoint> localEndpoints, peerEndpoints;
  String failure;
};

class ProdigyClusterPairEnrollmentRequest {
public:
  static constexpr uint32_t version = 1; uint32_t protocolVersion = version; uint64_t expectedAuthorityGeneration = 0;
  ProdigyClusterPairEnrollment enrollment; Vector<ClusterPairControlEndpoint> localEndpoints, peerEndpoints;
};
class ProdigyClusterPairEnrollmentQuery { public: static constexpr uint32_t version = 1; uint32_t protocolVersion = version; uint128_t operationUUID = 0; };
class ProdigyClusterPairEnrollmentResponse {
public:
  static constexpr uint32_t version = 1; uint32_t protocolVersion = version; bool success = false, found = false, qualified = false, initialProjectionDelivered = false;
  uint128_t localClusterUUID = 0; uint64_t currentAuthorityGeneration = 0; ProdigyClusterPairEnrollment enrollment;
  Vector<ClusterPairControlEndpoint> localEndpoints, peerEndpoints; String failure;
};
template <typename S> static void serialize(S&& serializer, ProdigyClusterPairAuthorityRevokeRequest& request) {
  serializer.value4b(request.protocolVersion); serializer.value8b(request.expectedAuthorityGeneration);
  serializer.value16b(request.pairUUID); serializer.value16b(request.operationUUID);
}
template <typename S> static void serialize(S&& serializer, ProdigyClusterPairAuthorityRevokeQuery& query) {
  serializer.value4b(query.protocolVersion); serializer.value16b(query.operationUUID);
}
template <typename S> static void serialize(S&& serializer, ProdigyClusterPairAuthorityRevokeResponse& response) {
  serializer.value4b(response.protocolVersion); serializer.value1b(response.success); serializer.value1b(response.found);
  serializer.value1b(response.qualifiedRevoked); serializer.value1b(response.projectionsWithdrawn);
  serializer.value16b(response.localClusterUUID); serializer.value8b(response.currentAuthorityGeneration);
  ProdigyClusterPairEnrollment publicEnrollment = response.enrollment;
  if constexpr (ProdigyPersistentSerializerIsWriter<std::remove_cvref_t<S>>::value) {
    OPENSSL_cleanse(publicEnrollment.root, sizeof(publicEnrollment.root)); serializer.object(publicEnrollment);
  } else {
    serializer.object(publicEnrollment);
    if (!prodigyClusterPairEnrollmentRootIsZero(publicEnrollment)) serializer.adapter().error(bitsery::ReaderError::InvalidData);
    response.enrollment = std::move(publicEnrollment);
  }
  serializer.container(response.localEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints, [](auto& n, auto& e){n.object(e);});
  serializer.container(response.peerEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints, [](auto& n, auto& e){n.object(e);});
  serializer.text1b(response.failure, 1024);
}

template <typename S> static void serialize(S&& serializer, ProdigyClusterPairEnrollmentRequest& request) {
  serializer.value4b(request.protocolVersion); serializer.value8b(request.expectedAuthorityGeneration); serializer.object(request.enrollment);
  serializer.container(request.localEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints, [](auto& n, auto& e){n.object(e);});
  serializer.container(request.peerEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints, [](auto& n, auto& e){n.object(e);});
}
template <typename S> static void serialize(S&& serializer, ProdigyClusterPairEnrollmentQuery& query) { serializer.value4b(query.protocolVersion); serializer.value16b(query.operationUUID); }
template <typename S> static void serialize(S&& serializer, ProdigyClusterPairEnrollmentResponse& response) {
  serializer.value4b(response.protocolVersion); serializer.value1b(response.success); serializer.value1b(response.found); serializer.value1b(response.qualified); serializer.value1b(response.initialProjectionDelivered);
  serializer.value16b(response.localClusterUUID); serializer.value8b(response.currentAuthorityGeneration);
  ProdigyClusterPairEnrollment publicEnrollment = response.enrollment;
  if constexpr (ProdigyPersistentSerializerIsWriter<std::remove_cvref_t<S>>::value) {
    OPENSSL_cleanse(publicEnrollment.root, sizeof(publicEnrollment.root)); serializer.object(publicEnrollment);
  } else {
    serializer.object(publicEnrollment);
    if (!prodigyClusterPairEnrollmentRootIsZero(publicEnrollment)) serializer.adapter().error(bitsery::ReaderError::InvalidData);
    response.enrollment = std::move(publicEnrollment);
  }
  serializer.container(response.localEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints, [](auto& n, auto& e){n.object(e);});
  serializer.container(response.peerEndpoints, ProdigyClusterPairEnrollmentOperationMaximumEndpoints, [](auto& n, auto& e){n.object(e);}); serializer.text1b(response.failure, 1024);
}
