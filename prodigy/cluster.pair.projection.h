#pragma once
#include <array>
#include <prodigy/cluster.pair.control.h>

constexpr inline uint32_t ProdigyLocalClusterPairControlProjectionMaximumCredentials = 256;
class ProdigyLocalClusterPairControlCredential {
public:
  uint128_t pairUUID = 0; uint64_t rootGeneration = 0; uint64_t keyEpoch = 0;
  ClusterPairControlEndpoint initiator = {}, responder = {};
  String localClaim = {}, remoteClaim = {}, canonicalContext = {};
  uint8_t psk[32] = {};
  ~ProdigyLocalClusterPairControlCredential() { OPENSSL_cleanse(psk, sizeof(psk)); }
};
class ProdigyLocalClusterPairControlProjection {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = 0; uint128_t localClusterUUID = 0, nodeUUID = 0;
  uint64_t committedAuthorityGeneration = 0;
  Vector<ProdigyLocalClusterPairControlCredential> credentials;
};
static inline bool prodigyLocalClusterPairControlCredentialValid(const ProdigyLocalClusterPairControlCredential& credential,
                                                                  uint128_t clusterUUID, uint128_t nodeUUID, bool requireSecret)
{
  uint8_t aggregate = 0; for (uint8_t byte : credential.psk) aggregate |= byte;
  ClusterPairControlEndpointClaim local = {}, remote = {};
  if (credential.pairUUID == 0 || credential.rootGeneration == 0 || credential.keyEpoch == 0 ||
      credential.canonicalContext.empty() || credential.canonicalContext.size() > 1024 ||
      credential.localClaim.size() > 222 || credential.remoteClaim.size() > 222 ||
      !clusterPairControlEndpointValid(credential.initiator) || !clusterPairControlEndpointValid(credential.responder) ||
      credential.initiator.clusterUUID == credential.responder.clusterUUID ||
      !clusterPairParseControlEndpointClaim(credential.localClaim, local) ||
      !clusterPairParseControlEndpointClaim(credential.remoteClaim, remote) ||
      local.presenter.clusterUUID != clusterUUID || local.presenter.nodeUUID != nodeUUID ||
      local.pairUUID != credential.pairUUID || remote.pairUUID != credential.pairUUID ||
      local.rootGeneration != credential.rootGeneration || remote.rootGeneration != credential.rootGeneration ||
      local.keyEpoch != credential.keyEpoch || remote.keyEpoch != credential.keyEpoch ||
      !clusterPairControlEndpointEquals(local.initiator, credential.initiator) ||
      !clusterPairControlEndpointEquals(local.responder, credential.responder) ||
      !clusterPairControlEndpointEquals(remote.initiator, credential.initiator) ||
      !clusterPairControlEndpointEquals(remote.responder, credential.responder) ||
      clusterPairControlEndpointEquals(local.presenter, remote.presenter) || (requireSecret && aggregate == 0) ||
      (!requireSecret && aggregate != 0)) return false;
  return true;
}
static inline bool prodigyLocalClusterPairControlProjectionValid(const ProdigyLocalClusterPairControlProjection& projection, bool requireSecret)
{
  if (projection.protocolVersion != ProdigyLocalClusterPairControlProjection::version || projection.localClusterUUID == 0 ||
      projection.nodeUUID == 0 || projection.committedAuthorityGeneration == 0 ||
      projection.credentials.size() > ProdigyLocalClusterPairControlProjectionMaximumCredentials) return false;
  for (uint32_t left=0; left<projection.credentials.size(); ++left) {
    const auto& credential=projection.credentials[left];
    if (!prodigyLocalClusterPairControlCredentialValid(credential, projection.localClusterUUID, projection.nodeUUID, requireSecret)) return false;
    for (uint32_t right = 0; right < left; ++right)
    {
      const auto& prior = projection.credentials[right];
      if (credential.pairUUID != prior.pairUUID) continue;
      ClusterPairControlEndpointClaim a, b;
      if (credential.rootGeneration != prior.rootGeneration || credential.keyEpoch != prior.keyEpoch ||
          !clusterPairParseControlEndpointClaim(credential.remoteClaim, a) ||
          !clusterPairParseControlEndpointClaim(prior.remoteClaim, b) || a.presenter == b.presenter) return false;
    }
  }
  return true;
}
static inline bool prodigyLocalClusterPairControlProjectionEqual(const ProdigyLocalClusterPairControlProjection& left, const ProdigyLocalClusterPairControlProjection& right)
{
  if (left.protocolVersion != right.protocolVersion || left.localClusterUUID != right.localClusterUUID || left.nodeUUID != right.nodeUUID || left.committedAuthorityGeneration != right.committedAuthorityGeneration || left.credentials.size() != right.credentials.size()) return false;
  for (uint32_t index = 0; index < left.credentials.size(); ++index) {
    const auto& a = left.credentials[index]; const auto& b = right.credentials[index];
    if (a.pairUUID != b.pairUUID || a.rootGeneration != b.rootGeneration || a.keyEpoch != b.keyEpoch || a.initiator != b.initiator || a.responder != b.responder || a.localClaim != b.localClaim || a.remoteClaim != b.remoteClaim || a.canonicalContext != b.canonicalContext || CRYPTO_memcmp(a.psk, b.psk, sizeof(a.psk)) != 0) return false;
  }
  return true;
}

template <typename S> static void serialize(S&& serializer, ProdigyLocalClusterPairControlCredential& credential) {
  serializer.value16b(credential.pairUUID); serializer.value8b(credential.rootGeneration); serializer.value8b(credential.keyEpoch);
  serializer.object(credential.initiator); serializer.object(credential.responder); serializer.text1b(credential.localClaim, 222);
  serializer.text1b(credential.remoteClaim, 222); serializer.text1b(credential.canonicalContext, 1024);
  for (auto& byte: credential.psk) serializer.value1b(byte);
}
template <typename S> static void serialize(S&& serializer, ProdigyLocalClusterPairControlProjection& projection) {
  serializer.value4b(projection.protocolVersion); serializer.value16b(projection.localClusterUUID); serializer.value16b(projection.nodeUUID);
  serializer.value8b(projection.committedAuthorityGeneration); serializer.container(projection.credentials, ProdigyLocalClusterPairControlProjectionMaximumCredentials,
      [](auto& nested, auto& credential) { nested.object(credential); });
}
