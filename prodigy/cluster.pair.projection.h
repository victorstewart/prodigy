#pragma once
#include <array>
#include <prodigy/cluster.pair.control.h>
#include <prodigy/cluster.pair.epoch.h>

constexpr inline uint32_t ProdigyLocalClusterPairControlProjectionLegacyMaximumCredentials = 256;
constexpr inline uint32_t ProdigyLocalClusterPairControlProjectionMaximumCredentials = 512;
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
  static constexpr uint32_t legacyVersion1 = 1;
  static constexpr uint32_t version = 2;
  uint32_t protocolVersion = 0; uint128_t localClusterUUID = 0, nodeUUID = 0;
  uint64_t committedAuthorityGeneration = 0;
  Vector<ProdigyLocalClusterPairControlCredential> credentials;
  Vector<ProdigyClusterPairEpochStatus> epochStatuses;
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
static inline const ProdigyClusterPairEpochStatus *prodigyLocalClusterPairControlEpochStatus(
    const ProdigyLocalClusterPairControlProjection& projection, uint128_t pairUUID, uint64_t rootGeneration,
    uint128_t localClusterUUID, uint128_t peerClusterUUID)
{
  const ProdigyClusterPairEpochStatus *matched = nullptr;
  for (const auto& status : projection.epochStatuses)
  {
    if (status.pairUUID != pairUUID || status.rootGeneration != rootGeneration ||
        status.sourceClusterUUID != localClusterUUID || status.peerClusterUUID != peerClusterUUID) continue;
    if (matched) return nullptr;
    matched = &status;
  }
  return matched;
}
static inline bool prodigyLocalClusterPairControlCredentialAllowedByEpoch(
    const ProdigyLocalClusterPairControlProjection& projection, const ProdigyLocalClusterPairControlCredential& credential)
{
  const uint128_t peerClusterUUID = credential.initiator.clusterUUID == projection.localClusterUUID ?
      credential.responder.clusterUUID : credential.initiator.clusterUUID;
  const auto *status = prodigyLocalClusterPairControlEpochStatus(projection, credential.pairUUID,
      credential.rootGeneration, projection.localClusterUUID, peerClusterUUID);
  if (!status) return true;
  if (status->phase == ProdigyClusterPairEpochPhase::prepared) return credential.keyEpoch == status->oldEpoch;
  if (status->phase == ProdigyClusterPairEpochPhase::staged || status->phase == ProdigyClusterPairEpochPhase::ready)
    return credential.keyEpoch == status->oldEpoch || credential.keyEpoch == status->nextEpoch;
  return credential.keyEpoch == status->nextEpoch;
}
static inline bool prodigyLocalClusterPairControlProjectionValid(const ProdigyLocalClusterPairControlProjection& projection, bool requireSecret)
{
  if ((projection.protocolVersion != ProdigyLocalClusterPairControlProjection::legacyVersion1 &&
       projection.protocolVersion != ProdigyLocalClusterPairControlProjection::version) || projection.localClusterUUID == 0 ||
      projection.nodeUUID == 0 || projection.committedAuthorityGeneration == 0 ||
      projection.credentials.size() > ProdigyLocalClusterPairControlProjectionMaximumCredentials ||
      projection.epochStatuses.size() > ProdigyClusterPairEpochMaximumStatuses ||
      (projection.protocolVersion == ProdigyLocalClusterPairControlProjection::legacyVersion1 &&
       (projection.credentials.size() > ProdigyLocalClusterPairControlProjectionLegacyMaximumCredentials || !projection.epochStatuses.empty()))) return false;
  for (uint32_t index = 0; index < projection.epochStatuses.size(); ++index)
  {
    const auto& status = projection.epochStatuses[index];
    if (!prodigyClusterPairEpochStatusValid(status) || status.sourceClusterUUID != projection.localClusterUUID) return false;
    for (uint32_t prior = 0; prior < index; ++prior)
      if (status.pairUUID == projection.epochStatuses[prior].pairUUID && status.rootGeneration == projection.epochStatuses[prior].rootGeneration &&
          status.sourceClusterUUID == projection.epochStatuses[prior].sourceClusterUUID && status.peerClusterUUID == projection.epochStatuses[prior].peerClusterUUID) return false;
  }
  for (uint32_t left=0; left<projection.credentials.size(); ++left) {
    const auto& credential=projection.credentials[left];
    if (!prodigyLocalClusterPairControlCredentialValid(credential, projection.localClusterUUID, projection.nodeUUID, requireSecret) ||
        !prodigyLocalClusterPairControlCredentialAllowedByEpoch(projection, credential)) return false;
    for (uint32_t right = 0; right < left; ++right)
    {
      const auto& prior = projection.credentials[right];
      if (credential.pairUUID != prior.pairUUID) continue;
      if (credential.rootGeneration != prior.rootGeneration) return false;
      ClusterPairControlEndpointClaim a, b;
      if (!clusterPairParseControlEndpointClaim(credential.remoteClaim, a) ||
          !clusterPairParseControlEndpointClaim(prior.remoteClaim, b)) return false;
      if (credential.keyEpoch == prior.keyEpoch)
      {
        // A repeated exact remote presenter would create duplicate inbound or
        // outbound authentication state. Distinct approved peers may share an epoch.
        if (a.presenter == b.presenter) return false;
        continue;
      }
      const uint128_t peerClusterUUID = credential.initiator.clusterUUID == projection.localClusterUUID ?
          credential.responder.clusterUUID : credential.initiator.clusterUUID;
      const auto *status = prodigyLocalClusterPairControlEpochStatus(projection, credential.pairUUID,
          credential.rootGeneration, projection.localClusterUUID, peerClusterUUID);
      const uint64_t oldEpoch = credential.keyEpoch < prior.keyEpoch ? credential.keyEpoch : prior.keyEpoch;
      const uint64_t nextEpoch = credential.keyEpoch < prior.keyEpoch ? prior.keyEpoch : credential.keyEpoch;
      if (!status || (status->phase != ProdigyClusterPairEpochPhase::staged && status->phase != ProdigyClusterPairEpochPhase::ready) ||
          status->oldEpoch != oldEpoch || status->nextEpoch != nextEpoch) return false;
    }
  }
  for (const auto& credential : projection.credentials)
  {
    const uint128_t peerClusterUUID = credential.initiator.clusterUUID == projection.localClusterUUID ?
        credential.responder.clusterUUID : credential.initiator.clusterUUID;
    const auto *status = prodigyLocalClusterPairControlEpochStatus(projection, credential.pairUUID,
        credential.rootGeneration, projection.localClusterUUID, peerClusterUUID);
    if (!status || (status->phase != ProdigyClusterPairEpochPhase::staged && status->phase != ProdigyClusterPairEpochPhase::ready)) continue;
    const uint64_t counterpartEpoch = credential.keyEpoch == status->oldEpoch ? status->nextEpoch : status->oldEpoch;
    const bool hasCounterpart = std::any_of(projection.credentials.begin(), projection.credentials.end(),
        [&](const auto& candidate) {
          ClusterPairControlEndpointClaim candidateRemote = {}, credentialRemote = {};
          return candidate.pairUUID == credential.pairUUID && candidate.rootGeneration == credential.rootGeneration &&
              candidate.keyEpoch == counterpartEpoch && clusterPairParseControlEndpointClaim(candidate.remoteClaim, candidateRemote) &&
              clusterPairParseControlEndpointClaim(credential.remoteClaim, credentialRemote) && candidateRemote.presenter == credentialRemote.presenter;
        });
    if (!hasCounterpart) return false;
  }
  return true;
}
static inline bool prodigyLocalClusterPairControlProjectionEqual(const ProdigyLocalClusterPairControlProjection& left, const ProdigyLocalClusterPairControlProjection& right)
{
  if (left.protocolVersion != right.protocolVersion || left.localClusterUUID != right.localClusterUUID || left.nodeUUID != right.nodeUUID || left.committedAuthorityGeneration != right.committedAuthorityGeneration || left.credentials.size() != right.credentials.size() || left.epochStatuses.size() != right.epochStatuses.size()) return false;
  for (uint32_t index = 0; index < left.credentials.size(); ++index) {
    const auto& a = left.credentials[index]; const auto& b = right.credentials[index];
    if (a.pairUUID != b.pairUUID || a.rootGeneration != b.rootGeneration || a.keyEpoch != b.keyEpoch || a.initiator != b.initiator || a.responder != b.responder || a.localClaim != b.localClaim || a.remoteClaim != b.remoteClaim || a.canonicalContext != b.canonicalContext || CRYPTO_memcmp(a.psk, b.psk, sizeof(a.psk)) != 0) return false;
  }
  for (uint32_t index = 0; index < left.epochStatuses.size(); ++index) {
    const auto& a = left.epochStatuses[index]; const auto& b = right.epochStatuses[index];
    if (a.protocolVersion != b.protocolVersion || a.pairUUID != b.pairUUID || a.rootGeneration != b.rootGeneration ||
        a.sourceClusterUUID != b.sourceClusterUUID || a.peerClusterUUID != b.peerClusterUUID || a.agreedKeyEpoch != b.agreedKeyEpoch ||
        a.committedAgreementUUID != b.committedAgreementUUID || a.agreementUUID != b.agreementUUID || a.oldEpoch != b.oldEpoch ||
        a.nextEpoch != b.nextEpoch || a.phase != b.phase || a.authorityGeneration != b.authorityGeneration ||
        CRYPTO_memcmp(a.agreementDigest.data(), b.agreementDigest.data(), a.agreementDigest.size()) != 0) return false;
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
  // Empty ordinary projections retain the v1 wire shape until rotation needs
  // a status record. The value read from a v1 record remains v1 in memory.
  uint32_t wireVersion = projection.epochStatuses.empty() ? ProdigyLocalClusterPairControlProjection::legacyVersion1 : projection.protocolVersion;
  serializer.value4b(wireVersion); projection.protocolVersion = wireVersion;
  serializer.value16b(projection.localClusterUUID); serializer.value16b(projection.nodeUUID);
  serializer.value8b(projection.committedAuthorityGeneration);
  const uint32_t credentialMaximum = projection.protocolVersion == ProdigyLocalClusterPairControlProjection::legacyVersion1 ?
      ProdigyLocalClusterPairControlProjectionLegacyMaximumCredentials : ProdigyLocalClusterPairControlProjectionMaximumCredentials;
  serializer.container(projection.credentials, credentialMaximum,
      [](auto& nested, auto& credential) { nested.object(credential); });
  if (projection.protocolVersion >= ProdigyLocalClusterPairControlProjection::version)
    serializer.container(projection.epochStatuses, ProdigyClusterPairEpochMaximumStatuses,
        [](auto& nested, auto& status) { nested.object(status); });
}
