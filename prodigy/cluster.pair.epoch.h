#pragma once

// Public, root-free epoch agreement records for the authenticated pair-control
// carrier. Durable transition ownership remains in Brain; this header only
// defines canonical agreement identity and bounded transport codecs.

#include <array>
#include <cstdint>
#include <cstring>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <prodigy/cluster.pair.endpoint.h>
#include <prodigy/cluster.pair.codec.h>

constexpr inline uint32_t ProdigyClusterPairEpochProtocolVersion = 1;
constexpr inline uint32_t ProdigyClusterPairEpochStatusBytes = 157;
constexpr inline uint32_t ProdigyClusterPairEpochMaximumStatuses = 64;

enum class ProdigyClusterPairEpochPhase : uint8_t {
  none = 0,
  prepared = 1,
  staged = 2,
  ready = 3,
  committed = 4,
  complete = 5,
};

class ProdigyClusterPairEpochStatus {
public:
  uint32_t protocolVersion = 0;
  uint128_t pairUUID = 0;
  uint64_t rootGeneration = 0;
  uint128_t sourceClusterUUID = 0;
  uint128_t peerClusterUUID = 0;
  uint64_t agreedKeyEpoch = 0;
  uint128_t committedAgreementUUID = 0;
  uint128_t agreementUUID = 0;
  uint64_t oldEpoch = 0;
  uint64_t nextEpoch = 0;
  ProdigyClusterPairEpochPhase phase = ProdigyClusterPairEpochPhase::none;
  uint64_t authorityGeneration = 0;
  std::array<uint8_t, 32> agreementDigest = {};
};

class ProdigyClusterPairEpochReceipt {
public:
  ClusterPairControlEndpoint localEndpoint = {};
  ClusterPairControlEndpoint remoteEndpoint = {};
  uint64_t wireEpoch = 0;
  uint64_t projectionGeneration = 0;
  ProdigyClusterPairEpochStatus status = {};
};

static inline bool prodigyClusterPairEpochPhaseValid(ProdigyClusterPairEpochPhase phase)
{
  return phase == ProdigyClusterPairEpochPhase::prepared || phase == ProdigyClusterPairEpochPhase::staged ||
      phase == ProdigyClusterPairEpochPhase::ready || phase == ProdigyClusterPairEpochPhase::committed ||
      phase == ProdigyClusterPairEpochPhase::complete;
}

static inline bool prodigyClusterPairEpochAgreementDigest(uint128_t pairUUID, uint64_t rootGeneration,
                                                           uint128_t sourceClusterUUID, uint128_t peerClusterUUID,
                                                           uint128_t agreementUUID, uint64_t oldEpoch,
                                                           uint64_t nextEpoch, std::array<uint8_t, 32>& digest)
{
  OPENSSL_cleanse(digest.data(), digest.size());
  if (pairUUID == 0 || rootGeneration == 0 || sourceClusterUUID == 0 || peerClusterUUID == 0 ||
      sourceClusterUUID == peerClusterUUID || agreementUUID == 0 || oldEpoch == 0 || oldEpoch == UINT64_MAX || nextEpoch == 0 || nextEpoch != oldEpoch + 1) return false;
  const uint128_t first = sourceClusterUUID < peerClusterUUID ? sourceClusterUUID : peerClusterUUID;
  const uint128_t second = sourceClusterUUID < peerClusterUUID ? peerClusterUUID : sourceClusterUUID;
  String canonical = {};
  constexpr char domain[] = "prodigy/cluster-pair/epoch-agreement/v1";
  if (!canonical.reserve(sizeof(domain) - 1 + 16 + 8 + 16 + 16 + 16 + 8 + 8)) return false;
  canonical.append(domain, sizeof(domain) - 1);
  clusterPairKeyAppendU128BE(canonical, pairUUID);
  clusterPairKeyAppendU64BE(canonical, rootGeneration);
  clusterPairKeyAppendU128BE(canonical, first);
  clusterPairKeyAppendU128BE(canonical, second);
  clusterPairKeyAppendU128BE(canonical, agreementUUID);
  clusterPairKeyAppendU64BE(canonical, oldEpoch);
  clusterPairKeyAppendU64BE(canonical, nextEpoch);
  unsigned int outputSize = 0;
  return canonical.size() == sizeof("prodigy/cluster-pair/epoch-agreement/v1") - 1 + 88 && EVP_Digest(canonical.data(), canonical.size(), digest.data(), &outputSize,
      EVP_sha256(), nullptr) == 1 && outputSize == digest.size();
}

static inline bool prodigyClusterPairEpochStatusValid(const ProdigyClusterPairEpochStatus& status)
{
  if (status.protocolVersion != ProdigyClusterPairEpochProtocolVersion || status.pairUUID == 0 ||
      status.rootGeneration == 0 || status.sourceClusterUUID == 0 || status.peerClusterUUID == 0 ||
      status.sourceClusterUUID == status.peerClusterUUID || status.agreedKeyEpoch == 0 ||
      status.agreementUUID == 0 || status.oldEpoch == 0 || status.oldEpoch == UINT64_MAX || status.nextEpoch == 0 || status.nextEpoch != status.oldEpoch + 1 ||
      !prodigyClusterPairEpochPhaseValid(status.phase) || status.authorityGeneration == 0) return false;
  if ((status.phase == ProdigyClusterPairEpochPhase::prepared || status.phase == ProdigyClusterPairEpochPhase::staged ||
       status.phase == ProdigyClusterPairEpochPhase::ready) && status.agreedKeyEpoch != status.oldEpoch) return false;
  if ((status.phase == ProdigyClusterPairEpochPhase::committed || status.phase == ProdigyClusterPairEpochPhase::complete) &&
      (status.agreedKeyEpoch != status.nextEpoch || status.committedAgreementUUID != status.agreementUUID)) return false;
  std::array<uint8_t, 32> expected = {};
  return prodigyClusterPairEpochAgreementDigest(status.pairUUID, status.rootGeneration, status.sourceClusterUUID,
      status.peerClusterUUID, status.agreementUUID, status.oldEpoch, status.nextEpoch, expected) &&
      CRYPTO_memcmp(expected.data(), status.agreementDigest.data(), expected.size()) == 0;
}

static inline bool prodigyClusterPairEpochStatusAllowsWireEpoch(const ProdigyClusterPairEpochStatus& status,
                                                                  uint64_t wireEpoch)
{
  if (!prodigyClusterPairEpochStatusValid(status)) return false;
  if (status.phase == ProdigyClusterPairEpochPhase::prepared) return wireEpoch == status.oldEpoch;
  if (status.phase == ProdigyClusterPairEpochPhase::staged || status.phase == ProdigyClusterPairEpochPhase::ready)
    return wireEpoch == status.oldEpoch || wireEpoch == status.nextEpoch;
  return wireEpoch == status.nextEpoch;
}

static inline bool prodigyClusterPairEpochStatusAppend(String& bytes, const ProdigyClusterPairEpochStatus& status)
{
  if (!prodigyClusterPairEpochStatusValid(status)) return false;
  const uint64_t before = bytes.size();
  if (!bytes.reserve(before + ProdigyClusterPairEpochStatusBytes)) return false;
  clusterPairControlAppendU32BE(bytes, status.protocolVersion);
  clusterPairKeyAppendU128BE(bytes, status.pairUUID);
  clusterPairKeyAppendU64BE(bytes, status.rootGeneration);
  clusterPairKeyAppendU128BE(bytes, status.sourceClusterUUID);
  clusterPairKeyAppendU128BE(bytes, status.peerClusterUUID);
  clusterPairKeyAppendU64BE(bytes, status.agreedKeyEpoch);
  clusterPairKeyAppendU128BE(bytes, status.committedAgreementUUID);
  clusterPairKeyAppendU128BE(bytes, status.agreementUUID);
  clusterPairKeyAppendU64BE(bytes, status.oldEpoch);
  clusterPairKeyAppendU64BE(bytes, status.nextEpoch);
  bytes.append(uint8_t(status.phase));
  clusterPairKeyAppendU64BE(bytes, status.authorityGeneration);
  bytes.append(status.agreementDigest.data(), status.agreementDigest.size());
  return bytes.size() == before + ProdigyClusterPairEpochStatusBytes;
}

static inline bool prodigyClusterPairEpochStatusParse(const uint8_t* data, uint64_t size,
                                                       ProdigyClusterPairEpochStatus& status)
{
  status = {};
  if (!data || size != ProdigyClusterPairEpochStatusBytes) return false;
  const uint8_t* cursor = data;
  const uint8_t* end = data + size;
  uint8_t phase = 0;
  if (!clusterPairControlReadU32BE(cursor, end, status.protocolVersion) ||
      !clusterPairControlReadU128BE(cursor, end, status.pairUUID) ||
      !clusterPairControlReadU64BE(cursor, end, status.rootGeneration) ||
      !clusterPairControlReadU128BE(cursor, end, status.sourceClusterUUID) ||
      !clusterPairControlReadU128BE(cursor, end, status.peerClusterUUID) ||
      !clusterPairControlReadU64BE(cursor, end, status.agreedKeyEpoch) ||
      !clusterPairControlReadU128BE(cursor, end, status.committedAgreementUUID) ||
      !clusterPairControlReadU128BE(cursor, end, status.agreementUUID) ||
      !clusterPairControlReadU64BE(cursor, end, status.oldEpoch) ||
      !clusterPairControlReadU64BE(cursor, end, status.nextEpoch) || end - cursor < 1) return false;
  phase = *cursor++;
  status.phase = ProdigyClusterPairEpochPhase(phase);
  if (!clusterPairControlReadU64BE(cursor, end, status.authorityGeneration) || uint64_t(end - cursor) != status.agreementDigest.size()) return false;
  std::memcpy(status.agreementDigest.data(), cursor, status.agreementDigest.size());
  cursor += status.agreementDigest.size();
  return cursor == end && prodigyClusterPairEpochStatusValid(status);
}

template <typename S> static void serialize(S&& serializer, ProdigyClusterPairEpochStatus& status)
{
  serializer.value4b(status.protocolVersion); serializer.value16b(status.pairUUID); serializer.value8b(status.rootGeneration);
  serializer.value16b(status.sourceClusterUUID); serializer.value16b(status.peerClusterUUID); serializer.value8b(status.agreedKeyEpoch);
  serializer.value16b(status.committedAgreementUUID); serializer.value16b(status.agreementUUID); serializer.value8b(status.oldEpoch);
  serializer.value8b(status.nextEpoch); uint8_t phase = uint8_t(status.phase); serializer.value1b(phase); status.phase = ProdigyClusterPairEpochPhase(phase);
  serializer.value8b(status.authorityGeneration); for (auto& byte : status.agreementDigest) serializer.value1b(byte);
}
template <typename S> static void serialize(S&& serializer, ProdigyClusterPairEpochReceipt& receipt)
{
  serializer.object(receipt.localEndpoint); serializer.object(receipt.remoteEndpoint); serializer.value8b(receipt.wireEpoch);
  serializer.value8b(receipt.projectionGeneration); serializer.object(receipt.status);
}
