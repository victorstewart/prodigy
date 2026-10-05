#pragma once

#include <openssl/crypto.h>
#include <types/types.containers.h>

// This is durable enrollment metadata only.  It does not itself establish
// authority, quorum, or permission to issue/use any credential.
enum class ProdigyClusterPairEnrollmentState : uint8_t {
  pending = 1,
  active = 2,
  revoked = 3,
};

constexpr inline uint32_t ProdigyClusterPairEnrollmentMaximumRecords = 64;
constexpr inline uint32_t ProdigyClusterPairEnrollmentRootBytes = 32;

class ProdigyClusterPairEnrollment {
public:
  // This tuple binds this persisted root/key generation. Future validated
  // supersession and rotation remain the existing authority owner's concern.
  uint128_t pairUUID = 0;
  uint128_t localClusterUUID = 0;
  uint128_t peerClusterUUID = 0;
  uint128_t operationUUID = 0;
  uint64_t rootGeneration = 0;
  uint64_t agreedKeyEpoch = 0;
  uint64_t localAuthorityGeneration = 0;
  ProdigyClusterPairEnrollmentState state = ProdigyClusterPairEnrollmentState::pending;
  // Hydrated runtime only. Persistent public snapshots must contain zeros;
  // the matching root lives in ProdigyPersistentBrainSnapshotSecrets.
  uint8_t root[ProdigyClusterPairEnrollmentRootBytes] = {};

  // Snapshots remain copyable. Each deliberate copy owns its own root bytes
  // and wipes them when that copy is destroyed, including vector relocation.
  ~ProdigyClusterPairEnrollment()
  {
    OPENSSL_cleanse(root, sizeof(root));
  }
};

static inline bool prodigyClusterPairEnrollmentRootIsZero(const ProdigyClusterPairEnrollment& enrollment)
{
  uint8_t aggregate = 0;
  for (uint8_t byte : enrollment.root) aggregate |= byte;
  return aggregate == 0;
}

static inline bool prodigyClusterPairEnrollmentRootEquals(
    const ProdigyClusterPairEnrollment& left, const ProdigyClusterPairEnrollment& right)
{
  return CRYPTO_memcmp(left.root, right.root, ProdigyClusterPairEnrollmentRootBytes) == 0;
}

static inline bool prodigyClusterPairEnrollmentDescriptorValid(const ProdigyClusterPairEnrollment& enrollment)
{
  if (enrollment.pairUUID == 0 || enrollment.localClusterUUID == 0 ||
      enrollment.peerClusterUUID == 0 || enrollment.localClusterUUID == enrollment.peerClusterUUID ||
      enrollment.operationUUID == 0 || enrollment.rootGeneration == 0 ||
      enrollment.agreedKeyEpoch == 0 || enrollment.localAuthorityGeneration == 0)
    return false;
  return enrollment.state == ProdigyClusterPairEnrollmentState::pending ||
         enrollment.state == ProdigyClusterPairEnrollmentState::active ||
         enrollment.state == ProdigyClusterPairEnrollmentState::revoked;
}

static inline bool prodigyClusterPairEnrollmentIdentityEquals(
    const ProdigyClusterPairEnrollment& left, const ProdigyClusterPairEnrollment& right)
{
  return left.pairUUID == right.pairUUID &&
         left.localClusterUUID == right.localClusterUUID &&
         left.peerClusterUUID == right.peerClusterUUID &&
         left.operationUUID == right.operationUUID &&
         left.rootGeneration == right.rootGeneration &&
         left.agreedKeyEpoch == right.agreedKeyEpoch &&
         left.localAuthorityGeneration == right.localAuthorityGeneration;
}

static inline bool prodigyClusterPairEnrollmentsEqual(
    const Vector<ProdigyClusterPairEnrollment>& left,
    const Vector<ProdigyClusterPairEnrollment>& right)
{
  if (left.size() != right.size()) return false;
  for (uint32_t index = 0; index < left.size(); ++index)
  {
    if (!prodigyClusterPairEnrollmentIdentityEquals(left[index], right[index]) ||
        left[index].state != right[index].state ||
        !prodigyClusterPairEnrollmentRootEquals(left[index], right[index])) return false;
  }
  return true;
}

template <typename S>
static void serialize(S&& serializer, ProdigyClusterPairEnrollment& enrollment)
{
  serializer.value16b(enrollment.pairUUID);
  serializer.value16b(enrollment.localClusterUUID);
  serializer.value16b(enrollment.peerClusterUUID);
  serializer.value16b(enrollment.operationUUID);
  serializer.value8b(enrollment.rootGeneration);
  serializer.value8b(enrollment.agreedKeyEpoch);
  serializer.value8b(enrollment.localAuthorityGeneration);
  uint8_t state = uint8_t(enrollment.state);
  serializer.value1b(state);
  enrollment.state = ProdigyClusterPairEnrollmentState(state);
  for (uint8_t& byte : enrollment.root) serializer.value1b(byte);
}
