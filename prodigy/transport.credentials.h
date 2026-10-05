#pragma once

#include <algorithm>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <types/types.containers.h>

// Durable control-plane contract for the internal AEGIS credential authority.
// These records are enrollment evidence only: transport activation and live
// liveness remain owned by the caller's authenticated control path.
enum class ProdigyTransportCredentialNodeRole : uint8_t {
  brain = 1,
  neuron = 2,
};

enum class ProdigyTransportCredentialEnrollmentState : uint8_t {
  pending = 1,
  active = 2,
  revoked = 3,
};

constexpr inline uint32_t ProdigyTransportCredentialAuthorityRootBytes = 32;
constexpr inline uint32_t ProdigyTransportCredentialEnrollmentMaximumRecords = 4096;

class ProdigyTransportCredentialEnrollment {
public:
  uint128_t operationUUID = 0;
  uint128_t nodeUUID = 0;
  uint128_t clusterUUID = 0;
  uint64_t authorityEpoch = 0;
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  ProdigyTransportCredentialNodeRole role = ProdigyTransportCredentialNodeRole::neuron;
  ProdigyTransportCredentialEnrollmentState state = ProdigyTransportCredentialEnrollmentState::pending;

  bool valid(void) const
  {
    return operationUUID != 0 && nodeUUID != 0 && clusterUUID != 0 && authorityEpoch != 0 &&
           keyEpoch != 0 && authorityGeneration != 0 &&
           (role == ProdigyTransportCredentialNodeRole::brain || role == ProdigyTransportCredentialNodeRole::neuron) &&
           (state == ProdigyTransportCredentialEnrollmentState::pending ||
            state == ProdigyTransportCredentialEnrollmentState::active ||
            state == ProdigyTransportCredentialEnrollmentState::revoked);
  }

  bool operator==(const ProdigyTransportCredentialEnrollment& other) const
  {
    return operationUUID == other.operationUUID && nodeUUID == other.nodeUUID && clusterUUID == other.clusterUUID &&
           authorityEpoch == other.authorityEpoch && keyEpoch == other.keyEpoch &&
           authorityGeneration == other.authorityGeneration && role == other.role && state == other.state;
  }
  bool operator!=(const ProdigyTransportCredentialEnrollment& other) const { return !(*this == other); }
};

enum class ProdigyTransportCredentialEnrollmentOperationPhase : uint8_t { pending = 1, active = 2, delivered = 3, revoked = 4 };

// A cohort is appended atomically at one authority-state generation. Its
// cardinality and target roles come from the existing addMachines journal;
// these public fields identify it without another persisted operation owner.
static inline bool prodigyTransportCredentialSameCohort(
    const ProdigyTransportCredentialEnrollment& lhs,
    const ProdigyTransportCredentialEnrollment& rhs)
{
  return lhs.clusterUUID == rhs.clusterUUID && lhs.authorityEpoch == rhs.authorityEpoch &&
      lhs.keyEpoch == rhs.keyEpoch && lhs.authorityGeneration == rhs.authorityGeneration;
}

// Enrollment is serialized while a cohort can still release credentials.
// Every target in that cohort is excluded from its original electorate. A
// membership removal must cancel unfinished enrollment before changing this
// set; a smaller reconstructed electorate never authorizes replay.
static inline bool prodigyTransportCredentialElectorateMatches(
    const ProdigyTransportCredentialEnrollment& enrollment,
    const Vector<uint128_t>& electorate,
    const Vector<ProdigyTransportCredentialEnrollment>& ledger)
{
  Vector<uint128_t> expected;
  for (const auto& member : ledger)
    if (member.clusterUUID == enrollment.clusterUUID &&
        member.authorityEpoch == enrollment.authorityEpoch && member.keyEpoch == enrollment.keyEpoch &&
        member.authorityGeneration < enrollment.authorityGeneration &&
        member.role == ProdigyTransportCredentialNodeRole::brain &&
        member.state == ProdigyTransportCredentialEnrollmentState::active)
      expected.push_back(member.nodeUUID);
  auto actual = electorate;
  std::sort(expected.begin(), expected.end());
  std::sort(actual.begin(), actual.end());
  return !expected.empty() && expected == actual &&
      std::adjacent_find(actual.begin(), actual.end()) == actual.end();
}

class ProdigyTransportCredentialEnrollmentOperation {
public:
  ProdigyTransportCredentialEnrollment enrollment;
  Vector<uint128_t> electorate;
  uint64_t pinnedMasterAuthorityEpoch = 0;
  uint64_t transitionGeneration = 0;
  ProdigyTransportCredentialEnrollmentOperationPhase phase = ProdigyTransportCredentialEnrollmentOperationPhase::pending;
  bool valid(void) const {
    if (!enrollment.valid() || electorate.empty() || electorate.size() > 4096 || pinnedMasterAuthorityEpoch == 0 || transitionGeneration == 0 ||
        uint8_t(phase) < uint8_t(ProdigyTransportCredentialEnrollmentOperationPhase::pending) || uint8_t(phase) > uint8_t(ProdigyTransportCredentialEnrollmentOperationPhase::revoked)) return false;
    if (transitionGeneration < enrollment.authorityGeneration ||
        (phase == ProdigyTransportCredentialEnrollmentOperationPhase::pending && enrollment.state != ProdigyTransportCredentialEnrollmentState::pending) ||
        ((phase == ProdigyTransportCredentialEnrollmentOperationPhase::active || phase == ProdigyTransportCredentialEnrollmentOperationPhase::delivered) && enrollment.state != ProdigyTransportCredentialEnrollmentState::active) ||
        (phase == ProdigyTransportCredentialEnrollmentOperationPhase::revoked && enrollment.state != ProdigyTransportCredentialEnrollmentState::revoked)) return false;
    for (uint32_t i = 0; i < electorate.size(); ++i) {
      if (electorate[i] == 0) return false;
      for (uint32_t j = 0; j < i; ++j) if (electorate[j] == electorate[i]) return false;
    }
    return true;
  }
};

class ProdigyTransportCredentialAuthorityRoot {
public:
  uint64_t authorityEpoch = 0;
  uint64_t keyEpoch = 0;
  // This is the durable master-authority generation that authorized the
  // root.  It is deliberately part of every derived credential's context.
  uint64_t authorityGeneration = 0;
  uint8_t root[ProdigyTransportCredentialAuthorityRootBytes] = {};

  ~ProdigyTransportCredentialAuthorityRoot()
  {
    OPENSSL_cleanse(root, sizeof(root));
  }

  bool valid(void) const
  {
    uint8_t aggregate = 0;
    for (uint8_t byte : root) aggregate |= byte;
    return authorityEpoch != 0 && keyEpoch != 0 && authorityGeneration != 0 && aggregate != 0;
  }
};

// A node credential is the only secret an enrolled Neuron receives.  It is
// already bound to that node and role, so it cannot be used as an authority
// root to mint a credential for a different identity.
class ProdigyTransportNodeCredential {
public:
  uint128_t operationUUID = 0;
  uint128_t nodeUUID = 0;
  uint128_t clusterUUID = 0;
  uint64_t authorityEpoch = 0;
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  uint64_t rootAuthorityGeneration = 0;
  ProdigyTransportCredentialNodeRole role = ProdigyTransportCredentialNodeRole::neuron;
  uint8_t secret[ProdigyTransportCredentialAuthorityRootBytes] = {};

  ~ProdigyTransportNodeCredential() { OPENSSL_cleanse(secret, sizeof(secret)); }

  bool descriptorValid(void) const
  {
    return operationUUID != 0 && nodeUUID != 0 && clusterUUID != 0 && authorityEpoch != 0 && keyEpoch != 0 &&
           authorityGeneration != 0 && rootAuthorityGeneration != 0 && rootAuthorityGeneration <= authorityGeneration &&
           (role == ProdigyTransportCredentialNodeRole::brain || role == ProdigyTransportCredentialNodeRole::neuron);
  }

  bool secretIsZero(void) const { uint8_t aggregate = 0; for (uint8_t byte : secret) aggregate |= byte; return aggregate == 0; }
  bool valid(void) const
  {
    return descriptorValid() && !secretIsZero();
  }
};

static inline void prodigyTransportCredentialAppendU64(String& bytes, uint64_t value);
static inline void prodigyTransportCredentialAppendU128(String& bytes, uint128_t value);
static inline bool prodigyDeriveTransportNodeCredential(
    const ProdigyTransportCredentialAuthorityRoot& authority,
    const ProdigyTransportCredentialEnrollment& enrollment,
    ProdigyTransportNodeCredential& output);
static inline bool prodigyDeriveTransportCredentialPSK(
    const ProdigyTransportNodeCredential& self, uint128_t peerOperationUUID,
    uint128_t peerNodeUUID, ProdigyTransportCredentialNodeRole peerRole,
    const String& purpose, String& canonicalContext,
    uint8_t output[ProdigyTransportCredentialAuthorityRootBytes]);

// This bounded, plaintext identity prelude is only a lookup hint.  The
// resolver must reject it unless it exactly matches an active local
// authorization, and the same fields are subsequently in the Noise prologue.
class ProdigyTransportCredentialPrelude {
public:
  uint128_t operationUUID = 0;
  uint128_t nodeUUID = 0;
  uint64_t authorityEpoch = 0;
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  ProdigyTransportCredentialNodeRole role = ProdigyTransportCredentialNodeRole::neuron;

  bool valid(void) const
  {
    return operationUUID != 0 && nodeUUID != 0 && authorityEpoch != 0 && keyEpoch != 0 && authorityGeneration != 0 &&
           (role == ProdigyTransportCredentialNodeRole::brain || role == ProdigyTransportCredentialNodeRole::neuron);
  }
};

static inline bool prodigyTransportCredentialPreludeMatches(
    const ProdigyTransportCredentialPrelude& prelude,
    const ProdigyTransportCredentialEnrollment& enrollment)
{
  return prelude.valid() && enrollment.valid() && enrollment.state == ProdigyTransportCredentialEnrollmentState::active &&
         prelude.operationUUID == enrollment.operationUUID && prelude.nodeUUID == enrollment.nodeUUID &&
         prelude.authorityEpoch == enrollment.authorityEpoch && prelude.keyEpoch == enrollment.keyEpoch &&
         prelude.authorityGeneration == enrollment.authorityGeneration && prelude.role == enrollment.role;
}

constexpr inline uint32_t ProdigyTransportCredentialPreludeBytes = 61;

static inline bool prodigyRenderTransportCredentialPrelude(
    const ProdigyTransportCredentialPrelude& prelude, String& encoded)
{
  encoded = {};
  if (!prelude.valid() || !encoded.reserve(ProdigyTransportCredentialPreludeBytes)) return false;
  constexpr char magic[] = "PAE1";
  encoded.append(magic, sizeof(magic) - 1);
  prodigyTransportCredentialAppendU128(encoded, prelude.operationUUID);
  prodigyTransportCredentialAppendU128(encoded, prelude.nodeUUID);
  prodigyTransportCredentialAppendU64(encoded, prelude.authorityEpoch);
  prodigyTransportCredentialAppendU64(encoded, prelude.keyEpoch);
  prodigyTransportCredentialAppendU64(encoded, prelude.authorityGeneration);
  encoded.append(char(prelude.role));
  return encoded.size() == ProdigyTransportCredentialPreludeBytes;
}

static inline bool prodigyParseTransportCredentialPrelude(
    const String& encoded, ProdigyTransportCredentialPrelude& prelude)
{
  prelude = {};
  if (encoded.size() != ProdigyTransportCredentialPreludeBytes ||
      std::memcmp(encoded.data(), "PAE1", 4) != 0) return false;
  uint32_t offset = 4;
  auto readU64 = [&](uint64_t& value) {
    value = 0;
    for (uint32_t byte = 0; byte < 8; ++byte) value = (value << 8) | uint8_t(encoded[offset++]);
  };
  auto readU128 = [&](uint128_t& value) {
    value = 0;
    for (uint32_t byte = 0; byte < 16; ++byte) value = (value << 8) | uint8_t(encoded[offset++]);
  };
  readU128(prelude.operationUUID);
  readU128(prelude.nodeUUID);
  readU64(prelude.authorityEpoch);
  readU64(prelude.keyEpoch);
  readU64(prelude.authorityGeneration);
  prelude.role = ProdigyTransportCredentialNodeRole(uint8_t(encoded[offset++]));
  return offset == encoded.size() && prelude.valid();
}

// A Neuron stores only this bundle. It can authenticate its authorized peers,
// but has neither the authority root nor any API that derives a second node's
// credential. The peer list is replicated over already-authenticated Brain
// control traffic and replaced atomically on a committed authority revision.
class ProdigyTransportCredentialBootstrap {
public:
  bool enabled = false;
  ProdigyTransportNodeCredential self;
  Vector<ProdigyTransportCredentialEnrollment> authorizedPeers;
  // The durable authority revision whose peer projection this is.  It is
  // monotonic independently of the creation generations in the projection.
  uint64_t committedAuthorityGeneration = 0;

  void clear(void)
  {
    self = {};
    authorizedPeers.clear();
    committedAuthorityGeneration = 0;
    enabled = false;
  }

  bool resolvePeer(const ProdigyTransportCredentialPrelude& prelude,
                   ProdigyTransportCredentialEnrollment& enrollment) const
  {
    if (!enabled || !self.valid() || !prelude.valid() || (prelude.nodeUUID == self.nodeUUID && prelude.role == self.role) ||
        prelude.authorityEpoch != self.authorityEpoch || prelude.keyEpoch != self.keyEpoch) return false;
    uint32_t matches = 0;
    for (const auto& candidate : authorizedPeers)
    {
      if (prodigyTransportCredentialPreludeMatches(prelude, candidate))
      {
        enrollment = candidate;
        ++matches;
      }
    }
    return matches == 1;
  }
};

static inline bool prodigyTransportCredentialBootstrapValid(const ProdigyTransportCredentialBootstrap& bootstrap, bool requireSecret = true)
{
  if (!bootstrap.enabled) return bootstrap.authorizedPeers.empty() && bootstrap.committedAuthorityGeneration == 0 && bootstrap.self.operationUUID == 0 && bootstrap.self.nodeUUID == 0 && bootstrap.self.clusterUUID == 0 && bootstrap.self.authorityEpoch == 0 && bootstrap.self.keyEpoch == 0 && bootstrap.self.authorityGeneration == 0 && bootstrap.self.rootAuthorityGeneration == 0 && bootstrap.self.role == ProdigyTransportCredentialNodeRole::neuron && bootstrap.self.secretIsZero();
  if (!(requireSecret ? bootstrap.self.valid() : (bootstrap.self.descriptorValid() && bootstrap.self.secretIsZero())) ||
      bootstrap.committedAuthorityGeneration < bootstrap.self.authorityGeneration ||
      bootstrap.committedAuthorityGeneration < bootstrap.self.rootAuthorityGeneration ||
      bootstrap.authorizedPeers.size() > ProdigyTransportCredentialEnrollmentMaximumRecords) return false;
  for (uint32_t index = 0; index < bootstrap.authorizedPeers.size(); ++index)
  {
    const auto& peer = bootstrap.authorizedPeers[index];
    if (!peer.valid() || peer.state != ProdigyTransportCredentialEnrollmentState::active ||
        peer.clusterUUID != bootstrap.self.clusterUUID || (peer.nodeUUID == bootstrap.self.nodeUUID && peer.role == bootstrap.self.role) ||
        peer.authorityEpoch != bootstrap.self.authorityEpoch || peer.keyEpoch != bootstrap.self.keyEpoch ||
        peer.authorityGeneration < bootstrap.self.rootAuthorityGeneration ||
        peer.authorityGeneration > bootstrap.committedAuthorityGeneration) return false;
    if (bootstrap.self.role == ProdigyTransportCredentialNodeRole::neuron && peer.role != ProdigyTransportCredentialNodeRole::brain) return false;
    for (uint32_t prior = 0; prior < index; ++prior)
      if (bootstrap.authorizedPeers[prior].operationUUID == peer.operationUUID ||
          (bootstrap.authorizedPeers[prior].nodeUUID == peer.nodeUUID && bootstrap.authorizedPeers[prior].role == peer.role)) return false;
  }
  return true;
}

template <typename S>
static void serialize(S&& serializer, ProdigyTransportNodeCredential& credential)
{
  serializer.value16b(credential.operationUUID); serializer.value16b(credential.nodeUUID); serializer.value16b(credential.clusterUUID);
  serializer.value8b(credential.authorityEpoch); serializer.value8b(credential.keyEpoch);
  serializer.value8b(credential.authorityGeneration); serializer.value8b(credential.rootAuthorityGeneration);
  uint8_t role = uint8_t(credential.role); serializer.value1b(role); credential.role = ProdigyTransportCredentialNodeRole(role);
  for (uint8_t& byte : credential.secret) serializer.value1b(byte);
}

template <typename S>
static void serialize(S&& serializer, ProdigyTransportCredentialBootstrap& bootstrap)
{
  serializer.value1b(bootstrap.enabled); serializer.object(bootstrap.self);
  serializer.container(bootstrap.authorizedPeers, ProdigyTransportCredentialEnrollmentMaximumRecords,
      [](auto& nested, ProdigyTransportCredentialEnrollment& peer) { nested.object(peer); });
  serializer.value8b(bootstrap.committedAuthorityGeneration);
}

static inline bool prodigyRenderLocalTransportCredentialPrelude(
    const ProdigyTransportCredentialBootstrap& bootstrap, String& encoded)
{
  ProdigyTransportCredentialPrelude prelude = {};
  if (!bootstrap.enabled || !bootstrap.self.valid()) { encoded.clear(); return false; }
  prelude.operationUUID = bootstrap.self.operationUUID;
  prelude.nodeUUID = bootstrap.self.nodeUUID;
  prelude.authorityEpoch = bootstrap.self.authorityEpoch;
  prelude.keyEpoch = bootstrap.self.keyEpoch;
  prelude.authorityGeneration = bootstrap.self.authorityGeneration;
  prelude.role = bootstrap.self.role;
  return prodigyRenderTransportCredentialPrelude(prelude, encoded);
}

static inline bool prodigyBuildTransportCredentialBootstrap(
    const ProdigyTransportCredentialAuthorityRoot& authority,
    const ProdigyTransportCredentialEnrollment& localEnrollment,
    const Vector<ProdigyTransportCredentialEnrollment>& ledger,
    bool enabled,
    ProdigyTransportCredentialBootstrap& bootstrap,
    uint64_t committedAuthorityGeneration = 0)
{
  bootstrap.clear();
  if (!enabled) return true;
  if (!prodigyDeriveTransportNodeCredential(authority, localEnrollment, bootstrap.self)) return false;
  for (const auto& enrollment : ledger)
  {
    if (enrollment.state != ProdigyTransportCredentialEnrollmentState::active ||
        enrollment.operationUUID == localEnrollment.operationUUID ||
        enrollment.clusterUUID != bootstrap.self.clusterUUID ||
        (bootstrap.self.role == ProdigyTransportCredentialNodeRole::neuron && enrollment.role != ProdigyTransportCredentialNodeRole::brain) || enrollment.authorityEpoch != bootstrap.self.authorityEpoch ||
        enrollment.keyEpoch != bootstrap.self.keyEpoch) continue;
    bootstrap.authorizedPeers.push_back(enrollment);
  }
  std::sort(bootstrap.authorizedPeers.begin(), bootstrap.authorizedPeers.end(), [](const auto& lhs, const auto& rhs) {
    if (lhs.nodeUUID != rhs.nodeUUID) return lhs.nodeUUID < rhs.nodeUUID;
    if (lhs.role != rhs.role) return uint8_t(lhs.role) < uint8_t(rhs.role);
    return lhs.operationUUID < rhs.operationUUID;
  });
  uint64_t maximumActiveGeneration = 0;
  for (const auto& enrollment : ledger)
    if (enrollment.state == ProdigyTransportCredentialEnrollmentState::active)
      maximumActiveGeneration = std::max(maximumActiveGeneration, enrollment.authorityGeneration);
  bootstrap.committedAuthorityGeneration = committedAuthorityGeneration ? committedAuthorityGeneration : maximumActiveGeneration;
  bootstrap.enabled = true;
  return prodigyTransportCredentialBootstrapValid(bootstrap);
}

static inline bool prodigyTransportCredentialBootstrapSameProjection(
    const ProdigyTransportCredentialBootstrap& lhs,
    const ProdigyTransportCredentialBootstrap& rhs)
{
  if (lhs.enabled != rhs.enabled || lhs.committedAuthorityGeneration != rhs.committedAuthorityGeneration ||
      lhs.self.operationUUID != rhs.self.operationUUID || lhs.self.nodeUUID != rhs.self.nodeUUID ||
      lhs.self.clusterUUID != rhs.self.clusterUUID || lhs.self.authorityEpoch != rhs.self.authorityEpoch ||
      lhs.self.keyEpoch != rhs.self.keyEpoch || lhs.self.authorityGeneration != rhs.self.authorityGeneration ||
      lhs.self.rootAuthorityGeneration != rhs.self.rootAuthorityGeneration || lhs.self.role != rhs.self.role ||
      lhs.authorizedPeers.size() != rhs.authorizedPeers.size()) return false;
  for (uint32_t index = 0; index < lhs.authorizedPeers.size(); ++index)
    if (lhs.authorizedPeers[index] != rhs.authorizedPeers[index]) return false;
  return true;
}

// Applies the public peer projection received over an already authenticated
// control stream. The sender never receives or replaces this node's secret.
static inline bool prodigyApplyTransportCredentialPeerProjection(
    const ProdigyTransportCredentialBootstrap& current,
    const ProdigyTransportCredentialBootstrap& projection,
    ProdigyTransportCredentialBootstrap& output)
{
  if (!prodigyTransportCredentialBootstrapValid(current) ||
      !prodigyTransportCredentialBootstrapValid(projection, false) ||
      projection.self.operationUUID != current.self.operationUUID ||
      projection.self.nodeUUID != current.self.nodeUUID ||
      projection.self.clusterUUID != current.self.clusterUUID ||
      projection.self.authorityEpoch != current.self.authorityEpoch ||
      projection.self.keyEpoch != current.self.keyEpoch ||
      projection.self.authorityGeneration != current.self.authorityGeneration ||
      projection.self.rootAuthorityGeneration != current.self.rootAuthorityGeneration ||
      projection.self.role != current.self.role) return false;
  if (projection.committedAuthorityGeneration < current.committedAuthorityGeneration) return false;
  if (projection.committedAuthorityGeneration == current.committedAuthorityGeneration)
  {
    ProdigyTransportCredentialBootstrap publicCurrent = current;
    OPENSSL_cleanse(publicCurrent.self.secret, sizeof(publicCurrent.self.secret));
    return prodigyTransportCredentialBootstrapSameProjection(publicCurrent, projection) &&
        ((output = current), true);
  }
  // Preserve the current secret before assigning output, which may alias the
  // current local credential state.
  auto candidate = projection;
  std::memcpy(candidate.self.secret, current.self.secret, sizeof(candidate.self.secret));
  if (!prodigyTransportCredentialBootstrapValid(candidate)) return false;
  output = std::move(candidate);
  return true;
}

static inline bool prodigyResolveTransportCredentialBootstrapPeer(
    const ProdigyTransportCredentialBootstrap& bootstrap,
    const String& claimedPeerPrelude,
    const String& purpose,
    uint8_t outputPSK[ProdigyTransportCredentialAuthorityRootBytes],
    String& canonicalContext,
    uint128_t& peerUUID)
{
  peerUUID = 0;
  if (outputPSK == nullptr) { canonicalContext = {}; return false; }
  OPENSSL_cleanse(outputPSK, ProdigyTransportCredentialAuthorityRootBytes);
  canonicalContext = {};
  ProdigyTransportCredentialPrelude prelude = {};
  ProdigyTransportCredentialEnrollment peer = {};
  if (!prodigyParseTransportCredentialPrelude(claimedPeerPrelude, prelude) ||
      !bootstrap.resolvePeer(prelude, peer) ||
      !prodigyDeriveTransportCredentialPSK(bootstrap.self, peer.operationUUID, peer.nodeUUID,
                                            peer.role, purpose, canonicalContext, outputPSK)) return false;
  peerUUID = peer.nodeUUID;
  return true;
}

// Brain-side resolver: the authority root derives only the deterministic
// session subject (the Neuron for Brain↔Neuron, lower UUID for Brain↔Brain).
// Thus it obtains the identical node credential held by the other endpoint.
static inline bool prodigyResolveBrainTransportCredentialPeer(
    const ProdigyTransportCredentialAuthorityRoot& authority,
    const Vector<ProdigyTransportCredentialEnrollment>& ledger,
    uint128_t localNodeUUID, ProdigyTransportCredentialNodeRole localRole,
    const String& claimedPeerPrelude, const String& purpose,
    uint8_t outputPSK[ProdigyTransportCredentialAuthorityRootBytes], String& canonicalContext,
    uint128_t& peerUUID)
{
  peerUUID = 0; canonicalContext = {};
  if (outputPSK == nullptr) return false;
  OPENSSL_cleanse(outputPSK, ProdigyTransportCredentialAuthorityRootBytes);
  ProdigyTransportCredentialPrelude prelude = {};
  if (!authority.valid() || !prodigyParseTransportCredentialPrelude(claimedPeerPrelude, prelude)) return false;
  const ProdigyTransportCredentialEnrollment *local = nullptr, *peer = nullptr;
  for (const auto& enrollment : ledger) {
    if (enrollment.state != ProdigyTransportCredentialEnrollmentState::active) continue;
    if (enrollment.nodeUUID == localNodeUUID && enrollment.role == localRole) {
      if (local != nullptr) return false;
      local = &enrollment;
    }
    if (prodigyTransportCredentialPreludeMatches(prelude, enrollment)) {
      if (peer != nullptr) return false;
      peer = &enrollment;
    }
  }
  if (local == nullptr || peer == nullptr || local->clusterUUID != peer->clusterUUID || (local->nodeUUID == peer->nodeUUID && local->role == peer->role) ||
      local->authorityEpoch != peer->authorityEpoch || local->keyEpoch != peer->keyEpoch) return false;
  const ProdigyTransportCredentialEnrollment *subject = local;
  const ProdigyTransportCredentialEnrollment *other = peer;
  if (localRole == ProdigyTransportCredentialNodeRole::brain && peer->role == ProdigyTransportCredentialNodeRole::neuron) { subject = peer; other = local; }
  else if (localRole == ProdigyTransportCredentialNodeRole::brain && peer->role == ProdigyTransportCredentialNodeRole::brain && peer->nodeUUID < local->nodeUUID) { subject = peer; other = local; }
  else if (localRole != ProdigyTransportCredentialNodeRole::neuron && peer->role != ProdigyTransportCredentialNodeRole::brain) return false;
  ProdigyTransportNodeCredential credential = {};
  if (!prodigyDeriveTransportNodeCredential(authority, *subject, credential) ||
      !prodigyDeriveTransportCredentialPSK(credential, other->operationUUID, other->nodeUUID, other->role,
                                            purpose, canonicalContext, outputPSK)) return false;
  peerUUID = peer->nodeUUID;
  return true;
}

static inline void prodigyTransportCredentialAppendU64(String& bytes, uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8) bytes.append(char((value >> shift) & 0xff));
}

static inline void prodigyTransportCredentialAppendU128(String& bytes, uint128_t value)
{
  for (int shift = 120; shift >= 0; shift -= 8) bytes.append(char((value >> shift) & 0xff));
}

static inline bool prodigyDeriveTransportCredentialHKDF(const uint8_t input[32], const String& info, uint8_t output[32])
{
  constexpr uint8_t salt[] = "prodigy/internal-aegis128l/hkdf-sha256/v1";
  if (input == nullptr || output == nullptr || info.empty()) return false;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  size_t length = ProdigyTransportCredentialAuthorityRootBytes;
  const bool ok = ctx != nullptr && EVP_PKEY_derive_init(ctx) > 0 &&
      EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt) - 1) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_key(ctx, input, ProdigyTransportCredentialAuthorityRootBytes) > 0 &&
      EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const uint8_t *>(info.data()), info.size()) > 0 &&
      EVP_PKEY_derive(ctx, output, &length) > 0 && length == ProdigyTransportCredentialAuthorityRootBytes;
  if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
  if (!ok) OPENSSL_cleanse(output, ProdigyTransportCredentialAuthorityRootBytes);
  return ok;
}

static inline bool prodigyDeriveTransportNodeCredential(
    const ProdigyTransportCredentialAuthorityRoot& authority,
    const ProdigyTransportCredentialEnrollment& enrollment,
    ProdigyTransportNodeCredential& output)
{
  OPENSSL_cleanse(output.secret, sizeof(output.secret));
  output = {};
  if (!authority.valid() || !enrollment.valid() ||
      authority.authorityEpoch != enrollment.authorityEpoch ||
      authority.keyEpoch != enrollment.keyEpoch ||
      authority.authorityGeneration > enrollment.authorityGeneration ||
      enrollment.state != ProdigyTransportCredentialEnrollmentState::active) return false;
  String info = {};
  constexpr char label[] = "prodigy/internal-aegis128l/node-credential/v1";
  info.append(label, sizeof(label) - 1);
  prodigyTransportCredentialAppendU128(info, enrollment.clusterUUID);
  prodigyTransportCredentialAppendU128(info, enrollment.nodeUUID);
  prodigyTransportCredentialAppendU128(info, enrollment.operationUUID);
  prodigyTransportCredentialAppendU64(info, enrollment.authorityEpoch);
  prodigyTransportCredentialAppendU64(info, enrollment.keyEpoch);
  prodigyTransportCredentialAppendU64(info, enrollment.authorityGeneration);
  prodigyTransportCredentialAppendU64(info, authority.authorityGeneration);
  info.append(char(enrollment.role));
  const bool ok = prodigyDeriveTransportCredentialHKDF(authority.root, info, output.secret);
  OPENSSL_cleanse(info.data(), size_t(info.reservedBytes()));
  if (!ok) return false;
  output.operationUUID = enrollment.operationUUID;
  output.nodeUUID = enrollment.nodeUUID;
  output.clusterUUID = enrollment.clusterUUID;
  output.authorityEpoch = enrollment.authorityEpoch;
  output.keyEpoch = enrollment.keyEpoch;
  output.authorityGeneration = enrollment.authorityGeneration;
  output.rootAuthorityGeneration = authority.authorityGeneration;
  output.role = enrollment.role;
  return true;
}

// Produce the bytes consumed by ProdigyAegisSession::begin().  `peer` is a
// public identity and purpose context, while `self` remains fixed by the
// credential itself. Ordering identities means both endpoints derive exactly
// the same PSK and canonical prologue without a directional convention.
static inline bool prodigyDeriveTransportCredentialPSK(
    const ProdigyTransportNodeCredential& self,
    uint128_t peerOperationUUID,
    uint128_t peerNodeUUID,
    ProdigyTransportCredentialNodeRole peerRole,
    const String& purpose,
    String& canonicalContext,
    uint8_t output[ProdigyTransportCredentialAuthorityRootBytes])
{
  canonicalContext = {};
  if (output == nullptr) return false;
  OPENSSL_cleanse(output, ProdigyTransportCredentialAuthorityRootBytes);
  if (!self.valid() || peerOperationUUID == 0 || peerNodeUUID == 0 || purpose.empty() ||
      (peerRole != ProdigyTransportCredentialNodeRole::brain && peerRole != ProdigyTransportCredentialNodeRole::neuron)) return false;
  uint128_t firstNode = self.nodeUUID, secondNode = peerNodeUUID;
  uint8_t firstRole = uint8_t(self.role), secondRole = uint8_t(peerRole);
  const bool reverseIdentityOrder = secondNode < firstNode || (secondNode == firstNode && secondRole < firstRole);
  if (reverseIdentityOrder)
  {
    std::swap(firstNode, secondNode); std::swap(firstRole, secondRole);
  }
  constexpr char label[] = "prodigy/internal-aegis128l/peer-psk/v1";
  String context = {};
  if (!context.reserve(sizeof(label) - 1 + 16 * 5 + 2 + 8 * 5 + purpose.size())) return false;
  context.append(label, sizeof(label) - 1);
  prodigyTransportCredentialAppendU128(context, self.clusterUUID);
  // Both operation identities make a rotate/revoke replacement distinct even
  // when it reuses a machine UUID and key epoch.
  uint128_t firstOperation = self.operationUUID, secondOperation = peerOperationUUID;
  if (reverseIdentityOrder) std::swap(firstOperation, secondOperation);
  prodigyTransportCredentialAppendU128(context, firstOperation);
  prodigyTransportCredentialAppendU128(context, firstNode);
  context.append(char(firstRole));
  prodigyTransportCredentialAppendU128(context, secondOperation);
  prodigyTransportCredentialAppendU128(context, secondNode);
  context.append(char(secondRole));
  prodigyTransportCredentialAppendU64(context, self.authorityEpoch);
  prodigyTransportCredentialAppendU64(context, self.keyEpoch);
  prodigyTransportCredentialAppendU64(context, self.authorityGeneration);
  prodigyTransportCredentialAppendU64(context, self.rootAuthorityGeneration);
  prodigyTransportCredentialAppendU64(context, purpose.size());
  context.append(purpose);
  canonicalContext = std::move(context);
  return prodigyDeriveTransportCredentialHKDF(self.secret, canonicalContext, output);
}

template <typename S>
static void serialize(S&& serializer, ProdigyTransportCredentialEnrollment& enrollment)
{
  serializer.value16b(enrollment.operationUUID);
  serializer.value16b(enrollment.nodeUUID);
  serializer.value16b(enrollment.clusterUUID);
  serializer.value8b(enrollment.authorityEpoch);
  serializer.value8b(enrollment.keyEpoch);
  serializer.value8b(enrollment.authorityGeneration);
  uint8_t role = uint8_t(enrollment.role);
  uint8_t state = uint8_t(enrollment.state);
  serializer.value1b(role);
  serializer.value1b(state);
  enrollment.role = ProdigyTransportCredentialNodeRole(role);
  enrollment.state = ProdigyTransportCredentialEnrollmentState(state);
}

template <typename S>
static void serialize(S&& serializer, ProdigyTransportCredentialEnrollmentOperation& operation)
{
  serializer.object(operation.enrollment);
  serializer.container(operation.electorate, 4096, [](auto& nested, uint128_t& voter) { nested.value16b(voter); });
  serializer.value8b(operation.pinnedMasterAuthorityEpoch);
  serializer.value8b(operation.transitionGeneration);
  uint8_t phase = uint8_t(operation.phase);
  serializer.value1b(phase);
  operation.phase = ProdigyTransportCredentialEnrollmentOperationPhase(phase);
}

template <typename S>
static void serialize(S&& serializer, ProdigyTransportCredentialAuthorityRoot& root)
{
  serializer.value8b(root.authorityEpoch);
  serializer.value8b(root.keyEpoch);
  serializer.value8b(root.authorityGeneration);
  for (uint8_t& byte : root.root) serializer.value1b(byte);
}
