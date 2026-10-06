#pragma once

// Cluster-pair root derivation.  Enrollment owns generation, persistence,
// distribution, epoch advancement, and revocation; this file only provides
// deterministic, domain-separated provisioning/authentication material from an
// already-installed pair root. It performs no authorization or handshake. In
// particular, it must never generate X25519 private keys or replace the fresh
// ephemeral agreement required for forward-secret session traffic keys.

#include <array>
#include <cstdint>
#include <cstring>
#include <utility>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <prodigy/cousin.route.h>
#include <prodigy/cluster.pair.codec.h>

enum class ClusterPairKeyPurpose : uint8_t {
  servicePairingBase = 1,
  switchboardAdmissionControl = 2,
  pairControl = 3,
  serviceSessionAuthentication = 4,
};

enum class ClusterPairKeyScope : uint8_t { serviceRoute = 1, pairControl = 2, nodeRoleCredential = 3, pairControlEndpoint = 4 };

struct ClusterPairRoot {
  uint128_t pairUUID = 0;
  uint128_t firstClusterUUID = 0;
  uint128_t secondClusterUUID = 0;
  uint64_t rootGeneration = 0;
  std::array<uint8_t, 32> root = {};
  ClusterPairRoot() = default;
  ClusterPairRoot(const ClusterPairRoot&) = delete;
  ClusterPairRoot& operator=(const ClusterPairRoot&) = delete;
  ClusterPairRoot(ClusterPairRoot&& other) noexcept { *this = std::move(other); }
  ClusterPairRoot& operator=(ClusterPairRoot&& other) noexcept
  {
    if (this != &other)
    {
      clear();
      pairUUID = other.pairUUID;
      firstClusterUUID = other.firstClusterUUID;
      secondClusterUUID = other.secondClusterUUID;
      rootGeneration = other.rootGeneration;
      root = other.root;
      other.clear();
    }
    return *this;
  }
  void clear()
  {
    OPENSSL_cleanse(root.data(), root.size());
    pairUUID = 0;
    firstClusterUUID = 0;
    secondClusterUUID = 0;
    rootGeneration = 0;
  }
  ~ClusterPairRoot() { clear(); }
};

struct ClusterPairKeyContext {
  ClusterPairKeyScope scope = ClusterPairKeyScope::serviceRoute;
  uint128_t logicalWorkloadUUID = 0;
  uint128_t logicalServiceUUID = 0;
  CousinRouteSlotBitmap slots = {};
  uint64_t keyEpoch = 0;
  ClusterPairKeyPurpose purpose = ClusterPairKeyPurpose::servicePairingBase;
  uint128_t senderClusterUUID = 0;
  uint128_t receiverClusterUUID = 0;
  uint128_t senderNodeUUID = 0;
  uint128_t receiverNodeUUID = 0;
  uint64_t senderRole = 0;
  uint64_t receiverRole = 0;
  String channelIdentity = {};
};

struct ClusterPairDerivedKey {
  std::array<uint8_t, 32> bytes = {};
  uint32_t size = 0;
  ClusterPairDerivedKey() = default;
  ClusterPairDerivedKey(const ClusterPairDerivedKey&) = delete;
  ClusterPairDerivedKey& operator=(const ClusterPairDerivedKey&) = delete;
  ClusterPairDerivedKey(ClusterPairDerivedKey&& other) noexcept { *this = std::move(other); }
  ClusterPairDerivedKey& operator=(ClusterPairDerivedKey&& other) noexcept
  {
    if (this != &other)
    {
      clear();
      bytes = other.bytes;
      size = other.size;
      other.clear();
    }
    return *this;
  }
  void clear()
  {
    OPENSSL_cleanse(bytes.data(), bytes.size());
    size = 0;
  }
  ~ClusterPairDerivedKey() { clear(); }
};

static inline bool clusterPairKeyPurposeValid(ClusterPairKeyPurpose purpose)
{
  return purpose == ClusterPairKeyPurpose::servicePairingBase ||
         purpose == ClusterPairKeyPurpose::switchboardAdmissionControl ||
         purpose == ClusterPairKeyPurpose::pairControl ||
         purpose == ClusterPairKeyPurpose::serviceSessionAuthentication;
}

static inline uint32_t clusterPairKeySize(ClusterPairKeyPurpose purpose)
{
  if (purpose == ClusterPairKeyPurpose::servicePairingBase) return 16;
  return clusterPairKeyPurposeValid(purpose) ? 32 : 0;
}

static inline bool clusterPairRootValid(const ClusterPairRoot& root)
{
  if (root.pairUUID == 0 || root.firstClusterUUID == 0 || root.secondClusterUUID == 0 ||
      root.firstClusterUUID == root.secondClusterUUID || root.rootGeneration == 0)
  {
    return false;
  }
  uint8_t combined = 0;
  for (uint8_t byte : root.root) combined |= byte;
  return combined != 0;
}

static inline bool clusterPairKeyContextValid(const ClusterPairKeyContext& context)
{
  if (context.keyEpoch == 0 || !clusterPairKeyPurposeValid(context.purpose) || context.channelIdentity.empty() || context.channelIdentity.size() > 128 ||
      context.senderClusterUUID == 0 || context.receiverClusterUUID == 0 || context.senderClusterUUID == context.receiverClusterUUID) return false;
  if (context.scope == ClusterPairKeyScope::serviceRoute)
    return context.logicalWorkloadUUID != 0 && context.logicalServiceUUID != 0 && !context.slots.empty() && context.purpose != ClusterPairKeyPurpose::pairControl;
  if (context.scope == ClusterPairKeyScope::pairControl)
    return context.logicalWorkloadUUID == 0 && context.logicalServiceUUID == 0 && context.slots.empty() && context.purpose == ClusterPairKeyPurpose::pairControl &&
           context.senderNodeUUID == 0 && context.receiverNodeUUID == 0 && context.senderRole == 0 && context.receiverRole == 0;
  if (context.scope == ClusterPairKeyScope::nodeRoleCredential)
    return context.logicalWorkloadUUID == 0 && context.logicalServiceUUID == 0 && context.slots.empty() && context.purpose == ClusterPairKeyPurpose::switchboardAdmissionControl &&
           context.senderNodeUUID != 0 && context.receiverNodeUUID != 0 && context.senderRole != 0 && context.receiverRole != 0;
  if (context.scope == ClusterPairKeyScope::pairControlEndpoint)
    return context.logicalWorkloadUUID == 0 && context.logicalServiceUUID == 0 && context.slots.empty() && context.purpose == ClusterPairKeyPurpose::pairControl &&
           context.senderNodeUUID != 0 && context.receiverNodeUUID != 0 && context.senderRole != 0 && context.receiverRole != 0;
  return false;
}



static inline bool clusterPairCanonicalKeyContext(const ClusterPairRoot& root,
                                                     const ClusterPairKeyContext& context,
                                                     String& info)
{
  info.clear();
  if (!clusterPairRootValid(root) || !clusterPairKeyContextValid(context)) return false;
  if (!((context.senderClusterUUID == root.firstClusterUUID || context.senderClusterUUID == root.secondClusterUUID) &&
        (context.receiverClusterUUID == root.firstClusterUUID || context.receiverClusterUUID == root.secondClusterUUID))) return false;
  constexpr unsigned char domain[] = "prodigy/cluster-pair/aegis-key/v1";
  constexpr uint64_t fixedBytes = sizeof(domain) + 3 * 16 + 2 * 8 + 1 + 4 * 16 + 2 * 8 + 2 * 16 +
                                  CousinRouteSlotBitmap::wordCount * 8 + 1 + 8;
  // Build into owned storage: String may hold an immutable literal view, and
  // append otherwise fails silently. Reserve once so allocation failure cannot
  // turn different contexts into the same truncated KDF input.
  String encoded = {};
  const uint64_t expectedBytes = fixedBytes + context.channelIdentity.size();
  if (!encoded.reserve(expectedBytes)) return false;
  encoded.append(domain, sizeof(domain) - 1);
  encoded.append(uint8_t(0));
  clusterPairKeyAppendU128BE(encoded, root.pairUUID);
  const uint128_t firstClusterUUID = root.firstClusterUUID < root.secondClusterUUID ? root.firstClusterUUID : root.secondClusterUUID;
  const uint128_t secondClusterUUID = root.firstClusterUUID < root.secondClusterUUID ? root.secondClusterUUID : root.firstClusterUUID;
  clusterPairKeyAppendU128BE(encoded, firstClusterUUID);
  clusterPairKeyAppendU128BE(encoded, secondClusterUUID);
  clusterPairKeyAppendU64BE(encoded, root.rootGeneration);
  clusterPairKeyAppendU64BE(encoded, context.keyEpoch);
  encoded.append(uint8_t(context.scope));
  clusterPairKeyAppendU128BE(encoded, context.senderClusterUUID);
  clusterPairKeyAppendU128BE(encoded, context.receiverClusterUUID);
  clusterPairKeyAppendU128BE(encoded, context.senderNodeUUID);
  clusterPairKeyAppendU128BE(encoded, context.receiverNodeUUID);
  clusterPairKeyAppendU64BE(encoded, context.senderRole);
  clusterPairKeyAppendU64BE(encoded, context.receiverRole);
  clusterPairKeyAppendU128BE(encoded, context.logicalWorkloadUUID);
  clusterPairKeyAppendU128BE(encoded, context.logicalServiceUUID);
  for (uint64_t word : context.slots.words) clusterPairKeyAppendU64BE(encoded, word);
  encoded.append(uint8_t(context.purpose));
  clusterPairKeyAppendU64BE(encoded, context.channelIdentity.size());
  encoded.append(context.channelIdentity);
  if (encoded.size() != expectedBytes) return false;
  info = std::move(encoded);
  return true;
}

static inline bool clusterPairGenerateRoot(ClusterPairRoot& root)
{
  uint8_t combined = 0;
  for (uint8_t byte : root.root) combined |= byte;
  if (combined != 0) return false;
  if (root.pairUUID == 0 || root.firstClusterUUID == 0 || root.secondClusterUUID == 0 ||
      root.firstClusterUUID == root.secondClusterUUID || root.rootGeneration == 0)
  {
    return false;
  }
  if (root.firstClusterUUID > root.secondClusterUUID)
  {
    uint128_t swap = root.firstClusterUUID;
    root.firstClusterUUID = root.secondClusterUUID;
    root.secondClusterUUID = swap;
  }
  if (RAND_priv_bytes(root.root.data(), int(root.root.size())) != 1 || !clusterPairRootValid(root))
  {
    OPENSSL_cleanse(root.root.data(), root.root.size());
    return false;
  }
  return true;
}

static inline bool clusterPairDeriveKey(const ClusterPairRoot& root,
                                          const ClusterPairKeyContext& context,
                                          ClusterPairDerivedKey& derived)
{
  OPENSSL_cleanse(derived.bytes.data(), derived.bytes.size());
  derived.size = 0;
  String info = {};
  if (!clusterPairCanonicalKeyContext(root, context, info)) return false;
  const uint32_t keySize = clusterPairKeySize(context.purpose);
  constexpr unsigned char salt[] = "prodigy/cluster-pair/hkdf-salt/v1";
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  size_t outputSize = keySize;
  const bool ok = pctx != nullptr &&
      EVP_PKEY_derive_init(pctx) > 0 &&
      EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt) - 1) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_key(pctx, root.root.data(), int(root.root.size())) > 0 &&
      EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), int(info.size())) > 0 &&
      EVP_PKEY_derive(pctx, derived.bytes.data(), &outputSize) > 0 && outputSize == keySize;
  if (pctx != nullptr) EVP_PKEY_CTX_free(pctx);
  if (!ok) { OPENSSL_cleanse(derived.bytes.data(), derived.bytes.size()); derived.size = 0; return false; }
  derived.size = keySize;
  return true;
}
