#pragma once

#include <cstdint>
#include <cstring>
#include <limits.h>

#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <prodigy/biphasal.key.h>
#include <services/prodigy.h>

enum class TlsResumptionKeyRole : uint8_t {
  issueAndAccept = 0,
  acceptOnly = 1
};

constexpr static uint64_t prodigyTlsResumptionTicketLifetimeMs = 24ull * 60ull * 60ull * 1000ull;
constexpr static uint64_t prodigyTlsResumptionRotationPeriodMs = 6ull * 60ull * 60ull * 1000ull;
constexpr static uint64_t prodigyTlsResumptionOverlapMs = 30ull * 60ull * 1000ull;

class TlsResumptionKeyEpoch {
public:

  uint64_t generation = 0;
  TlsResumptionKeyRole role = TlsResumptionKeyRole::acceptOnly;
  uint8_t keyID[16] = {};
  uint8_t masterSecret[32] = {};
  int64_t issueUntilMs = 0;
  int64_t acceptUntilMs = 0;
};

static inline uint8_t prodigyTlsResumptionEpochPhase(const TlsResumptionKeyEpoch& epoch)
{
  return prodigyBiphasalKeyPhase(epoch.masterSecret);
}

static inline void prodigyTlsResumptionForceEpochPhase(TlsResumptionKeyEpoch& epoch, uint8_t phase)
{
  prodigyForceBiphasalKeyPhase(epoch.masterSecret, phase);
}

template <typename S>
static void serialize(S&& serializer, TlsResumptionKeyEpoch& epoch)
{
  serializer.value8b(epoch.generation);
  serializer.value1b(epoch.role);
  for (uint8_t& byte : epoch.keyID)
  {
    serializer.value1b(byte);
  }
  for (uint8_t& byte : epoch.masterSecret)
  {
    serializer.value1b(byte);
  }
  serializer.value8b(epoch.issueUntilMs);
  serializer.value8b(epoch.acceptUntilMs);
}

class TlsResumptionWormholeConfig {
public:

  Vector<String> alpns;
  Vector<String> sniNames;
};

template <typename S>
static void serialize(S&& serializer, TlsResumptionWormholeConfig& config)
{
  serializer.container(config.alpns, UINT32_MAX, [](S& serializer, String& alpn) {
    serializer.text1b(alpn, UINT32_MAX);
  });
  serializer.container(config.sniNames, UINT32_MAX, [](S& serializer, String& sni) {
    serializer.text1b(sni, UINT32_MAX);
  });
}

class TlsResumptionSnapshot {
public:

  uint64_t generation = 0;
  String wormholeName;
  Vector<TlsResumptionKeyEpoch> keyRing;
};

template <typename S>
static void serialize(S&& serializer, TlsResumptionSnapshot& snapshot)
{
  serializer.value8b(snapshot.generation);
  serializer.text1b(snapshot.wormholeName, UINT32_MAX);
  serializer.object(snapshot.keyRing);
}

static inline bool prodigyTlsResumptionKeyEpochsEqual(const TlsResumptionKeyEpoch& lhs, const TlsResumptionKeyEpoch& rhs)
{
  return lhs.generation == rhs.generation &&
         lhs.role == rhs.role &&
         std::memcmp(lhs.keyID, rhs.keyID, sizeof(lhs.keyID)) == 0 &&
         std::memcmp(lhs.masterSecret, rhs.masterSecret, sizeof(lhs.masterSecret)) == 0 &&
         lhs.issueUntilMs == rhs.issueUntilMs &&
         lhs.acceptUntilMs == rhs.acceptUntilMs;
}

static inline bool prodigyTlsResumptionSnapshotsEqual(const TlsResumptionSnapshot& lhs, const TlsResumptionSnapshot& rhs)
{
  if (lhs.generation != rhs.generation ||
      lhs.wormholeName.equal(rhs.wormholeName) == false ||
      lhs.keyRing.size() != rhs.keyRing.size())
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.keyRing.size(); index += 1)
  {
    if (prodigyTlsResumptionKeyEpochsEqual(lhs.keyRing[index], rhs.keyRing[index]) == false)
    {
      return false;
    }
  }

  return true;
}

class TlsResumptionApplyResult {
public:

  String wormholeName;
  uint64_t generation = 0;
  bool success = false;
  String failureReason;
};

template <typename S>
static void serialize(S&& serializer, TlsResumptionApplyResult& result)
{
  serializer.text1b(result.wormholeName, UINT32_MAX);
  serializer.value8b(result.generation);
  serializer.value1b(result.success);
  serializer.text1b(result.failureReason, UINT32_MAX);
}

static inline void prodigyTlsResumptionAssignFailure(String *failure, const char *reason)
{
  if (failure)
  {
    failure->assign(reason);
  }
}

static inline bool prodigyTlsResumptionHmacSha256(
    const uint8_t *key,
    uint64_t keySize,
    const uint8_t *data,
    uint64_t dataSize,
    uint8_t digest[32])
{
  if (key == nullptr || digest == nullptr || keySize > INT_MAX)
  {
    return false;
  }

  static const uint8_t empty = 0;
  const uint8_t *dataPtr = (dataSize > 0 && data != nullptr) ? data : &empty;
  unsigned int digestLength = 0;
  return HMAC(
             EVP_sha256(),
             key,
             int(keySize),
             dataPtr,
             size_t(dataSize),
             digest,
             &digestLength) != nullptr &&
         digestLength == 32;
}

static inline bool prodigyTlsResumptionDeriveAeadKey(
    const TlsResumptionKeyEpoch& epoch,
    const char *label,
    uint8_t key[32],
    String *failure = nullptr)
{
  if (label == nullptr)
  {
    prodigyTlsResumptionAssignFailure(failure, "ticket key label required");
    return false;
  }

  constexpr static uint8_t salt[] = "prodigy/tls-resumption-hkdf-salt/v1";
  uint8_t prk[32] = {};
  if (prodigyTlsResumptionHmacSha256(
          salt,
          sizeof(salt) - 1,
          epoch.masterSecret,
          sizeof(epoch.masterSecret),
          prk) == false)
  {
    prodigyTlsResumptionAssignFailure(failure, "ticket HKDF extract failed");
    return false;
  }

  String info;
  info.append(reinterpret_cast<const uint8_t *>(label), std::strlen(label));
  uint8_t counter = 1;
  info.append(&counter, 1);

  bool ok = prodigyTlsResumptionHmacSha256(prk, sizeof(prk), info.data(), info.size(), key);
  OPENSSL_cleanse(prk, sizeof(prk));
  if (ok == false)
  {
    prodigyTlsResumptionAssignFailure(failure, "ticket HKDF expand failed");
    return false;
  }

  return true;
}

static inline bool prodigyTlsResumptionDeriveOpenSSLTicketKeys(
    const TlsResumptionKeyEpoch& epoch,
    uint8_t cipherKey[32],
    uint8_t macKey[32],
    String *failure = nullptr)
{
  if (prodigyTlsResumptionDeriveAeadKey(epoch, "prodigy/tls13/openssl-ticket-cipher/v1", cipherKey, failure) == false)
  {
    return false;
  }

  if (prodigyTlsResumptionDeriveAeadKey(epoch, "prodigy/tls13/openssl-ticket-hmac/v1", macKey, failure) == false)
  {
    OPENSSL_cleanse(cipherKey, 32);
    return false;
  }

  return true;
}

static inline bool prodigyTlsResumptionDeriveQuicTicketKey(
    const TlsResumptionKeyEpoch& epoch,
    uint8_t key[32],
    String *failure = nullptr)
{
  return prodigyTlsResumptionDeriveAeadKey(epoch, "prodigy/quic/ticket-aead/v1", key, failure);
}

class ProdigyResumptionRegistry {
public:

  using SnapshotMap = bytell_hash_map_with_policy<String, TlsResumptionSnapshot, Hasher::SeedPolicy::global_shared>;

  SnapshotMap snapshotsByWormhole;

  static bool bytesAllZero(const uint8_t *bytes, size_t size)
  {
    for (size_t index = 0; index < size; index += 1)
    {
      if (bytes[index] != 0)
      {
        return false;
      }
    }

    return true;
  }

  static bool validateSnapshot(const TlsResumptionSnapshot& snapshot, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }

    auto fail = [&](const char *reason) -> bool {
      if (failure)
      {
        failure->assign(reason);
      }
      return false;
    };

    if (snapshot.wormholeName.size() == 0)
    {
      return fail("wormholeName required");
    }
    if (snapshot.generation == 0)
    {
      return fail("generation required");
    }
    if (snapshot.keyRing.size() == 0)
    {
      return fail("keyRing required");
    }

    uint32_t issueCapableCount = 0;
    for (const TlsResumptionKeyEpoch& epoch : snapshot.keyRing)
    {
      if (epoch.generation == 0)
      {
        return fail("epoch generation required");
      }
      if (bytesAllZero(epoch.keyID, sizeof(epoch.keyID)))
      {
        return fail("epoch keyID required");
      }
      if (bytesAllZero(epoch.masterSecret, sizeof(epoch.masterSecret)))
      {
        return fail("epoch master secret required");
      }
      if (epoch.acceptUntilMs <= 0)
      {
        return fail("epoch accept window invalid");
      }
      if (epoch.role == TlsResumptionKeyRole::issueAndAccept)
      {
        issueCapableCount += 1;
        if (epoch.issueUntilMs <= 0)
        {
          return fail("epoch issue window invalid");
        }
      }
    }

    if (issueCapableCount > 1)
    {
      return fail("multiple issue-capable epochs");
    }

    return true;
  }

  static void buildApplyResult(const TlsResumptionSnapshot& snapshot, bool success, const String& failureReason, TlsResumptionApplyResult& result)
  {
    result = {};
    result.wormholeName = snapshot.wormholeName;
    result.generation = snapshot.generation;
    result.success = success;
    result.failureReason = failureReason;
  }

  bool applySnapshot(const TlsResumptionSnapshot& snapshot, TlsResumptionApplyResult *result = nullptr)
  {
    String failure = {};
    if (validateSnapshot(snapshot, &failure) == false)
    {
      if (result)
      {
        buildApplyResult(snapshot, false, failure, *result);
      }
      return false;
    }

    if (auto existing = snapshotsByWormhole.find(snapshot.wormholeName); existing != snapshotsByWormhole.end())
    {
      if (snapshot.generation < existing->second.generation)
      {
        failure.assign("stale generation"_ctv);
        if (result)
        {
          buildApplyResult(snapshot, false, failure, *result);
        }
        return false;
      }
    }

    snapshotsByWormhole.insert_or_assign(snapshot.wormholeName, snapshot);
    if (result)
    {
      buildApplyResult(snapshot, true, failure, *result);
    }
    return true;
  }

  bool removeWormhole(const String& wormholeName, uint64_t generation, TlsResumptionApplyResult *result = nullptr)
  {
    snapshotsByWormhole.erase(wormholeName);
    if (result)
    {
      result->wormholeName = wormholeName;
      result->generation = generation;
      result->success = true;
      result->failureReason.clear();
    }
    return true;
  }

  bool applyDelta(
      const Vector<TlsResumptionSnapshot>& updatedSnapshots,
      const Vector<String>& removedWormholeNames,
      uint64_t generation,
      Vector<TlsResumptionApplyResult> *results = nullptr)
  {
    bool ok = true;
    if (results)
    {
      results->clear();
    }

    for (const TlsResumptionSnapshot& snapshot : updatedSnapshots)
    {
      TlsResumptionApplyResult result = {};
      bool applied = applySnapshot(snapshot, results ? &result : nullptr);
      ok = applied && ok;
      if (results)
      {
        results->push_back(result);
      }
    }

    for (const String& wormholeName : removedWormholeNames)
    {
      TlsResumptionApplyResult result = {};
      bool removed = removeWormhole(wormholeName, generation, results ? &result : nullptr);
      ok = removed && ok;
      if (results)
      {
        results->push_back(result);
      }
    }

    return ok;
  }

  const TlsResumptionSnapshot *find(const String& wormholeName) const
  {
    auto it = snapshotsByWormhole.find(wormholeName);
    if (it == snapshotsByWormhole.end())
    {
      return nullptr;
    }

    return &it->second;
  }

  const TlsResumptionKeyEpoch *currentIssueKey(const String& wormholeName, int64_t nowMs) const
  {
    const TlsResumptionSnapshot *snapshot = find(wormholeName);
    if (snapshot == nullptr)
    {
      return nullptr;
    }

    for (const TlsResumptionKeyEpoch& epoch : snapshot->keyRing)
    {
      if (epoch.role == TlsResumptionKeyRole::issueAndAccept &&
          (nowMs == 0 || (nowMs < epoch.issueUntilMs && nowMs < epoch.acceptUntilMs)))
      {
        return &epoch;
      }
    }

    return nullptr;
  }

  const TlsResumptionKeyEpoch *acceptKeyByID(const String& wormholeName, const uint8_t keyID[16], int64_t nowMs) const
  {
    const TlsResumptionSnapshot *snapshot = find(wormholeName);
    if (snapshot == nullptr)
    {
      return nullptr;
    }

    for (const TlsResumptionKeyEpoch& epoch : snapshot->keyRing)
    {
      if (std::memcmp(epoch.keyID, keyID, sizeof(epoch.keyID)) == 0 &&
          (epoch.role == TlsResumptionKeyRole::issueAndAccept || epoch.role == TlsResumptionKeyRole::acceptOnly) &&
          (nowMs == 0 || nowMs < epoch.acceptUntilMs))
      {
        return &epoch;
      }
    }

    return nullptr;
  }
};

class ProdigyOpenSSLTlsTicketBinding {
public:

  String wormholeName;
  int64_t nowMs = 0;

  bool configured(void) const
  {
    return wormholeName.size() > 0;
  }
};

class ProdigyOpenSSLTlsTicketContext {
public:

  ProdigyResumptionRegistry *registry = nullptr;
  int64_t (*nowMsCallback)(void *arg) = nullptr;
  void *nowMsCallbackArg = nullptr;
  uint64_t renewBeforeMs = 0;
  uint64_t issuedTickets = 0;
  uint64_t acceptedTickets = 0;
  uint64_t renewedTickets = 0;
  uint64_t fallbackTickets = 0;
  uint64_t failedTickets = 0;

  int64_t nowMs(void) const
  {
    if (nowMsCallback)
    {
      return nowMsCallback(nowMsCallbackArg);
    }

    return 0;
  }
};

static inline int prodigyOpenSSLTlsTicketContextIndex(void)
{
  static int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}

static inline int prodigyOpenSSLTlsTicketBindingIndex(void)
{
  static int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}

static inline ProdigyOpenSSLTlsTicketContext *prodigyOpenSSLTlsTicketContextForSSL(SSL *ssl)
{
  if (ssl == nullptr)
  {
    return nullptr;
  }

  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  int index = prodigyOpenSSLTlsTicketContextIndex();
  if (ctx == nullptr || index < 0)
  {
    return nullptr;
  }

  return reinterpret_cast<ProdigyOpenSSLTlsTicketContext *>(SSL_CTX_get_ex_data(ctx, index));
}

static inline ProdigyOpenSSLTlsTicketBinding *prodigyOpenSSLTlsTicketBindingForSSL(SSL *ssl)
{
  int index = prodigyOpenSSLTlsTicketBindingIndex();
  if (ssl == nullptr || index < 0)
  {
    return nullptr;
  }

  return reinterpret_cast<ProdigyOpenSSLTlsTicketBinding *>(SSL_get_ex_data(ssl, index));
}

static inline bool prodigyOpenSSLTlsTicketInitHmac(EVP_MAC_CTX *ctx, const uint8_t key[32])
{
  OSSL_PARAM params[2] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>("SHA256"), 0),
      OSSL_PARAM_construct_end(),
  };
  return EVP_MAC_init(ctx, key, 32, params) == 1;
}

static inline bool prodigyOpenSSLTlsTicketInitCrypto(
    const TlsResumptionKeyEpoch& epoch,
    unsigned char *iv,
    EVP_CIPHER_CTX *cipherCtx,
    EVP_MAC_CTX *macCtx,
    bool encrypt,
    String *failure = nullptr)
{
  uint8_t cipherKey[32] = {};
  uint8_t macKey[32] = {};
  if (prodigyTlsResumptionDeriveOpenSSLTicketKeys(epoch, cipherKey, macKey, failure) == false)
  {
    return false;
  }

  bool ok = (encrypt ? EVP_EncryptInit_ex(cipherCtx, EVP_aes_256_cbc(), nullptr, cipherKey, iv)
                     : EVP_DecryptInit_ex(cipherCtx, EVP_aes_256_cbc(), nullptr, cipherKey, iv)) == 1 &&
            prodigyOpenSSLTlsTicketInitHmac(macCtx, macKey);
  OPENSSL_cleanse(cipherKey, sizeof(cipherKey));
  OPENSSL_cleanse(macKey, sizeof(macKey));
  if (ok == false)
  {
    prodigyTlsResumptionAssignFailure(failure, "OpenSSL ticket crypto initialization failed");
  }

  return ok;
}

static inline int prodigyOpenSSLTlsTicketKeyCallback(
    SSL *ssl,
    unsigned char keyName[16],
    unsigned char *iv,
    EVP_CIPHER_CTX *cipherCtx,
    EVP_MAC_CTX *macCtx,
    int encrypt)
{
  if (ssl == nullptr || keyName == nullptr || iv == nullptr || cipherCtx == nullptr || macCtx == nullptr)
  {
    return -1;
  }

  ProdigyOpenSSLTlsTicketContext *context = prodigyOpenSSLTlsTicketContextForSSL(ssl);
  if (context == nullptr || context->registry == nullptr)
  {
    return 0;
  }

  ProdigyOpenSSLTlsTicketBinding *binding = prodigyOpenSSLTlsTicketBindingForSSL(ssl);
  if (binding == nullptr || binding->configured() == false)
  {
    context->fallbackTickets += 1;
    return 0;
  }

  const int64_t nowMs = binding->nowMs > 0 ? binding->nowMs : context->nowMs();
  if (encrypt)
  {
    const TlsResumptionKeyEpoch *epoch = context->registry->currentIssueKey(
        binding->wormholeName,
        nowMs);
    if (epoch == nullptr)
    {
      context->fallbackTickets += 1;
      return 0;
    }

    int ivLength = EVP_CIPHER_get_iv_length(EVP_aes_256_cbc());
    if (ivLength <= 0 || ivLength > EVP_MAX_IV_LENGTH || RAND_bytes(iv, ivLength) != 1)
    {
      context->failedTickets += 1;
      return -1;
    }

    std::memcpy(keyName, epoch->keyID, sizeof(epoch->keyID));
    String failure = {};
    if (prodigyOpenSSLTlsTicketInitCrypto(*epoch, iv, cipherCtx, macCtx, true, &failure) == false)
    {
      (void)failure;
      context->failedTickets += 1;
      return -1;
    }

    context->issuedTickets += 1;
    return 1;
  }

  const TlsResumptionKeyEpoch *epoch = context->registry->acceptKeyByID(
      binding->wormholeName,
      keyName,
      nowMs);
  if (epoch == nullptr)
  {
    context->fallbackTickets += 1;
    return 0;
  }

  String failure = {};
  if (prodigyOpenSSLTlsTicketInitCrypto(*epoch, iv, cipherCtx, macCtx, false, &failure) == false)
  {
    (void)failure;
    context->failedTickets += 1;
    return -1;
  }

  const bool shouldRenew =
      epoch->role == TlsResumptionKeyRole::acceptOnly ||
      (context->renewBeforeMs > 0 &&
       epoch->acceptUntilMs > 0 &&
       nowMs >= 0 &&
       uint64_t(nowMs) + context->renewBeforeMs >= uint64_t(epoch->acceptUntilMs));
  if (shouldRenew)
  {
    context->renewedTickets += 1;
    return 2;
  }

  context->acceptedTickets += 1;
  return 1;
}

static inline bool prodigyInstallOpenSSLTlsResumptionTicketKeyCallback(
    SSL_CTX *ctx,
    ProdigyOpenSSLTlsTicketContext *ticketContext,
    String *failure = nullptr)
{
  if (failure)
  {
    failure->clear();
  }
  if (ctx == nullptr || ticketContext == nullptr || ticketContext->registry == nullptr)
  {
    prodigyTlsResumptionAssignFailure(failure, "OpenSSL ticket context and registry required");
    return false;
  }

  int index = prodigyOpenSSLTlsTicketContextIndex();
  if (index < 0 || SSL_CTX_set_ex_data(ctx, index, ticketContext) != 1)
  {
    prodigyTlsResumptionAssignFailure(failure, "failed to attach OpenSSL ticket context");
    return false;
  }

  if (SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, prodigyOpenSSLTlsTicketKeyCallback) != 1)
  {
    prodigyTlsResumptionAssignFailure(failure, "failed to install OpenSSL ticket key callback");
    return false;
  }

  return true;
}

static inline bool prodigyBindOpenSSLTlsResumptionTicketContext(
    SSL *ssl,
    ProdigyOpenSSLTlsTicketBinding *binding,
    String *failure = nullptr)
{
  if (failure)
  {
    failure->clear();
  }
  if (ssl == nullptr || binding == nullptr || binding->configured() == false)
  {
    prodigyTlsResumptionAssignFailure(failure, "OpenSSL ticket binding incomplete");
    return false;
  }

  int index = prodigyOpenSSLTlsTicketBindingIndex();
  if (index < 0 || SSL_set_ex_data(ssl, index, binding) != 1)
  {
    prodigyTlsResumptionAssignFailure(failure, "failed to attach OpenSSL ticket binding");
    return false;
  }

  return true;
}
