#pragma once

#include <cstdint>
#include <networking/includes.h>
#include <openssl/evp.h>

static inline void prodigyAppendHexByte(String& digest, uint8_t value)
{
  constexpr static char hex[] = "0123456789abcdef";
  digest.append(hex[value >> 4]);
  digest.append(hex[value & 0x0F]);
}

static inline bool prodigyComputeSHA256Hex(const uint8_t *data, uint64_t size,
                                           String& digest, String *failure = nullptr)
{
  digest.clear();
  if (failure) failure->clear();
  if (data == nullptr && size > 0)
  {
    if (failure) failure->assign("sha256 source buffer is null"_ctv);
    return false;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == nullptr)
  {
    if (failure) failure->assign("EVP_MD_CTX_new failed"_ctv);
    return false;
  }
  bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
  if (!ok && failure) failure->assign("EVP_DigestInit_ex failed"_ctv);
  if (ok && size > 0 && EVP_DigestUpdate(ctx, data, size_t(size)) != 1)
  {
    ok = false;
    if (failure) failure->assign("EVP_DigestUpdate failed"_ctv);
  }
  uint8_t rawDigest[EVP_MAX_MD_SIZE] = {};
  unsigned int rawDigestSize = 0;
  if (ok && EVP_DigestFinal_ex(ctx, rawDigest, &rawDigestSize) != 1)
  {
    ok = false;
    if (failure) failure->assign("EVP_DigestFinal_ex failed"_ctv);
  }
  EVP_MD_CTX_free(ctx);
  if (!ok || rawDigestSize != 32)
  {
    if (ok && failure) failure->snprintf<"unexpected sha256 size: {}"_ctv>(rawDigestSize);
    digest.clear();
    return false;
  }
  digest.reserve(64);
  for (unsigned int index = 0; index < rawDigestSize; ++index)
    prodigyAppendHexByte(digest, rawDigest[index]);
  return true;
}

static inline bool prodigyComputeSHA256Hex(const String& payload, String& digest,
                                           String *failure = nullptr)
{
  return prodigyComputeSHA256Hex(
      reinterpret_cast<const uint8_t *>(payload.data()), payload.size(), digest, failure);
}

static inline bool prodigyIsSHA256HexDigest(const String& digest)
{
  if (digest.size() != 64)
  {
    return false;
  }

  for (uint64_t index = 0; index < digest.size(); ++index)
  {
    unsigned char ch = static_cast<unsigned char>(digest[index]);
    bool isDigit = (ch >= '0' && ch <= '9');
    bool isLowerHex = (ch >= 'a' && ch <= 'f');
    if (isDigit == false && isLowerHex == false)
    {
      return false;
    }
  }

  return true;
}
