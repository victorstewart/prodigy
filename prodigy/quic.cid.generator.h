#pragma once

#include <cstddef>
#include <cstring>
#include <cstdint>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <sys/socket.h>

#include <macros/quic.h>

#include <prodigy/biphasal.key.h>

#include <switchboard/common/quic.cid.h>

struct ProdigyQuicCID {
  constexpr static uint8_t maxLen = 20;

  uint8_t id[maxLen] = {};
  uint8_t id_len = 0;
};

class ProdigyQuicCidEncryptor {
private:

  EVP_CIPHER_CTX *context_ = nullptr;
  uint8_t keyPhase_ = 0;

public:

  ProdigyQuicCidEncryptor() = default;

  ~ProdigyQuicCidEncryptor()
  {
    if (context_ != nullptr)
    {
      EVP_CIPHER_CTX_free(context_);
    }
  }

  ProdigyQuicCidEncryptor(const ProdigyQuicCidEncryptor&) = delete;
  ProdigyQuicCidEncryptor& operator=(const ProdigyQuicCidEncryptor&) = delete;

  bool setKey(const uint8_t key[16])
  {
    if (key == nullptr)
    {
      return false;
    }

    if (context_ == nullptr)
    {
      context_ = EVP_CIPHER_CTX_new();
      if (context_ == nullptr)
      {
        return false;
      }
    }

    if (EVP_EncryptInit_ex2(context_, EVP_aes_128_ecb(), key, nullptr, nullptr) != 1)
    {
      return false;
    }

    keyPhase_ = prodigyBiphasalKeyPhase(key);
    return EVP_CIPHER_CTX_set_padding(context_, 0) == 1;
  }

  uint8_t keyPhase(void) const
  {
    return keyPhase_;
  }

  bool encryptBlock(const uint8_t plaintext[16], uint8_t ciphertext[16])
  {
    if (context_ == nullptr || plaintext == nullptr || ciphertext == nullptr)
    {
      return false;
    }

    int written = 0;
    return EVP_EncryptUpdate(context_, ciphertext, &written, plaintext, 16) == 1 && written == 16;
  }
};

static inline uint32_t prodigyQuicCidLoadBE32(const uint8_t *bytes)
{
  return (uint32_t(bytes[0]) << 24) |
         (uint32_t(bytes[1]) << 16) |
         (uint32_t(bytes[2]) << 8) |
         uint32_t(bytes[3]);
}

static inline uint8_t prodigyAesGFMul(uint8_t value, uint8_t multiplier)
{
  uint8_t result = 0;
  while (multiplier != 0)
  {
    if (multiplier & 1u)
    {
      result ^= value;
    }

    bool highBit = (value & 0x80u) != 0;
    value = uint8_t(value << 1);
    if (highBit)
    {
      value ^= 0x1bu;
    }

    multiplier >>= 1;
  }

  return result;
}

static inline uint8_t prodigyAesGFPow(uint8_t value, uint8_t exponent)
{
  uint8_t result = 1;
  while (exponent != 0)
  {
    if (exponent & 1u)
    {
      result = prodigyAesGFMul(result, value);
    }

    value = prodigyAesGFMul(value, value);
    exponent >>= 1;
  }

  return result;
}

static inline uint8_t prodigyAesRotL8(uint8_t value, uint8_t shift)
{
  return uint8_t((value << shift) | (value >> (8u - shift)));
}

static inline uint8_t prodigyAesSBox(uint8_t value)
{
  uint8_t inverse = (value == 0) ? 0 : prodigyAesGFPow(value, 254);
  return uint8_t(0x63u ^
                 inverse ^
                 prodigyAesRotL8(inverse, 1) ^
                 prodigyAesRotL8(inverse, 2) ^
                 prodigyAesRotL8(inverse, 3) ^
                 prodigyAesRotL8(inverse, 4));
}

static inline uint32_t prodigyAesSubWord(uint32_t value)
{
  return (uint32_t(prodigyAesSBox(uint8_t(value >> 24))) << 24) |
         (uint32_t(prodigyAesSBox(uint8_t(value >> 16))) << 16) |
         (uint32_t(prodigyAesSBox(uint8_t(value >> 8))) << 8) |
         uint32_t(prodigyAesSBox(uint8_t(value)));
}

static inline uint32_t prodigyAesRotWord(uint32_t value)
{
  return (value << 8) | (value >> 24);
}

static inline uint32_t prodigyAesInvMixColumnWord(uint32_t value)
{
  uint8_t b0 = uint8_t(value >> 24);
  uint8_t b1 = uint8_t(value >> 16);
  uint8_t b2 = uint8_t(value >> 8);
  uint8_t b3 = uint8_t(value);

  uint8_t o0 = prodigyAesGFMul(b0, 0x0eu) ^ prodigyAesGFMul(b1, 0x0bu) ^ prodigyAesGFMul(b2, 0x0du) ^ prodigyAesGFMul(b3, 0x09u);
  uint8_t o1 = prodigyAesGFMul(b0, 0x09u) ^ prodigyAesGFMul(b1, 0x0eu) ^ prodigyAesGFMul(b2, 0x0bu) ^ prodigyAesGFMul(b3, 0x0du);
  uint8_t o2 = prodigyAesGFMul(b0, 0x0du) ^ prodigyAesGFMul(b1, 0x09u) ^ prodigyAesGFMul(b2, 0x0eu) ^ prodigyAesGFMul(b3, 0x0bu);
  uint8_t o3 = prodigyAesGFMul(b0, 0x0bu) ^ prodigyAesGFMul(b1, 0x0du) ^ prodigyAesGFMul(b2, 0x09u) ^ prodigyAesGFMul(b3, 0x0eu);

  return (uint32_t(o0) << 24) |
         (uint32_t(o1) << 16) |
         (uint32_t(o2) << 8) |
         uint32_t(o3);
}

static inline bool prodigyBuildQuicCidDecryptRoundKeys(const uint8_t key[16], uint32_t rk[44])
{
  if (key == nullptr || rk == nullptr)
  {
    return false;
  }

  static constexpr uint32_t rcon[10] = {
      0x01000000u,
      0x02000000u,
      0x04000000u,
      0x08000000u,
      0x10000000u,
      0x20000000u,
      0x40000000u,
      0x80000000u,
      0x1b000000u,
      0x36000000u};

  uint32_t enc[44] = {};
  enc[0] = prodigyQuicCidLoadBE32(key);
  enc[1] = prodigyQuicCidLoadBE32(key + 4);
  enc[2] = prodigyQuicCidLoadBE32(key + 8);
  enc[3] = prodigyQuicCidLoadBE32(key + 12);

  for (uint32_t round = 0; round < 10; ++round)
  {
    uint32_t *cur = enc + (round * 4u);
    uint32_t *next = cur + 4;
    next[0] = cur[0] ^ prodigyAesSubWord(prodigyAesRotWord(cur[3])) ^ rcon[round];
    next[1] = cur[1] ^ next[0];
    next[2] = cur[2] ^ next[1];
    next[3] = cur[3] ^ next[2];
  }

  for (uint32_t round = 0; round <= 10; ++round)
  {
    for (uint32_t column = 0; column < 4; ++column)
    {
      rk[(round * 4u) + column] = enc[((10u - round) * 4u) + column];
    }
  }

  for (uint32_t round = 1; round < 10; ++round)
  {
    for (uint32_t column = 0; column < 4; ++column)
    {
      uint32_t index = (round * 4u) + column;
      rk[index] = prodigyAesInvMixColumnWord(rk[index]);
    }
  }

  return true;
}

/*
        +-------------------------+
        |        CID Schema       |
        |   +-----------------+   |
        |   |   CID Version   |   |
        |   |    (1 byte)     |   |
        |   +-----------------+   |
        |   |   container_id  |   |
        |   |    (5 bytes)    |   |
        |   +-----------------+   |
        |   |      nonce      |   |
        |   |    (4 bytes)    |   |
        |   +-----------------+   |
        |   |  verify tag     |   |
        |   |    (6 bytes)    |   |
        |   +-----------------+   |
        |        16 bytes         |
        +-------------------------+
*/
__attribute__((__always_inline__)) static inline ProdigyQuicCID prodigyGenerateQuicCID(
    ProdigyQuicCidEncryptor& encryptor,
    const uint8_t container_id[5],
    uint32_t *nonceCursor,
    const struct sockaddr *destination,
    uint8_t requiredEncryptedKeyIndex = 2)
{
  ProdigyQuicCID cid_returned = {};

  if (container_id == nullptr || nonceCursor == nullptr || destination == nullptr)
  {
    return cid_returned;
  }

  if (requiredEncryptedKeyIndex > 1)
  {
    requiredEncryptedKeyIndex = encryptor.keyPhase();
  }
  else if (requiredEncryptedKeyIndex != encryptor.keyPhase())
  {
    return cid_returned;
  }

  uint32_t nonce = *nonceCursor;
  for (uint32_t attempt = 0; attempt < 256; ++attempt)
  {
    uint8_t cid[16];
    cid[0] = QUIC_CID_VERSION;
    memcpy(cid + QUIC_CID_CONTAINER_ID_OFFSET, container_id, 5);
    memcpy(cid + QUIC_CID_NONCE_OFFSET, &nonce, 4);

    if (destination->sa_family == AF_INET)
    {
      const struct sockaddr_in *in4 = reinterpret_cast<const struct sockaddr_in *>(destination);
      quicCidDeriveTagForIPv4(cid + QUIC_CID_TAG_OFFSET, cid[0], container_id, nonce, in4->sin_addr.s_addr, in4->sin_port, IPPROTO_UDP);
    }
    else if (destination->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *in6 = reinterpret_cast<const struct sockaddr_in6 *>(destination);
      quicCidDeriveTagForIPv6(cid + QUIC_CID_TAG_OFFSET, cid[0], container_id, nonce, reinterpret_cast<const __be32 *>(in6->sin6_addr.s6_addr), in6->sin6_port, IPPROTO_UDP);
    }
    else
    {
      return cid_returned;
    }

    cid_returned.id_len = sizeof(cid);
    if (encryptor.encryptBlock(cid, cid_returned.id) == false)
    {
      cid_returned.id_len = 0;
      return cid_returned;
    }
    if (quicCidEncryptedKeyIndex(cid_returned.id) == requiredEncryptedKeyIndex)
    {
      *nonceCursor = nonce + 1;
      return cid_returned;
    }

    nonce += 1;
  }

  cid_returned.id_len = 0;
  return cid_returned;
}
