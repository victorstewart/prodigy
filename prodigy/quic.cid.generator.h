#pragma once

#include <cstddef>
#include <cstring>
#include <cstdint>
#include <netinet/in.h>

#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define PRODIGY_QUIC_CID_RESTORE_OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif
#include <openssl/aes.h>
#ifdef PRODIGY_QUIC_CID_RESTORE_OPENSSL_SUPPRESS_DEPRECATED
#undef OPENSSL_SUPPRESS_DEPRECATED
#undef PRODIGY_QUIC_CID_RESTORE_OPENSSL_SUPPRESS_DEPRECATED
#endif
#include <openssl/evp.h>
#include <sys/socket.h>

#include <macros/quic.h>

#include <switchboard/common/quic.cid.h>

struct ProdigyQuicCID {
	static constexpr uint8_t maxLen = 20;

	uint8_t id[maxLen] = {};
	uint8_t id_len = 0;
};

class ProdigyQuicCidEncryptor {
private:
	EVP_CIPHER_CTX *context_ = nullptr;

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

		return EVP_CIPHER_CTX_set_padding(context_, 0) == 1;
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

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
static inline bool prodigyBuildQuicCidDecryptRoundKeys(const uint8_t key[16], uint32_t rk[44])
{
	if (key == nullptr || rk == nullptr)
	{
		return false;
	}

	AES_KEY decryptKey = {};
	if (AES_set_decrypt_key(key, 128, &decryptKey) != 0)
	{
		return false;
	}

	static_assert((sizeof(decryptKey.rd_key) / sizeof(decryptKey.rd_key[0])) >= 44, "OpenSSL AES decrypt key schedule is smaller than expected");
	for (size_t i = 0; i < 44; ++i)
	{
		rk[i] = __builtin_bswap32(static_cast<uint32_t>(decryptKey.rd_key[i]));
	}

	return true;
}
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

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
__attribute__((__always_inline__))
static inline ProdigyQuicCID prodigyGenerateQuicCID(
   ProdigyQuicCidEncryptor& encryptor,
   const uint8_t container_id[5],
   uint32_t *nonceCursor,
   const struct sockaddr *destination,
   uint8_t requiredEncryptedKeyIndex)
{
	ProdigyQuicCID cid_returned = {};

	if (container_id == nullptr || nonceCursor == nullptr || destination == nullptr)
	{
		return cid_returned;
	}

	requiredEncryptedKeyIndex &= 0x01;
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
