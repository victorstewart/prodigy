#include <networking/includes.h>
#include <services/debug.h>

#include <ebpf/kernel/aes.h>

#include <prodigy/quic.cid.generator.h>

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         basics_log("PASS: %s\n", name);
      }
      else
      {
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
   }
};

static bool buildDecryptState(const uint8_t key[16], aes_decrypt_state& state)
{
   state = {};
   return prodigyBuildQuicCidDecryptRoundKeys(key, state.rk);
}

static bool decryptAndValidateIPv4CID(
   const uint8_t key[16],
   const ProdigyQuicCID& cid,
   const uint8_t expectedContainerID[5],
   __be32 destinationAddress,
   __u16 destinationPort,
   uint32_t& extractedNonce)
{
   extractedNonce = 0;
   if (cid.id_len != 16)
   {
      return false;
   }

   aes_decrypt_state decryptState = {};
   if (buildDecryptState(key, decryptState) == false)
   {
      return false;
   }

   uint8_t plain[16] = {};
   aesDecrypt(&decryptState, cid.id, plain);
   if (plain[0] != QUIC_CID_VERSION)
   {
      return false;
   }

   if (std::memcmp(plain + QUIC_CID_CONTAINER_ID_OFFSET, expectedContainerID, 5) != 0)
   {
      return false;
   }

   std::memcpy(&extractedNonce, plain + QUIC_CID_NONCE_OFFSET, sizeof(extractedNonce));

   uint8_t expectedTag[QUIC_CID_TAG_LEN] = {};
   quicCidDeriveTagForIPv4(
      expectedTag,
      plain[0],
      plain + QUIC_CID_CONTAINER_ID_OFFSET,
      extractedNonce,
      destinationAddress,
      destinationPort,
      IPPROTO_UDP);

   return quicCidTagMatches(expectedTag, plain + QUIC_CID_TAG_OFFSET);
}

static bool decryptAndValidateIPv6CID(
   const uint8_t key[16],
   const ProdigyQuicCID& cid,
   const uint8_t expectedContainerID[5],
   const uint8_t destinationAddress[16],
   __u16 destinationPort,
   uint32_t& extractedNonce)
{
   extractedNonce = 0;
   if (cid.id_len != 16)
   {
      return false;
   }

   aes_decrypt_state decryptState = {};
   if (buildDecryptState(key, decryptState) == false)
   {
      return false;
   }

   uint8_t plain[16] = {};
   aesDecrypt(&decryptState, cid.id, plain);
   if (plain[0] != QUIC_CID_VERSION)
   {
      return false;
   }

   if (std::memcmp(plain + QUIC_CID_CONTAINER_ID_OFFSET, expectedContainerID, 5) != 0)
   {
      return false;
   }

   std::memcpy(&extractedNonce, plain + QUIC_CID_NONCE_OFFSET, sizeof(extractedNonce));

   uint8_t expectedTag[QUIC_CID_TAG_LEN] = {};
   quicCidDeriveTagForIPv6(
      expectedTag,
      plain[0],
      plain + QUIC_CID_CONTAINER_ID_OFFSET,
      extractedNonce,
      reinterpret_cast<const __be32 *>(destinationAddress),
      destinationPort,
      IPPROTO_UDP);

   return quicCidTagMatches(expectedTag, plain + QUIC_CID_TAG_OFFSET);
}

int main(void)
{
   TestSuite suite = {};

   const uint8_t key0[16] = {
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb,
      0xcc, 0xdd, 0xee, 0xff,
   };
   ProdigyQuicCidEncryptor cidEncryptor = {};
   suite.expect(cidEncryptor.setKey(key0), "quic_cid_encryptor_initializes");

   uint8_t containerID[5] = {0x7a, 0x01, 0x02, 0x03, 0x04};
   struct sockaddr_in destination = {};
   destination.sin_family = AF_INET;
   destination.sin_port = htons(443);
   inet_pton(AF_INET, "203.0.113.44", &destination.sin_addr);

   {
      uint32_t nonceCursor = 7;
      ProdigyQuicCID cid = prodigyGenerateQuicCID(
         cidEncryptor,
         containerID,
         &nonceCursor,
         reinterpret_cast<const struct sockaddr *>(&destination),
         0);

      uint32_t extractedNonce = 0;
      suite.expect(cid.id_len == 16, "quic_cid_generate_index0_returns_16_bytes");
      suite.expect(quicCidEncryptedKeyIndex(cid.id) == 0, "quic_cid_generate_index0_matches_requested_bit");
      suite.expect(decryptAndValidateIPv4CID(key0, cid, containerID, destination.sin_addr.s_addr, destination.sin_port, extractedNonce), "quic_cid_generate_index0_roundtrips_and_validates_tag");
      suite.expect(nonceCursor == extractedNonce + 1, "quic_cid_generate_index0_advances_nonce_cursor");
   }

   {
      uint32_t nonceCursor = 19;
      ProdigyQuicCID cid = prodigyGenerateQuicCID(
         cidEncryptor,
         containerID,
         &nonceCursor,
         reinterpret_cast<const struct sockaddr *>(&destination),
         1);

      uint32_t extractedNonce = 0;
      suite.expect(cid.id_len == 16, "quic_cid_generate_index1_returns_16_bytes");
      suite.expect(quicCidEncryptedKeyIndex(cid.id) == 1, "quic_cid_generate_index1_matches_requested_bit");
      suite.expect(decryptAndValidateIPv4CID(key0, cid, containerID, destination.sin_addr.s_addr, destination.sin_port, extractedNonce), "quic_cid_generate_index1_roundtrips_and_validates_tag");
      suite.expect(nonceCursor == extractedNonce + 1, "quic_cid_generate_index1_advances_nonce_cursor");
   }

   {
      struct sockaddr unsupported = {};
      unsupported.sa_family = AF_UNIX;
      uint32_t nonceCursor = 77;
      ProdigyQuicCID cid = prodigyGenerateQuicCID(cidEncryptor, containerID, &nonceCursor, &unsupported, 0);
      suite.expect(cid.id_len == 0, "quic_cid_generate_rejects_unsupported_family");
      suite.expect(nonceCursor == 77, "quic_cid_generate_preserves_nonce_on_failure");
   }

   {
      struct sockaddr_in6 destination6 = {};
      destination6.sin6_family = AF_INET6;
      destination6.sin6_port = htons(443);
      inet_pton(AF_INET6, "2001:db8:100::b", &destination6.sin6_addr);

      uint32_t nonceCursor = 93;
      ProdigyQuicCID cid = prodigyGenerateQuicCID(
         cidEncryptor,
         containerID,
         &nonceCursor,
         reinterpret_cast<const struct sockaddr *>(&destination6),
         0);

      uint32_t extractedNonce = 0;
      suite.expect(cid.id_len == 16, "quic_cid_generate_ipv6_returns_16_bytes");
      suite.expect(quicCidEncryptedKeyIndex(cid.id) == 0, "quic_cid_generate_ipv6_matches_requested_bit");
      suite.expect(
         decryptAndValidateIPv6CID(
            key0,
            cid,
            containerID,
            destination6.sin6_addr.s6_addr,
            destination6.sin6_port,
            extractedNonce),
         "quic_cid_generate_ipv6_roundtrips_and_validates_tag");
      suite.expect(nonceCursor == extractedNonce + 1, "quic_cid_generate_ipv6_advances_nonce_cursor");
   }

   suite.expect(quicCidPortalDecryptMapIndex(7, 0) == 14, "quic_cid_portal_decrypt_map_index_slot0");
   suite.expect(quicCidPortalDecryptMapIndex(7, 1) == 15, "quic_cid_portal_decrypt_map_index_slot1");

   return (suite.failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
