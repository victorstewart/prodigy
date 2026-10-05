#ifndef PRODIGY_CRYPTO_NOISE_INCLUDE_PRODIGY_NOISE_H
#define PRODIGY_CRYPTO_NOISE_INCLUDE_PRODIGY_NOISE_H

/*
 * Bounded Noise_NNpsk0_25519_ChaChaPoly_SHA256 handshake API.
 * The caller owns framing and must exchange exactly 48 bytes per handshake
 * message. No application payload is accepted by this interface.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  PRODIGY_NOISE_PSK_BYTES = 32,
  PRODIGY_NOISE_HANDSHAKE_BYTES = 48,
  PRODIGY_NOISE_HANDSHAKE_HASH_BYTES = 32,
  PRODIGY_NOISE_SPLIT_KEY_BYTES = 32,
  PRODIGY_NOISE_MAX_PROLOGUE_BYTES = 4096,
};

typedef struct ProdigyNoiseHandshake ProdigyNoiseHandshake;

typedef enum ProdigyNoiseStatus {
  PRODIGY_NOISE_OK = 0,
  PRODIGY_NOISE_INVALID_ARGUMENT = 1,
  PRODIGY_NOISE_ALLOCATION_FAILURE = 2,
  PRODIGY_NOISE_CRYPTO_FAILURE = 3,
  PRODIGY_NOISE_ORDER_FAILURE = 4,
  PRODIGY_NOISE_AUTH_FAILURE = 5,
  PRODIGY_NOISE_NOT_FINISHED = 6,
  PRODIGY_NOISE_ALREADY_EXPORTED = 7,
} ProdigyNoiseStatus;

/* Returns NULL on invalid input or allocation/crypto failure. */
ProdigyNoiseHandshake *prodigy_noise_new(const uint8_t psk[PRODIGY_NOISE_PSK_BYTES],
                                         const uint8_t *prologue,
                                         size_t prologue_size,
                                         int initiator);

/* Writes/reads one exact 48-byte empty-payload handshake message. */
ProdigyNoiseStatus prodigy_noise_write(ProdigyNoiseHandshake *handshake,
                                       uint8_t out[PRODIGY_NOISE_HANDSHAKE_BYTES]);
ProdigyNoiseStatus prodigy_noise_read(ProdigyNoiseHandshake *handshake,
                                      const uint8_t input[PRODIGY_NOISE_HANDSHAKE_BYTES]);

/* Returns one only after both handshake messages have completed. */
int prodigy_noise_finished(const ProdigyNoiseHandshake *handshake);

/*
 * One-shot export after completion. k1 is initiator-to-responder and k2 is
 * responder-to-initiator. The public handshake hash is channel-binding data,
 * never traffic-key input material. Success destroys the internal handshake
 * state; prodigy_noise_free must still be called for the opaque allocation.
 * All output arrays are cleared before any failure return.
 */
ProdigyNoiseStatus prodigy_noise_export(ProdigyNoiseHandshake *handshake,
                                        uint8_t k1[PRODIGY_NOISE_SPLIT_KEY_BYTES],
                                        uint8_t k2[PRODIGY_NOISE_SPLIT_KEY_BYTES],
                                        uint8_t handshake_hash[PRODIGY_NOISE_HANDSHAKE_HASH_BYTES]);

void prodigy_noise_free(ProdigyNoiseHandshake *handshake);

#ifdef __cplusplus
}
#endif

#endif
