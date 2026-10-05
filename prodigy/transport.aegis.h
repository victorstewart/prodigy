#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <networking/includes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <aegis/aegis.h>
#include <aegis/aegis128l.h>
#include <prodigy/crypto/noise/include/prodigy_noise.h>

// One connection's record protection. The credential/membership owner must
// authorize the PSK and canonical context before begin(), and invalidate the
// connection on revocation. This class never grants membership or authority.
// Noise authenticates fresh X25519; its secret Split outputs, not the public
// transcript hash or a deterministic root, supply the traffic-key entropy.
class ProdigyAegisSession {
public:
  enum class Record : uint8_t { confirmation = 0, application = 1, close = 2 };
  static constexpr uint32_t headerBytes = 16;
  static constexpr uint32_t tagBytes = 16;
  static constexpr uint32_t maximumPayloadBytes = 64 * 1024;
  static constexpr uint32_t maximumRecordBytes = headerBytes + maximumPayloadBytes + tagBytes;
  static constexpr uint64_t maximumRecords = uint64_t(1) << 32;

private:
  ProdigyNoiseHandshake *handshake = nullptr;
  std::array<uint8_t, 16> sendKey = {}, receiveKey = {};
  std::array<uint8_t, 32> transcript = {};
  uint64_t sendSequence = 0, receiveSequence = 0;
  bool initiator = false, keysReady = false, sentConfirmation = false;
  bool receivedConfirmation = false, sentClose = false, receivedClose = false;
  bool failed = false;

  static void put32(uint8_t *out, uint32_t value)
  {
    for (unsigned i = 0; i < 4; ++i) out[i] = uint8_t(value >> (24 - 8 * i));
  }
  static uint32_t get32(const uint8_t *in)
  {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value = (value << 8) | in[i];
    return value;
  }
  static void put64(uint8_t *out, uint64_t value)
  {
    for (unsigned i = 0; i < 8; ++i) out[i] = uint8_t(value >> (56 - 8 * i));
  }
  static uint64_t get64(const uint8_t *in)
  {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8) | in[i];
    return value;
  }
  static void clearOutput(String& output)
  {
    if (output.ownsMemory() && output.size() != 0) OPENSSL_cleanse(output.data(), output.size());
    output.clear();
  }
  bool fail()
  {
    reset();
    failed = true;
    return false;
  }
  bool deriveDirection(const uint8_t raw[32], uint8_t direction, uint8_t key[16])
  {
    constexpr uint8_t label[] = "prodigy/noise-to-aegis128l/record-v1";
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    size_t bytes = 16;
    const bool ok = ctx != nullptr && EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, transcript.data(), transcript.size()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, raw, 32) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx, label, sizeof(label)) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx, &direction, 1) > 0 &&
        EVP_PKEY_derive(ctx, key, &bytes) > 0 && bytes == 16;
    if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
    return ok;
  }
  bool exportKeysIfFinished()
  {
    if (handshake == nullptr || !prodigy_noise_finished(handshake)) return true;
    std::array<uint8_t, 32> k1 = {}, k2 = {};
    bool ok = prodigy_noise_export(handshake, k1.data(), k2.data(), transcript.data()) == PRODIGY_NOISE_OK;
    if (ok)
      ok = deriveDirection(initiator ? k1.data() : k2.data(), initiator ? 0 : 1, sendKey.data()) &&
           deriveDirection(initiator ? k2.data() : k1.data(), initiator ? 1 : 0, receiveKey.data());
    OPENSSL_cleanse(k1.data(), k1.size());
    OPENSSL_cleanse(k2.data(), k2.size());
    prodigy_noise_free(handshake);
    handshake = nullptr;
    if (!ok) return fail();
    keysReady = true;
    return true;
  }

public:
  ProdigyAegisSession() = default;
  ProdigyAegisSession(const ProdigyAegisSession&) = delete;
  ProdigyAegisSession& operator=(const ProdigyAegisSession&) = delete;
  ~ProdigyAegisSession() { reset(); }

  void reset()
  {
    if (handshake != nullptr) prodigy_noise_free(handshake);
    handshake = nullptr;
    OPENSSL_cleanse(sendKey.data(), sendKey.size());
    OPENSSL_cleanse(receiveKey.data(), receiveKey.size());
    transcript.fill(0);
    sendSequence = receiveSequence = 0;
    initiator = keysReady = sentConfirmation = receivedConfirmation = false;
    sentClose = receivedClose = failed = false;
  }
  bool begin(const uint8_t psk[32], const String& canonicalContext, bool isInitiator)
  {
    reset();
    // Include the exact record profile in the Noise transcript. A peer cannot
    // negotiate another record format while retaining a successful proof.
    constexpr uint8_t domain[] = "prodigy/authenticated-aegis128l/v1";
    if (psk == nullptr || canonicalContext.empty() ||
        canonicalContext.size() > PRODIGY_NOISE_MAX_PROLOGUE_BYTES - sizeof(domain) - 8) return fail();
    uint8_t keyBits = 0;
    for (unsigned i = 0; i < 32; ++i) keyBits |= psk[i];
    if (keyBits == 0) return fail();
    String prologue = {};
    if (!prologue.reserve(sizeof(domain) + 8 + canonicalContext.size())) return fail();
    prologue.append(domain, sizeof(domain));
    uint8_t length[8] = {};
    put64(length, canonicalContext.size());
    prologue.append(length, sizeof(length));
    prologue.append(canonicalContext);
    initiator = isInitiator;
    handshake = prodigy_noise_new(psk, prologue.data(), prologue.size(), initiator ? 1 : 0);
    return handshake != nullptr || fail();
  }
  bool writeHandshake(std::array<uint8_t, PRODIGY_NOISE_HANDSHAKE_BYTES>& output)
  {
    output.fill(0);
    if (failed || handshake == nullptr ||
        prodigy_noise_write(handshake, output.data()) != PRODIGY_NOISE_OK) return fail();
    if (!exportKeysIfFinished()) { output.fill(0); return false; }
    return true;
  }
  bool readHandshake(const uint8_t *input, uint32_t size)
  {
    if (failed || handshake == nullptr || input == nullptr || size != PRODIGY_NOISE_HANDSHAKE_BYTES ||
        prodigy_noise_read(handshake, input) != PRODIGY_NOISE_OK) return fail();
    return exportKeysIfFinished();
  }
  bool handshakeComplete() const { return keysReady && !failed; }
  bool authenticated() const
  {
    return keysReady && sentConfirmation && receivedConfirmation && !failed && !sentClose && !receivedClose;
  }
  bool failedClosed() const { return failed; }
  bool peerClosed() const { return receivedClose; }
  bool confirmationNeeded() const { return keysReady && !sentConfirmation && !failed; }

  // Header is version(1), record type(1), direction(1), reserved(1), payload
  // length(4 BE), sequence(8 BE). Header and full Noise transcript are AEAD AD.
  // The nonce is 64 zero bits followed by the sequence; each direction has a
  // distinct fresh key. No random-nonce collision or replay cache is involved.
  static bool recordSize(const uint8_t *header, uint32_t available, uint32_t& bytes)
  {
    bytes = 0;
    if (header == nullptr || available < headerBytes) return false;
    const uint32_t payload = get32(header + 4);
    if (header[0] != 1 || header[1] > uint8_t(Record::close) || header[2] > 1 || header[3] != 0 ||
        payload > maximumPayloadBytes || (header[1] != uint8_t(Record::application) && payload != 0)) return false;
    bytes = headerBytes + payload + tagBytes;
    return true;
  }
  bool encrypt(Record kind, const uint8_t *plaintext, uint32_t size, String& output)
  {
    clearOutput(output);
    if (failed || !keysReady || sentClose || receivedClose || sendSequence >= maximumRecords ||
        uint8_t(kind) > uint8_t(Record::close) || size > maximumPayloadBytes || (size != 0 && plaintext == nullptr) ||
        (kind == Record::confirmation ? (sentConfirmation || sendSequence != 0 || size != 0) : !authenticated()) ||
        (kind != Record::application && size != 0)) return fail();
    const uint32_t bytes = headerBytes + size + tagBytes;
    String frame = {};
    if (!frame.reserve(bytes)) return fail();
    frame.resize(bytes);
    auto *header = frame.data();
    header[0] = 1;
    header[1] = uint8_t(kind);
    header[2] = initiator ? 0 : 1;
    header[3] = 0;
    put32(header + 4, size);
    put64(header + 8, sendSequence);
    std::array<uint8_t, 16> nonce = {};
    put64(nonce.data() + 8, sendSequence);
    std::array<uint8_t, headerBytes + 32> ad = {};
    std::memcpy(ad.data(), header, headerBytes);
    std::memcpy(ad.data() + headerBytes, transcript.data(), transcript.size());
    const uint8_t empty = 0;
    if (aegis128l_encrypt(header + headerBytes, tagBytes, size ? plaintext : &empty, size,
                         ad.data(), ad.size(), nonce.data(), sendKey.data()) != 0)
    {
      clearOutput(frame);
      return fail();
    }
    ++sendSequence;
    if (kind == Record::confirmation) sentConfirmation = true;
    if (kind == Record::close) sentClose = true;
    output = std::move(frame);
    return true;
  }
  bool decrypt(const uint8_t *frame, uint32_t size, Record& kind, String& plaintext)
  {
    clearOutput(plaintext);
    kind = Record::close;
    uint32_t expectedBytes = 0;
    if (failed || !keysReady || receivedClose || receiveSequence >= maximumRecords ||
        !recordSize(frame, size, expectedBytes) || expectedBytes != size ||
        frame[2] != (initiator ? 1 : 0) || get64(frame + 8) != receiveSequence) return fail();
    const Record type = Record(frame[1]);
    const uint32_t payloadBytes = get32(frame + 4);
    if (type == Record::confirmation ? (receivedConfirmation || receiveSequence != 0) : !authenticated()) return fail();
    String decoded = {};
    // libaegis accepts a nonnull output even for the empty confirmation record.
    if (!decoded.reserve(payloadBytes ? payloadBytes : 1)) return fail();
    decoded.resize(payloadBytes);
    std::array<uint8_t, 16> nonce = {};
    put64(nonce.data() + 8, receiveSequence);
    std::array<uint8_t, headerBytes + 32> ad = {};
    std::memcpy(ad.data(), frame, headerBytes);
    std::memcpy(ad.data() + headerBytes, transcript.data(), transcript.size());
    if (aegis128l_decrypt(decoded.data(), frame + headerBytes, payloadBytes + tagBytes, tagBytes,
                         ad.data(), ad.size(), nonce.data(), receiveKey.data()) != 0)
    {
      clearOutput(decoded);
      return fail();
    }
    ++receiveSequence;
    if (type == Record::confirmation) receivedConfirmation = true;
    if (type == Record::close) receivedClose = true;
    plaintext = std::move(decoded);
    kind = type;
    return true;
  }
};
