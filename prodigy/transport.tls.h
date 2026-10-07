#pragma once

#include <prodigy/transport.aegis.h>

#include <algorithm>
#include <functional>

#include <prodigy/server.state.h>
#include <services/vault.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/tls.h>

class ProdigyTransportTLSMaterial {
public:

  uint64_t generation = 0;
  String clusterRootCertPem;
  String clusterRootKeyPem;
  String localCertPem;
  String localKeyPem;

  bool configured(void) const
  {
    return clusterRootCertPem.size() > 0 && localCertPem.size() > 0 && localKeyPem.size() > 0;
  }

  bool canMintForCluster(void) const
  {
    return configured() && clusterRootKeyPem.size() > 0;
  }

  bool operator==(const ProdigyTransportTLSMaterial& other) const
  {
    return generation == other.generation && clusterRootCertPem.equals(other.clusterRootCertPem) && clusterRootKeyPem.equals(other.clusterRootKeyPem) && localCertPem.equals(other.localCertPem) && localKeyPem.equals(other.localKeyPem);
  }

  bool operator!=(const ProdigyTransportTLSMaterial& other) const
  {
    return (*this == other) == false;
  }
};

constexpr static int64_t ProdigyTransportTLSNotBeforeBackdateSeconds = 300;

static inline bool prodigyBackdateTransportCertificate(
    X509 *cert,
    EVP_PKEY *signingKey,
    String *failure = nullptr)
{
  if (failure)
  {
    failure->clear();
  }
  if (cert == nullptr || signingKey == nullptr)
  {
    if (failure)
    {
      failure->assign("transport tls certificate and signing key required"_ctv);
    }
    return false;
  }

  if (X509_gmtime_adj(X509_getm_notBefore(cert), -ProdigyTransportTLSNotBeforeBackdateSeconds) == nullptr)
  {
    if (failure)
    {
      failure->assign("failed to backdate transport tls certificate notBefore"_ctv);
    }
    return false;
  }

  if (X509_sign(cert, signingKey, nullptr) == 0)
  {
    if (failure)
    {
      failure->assign("failed to resign backdated transport tls certificate"_ctv);
    }
    return false;
  }

  return true;
}

static inline bool prodigyGenerateTransportRootCertificateEd25519(
    String& certPem,
    String& keyPem,
    String *failure = nullptr)
{
  certPem.clear();
  keyPem.clear();
  if (failure)
  {
    failure->clear();
  }

  String generatedCertPem = {};
  String generatedKeyPem = {};
  if (Vault::generateTransportRootCertificateEd25519(generatedCertPem, generatedKeyPem, failure) == false)
  {
    return false;
  }

  X509 *cert = VaultPem::x509FromPem(generatedCertPem);
  EVP_PKEY *key = VaultPem::privateKeyFromPem(generatedKeyPem);
  bool ok = (cert != nullptr && key != nullptr);
  if (ok == false)
  {
    if (failure)
    {
      failure->assign("failed to parse generated transport root material"_ctv);
    }
  }
  if (ok)
  {
    ok = prodigyBackdateTransportCertificate(cert, key, failure);
  }
  if (ok)
  {
    ok = VaultPem::x509ToPem(cert, certPem);
    if (ok == false && failure)
    {
      failure->assign("failed to serialize backdated transport root certificate"_ctv);
    }
  }

  if (cert)
  {
    X509_free(cert);
  }
  if (key)
  {
    EVP_PKEY_free(key);
  }

  if (ok == false)
  {
    certPem.clear();
    keyPem.clear();
    return false;
  }

  keyPem = generatedKeyPem;
  return true;
}

static inline bool prodigyGenerateTransportNodeCertificateEd25519(
    const String& rootCertPem,
    const String& rootKeyPem,
    uint128_t uuid,
    const Vector<String>& ipAddresses,
    String& certPem,
    String& keyPem,
    String *failure = nullptr)
{
  certPem.clear();
  keyPem.clear();
  if (failure)
  {
    failure->clear();
  }

  String generatedCertPem = {};
  String generatedKeyPem = {};
  if (Vault::generateTransportNodeCertificateEd25519(
          rootCertPem,
          rootKeyPem,
          uuid,
          ipAddresses,
          generatedCertPem,
          generatedKeyPem,
          failure) == false)
  {
    return false;
  }

  X509 *cert = VaultPem::x509FromPem(generatedCertPem);
  EVP_PKEY *rootKey = VaultPem::privateKeyFromPem(rootKeyPem);
  bool ok = (cert != nullptr && rootKey != nullptr);
  if (ok == false)
  {
    if (failure)
    {
      failure->assign("failed to parse generated transport node material"_ctv);
    }
  }
  if (ok)
  {
    ok = prodigyBackdateTransportCertificate(cert, rootKey, failure);
  }
  if (ok)
  {
    ok = VaultPem::x509ToPem(cert, certPem);
    if (ok == false && failure)
    {
      failure->assign("failed to serialize backdated transport node certificate"_ctv);
    }
  }

  if (cert)
  {
    X509_free(cert);
  }
  if (rootKey)
  {
    EVP_PKEY_free(rootKey);
  }

  if (ok == false)
  {
    certPem.clear();
    keyPem.clear();
    return false;
  }

  keyPem = generatedKeyPem;
  return true;
}

template <typename S>
static void serialize(S&& serializer, ProdigyTransportTLSMaterial& material)
{
  serializer.value8b(material.generation);
  serializer.text1b(material.clusterRootCertPem, UINT32_MAX);
  serializer.text1b(material.clusterRootKeyPem, UINT32_MAX);
  serializer.text1b(material.localCertPem, UINT32_MAX);
  serializer.text1b(material.localKeyPem, UINT32_MAX);
}

class ProdigyTransportTLSBootstrap {
public:

  uint128_t uuid = 0;
  ProdigyTransportTLSMaterial transport;

  bool configured(void) const
  {
    return uuid != 0 && transport.configured();
  }

  bool canMintForCluster(void) const
  {
    return uuid != 0 && transport.canMintForCluster();
  }
};

class ProdigyTransportTLSResumptionConfig {
public:

  ProdigyResumptionRegistry *registry = nullptr;
  int64_t (*nowMsCallback)(void *arg) = nullptr;
  void *nowMsCallbackArg = nullptr;
  uint64_t renewBeforeMs = 0;

  bool configured(void) const
  {
    return registry != nullptr;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyTransportTLSBootstrap& bootstrap)
{
  serializer.value16b(bootstrap.uuid);
  serializer.object(bootstrap.transport);
}

class ProdigyTransportTLSRuntime {
private:

  static inline SSL_CTX *ctx = nullptr;
  static inline ProdigyTransportTLSBootstrap bootstrap = {};
  static inline ProdigyOpenSSLTlsTicketContext ticketContext = {};

public:

  static void clear(void)
  {
    if (ctx)
    {
      SSL_CTX_free(ctx);
      ctx = nullptr;
    }

    ticketContext = {};
    bootstrap = {};
  }

  static bool configure(const ProdigyTransportTLSBootstrap& newBootstrap, String *failure = nullptr)
  {
    return configure(newBootstrap, ProdigyTransportTLSResumptionConfig {}, failure);
  }

  static bool configure(
      const ProdigyTransportTLSBootstrap& newBootstrap,
      const ProdigyTransportTLSResumptionConfig& newResumption,
      String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }
    if (newBootstrap.configured() == false)
    {
      if (failure)
      {
        failure->assign("transport tls bootstrap incomplete"_ctv);
      }
      return false;
    }

    String clusterRootCertPem = {};
    clusterRootCertPem.assign(newBootstrap.transport.clusterRootCertPem);
    String localCertPem = {};
    localCertPem.assign(newBootstrap.transport.localCertPem);
    String localKeyPem = {};
    localKeyPem.assign(newBootstrap.transport.localKeyPem);

    SSL_CTX *newCtx = TLSBase::generateCtxFromPEM(
        clusterRootCertPem.c_str(),
        uint32_t(clusterRootCertPem.size()),
        localCertPem.c_str(),
        uint32_t(localCertPem.size()),
        localKeyPem.c_str(),
        uint32_t(localKeyPem.size()));
    if (newCtx == nullptr)
    {
      if (failure)
      {
        failure->assign("failed to build transport tls context"_ctv);
      }
      return false;
    }

    bool ok = (SSL_CTX_set1_groups_list(newCtx, "X25519") == 1);
    if (ok)
    {
      ok = (SSL_CTX_set1_sigalgs_list(newCtx, "ed25519") == 1);
    }
    if (ok)
    {
      SSL_CTX_set_verify_depth(newCtx, 2);
    }

    if (ok == false)
    {
      SSL_CTX_free(newCtx);
      if (failure)
      {
        failure->assign("failed to harden transport tls context"_ctv);
      }
      return false;
    }

    ProdigyOpenSSLTlsTicketContext oldTicketContext = ticketContext;
    if (newResumption.configured())
    {
      ticketContext = {};
      ticketContext.registry = newResumption.registry;
      ticketContext.nowMsCallback = newResumption.nowMsCallback;
      ticketContext.nowMsCallbackArg = newResumption.nowMsCallbackArg;
      ticketContext.renewBeforeMs = newResumption.renewBeforeMs;
      if (prodigyInstallOpenSSLTlsResumptionTicketKeyCallback(newCtx, &ticketContext, failure) == false)
      {
        ticketContext = oldTicketContext;
        SSL_CTX_free(newCtx);
        return false;
      }
    }

    if (ctx)
    {
      SSL_CTX_free(ctx);
    }
    ctx = newCtx;
    bootstrap = newBootstrap;
    if (newResumption.configured() == false)
    {
      ticketContext = {};
    }
    return true;
  }

  static bool configured(void)
  {
    return ctx != nullptr;
  }

  static bool canMintForCluster(void)
  {
    return bootstrap.canMintForCluster();
  }

  static SSL_CTX *context(void)
  {
    return ctx;
  }

  static bool resumptionConfigured(void)
  {
    return ticketContext.registry != nullptr;
  }

  static ProdigyOpenSSLTlsTicketContext *resumptionTicketContext(void)
  {
    return resumptionConfigured() ? &ticketContext : nullptr;
  }

  static const ProdigyTransportTLSBootstrap& state(void)
  {
    return bootstrap;
  }

  static bool extractPeerUUID(SSL *ssl, uint128_t& uuid)
  {
    uuid = 0;
    if (ssl == nullptr || SSL_is_init_finished(ssl) != 1)
    {
      return false;
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
      return false;
    }

    X509 *peerCert = SSL_get1_peer_certificate(ssl);
    if (peerCert == nullptr)
    {
      return false;
    }

    bool ok = Vault::extractTransportCertificateUUID(peerCert, uuid);
    X509_free(peerCert);
    return ok;
  }
};

class ProdigyTransportTLSStream : public TCPStream, public TLSBase {
public:
  using AEGISPeerResolver = std::function<bool(const String&, std::array<uint8_t, 32>&, String&, uint128_t&)>;
  using AEGISDeferredServerPreludeResolver = std::function<bool(const String&, String&, std::array<uint8_t, 32>&, String&, uint128_t&)>;

private:

  bool tlsEnabled = false;
  bool aegisEnabled = false;
  bool aegisFailed = false;
  bool aegisInitiator = false;
  bool aegisHandshakeWritten = false;
  bool aegisHandshakeRead = false;
  bool aegisPreludeWritten = false;
  bool aegisPeerResolved = true;
  uint128_t aegisLocalUUID = 0;
  uint128_t aegisExpectedPeerUUID = 0;
  String aegisLocalPrelude;
  String aegisPeerPrelude;
  bool aegisDeferredServerPrelude = false;
  AEGISPeerResolver aegisPeerResolver;
  AEGISDeferredServerPreludeResolver aegisDeferredServerPreludeResolver;
  ProdigyAegisSession aegisSession;
  StreamBuffer aegisInbound;
  StreamBuffer encryptedWBuffer;
  ProdigyOpenSSLTlsTicketBinding tlsResumptionBinding = {};

  static void clearAEGISBuffer(StreamBuffer& buffer)
  {
    if (buffer.ownsMemory() && buffer.data() != nullptr)
      OPENSSL_cleanse(buffer.data(), buffer.reservedBytes());
    buffer.clear();
  }

  bool failTransportAEGIS()
  {
    aegisFailed = true;
    aegisSession.reset();
    tlsPeerVerified = false;
    tlsPeerUUID = 0;
    clearAEGISBuffer(rBuffer);
    clearAEGISBuffer(wBuffer);
    clearAEGISBuffer(encryptedWBuffer);
    clearAEGISBuffer(aegisInbound);
    aegisPeerResolver = {};
    aegisDeferredServerPreludeResolver = {};
    aegisDeferredServerPrelude = false;
    aegisPeerPrelude.reset();
    nEncryptedBytesToSend = 0;
    return false;
  }

  void publishAEGISPeerProof()
  {
    if (aegisSession.authenticated())
    {
      tlsPeerUUID = aegisExpectedPeerUUID;
      tlsPeerVerified = true;
    }
  }

  bool startTransportAEGISKeys(const uint8_t psk[32], const String& credentialContext,
                              uint128_t localUUID, uint128_t peerUUID,
                              const String& localPrelude = {}, const String& peerPrelude = {})
  {
    if (localUUID == 0 || peerUUID == 0 || credentialContext.empty() ||
        credentialContext.size() + localPrelude.size() + peerPrelude.size() > PRODIGY_NOISE_MAX_PROLOGUE_BYTES - 256)
      return failTransportAEGIS();
    // Bind the actual asserted identity inside this owner, even if a caller's
    // credential context omitted it. Ordering is initiator then responder.
    constexpr uint8_t domain[] = "prodigy/aegis-stream-identities/v1";
    String canonicalContext = {};
    if (!canonicalContext.reserve(sizeof(domain) + 32 + 24 + credentialContext.size() + localPrelude.size() + peerPrelude.size()))
      return failTransportAEGIS();
    canonicalContext.append(domain, sizeof(domain));
    const uint128_t identities[] = {aegisInitiator ? localUUID : peerUUID, aegisInitiator ? peerUUID : localUUID};
    for (uint128_t identity : identities)
      for (int shift = 120; shift >= 0; shift -= 8) canonicalContext.append(uint8_t(identity >> shift));
    const String *fields[] = {&credentialContext, aegisInitiator ? &localPrelude : &peerPrelude,
                             aegisInitiator ? &peerPrelude : &localPrelude};
    for (const String *field : fields)
    {
      for (int shift = 56; shift >= 0; shift -= 8) canonicalContext.append(uint8_t(uint64_t(field->size()) >> shift));
      canonicalContext.append(*field);
    }
    if (!aegisSession.begin(psk, canonicalContext, aegisInitiator)) return failTransportAEGIS();
    aegisExpectedPeerUUID = peerUUID;
    aegisPeerResolved = true;
    return true;
  }

  bool prepareTransportAEGISSend()
  {
    if (aegisFailed) return false;
    if (hasBufferedTransportCiphertext()) return true;
    // A deferred responder has no public prelude or Noise state until it
    // validates the initiator's bounded prelude. It must not emit application
    // data, a fallback greeting, or a transcript fragment before that point.
    if (!aegisPeerResolved && aegisDeferredServerPrelude)
    {
      nEncryptedBytesToSend = 0;
      return true;
    }
    // Emit a fixed public prelude as a standalone first flight. The resolver
    // needs the peer's corresponding PGA claim before startTransportAEGISKeys
    // creates Noise state, so an initiator must not write Noise in this call.
    if (!aegisLocalPrelude.empty() && !aegisPreludeWritten)
    {
      const uint32_t size = aegisLocalPrelude.size();
      const uint8_t header[] = {'P', 'G', 'A', 1, uint8_t(size >> 8), uint8_t(size), 0, 0};
      if (!encryptedWBuffer.need(sizeof(header) + size)) return failTransportAEGIS();
      encryptedWBuffer.append(header, sizeof(header));
      encryptedWBuffer.append(aegisLocalPrelude);
      aegisPreludeWritten = true;
    }
    if (!aegisPeerResolved)
    {
      nEncryptedBytesToSend = uint32_t(encryptedWBuffer.outstandingBytes());
      return true;
    }
    // After a deferred responder resolves the peer prelude, its selected PGA
    // is already written above and the resolver has started Noise. Append the
    // mandatory responder reply in this same ciphertext generation.
    if (!aegisHandshakeWritten && (aegisInitiator || aegisHandshakeRead))
    {
      std::array<uint8_t, PRODIGY_NOISE_HANDSHAKE_BYTES> message = {};
      if (!aegisSession.writeHandshake(message) || !encryptedWBuffer.need(message.size())) return failTransportAEGIS();
      encryptedWBuffer.append(message.data(), message.size());
      aegisHandshakeWritten = true;
    }
    if (aegisSession.confirmationNeeded())
    {
      String frame = {};
      if (!aegisSession.encrypt(ProdigyAegisSession::Record::confirmation, nullptr, 0, frame) ||
          !encryptedWBuffer.need(frame.size())) return failTransportAEGIS();
      encryptedWBuffer.append(frame);
      publishAEGISPeerProof();
    }
    if (aegisSession.authenticated() && wBuffer.outstandingBytes() != 0)
    {
      const uint32_t bytes = uint32_t(std::min<uint64_t>(wBuffer.outstandingBytes(), ProdigyAegisSession::maximumPayloadBytes));
      String frame = {};
      if (!aegisSession.encrypt(ProdigyAegisSession::Record::application, wBuffer.pHead(), bytes, frame) ||
          !encryptedWBuffer.need(frame.size())) return failTransportAEGIS();
      encryptedWBuffer.append(frame);
      wBuffer.consume(bytes, false);
    }
    nEncryptedBytesToSend = uint32_t(encryptedWBuffer.outstandingBytes());
    return !aegisSession.failedClosed();
  }

  bool decryptTransportAEGIS(uint32_t bytesReceived)
  {
    if (aegisFailed) return false;
    // A single recv may coalesce many complete records when the application
    // has a large read buffer. Bound incomplete framing state, not that valid
    // coalesced read; the socket owner already bounds it by allocated space.
    if (bytesReceived > rBuffer.remainingCapacity() ||
        aegisInbound.outstandingBytes() > ProdigyAegisSession::maximumRecordBytes ||
        !aegisInbound.need(bytesReceived)) return failTransportAEGIS();
    // Ring has written ciphertext at rBuffer's tail without advancing it.
    // Save it before decrypted application bytes overwrite the same storage.
    aegisInbound.append(rBuffer.pTail(), bytesReceived);
    while (aegisInbound.outstandingBytes() != 0)
    {
      if (!aegisPeerResolved)
      {
        if (aegisInbound.outstandingBytes() < 8) break;
        const uint8_t *header = aegisInbound.pHead();
        const uint32_t size = (uint32_t(header[4]) << 8) | header[5];
        if (header[0] != 'P' || header[1] != 'G' || header[2] != 'A' || header[3] != 1 ||
            header[6] != 0 || header[7] != 0 || size == 0 || size > 512 ||
            (aegisDeferredServerPrelude ? !aegisDeferredServerPreludeResolver : !aegisPeerResolver))
          return failTransportAEGIS();
        if (aegisInbound.outstandingBytes() < 8 + size) break;
        String peerPrelude = {};
        if (!peerPrelude.reserve(size)) return failTransportAEGIS();
        peerPrelude.append(header + 8, size);
        std::array<uint8_t, 32> psk = {};
        String credentialContext = {}, selectedLocalPrelude = {};
        uint128_t peerUUID = 0;
        bool ok = aegisDeferredServerPrelude
            ? aegisDeferredServerPreludeResolver(peerPrelude, selectedLocalPrelude, psk, credentialContext, peerUUID)
            : aegisPeerResolver(peerPrelude, psk, credentialContext, peerUUID);
        if (ok && aegisDeferredServerPrelude)
        {
          if (selectedLocalPrelude.empty() || selectedLocalPrelude.size() > 512 ||
              !aegisLocalPrelude.reserve(selectedLocalPrelude.size())) ok = false;
          else aegisLocalPrelude.append(selectedLocalPrelude);
        }
        if (ok) ok = startTransportAEGISKeys(psk.data(), credentialContext, aegisLocalUUID, peerUUID,
                                            aegisLocalPrelude, peerPrelude);
        if (ok) aegisPeerPrelude = std::move(peerPrelude);
        OPENSSL_cleanse(psk.data(), psk.size());
        if (selectedLocalPrelude.ownsMemory()) OPENSSL_cleanse(selectedLocalPrelude.data(), selectedLocalPrelude.size());
        aegisPeerResolver = {};
        aegisDeferredServerPreludeResolver = {};
        aegisDeferredServerPrelude = false;
        if (!ok) return failTransportAEGIS();
        aegisInbound.consume(8 + size, false);
        continue;
      }
      if (!aegisHandshakeRead)
      {
        if (aegisInbound.outstandingBytes() < PRODIGY_NOISE_HANDSHAKE_BYTES) break;
        if (!aegisSession.readHandshake(aegisInbound.pHead(), PRODIGY_NOISE_HANDSHAKE_BYTES)) return failTransportAEGIS();
        aegisHandshakeRead = true;
        aegisInbound.consume(PRODIGY_NOISE_HANDSHAKE_BYTES, false);
        continue;
      }
      if (!aegisSession.handshakeComplete())
      {
        // A responder must write message two before interpreting records.
        if (!prepareTransportAEGISSend() || !aegisSession.handshakeComplete()) return failTransportAEGIS();
      }
      if (aegisInbound.outstandingBytes() < ProdigyAegisSession::headerBytes) break;
      uint32_t frameBytes = 0;
      if (!ProdigyAegisSession::recordSize(aegisInbound.pHead(), uint32_t(aegisInbound.outstandingBytes()), frameBytes))
        return failTransportAEGIS();
      if (aegisInbound.outstandingBytes() < frameBytes) break;
      String plaintext = {};
      ProdigyAegisSession::Record type;
      if (!aegisSession.decrypt(aegisInbound.pHead(), frameBytes, type, plaintext)) return failTransportAEGIS();
      aegisInbound.consume(frameBytes, false);
      publishAEGISPeerProof();
      if (type == ProdigyAegisSession::Record::close) return failTransportAEGIS();
      if (type == ProdigyAegisSession::Record::application)
      {
        if (!tlsPeerVerified || !rBuffer.need(plaintext.size()))
        {
          if (plaintext.size() != 0) OPENSSL_cleanse(plaintext.data(), plaintext.size());
          return failTransportAEGIS();
        }
        rBuffer.append(plaintext);
        if (plaintext.size() != 0) OPENSSL_cleanse(plaintext.data(), plaintext.size());
      }
    }
    if (aegisInbound.outstandingBytes() > ProdigyAegisSession::maximumRecordBytes) return failTransportAEGIS();
    aegisInbound.releaseIdleCapacityAbove(2 * ProdigyAegisSession::maximumRecordBytes);
    return true;
  }

  bool harvestEncryptedOutput(void)
  {
    while (BIO_ctrl_pending(rbio) > 0)
    {
      if (encryptedWBuffer.remainingCapacity() == 0)
      {
        encryptedWBuffer.reserve((encryptedWBuffer.size() > 0) ? (encryptedWBuffer.size() * 2) : 4096);
      }

      int written = BIO_read(rbio, encryptedWBuffer.pTail(), encryptedWBuffer.remainingCapacity());
      if (written > 0)
      {
        encryptedWBuffer.advance(written);
      }
      else
      {
        if (BIO_should_retry(rbio) == false)
        {
          encryptedWBuffer.reset();
          return false;
        }

        break;
      }
    }

    nEncryptedBytesToSend = uint32_t(encryptedWBuffer.outstandingBytes());
    return true;
  }

  bool driveHandshake(void)
  {
    int handshake = SSL_do_handshake(ssl);
    if (handshake != 1)
    {
      switch (SSL_get_error(ssl, handshake))
      {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          {
            break;
          }
        default:
          {
            encryptedWBuffer.reset();
            return false;
          }
      }
    }

    return harvestEncryptedOutput();
  }

  constexpr static uint32_t maxPlaintextEncryptionBytesPerSendKick = (64u * 1024u);

  bool flushPlaintextQueue(void)
  {
    // A Ring send kick encrypts one bounded plaintext chunk. On a retry, the
    // unconsumed wBuffer head and its exact byte count remain unchanged.
    const uint32_t plaintextBytes = uint32_t(std::min<uint64_t>(
        wBuffer.outstandingBytes(), maxPlaintextEncryptionBytesPerSendKick));
    if (plaintextBytes == 0)
    {
      return harvestEncryptedOutput();
    }

    int consumed = SSL_write(ssl, wBuffer.pHead(), plaintextBytes);
    if (consumed > 0)
    {
      wBuffer.consume(uint32_t(consumed), false);
      return harvestEncryptedOutput();
    }

    switch (SSL_get_error(ssl, consumed))
    {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        {
          return harvestEncryptedOutput();
        }
      default:
        {
          encryptedWBuffer.reset();
          wBuffer.clear();
          return false;
        }
    }
  }

public:

  bool tlsPeerVerified = false;
  uint128_t tlsPeerUUID = 0;

  // These exact public descriptors are bound to the authenticated Noise
  // transcript. Credential owners use them to fence a live stream after a
  // rotation/revocation; a UUID alone cannot distinguish successive keys.
  // Returned views belong to this stream and must not survive reset/reuse.
  bool authenticatedTransportAEGISPreludes(const String *&local, const String *&peer) const
  {
    local = peer = nullptr;
    if (!aegisEnabled || !aegisSession.authenticated() || !tlsPeerVerified ||
        aegisLocalPrelude.empty() || aegisPeerPrelude.empty()) return false;
    local = &aegisLocalPrelude;
    peer = &aegisPeerPrelude;
    return true;
  }

  // The existing stream remains the sole send/receive owner. This explicit
  // entry point is used only after credential policy has authorized both
  // canonical peer identities and the PSK; there is no TLS/plaintext fallback.
  bool beginTransportAEGIS(bool isServer, const uint8_t psk[32], const String& credentialContext,
                           uint128_t localUUID, uint128_t expectedPeerUUID)
  {
    resetTransportState(false);
    aegisEnabled = true;
    aegisInitiator = !isServer;
    return startTransportAEGISKeys(psk, credentialContext, localUUID, expectedPeerUUID);
  }

  // Only public lookup hints are sent here. The credential owner must reject
  // unknown/stale/revoked claims in the resolver; neither a prelude nor a
  // successful lookup authenticates the peer. Both exact preludes are bound
  // to the ensuing fresh Noise handshake and AEGIS confirmation.
  bool beginTransportAEGISWithPrelude(bool isServer, uint128_t localUUID,
                                      const String& localPublicPrelude, AEGISPeerResolver resolver)
  {
    resetTransportState(false);
    aegisEnabled = true;
    aegisInitiator = !isServer;
    aegisLocalUUID = localUUID;
    aegisPeerResolved = false;
    if (localUUID == 0 || localPublicPrelude.empty() || localPublicPrelude.size() > 512 || !resolver ||
        !aegisLocalPrelude.reserve(localPublicPrelude.size())) return failTransportAEGIS();
    aegisLocalPrelude.append(localPublicPrelude);
    aegisPeerResolver = std::move(resolver);
    return true;
  }

  // Server-only variant for one listener that can terminate several approved
  // pair credentials. The selected local public prelude is returned only
  // after the exact bounded peer prelude resolves a credential.
  bool beginTransportAEGISWithDeferredServerPrelude(
      uint128_t localUUID, AEGISDeferredServerPreludeResolver resolver)
  {
    resetTransportState(false);
    aegisEnabled = true;
    aegisInitiator = false;
    aegisLocalUUID = localUUID;
    aegisPeerResolved = false;
    aegisDeferredServerPrelude = true;
    if (localUUID == 0 || !resolver) return failTransportAEGIS();
    aegisDeferredServerPreludeResolver = std::move(resolver);
    return true;
  }

  bool transportAEGISEnabled() const { return aegisEnabled; }
  bool transportEncryptionEnabled() const { return tlsEnabled || aegisEnabled; }
  bool isTransportNegotiated() const
  {
    return aegisEnabled ? aegisSession.authenticated() : TLSBase::isTLSNegotiated();
  }
  bool extractAuthenticatedPeerUUID(uint128_t& peerUUID) const
  {
    peerUUID = 0;
    if (aegisEnabled)
    {
      if (!aegisSession.authenticated() || !tlsPeerVerified) return false;
      peerUUID = tlsPeerUUID;
      return peerUUID != 0;
    }
    return ProdigyTransportTLSRuntime::extractPeerUUID(ssl, peerUUID);
  }

  const ProdigyOpenSSLTlsTicketBinding& transportTLSResumptionBinding(void) const
  {
    return tlsResumptionBinding;
  }

  bool transportTLSResumptionBindingConfigured(void) const
  {
    return tlsResumptionBinding.configured();
  }

  bool beginTransportTLS(bool isServer, const ProdigyOpenSSLTlsTicketBinding *resumptionBinding = nullptr)
  {
    if (aegisEnabled) return false;
    if (ProdigyTransportTLSRuntime::configured() == false)
    {
      std::fprintf(stderr,
                   "prodigy debug transport-tls-begin-skip stream=%p server=%d reason=runtime-unconfigured fd=%d fslot=%d\n",
                   static_cast<void *>(this),
                   int(isServer),
                   fd,
                   fslot);
      std::fflush(stderr);
      return false;
    }

    // A new TLS session always implies a new stream generation. Never carry
    // buffered plaintext or ciphertext across reconnect/accept reuse.
    rBuffer.clear();
    wBuffer.clear();
    encryptedWBuffer.clear();
    tlsEnabled = true;
    tlsPeerVerified = false;
    tlsPeerUUID = 0;
    tlsResumptionBinding = {};
    nEncryptedBytesToSend = 0;
    setupTLS(ProdigyTransportTLSRuntime::context(), isServer);
    if (ssl == nullptr)
    {
      std::fprintf(stderr,
                   "prodigy debug transport-tls-begin-fail stream=%p server=%d reason=setup-null-ssl fd=%d fslot=%d ctx=%p\n",
                   static_cast<void *>(this),
                   int(isServer),
                   fd,
                   fslot,
                   static_cast<void *>(ProdigyTransportTLSRuntime::context()));
      std::fflush(stderr);
      return false;
    }

    if (resumptionBinding != nullptr)
    {
      tlsResumptionBinding = *resumptionBinding;
      String failure = {};
      if (ProdigyTransportTLSRuntime::resumptionConfigured() == false)
      {
        failure.assign("transport tls resumption runtime unconfigured"_ctv);
      }
      else
      {
        (void)prodigyBindOpenSSLTlsResumptionTicketContext(ssl, &tlsResumptionBinding, &failure);
      }

      if (failure.size() > 0)
      {
        std::fprintf(stderr,
                     "prodigy debug transport-tls-resumption-bind-fail stream=%p server=%d reason=%s fd=%d fslot=%d ctx=%p\n",
                     static_cast<void *>(this),
                     int(isServer),
                     failure.c_str(),
                     fd,
                     fslot,
                     static_cast<void *>(ProdigyTransportTLSRuntime::context()));
        std::fflush(stderr);
        tlsResumptionBinding = {};
        resetTLS();
        tlsEnabled = false;
        return false;
      }
    }

#if PRODIGY_DEBUG
    std::fprintf(stderr,
                 "prodigy debug transport-tls-begin-ok stream=%p server=%d fd=%d fslot=%d ctx=%p\n",
                 static_cast<void *>(this),
                 int(isServer),
                 fd,
                 fslot,
                 static_cast<void *>(ProdigyTransportTLSRuntime::context()));
    std::fflush(stderr);
#endif
    return true;
  }

  bool transportTLSEnabled(void) const
  {
    return tlsEnabled;
  }

  bool hasBufferedTransportCiphertext(void) const
  {
    return encryptedWBuffer.outstandingBytes() > 0;
  }

  bool needsTransportTLSSendKick(void) const
  {
    if (aegisEnabled) return !aegisFailed && (hasBufferedTransportCiphertext() ||
        (!aegisLocalPrelude.empty() && !aegisPreludeWritten) ||
        (aegisPeerResolved && !aegisHandshakeWritten && (aegisInitiator || aegisHandshakeRead)) || aegisSession.confirmationNeeded() ||
        (aegisSession.authenticated() && wBuffer.outstandingBytes() > 0));
    return tlsEnabled && (isTLSNegotiated() == false || hasBufferedTransportCiphertext() || wBuffer.outstandingBytes() > 0);
  }

  bool prepareTransportTLSSend(void)
  {
    if (aegisEnabled) return prepareTransportAEGISSend();
    if (tlsEnabled == false)
    {
      return true;
    }

    if (ssl == nullptr)
    {
      return false;
    }

    if (hasBufferedTransportCiphertext())
    {
      nEncryptedBytesToSend = uint32_t(encryptedWBuffer.outstandingBytes());
      return true;
    }

    if (harvestEncryptedOutput() == false)
    {
      return false;
    }

    if (hasBufferedTransportCiphertext())
    {
      return true;
    }

    if (isTLSNegotiated() == false)
    {
      if (driveHandshake() == false)
      {
        return false;
      }

      if (isTLSNegotiated() == false || hasBufferedTransportCiphertext())
      {
        return true;
      }
    }

    if (wBuffer.outstandingBytes() > 0)
    {
      return flushPlaintextQueue();
    }

    return true;
  }

  bool decryptTransportTLS(uint32_t bytesReceived)
  {
    if (aegisEnabled) return decryptTransportAEGIS(bytesReceived);
    if (tlsEnabled == false)
    {
      return true;
    }

    return decryptFrom(rBuffer, bytesReceived);
  }

  void noteEncryptedBytesSent(uint32_t bytesSent)
  {
    consumeSentBytes(bytesSent, false);
  }

  uint32_t encryptedBytesToSend(void) const
  {
    return uint32_t(encryptedWBuffer.outstandingBytes());
  }

  uint32_t nBytesToSend(void) override
  {
    if (!transportEncryptionEnabled())
    {
      return TCPStream::nBytesToSend();
    }

    if (hasBufferedTransportCiphertext())
    {
      nEncryptedBytesToSend = uint32_t(encryptedWBuffer.outstandingBytes());
      return nEncryptedBytesToSend;
    }

    if (prepareTransportTLSSend() == false)
    {
      return 0;
    }

    return uint32_t(encryptedWBuffer.outstandingBytes());
  }

  uint8_t *pBytesToSend(void) override
  {
    if (!transportEncryptionEnabled())
    {
      return TCPStream::pBytesToSend();
    }

    if (encryptedWBuffer.outstandingBytes() == 0 && prepareTransportTLSSend() == false)
    {
      return nullptr;
    }

    return encryptedWBuffer.pHead();
  }

  uint64_t queuedSendOutstandingBytes(void) const override
  {
    if (!transportEncryptionEnabled())
    {
      return TCPStream::queuedSendOutstandingBytes();
    }

    return encryptedWBuffer.outstandingBytes();
  }

  void consumeSentBytes(uint32_t bytesSent, bool zeroIfConsumed) override
  {
    if (!transportEncryptionEnabled())
    {
      TCPStream::consumeSentBytes(bytesSent, zeroIfConsumed);
      return;
    }

    encryptedWBuffer.consume(bytesSent, zeroIfConsumed);
    nEncryptedBytesToSend = uint32_t(encryptedWBuffer.outstandingBytes());
  }

  void noteSendQueued(void) override
  {
    if (!transportEncryptionEnabled())
    {
      TCPStream::noteSendQueued();
      return;
    }

    encryptedWBuffer.noteSendQueued();
  }

  void noteSendCompleted(void) override
  {
    if (!transportEncryptionEnabled())
    {
      TCPStream::noteSendCompleted();
      return;
    }

    encryptedWBuffer.noteSendCompleted();
  }

  void clearQueuedSendBytes(void) override
  {
    if (aegisEnabled) { (void)failTransportAEGIS(); return; }
    if (!transportEncryptionEnabled())
    {
      TCPStream::clearQueuedSendBytes();
      return;
    }

    encryptedWBuffer.clear();
    wBuffer.clear();
    nEncryptedBytesToSend = 0;
  }

private:

  void resetTransportState(bool resetSocket)
  {
    uint64_t rBufferCapacity = rBuffer.tentativeCapacity();
    uint64_t wBufferCapacity = wBuffer.tentativeCapacity();
    uint64_t encryptedWBufferCapacity = encryptedWBuffer.tentativeCapacity();

    if (aegisEnabled)
    {
      clearAEGISBuffer(rBuffer);
      clearAEGISBuffer(wBuffer);
      clearAEGISBuffer(aegisInbound);
    }
    aegisSession.reset();
    aegisInbound.reset();
    aegisEnabled = aegisFailed = aegisInitiator = aegisHandshakeWritten = aegisHandshakeRead = false;
    aegisPreludeWritten = false;
    aegisPeerResolved = true;
    aegisLocalUUID = 0;
    aegisExpectedPeerUUID = 0;
    aegisLocalPrelude.reset();
    aegisPeerPrelude.reset();
    aegisDeferredServerPrelude = false;
    aegisPeerResolver = {};
    aegisDeferredServerPreludeResolver = {};
    if (resetSocket) TCPStream::reset();
    else Stream::reset();
    if (rBufferCapacity > 0)
    {
      rBuffer.reserve(rBufferCapacity);
    }
    if (wBufferCapacity > 0)
    {
      wBuffer.reserve(wBufferCapacity);
    }
    destroyTLS();

    tlsEnabled = false;
    tlsPeerVerified = false;
    tlsPeerUUID = 0;
    tlsResumptionBinding = {};
    nEncryptedBytesToSend = 0;
    encryptedWBuffer.reset();
    if (encryptedWBufferCapacity > 0)
    {
      encryptedWBuffer.reserve(encryptedWBufferCapacity);
    }
  }

public:

  void reset(void) override { resetTransportState(true); }

  void recreateSocket(void) override
  {
    SocketBase::recreateSocket();
  }
};
