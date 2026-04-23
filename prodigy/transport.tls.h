#pragma once

#include <services/vault.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/tls.h>

class ProdigyTransportTLSMaterial
{
public:

   uint64_t generation = 0;
   String clusterRootCertPem;
   String clusterRootKeyPem;
   String localCertPem;
   String localKeyPem;

   bool configured(void) const
   {
      return clusterRootCertPem.size() > 0
         && localCertPem.size() > 0
         && localKeyPem.size() > 0;
   }

   bool canMintForCluster(void) const
   {
      return configured() && clusterRootKeyPem.size() > 0;
   }

   bool operator==(const ProdigyTransportTLSMaterial& other) const
   {
      return generation == other.generation
         && clusterRootCertPem.equals(other.clusterRootCertPem)
         && clusterRootKeyPem.equals(other.clusterRootKeyPem)
         && localCertPem.equals(other.localCertPem)
         && localKeyPem.equals(other.localKeyPem);
   }

   bool operator!=(const ProdigyTransportTLSMaterial& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, ProdigyTransportTLSMaterial& material)
{
   serializer.value8b(material.generation);
   serializer.text1b(material.clusterRootCertPem, UINT32_MAX);
   serializer.text1b(material.clusterRootKeyPem, UINT32_MAX);
   serializer.text1b(material.localCertPem, UINT32_MAX);
   serializer.text1b(material.localKeyPem, UINT32_MAX);
}

class ProdigyTransportTLSBootstrap
{
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

template <typename S>
static void serialize(S&& serializer, ProdigyTransportTLSBootstrap& bootstrap)
{
   serializer.value16b(bootstrap.uuid);
   serializer.object(bootstrap.transport);
}

class ProdigyTransportTLSRuntime
{
private:

   static inline SSL_CTX *ctx = nullptr;
   static inline ProdigyTransportTLSBootstrap bootstrap = {};

public:

   static void clear(void)
   {
      if (ctx)
      {
         SSL_CTX_free(ctx);
         ctx = nullptr;
      }

      bootstrap = {};
   }

   static bool configure(const ProdigyTransportTLSBootstrap& newBootstrap, String *failure = nullptr)
   {
      if (failure) failure->clear();
      if (newBootstrap.configured() == false)
      {
         if (failure) failure->assign("transport tls bootstrap incomplete"_ctv);
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
         if (failure) failure->assign("failed to build transport tls context"_ctv);
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
         if (failure) failure->assign("failed to harden transport tls context"_ctv);
         return false;
      }

      clear();
      ctx = newCtx;
      bootstrap = newBootstrap;
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

class ProdigyTransportTLSStream : public TCPStream, public TLSBase
{
private:

   bool tlsEnabled = false;
   StreamBuffer encryptedWBuffer;

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

   bool flushPlaintextQueue(void)
   {
      while (wBuffer.outstandingBytes() > 0)
      {
         int consumed = SSL_write(ssl, wBuffer.pHead(), wBuffer.outstandingBytes());
         if (consumed > 0)
         {
            wBuffer.consume(consumed, false);
            continue;
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

      return harvestEncryptedOutput();
   }

public:

   bool tlsPeerVerified = false;
   uint128_t tlsPeerUUID = 0;

   bool beginTransportTLS(bool isServer)
   {
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

      std::fprintf(stderr,
         "prodigy debug transport-tls-begin-ok stream=%p server=%d fd=%d fslot=%d ctx=%p\n",
         static_cast<void *>(this),
         int(isServer),
         fd,
         fslot,
         static_cast<void *>(ProdigyTransportTLSRuntime::context()));
      std::fflush(stderr);
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
      return tlsEnabled
         && (isTLSNegotiated() == false
            || hasBufferedTransportCiphertext()
            || wBuffer.outstandingBytes() > 0);
   }

   bool prepareTransportTLSSend(void)
   {
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
      if (tlsEnabled == false)
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
      if (tlsEnabled == false)
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
      if (tlsEnabled == false)
      {
         return TCPStream::queuedSendOutstandingBytes();
      }

      return encryptedWBuffer.outstandingBytes();
   }

   void consumeSentBytes(uint32_t bytesSent, bool zeroIfConsumed) override
   {
      if (tlsEnabled == false)
      {
         TCPStream::consumeSentBytes(bytesSent, zeroIfConsumed);
         return;
      }

      encryptedWBuffer.consume(bytesSent, zeroIfConsumed);
      nEncryptedBytesToSend = uint32_t(encryptedWBuffer.outstandingBytes());
   }

   void noteSendQueued(void) override
   {
      if (tlsEnabled == false)
      {
         TCPStream::noteSendQueued();
         return;
      }

      encryptedWBuffer.noteSendQueued();
   }

   void noteSendCompleted(void) override
   {
      if (tlsEnabled == false)
      {
         TCPStream::noteSendCompleted();
         return;
      }

      encryptedWBuffer.noteSendCompleted();
   }

   void clearQueuedSendBytes(void) override
   {
      if (tlsEnabled == false)
      {
         TCPStream::clearQueuedSendBytes();
         return;
      }

      encryptedWBuffer.clear();
      wBuffer.clear();
      nEncryptedBytesToSend = 0;
   }

   void reset(void) override
   {
      uint64_t rBufferCapacity = rBuffer.tentativeCapacity();
      uint64_t wBufferCapacity = wBuffer.tentativeCapacity();
      uint64_t encryptedWBufferCapacity = encryptedWBuffer.tentativeCapacity();

      TCPStream::reset();
      if (rBufferCapacity > 0)
      {
         rBuffer.reserve(rBufferCapacity);
      }
      if (wBufferCapacity > 0)
      {
         wBuffer.reserve(wBufferCapacity);
      }
      if (ssl)
      {
         resetTLS();
      }

      tlsEnabled = false;
      tlsPeerVerified = false;
      tlsPeerUUID = 0;
      nEncryptedBytesToSend = 0;
      encryptedWBuffer.reset();
      if (encryptedWBufferCapacity > 0)
      {
         encryptedWBuffer.reserve(encryptedWBufferCapacity);
      }
   }

   void recreateSocket(void) override
   {
      SocketBase::recreateSocket();
   }
};
