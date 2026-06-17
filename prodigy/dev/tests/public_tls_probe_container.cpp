#include <networking/includes.h>
#include <services/debug.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/pool.h>
#include <networking/ring.h>
#include <prodigy/neuron.hub.h>

#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

namespace {

constexpr static const char *kEvidencePath = "/readytrace.log";
constexpr static const char *kResponse = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nprodigy-public\n";

void appendEvidence(const char *stage, const char *detail = nullptr)
{
  int fd = open(kEvidencePath, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
  if (fd < 0)
  {
    return;
  }
  if (stage != nullptr)
  {
    (void)write(fd, stage, std::strlen(stage));
  }
  if (detail != nullptr && *detail)
  {
    (void)write(fd, " ", 1);
    (void)write(fd, detail, std::strlen(detail));
  }
  (void)write(fd, "\n", 1);
  close(fd);
}

BIO *bioFromString(const String& pem)
{
  if (pem.size() == 0 || pem.size() > INT_MAX)
  {
    return nullptr;
  }
  return BIO_new_mem_buf(reinterpret_cast<const char *>(pem.data()), int(pem.size()));
}

class PublicTLSProbeContainer final : public NeuronHubDispatch {
private:

  std::unique_ptr<NeuronHub> neuronHub;
  CredentialBundle credentials;
  std::mutex tlsMutex;
  std::thread tlsThread;
  std::atomic<bool> stopRequested {false};
  SSL_CTX *tlsContext = nullptr;
  int listenFD = -1;
  uint16_t listenPort = 0;
  bool readySignaled = false;

  const TlsIdentity *currentIdentity(void) const
  {
    for (const TlsIdentity& identity : credentials.tlsIdentities)
    {
      if (identity.certPem.size() > 0 && identity.keyPem.size() > 0)
      {
        return &identity;
      }
    }
    return nullptr;
  }

  static bool addChain(SSL_CTX *ctx, const String& chainPem, std::string& failure)
  {
    if (chainPem.size() == 0)
    {
      return true;
    }
    BIO *bio = bioFromString(chainPem);
    if (bio == nullptr)
    {
      failure = "chain_bio_failed";
      return false;
    }
    for (;;)
    {
      X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
      if (cert == nullptr)
      {
        ERR_clear_error();
        BIO_free(bio);
        return true;
      }
      if (SSL_CTX_add_extra_chain_cert(ctx, cert) != 1)
      {
        X509_free(cert);
        BIO_free(bio);
        failure = "chain_install_failed";
        return false;
      }
    }
  }

  static SSL_CTX *buildContext(const TlsIdentity& identity, std::string& failure)
  {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    BIO *certBio = bioFromString(identity.certPem);
    BIO *keyBio = bioFromString(identity.keyPem);
    X509 *cert = certBio == nullptr ? nullptr : PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    EVP_PKEY *key = keyBio == nullptr ? nullptr : PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    bool ok = ctx != nullptr &&
              cert != nullptr &&
              key != nullptr &&
              SSL_CTX_use_certificate(ctx, cert) == 1 &&
              SSL_CTX_use_PrivateKey(ctx, key) == 1 &&
              SSL_CTX_check_private_key(ctx) == 1 &&
              addChain(ctx, identity.chainPem, failure);
    if (certBio != nullptr)
    {
      BIO_free(certBio);
    }
    if (keyBio != nullptr)
    {
      BIO_free(keyBio);
    }
    if (cert != nullptr)
    {
      X509_free(cert);
    }
    if (key != nullptr)
    {
      EVP_PKEY_free(key);
    }
    if (ok == false)
    {
      if (failure.empty())
      {
        failure = "tls_context_failed";
      }
      if (ctx != nullptr)
      {
        SSL_CTX_free(ctx);
      }
      return nullptr;
    }
    return ctx;
  }

  bool refreshContextLocked(std::string& failure)
  {
    const TlsIdentity *identity = currentIdentity();
    if (identity == nullptr)
    {
      failure = "missing_tls_identity";
      return false;
    }
    SSL_CTX *next = buildContext(*identity, failure);
    if (next == nullptr)
    {
      return false;
    }
    if (tlsContext != nullptr)
    {
      SSL_CTX_free(tlsContext);
    }
    tlsContext = next;

    char detail[256] = {};
    std::snprintf(detail,
                  sizeof(detail),
                  "identity=%.*s generation=%llu",
                  int(identity->name.size()),
                  reinterpret_cast<const char *>(identity->name.data()),
                  (unsigned long long)identity->generation);
    appendEvidence("tls.identity.ready", detail);
    return true;
  }

  bool openListener(void)
  {
    for (const Wormhole& wormhole : neuronHub->parameters.wormholes)
    {
      if (wormhole.layer4 == IPPROTO_TCP && wormhole.containerPort != 0)
      {
        listenPort = wormhole.containerPort;
        break;
      }
    }
    if (listenPort == 0)
    {
      appendEvidence("tls.listen.failed", "missing_tcp_wormhole");
      return false;
    }

    listenFD = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listenFD < 0)
    {
      appendEvidence("tls.listen.failed", "socket");
      return false;
    }
    int one = 1;
    int zero = 0;
    (void)setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)setsockopt(listenFD, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));

    sockaddr_in6 address = {};
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(listenPort);
    if (bind(listenFD, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
        listen(listenFD, 64) != 0)
    {
      appendEvidence("tls.listen.failed", "bind_or_listen");
      close(listenFD);
      listenFD = -1;
      return false;
    }

    char detail[64] = {};
    std::snprintf(detail, sizeof(detail), "port=%u", unsigned(listenPort));
    appendEvidence("tls.listen.ready", detail);
    return true;
  }

  SSL_CTX *borrowContext(void)
  {
    std::lock_guard<std::mutex> lock(tlsMutex);
    if (tlsContext != nullptr)
    {
      SSL_CTX_up_ref(tlsContext);
    }
    return tlsContext;
  }

  void handleClient(int fd)
  {
    SSL_CTX *ctx = borrowContext();
    if (ctx == nullptr)
    {
      close(fd);
      return;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);
    if (ssl != nullptr)
    {
      SSL_set_fd(ssl, fd);
      if (SSL_accept(ssl) == 1)
      {
        pollfd requestPoll = {fd, POLLIN, 0};
        if (poll(&requestPoll, 1, 1000) > 0 && (requestPoll.revents & POLLIN))
        {
          char request[512];
          (void)SSL_read(ssl, request, sizeof(request));
        }
        if (SSL_write(ssl, kResponse, int(std::strlen(kResponse))) > 0)
        {
          appendEvidence("tls.write.ok");
        }
        else
        {
          appendEvidence("tls.write.failed");
        }
        appendEvidence("tls.handshake.ok");
      }
      else
      {
        appendEvidence("tls.handshake.failed");
      }
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    close(fd);
  }

  void serve(void)
  {
    pollfd pfd = {listenFD, POLLIN, 0};
    while (stopRequested.load(std::memory_order_relaxed) == false)
    {
      int ready = poll(&pfd, 1, 250);
      if (ready < 0 && errno == EINTR)
      {
        continue;
      }
      if (ready <= 0 || (pfd.revents & POLLIN) == 0)
      {
        continue;
      }
      int fd = accept4(listenFD, nullptr, nullptr, SOCK_CLOEXEC);
      if (fd >= 0)
      {
        handleClient(fd);
      }
    }
  }

public:

  ~PublicTLSProbeContainer()
  {
    beginShutdown();
    if (tlsThread.joinable())
    {
      tlsThread.join();
    }
    if (tlsContext != nullptr)
    {
      SSL_CTX_free(tlsContext);
    }
  }

  void beginShutdown(void) override
  {
    stopRequested.store(true, std::memory_order_relaxed);
    if (listenFD >= 0)
    {
      shutdown(listenFD, SHUT_RDWR);
      close(listenFD);
      listenFD = -1;
    }
  }

  void credentialsRefresh(const CredentialDelta& delta) override
  {
    std::string failure;
    bool refreshed = false;
    {
      std::lock_guard<std::mutex> lock(tlsMutex);
      applyCredentialDelta(credentials, delta);
      refreshed = refreshContextLocked(failure);
    }
    if (refreshed)
    {
      neuronHub->acknowledgeCredentialsRefresh();
    }
    else
    {
      appendEvidence("tls.identity.failed", failure.c_str());
    }
  }

  void signalReadyOnce(void)
  {
    if (neuronHub == nullptr || readySignaled)
    {
      return;
    }
    readySignaled = true;
    appendEvidence("probe.ready.signal");
    neuronHub->signalReady();
    neuronHub->signalRuntimeReady();
  }

  void endOfDynamicArgs(void) override
  {
    signalReadyOnce();
  }

  void prepare(int argc, char *argv[])
  {
    (void)std::signal(SIGPIPE, SIG_IGN);
    int evidenceFD = open(kEvidencePath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (evidenceFD >= 0)
    {
      close(evidenceFD);
    }

    appendEvidence("probe.prepare");
    Ring::createRing(64, 128, 512, 128, -1, -1, 0);
    appendEvidence("probe.ring.ready");
    appendEvidence("probe.hub.create");
    neuronHub = std::make_unique<NeuronHub>(this);
    appendEvidence("probe.params.load");
    neuronHub->fillFromMainArgs(argc, argv);
    appendEvidence("probe.params.ready");
    if (neuronHub->parameters.hasCredentialBundle)
    {
      credentials = neuronHub->parameters.credentialBundle;
    }
    if (openListener() == false)
    {
      std::exit(EXIT_FAILURE);
    }
    {
      std::string ignored;
      std::lock_guard<std::mutex> lock(tlsMutex);
      (void)refreshContextLocked(ignored);
    }
    tlsThread = std::thread([this]() {
      serve();
    });
    neuronHub->afterRing();
    signalReadyOnce();
  }

  void start(void)
  {
    Ring::start();
  }
};

} // namespace

int main(int argc, char *argv[])
{
  PublicTLSProbeContainer container;
  container.prepare(argc, argv);
  container.start();
  return 0;
}
