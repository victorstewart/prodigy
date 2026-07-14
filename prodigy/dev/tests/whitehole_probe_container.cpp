#include <limits.h>
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

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

namespace {
constexpr static auto kTargetAddressPath = "/whitehole-target-ip"_ctv;
constexpr static uint16_t kTargetPort = 32'101;
constexpr static const char *kOpenPayload = "whitehole-open";
constexpr static const char *kReplyPayload = "whitehole-ok";
constexpr static int kReplyTimeoutMs = 5000;
constexpr static int kSpoofGuardMs = 1200;

void appendTrace(const char *stage, const char *detail = nullptr)
{
  int fd = open("/whitehole_probe_trace.log", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
  if (fd < 0)
  {
    return;
  }

  if (stage && *stage)
  {
    (void)write(fd, stage, std::strlen(stage));
  }

  if (detail && *detail)
  {
    constexpr static char separator = ' ';
    (void)write(fd, &separator, 1);
    (void)write(fd, detail, std::strlen(detail));
  }

  constexpr static char newline = '\n';
  (void)write(fd, &newline, 1);
  close(fd);
}

bool waitReadable(int fd, int timeoutMs)
{
  struct pollfd descriptor = {};
  descriptor.fd = fd;
  descriptor.events = POLLIN;
  return poll(&descriptor, 1, timeoutMs) > 0 && (descriptor.revents & POLLIN);
}

bool loadTargetAddress(struct in_addr& address, String& failure)
{
  String text = {};
  Filesystem::openReadAtClose(-1, kTargetAddressPath, text);
  while (text.size() > 0 && (text[text.size() - 1] == '\n' || text[text.size() - 1] == '\r'))
  {
    text.resize(text.size() - 1);
  }

  if (text.size() == 0 || inet_pton(AF_INET, text.c_str(), &address) != 1)
  {
    failure = "invalid_target_address";
    return false;
  }

  return true;
}

String renderIPv4(const struct in_addr& address)
{
  char buffer[INET_ADDRSTRLEN] = {};
  if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr)
  {
    return String("invalid"_ctv);
  }

  return String(buffer);
}
} // namespace

class WhiteholeProbeContainer final : public NeuronHubDispatch {
private:

  std::unique_ptr<NeuronHub> neuronHub;

  bool runWhiteholeProbe(String& failure)
  {
    if (!neuronHub)
    {
      failure = "missing_neuron_hub";
      return false;
    }

    if (neuronHub->parameters.whiteholes.size() == 0)
    {
      failure = "missing_whitehole";
      return false;
    }

    const Whitehole& whitehole = neuronHub->parameters.whiteholes[0];
    if (whitehole.family != ExternalAddressFamily::ipv4 || whitehole.address.is6 || whitehole.hasAddress == false)
    {
      failure = "whitehole_must_be_ipv4";
      return false;
    }

    if (whitehole.sourcePort == 0 || whitehole.transport != ExternalAddressTransport::quic)
    {
      failure = "whitehole_requires_udp_source_port";
      return false;
    }

    struct in_addr targetAddress = {};
    if (loadTargetAddress(targetAddress, failure) == false)
    {
      return false;
    }

    int socketFD = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socketFD < 0)
    {
      failure = "socket_failed";
      appendTrace("probe.socket.fail", strerror(errno));
      return false;
    }

    int enabled = 1;
    if (setsockopt(socketFD, SOL_IP, IP_FREEBIND, &enabled, sizeof(enabled)) != 0)
    {
      failure = "freebind_failed";
      appendTrace("probe.freebind.fail", strerror(errno));
      close(socketFD);
      return false;
    }

    struct sockaddr_in bindAddress = {};
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_port = htons(whitehole.sourcePort);
    memcpy(&bindAddress.sin_addr.s_addr, &whitehole.address.v4, sizeof(bindAddress.sin_addr.s_addr));
    if (bind(socketFD, reinterpret_cast<const struct sockaddr *>(&bindAddress), sizeof(bindAddress)) != 0)
    {
      failure = "bind_failed";
      appendTrace("probe.bind.fail", strerror(errno));
      close(socketFD);
      return false;
    }

    String whiteholeAddress = renderIPv4(*reinterpret_cast<const struct in_addr *>(&whitehole.address.v4));
    appendTrace("probe.bind", whiteholeAddress.c_str());
    basics_log("probe.bind %s:%u\n", whiteholeAddress.c_str(), unsigned(whitehole.sourcePort));

    struct sockaddr_in target = {};
    target.sin_family = AF_INET;
    target.sin_port = htons(kTargetPort);
    target.sin_addr = targetAddress;

    appendTrace("probe.send.begin", renderIPv4(targetAddress).c_str());
    ssize_t sent = sendto(socketFD,
                          kOpenPayload,
                          std::strlen(kOpenPayload),
                          MSG_NOSIGNAL,
                          reinterpret_cast<const struct sockaddr *>(&target),
                          sizeof(target));
    if (sent != static_cast<ssize_t>(std::strlen(kOpenPayload)))
    {
      failure = "sendto_failed";
      appendTrace("probe.send.fail", strerror(errno));
      close(socketFD);
      return false;
    }

    if (waitReadable(socketFD, kReplyTimeoutMs) == false)
    {
      failure = "reply_timeout";
      appendTrace("probe.recv.timeout");
      close(socketFD);
      return false;
    }

    char buffer[256] = {};
    struct sockaddr_in replySource = {};
    socklen_t replySourceLen = sizeof(replySource);
    ssize_t received = recvfrom(socketFD,
                                buffer,
                                sizeof(buffer),
                                0,
                                reinterpret_cast<struct sockaddr *>(&replySource),
                                &replySourceLen);
    if (received <= 0)
    {
      failure = "recvfrom_failed";
      appendTrace("probe.recv.fail", failure.c_str());
      close(socketFD);
      return false;
    }

    if (replySource.sin_addr.s_addr != targetAddress.s_addr || replySource.sin_port != htons(kTargetPort))
    {
      failure = "reply_source_mismatch";
      appendTrace("probe.recv.bad_source", failure.c_str());
      close(socketFD);
      return false;
    }

    if (size_t(received) != std::strlen(kReplyPayload) ||
        memcmp(buffer, kReplyPayload, size_t(received)) != 0)
    {
      failure = "reply_payload_mismatch";
      appendTrace("probe.recv.bad_payload", failure.c_str());
      close(socketFD);
      return false;
    }

    appendTrace("probe.recv.ok");

    if (waitReadable(socketFD, kSpoofGuardMs))
    {
      struct sockaddr_in unexpected = {};
      socklen_t unexpectedLen = sizeof(unexpected);
      received = recvfrom(socketFD,
                          buffer,
                          sizeof(buffer),
                          0,
                          reinterpret_cast<struct sockaddr *>(&unexpected),
                          &unexpectedLen);

      char detail[192] = {};
      std::snprintf(detail,
                    sizeof(detail),
                    "unexpected_second_reply from=%s:%u bytes=%lld",
                    renderIPv4(unexpected.sin_addr).c_str(),
                    unsigned(ntohs(unexpected.sin_port)),
                    static_cast<long long>(received));
      failure = detail;
      appendTrace("probe.recv.unexpected", detail);
      close(socketFD);
      return false;
    }

    appendTrace("probe.spoof_guard.ok");
    close(socketFD);
    return true;
  }

public:

  void beginShutdown(void) override
  {
  }

  void endOfDynamicArgs(void) override
  {
  }

  void prepare(int argc, char *argv[])
  {
    appendTrace("probe.start");

    Ring::createRing(64, 128, 512, 128, -1, -1, 0);

    neuronHub = std::make_unique<NeuronHub>(this);
    neuronHub->fillFromMainArgs(argc, argv);
    neuronHub->afterRing();

    String failure;
    if (runWhiteholeProbe(failure) == false)
    {
      appendTrace("probe.fail", failure.c_str());
      basics_log("WhiteholeProbeContainer::prepare failed detail=%s\n", failure.c_str());
      std::fflush(stdout);
      std::fflush(stderr);
      std::exit(EXIT_FAILURE);
    }

    appendTrace("probe.success");
    basics_log("probe.success\n");
    std::fflush(stdout);
    std::fflush(stderr);
    neuronHub->signalReady();
  }

  void start(void)
  {
    Ring::start();
  }
};

int main(int argc, char *argv[])
{
  WhiteholeProbeContainer container;
  container.prepare(argc, argv);
  container.start();
  return 0;
}
