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
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {
constexpr static const char *kOpenPayload = "wormhole-open";
constexpr static int kPollTimeoutMs = 1000;

void appendTrace(const char *stage, const char *detail = nullptr)
{
  int fd = open("/wormhole_matrix_probe_trace.log", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
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

std::string wormholeLabel(const Wormhole& wormhole)
{
  std::string label = wormhole.externalAddress.is6 ? "ipv6" : "ipv4";
  label += (wormhole.layer4 == IPPROTO_TCP) ? "-tcp" : "-udp";
  return label;
}
} // namespace

class WormholeMatrixProbeContainer final : public NeuronHubDispatch {
private:

  class Listener {
  public:

    Wormhole wormhole;
    int fd = -1;
    bool done = false;
    std::string label;
  };

  std::unique_ptr<NeuronHub> neuronHub;
  std::vector<Listener> listeners;
  std::atomic<bool> stopRequested {false};

  static bool configureReuse(int fd, std::string& failure)
  {
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0)
    {
      failure = "setsockopt_reuseaddr_failed";
      return false;
    }

    return true;
  }

  static bool bindListener(Listener& listener, std::string& failure)
  {
    const bool isIPv6 = listener.wormhole.externalAddress.is6;
    const int family = isIPv6 ? AF_INET6 : AF_INET;
    const int type = listener.wormhole.layer4 == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM;
    int fd = socket(family, type | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
      failure = "socket_failed";
      return false;
    }

    if (configureReuse(fd, failure) == false)
    {
      close(fd);
      return false;
    }

    if (isIPv6)
    {
      int only = 1;
      (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only));

      struct sockaddr_in6 bindAddress = {};
      bindAddress.sin6_family = AF_INET6;
      bindAddress.sin6_addr = in6addr_any;
      bindAddress.sin6_port = htons(listener.wormhole.containerPort);
      if (bind(fd, reinterpret_cast<const struct sockaddr *>(&bindAddress), sizeof(bindAddress)) != 0)
      {
        failure = "bind_ipv6_failed";
        close(fd);
        return false;
      }
    }
    else
    {
      struct sockaddr_in bindAddress = {};
      bindAddress.sin_family = AF_INET;
      bindAddress.sin_addr.s_addr = htonl(INADDR_ANY);
      bindAddress.sin_port = htons(listener.wormhole.containerPort);
      if (bind(fd, reinterpret_cast<const struct sockaddr *>(&bindAddress), sizeof(bindAddress)) != 0)
      {
        failure = "bind_ipv4_failed";
        close(fd);
        return false;
      }
    }

    if (listener.wormhole.layer4 == IPPROTO_TCP && listen(fd, 16) != 0)
    {
      failure = "listen_failed";
      close(fd);
      return false;
    }

    listener.fd = fd;
    return true;
  }

  bool prepareListeners(std::string& failure)
  {
    if (!neuronHub)
    {
      failure = "missing_neuron_hub";
      return false;
    }

    if (neuronHub->parameters.wormholes.empty())
    {
      failure = "missing_wormholes";
      return false;
    }

    listeners.clear();
    listeners.reserve(neuronHub->parameters.wormholes.size());

    for (const Wormhole& wormhole : neuronHub->parameters.wormholes)
    {
      if (wormhole.externalAddress.isNull() || wormhole.externalPort == 0 || wormhole.containerPort == 0 || (wormhole.layer4 != IPPROTO_UDP && wormhole.layer4 != IPPROTO_TCP))
      {
        failure = "invalid_wormhole";
        return false;
      }

      Listener listener = {};
      listener.wormhole = wormhole;
      listener.label = wormholeLabel(wormhole);
      if (bindListener(listener, failure) == false)
      {
        return false;
      }

      char detail[160] = {};
      std::snprintf(detail,
                    sizeof(detail),
                    "%s external=%u container=%u",
                    listener.label.c_str(),
                    unsigned(wormhole.externalPort),
                    unsigned(wormhole.containerPort));
      appendTrace("probe.listen", detail);
      listeners.push_back(listener);
    }

    return true;
  }

  bool handleUDP(Listener& listener)
  {
    char buffer[512] = {};
    sockaddr_storage source = {};
    socklen_t sourceLen = sizeof(source);
    ssize_t received = recvfrom(listener.fd, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&source), &sourceLen);
    if (received <= 0)
    {
      appendTrace("probe.udp.recv_failed", listener.label.c_str());
      return false;
    }

    if (std::string_view(buffer, size_t(received)) != kOpenPayload)
    {
      appendTrace("probe.udp.bad_payload", listener.label.c_str());
      return false;
    }

    std::string reply = "wormhole-ok:";
    reply += listener.label;
    ssize_t sent = sendto(listener.fd, reply.data(), reply.size(), MSG_NOSIGNAL, reinterpret_cast<const struct sockaddr *>(&source), sourceLen);
    if (sent != static_cast<ssize_t>(reply.size()))
    {
      appendTrace("probe.udp.send_failed", listener.label.c_str());
      return false;
    }

    appendTrace("probe.udp.ok", listener.label.c_str());
    listener.done = true;
    return true;
  }

  bool handleTCP(Listener& listener)
  {
    sockaddr_storage source = {};
    socklen_t sourceLen = sizeof(source);
    int accepted = accept4(listener.fd, reinterpret_cast<struct sockaddr *>(&source), &sourceLen, SOCK_CLOEXEC);
    if (accepted < 0)
    {
      appendTrace("probe.tcp.accept_failed", listener.label.c_str());
      return false;
    }

    char buffer[512] = {};
    ssize_t received = recv(accepted, buffer, sizeof(buffer), 0);
    if (received <= 0 || std::string_view(buffer, size_t(received)) != kOpenPayload)
    {
      appendTrace("probe.tcp.bad_payload", listener.label.c_str());
      close(accepted);
      return false;
    }

    std::string reply = "wormhole-ok:";
    reply += listener.label;
    ssize_t sent = send(accepted, reply.data(), reply.size(), MSG_NOSIGNAL);
    close(accepted);
    if (sent != static_cast<ssize_t>(reply.size()))
    {
      appendTrace("probe.tcp.send_failed", listener.label.c_str());
      return false;
    }

    appendTrace("probe.tcp.ok", listener.label.c_str());
    listener.done = true;
    return true;
  }

  void serveProbes(void)
  {
    appendTrace("probe.serve.begin");

    while (stopRequested.load(std::memory_order_relaxed) == false)
    {
      size_t remaining = 0;
      std::vector<pollfd> pollfds;
      pollfds.reserve(listeners.size());

      for (Listener& listener : listeners)
      {
        if (listener.done == false)
        {
          remaining += 1;
          pollfd descriptor = {};
          descriptor.fd = listener.fd;
          descriptor.events = POLLIN;
          pollfds.push_back(descriptor);
        }
      }

      if (remaining == 0)
      {
        appendTrace("probe.all_ok");
        return;
      }

      int rc = poll(pollfds.data(), pollfds.size(), kPollTimeoutMs);
      if (rc < 0)
      {
        appendTrace("probe.poll_failed", strerror(errno));
        return;
      }

      if (rc == 0)
      {
        continue;
      }

      size_t descriptorIndex = 0;
      for (Listener& listener : listeners)
      {
        if (listener.done)
        {
          continue;
        }

        if (descriptorIndex >= pollfds.size())
        {
          appendTrace("probe.poll_index_failed");
          return;
        }

        const short revents = pollfds[descriptorIndex].revents;
        descriptorIndex += 1;
        if ((revents & POLLIN) == 0)
        {
          continue;
        }

        if (listener.wormhole.layer4 == IPPROTO_UDP)
        {
          (void)handleUDP(listener);
        }
        else
        {
          (void)handleTCP(listener);
        }
      }
    }
  }

public:

  void beginShutdown(void) override
  {
    stopRequested.store(true, std::memory_order_relaxed);
  }

  void endOfDynamicArgs(void) override
  {
  }

  void prepare(int argc, char *argv[])
  {
    int truncateFD = open("/wormhole_matrix_probe_trace.log", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (truncateFD >= 0)
    {
      close(truncateFD);
    }

    Ring::createRing(64, 128, 512, 128, -1, -1, 0);

    neuronHub = std::make_unique<NeuronHub>(this);
    neuronHub->fillFromMainArgs(argc, argv);
    neuronHub->afterRing();

    std::string failure;
    if (prepareListeners(failure) == false)
    {
      appendTrace("probe.fail", failure.c_str());
      basics_log("WormholeMatrixProbeContainer::prepare failed detail=%s\n", failure.c_str());
      std::fflush(stdout);
      std::fflush(stderr);
      std::exit(EXIT_FAILURE);
    }

    neuronHub->signalReady();
    neuronHub->signalRuntimeReady();

    std::thread([this] {
      serveProbes();
    }).detach();
  }

  void start(void)
  {
    Ring::start();
  }
};

int main(int argc, char *argv[])
{
  WormholeMatrixProbeContainer container;
  container.prepare(argc, argv);
  container.start();
  return 0;
}
