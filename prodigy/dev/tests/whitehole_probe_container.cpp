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
#include <netdb.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
   static constexpr const char *kTargetHost = "whitehole-target.test";
   static constexpr uint16_t kTargetPort = 32101;
   static constexpr const char *kOpenPayload = "whitehole-open";
   static constexpr const char *kReplyPayload = "whitehole-ok";
   static constexpr int kReplyTimeoutMs = 5000;
   static constexpr int kSpoofGuardMs = 1200;

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
         static constexpr char separator = ' ';
         (void)write(fd, &separator, 1);
         (void)write(fd, detail, std::strlen(detail));
      }

      static constexpr char newline = '\n';
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

   bool resolveIPv4Host(const char *hostname, struct in_addr& address, std::string& failure)
   {
      struct addrinfo hints = {};
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;

      struct addrinfo *result = nullptr;
      int rc = getaddrinfo(hostname, nullptr, &hints, &result);
      if (rc != 0 || result == nullptr)
      {
         failure = "getaddrinfo_failed";
         return false;
      }

      const struct sockaddr_in *ipv4 = reinterpret_cast<const struct sockaddr_in *>(result->ai_addr);
      address = ipv4->sin_addr;
      freeaddrinfo(result);
      return true;
   }

   std::string renderIPv4(const struct in_addr& address)
   {
      char buffer[INET_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr)
      {
         return "invalid";
      }

      return buffer;
   }
}

class WhiteholeProbeContainer final : public NeuronHubDispatch
{
private:

   std::unique_ptr<NeuronHub> neuronHub;

   bool runWhiteholeProbe(std::string& failure)
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
      if (resolveIPv4Host(kTargetHost, targetAddress, failure) == false)
      {
         return false;
      }

      UDPSocket socket;
      socket.setIPVersion(AF_INET);
      socket.setSaddr(whitehole.address, whitehole.sourcePort);
      socket.bind();

      std::string whiteholeAddress = renderIPv4(*reinterpret_cast<const struct in_addr *>(&whitehole.address.v4));
      appendTrace("probe.bind", whiteholeAddress.c_str());
      basics_log("probe.bind %s:%u\n", whiteholeAddress.c_str(), unsigned(whitehole.sourcePort));

      struct sockaddr_in target = {};
      target.sin_family = AF_INET;
      target.sin_port = htons(kTargetPort);
      target.sin_addr = targetAddress;

      appendTrace("probe.send.begin", renderIPv4(targetAddress).c_str());
      ssize_t sent = sendto(socket.fd,
         kOpenPayload,
         std::strlen(kOpenPayload),
         MSG_NOSIGNAL,
         reinterpret_cast<const struct sockaddr *>(&target),
         sizeof(target));
      if (sent != static_cast<ssize_t>(std::strlen(kOpenPayload)))
      {
         failure = "sendto_failed";
         appendTrace("probe.send.fail", failure.c_str());
         socket.close();
         return false;
      }

      if (waitReadable(socket.fd, kReplyTimeoutMs) == false)
      {
         failure = "reply_timeout";
         appendTrace("probe.recv.timeout");
         socket.close();
         return false;
      }

      char buffer[256] = {};
      struct sockaddr_in replySource = {};
      socklen_t replySourceLen = sizeof(replySource);
      ssize_t received = recvfrom(socket.fd,
         buffer,
         sizeof(buffer),
         0,
         reinterpret_cast<struct sockaddr *>(&replySource),
         &replySourceLen);
      if (received <= 0)
      {
         failure = "recvfrom_failed";
         appendTrace("probe.recv.fail", failure.c_str());
         socket.close();
         return false;
      }

      if (replySource.sin_addr.s_addr != targetAddress.s_addr || replySource.sin_port != htons(kTargetPort))
      {
         failure = "reply_source_mismatch";
         appendTrace("probe.recv.bad_source", failure.c_str());
         socket.close();
         return false;
      }

      if (std::string_view(buffer, size_t(received)) != kReplyPayload)
      {
         failure = "reply_payload_mismatch";
         appendTrace("probe.recv.bad_payload", failure.c_str());
         socket.close();
         return false;
      }

      appendTrace("probe.recv.ok");

      if (waitReadable(socket.fd, kSpoofGuardMs))
      {
         struct sockaddr_in unexpected = {};
         socklen_t unexpectedLen = sizeof(unexpected);
         received = recvfrom(socket.fd,
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
         socket.close();
         return false;
      }

      appendTrace("probe.spoof_guard.ok");
      socket.close();
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
      int truncateFD = open("/whitehole_probe_trace.log", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
      if (truncateFD >= 0)
      {
         close(truncateFD);
      }

      Ring::createRing(64, 128, 512, 128, -1, -1, 0);

      neuronHub = std::make_unique<NeuronHub>(this);
      neuronHub->fillFromMainArgs(argc, argv);
      neuronHub->afterRing();

      std::string failure;
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
