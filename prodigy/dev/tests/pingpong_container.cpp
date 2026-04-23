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
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <memory>
#include <netdb.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/time.h>
#include <thread>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PRODIGY_PINGPONG_DEFAULT_PORT
#define PRODIGY_PINGPONG_DEFAULT_PORT 19090
#endif

#ifndef PRODIGY_PINGPONG_DISABLE_SERVER
#define PRODIGY_PINGPONG_DISABLE_SERVER 0
#endif

#ifndef PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS
#define PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS 0
#endif

#ifndef PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS_DUALSTACK
#define PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS_DUALSTACK 1
#endif

static uint64_t pingPongQueueWaitFineBucketMetricKey(void)
{
   static const uint64_t key = ProdigyMetrics::metricKeyForName("runtime.ingress.queue_wait_us.fine.bucket.10"_ctv);
   return key;
}

static uint64_t pingPongHandlerFineBucketMetricKey(void)
{
   static const uint64_t key = ProdigyMetrics::metricKeyForName("runtime.ingress.handler_us.fine.bucket.9"_ctv);
   return key;
}

class PingPongServer : public RingMultiplexer
{
private:

   std::atomic<bool>& running;
   TCPSocket listener;
   std::vector<TCPStream *> clients;
   uint16_t port = PRODIGY_PINGPONG_DEFAULT_PORT;
   bool listenerActive = false;
   static constexpr uint32_t maxLineBytes = 4096;
   static constexpr uint32_t initialClientBufferBytes = 4096;
   NeuronHub *metricsSink = nullptr;
   uint64_t requestMetricKey = 0;
   bool readyReassertedOnTraffic = false;

#if PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS == 1
   bool googleProbeComplete = false;
   bool googleProbeSuccess = false;
   String googleProbeDetail;
#endif

#if PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS == 1
   static void resetGoogleProbeTrace()
   {
      int fd = open("/google_probe_trace.log", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
      if (fd >= 0)
      {
         close(fd);
      }
   }

   static void appendGoogleProbeTrace(const char *stage, const char *detail = nullptr)
   {
      int fd = open("/google_probe_trace.log", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
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
         static constexpr const char *separator = " ";
         (void)write(fd, separator, 1);
         (void)write(fd, detail, std::strlen(detail));
      }

      static constexpr const char *newline = "\n";
      (void)write(fd, newline, 1);
      close(fd);
   }

   static void describeLocalSocket(TCPSocket& socket, char *buffer, size_t bufferSize)
   {
      if (bufferSize == 0)
      {
         return;
      }

      buffer[0] = '\0';

      struct sockaddr_storage localAddress = {};
      socklen_t localAddressLength = sizeof(localAddress);
      if (getsockname(socket.fd, reinterpret_cast<struct sockaddr *>(&localAddress), &localAddressLength) != 0)
      {
         std::snprintf(buffer, bufferSize, "local=getsockname_errno_%d", errno);
         return;
      }

      if (localAddress.ss_family == AF_INET)
      {
         const struct sockaddr_in *ipv4 = reinterpret_cast<const struct sockaddr_in *>(&localAddress);
         char localIP[INET_ADDRSTRLEN] = {};
         if (inet_ntop(AF_INET, &ipv4->sin_addr, localIP, sizeof(localIP)) == nullptr)
         {
            std::snprintf(buffer, bufferSize, "local=inet_ntop_errno_%d", errno);
            return;
         }

         std::snprintf(buffer, bufferSize, "local=%s:%u", localIP, unsigned(ntohs(ipv4->sin_port)));
         return;
      }

      if (localAddress.ss_family == AF_INET6)
      {
         const struct sockaddr_in6 *ipv6 = reinterpret_cast<const struct sockaddr_in6 *>(&localAddress);
         char localIP[INET6_ADDRSTRLEN] = {};
         if (inet_ntop(AF_INET6, &ipv6->sin6_addr, localIP, sizeof(localIP)) == nullptr)
         {
            std::snprintf(buffer, bufferSize, "local=inet_ntop6_errno_%d", errno);
            return;
         }

         std::snprintf(buffer, bufferSize, "local=[%s]:%u", localIP, unsigned(ntohs(ipv6->sin6_port)));
         return;
      }

      std::snprintf(buffer, bufferSize, "local=af_%d", int(localAddress.ss_family));
   }

   bool resolveGoogleIPv4FromHosts(struct in_addr& outAddress)
   {
      std::ifstream hostsFile("/etc/hosts");
      if (!hostsFile.is_open())
      {
         return false;
      }

      std::string line;
      while (std::getline(hostsFile, line))
      {
         if (line.empty() || line[0] == '#')
         {
            continue;
         }

         std::istringstream stream(line);
         std::string ipText;
         if (!(stream >> ipText))
         {
            continue;
         }

         std::string hostname;
         while (stream >> hostname)
         {
            if (!hostname.empty() && hostname[0] == '#')
            {
               break;
            }

            if (hostname == "www.google.com")
            {
               if (inet_pton(AF_INET, ipText.c_str(), &outAddress) == 1)
               {
                  return true;
               }
            }
         }
      }

      return false;
   }

   bool resolveGoogleIPv4(struct in_addr& outAddress)
   {
      return resolveGoogleIPv4FromHosts(outAddress);
   }

   bool resolveGoogleIPv6FromHosts(struct in6_addr& outAddress)
   {
      std::ifstream hostsFile("/etc/hosts");
      if (!hostsFile.is_open())
      {
         return false;
      }

      std::string line;
      while (std::getline(hostsFile, line))
      {
         if (line.empty() || line[0] == '#')
         {
            continue;
         }

         std::istringstream stream(line);
         std::string ipText;
         if (!(stream >> ipText))
         {
            continue;
         }

         std::string hostname;
         while (stream >> hostname)
         {
            if (!hostname.empty() && hostname[0] == '#')
            {
               break;
            }

            if (hostname == "www.google.com")
            {
               if (inet_pton(AF_INET6, ipText.c_str(), &outAddress) == 1)
               {
                  return true;
               }
            }
         }
      }

      return false;
   }

   bool resolveGoogleIPv6(struct in6_addr& outAddress)
   {
      return resolveGoogleIPv6FromHosts(outAddress);
   }

   bool probeGoogleAddress(const struct in_addr& googleAddress, String& detail)
   {
      char candidateIP[INET_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET, &googleAddress, candidateIP, sizeof(candidateIP)) == nullptr)
      {
         std::strncpy(candidateIP, "unknown", sizeof(candidateIP));
         candidateIP[sizeof(candidateIP) - 1] = '\0';
      }

      appendGoogleProbeTrace("probe4.candidate", candidateIP);

      TCPSocket socket;
      socket.setIPVersion(AF_INET);
      socket.setDaddr(&googleAddress, 80);
      socket.setNonBlocking();

      appendGoogleProbeTrace("probe4.connect.begin", candidateIP);
      int connectResult = socket.connect();
      appendGoogleProbeTrace("probe4.connect.end", candidateIP);
      if (connectResult != 0)
      {
         if (errno != EINPROGRESS)
         {
            char reason[224] = {};
            std::snprintf(reason, sizeof(reason), "connect_errno_%d_ip_%s", errno, candidateIP);
            detail.assign(reason);
            appendGoogleProbeTrace("probe4.connect.fail", reason);
            socket.close();
            return false;
         }

         struct pollfd pollDescriptor = {};
         pollDescriptor.fd = socket.fd;
         pollDescriptor.events = POLLOUT;

         int pollResult = poll(&pollDescriptor, 1, 5000);
         if (pollResult <= 0)
         {
            char localDescription[96] = {};
            describeLocalSocket(socket, localDescription, sizeof(localDescription));

            if (pollResult == 0)
            {
               char reason[224] = {};
               std::snprintf(reason, sizeof(reason), "connect_timeout_ip_%s_%s_revents_0x%x", candidateIP, localDescription, unsigned(pollDescriptor.revents));
               detail.assign(reason);
               appendGoogleProbeTrace("probe4.poll.fail", reason);
            }
            else
            {
               char reason[224] = {};
               std::snprintf(reason, sizeof(reason), "connect_poll_errno_%d_ip_%s_%s_revents_0x%x", errno, candidateIP, localDescription, unsigned(pollDescriptor.revents));
               detail.assign(reason);
               appendGoogleProbeTrace("probe4.poll.fail", reason);
            }

            socket.close();
            return false;
         }

         int soError = 0;
         socklen_t soErrorLen = sizeof(soError);
         if (getsockopt(socket.fd, SOL_SOCKET, SO_ERROR, &soError, &soErrorLen) != 0 || soError != 0)
         {
            char localDescription[96] = {};
            describeLocalSocket(socket, localDescription, sizeof(localDescription));
            char reason[224] = {};
            std::snprintf(reason, sizeof(reason), "connect_soerror_%d_ip_%s_%s", soError, candidateIP, localDescription);
            detail.assign(reason);
            appendGoogleProbeTrace("probe4.soerror.fail", reason);
            socket.close();
            return false;
         }
      }

      int socketFlags = fcntl(socket.fd, F_GETFL, 0);
      if (socketFlags >= 0)
      {
         (void)fcntl(socket.fd, F_SETFL, socketFlags & ~O_NONBLOCK);
      }

      struct timeval timeout = {};
      timeout.tv_sec = 5;
      timeout.tv_usec = 0;
      setsockopt(socket.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      setsockopt(socket.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

      static constexpr const char *request =
         "GET / HTTP/1.1\r\n"
         "Host: www.google.com\r\n"
         "Connection: close\r\n"
         "User-Agent: nametag-prodigy-dev-egress-probe\r\n"
         "Accept: text/html\r\n"
         "\r\n";

      ssize_t sent = socket.send(request, std::strlen(request), MSG_NOSIGNAL);
      if (sent <= 0)
      {
         char localDescription[96] = {};
         describeLocalSocket(socket, localDescription, sizeof(localDescription));
         char reason[224] = {};
         std::snprintf(reason, sizeof(reason), "send_errno_%d_ip_%s_%s", errno, candidateIP, localDescription);
         detail.assign(reason);
         appendGoogleProbeTrace("probe4.send.fail", reason);
         socket.close();
         return false;
      }

      char response[512] = {};
      ssize_t received = socket.recv(response, sizeof(response), 0);
      if (received <= 0)
      {
         char localDescription[96] = {};
         describeLocalSocket(socket, localDescription, sizeof(localDescription));
         char reason[224] = {};
         std::snprintf(reason, sizeof(reason), "recv_errno_%d_ip_%s_%s", errno, candidateIP, localDescription);
         detail.assign(reason);
         appendGoogleProbeTrace("probe4.recv.fail", reason);
         socket.close();
         return false;
      }

      if (received < 5 || std::memcmp(response, "HTTP/", 5) != 0)
      {
         detail.assign("invalid_http_response"_ctv);
         appendGoogleProbeTrace("probe4.http.fail", "invalid_http_response");
         socket.close();
         return false;
      }

      detail.assign("ok"_ctv);
      appendGoogleProbeTrace("probe4.success", candidateIP);
      socket.close();
      return true;
   }

   bool probeGoogleAddress(const struct in6_addr& googleAddress, String& detail)
   {
      char candidateIP[INET6_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET6, &googleAddress, candidateIP, sizeof(candidateIP)) == nullptr)
      {
         std::strncpy(candidateIP, "unknown", sizeof(candidateIP));
         candidateIP[sizeof(candidateIP) - 1] = '\0';
      }

      appendGoogleProbeTrace("probe6.candidate", candidateIP);

      TCPSocket socket;
      socket.setIPVersion(AF_INET6);
      socket.setDaddr(&googleAddress, 80);
      socket.setNonBlocking();

      appendGoogleProbeTrace("probe6.connect.begin", candidateIP);
      int connectResult = socket.connect();
      appendGoogleProbeTrace("probe6.connect.end", candidateIP);
      if (connectResult != 0)
      {
         if (errno != EINPROGRESS)
         {
            char reason[256] = {};
            std::snprintf(reason, sizeof(reason), "connect6_errno_%d_ip_%s", errno, candidateIP);
            detail.assign(reason);
            appendGoogleProbeTrace("probe6.connect.fail", reason);
            socket.close();
            return false;
         }

         struct pollfd pollDescriptor = {};
         pollDescriptor.fd = socket.fd;
         pollDescriptor.events = POLLOUT;

         int pollResult = poll(&pollDescriptor, 1, 5000);
         if (pollResult <= 0)
         {
            char localDescription[128] = {};
            describeLocalSocket(socket, localDescription, sizeof(localDescription));

            if (pollResult == 0)
            {
               char reason[320] = {};
               std::snprintf(reason, sizeof(reason), "connect6_timeout_ip_%s_%s_revents_0x%x", candidateIP, localDescription, unsigned(pollDescriptor.revents));
               detail.assign(reason);
               appendGoogleProbeTrace("probe6.poll.fail", reason);
            }
            else
            {
               char reason[320] = {};
               std::snprintf(reason, sizeof(reason), "connect6_poll_errno_%d_ip_%s_%s_revents_0x%x", errno, candidateIP, localDescription, unsigned(pollDescriptor.revents));
               detail.assign(reason);
               appendGoogleProbeTrace("probe6.poll.fail", reason);
            }

            socket.close();
            return false;
         }

         int soError = 0;
         socklen_t soErrorLen = sizeof(soError);
         if (getsockopt(socket.fd, SOL_SOCKET, SO_ERROR, &soError, &soErrorLen) != 0 || soError != 0)
         {
            char localDescription[128] = {};
            describeLocalSocket(socket, localDescription, sizeof(localDescription));
            char reason[320] = {};
            std::snprintf(reason, sizeof(reason), "connect6_soerror_%d_ip_%s_%s", soError, candidateIP, localDescription);
            detail.assign(reason);
            appendGoogleProbeTrace("probe6.soerror.fail", reason);
            socket.close();
            return false;
         }
      }

      int socketFlags = fcntl(socket.fd, F_GETFL, 0);
      if (socketFlags >= 0)
      {
         (void)fcntl(socket.fd, F_SETFL, socketFlags & ~O_NONBLOCK);
      }

      struct timeval timeout = {};
      timeout.tv_sec = 5;
      timeout.tv_usec = 0;
      setsockopt(socket.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      setsockopt(socket.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

      static constexpr const char *request =
         "GET / HTTP/1.1\r\n"
         "Host: www.google.com\r\n"
         "Connection: close\r\n"
         "User-Agent: nametag-prodigy-dev-egress-probe\r\n"
         "Accept: text/html\r\n"
         "\r\n";

      ssize_t sent = socket.send(request, std::strlen(request), MSG_NOSIGNAL);
      if (sent <= 0)
      {
         char localDescription[128] = {};
         describeLocalSocket(socket, localDescription, sizeof(localDescription));
         char reason[320] = {};
         std::snprintf(reason, sizeof(reason), "send6_errno_%d_ip_%s_%s", errno, candidateIP, localDescription);
         detail.assign(reason);
         appendGoogleProbeTrace("probe6.send.fail", reason);
         socket.close();
         return false;
      }

      char response[512] = {};
      ssize_t received = socket.recv(response, sizeof(response), 0);
      if (received <= 0)
      {
         char localDescription[128] = {};
         describeLocalSocket(socket, localDescription, sizeof(localDescription));
         char reason[320] = {};
         std::snprintf(reason, sizeof(reason), "recv6_errno_%d_ip_%s_%s", errno, candidateIP, localDescription);
         detail.assign(reason);
         appendGoogleProbeTrace("probe6.recv.fail", reason);
         socket.close();
         return false;
      }

      if (received < 5 || std::memcmp(response, "HTTP/", 5) != 0)
      {
         detail.assign("invalid_http_response6"_ctv);
         appendGoogleProbeTrace("probe6.http.fail", "invalid_http_response6");
         socket.close();
         return false;
      }

      detail.assign("ok"_ctv);
      appendGoogleProbeTrace("probe6.success", candidateIP);
      socket.close();
      return true;
   }

   bool performGoogleHttpProbeV4(String& detail)
   {
      std::vector<struct in_addr> candidates;
      candidates.reserve(3);

      struct in_addr resolvedAddress = {};
      if (resolveGoogleIPv4(resolvedAddress))
      {
         candidates.push_back(resolvedAddress);
      }

      static constexpr const char *fallbackIPs[] = {
         "142.250.191.4",
         "142.251.32.4"
      };

      for (const char *fallbackIP : fallbackIPs)
      {
         struct in_addr fallbackAddress = {};
         if (inet_pton(AF_INET, fallbackIP, &fallbackAddress) != 1)
         {
            continue;
         }

         bool duplicate = false;
         for (const struct in_addr& existing : candidates)
         {
            if (existing.s_addr == fallbackAddress.s_addr)
            {
               duplicate = true;
               break;
            }
         }

         if (!duplicate)
         {
            candidates.push_back(fallbackAddress);
         }
      }

      if (candidates.empty())
      {
         detail.assign("dns_resolution_failed"_ctv);
         return false;
      }

      String lastFailure;
      String allFailures;

      for (const struct in_addr& candidate : candidates)
      {
         String candidateDetail;
         if (probeGoogleAddress(candidate, candidateDetail))
         {
            detail.assign(candidateDetail);
            return true;
         }

         if (allFailures.size() > 0)
         {
            allFailures.append(";"_ctv);
         }

         allFailures.append(candidateDetail);
         lastFailure.assign(candidateDetail);
      }

      if (allFailures.size() > 0)
      {
         detail.assign(allFailures);
      }
      else if (lastFailure.size() == 0)
      {
         detail.assign("probe_failed"_ctv);
      }
      else
      {
         detail.assign(lastFailure);
      }

      return false;
   }

   bool performGoogleHttpProbeV6(String& detail)
   {
      std::vector<struct in6_addr> candidates;
      candidates.reserve(3);

      struct in6_addr resolvedAddress = {};
      if (resolveGoogleIPv6(resolvedAddress))
      {
         candidates.push_back(resolvedAddress);
      }

      static constexpr const char *fallbackIPs[] = {
         "2607:f8b0:400a:801::2004",
         "2607:f8b0:400a:806::2004"
      };

      for (const char *fallbackIP : fallbackIPs)
      {
         struct in6_addr fallbackAddress = {};
         if (inet_pton(AF_INET6, fallbackIP, &fallbackAddress) != 1)
         {
            continue;
         }

         bool duplicate = false;
         for (const struct in6_addr& existing : candidates)
         {
            if (memcmp(&existing, &fallbackAddress, sizeof(existing)) == 0)
            {
               duplicate = true;
               break;
            }
         }

         if (!duplicate)
         {
            candidates.push_back(fallbackAddress);
         }
      }

      if (candidates.empty())
      {
         detail.assign("dns6_resolution_failed"_ctv);
         return false;
      }

      String lastFailure;
      String allFailures;

      for (const struct in6_addr& candidate : candidates)
      {
         String candidateDetail;
         if (probeGoogleAddress(candidate, candidateDetail))
         {
            detail.assign(candidateDetail);
            return true;
         }

         if (allFailures.size() > 0)
         {
            allFailures.append(";"_ctv);
         }

         allFailures.append(candidateDetail);
         lastFailure.assign(candidateDetail);
      }

      if (allFailures.size() > 0)
      {
         detail.assign(allFailures);
      }
      else if (lastFailure.size() == 0)
      {
         detail.assign("probe6_failed"_ctv);
      }
      else
      {
         detail.assign(lastFailure);
      }

      return false;
   }

   bool performGoogleHttpProbe(String& detail)
   {
      appendGoogleProbeTrace("probe.start");
      String detailV4;
      bool v4Okay = performGoogleHttpProbeV4(detailV4);
      appendGoogleProbeTrace(v4Okay ? "probe.v4.ok" : "probe.v4.fail", detailV4.c_str());

#if PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS_DUALSTACK == 1
      String detailV6;
      bool v6Okay = performGoogleHttpProbeV6(detailV6);
      appendGoogleProbeTrace(v6Okay ? "probe.v6.ok" : "probe.v6.fail", detailV6.c_str());

      detail.assign("v4="_ctv);
      detail.append(detailV4);
      detail.append(";v6="_ctv);
      detail.append(detailV6);

      return v4Okay && v6Okay;
#else
      detail.assign(detailV4);
      return v4Okay;
#endif
   }

   bool ensureGoogleHttpProbe(String& detail)
   {
      if (!googleProbeComplete)
      {
         googleProbeSuccess = performGoogleHttpProbe(googleProbeDetail);
         googleProbeComplete = true;
      }

      detail.assign(googleProbeDetail);
      return googleProbeSuccess;
   }
#endif

   TCPStream *findClient(void *socket)
   {
      for (TCPStream *client : clients)
      {
         if (client == socket) return client;
      }

      return nullptr;
   }

   void closeClient(TCPStream *client)
   {
      if (client == nullptr) return;
      if (Ring::socketIsClosing(client)) return;
      if (client->fslot < 0) return;

      Ring::queueCancelAll(client);
      Ring::queueClose(client);
   }

   void eraseClient(TCPStream *client)
   {
      RingDispatcher::eraseMultiplexee(client);

      for (auto it = clients.begin(); it != clients.end(); ++it)
      {
         if (*it == client)
         {
            clients.erase(it);
            break;
         }
      }

      delete client;
   }

   void queueClientSendIfNeeded(TCPStream *client)
   {
      if (client->wBuffer.outstandingBytes() > 0)
      {
         Ring::queueSend(client);
      }
   }

   void publishRequestMetric(void)
   {
      if (metricsSink == nullptr) return;

      if (readyReassertedOnTraffic == false)
      {
         readyReassertedOnTraffic = true;
         metricsSink->signalReady();
      }

      if (requestMetricKey == 0) return;

      metricsSink->publishStatistic(requestMetricKey, uint64_t(1));

      // Emit deterministic ingress fine-bucket samples so autoscale composite
      // dimensions can be exercised in battery tests with this probe container.
      metricsSink->publishStatistic(pingPongQueueWaitFineBucketMetricKey(), uint64_t(1));
      metricsSink->publishStatistic(pingPongHandlerFineBucketMetricKey(), uint64_t(1));
   }

   void handleClientData(TCPStream *client)
   {
      while (client->rBuffer.outstandingBytes() > 0)
      {
         uint8_t *head = client->rBuffer.pHead();
         uint32_t available = client->rBuffer.outstandingBytes();

         uint8_t *newline = static_cast<uint8_t *>(memchr(head, '\n', available));
         if (newline == nullptr)
         {
            if (available >= maxLineBytes)
            {
               closeClient(client);
            }

            break;
         }

         uint32_t lineLength = static_cast<uint32_t>(newline - head);
         if (lineLength > 0 && head[lineLength - 1] == '\r')
         {
            lineLength -= 1;
         }

         if (lineLength == 4 && memcmp(head, "ping", 4) == 0)
         {
#if PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS == 1
            String googleProbeReason;
            if (ensureGoogleHttpProbe(googleProbeReason))
            {
               client->wBuffer.append("pong\n"_ctv);
            }
            else
            {
               client->wBuffer.append("egress_fail:"_ctv);
               if (googleProbeReason.size() > 0)
               {
                  client->wBuffer.append(googleProbeReason);
               }
               client->wBuffer.append('\n');
            }
#else
            client->wBuffer.append("pong\n"_ctv);
#endif
         }
         else
         {
            client->wBuffer.append("pong:"_ctv);
            if (lineLength > 0)
            {
               client->wBuffer.append(head, lineLength);
            }

            client->wBuffer.append('\n');
         }

         publishRequestMetric();

         uint32_t consumeBytes = static_cast<uint32_t>((newline - head) + 1);
         client->rBuffer.consume(consumeBytes, true);
      }

      queueClientSendIfNeeded(client);
   }

public:

   explicit PingPongServer(std::atomic<bool>& runningFlag) : running(runningFlag)
   {
   }

#if PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS == 1
   bool runGoogleProbeNow(String& detail)
   {
      resetGoogleProbeTrace();
      appendGoogleProbeTrace("probe.run.begin");
      googleProbeSuccess = performGoogleHttpProbe(googleProbeDetail);
      googleProbeComplete = true;
      detail.assign(googleProbeDetail);
      appendGoogleProbeTrace(googleProbeSuccess ? "probe.run.success" : "probe.run.fail", googleProbeDetail.c_str());
      return googleProbeSuccess;
   }
#endif

   void setPort(uint16_t value)
   {
      port = value;
   }

   void setMetricsSink(NeuronHub *sink, uint64_t metricKey)
   {
      metricsSink = sink;
      requestMetricKey = metricKey;
   }

   void start()
   {
      listener.setIPVersion(AF_INET);
      listener.setSaddr("0.0.0.0"_ctv, port);
      listener.bindThenListen();

      Ring::installFDIntoFixedFileSlot(&listener);
      RingDispatcher::installMultiplexee(&listener, this);

      listenerActive = true;
      Ring::queueAccept(&listener);
   }

   void stop()
   {
      running.store(false);

      for (TCPStream *client : clients)
      {
         closeClient(client);
      }

      if (listenerActive && listener.fslot >= 0 && Ring::socketIsClosing(&listener) == false)
      {
         Ring::queueCancelAll(&listener);
         Ring::queueClose(&listener);
      }
   }

   void acceptHandler(void *socket, int fslot) override
   {
      if (socket != static_cast<void *>(&listener))
      {
         return;
      }

      if (running.load() && fslot >= 0)
      {
         TCPStream *client = new TCPStream();
         client->fslot = fslot;
         client->isFixedFile = true;
         client->rBuffer.reserve(initialClientBufferBytes);
         client->wBuffer.reserve(initialClientBufferBytes);

         clients.push_back(client);
         RingDispatcher::installMultiplexee(client, this);
         Ring::queueRecv(client);
      }
      else if (fslot >= 0)
      {
         Ring::queueCloseRaw(fslot);
      }

      if (running.load() && listenerActive)
      {
         Ring::queueAccept(&listener);
      }
   }

   void recvHandler(void *socket, int result) override
   {
      TCPStream *client = findClient(socket);
      if (client == nullptr)
      {
         return;
      }

      client->pendingRecv = false;

      if (result <= 0)
      {
         closeClient(client);
         return;
      }

      client->rBuffer.advance(result);
      handleClientData(client);

      if (running.load() && Ring::socketIsClosing(client) == false)
      {
         Ring::queueRecv(client);
      }
   }

   void sendHandler(void *socket, int result) override
   {
      TCPStream *client = findClient(socket);
      if (client == nullptr)
      {
         return;
      }

	      client->pendingSend = false;

      if (result <= 0)
      {
         client->wBuffer.noteSendCompleted();
         closeClient(client);
         return;
      }

      client->wBuffer.consume(result, false);
      client->wBuffer.noteSendCompleted();
      queueClientSendIfNeeded(client);
   }

   void closeHandler(void *socket) override
   {
      if (socket == static_cast<void *>(&listener))
      {
         listenerActive = false;
         RingDispatcher::eraseMultiplexee(&listener);
         return;
      }

      TCPStream *client = findClient(socket);
      if (client == nullptr)
      {
         return;
      }

      eraseClient(client);
   }
};

class PingPongContainer final : public NeuronHubDispatch
{
private:

   std::atomic<bool> running{true};
   PingPongServer server;
   std::unique_ptr<NeuronHub> neuronHub;
   uint64_t requestMetricKey = 0;
   bool readySignaled = false;
   uint16_t currentLogicalCores = 1;
   uint32_t currentMemoryMB = 0;
   uint32_t currentStorageMB = 0;
   std::vector<uint8_t> memoryReservation;

   bool probeCpuCapacity(uint16_t nLogicalCores)
   {
      std::atomic<uint32_t> completed{0};
      std::vector<std::thread> workers;
      workers.reserve(nLogicalCores);

      for (uint16_t index = 0; index < nLogicalCores; index++)
      {
         workers.emplace_back([&completed] () -> void {
            completed.fetch_add(1, std::memory_order_relaxed);
         });
      }

      for (std::thread& worker : workers)
      {
         worker.join();
      }

      return (completed.load(std::memory_order_relaxed) == nLogicalCores);
   }

   bool applyMemoryTarget(uint32_t memoryMB)
   {
      const uint64_t bytes = uint64_t(memoryMB) * 1024ULL * 1024ULL;

      std::vector<uint8_t> next;
      try
      {
         next.resize(bytes);
      }
      catch (...)
      {
         return false;
      }

      for (uint64_t offset = 0; offset < bytes; offset += 4096)
      {
         next[offset] = uint8_t(offset & 0xFF);
      }

      memoryReservation.swap(next);
      return true;
   }

   bool applyStorageTarget(uint32_t storageMB)
   {
      const uint64_t bytes = uint64_t(storageMB) * 1024ULL * 1024ULL;
      if (bytes > uint64_t(std::numeric_limits<off_t>::max()))
      {
         return false;
      }

      int fd = open("/storage/.vertical_scale_probe.bin", O_CREAT | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
      if (fd < 0)
      {
         return false;
      }

      bool success = true;
      const off_t targetSize = off_t(bytes);

      if (storageMB >= currentStorageMB)
      {
         int result = posix_fallocate(fd, 0, targetSize);
         if (result != 0)
         {
            success = false;
         }
      }

      if (success && ftruncate(fd, targetSize) != 0)
      {
         success = false;
      }

      close(fd);
      return success;
   }

   void signalReadyAndSeedMetricOnce(void)
   {
      if (neuronHub == nullptr) return;
      if (readySignaled) return;

      readySignaled = true;
      neuronHub->signalReady();

      if (requestMetricKey != 0)
      {
         neuronHub->publishStatistic(requestMetricKey, uint64_t(1));
      }

      neuronHub->publishStatistic(pingPongQueueWaitFineBucketMetricKey(), uint64_t(1));
      neuronHub->publishStatistic(pingPongHandlerFineBucketMetricKey(), uint64_t(1));
   }

public:

   PingPongContainer() : server(running)
   {
   }

   ~PingPongContainer()
   {
      server.stop();
   }

   void endOfDynamicArgs(void) override
   {
      // Emit startup readiness/metric once; keep a fallback in prepare()
      // in case the dynamic-args completion callback is delayed or missed.
      signalReadyAndSeedMetricOnce();
   }

   void beginShutdown(void) override
   {
      running.store(false);
      server.stop();
   }

   void resourceDelta(uint16_t nLogicalCores, uint32_t memoryMB, uint32_t storageMB, bool isDownscale, uint32_t graceSeconds) override
   {
      (void)isDownscale;
      (void)graceSeconds;

      bool success = true;
      if (nLogicalCores == 0 || memoryMB == 0 || storageMB == 0)
      {
         success = false;
      }

      if (success && !probeCpuCapacity(nLogicalCores))
      {
         success = false;
      }

      if (success && !applyMemoryTarget(memoryMB))
      {
         success = false;
      }

      if (success && !applyStorageTarget(storageMB))
      {
         success = false;
      }

      if (success)
      {
         currentLogicalCores = nLogicalCores;
         currentMemoryMB = memoryMB;
         currentStorageMB = storageMB;
      }

      if (neuronHub)
      {
         neuronHub->acknowledgeResourceDelta(success);
      }
   }

   void prepare(int argc, char *argv[])
   {
      if (const char *portEnv = getenv("PINGPONG_PORT"); portEnv && *portEnv)
      {
         long value = strtol(portEnv, nullptr, 10);
         if (value > 0 && value <= UINT16_MAX)
         {
            server.setPort(uint16_t(value));
         }
      }

      uint32_t sqeCount = 64;
      uint32_t cqeCount = 128;
      uint32_t nFixedFiles = 512;
      uint32_t nReservedFixedFiles = 128;
      uint32_t nMsgHdrPackages = 0;
      Ring::createRing(sqeCount, cqeCount, nFixedFiles, nReservedFixedFiles, -1, -1, nMsgHdrPackages);

      // NeuronHub installs sockets into ring fixed-file slots during construction,
      // so it must be initialized only after Ring::createRing is live.
      neuronHub = std::make_unique<NeuronHub>(this);
      neuronHub->fillFromMainArgs(argc, argv);
      neuronHub->afterRing();
      currentLogicalCores = neuronHub->parameters.nLogicalCores;
      currentMemoryMB = neuronHub->parameters.memoryMB;
      currentStorageMB = neuronHub->parameters.storageMB;
      (void)applyMemoryTarget(currentMemoryMB);
      (void)applyStorageTarget(currentStorageMB);
      {
         String metricName;
         metricName.assign("pingpong.requests"_ctv);

         if (const char *metricNameEnv = getenv("PINGPONG_METRIC_NAME"); metricNameEnv && metricNameEnv[0] != '\0')
         {
            metricName.assign(metricNameEnv);
         }

         requestMetricKey = ProdigyMetrics::metricKeyForName(metricName);
         server.setMetricsSink(neuronHub.get(), requestMetricKey);
      }

#if PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS == 1
      {
         String googleProbeResult;
         if (!server.runGoogleProbeNow(googleProbeResult))
         {
            basics_log("PingPongContainer::prepare google egress probe failed detail=%s\n", googleProbeResult.c_str());
            fflush(stdout);
            fflush(stderr);
            std::exit(EXIT_FAILURE);
         }

         basics_log("PingPongContainer::prepare google egress probe succeeded detail=%s\n", googleProbeResult.c_str());
         fflush(stdout);
         fflush(stderr);
      }
#endif

#if PRODIGY_PINGPONG_DISABLE_SERVER == 0
      server.start();
#endif
      signalReadyAndSeedMetricOnce();
   }

   void start(void)
   {
      Ring::start();
   }
};

int main(int argc, char *argv[])
{
   PingPongContainer app;
   app.prepare(argc, argv);
   app.start();
   return EXIT_SUCCESS;
}
