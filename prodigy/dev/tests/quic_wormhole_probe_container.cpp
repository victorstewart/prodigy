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
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

#include <prodigy/quic.cid.generator.h>

namespace
{
   static constexpr const char *kReplyPayload = "wormhole-ok";

   void appendTrace(const char *stage, const char *detail = nullptr)
   {
      int fd = open("/quic_wormhole_probe_trace.log", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
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

   std::string renderIPv4(const struct in_addr& address)
   {
      char buffer[INET_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr)
      {
         return "invalid";
      }

      return buffer;
   }

   void renderCIDHex(const ProdigyQuicCID& cid, std::string& output)
   {
      static constexpr char digits[] = "0123456789abcdef";

      output.clear();
      output.reserve(size_t(cid.id_len) * 2);
      for (uint8_t index = 0; index < cid.id_len; ++index)
      {
         output.push_back(digits[(cid.id[index] >> 4) & 0x0f]);
         output.push_back(digits[cid.id[index] & 0x0f]);
      }
   }
}

class QuicWormholeProbeContainer final : public NeuronHubDispatch
{
private:

   std::unique_ptr<NeuronHub> neuronHub;
   std::thread receiverThread;
   std::atomic<bool> stopRequested = false;
   int udpFD = -1;

   bool prepareWormholeSocket(std::string& failure)
   {
      if (!neuronHub)
      {
         failure = "missing_neuron_hub";
         return false;
      }

      if (neuronHub->parameters.wormholes.size() == 0)
      {
         failure = "missing_wormhole";
         return false;
      }

      const Wormhole& wormhole = neuronHub->parameters.wormholes[0];
      if (wormhole.isQuic == false || wormhole.layer4 != IPPROTO_UDP)
      {
         failure = "wormhole_must_be_quic_udp";
         return false;
      }

      if (wormhole.externalAddress.is6 || wormhole.containerPort == 0 || wormhole.externalPort == 0)
      {
         failure = "wormhole_must_be_ipv4";
         return false;
      }

      if (wormhole.hasQuicCidKeyState == false)
      {
         failure = "wormhole_missing_cid_key_state";
         return false;
      }

      if (neuronHub->parameters.private6.network.is6 == false)
      {
         failure = "missing_container_private6";
         return false;
      }

      uint8_t containerID[5] = {};
      memcpy(containerID, neuronHub->parameters.private6.network.v6 + 11, sizeof(containerID));

      struct sockaddr_in destination = {};
      destination.sin_family = AF_INET;
      destination.sin_port = htons(wormhole.externalPort);
      memcpy(&destination.sin_addr.s_addr, &wormhole.externalAddress.v4, sizeof(destination.sin_addr.s_addr));

      const uint8_t activeKeyIndex = wormhole.quicCidKeyState.activeKeyIndex & 0x01;
      uint8_t key[16] = {};
      memcpy(key, &wormhole.quicCidKeyState.keyMaterialByIndex[activeKeyIndex], sizeof(key));

      ProdigyQuicCidEncryptor cidEncryptor;
      if (cidEncryptor.setKey(key) == false)
      {
         failure = "cid_cipher_init_failed";
         return false;
      }

      uint32_t nonceCursor = 1;
      ProdigyQuicCID cid = prodigyGenerateQuicCID(
         cidEncryptor,
         containerID,
         &nonceCursor,
         reinterpret_cast<const struct sockaddr *>(&destination),
         activeKeyIndex
      );
      if (cid.id_len == 0)
      {
         failure = "cid_generation_failed";
         return false;
      }

      udpFD = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (udpFD < 0)
      {
         failure = "socket_failed";
         return false;
      }

      int enableReuse = 1;
      (void)setsockopt(udpFD, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(enableReuse));

      struct sockaddr_in bindAddress = {};
      bindAddress.sin_family = AF_INET;
      bindAddress.sin_port = htons(wormhole.containerPort);
      bindAddress.sin_addr.s_addr = htonl(INADDR_ANY);
      if (bind(udpFD, reinterpret_cast<const struct sockaddr *>(&bindAddress), sizeof(bindAddress)) != 0)
      {
         failure = "bind_failed";
         close(udpFD);
         udpFD = -1;
         return false;
      }

      std::string cidHex;
      renderCIDHex(cid, cidHex);
      std::string externalAddress = renderIPv4(*reinterpret_cast<const struct in_addr *>(&wormhole.externalAddress.v4));

      appendTrace("probe.cid", cidHex.c_str());
      basics_log("probe.cid %s\n", cidHex.c_str());
      basics_log("probe.external %s:%u containerPort=%u keyIndex=%u\n",
         externalAddress.c_str(),
         unsigned(wormhole.externalPort),
         unsigned(wormhole.containerPort),
         unsigned(activeKeyIndex));

      receiverThread = std::thread([this] () {
         char buffer[2048] = {};
         struct sockaddr_in source = {};
         socklen_t sourceLen = sizeof(source);

         while (stopRequested.load() == false)
         {
            ssize_t received = recvfrom(udpFD, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&source), &sourceLen);
            if (received < 0)
            {
               if (stopRequested.load() || errno == EINTR)
               {
                  continue;
               }

               appendTrace("probe.recv.fail", strerror(errno));
               basics_log("probe.fail recvfrom errno=%d(%s)\n", errno, strerror(errno));
               return;
            }

            std::string sourceText = renderIPv4(source.sin_addr);
            appendTrace("probe.recv", sourceText.c_str());

            ssize_t sent = sendto(udpFD,
               kReplyPayload,
               std::strlen(kReplyPayload),
               MSG_NOSIGNAL,
               reinterpret_cast<const struct sockaddr *>(&source),
               sizeof(source));
            if (sent != static_cast<ssize_t>(std::strlen(kReplyPayload)))
            {
               appendTrace("probe.send.fail");
               basics_log("probe.fail sendto bytes=%lld errno=%d(%s)\n",
                  static_cast<long long>(sent), errno, strerror(errno));
               return;
            }

            appendTrace("probe.success", sourceText.c_str());
            basics_log("probe.success source=%s:%u\n", sourceText.c_str(), unsigned(ntohs(source.sin_port)));
         }
      });

      return true;
   }

public:

   ~QuicWormholeProbeContainer()
   {
      beginShutdown();
   }

   void beginShutdown(void) override
   {
      stopRequested.store(true);

      if (udpFD >= 0)
      {
         close(udpFD);
         udpFD = -1;
      }

      if (receiverThread.joinable())
      {
         receiverThread.join();
      }
   }

   void endOfDynamicArgs(void) override
   {
   }

   void prepare(int argc, char *argv[])
   {
      int truncateFD = open("/quic_wormhole_probe_trace.log", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
      if (truncateFD >= 0)
      {
         close(truncateFD);
      }

      Ring::createRing(64, 128, 512, 128, -1, -1, 0);

      neuronHub = std::make_unique<NeuronHub>(this);
      neuronHub->fillFromMainArgs(argc, argv);
      neuronHub->afterRing();

      std::string failure;
      if (prepareWormholeSocket(failure) == false)
      {
         appendTrace("probe.fail", failure.c_str());
         basics_log("QuicWormholeProbeContainer::prepare failed detail=%s\n", failure.c_str());
         std::fflush(stdout);
         std::fflush(stderr);
         std::exit(EXIT_FAILURE);
      }

      neuronHub->signalReady();
   }

   void start(void)
   {
      Ring::start();
   }
};

int main(int argc, char *argv[])
{
   QuicWormholeProbeContainer container;
   container.prepare(argc, argv);
   container.start();
   return 0;
}
