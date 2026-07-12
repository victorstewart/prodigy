#include <prodigy/host.control.network.h>

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <liburing.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

class HttpFixture final
{
private:

   int listener = -1;
   uint16_t boundPort = 0;
   std::atomic<bool> stopping = false;
   std::thread worker;

   static bool sendAll(int fd, const char *data, size_t size)
   {
      size_t sent = 0;
      while (sent < size)
      {
         const ssize_t count = send(fd, data + sent, size - sent, MSG_NOSIGNAL);
         if (count <= 0)
         {
            return false;
         }
         sent += size_t(count);
      }
      return true;
   }

   void run(void)
   {
      pollfd descriptor {.fd = listener, .events = POLLIN, .revents = 0};
      while (!stopping.load(std::memory_order_relaxed) && poll(&descriptor, 1, 25) >= 0)
      {
         if ((descriptor.revents & POLLIN) == 0)
         {
            descriptor.revents = 0;
            continue;
         }
         const int connection = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
         if (connection < 0)
         {
            continue;
         }
         char request[1024];
         (void)recv(connection, request, sizeof(request), 0);
         constexpr char response[] =
             "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect";
         (void)sendAll(connection, response, sizeof(response) - 1);
         close(connection);
         return;
      }
   }

public:

   HttpFixture()
   {
      listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (listener < 0)
      {
         return;
      }
      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      if (bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
          listen(listener, 1) != 0)
      {
         close(listener);
         listener = -1;
         return;
      }
      socklen_t length = sizeof(address);
      if (getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) != 0)
      {
         close(listener);
         listener = -1;
         return;
      }
      boundPort = ntohs(address.sin_port);
      worker = std::thread([this]
      {
         run();
      });
   }

   ~HttpFixture()
   {
      stopping.store(true, std::memory_order_relaxed);
      if (listener >= 0)
      {
         ::shutdown(listener, SHUT_RDWR);
         close(listener);
      }
      if (worker.joinable())
      {
         worker.join();
      }
   }

   bool ready(void) const
   {
      return listener >= 0 && boundPort != 0;
   }

   uint16_t port(void) const
   {
      return boundPort;
   }
};

class Scenario final : public RingMultiplexer
{
public:

   ProdigyHostControlNetwork *network = nullptr;
   TimeoutPacket guard;
   bool guardArmed = false;
   bool guardCancellationRequested = false;
   bool completed = false;
   bool succeeded = false;
   bool timedOut = false;
   uint32_t callbacks = 0;

   Scenario()
   {
      guard.originator = this;
   }

   static void callback(void *context,
                        MultiCurlClient::Ticket,
                        MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.callbacks;
      scenario.completed = true;
      scenario.succeeded = result.succeeded() && result.statusCode == 200 &&
                           result.body == "direct"_ctv;
      (void)scenario.network->shutdown();
      if (scenario.guardArmed && !scenario.guardCancellationRequested)
      {
         scenario.guardCancellationRequested = true;
         Ring::queueCancelTimeout(&scenario.guard);
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guardCancellationRequested = false;
      guard.clear();
      if (result != -ECANCELED)
      {
         timedOut = true;
      }
      if (network->shutdown())
      {
         Ring::exit = true;
      }
   }

   void completionBatchHandler(uint32_t) override
   {
      if ((completed || timedOut) && network->shutdown() && !guardArmed)
      {
         Ring::exit = true;
      }
   }
};

template <size_t Size>
static bool writeHostsFile(char (&path)[Size])
{
   const int fd = mkstemp(path);
   if (fd < 0)
   {
      return false;
   }
   constexpr char entry[] = "127.0.0.1 direct-host.test\n";
   const bool written = write(fd, entry, sizeof(entry) - 1) == ssize_t(sizeof(entry) - 1);
   close(fd);
   return written;
}

static int runScenario(void)
{
   (void)unsetenv("HTTP_PROXY");
   (void)unsetenv("HTTPS_PROXY");
   (void)unsetenv("ALL_PROXY");
   HttpFixture http;
   char hostsPath[] = "/tmp/prodigy-host-control-XXXXXX";
   if (!http.ready() || !writeHostsFile(hostsPath))
   {
      unlink(hostsPath);
      return 2;
   }

   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(64, 128, 8, 2, -1, -1, 8);

   RingAsyncDnsResolver::BackendConfig config;
   config.hostsPath.assign(hostsPath);
   ProdigyHostControlNetwork network(std::move(config));
   const bool resolverReady = network.ready();
   Scenario scenario;
   scenario.network = &network;
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);

   MultiCurlClient::Request request;
   request.url.snprintf<"http://direct-host.test:{itoa}/"_ctv>(uint64_t(http.port()));
   request.requireTls = false;
   request.httpPolicy = MultiCurlClient::HttpPolicy::requireHttp1;
   request.responseBytes = 64;
   request.overallDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(3);
   const ProdigyHostHttpSubmission submission = network.http();
   const MultiCurlClient::Ticket ticket =
       submission.submit(submission.context, std::move(request), {&scenario, Scenario::callback});
   scenario.guard.setTimeoutSeconds(5);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   if (!resolverReady || !ticket)
   {
      scenario.timedOut = true;
      if (!network.shutdown())
      {
         Ring::start();
      }
   }
   else
   {
      Ring::start();
   }

   const bool passed = resolverReady && network.ready() == false && network.shutdownSafe() &&
                       scenario.completed && scenario.succeeded && !scenario.timedOut &&
                       scenario.callbacks == 1;
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   unlink(hostsPath);
   return passed ? 0 : 3;
}

int main(void)
{
   io_uring probe = {};
   const int support = io_uring_queue_init(2, &probe, 0);
   if (support != 0)
   {
      return (support == -ENOSYS || support == -EPERM || support == -EACCES) ? 77 : 1;
   }
   io_uring_queue_exit(&probe);
   const pid_t child = fork();
   if (child == 0)
   {
      _exit(runScenario());
   }
   if (child < 0)
   {
      return 1;
   }
   int status = 0;
   if (waitpid(child, &status, 0) != child)
   {
      return 1;
   }
   if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
   {
      return 0;
   }
   return WIFEXITED(status) && WEXITSTATUS(status) == 2 ? 77 : 1;
}
