#include <array>
#include <cerrno>
#include <cstdint>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct TunnelProviderEndpoint {
  std::string host;
  uint16_t port = 0;
};

static bool parsePort(const char *value, uint16_t& port)
{
  if (value == nullptr || value[0] == '\0')
  {
    return false;
  }
  char *end = nullptr;
  errno = 0;
  unsigned long parsed = std::strtoul(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0 || parsed > 65535)
  {
    return false;
  }
  port = uint16_t(parsed);
  return true;
}

static int connectUnix(const char *path)
{
  if (path == nullptr || std::strlen(path) >= sizeof(sockaddr_un::sun_path))
  {
    return -1;
  }
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
  {
    return -1;
  }

  sockaddr_un address = {};
  address.sun_family = AF_UNIX;
  std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
  if (::connect(fd, reinterpret_cast<sockaddr *>(&address), socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path))) == 0)
  {
    return fd;
  }
  ::close(fd);
  return -1;
}

static int connectTCP(const TunnelProviderEndpoint& endpoint)
{
  auto connectWithTimeout = [](int fd, const sockaddr *address, socklen_t addressSize) -> int {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
      ::close(fd);
      return -1;
    }
    if (::connect(fd, address, addressSize) == 0)
    {
      (void)::fcntl(fd, F_SETFL, flags);
      return fd;
    }
    if (errno != EINPROGRESS)
    {
      ::close(fd);
      return -1;
    }

    pollfd pending = { .fd = fd, .events = POLLOUT };
    if (::poll(&pending, 1, 5'000) == 1)
    {
      int error = 0;
      socklen_t errorSize = sizeof(error);
      if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorSize) == 0 && error == 0)
      {
        (void)::fcntl(fd, F_SETFL, flags);
        return fd;
      }
    }
    ::close(fd);
    return -1;
  };

  auto connectLiteral = [&](const sockaddr *address, socklen_t addressSize, int family) -> int {
    int fd = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
    {
      return -1;
    }
    return connectWithTimeout(fd, address, addressSize);
  };

  in_addr v4 = {};
  if (::inet_pton(AF_INET, endpoint.host.c_str(), &v4) == 1)
  {
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(endpoint.port);
    address.sin_addr = v4;
    return connectLiteral(reinterpret_cast<const sockaddr *>(&address), sizeof(address), AF_INET);
  }

  in6_addr v6 = {};
  if (::inet_pton(AF_INET6, endpoint.host.c_str(), &v6) == 1)
  {
    sockaddr_in6 address = {};
    address.sin6_family = AF_INET6;
    address.sin6_port = htons(endpoint.port);
    address.sin6_addr = v6;
    return connectLiteral(reinterpret_cast<const sockaddr *>(&address), sizeof(address), AF_INET6);
  }

  return -1;
}

static bool writeAll(int fd, const char *buffer, size_t size)
{
  while (size > 0)
  {
    ssize_t rc = ::send(fd, buffer, size, 0);
    if (rc > 0)
    {
      buffer += rc;
      size -= size_t(rc);
      continue;
    }
    if (rc < 0 && errno == EINTR)
    {
      continue;
    }
    return false;
  }
  return true;
}

static bool relay(int left, int right)
{
  std::array<char, 64 * 1024> buffer;
  bool leftOpen = true;
  bool rightOpen = true;

  while (leftOpen || rightOpen)
  {
    pollfd fds[2] = {};
    nfds_t count = 0;
    int leftIndex = -1;
    int rightIndex = -1;
    if (leftOpen)
    {
      leftIndex = int(count);
      fds[count++] = pollfd { .fd = left, .events = POLLIN };
    }
    if (rightOpen)
    {
      rightIndex = int(count);
      fds[count++] = pollfd { .fd = right, .events = POLLIN };
    }

    int ready = ::poll(fds, count, -1);
    if (ready < 0 && errno == EINTR)
    {
      continue;
    }
    if (ready <= 0)
    {
      return false;
    }

    auto drain = [&](int index, int from, int to, bool& open) {
      if (index < 0 || (fds[index].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0)
      {
        return;
      }
      ssize_t rc = ::read(from, buffer.data(), buffer.size());
      if (rc > 0)
      {
        if (writeAll(to, buffer.data(), size_t(rc)))
        {
          return;
        }
        open = false;
        (void)::shutdown(to, SHUT_WR);
        return;
      }
      if (rc < 0 && errno == EINTR)
      {
        return;
      }
      open = false;
      (void)::shutdown(to, SHUT_WR);
    };

    drain(leftIndex, left, right, leftOpen);
    drain(rightIndex, right, left, rightOpen);
  }
  return true;
}

static int fail(const char *message)
{
  std::fprintf(stderr, "mothership-tunnel-provider: %s\n", message);
  return EXIT_FAILURE;
}

int main()
{
  std::signal(SIGPIPE, SIG_IGN);
  const char *gatewaySocket = std::getenv("PRODIGY_MOTHERSHIP_SOCKET");
  const char *egressHost = std::getenv("PRODIGY_TUNNEL_EGRESS_HOST");
  const char *egressPort = std::getenv("PRODIGY_TUNNEL_EGRESS_PORT");
  TunnelProviderEndpoint endpoint;
  endpoint.host.assign(egressHost == nullptr ? "" : egressHost);
  if (gatewaySocket == nullptr || gatewaySocket[0] == '\0' ||
      endpoint.host.empty() || parsePort(egressPort, endpoint.port) == false)
  {
    return fail("invalid launch environment");
  }

  for (;;)
  {
    int edgeFD = connectTCP(endpoint);
    if (edgeFD >= 0)
    {
      int gatewayFD = connectUnix(gatewaySocket);
      if (gatewayFD >= 0)
      {
        (void)relay(edgeFD, gatewayFD);
        ::close(gatewayFD);
      }
      ::close(edgeFD);
    }
    ::usleep(250'000);
  }
}
