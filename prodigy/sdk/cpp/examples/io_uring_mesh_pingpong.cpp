/* SPDX-License-Identifier: Apache-2.0 */

#include "../io_uring_reactor.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <optional>
#include <string>
#include <vector>

namespace
{
   using ProdigySDK::AdvertisementPairing;
   using ProdigySDK::CredentialDelta;
   using ProdigySDK::ContainerParameters;
   using ProdigySDK::Dispatch;
   using ProdigySDK::IPAddress;
   using ProdigySDK::MetricPair;
   using ProdigySDK::NeuronHub;
   using ProdigySDK::Result;
   using ProdigySDK::ResourceDelta;
   using ProdigySDK::SubscriptionPairing;
   using ProdigySDK::U128;
   using ProdigySDK::IOUring::AttachedNeuron;
   using ProdigySDK::IOUring::NeuronEvent;
   using ProdigySDK::IOUring::Reactor;
   using ProdigySDK::IOUring::ReactorEvent;

   constexpr unsigned requiredRounds = 3;
   constexpr std::uint64_t statPairingActivity = 1;
   constexpr std::uint64_t statResourceActivity = 2;
   constexpr std::uint64_t statCredentialActivity = 3;

   enum class Event : std::uint8_t
   {
      listenReadable = 1,
      connectReady = 2,
      sessionReadable = 3,
   };

   bool isUnspecified(const U128& bytes)
   {
      for (std::uint8_t byte : bytes)
      {
         if (byte != 0)
         {
            return false;
         }
      }

      return true;
   }

   bool sameSecret(const U128& left, const U128& right)
   {
      return left == right;
   }

   Result private6Address(const ContainerParameters& parameters, IPAddress& address)
   {
      if (parameters.private6.isIPv6 == false || isUnspecified(parameters.private6.address))
      {
         return Result::argument;
      }

      address.address = parameters.private6.address;
      address.isIPv6 = true;
      return Result::ok;
   }

   Result makeIPv6Address(const U128& bytes, std::uint16_t port, sockaddr_in6& address)
   {
      if (isUnspecified(bytes))
      {
         return Result::argument;
      }

      address = {};
      address.sin6_family = AF_INET6;
      address.sin6_port = htons(port);
      std::memcpy(&address.sin6_addr, bytes.data(), bytes.size());
      return Result::ok;
   }

   Result sendLine(int fd, const char *label, unsigned value)
   {
      char line[32];
      const int length = std::snprintf(line, sizeof(line), "%s %u\n", label, value);
      if (length <= 0 || static_cast<std::size_t>(length) >= sizeof(line))
      {
         return Result::argument;
      }

      const char *cursor = line;
      std::size_t remaining = static_cast<std::size_t>(length);
      while (remaining > 0)
      {
         const ssize_t bytesWritten = ::send(fd, cursor, remaining, 0);
         if (bytesWritten == 0)
         {
            return Result::io;
         }

         if (bytesWritten < 0)
         {
            if (errno == EINTR)
            {
               continue;
            }

            return Result::io;
         }

         cursor += bytesWritten;
         remaining -= static_cast<std::size_t>(bytesWritten);
      }

      return Result::ok;
   }

   bool parseLine(const std::string& line, const char *label, unsigned& value)
   {
      return std::sscanf(line.c_str(), label, &value) == 1;
   }

   MetricPair metric(std::uint64_t key, std::uint64_t value)
   {
      return MetricPair {key, value};
   }

   MetricPair activityMetric(
      std::uint64_t slot,
      const ContainerParameters& parameters,
      std::uint64_t value)
   {
      return metric(
         (slot << 8u) | static_cast<std::uint64_t>(parameters.datacenterUniqueTag),
         value);
   }

   void queueStats(ProdigySDK::NeuronHub& hub, std::initializer_list<MetricPair> metrics)
   {
      hub.queueStatistics(metrics);
   }

   struct State
   {
      bool advertiser = false;
      bool ready = false;
      bool succeeded = false;
      bool connectInFlight = false;
      int listenFD = -1;
      int sessionFD = -1;
      std::string readBuffer;
      std::optional<SubscriptionPairing> subscription;
      std::vector<AdvertisementPairing> advertisements;
      std::uint64_t pairingEvents = 0;
      std::uint64_t resourceDeltaEvents = 0;
      std::uint64_t credentialRefreshEvents = 0;

      explicit State(const ContainerParameters& parameters)
         : advertiser(parameters.advertises.empty() == false)
      {
      }

      void closeSession(void)
      {
         if (sessionFD >= 0)
         {
            (void)::close(sessionFD);
            sessionFD = -1;
         }

         connectInFlight = false;
         readBuffer.clear();
      }

      void note(NeuronHub& hub, std::uint64_t& counter, std::uint64_t slot)
      {
         counter += 1;
         queueStats(hub, {activityMetric(slot, hub.parameters, counter)});
      }

      void apply(const SubscriptionPairing& pairing)
      {
         if (pairing.activate)
         {
            subscription = pairing;
         }
         else if (subscription.has_value() && sameSecret(subscription->secret, pairing.secret))
         {
            subscription.reset();
         }
      }

      void apply(const AdvertisementPairing& pairing)
      {
         if (pairing.activate)
         {
            for (AdvertisementPairing& existing : advertisements)
            {
               if (sameSecret(existing.secret, pairing.secret))
               {
                  existing = pairing;
                  return;
               }
            }

            advertisements.push_back(pairing);
            return;
         }

         for (auto it = advertisements.begin(); it != advertisements.end(); ++it)
         {
            if (sameSecret(it->secret, pairing.secret))
            {
               advertisements.erase(it);
               return;
            }
         }
      }

      void apply(NeuronHub& hub, const SubscriptionPairing& pairing)
      {
         apply(pairing);
         note(hub, pairingEvents, statPairingActivity);
      }

      void apply(NeuronHub& hub, const AdvertisementPairing& pairing)
      {
         apply(pairing);
         note(hub, pairingEvents, statPairingActivity);
      }

      void noteResourceDelta(NeuronHub& hub, const ResourceDelta& delta)
      {
         (void)delta;
         note(hub, resourceDeltaEvents, statResourceActivity);
      }

      void noteCredentialsRefresh(NeuronHub& hub, const CredentialDelta& delta)
      {
         (void)delta;
         note(hub, credentialRefreshEvents, statCredentialActivity);
      }

      void prime(NeuronHub& hub, const ContainerParameters& parameters)
      {
         for (const SubscriptionPairing& pairing : parameters.subscriptionPairings)
         {
            apply(hub, pairing);
         }

         for (const AdvertisementPairing& pairing : parameters.advertisementPairings)
         {
            apply(hub, pairing);
         }
      }

      bool allowsPeer(const sockaddr_in6& peer) const
      {
         if (advertisements.empty())
         {
            return false;
         }

         for (const AdvertisementPairing& pairing : advertisements)
         {
            if (std::memcmp(&peer.sin6_addr, pairing.address.data(), pairing.address.size()) == 0)
            {
               return true;
            }
         }

         return false;
      }
   };

   class MeshDispatch final : public Dispatch
   {
   private:

      State& state;

   public:

      explicit MeshDispatch(State& inputState)
         : state(inputState)
      {
      }

      void subscriptionPairing(NeuronHub& hub, const SubscriptionPairing& pairing) override
      {
         state.apply(hub, pairing);
      }

      void advertisementPairing(NeuronHub& hub, const AdvertisementPairing& pairing) override
      {
         state.apply(hub, pairing);
      }

      void resourceDelta(NeuronHub& hub, const ResourceDelta& delta) override
      {
         state.noteResourceDelta(hub, delta);
         hub.queueResourceDeltaAck(true);
      }

      void credentialsRefresh(NeuronHub& hub, const CredentialDelta& delta) override
      {
         state.noteCredentialsRefresh(hub, delta);
         hub.queueCredentialsRefreshAck();
      }
   };

   Result openAdvertiserListener(const ContainerParameters& parameters, int& fd)
   {
      fd = -1;
      if (parameters.advertises.empty())
      {
         return Result::argument;
      }

      IPAddress address;
      Result result = private6Address(parameters, address);
      if (result != Result::ok)
      {
         return result;
      }

      sockaddr_in6 local {};
      result = makeIPv6Address(address.address, parameters.advertises.front().port, local);
      if (result != Result::ok)
      {
         return result;
      }

      const int socketFD = ::socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
      if (socketFD < 0)
      {
         return Result::io;
      }

      const int reuse = 1;
      (void)::setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
      if (::bind(socketFD, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0 ||
         ::listen(socketFD, 16) != 0)
      {
         (void)::close(socketFD);
         return Result::io;
      }

      fd = socketFD;
      return Result::ok;
   }

   Result maybeSignalReady(Reactor<Event>::NeuronHandle& neuron, State& state)
   {
      if (state.ready)
      {
         return Result::ok;
      }

      state.ready = true;
      return neuron.ready();
   }

   Result armSessionReadable(Reactor<Event>& reactor, const State& state)
   {
      if (state.sessionFD < 0)
      {
         return Result::argument;
      }

      return reactor.onceReadable(state.sessionFD, Event::sessionReadable);
   }

   Result startSubscriberConnect(Reactor<Event>& reactor, State& state)
   {
      if (state.subscription.has_value() == false)
      {
         return Result::argument;
      }

      sockaddr_in6 remote {};
      Result result = makeIPv6Address(state.subscription->address, state.subscription->port, remote);
      if (result != Result::ok)
      {
         return result;
      }

      const int socketFD = ::socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
      if (socketFD < 0)
      {
         return Result::io;
      }

      if (::connect(socketFD, reinterpret_cast<const sockaddr *>(&remote), sizeof(remote)) == 0)
      {
         state.sessionFD = socketFD;
         state.connectInFlight = false;
         return reactor.emit(Event::connectReady);
      }

      if (errno != EINPROGRESS)
      {
         (void)::close(socketFD);
         return Result::io;
      }

      state.sessionFD = socketFD;
      state.connectInFlight = true;
      return reactor.onceConnect(socketFD, Event::connectReady);
   }

   Result reconcile(
      Reactor<Event>& reactor,
      Reactor<Event>::NeuronHandle& neuron,
      const ContainerParameters& parameters,
      State& state)
   {
      if (state.advertiser)
      {
         if (state.listenFD < 0)
         {
            Result result = openAdvertiserListener(parameters, state.listenFD);
            if (result != Result::ok)
            {
               return result;
            }

            result = maybeSignalReady(neuron, state);
            if (result != Result::ok)
            {
               return result;
            }

            return reactor.onceReadable(state.listenFD, Event::listenReadable);
         }

         return Result::ok;
      }

      if (state.succeeded)
      {
         return Result::ok;
      }

      if (state.subscription.has_value() == false)
      {
         if (state.sessionFD >= 0 || state.connectInFlight)
         {
            state.closeSession();
         }

         return Result::ok;
      }

      if (state.sessionFD >= 0 || state.connectInFlight)
      {
         return Result::ok;
      }

      return startSubscriberConnect(reactor, state);
   }

   Result handleAdvertiserReadable(
      Reactor<Event>& reactor,
      State& state)
   {
      while (true)
      {
         sockaddr_in6 peer {};
         socklen_t peerSize = sizeof(peer);
         const int acceptedFD = ::accept4(
            state.listenFD,
            reinterpret_cast<sockaddr *>(&peer),
            &peerSize,
            SOCK_NONBLOCK);
         if (acceptedFD < 0)
         {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
               return reactor.onceReadable(state.listenFD, Event::listenReadable);
            }

            if (errno == EINTR)
            {
               continue;
            }

            return Result::io;
         }

         if (state.succeeded || state.sessionFD >= 0 || state.allowsPeer(peer) == false)
         {
            (void)::close(acceptedFD);
            continue;
         }

         state.sessionFD = acceptedFD;
         state.connectInFlight = false;
         state.readBuffer.clear();

         Result result = reactor.onceReadable(state.listenFD, Event::listenReadable);
         if (result != Result::ok)
         {
            return result;
         }

         return armSessionReadable(reactor, state);
      }
   }

   Result handleConnectReady(Reactor<Event>& reactor, State& state)
   {
      state.connectInFlight = false;
      Result result = sendLine(state.sessionFD, "ping", 1);
      if (result != Result::ok)
      {
         return result;
      }

      return armSessionReadable(reactor, state);
   }

   Result handleSessionReadable(
      Reactor<Event>& reactor,
      Reactor<Event>::NeuronHandle& neuron,
      State& state)
   {
      char buffer[256];
      while (true)
      {
         const ssize_t bytesRead = ::recv(state.sessionFD, buffer, sizeof(buffer), 0);
         if (bytesRead == 0)
         {
            state.closeSession();
            return Result::ok;
         }

         if (bytesRead < 0)
         {
            if (errno == EINTR)
            {
               continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
               break;
            }

            return Result::io;
         }

         state.readBuffer.append(buffer, buffer + bytesRead);
      }

      while (true)
      {
         const std::size_t newline = state.readBuffer.find('\n');
         if (newline == std::string::npos)
         {
            break;
         }

         const std::string line = state.readBuffer.substr(0, newline);
         state.readBuffer.erase(0, newline + 1);

         unsigned value = 0;
         if (state.advertiser)
         {
            if (parseLine(line, "ping %u", value) == false)
            {
               return Result::protocol;
            }

            Result result = sendLine(state.sessionFD, "pong", value);
            if (result != Result::ok)
            {
               return result;
            }

            if (value >= requiredRounds)
            {
               result = maybeSignalReady(neuron, state);
               state.closeSession();
               return result;
            }
         }
         else
         {
            if (parseLine(line, "pong %u", value) == false)
            {
               return Result::protocol;
            }

            if (value >= requiredRounds)
            {
               Result result = maybeSignalReady(neuron, state);
               state.closeSession();
               return result;
            }

            Result result = sendLine(state.sessionFD, "ping", value + 1);
            if (result != Result::ok)
            {
               return result;
            }
         }
      }

      if (state.sessionFD < 0)
      {
         return Result::ok;
      }

      return armSessionReadable(reactor, state);
   }
}

int main(int argc, char *argv[])
{
   ContainerParameters parameters;
   Result result = ProdigySDK::IOUring::loadContainerParametersFromProcess(argc, argv, parameters);
   if (result != Result::ok)
   {
      return 1;
   }

   State state {parameters};
   MeshDispatch dispatch {state};
   AttachedNeuron neuron {ProdigySDK::NeuronHub(&dispatch, std::move(parameters)), -1};

   Reactor<Event> reactor;
   if (reactor.valid() == false)
   {
      return 1;
   }

   Reactor<Event>::NeuronHandle handle;
   result = reactor.attachNeuron(neuron, handle);
   if (result != Result::ok)
   {
      return 1;
   }

   state.prime(neuron.endpoint(), neuron.endpoint().parameters);
   result = reconcile(reactor, handle, neuron.endpoint().parameters, state);
   if (result != Result::ok)
   {
      return 1;
   }

   while (true)
   {
      ReactorEvent<Event> event;
      result = reactor.next(event);
      if (result != Result::ok)
      {
         break;
      }

      if (const auto *neuronEvent = std::get_if<NeuronEvent>(&event))
      {
         if (*neuronEvent == NeuronEvent::shutdown || *neuronEvent == NeuronEvent::closed)
         {
            result = Result::ok;
            break;
         }

         result = reconcile(reactor, handle, neuron.endpoint().parameters, state);
         if (result != Result::ok)
         {
            break;
         }

         continue;
      }

      switch (std::get<Event>(event))
      {
         case Event::listenReadable:
            result = handleAdvertiserReadable(reactor, state);
            break;
         case Event::connectReady:
            result = handleConnectReady(reactor, state);
            break;
         case Event::sessionReadable:
            result = handleSessionReadable(reactor, handle, state);
            break;
      }

      if (result != Result::ok)
      {
         break;
      }

      result = reconcile(reactor, handle, neuron.endpoint().parameters, state);
      if (result != Result::ok)
      {
         break;
      }
   }

   state.closeSession();
   if (state.listenFD >= 0)
   {
      (void)::close(state.listenFD);
   }

   return result == Result::ok ? 0 : 1;
}
