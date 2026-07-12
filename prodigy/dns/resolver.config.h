#pragma once

#include <networking/async.dns.cares.h>
#include <prodigy/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace ProdigyDns
{

constexpr static size_t whiteholeEndpointCount = 8;
constexpr static size_t endpointsPerTransportFamily = 2;
constexpr static char upstreamServers[] =
    "1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001";

struct RuntimeConfig
{
   uint64_t service = 0;
   uint16_t applicationID = 0;
   uint16_t listenPort = 0;
   IPAddress listenAddress;
   AsyncDnsResolver::Config resolver;
   RingAsyncDnsResolver::BackendConfig backend;
   bool controlDeployment = false;
};

inline bool validControlWormhole(const Wormhole& wormhole,
                                 uint16_t listenPort)
{
   return wormhole.name.equal("dns-control"_ctv) &&
          wormhole.externalAddress.is6 &&
          wormhole.externalAddress.isNull() == false &&
          wormhole.externalPort == listenPort &&
          wormhole.containerPort == listenPort &&
          wormhole.layer4 == IPPROTO_TCP && wormhole.isQuic == false &&
          wormhole.source == ExternalAddressSource::registeredRoutablePrefix &&
          wormhole.routablePrefixUUID != 0 &&
          wormhole.hasTlsResumptionConfig == false &&
          wormhole.hasDNSConfig == false;
}

inline bool addWhiteholeEndpoint(LocalSocketBindSet& endpoints,
                                 const Whitehole& whitehole)
{
   if (whitehole.family == ExternalAddressFamily::ipv4)
   {
      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_port = htons(whitehole.sourcePort);
      address.sin_addr.s_addr = whitehole.address.v4;
      return endpoints.add(reinterpret_cast<const sockaddr *>(&address),
                           sizeof(address),
                           true);
   }

   sockaddr_in6 address = {};
   address.sin6_family = AF_INET6;
   address.sin6_port = htons(whitehole.sourcePort);
   memcpy(&address.sin6_addr, whitehole.address.v6, sizeof(address.sin6_addr));
   return endpoints.add(reinterpret_cast<const sockaddr *>(&address),
                        sizeof(address),
                        true);
}

inline bool configure(const ContainerParameters& parameters,
                      RuntimeConfig& config,
                      String *failure = nullptr)
{
   auto fail = [&](const auto& message) -> bool {
      if (failure)
      {
         failure->assign(message);
      }
      return false;
   };

   config = {};
   if (parameters.advertisesOnPorts.size() != 1)
   {
      return fail("DNS resolver requires exactly one advertisement"_ctv);
   }
   if (parameters.subscriptionPairings.size() != 0)
   {
      return fail("DNS resolver does not accept subscriptions"_ctv);
   }
   if (parameters.hasCredentialBundle)
   {
      return fail("DNS resolver does not accept credentials"_ctv);
   }
   if (parameters.wormholes.size() > 1)
   {
      return fail("DNS resolver accepts only the strict control wormhole variant"_ctv);
   }
   if (parameters.private6.network.is6 == false ||
       parameters.private6.network.isNull())
   {
      return fail("DNS resolver requires a private IPv6 address"_ctv);
   }

   const auto advertisement = parameters.advertisesOnPorts.begin();
   config.service = advertisement->first;
   config.applicationID = uint16_t(config.service >> 48);
   config.listenPort = advertisement->second;
   config.listenAddress = parameters.private6.network;
   if (config.service != MeshRegistry::DNS::resolver ||
       config.applicationID != MeshRegistry::DNS::applicationID ||
       config.listenPort == 0)
   {
      return fail("DNS resolver advertisement is invalid"_ctv);
   }

   if (parameters.wormholes.size() == 1)
   {
      if (validControlWormhole(parameters.wormholes[0], config.listenPort) == false)
      {
         return fail("DNS resolver control wormhole shape is invalid"_ctv);
      }
      config.controlDeployment = true;
   }

   if (parameters.whiteholes.size() != whiteholeEndpointCount ||
       resolvedWhiteholesValid(parameters.whiteholes) == false)
   {
      return fail("DNS resolver requires exactly eight resolved DNS whiteholes"_ctv);
   }

   size_t counts[2][2] = {};
   bytell_hash_set<uint64_t> nonces;
   nonces.reserve(whiteholeEndpointCount);

   for (const Whitehole& whitehole : parameters.whiteholes)
   {
      if (whitehole.source != ExternalAddressSource::hostPublicAddress ||
          nonces.emplace(whitehole.bindingNonce).second == false)
      {
         return fail("DNS resolver whitehole source or nonce is invalid"_ctv);
      }

      const size_t transport =
          whitehole.transport == ExternalAddressTransport::quic ? 0 : 1;
      const size_t family =
          whitehole.family == ExternalAddressFamily::ipv4 ? 0 : 1;
      if (++counts[transport][family] > endpointsPerTransportFamily)
      {
         return fail("DNS resolver whitehole transport/family shape is invalid"_ctv);
      }

      LocalSocketBindSet& endpoints = transport == 0
                                          ? config.backend.udpBinds
                                          : config.backend.tcpBinds;
      if (addWhiteholeEndpoint(endpoints, whitehole) == false)
      {
         return fail("DNS resolver whitehole endpoint is duplicated or invalid"_ctv);
      }
   }

   for (size_t transport = 0; transport < 2; transport += 1)
   {
      for (size_t family = 0; family < 2; family += 1)
      {
         if (counts[transport][family] != endpointsPerTransportFamily)
         {
            return fail("DNS resolver whitehole transport/family shape is incomplete"_ctv);
         }
      }
   }

   config.backend.timeoutMilliseconds = 1000;
   config.backend.tries = 2;
   config.backend.maximumTimeoutMilliseconds = 2000;
   config.backend.udpMaximumQueries = 256;
   config.backend.servers.assign(upstreamServers);
   config.backend.stayOpen = true;
   config.resolver.positiveCacheEntries = 448;
   config.resolver.negativeCacheEntries = 64;
   config.resolver.activeQueries = 256;
   config.resolver.waitersPerQuery = 64;
   config.resolver.totalWaiters = 1024;
   config.resolver.answers = 32;
   config.resolver.maximumPositiveTtlSeconds = 3600;
   config.resolver.rejectSingleLabel = true;

   if (failure)
   {
      failure->clear();
   }
   return true;
}

} // namespace ProdigyDns
