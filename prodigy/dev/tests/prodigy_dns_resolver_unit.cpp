#include <networking/includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/ring.h>
#include <prodigy/dns/resolver.service.h>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      basics_log("%s: %s\n", condition ? "PASS" : "FAIL", name);
      failed += condition ? 0 : 1;
   }
};

static Whitehole whitehole(ExternalAddressTransport transport,
                           ExternalAddressFamily family,
                           uint16_t port,
                           uint64_t nonce,
                           uint8_t addressSuffix)
{
   Whitehole endpoint;
   endpoint.transport = transport;
   endpoint.family = family;
   endpoint.source = ExternalAddressSource::hostPublicAddress;
   endpoint.hasAddress = true;
   endpoint.sourcePort = port;
   endpoint.bindingNonce = nonce;

   char address[64] = {};
   if (family == ExternalAddressFamily::ipv4)
   {
      snprintf(address, sizeof(address), "192.0.2.%u", unsigned(addressSuffix));
      endpoint.address = IPAddress(address, false);
   }
   else
   {
      snprintf(address, sizeof(address), "2001:db8::%x", unsigned(addressSuffix));
      endpoint.address = IPAddress(address, true);
   }
   return endpoint;
}

static ContainerParameters validParameters(void)
{
   ContainerParameters parameters;
   parameters.private6 = IPPrefix("fd00::53", true, 128);
   parameters.advertisesOnPorts.emplace(MeshRegistry::DNS::resolver, 5353);

   uint16_t port = 40000;
   uint64_t nonce = 1;
   uint8_t suffix = 1;
   for (ExternalAddressTransport transport : {
            ExternalAddressTransport::quic,
            ExternalAddressTransport::tcp})
   {
      for (ExternalAddressFamily family : {
               ExternalAddressFamily::ipv4,
               ExternalAddressFamily::ipv6})
      {
         for (size_t index = 0;
              index < ProdigyDns::endpointsPerTransportFamily;
              index += 1)
         {
            parameters.whiteholes.push_back(
                whitehole(transport, family, port++, nonce++, suffix++));
         }
      }
   }
   return parameters;
}

static bool endpointsAreExact(const LocalSocketBindSet& endpoints)
{
   if (endpoints.count(AF_INET) != 2 || endpoints.count(AF_INET6) != 2)
   {
      return false;
   }
   for (size_t index = 0; index < endpoints.size(); index += 1)
   {
      const LocalSocketBindSet::Endpoint *endpoint = endpoints.at(index);
      if (endpoint == nullptr || endpoint->freebind == false)
      {
         return false;
      }
   }
   return true;
}

static void testRuntimeConfig(TestSuite& suite)
{
   ContainerParameters parameters = validParameters();
   ProdigyDns::RuntimeConfig config;
   String failure;
   suite.expect(ProdigyDns::configure(parameters, config, &failure),
                "dns_config_accepts_exact_contract");
   suite.expect(failure.empty() &&
                    config.service == MeshRegistry::DNS::resolver &&
                    config.applicationID == MeshRegistry::DNS::applicationID &&
                    config.listenPort == 5353 && config.listenAddress.is6,
                "dns_config_preserves_service_and_private6_listener");
   suite.expect(config.backend.servers.equal(
                    ProdigyDns::upstreamServers,
                    sizeof(ProdigyDns::upstreamServers) - 1) &&
                    config.backend.stayOpen && config.backend.tries == 2 &&
                    config.backend.udpMaximumQueries == 256,
                "dns_config_owns_literal_stay_open_upstreams");
   suite.expect(config.resolver.positiveCacheEntries == 448 &&
                    config.resolver.negativeCacheEntries == 64 &&
                    config.resolver.activeQueries == 256 &&
                    config.resolver.waitersPerQuery == 64 &&
                    config.resolver.totalWaiters == 1024 &&
                    config.resolver.answers == 32 &&
                    config.resolver.maximumPositiveTtlSeconds == 3600 &&
                    config.resolver.rejectSingleLabel,
                "dns_config_owns_cache_singleflight_and_ttl_bounds");
   suite.expect(endpointsAreExact(config.backend.udpBinds) &&
                    endpointsAreExact(config.backend.tcpBinds),
                "dns_config_builds_two_freebind_endpoints_per_transport_family");

   ContainerParameters missing = validParameters();
   missing.whiteholes.pop_back();
   suite.expect(ProdigyDns::configure(missing, config) == false,
                "dns_config_rejects_missing_whitehole");

   ContainerParameters duplicate = validParameters();
   duplicate.whiteholes[1] = duplicate.whiteholes[0];
   suite.expect(ProdigyDns::configure(duplicate, config) == false,
                "dns_config_rejects_duplicate_whitehole");

   ContainerParameters wrongSource = validParameters();
   wrongSource.whiteholes[0].source =
       ExternalAddressSource::registeredRoutablePrefix;
   suite.expect(ProdigyDns::configure(wrongSource, config) == false,
                "dns_config_rejects_non_host_public_source");

   ContainerParameters wrongFamily = validParameters();
   wrongFamily.whiteholes[0].address = IPAddress("2001:db8::99", true);
   suite.expect(ProdigyDns::configure(wrongFamily, config) == false,
                "dns_config_rejects_address_family_mismatch");

   ContainerParameters wrongService = validParameters();
   wrongService.advertisesOnPorts.clear();
   wrongService.advertisesOnPorts.emplace(MeshRegistry::DNS::resolver + 1, 5353);
   suite.expect(ProdigyDns::configure(wrongService, config) == false,
                "dns_config_rejects_non_platform_service");

   ContainerParameters credentialed = validParameters();
   credentialed.hasCredentialBundle = true;
   suite.expect(ProdigyDns::configure(credentialed, config) == false,
                "dns_config_rejects_credentials");

   ContainerParameters subscribed = validParameters();
   subscribed.subscriptionPairings.insert(
       MeshRegistry::DNS::resolver,
       SubscriptionPairing(1, 2, MeshRegistry::DNS::resolver, 5353));
   suite.expect(ProdigyDns::configure(subscribed, config) == false,
                "dns_config_rejects_subscriptions");

   ContainerParameters wormholed = validParameters();
   wormholed.wormholes.emplace_back();
   suite.expect(ProdigyDns::configure(wormholed, config) == false,
                "dns_config_rejects_wormholes");
}

static void testSessionIdentity(TestSuite& suite)
{
   suite.expect(ProdigyDns::maximumRequestsPerStream == 64 &&
                    ProdigyDns::maximumRequests == 1024 &&
                    ProdigyDns::maximumStreams == 1024,
                "dns_service_capacity_is_bounded");
   suite.expect(ProdigyDns::canQueueFrame(
                    0, ProdigyDns::Wire::maximumResolveFrameBytes) &&
                    ProdigyDns::canQueueFrame(
                        ProdigyDns::maximumQueuedCiphertextBytes -
                            ProdigyDns::maximumEncryptedFrameBytes,
                        ProdigyDns::Wire::maximumResolveFrameBytes) &&
                    ProdigyDns::canQueueFrame(
                        ProdigyDns::maximumQueuedCiphertextBytes,
                        ProdigyDns::Wire::maximumResolveFrameBytes) == false,
                "dns_service_enforces_ciphertext_high_water");

   ProdigyDns::Wire::Session expected;
   expected.phase = ProdigyDns::Wire::SessionPhase::serviceChallenge;
   expected.applicationID = MeshRegistry::DNS::applicationID;
   expected.service = MeshRegistry::DNS::resolver;
   expected.nonce = 123;
   expected.generation = 456;

   ProdigyDns::Wire::Session echo = expected;
   echo.phase = ProdigyDns::Wire::SessionPhase::applicationEcho;
   suite.expect(ProdigyDns::exactSessionEcho(expected, echo),
                "dns_session_accepts_exact_application_echo");
   echo.applicationID += 1;
   suite.expect(ProdigyDns::exactSessionEcho(expected, echo) == false,
                "dns_session_rejects_wrong_application");
   echo = expected;
   echo.phase = ProdigyDns::Wire::SessionPhase::applicationEcho;
   echo.generation += 1;
   suite.expect(ProdigyDns::exactSessionEcho(expected, echo) == false,
                "dns_session_rejects_wrong_generation");
}

static void testPairingCollision(TestSuite& suite)
{
   ProdigyDns::PairingRegistry pairings(4);
   uint128_t found = 0;
   ProdigyDns::Stream first;
   ProdigyDns::Stream second;
   ProdigyDns::Stream third;
   suite.expect(pairings.activate(7, 11).status ==
                    ProdigyDns::PairingRegistry::Activation::accepted &&
                    pairings.claim(7, &first, found) && found == 11,
                "dns_pairing_registry_accepts_first_secret");
   suite.expect(pairings.activate(7, 11).status ==
                    ProdigyDns::PairingRegistry::Activation::alreadyPresent &&
                    pairings.claim(7, &second, found) == false,
                "dns_pairing_registry_accepts_idempotent_activation");
   const ProdigyDns::PairingRegistry::ActivationResult collision =
       pairings.activate(7, 12);
   suite.expect(collision.status ==
                    ProdigyDns::PairingRegistry::Activation::collision &&
                    collision.displacedOwner == &first &&
                    pairings.claim(7, &second, found) == false,
                "dns_pairing_registry_fails_closed_on_hash_collision");
   suite.expect(pairings.activate(8, 13).status ==
                    ProdigyDns::PairingRegistry::Activation::accepted &&
                    pairings.claim(8, &first, found) && found == 13 &&
                    pairings.deactivate(8, 12) == nullptr &&
                    pairings.deactivate(8, 13) == &first,
                "dns_pairing_registry_requires_exact_deactivation_secret");

   ProdigyDns::PairingRegistry bounded(2);
   suite.expect(bounded.activate(1, 101).status ==
                    ProdigyDns::PairingRegistry::Activation::accepted &&
                    bounded.activate(2, 102).status ==
                        ProdigyDns::PairingRegistry::Activation::accepted &&
                    bounded.activate(1, 101).status ==
                        ProdigyDns::PairingRegistry::Activation::alreadyPresent &&
                    bounded.activate(3, 103).status ==
                        ProdigyDns::PairingRegistry::Activation::full,
                "dns_pairing_registry_enforces_capacity_after_idempotence");

   ProdigyDns::PairingRegistry ownership(2);
   suite.expect(ownership.activate(101, 201).status ==
                    ProdigyDns::PairingRegistry::Activation::accepted &&
                    ownership.activate(102, 202).status ==
                        ProdigyDns::PairingRegistry::Activation::accepted &&
                    ownership.claim(101, &first, found) &&
                    ownership.claim(101, &first, found) &&
                    ownership.claim(101, &second, found) == false,
                "dns_pairing_registry_rejects_duplicate_live_owner");
   suite.expect(ownership.release(101, 201, &second) == false &&
                    ownership.release(101, 201, &first) &&
                    ownership.claim(101, &third, found),
                "dns_pairing_registry_releases_only_exact_owner");
}

static void testResultTranslation(TestSuite& suite)
{
   AsyncDnsResolver::Result backend;
   backend.status = AsyncDnsResolver::Status::success;
   backend.canonicalName.assign("WWW.Example.COM.");
   backend.canonicalNameTtlSeconds = 60;
   AsyncDnsResolver::Address address;
   sockaddr_in *address4 = reinterpret_cast<sockaddr_in *>(&address.storage);
   address4->sin_family = AF_INET;
   inet_pton(AF_INET, "203.0.113.9", &address4->sin_addr);
   address.length = sizeof(sockaddr_in);
   address.ttlSeconds = 30;
   backend.addresses.push_back(address);

   String frame;
   ProdigyDns::Wire::Resolve result;
   suite.expect(ProdigyDns::Resolver::encodeResult(91, 92, std::move(backend), frame) &&
                    ProdigyDns::Wire::parseResolveResult(
                        frame.data(), frame.size(), result),
                "dns_result_translation_roundtrips_wire_frame");
   suite.expect(result.requestID == 91 && result.generation == 92 &&
                    result.status == ProdigyDns::Wire::ResolveStatus::success &&
                    result.canonicalName.equal("www.example.com"_ctv) &&
                    result.addresses.size() == 1 &&
                    result.addresses[0].family == ProdigyDns::Wire::Family::ipv4 &&
                    result.addresses[0].ttlSeconds == 30,
                "dns_result_translation_normalizes_canonical_and_address");

   AsyncDnsResolver::Result missing;
   missing.status = AsyncDnsResolver::Status::notFound;
   frame.clear();
   result = {};
   suite.expect(ProdigyDns::Resolver::encodeResult(93, 94, std::move(missing), frame) &&
                    ProdigyDns::Wire::parseResolveResult(
                        frame.data(), frame.size(), result) &&
                    result.status == ProdigyDns::Wire::ResolveStatus::notFound &&
                    result.addresses.empty(),
                "dns_result_translation_preserves_negative_status");
}

int main(void)
{
   TestSuite suite;
   testRuntimeConfig(suite);
   testSessionIdentity(suite);
   testPairingCollision(suite);
   testResultTranslation(suite);
   return suite.failed == 0 ? 0 : 1;
}
