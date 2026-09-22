#include <limits.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include <networking/includes.h>
#include <services/debug.h>

#include <switchboard/common/balancer.policy.h>

// Exercise the production ring builder without constructing runtime/BPF owners.
namespace MaglevFixture {
struct Wormhole {
  uint32_t containerID;
  uint32_t weight;
  uint64_t hash() const { return 156164; }
};
struct Portal {
  std::vector<Wormhole *> wormholes;
};
#include <switchboard/maglevhashv2.h>
}

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      basics_log("PASS: %s\n", name);
    }
    else
    {
      basics_log("FAIL: %s\n", name);
      failed += 1;
    }
  }
};

int main(void)
{
  TestSuite suite = {};

  // This endpoint produces offset 30993 and skip 65536. A 32-bit probe
  // product wraps before the last slot (30994), then repeats forever.
  MaglevFixture::Wormhole wormhole = {9, 1};
  MaglevFixture::Portal portal = {{&wormhole}};
  const auto ring = MaglevFixture::MaglevHashV2::generateHashRingForPortal(&portal);
  suite.expect(
      std::all_of(ring.begin(), ring.end(), [](uint32_t endpoint) { return endpoint == 9; }),
      "switchboard_maglev_maximum_skip_fills_entire_prime_ring");

  suite.expect(
      switchboardBalancerPassesIPv6ToKernel(IPPROTO_ICMPV6),
      "switchboard_balancer_ipv6_icmp_passes_to_kernel");
  suite.expect(
      switchboardBalancerPassesIPv6ToKernel(IPPROTO_IPIP),
      "switchboard_balancer_ipv6_ipip_overlay_passes_to_kernel");
  suite.expect(
      switchboardBalancerPassesIPv6ToKernel(IPPROTO_IPV6),
      "switchboard_balancer_ipv6_in_ipv6_overlay_passes_to_kernel");
  suite.expect(
      switchboardBalancerPassesIPv6ToKernel(IPPROTO_UDP) == false,
      "switchboard_balancer_ipv6_udp_stays_on_balancer_path");
  suite.expect(
      switchboardBalancerPassesIPv6ToKernel(IPPROTO_TCP) == false,
      "switchboard_balancer_ipv6_tcp_stays_on_balancer_path");
  suite.expect(
      switchboardBalancerPassesIPv6ToKernel(0) == false,
      "switchboard_balancer_ipv6_hop_by_hop_does_not_bypass_balancer_logic");

  suite.expect(
      switchboardQuicV1PacketTypeAllowsHashFallback(QUIC_V1_CLIENT_INITIAL),
      "switchboard_balancer_quic_initial_allows_hash_fallback");
  suite.expect(
      switchboardQuicV1PacketTypeAllowsHashFallback(QUIC_V1_0RTT) == false,
      "switchboard_balancer_quic_0rtt_rejects_hash_fallback");
  suite.expect(
      switchboardQuicV1PacketTypeAllowsHashFallback(QUIC_V1_HANDSHAKE) == false,
      "switchboard_balancer_quic_handshake_rejects_hash_fallback");
  suite.expect(
      switchboardQuicV1PacketTypeAllowsHashFallback(QUIC_V1_RETRY) == false,
      "switchboard_balancer_quic_retry_rejects_hash_fallback");

  suite.expect(
      switchboardQuicV1DestinationCidUsesProdigySchema(QUIC_CID_LEN),
      "switchboard_balancer_quic_exact_prodigy_cid_length_matches_schema");
  suite.expect(
      switchboardQuicV1DestinationCidUsesProdigySchema(8) == false,
      "switchboard_balancer_quic_foreign_short_cid_is_not_prodigy_schema");
  suite.expect(
      switchboardQuicV1DestinationCidUsesProdigySchema(20) == false,
      "switchboard_balancer_quic_foreign_long_cid_is_not_prodigy_schema");
  suite.expect(
      switchboardQuicV1DestinationCidLengthValid(20),
      "switchboard_balancer_quic_max_v1_cid_length_is_valid");
  suite.expect(
      switchboardQuicV1DestinationCidLengthValid(21) == false,
      "switchboard_balancer_quic_over_max_v1_cid_length_is_invalid");

  suite.expect(
      switchboardQuicV1LongHeaderAllowsHashFallback(QUIC_V1_CLIENT_INITIAL, 8),
      "switchboard_balancer_quic_foreign_initial_cid_allows_hash_fallback");
  suite.expect(
      switchboardQuicV1LongHeaderAllowsHashFallback(QUIC_V1_0RTT, 20) == false,
      "switchboard_balancer_quic_foreign_0rtt_cid_rejects_hash_fallback");
  suite.expect(
      switchboardQuicV1LongHeaderAllowsHashFallback(QUIC_V1_HANDSHAKE, 8) == false,
      "switchboard_balancer_quic_foreign_handshake_cid_rejects_hash_fallback");
  suite.expect(
      switchboardQuicV1LongHeaderAllowsHashFallback(QUIC_V1_CLIENT_INITIAL, 21) == false,
      "switchboard_balancer_quic_invalid_initial_cid_length_rejects_hash_fallback");

  return suite.failed == 0 ? 0 : 1;
}
