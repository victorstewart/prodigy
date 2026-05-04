#include <networking/includes.h>
#include <services/debug.h>

#include <switchboard/owned.routable.prefix.h>
#include <switchboard/common/local_container_subnet.h>

#include <arpa/inet.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

class TestSuite
{
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

static DistributableExternalSubnet makeSubnet(const char *name, const char *cidr)
{
   DistributableExternalSubnet subnet = {};
   subnet.name.assign(name);

   const char *slash = std::strrchr(cidr, '/');
   if (slash == nullptr)
   {
      std::fprintf(stderr, "unable to parse cidr: %s\n", cidr);
      std::abort();
   }

   String addressText = {};
   addressText.assign(cidr, uint64_t(slash - cidr));

   unsigned long prefixLength = std::strtoul(slash + 1, nullptr, 10);
   if (ClusterMachine::parseIPAddressLiteral(addressText, subnet.subnet.network) == false)
   {
      std::fprintf(stderr, "unable to parse cidr address: %s\n", cidr);
      std::abort();
   }

   subnet.subnet.cidr = uint8_t(prefixLength);

   return subnet;
}

static bool parseIPv6(const char *text, uint8_t out[16])
{
   return inet_pton(AF_INET6, text, out) == 1;
}

int main(void)
{
   TestSuite suite = {};

   Vector<DistributableExternalSubnet> subnets;
   subnets.push_back(makeSubnet("public-v4-a", "198.18.55.77/12"));
   subnets.push_back(makeSubnet("public-v4-b", "198.16.0.1/12"));
   subnets.push_back(makeSubnet("public-v6-a", "2602:fac0:0000:12ab:34cd:00aa::1234/64"));
   subnets.push_back(makeSubnet("public-v6-b", "2602:fac0:0000:12ab::beef/64"));

   Vector<switchboard_owned_routable_prefix4_key> keys4;
   Vector<switchboard_owned_routable_prefix6_key> keys6;
   switchboardBuildOwnedRoutablePrefixKeys(subnets, keys4, keys6);

   suite.expect(keys4.size() == 1, "switchboard_routable_prefix_ipv4_dedupes_equivalent_prefixes");
   suite.expect(keys4[0].prefixlen == 12, "switchboard_routable_prefix_ipv4_prefixlen");
   suite.expect(ntohl(keys4[0].addr) == 0xC6100000u, "switchboard_routable_prefix_ipv4_masks_host_bits");

   suite.expect(keys6.size() == 1, "switchboard_routable_prefix_ipv6_dedupes_equivalent_prefixes");
   suite.expect(keys6[0].prefixlen == 64, "switchboard_routable_prefix_ipv6_prefixlen");

   const uint8_t expectedIPv6[16] = {
      0x26, 0x02, 0xfa, 0xc0,
      0x00, 0x00, 0x12, 0xab,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
   };
   suite.expect(memcmp(keys6[0].addr, expectedIPv6, sizeof(expectedIPv6)) == 0, "switchboard_routable_prefix_ipv6_masks_host_bits");

   Vector<DistributableExternalSubnet> mixedSubnets;
   mixedSubnets.push_back(makeSubnet("mixed-v4", "203.0.113.128/20"));
   mixedSubnets.push_back(makeSubnet("mixed-v6", "2001:db8:abcd:1234:5678:9abc::1/72"));
   switchboardBuildOwnedRoutablePrefixKeys(mixedSubnets, keys4, keys6);

   suite.expect(keys4.size() == 1, "switchboard_routable_prefix_mixed_keeps_one_ipv4_key");
   suite.expect(keys6.size() == 1, "switchboard_routable_prefix_mixed_keeps_one_ipv6_key");
   suite.expect(ntohl(keys4[0].addr) == 0xCB007000u, "switchboard_routable_prefix_mixed_ipv4_canonicalizes");

   const uint8_t expectedMixedIPv6[16] = {
      0x20, 0x01, 0x0d, 0xb8,
      0xab, 0xcd, 0x12, 0x34,
      0x56, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
   };
   suite.expect(memcmp(keys6[0].addr, expectedMixedIPv6, sizeof(expectedMixedIPv6)) == 0, "switchboard_routable_prefix_mixed_ipv6_canonicalizes");

   {
      local_container_subnet6 subnet = {
         .dpfx = 0x01,
         .mpfx = {0xf2, 0x66, 0xe5}
      };
      uint8_t sameMachineA[16] = {};
      uint8_t sameMachineB[16] = {};
      uint8_t differentMachine[16] = {};
      uint8_t differentDatacenter[16] = {};

      suite.expect(parseIPv6("fdf8:d94c:7c33:e26e:ca4b:f501:f266:e5d9", sameMachineA), "switchboard_local_container_subnet_parse_same_machine_a");
      suite.expect(parseIPv6("fdf8:d94c:7c33:e26e:ca4b:f501:f266:e543", sameMachineB), "switchboard_local_container_subnet_parse_same_machine_b");
      suite.expect(parseIPv6("fdf8:d94c:7c33:e26e:ca4b:f501:7347:a9db", differentMachine), "switchboard_local_container_subnet_parse_different_machine");
      suite.expect(parseIPv6("fdf8:d94c:7c33:e26e:ca4b:f502:f266:e5d9", differentDatacenter), "switchboard_local_container_subnet_parse_different_datacenter");

      suite.expect(switchboardLocalContainerSubnetMatchesIPv6(sameMachineA, &subnet), "switchboard_local_container_subnet_matches_same_machine_a");
      suite.expect(switchboardLocalContainerSubnetMatchesIPv6(sameMachineB, &subnet), "switchboard_local_container_subnet_matches_same_machine_b");
      suite.expect(!switchboardLocalContainerSubnetMatchesIPv6(differentMachine, &subnet), "switchboard_local_container_subnet_rejects_different_machine");
      suite.expect(!switchboardLocalContainerSubnetMatchesIPv6(differentDatacenter, &subnet), "switchboard_local_container_subnet_rejects_different_datacenter");
   }

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
