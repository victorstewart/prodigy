#include <networking/includes.h>
#include <services/debug.h>

#include <switchboard/common/balancer.policy.h>

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

int main(void)
{
   TestSuite suite = {};

   suite.expect(
      switchboardBalancerPassesIPv6ToKernel(IPPROTO_ICMPV6),
      "switchboard_balancer_ipv6_icmp_passes_to_kernel"
   );
   suite.expect(
      switchboardBalancerPassesIPv6ToKernel(IPPROTO_UDP) == false,
      "switchboard_balancer_ipv6_udp_stays_on_balancer_path"
   );
   suite.expect(
      switchboardBalancerPassesIPv6ToKernel(IPPROTO_TCP) == false,
      "switchboard_balancer_ipv6_tcp_stays_on_balancer_path"
   );
   suite.expect(
      switchboardBalancerPassesIPv6ToKernel(0) == false,
      "switchboard_balancer_ipv6_hop_by_hop_does_not_bypass_balancer_logic"
   );

   return suite.failed == 0 ? 0 : 1;
}
