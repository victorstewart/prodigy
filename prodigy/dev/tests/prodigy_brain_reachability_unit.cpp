#include <prodigy/brain.reachability.h>
#include <services/debug.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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
   TestSuite suite;

   ClusterMachine machine = {};
   machine.ssh.address.assign("2001:db8::10"_ctv);
   prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, "10.0.0.10"_ctv);

   IPAddress peerAddress = {};
   String peerAddressText = {};
   suite.expect(machine.resolvePeerAddress(peerAddress, &peerAddressText), "resolve_peer_address_prefers_private_address");
   suite.expect(peerAddress.is6 == false, "resolve_peer_address_prefers_private_address_family");
   suite.expect(peerAddressText.equals("10.0.0.10"_ctv), "resolve_peer_address_prefers_private_address_text");

   ClusterMachine sshFallbackMachine = {};
   sshFallbackMachine.ssh.address.assign("2001:db8::10"_ctv);
   prodigyAppendUniqueClusterMachineAddress(sshFallbackMachine.addresses.publicAddresses, "203.0.113.10"_ctv);
   peerAddress = {};
   peerAddressText.clear();
   suite.expect(sshFallbackMachine.resolvePeerAddress(peerAddress, &peerAddressText), "resolve_peer_address_falls_back_to_ssh_address");
   suite.expect(peerAddress.is6, "resolve_peer_address_falls_back_to_ssh_address_family");
   suite.expect(peerAddressText.equals("2001:db8::10"_ctv), "resolve_peer_address_falls_back_to_ssh_address_text");

   ClusterMachine fallbackMachine = {};
   prodigyAppendUniqueClusterMachineAddress(fallbackMachine.addresses.privateAddresses, "10.2.3.4"_ctv, 24, "10.2.3.1"_ctv);
   peerAddress = {};
   peerAddressText.clear();
   suite.expect(fallbackMachine.resolvePeerAddress(peerAddress, &peerAddressText), "resolve_peer_address_uses_private_address");
   suite.expect(peerAddress.is6 == false, "resolve_peer_address_uses_private_address_family");
   suite.expect(peerAddressText.equals("10.2.3.4"_ctv), "resolve_peer_address_uses_private_address_text");

   ClusterMachine peerIdentityA = {};
   prodigyAppendUniqueClusterMachineAddress(peerIdentityA.addresses.publicAddresses, "2602:fac0:0:12ab:34cd::20"_ctv);
   ClusterMachine peerIdentityB = {};
   prodigyAppendUniqueClusterMachineAddress(peerIdentityB.addresses.publicAddresses, "2602:fac0:0:12ab:34cd::20"_ctv);
   suite.expect(peerIdentityA.sameIdentityAs(peerIdentityB), "same_identity_accepts_ipv6_peer_address");

   bool reachable = false;
   uint32_t latencyMs = 0;
   String failure = {};
   suite.expect(
      prodigyParseReachabilityProbeOutput(
         "PING 1.2.3.4 (1.2.3.4): 56 data bytes\n64 bytes from 1.2.3.4: icmp_seq=1 ttl=57 time=2.31 ms\n\n__PRODIGY_PING_RC__=0\n"_ctv,
         reachable,
         latencyMs,
         &failure
      ),
      "parse_ping_probe_success"
   );
   suite.expect(reachable, "parse_ping_probe_success_reachable");
   suite.expect(latencyMs == 2, "parse_ping_probe_success_latency");
   suite.expect(failure.size() == 0, "parse_ping_probe_success_failure_clear");

   reachable = true;
   latencyMs = 99;
   failure.clear();
   suite.expect(
      prodigyParseReachabilityProbeOutput(
         "PING 2001:db8::20(2001:db8::20) 56 data bytes\nping: connect: Network is unreachable\n__PRODIGY_PING_RC__=2\n"_ctv,
         reachable,
         latencyMs,
         &failure
      ),
      "parse_ping_probe_failure"
   );
   suite.expect(reachable == false, "parse_ping_probe_failure_reachable_false");
   suite.expect(latencyMs == 0, "parse_ping_probe_failure_zero_latency");
   suite.expect(failure.equals("PING 2001:db8::20(2001:db8::20) 56 data bytes\nping: connect: Network is unreachable"_ctv), "parse_ping_probe_failure_text");

   struct sockaddr_in6 mapped = {};
   mapped.sin6_family = AF_INET6;
   mapped.sin6_addr.s6_addr[10] = 0xFF;
   mapped.sin6_addr.s6_addr[11] = 0xFF;
   mapped.sin6_addr.s6_addr[12] = 10;
   mapped.sin6_addr.s6_addr[13] = 9;
   mapped.sin6_addr.s6_addr[14] = 8;
   mapped.sin6_addr.s6_addr[15] = 7;
   IPAddress acceptedAddress = {};
   String acceptedText = {};
   suite.expect(prodigySockaddrToIPAddress(reinterpret_cast<struct sockaddr *>(&mapped), acceptedAddress, &acceptedText), "sockaddr_to_ip_v4_mapped");
   suite.expect(acceptedAddress.is6 == false, "sockaddr_to_ip_v4_mapped_family");
   suite.expect(acceptedText.equals("10.9.8.7"_ctv), "sockaddr_to_ip_v4_mapped_text");

   Vector<ClusterMachine> sourceBrains;
   ClusterMachine sourceA = {};
   sourceA.ssh.address.assign("10.0.0.1"_ctv);
   sourceBrains.push_back(sourceA);
   ClusterMachine sourceB = {};
   sourceB.ssh.address.assign("10.0.0.2"_ctv);
   sourceBrains.push_back(sourceB);

   Vector<BrainReachabilityProbeResult> results;
   failure.clear();
   suite.expect(
      prodigyProbeAddressFromClusterBrains(
         sourceBrains,
         "203.0.113.10"_ctv,
         [] (const ClusterMachine& sourceBrain, const String& targetAddress, BrainReachabilityProbeResult& result, String& probeFailure) -> bool {
            (void)targetAddress;
            if (sourceBrain.ssh.address.equals("10.0.0.1"_ctv))
            {
               result.reachable = true;
               result.latencyMs = 2;
               result.failure.clear();
               probeFailure.clear();
               return true;
            }

            result.reachable = false;
            result.latencyMs = 0;
            result.failure.assign("timed out"_ctv);
            probeFailure.assign("timed out"_ctv);
            return false;
         },
         results,
         failure
      ) == false,
      "probe_address_from_cluster_brains_failure"
   );
   suite.expect(results.size() == 2, "probe_address_from_cluster_brains_result_count");
   suite.expect(results[0].brainLabel.equals("10.0.0.1"_ctv), "probe_address_from_cluster_brains_first_label");
   suite.expect(results[0].reachable, "probe_address_from_cluster_brains_first_green");
   suite.expect(results[0].latencyMs == 2, "probe_address_from_cluster_brains_first_latency");
   suite.expect(results[1].brainLabel.equals("10.0.0.2"_ctv), "probe_address_from_cluster_brains_second_label");
   suite.expect(results[1].reachable == false, "probe_address_from_cluster_brains_second_red");
   suite.expect(results[1].failure.equals("timed out"_ctv), "probe_address_from_cluster_brains_second_failure");
   suite.expect(failure.equals("candidate brain address is not reachable from all existing brains"_ctv), "probe_address_from_cluster_brains_failure_text");

   if (suite.failed != 0)
   {
      basics_log("prodigy_brain_reachability_unit failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("prodigy_brain_reachability_unit ok\n");
   return EXIT_SUCCESS;
}
