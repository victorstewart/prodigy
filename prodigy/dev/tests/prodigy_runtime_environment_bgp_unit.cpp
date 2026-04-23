#include <prodigy/iaas/runtime/runtime.h>
#include <services/debug.h>

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

static NeuronBGPPeerConfig makeBGPPeer(const String& peerAddress, const String& sourceAddress, uint16_t peerASN, const String& md5Password, uint8_t hopLimit)
{
   NeuronBGPPeerConfig peer = {};
   peer.peerASN = peerASN;
   (void)prodigyParseIPAddressText(peerAddress, peer.peerAddress);
   (void)prodigyParseIPAddressText(sourceAddress, peer.sourceAddress);
   peer.md5Password = md5Password;
   peer.hopLimit = hopLimit;
   return peer;
}

int main(void)
{
   TestSuite suite = {};

   ProdigyBootstrapConfig bootstrap = {};
   RuntimeAwareNeuronIaaS neuron(nullptr, bootstrap, ProdigyPersistentBootState{});
   EthDevice eth = {};

   ProdigyRuntimeEnvironmentConfig overridden = {};
   overridden.bgp.specified = true;
   overridden.bgp.config.enabled = true;
   overridden.bgp.config.nextHop4 = IPAddress("10.0.0.1", false);
   overridden.bgp.config.nextHop6 = IPAddress("2001:db8::1", true);
   overridden.bgp.config.peers.push_back(makeBGPPeer("169.254.1.1"_ctv, "10.0.0.21"_ctv, 64512, "peer-md5-v4"_ctv, 2));
   overridden.bgp.config.peers.push_back(makeBGPPeer("2001:19f0:ffff::1"_ctv, "2001:db8::21"_ctv, 64512, "peer-md5-v6"_ctv, 3));
   neuron.configureRuntimeEnvironment(overridden);

   IPAddress private4 = {};
   (void)prodigyParseIPAddressText("10.0.0.21"_ctv, private4);

   NeuronBGPConfig resolved = {};
   neuron.gatherBGPConfig(resolved, eth, private4);
   suite.expect(resolved.enabled, "runtime_env_bgp_override_enabled");
   suite.expect(resolved.ourBGPID == private4.v4, "runtime_env_bgp_override_derives_bgp_id_from_private4");
   suite.expect(resolved.nextHop4.equals(IPAddress("10.0.0.1", false)), "runtime_env_bgp_override_nextHop4");
   suite.expect(resolved.nextHop6.equals(IPAddress("2001:db8::1", true)), "runtime_env_bgp_override_nextHop6");
   suite.expect(resolved.peers.size() == 2, "runtime_env_bgp_override_peer_count");
   suite.expect(resolved.peers[0].hopLimit == 2, "runtime_env_bgp_override_peer_v4_hop_limit");
   suite.expect(resolved.peers[1].peerAddress.equals(IPAddress("2001:19f0:ffff::1", true)), "runtime_env_bgp_override_peer_v6_address");

   ProdigyRuntimeEnvironmentConfig explicitDisabled = {};
   explicitDisabled.bgp.specified = true;
   neuron.configureRuntimeEnvironment(explicitDisabled);
   resolved = {};
   neuron.gatherBGPConfig(resolved, eth, private4);
   suite.expect(resolved.enabled == false, "runtime_env_bgp_override_disabled");
   suite.expect(resolved.peers.empty(), "runtime_env_bgp_override_disabled_no_peers");

   ProdigyRuntimeEnvironmentConfig fallback = {};
   neuron.configureRuntimeEnvironment(fallback);
   resolved = {};
   neuron.gatherBGPConfig(resolved, eth, private4);
   suite.expect(resolved.configured() == false, "runtime_env_bgp_falls_back_to_empty_without_override");

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
