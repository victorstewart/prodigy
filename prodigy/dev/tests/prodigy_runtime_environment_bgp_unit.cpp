#include <prodigy/iaas/runtime/runtime.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>

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

  prodigySetPrimaryNetworkDeviceOverride("lo");
  DevNeuronIaaS devNeuron;
  uint128_t uuid = 1;
  String metro;
  bool isBrain = false;
  EthDevice eth;
  IPAddress devPrivate4 = {};
  devNeuron.gatherSelfData(nullptr, uuid, metro, isBrain, eth, devPrivate4);
  suite.expect(eth.name == "lo"_ctv, "dev_neuron_uses_selected_network_device");
  suite.expect(eth.ifidx == if_nametoindex("lo"), "dev_neuron_resolves_selected_network_device_index");
  suite.expect(metro == "dev"_ctv, "dev_neuron_sets_metro");
  suite.expect(uuid == 0, "dev_neuron_defers_uuid_to_runtime_persistence");
  suite.expect(isBrain, "dev_neuron_preserves_dev_brain_default");
  prodigySetPrimaryNetworkDeviceOverride("");

  ProdigyRuntimeEnvironmentConfig overridden = {};
  overridden.bgp.specified = true;
  overridden.bgp.config.enabled = true;
  overridden.bgp.config.nextHop4 = IPAddress("10.0.0.1", false);
  overridden.bgp.config.nextHop6 = IPAddress("2001:db8::1", true);
  overridden.bgp.config.peers.push_back(makeBGPPeer("169.254.1.1"_ctv, "10.0.0.21"_ctv, 64'512, "peer-md5-v4"_ctv, 2));
  overridden.bgp.config.peers.push_back(makeBGPPeer("2001:19f0:ffff::1"_ctv, "2001:db8::21"_ctv, 64'512, "peer-md5-v6"_ctv, 3));
  IPAddress private4 = {};
  (void)prodigyParseIPAddressText("10.0.0.21"_ctv, private4);

  NeuronBGPConfig resolved = {};
  suite.expect(prodigyResolveRuntimeEnvironmentBGPOverride(overridden, private4, resolved), "runtime_env_bgp_override_applied");
  suite.expect(resolved.enabled, "runtime_env_bgp_override_enabled");
  suite.expect(resolved.ourBGPID == private4.v4, "runtime_env_bgp_override_derives_bgp_id_from_private4");
  suite.expect(resolved.nextHop4.equals(IPAddress("10.0.0.1", false)), "runtime_env_bgp_override_nextHop4");
  suite.expect(resolved.nextHop6.equals(IPAddress("2001:db8::1", true)), "runtime_env_bgp_override_nextHop6");
  suite.expect(resolved.peers.size() == 2, "runtime_env_bgp_override_peer_count");
  suite.expect(resolved.peers[0].hopLimit == 2, "runtime_env_bgp_override_peer_v4_hop_limit");
  suite.expect(resolved.peers[1].peerAddress.equals(IPAddress("2001:19f0:ffff::1", true)), "runtime_env_bgp_override_peer_v6_address");

  ProdigyRuntimeEnvironmentConfig explicitDisabled = {};
  explicitDisabled.bgp.specified = true;
  resolved = {};
  suite.expect(prodigyResolveRuntimeEnvironmentBGPOverride(explicitDisabled, private4, resolved), "runtime_env_bgp_disabled_override_applied");
  suite.expect(resolved.enabled == false, "runtime_env_bgp_override_disabled");
  suite.expect(resolved.peers.empty(), "runtime_env_bgp_override_disabled_no_peers");

  ProdigyRuntimeEnvironmentConfig fallback = {};
  resolved = {};
  suite.expect(prodigyResolveRuntimeEnvironmentBGPOverride(fallback, private4, resolved) == false, "runtime_env_bgp_fallback_not_overridden");
  suite.expect(resolved.configured() == false, "runtime_env_bgp_falls_back_to_empty_without_override");

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
