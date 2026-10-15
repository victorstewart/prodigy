#include <prodigy/iaas/runtime/runtime.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>

class TestNeuron final : public NeuronBase {
public:

  void pushContainer(Container *container) override { (void)container; }
  void popContainer(Container *container) override { (void)container; }
  bool ensureHostNetworkingReady(String *failureReport = nullptr) override
  {
    if (failureReport != nullptr)
    {
      failureReport->clear();
    }
    return true;
  }
  void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) override
  {
    (void)coro;
    (void)deploymentID;
  }
};

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

class FakeVultrBGPHttp {
public:

  MultiCurlClient::Request request;
  MultiCurlClient::Callback callback;
  MultiCurlClient::Ticket ticket {73, 11};

  static MultiCurlClient::Ticket submit(void *context,
                                        MultiCurlClient::Request&& request,
                                        MultiCurlClient::Callback callback)
  {
    FakeVultrBGPHttp& http = *static_cast<FakeVultrBGPHttp *>(context);
    http.request = std::move(request);
    http.callback = callback;
    return http.ticket;
  }

  static bool cancel(void *, MultiCurlClient::Ticket)
  {
    return true;
  }

  ProdigyHostHttpSubmission submission(void)
  {
    return {this, submit, cancel};
  }

  void complete(const String& body, uint16_t statusCode = 200)
  {
    MultiCurlClient::Result result = {};
    result.status = MultiCurlClient::Status::success;
    result.statusCode = statusCode;
    result.body.assign(body);
    callback.function(callback.context, ticket, std::move(result));
  }
};

class VultrBGPRefreshProbe {
public:

  CoroutineStack stack;
  VultrNeuronIaaS& iaas;
  bool ready = false;
  bool complete = false;

  explicit VultrBGPRefreshProbe(VultrNeuronIaaS& requestedIaaS)
      : iaas(requestedIaaS)
  {}

  void refresh(void)
  {
    ready = co_await iaas.refreshBGPConfiguration(&stack);
    complete = true;
  }
};

static const String *findHeader(const MultiCurlClient::Request& request, const String& name)
{
  for (const MultiCurlClient::Header& candidate : request.headers)
  {
    if (candidate.name == name)
    {
      return &candidate.value;
    }
  }
  return nullptr;
}

static void testRuntimeAwareInventoryUsesConfiguredProviderInsteadOfSharedNatBootstrapSnapshots(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.uuid = 0x2301;
  neuron.private4 = IPAddress("10.0.2.15", false);
  neuron.metro.assign("test-metro"_ctv);

  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &neuron;

  ProdigyPersistentBootState boot = {};
  boot.bootstrapConfig.nodeRole = ProdigyBootstrapNodeRole::brain;
  boot.runtimeEnvironment.kind = ProdigyEnvironmentKind::dev;
  for (const char *peer6 : {"2001:db8:230::10", "2001:db8:230::11", "2001:db8:230::12"})
  {
    ProdigyBootstrapConfig::BootstrapPeer peer = {};
    peer.isBrain = true;
    peer.addresses.push_back(ClusterMachinePeerAddress {"10.0.2.15"_ctv, 24});
    peer.addresses.push_back(ClusterMachinePeerAddress {String(peer6), 64});
    boot.bootstrapConfig.bootstrapPeers.push_back(std::move(peer));
  }

  RuntimeAwareBrainIaaS iaas(nullptr, boot.bootstrapConfig, boot, {});
  CoroutineStack coro;
  bytell_hash_set<Machine *> inventory;
  String failure = {};
  iaas.getMachines(&coro, neuron.metro, inventory, failure);
  coro.co_consume();

  suite.expect(failure.empty(), "runtime_aware_inventory_shared_nat_provider_succeeds");
  suite.expect(inventory.empty(), "runtime_aware_inventory_shared_nat_does_not_emit_bootstrap_seed_duplicates");
  for (Machine *machine : inventory)
  {
    prodigyDestroyMachineSnapshot(machine);
  }
  thisNeuron = previousNeuron;
}

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

  testRuntimeAwareInventoryUsesConfiguredProviderInsteadOfSharedNatBootstrapSnapshots(suite);

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

  NeuronBGPConfig vultrCloud = {};
  IPAddress vultrPublic6("2001:19f0:5c00:456a:5400:6ff:fedd:d6c9", true);
  suite.expect(vultrBuildCloudComputeIPv6BGPConfig(
                   35'870, "test-md5"_ctv, private4.v4, vultrPublic6, vultrCloud),
               "vultr_cloud_bgp_config_accepts_customer_asn_and_global_ipv6");
  suite.expect(vultrCloud.enabled && vultrCloud.community == 0 && vultrCloud.nextHop4.isNull(),
               "vultr_cloud_bgp_config_does_not_suppress_public_propagation_or_advertise_ipv4");
  suite.expect(vultrCloud.nextHop6.equals(vultrPublic6) && vultrCloud.peers.size() == 1,
               "vultr_cloud_bgp_config_uses_public_ipv6_next_hop");
  suite.expect(vultrCloud.peers[0].peerASN == 64'515 &&
                   vultrCloud.peers[0].peerAddress.equals(IPAddress("2001:19f0:ffff::1", true)) &&
                   vultrCloud.peers[0].sourceAddress.equals(vultrPublic6) &&
                   vultrCloud.peers[0].hopLimit == 2 &&
                   vultrCloud.peers[0].md5Password == "test-md5"_ctv,
               "vultr_cloud_bgp_config_uses_documented_vps_peer");

  NeuronBGPConfig rejectedVultr = {};
  suite.expect(vultrBuildCloudComputeIPv6BGPConfig(
                   64'512, "test-md5"_ctv, private4.v4, vultrPublic6, rejectedVultr) == false &&
                   rejectedVultr.configured() == false,
               "vultr_cloud_bgp_config_rejects_unsupported_customer_asn");
  suite.expect(vultrBuildCloudComputeIPv6BGPConfig(
                   35'870, "test-md5"_ctv, private4.v4, IPAddress {}, rejectedVultr) == false &&
                   rejectedVultr.configured() == false,
               "vultr_cloud_bgp_config_requires_global_ipv6_source");

  {
    FakeVultrBGPHttp http = {};
    VultrNeuronIaaS vultr = {};
    ProdigyProviderServices services = {};
    services.http = http.submission();
    vultr.configureProviderServices(services);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::vultr;
    runtime.providerCredentialMaterial = "test-token"_ctv;
    vultr.configureRuntimeEnvironment(runtime);

    VultrBGPRefreshProbe probe(vultr);
    probe.refresh();
    const String *authorization = findHeader(http.request, "Authorization"_ctv);
    suite.expect(probe.complete == false &&
                     http.request.method == MultiCurlClient::Method::get &&
                     http.request.url == "https://api.vultr.com/v2/account/bgp"_ctv,
                 "vultr_bgp_refresh_suspends_on_exact_account_request");
    suite.expect(authorization != nullptr && *authorization == "Bearer test-token"_ctv &&
                     http.request.originPolicy.requiredHost == "api.vultr.com"_ctv,
                 "vultr_bgp_refresh_owns_scoped_authorization");
    http.complete(R"json({"enabled":true,"asn":35870,"password":"test-md5"})json"_ctv);
    suite.expect(probe.complete && probe.ready,
                 "vultr_bgp_refresh_accepts_enabled_customer_account");
  }

  {
    FakeVultrBGPHttp http = {};
    VultrNeuronIaaS vultr = {};
    ProdigyProviderServices services = {};
    services.http = http.submission();
    vultr.configureProviderServices(services);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::vultr;
    runtime.providerCredentialMaterial = "test-token"_ctv;
    vultr.configureRuntimeEnvironment(runtime);

    VultrBGPRefreshProbe probe(vultr);
    probe.refresh();
    http.complete(R"json({"enabled":true,"asn":35870})json"_ctv);
    suite.expect(probe.complete && probe.ready == false,
                 "vultr_bgp_refresh_rejects_missing_password");
  }

#ifdef __linux__
  {
    BGPPeer peer = {};
    peer.is6 = true;
    peer.setIPVersion(AF_INET6);
    peer.setHopLimit(2);
    int hopLimit = 0;
    socklen_t hopLimitSize = sizeof(hopLimit);
    suite.expect(getsockopt(peer.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                            &hopLimit, &hopLimitSize) == 0 && hopLimit == 2,
                 "bgp_first_socket_applies_provider_hop_limit");
  }
#endif

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
