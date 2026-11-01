#include <prodigy/iaas/runtime/runtime.h>
#include <networking/bgp.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>
#include <vector>
#ifdef __linux__
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

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

static void observeBGPIPv6Import(void *context, const BGPIPv6UnicastImport& imported)
{
  static_cast<std::vector<BGPIPv6UnicastImport> *>(context)->push_back(imported);
}

static void appendBGP16(std::vector<uint8_t>& bytes, uint16_t value)
{
  bytes.push_back(uint8_t(value >> 8)); bytes.push_back(uint8_t(value));
}

static std::vector<uint8_t> makeBGPIPv6MPAttribute(uint8_t type, const std::vector<std::pair<uint8_t, std::vector<uint8_t>>>& nlri)
{
  std::vector<uint8_t> value = {0, 2, 1};
  if (type == 14)
  {
    value.push_back(16);
    const uint8_t nextHop[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    value.insert(value.end(), nextHop, nextHop + sizeof(nextHop));
    value.push_back(0);
  }
  for (const auto& entry : nlri) { value.push_back(entry.first); value.insert(value.end(), entry.second.begin(), entry.second.end()); }
  std::vector<uint8_t> update = {0, 0};
  appendBGP16(update, uint16_t(value.size() + 3));
  update.push_back(0x80); update.push_back(type); update.push_back(uint8_t(value.size()));
  update.insert(update.end(), value.begin(), value.end());
  return update;
}

static void testBGPCoalescedUpdates(TestSuite& suite)
{
  const auto body = makeBGPIPv6MPAttribute(14, {{96, {0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0}}});
  std::vector<uint8_t> frame(16, 0xff);
  appendBGP16(frame, uint16_t(19 + body.size()));
  frame.push_back(2);
  frame.insert(frame.end(), body.begin(), body.end());
  std::vector<uint8_t> combined = frame;
  combined.insert(combined.end(), frame.begin(), frame.end());
  combined.insert(combined.end(), frame.begin(), frame.begin() + 17);
  BGPPeer peer;
  std::vector<BGPIPv6UnicastImport> observed;
  peer.setIPv6UnicastImportObserver(observeBGPIPv6Import, &observed);
  peer.rBuffer.append(combined.data(), uint32_t(combined.size()));
  const bool first = peer.handleMessage();
  suite.expect(first && observed.size() == 2 && peer.rBuffer.outstandingBytes() == 17,
               "bgp_coalesced_updates_drain_complete_preserve_partial");
  peer.rBuffer.append(frame.data() + 17, uint32_t(frame.size() - 17));
  suite.expect(peer.handleMessage() && observed.size() == 3 && peer.rBuffer.outstandingBytes() == 0,
               "bgp_partial_update_resumes_after_remaining_bytes");
  // A connection that ends mid-frame must not prefix the next session's data.
  peer.rBuffer.append(frame.data(), 17);
  peer.wBuffer.append(frame.data(), 17);
  peer.clearSessionBuffers();
  peer.rBuffer.append(frame.data(), uint32_t(frame.size()));
  suite.expect(peer.wBuffer.outstandingBytes() == 0 && peer.handleMessage() &&
                   observed.size() == 4 && peer.rBuffer.outstandingBytes() == 0,
               "bgp_reconnect_discards_previous_session_bytes");
}

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

static void testGlobalIPv6DiscoveryUsesInterfaceAddress(TestSuite& suite)
{
  struct sockaddr_in6 linkLocal = {};
  linkLocal.sin6_family = AF_INET6;
  (void)inet_pton(AF_INET6, "fe80::1", &linkLocal.sin6_addr);
  struct sockaddr_in6 global = {};
  global.sin6_family = AF_INET6;
  (void)inet_pton(AF_INET6, "2001:19f0:5c00:456a:5400:6ff:fedd:d6c9", &global.sin6_addr);

  struct ifaddrs globalInterface = {};
  globalInterface.ifa_name = const_cast<char *>("enp1s0");
  globalInterface.ifa_addr = reinterpret_cast<struct sockaddr *>(&global);
  struct ifaddrs linkLocalInterface = {};
  linkLocalInterface.ifa_name = const_cast<char *>("enp1s0");
  linkLocalInterface.ifa_addr = reinterpret_cast<struct sockaddr *>(&linkLocal);
  linkLocalInterface.ifa_next = &globalInterface;

  IPAddress resolved = {};
  suite.expect(prodigyFindGlobalIPv6Address(&linkLocalInterface, "enp1s0"_ctv, resolved) &&
                   resolved.equals(IPAddress("2001:19f0:5c00:456a:5400:6ff:fedd:d6c9", true)),
               "global_ipv6_discovery_reads_ipv6_interface_address");
}

static void testBGPPeerReconnectBackoffIsBounded(TestSuite& suite)
{
  suite.expect(BGPHub::reconnectDelayMs(0) == 1000, "bgp_reconnect_initial_delay");
  suite.expect(BGPHub::reconnectDelayMs(1) == 1000, "bgp_reconnect_first_failure_delay");
  suite.expect(BGPHub::reconnectDelayMs(2) == 2000, "bgp_reconnect_second_failure_backoff");
  suite.expect(BGPHub::reconnectDelayMs(7) == 64'000, "bgp_reconnect_backoff_cap");
  suite.expect(BGPHub::reconnectDelayMs(UINT32_MAX) == 64'000, "bgp_reconnect_large_failure_cap");
}

#ifdef __linux__
// Opt-in only: this drives actual private BGP sockets and Ring in a fresh
// disposable guest network namespace. It never configures host networking.
class PrivateSessionHub final : public BGPHub {
public:
  void hasShutdownBGP(void) override {}
};

class PrivateSessionProbe final : public TimeoutDispatcher {
public:
  struct Side { bool up = false, down = false, imported = false, expectedLeft = false, wrongPeer = false; IPAddress expectedPeer = {}; } left, right;
  PrivateSessionHub listener, connector;
  RingDispatcher dispatcher;
  TimeoutPacket tick = {}, deadline = {};
  IPAddress listenerAddress = IPAddress("2001:db8:ffff::1", true);
  IPAddress connectorAddress = IPAddress("2001:db8:ffff::2", true);
  IPPrefix listenerPrefix = IPPrefix("2001:db8:100::", true, 96);
  IPPrefix connectorPrefix = IPPrefix("2001:db8:200::", true, 96);
  int netns = -1;
  int stage = 0;
  bool passed = false, failed = false;

  static void state(void *context, const IPAddress& peer, bool established)
  {
    auto& side = *static_cast<Side *>(context);
    if (!peer.equals(side.expectedPeer)) { side.wrongPeer = true; return; }
    side.up = established;
    if (!established) side.down = true;
  }
  static void imported(void *context, const BGPIPv6UnicastImport& route)
  {
    auto& side = *static_cast<Side *>(context);
    std::array<uint8_t, 16> expected = {};
    const char *prefix = sideIsLeft(side) ? "2001:db8:200::" : "2001:db8:100::";
    if (::inet_pton(AF_INET6, prefix, expected.data()) == 1 && route.cidr == 96 &&
        !route.withdrawn && route.prefix == expected) side.imported = true;
  }
  // Each callback context is tagged explicitly rather than inferring the peer.
  static bool sideIsLeft(const Side& side) { return side.expectedLeft; }

  bool listen()
  {
    String password; password.assign("private-session-test"_ctv);
    const bool ready = listener.listenPrivatePeer(64513, connectorAddress, listenerAddress, password,
        imported, &left, state, &left, netns, "lo"_ctv);
    std::fprintf(stderr, "private BGP listener ready=%d stage=%d\n", int(ready), stage);
    return ready;
  }
  void announce()
  {
    listener.announceLocalPrefix(listenerPrefix, listenerAddress);
    connector.announceLocalPrefix(connectorPrefix, connectorAddress);
  }
  void armTick()
  {
    tick.clear(); tick.setTimeoutMs(50); Ring::queueTimeout(&tick);
  }
  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet == &deadline) { std::fprintf(stderr, "private BGP deadline stage=%d left_up=%d right_up=%d left_down=%d right_down=%d left_import=%d right_import=%d\n", stage, int(left.up), int(right.up), int(left.down), int(right.down), int(left.imported), int(right.imported)); failed = true; Ring::exit = true; return; }
    if (packet != &tick) return;
    if (stage == 0 && left.up && right.up && left.imported && right.imported) {
      std::fprintf(stderr, "private BGP initial cached bilateral /96 import; withdrawing listener\n");
      left.down = right.down = false;
      listener.withdrawPeer(connectorAddress);
      stage = 2;
    } else if (stage == 2 && left.down && right.down) {
      left.imported = right.imported = false;
      if (listen()) {
        listener.announceLocalPrefix(listenerPrefix, listenerAddress);
        std::fprintf(stderr, "private BGP listener reinstalled; awaiting automatic reconnect\n"); stage = 3;
      }
    } else if (stage == 3 && left.up && right.up && left.imported && right.imported) {
      std::fprintf(stderr, "private BGP cached bilateral /96 import after reconnect\n");
      // Separately count imports following an explicit re-announcement.
      left.imported = right.imported = false;
      announce(); stage = 4;
    }
    else if (stage == 4 && left.up && right.up && left.imported && right.imported) {
      passed = true; Ring::exit = true; return;
    }
    armTick();
  }
  int run()
  {
    struct stat here = {}, init = {};
    FILE *marker = std::fopen("/run/prodigy-disposable-linux", "r");
    char markerText[64] = {};
    const bool marked = marker && std::fgets(markerText, sizeof(markerText), marker) &&
        std::strncmp(markerText, "prodigy-disposable-linux-v1", 27) == 0;
    if (marker) std::fclose(marker);
    char machineID[64] = {}, virtualization[64] = {};
    FILE *machine = std::fopen("/etc/machine-id", "r");
    const bool controller = machine && std::fgets(machineID, sizeof(machineID), machine) &&
        std::strncmp(machineID, "0ef2a43f92fd48b8a04e3dd8e4eaf80d", 32) == 0;
    if (machine) std::fclose(machine);
    FILE *virt = ::popen("/usr/bin/systemd-detect-virt", "r");
    const bool kvm = virt && std::fgets(virtualization, sizeof(virtualization), virt) &&
        std::strcmp(virtualization, "kvm\n") == 0;
    const int virtStatus = virt ? ::pclose(virt) : -1;
    const char *optIn = std::getenv("PRODIGY_PRIVATE_BGP_TEST");
    if (!marked || !controller || !kvm || virtStatus != 0 || !optIn || std::strcmp(optIn, "1") != 0 || ::stat("/proc/self/ns/net", &here) != 0 || ::stat("/proc/1/ns/net", &init) != 0 ||
        (here.st_dev == init.st_dev && here.st_ino == init.st_ino)) {
      std::fprintf(stderr, "private BGP test requires marked disposable guest and separate netns\n"); return 77;
    }
    netns = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (netns < 0) return 1;
    left.expectedLeft = true;
    left.expectedPeer = connectorAddress; right.expectedPeer = listenerAddress;
    listener.ourASN = 64512; listener.ourBGPID = 1;
    connector.ourASN = 64513; connector.ourBGPID = 2;
    Ring::interfacer = &dispatcher; Ring::lifecycler = &dispatcher;
    Ring::exit = false; Ring::shuttingDown = false;
    // Three locally created sockets plus accepted/reconnect slots need separate pools.
    Ring::createRing(64, 128, 128, 32, -1, -1, 8);
    tick.dispatcher = this; deadline.dispatcher = this;
    // Exercise malformed framing with a real fixed-file close on this isolated Ring.
    BGPPeer *invalidPeer = new BGPPeer();
    invalidPeer->setIPVersion(AF_INET6);
    if (invalidPeer->fd < 0) { delete invalidPeer; Ring::shutdownForExec(); ::close(netns); return 1; }
    RingDispatcher::installMultiplexee(invalidPeer, &listener);
    Ring::installFDIntoFixedFileSlot(invalidPeer);
    std::array<uint8_t, 18> invalidFrame = {};
    invalidFrame.fill(0xff); invalidFrame[16] = 0; invalidFrame[17] = 18;
    invalidPeer->rBuffer.append(invalidFrame.data(), uint32_t(invalidFrame.size()));
    const bool rejected = !invalidPeer->handleMessage() && invalidPeer->state == BGPState::failed;
    std::fprintf(stderr, "private BGP sub-header frame rejected=%d\n", int(rejected));
    String password; password.assign("private-session-test"_ctv);
    const bool ready = rejected && listen() && connector.addPeer(64512, listenerAddress, connectorAddress,
        password, 2, imported, &right, state, &right, netns, &loopback);
    std::fprintf(stderr, "private BGP peer setup ready=%d\n", int(ready));
    if (ready) {
      announce();
      deadline.setTimeoutMs(25000); Ring::queueTimeout(&deadline);
      armTick(); Ring::start();
    }
    Ring::shutdownForExec();
    Ring::interfacer = nullptr; Ring::lifecycler = nullptr;
    Ring::exit = false; Ring::shuttingDown = false; RingDispatcher::dispatcher = nullptr;
    ::close(netns);
    std::fprintf(stderr, "%s: real private BGP session, bilateral /96 import and reconnect\n",
                 ready && passed && !failed && !left.wrongPeer && !right.wrongPeer ? "PASS" : "FAIL");
    return ready && passed && !failed && !left.wrongPeer && !right.wrongPeer ? 0 : 1;
  }
private:
  String loopback = "lo"_ctv;
};
#endif

int main(int argc, char **argv)
{
#ifdef __linux__
  if (argc == 2 && std::strcmp(argv[1], "--private-session-only") == 0)
    return PrivateSessionProbe().run();
#endif
  if (argc != 1) return 2;
  TestSuite suite = {};
  testBGPCoalescedUpdates(suite);

  const std::vector<std::pair<uint8_t, std::vector<uint8_t>>> exact96 = {
      {96, {0x26, 0x02, 0xfa, 0xc0, 0, 0, 0, 0, 0, 0x12, 0xab, 0x34}}};
  std::vector<uint8_t> announce96 = makeBGPIPv6MPAttribute(14, exact96);
  std::vector<BGPIPv6UnicastImport> imports = {};
  suite.expect(bgpObserveIPv6UnicastUpdate(announce96.data(), announce96.size(), observeBGPIPv6Import, &imports) &&
                   imports.size() == 1 && !imports[0].withdrawn && imports[0].cidr == 96 &&
                   imports[0].prefix[0] == 0x26 && imports[0].nextHop[15] == 1,
               "bgp_import_observes_exact_ipv6_96_announcement");

  const std::vector<std::pair<uint8_t, std::vector<uint8_t>>> multiple = {
      {96, {0x26, 0x02, 0xfa, 0xc0, 0, 0, 0, 0, 0, 0x12, 0xab, 0x34}},
      {64, {0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2}}};
  std::vector<uint8_t> multipleUpdate = makeBGPIPv6MPAttribute(14, multiple);
  imports.clear();
  suite.expect(bgpObserveIPv6UnicastUpdate(multipleUpdate.data(), multipleUpdate.size(), observeBGPIPv6Import, &imports) && imports.size() == 2,
               "bgp_import_observes_multiple_ipv6_nlri");

  std::vector<uint8_t> withdraw96 = makeBGPIPv6MPAttribute(15, exact96);
  imports.clear();
  suite.expect(bgpObserveIPv6UnicastUpdate(withdraw96.data(), withdraw96.size(), observeBGPIPv6Import, &imports) &&
                   imports.size() == 1 && imports[0].withdrawn && imports[0].nextHop == std::array<uint8_t, 16> {},
               "bgp_import_observes_ipv6_96_withdrawal");

  std::vector<uint8_t> truncated = announce96;
  truncated.pop_back();
  imports.clear();
  suite.expect(!bgpObserveIPv6UnicastUpdate(truncated.data(), truncated.size(), observeBGPIPv6Import, &imports) && imports.empty(),
               "bgp_import_rejects_truncated_attribute_without_partial_observation");
  std::vector<uint8_t> noncanonical = makeBGPIPv6MPAttribute(14, {{65, {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x7f}}});
  imports.clear();
  suite.expect(!bgpObserveIPv6UnicastUpdate(noncanonical.data(), noncanonical.size(), observeBGPIPv6Import, &imports) && imports.empty(),
               "bgp_import_rejects_noncanonical_ipv6_nlri");

  std::vector<uint8_t> unspecifiedNextHop = announce96;
  for (size_t index = 11; index < 27; ++index) unspecifiedNextHop[index] = 0;
  imports.clear();
  suite.expect(!bgpObserveIPv6UnicastUpdate(unspecifiedNextHop.data(), unspecifiedNextHop.size(), observeBGPIPv6Import, &imports) && imports.empty(),
               "bgp_import_rejects_unspecified_ipv6_next_hop");

  std::vector<uint8_t> malformedLegacyTail = announce96;
  malformedLegacyTail.push_back(33);
  imports.clear();
  suite.expect(!bgpObserveIPv6UnicastUpdate(malformedLegacyTail.data(), malformedLegacyTail.size(), observeBGPIPv6Import, &imports) && imports.empty(),
               "bgp_import_rejects_legacy_tail_without_partial_observation");

  testRuntimeAwareInventoryUsesConfiguredProviderInsteadOfSharedNatBootstrapSnapshots(suite);
  testGlobalIPv6DiscoveryUsesInterfaceAddress(suite);
  testBGPPeerReconnectBackoffIsBounded(suite);

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
  IPAddress vultrPublic4("149.28.50.10", false);
  IPAddress vultrPublic6("2001:19f0:5c00:456a:5400:6ff:fedd:d6c9", true);
  suite.expect(vultrBuildCloudComputeBGPConfig(
                   35'870, "test-md5"_ctv, vultrPublic4.v4, vultrPublic6, vultrCloud) ==
                   NeuronBGPConfigurationRetry::none &&
                   vultrCloud.enabled,
               "vultr_cloud_bgp_config_accepts_customer_asn_and_global_ipv6");
  suite.expect(vultrCloud.enabled && vultrCloud.community == 0 &&
                   vultrCloud.nextHop4.equals(vultrPublic4) &&
                   vultrCloud.nextHop6.equals(vultrPublic6),
               "vultr_cloud_bgp_config_uses_verified_dual_stack_next_hops");
  suite.expect(vultrCloud.peers.size() == 2,
               "vultr_cloud_bgp_config_has_one_peer_per_address_family");
  suite.expect(vultrCloud.peers[0].peerASN == 64'515 &&
                   vultrCloud.peers[0].peerAddress.equals(IPAddress("169.254.169.254", false)) &&
                   vultrCloud.peers[0].sourceAddress.equals(vultrPublic4) &&
                   vultrCloud.peers[0].hopLimit == 2 &&
                   vultrCloud.peers[0].md5Password == "test-md5"_ctv,
               "vultr_cloud_bgp_config_uses_documented_ipv4_peer");
  suite.expect(vultrCloud.peers[1].peerASN == 64'515 &&
                   vultrCloud.peers[1].peerAddress.equals(IPAddress("2001:19f0:ffff::1", true)) &&
                   vultrCloud.peers[1].sourceAddress.equals(vultrPublic6) &&
                   vultrCloud.peers[1].hopLimit == 2 &&
                   vultrCloud.peers[1].md5Password == "test-md5"_ctv,
               "vultr_cloud_bgp_config_retains_documented_ipv6_peer");

  NeuronBGPConfig rejectedVultr = {};
  suite.expect(vultrBuildCloudComputeBGPConfig(
                   64'512, "test-md5"_ctv, private4.v4, vultrPublic6, rejectedVultr) ==
                   NeuronBGPConfigurationRetry::none &&
                   rejectedVultr.configured() == false,
               "vultr_cloud_bgp_config_rejects_unsupported_customer_asn");
  suite.expect(vultrBuildCloudComputeBGPConfig(
                   35'870, String {}, private4.v4, IPAddress {}, rejectedVultr) ==
                   NeuronBGPConfigurationRetry::none &&
                   rejectedVultr.configured() == false,
               "vultr_cloud_bgp_config_does_not_retry_permanent_account_input_failure");
  suite.expect(vultrBuildCloudComputeBGPConfig(
                   35'870, "test-md5"_ctv, 0, vultrPublic6, rejectedVultr) ==
                   NeuronBGPConfigurationRetry::none &&
                   rejectedVultr.configured() == false,
               "vultr_cloud_bgp_config_rejects_missing_public_ipv4_source");
  suite.expect(vultrBuildCloudComputeBGPConfig(
                   35'870, "test-md5"_ctv, private4.v4, vultrPublic6, rejectedVultr) ==
                   NeuronBGPConfigurationRetry::none &&
                   rejectedVultr.configured() == false,
               "vultr_cloud_bgp_config_rejects_private_ipv4_source");
  suite.expect(vultrBuildCloudComputeBGPConfig(
                   35'870, "test-md5"_ctv, vultrPublic4.v4, IPAddress {}, rejectedVultr) ==
                   NeuronBGPConfigurationRetry::waitForPublicIPv6 &&
                   rejectedVultr.configured() == false,
               "vultr_cloud_bgp_config_reports_public_ipv6_pending");
  IPAddress vultrULA("fdf8:d94c:1::1", true);
  suite.expect(vultrBuildCloudComputeBGPConfig(
                   35'870, "test-md5"_ctv, vultrPublic4.v4, vultrULA, rejectedVultr) ==
                   NeuronBGPConfigurationRetry::waitForPublicIPv6 &&
                   rejectedVultr.configured() == false,
               "vultr_cloud_bgp_config_rejects_ula_and_preserves_public_ipv6_retry");

  suite.expect(prodigyBGPIPv6ReadinessRetryEligible(
                   true, rejectedVultr,
                   NeuronBGPConfigurationRetry::waitForPublicIPv6, 0),
               "bgp_ipv6_readiness_retry_arms_for_provider_reported_address_pending");
  suite.expect(prodigyBGPIPv6ReadinessRetryDelayMs(0) == 1'000 &&
                   prodigyBGPIPv6ReadinessRetryDelayMs(1) == 2'000 &&
                   prodigyBGPIPv6ReadinessRetryDelayMs(2) == 4'000 &&
                   prodigyBGPIPv6ReadinessRetryDelayMs(3) == 8'000 &&
                   prodigyBGPIPv6ReadinessRetryDelayMs(4) == 16'000 &&
                   prodigyBGPIPv6ReadinessRetryDelayMs(5) == 32'000 &&
                   prodigyBGPIPv6ReadinessRetryDelayMs(6) == 60'000 &&
                   prodigyBGPIPv6ReadinessRetryDelayMs(
                       prodigyBGPIPv6ReadinessRetryMaximumAttempts - 1) == 60'000,
               "bgp_ipv6_readiness_retry_backoff_caps_at_one_minute");
  uint32_t bgpIPv6ReadinessRetryTotalDelayMs = 0;
  for (uint32_t attempt = 0;
       attempt < prodigyBGPIPv6ReadinessRetryMaximumAttempts; attempt += 1)
  {
    bgpIPv6ReadinessRetryTotalDelayMs += prodigyBGPIPv6ReadinessRetryDelayMs(attempt);
  }
  suite.expect(bgpIPv6ReadinessRetryTotalDelayMs == 603'000,
               "bgp_ipv6_readiness_retry_covers_ten_minute_provider_window");
  suite.expect(prodigyBGPIPv6ReadinessRetryEligible(
                   true, rejectedVultr,
                   NeuronBGPConfigurationRetry::waitForPublicIPv6,
                   prodigyBGPIPv6ReadinessRetryMaximumAttempts) == false &&
                   prodigyBGPIPv6ReadinessRetryEligible(
                       false, rejectedVultr,
                       NeuronBGPConfigurationRetry::waitForPublicIPv6, 0) == false &&
                   prodigyBGPIPv6ReadinessRetryEligible(
                       true, vultrCloud,
                       NeuronBGPConfigurationRetry::none, 0) == false,
               "bgp_ipv6_readiness_retry_rejects_exhausted_unready_and_enabled_configs");

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
