#include <prodigy/prodigy.h>
#include <services/debug.h>
#include <prodigy/brain/brain.h>

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
         std::fprintf(stderr, "FAIL: %s\n", name);
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
   }
};

static MachineNicHardwareProfile makeNic(const char *name,
   const char *mac,
   const char *addressCIDR)
{
   MachineNicHardwareProfile nic = {};
   nic.name.assign(name);
   nic.mac.assign(mac);

   MachineNicSubnetHardwareProfile subnet = {};
   const char *slash = std::strrchr(addressCIDR, '/');
   if (slash == nullptr)
   {
      std::fprintf(stderr, "unable to parse nic cidr: %s\n", addressCIDR);
      std::abort();
   }

   String addressText = {};
   addressText.assign(addressCIDR, uint64_t(slash - addressCIDR));
   if (ClusterMachine::parseIPAddressLiteral(addressText, subnet.address) == false)
   {
      std::fprintf(stderr, "unable to parse nic address: %s\n", addressCIDR);
      std::abort();
   }

   subnet.subnet.network = subnet.address;
   subnet.subnet.cidr = uint8_t(std::strtoul(slash + 1, nullptr, 10));
   subnet.subnet = subnet.subnet.canonicalized();
   nic.subnets.push_back(subnet);
   return nic;
}

class TestNeuron final : public NeuronBase
{
public:

   MachineHardwareProfile latestHardware = {};
   bool haveLatestHardware = false;
   MachineHardwareProfile deferredHardware = {};
   bool haveDeferredHardware = false;
   bool deferredProgressCalled = false;

   void pushContainer(Container *container) override
   {
      (void)container;
   }

   void popContainer(Container *container) override
   {
      (void)container;
   }

   void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) override
   {
      (void)coro;
      (void)deploymentID;
   }

   const MachineHardwareProfile *latestHardwareProfileIfReady(void) const override
   {
      return haveLatestHardware ? &latestHardware : nullptr;
   }

   void ensureDeferredHardwareInventoryProgress(void) override
   {
      deferredProgressCalled = true;
      if (haveLatestHardware == false && haveDeferredHardware)
      {
         latestHardware = deferredHardware;
         haveLatestHardware = true;
      }
   }

   bool ensureHostNetworkingReady(String *failureReport = nullptr) override
   {
      if (failureReport)
      {
         failureReport->clear();
      }
      return true;
   }
};

class ScopedSocketPair final
{
public:

   int left = -1;
   int right = -1;

   ~ScopedSocketPair()
   {
      if (left >= 0)
      {
         close(left);
      }
      if (right >= 0)
      {
         close(right);
      }
   }

   bool create(TestSuite& suite, const char *name)
   {
      int sockets[2] = {-1, -1};
      bool created = (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets) == 0);
      suite.expect(created, name);
      if (created == false)
      {
         if (sockets[0] >= 0)
         {
            close(sockets[0]);
         }
         if (sockets[1] >= 0)
         {
            close(sockets[1]);
         }
         return false;
      }

      left = sockets[0];
      right = sockets[1];
      return true;
   }

   int adoptLeftIntoFixedFileSlot(void)
   {
      if (left < 0)
      {
         return -1;
      }

      int fslot = Ring::adoptProcessFDIntoFixedFileSlot(left);
      if (fslot >= 0)
      {
         left = -1;
      }

      return fslot;
   }
};

class TestBrain final : public Brain
{
public:

   mutable ClusterTopology storedTopology = {};
   bool haveStoredTopology = false;
   bool persistTopologyShouldFail = false;

   void testSendNeuronSwitchboardRoutableSubnets(void)
   {
      sendNeuronSwitchboardRoutableSubnets();
   }

   void testBuildHostedSwitchboardIngressPrefixes(Machine *machine, Vector<IPPrefix>& prefixes) const
   {
      buildHostedSwitchboardIngressPrefixes(machine, prefixes);
   }

   bool testWhiteholeTargetsNeuronMachine(ContainerView *container, Machine *targetMachine, const Whitehole& whitehole) const
   {
      return whiteholeTargetsNeuronMachine(container, targetMachine, whitehole);
   }

   void testCollectWhiteholesForNeuronMachine(ContainerView *container, Machine *targetMachine, const Vector<Whitehole>& sourceWhiteholes, Vector<Whitehole>& whiteholes) const
   {
      collectWhiteholesForNeuronMachine(container, targetMachine, sourceWhiteholes, whiteholes);
   }

   void testSendNeuronSwitchboardHostedIngressPrefixes(void)
   {
      sendNeuronSwitchboardHostedIngressPrefixes();
   }

   void testSendNeuronRuntimeEnvironmentConfig(void)
   {
      sendNeuronRuntimeEnvironmentConfig();
   }

   bool testBuildSwitchboardOverlayRoutingConfig(Machine *machine, SwitchboardOverlayRoutingConfig& config) const
   {
      return buildSwitchboardOverlayRoutingConfig(machine, config);
   }

   void testSendNeuronSwitchboardOverlayRoutes(void)
   {
      sendNeuronSwitchboardOverlayRoutes();
   }

   uint128_t testUpdateSelfPeerTrackingKey(const BrainView *brain) const
   {
      return updateSelfPeerTrackingKey(brain);
   }

   uint128_t testUpdateSelfLocalPeerTrackingKey(void) const
   {
      return updateSelfLocalPeerTrackingKey();
   }

   BrainView *testFindBrainViewByPrivate4(uint32_t private4) const
   {
      return findBrainViewByPrivate4(private4);
   }

   BrainView *testFindBrainViewByUpdateSelfPeerKey(uint128_t peerKey) const
   {
      return findBrainViewByUpdateSelfPeerKey(peerKey);
   }

   void testAdoptLocalBrainPeerAddress(const IPAddress& address, const String& addressText)
   {
      adoptLocalBrainPeerAddress(address, addressText);
   }

   void testAdoptLocalBrainPeerAddresses(const Vector<ClusterMachinePeerAddress>& candidates)
   {
      adoptLocalBrainPeerAddresses(candidates);
   }

   static int testCompareIPAddresses(const IPAddress& lhs, const IPAddress& rhs)
   {
      return compareIPAddresses(lhs, rhs);
   }

   void testCollectLocalBrainCandidateAddresses(Vector<IPAddress>& localAddresses) const
   {
      collectLocalBrainCandidateAddresses(localAddresses);
   }

   void testRefreshLocalBrainPeerAddresses(void)
   {
      refreshLocalBrainPeerAddresses();
   }

   bool testLocalBrainAddressMatches(const IPAddress& address) const
   {
      return localBrainAddressMatches(address);
   }

   bool testResolveLocalBrainPeerAddressFromIaaS(void)
   {
      return resolveLocalBrainPeerAddressFromIaaS();
   }

   BrainView *testFindBrainViewByPeerAddresses(const Vector<ClusterMachinePeerAddress>& addresses) const
   {
      return findBrainViewByPeerAddresses(addresses);
   }

   static bool testMachineAddressMatchesLiteral(const String& candidate, const IPAddress& address, const String *addressText = nullptr)
   {
      return machineAddressMatchesLiteral(candidate, address, addressText);
   }

   bool testMachineMatchesPeerAddress(const Machine *machine, const IPAddress& address, const String *addressText = nullptr) const
   {
      return machineMatchesPeerAddress(machine, address, addressText);
   }

   void testQueueLocalPeerAddressCandidates(BrainView *brain)
   {
      queueLocalPeerAddressCandidates(brain);
   }

   void testBrainHandler(BrainView *brain, Message *message)
   {
      brainHandler(brain, message);
   }

   uint128_t testGetExistingMasterUUID(void) const
   {
      return getExistingMasterUUID();
   }

   void configureCloudflareTunnel(String& mothershipEndpoint) override
   {
      mothershipEndpoint.clear();
   }

   void teardownCloudflareTunnel(void) override
   {
   }

   void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, const String& message) override
   {
      (void)deployment;
      (void)message;
   }

   void spinApplicationFailed(ApplicationDeployment *deployment, const String& message) override
   {
      (void)deployment;
      (void)message;
   }

   bool loadAuthoritativeClusterTopology(ClusterTopology& topology) const override
   {
      if (haveStoredTopology == false)
      {
         topology = {};
         return false;
      }

      topology = storedTopology;
      return true;
   }

   bool persistAuthoritativeClusterTopology(const ClusterTopology& topology) override
   {
      if (persistTopologyShouldFail)
      {
         return false;
      }

      storedTopology = topology;
      haveStoredTopology = true;
      return true;
   }
};

class NoopBrainIaaS final : public BrainIaaS
{
public:

   bool bgpEnabled = false;
   bool shouldResolveLocalPeerAddress = false;
   IPAddress resolvedLocalPeerAddress = {};
   String resolvedLocalPeerAddressText = {};

   void boot(void) override {}

   void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
   {
      (void)coro;
      (void)lifetime;
      (void)config;
      (void)count;
      (void)newMachines;
      error.clear();
   }

   void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
   {
      (void)coro;
      (void)metro;
      (void)machines;
   }

   void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
   {
      (void)coro;
      (void)selfUUID;
      (void)brains;
      selfIsBrain = false;
   }

   void hardRebootMachine(uint128_t uuid) override
   {
      (void)uuid;
   }

   void reportHardwareFailure(uint128_t uuid, const String& report) override
   {
      (void)uuid;
      (void)report;
   }

   void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
   {
      (void)coro;
      (void)decommissionedIDs;
   }

   void destroyMachine(Machine *machine) override
   {
      (void)machine;
   }

   uint32_t supportedMachineKindsMask() const override
   {
      return 0;
   }

   bool bgpEnabledForEnvironment(void) const override
   {
      return bgpEnabled;
   }

   bool resolveLocalBrainPeerAddress(IPAddress& address, String& addressText) const override
   {
      if (shouldResolveLocalPeerAddress == false)
      {
         address = {};
         addressText.clear();
         return false;
      }

      address = resolvedLocalPeerAddress;
      addressText = resolvedLocalPeerAddressText;
      return true;
   }
};

static ClusterMachine makeBrainMachine(const String& address, bool usePublicAddress, uint128_t uuid)
{
   ClusterMachine machine = {};
   machine.source = ClusterMachineSource::adopted;
   machine.backing = ClusterMachineBacking::owned;
   machine.lifetime = MachineLifetime::owned;
   machine.isBrain = true;
   machine.uuid = uuid;
   machine.creationTimeMs = 1;

   if (usePublicAddress)
   {
      prodigyAppendUniqueClusterMachineAddress(machine.addresses.publicAddresses, address);
   }
   else
   {
      prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, address);
   }

   return machine;
}

static ClusterMachine makeMultihomedBrainMachine(uint128_t uuid, std::initializer_list<std::pair<const char *, uint8_t>> addresses)
{
   ClusterMachine machine = {};
   Vector<ClusterMachinePeerAddress> machineCandidates = {};
   machine.source = ClusterMachineSource::adopted;
   machine.backing = ClusterMachineBacking::owned;
   machine.lifetime = MachineLifetime::owned;
   machine.isBrain = true;
   machine.uuid = uuid;
   machine.creationTimeMs = 1;

   for (const auto& [address, cidr] : addresses)
   {
      ClusterMachinePeerAddress candidate = {};
      candidate.address.assign(address);
      candidate.cidr = cidr;
      prodigyAppendUniqueClusterMachinePeerAddress(machineCandidates, candidate);
   }
   prodigyAssignClusterMachineAddressesFromPeerCandidates(machine.addresses, machineCandidates);

   return machine;
}

static BrainView *firstBrainPeer(const TestBrain& brain)
{
   for (BrainView *candidate : brain.brains)
   {
      if (candidate != nullptr)
      {
         return candidate;
      }
   }

   return nullptr;
}

static Machine *findMachineByUUID(const TestBrain& brain, uint128_t uuid)
{
   auto it = brain.machinesByUUID.find(uuid);
   if (it == brain.machinesByUUID.end())
   {
      return nullptr;
   }

   return it->second;
}

static uint128_t makePeerTrackingKey(IPAddress address)
{
   if (address.isNull())
   {
      return 0;
   }

   if (address.is6 == false)
   {
      address = address.create4in6();
   }

   uint128_t key = 0;
   memcpy(&key, address.v6, sizeof(key));
   return key;
}

template <typename Handler>
static void forEachMessageInBuffer(String& buffer, Handler&& handler)
{
   uint8_t *cursor = buffer.data();
   uint8_t *end = buffer.data() + buffer.size();

   while (cursor < end)
   {
      Message *message = reinterpret_cast<Message *>(cursor);
      if (message->size == 0)
      {
         break;
      }

      handler(message);
      cursor += message->size;
   }
}

int main(void)
{
   TestSuite suite;
   bool createdRing = false;
   if (Ring::getRingFD() <= 0)
   {
      Ring::createRing(8, 8, 32, 32, -1, -1, 0);
      createdRing = true;
   }

   TestNeuron neuron = {};
   neuron.uuid = 0x111;
   thisNeuron = &neuron;

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      suite.expect(TestBrain::testCompareIPAddresses(IPAddress("10.0.0.1", false), IPAddress("fd00:10::1", true)) < 0, "compare_ip_addresses_orders_ipv4_before_ipv6");
      suite.expect(TestBrain::testCompareIPAddresses(IPAddress("fd00:10::1", true), IPAddress("10.0.0.1", false)) > 0, "compare_ip_addresses_orders_ipv6_after_ipv4");
      suite.expect(TestBrain::testCompareIPAddresses(IPAddress("10.0.0.1", false), IPAddress("10.0.0.2", false)) < 0, "compare_ip_addresses_orders_ipv4_numerically");
      suite.expect(TestBrain::testCompareIPAddresses(IPAddress("10.0.0.2", false), IPAddress("10.0.0.1", false)) > 0, "compare_ip_addresses_orders_ipv4_reverse");
      suite.expect(TestBrain::testCompareIPAddresses(IPAddress("fd00:10::1", true), IPAddress("fd00:10::1", true)) == 0, "compare_ip_addresses_accepts_equal_ipv6_literals");

      String exactText = "brain-peer"_ctv;
      suite.expect(TestBrain::testMachineAddressMatchesLiteral(""_ctv, IPAddress("fd00:10::20", true)) == false, "machine_address_matches_literal_rejects_empty_candidate");
      suite.expect(TestBrain::testMachineAddressMatchesLiteral("not-an-ip"_ctv, IPAddress("fd00:10::20", true), &exactText) == false, "machine_address_matches_literal_rejects_invalid_candidate");
      suite.expect(TestBrain::testMachineAddressMatchesLiteral(exactText, IPAddress("fd00:10::20", true), &exactText), "machine_address_matches_literal_accepts_exact_text_match");
      suite.expect(TestBrain::testMachineAddressMatchesLiteral("fd00:10::20"_ctv, IPAddress("fd00:10::20", true)), "machine_address_matches_literal_accepts_parseable_match");

      Machine machine = {};
      machine.privateAddress = "fd00:10::20"_ctv;
      machine.publicAddress = "2001:db8::20"_ctv;
      suite.expect(brain.testMachineMatchesPeerAddress(nullptr, IPAddress("fd00:10::20", true)) == false, "machine_matches_peer_address_rejects_null_machine");
      suite.expect(brain.testMachineMatchesPeerAddress(&machine, IPAddress()) == false, "machine_matches_peer_address_rejects_null_address");
      suite.expect(brain.testMachineMatchesPeerAddress(&machine, IPAddress("fd00:10::20", true)), "machine_matches_peer_address_accepts_private_address_match");
      suite.expect(brain.testMachineMatchesPeerAddress(&machine, IPAddress("2001:db8::20", true), &machine.publicAddress), "machine_matches_peer_address_accepts_exact_text_match");
      suite.expect(brain.testMachineMatchesPeerAddress(&machine, IPAddress("fd00:10::21", true)) == false, "machine_matches_peer_address_rejects_missing_candidate");

      BrainView byAddress = {};
      byAddress.uuid = 0x681;
      byAddress.peerAddress = IPAddress("fd00:10::41", true);

      BrainView byCandidate = {};
      byCandidate.uuid = 0x682;
      ClusterMachinePeerAddress invalidCandidate = {};
      invalidCandidate.address.assign("not-an-ip"_ctv);
      ClusterMachinePeerAddress validCandidate = {};
      validCandidate.address.assign("fd00:10::42"_ctv);
      byCandidate.peerAddresses.push_back(invalidCandidate);
      byCandidate.peerAddresses.push_back(validCandidate);

      brain.brains.insert(&byAddress);
      brain.brains.insert(&byCandidate);

      Vector<ClusterMachinePeerAddress> lookupCandidates = {};
      lookupCandidates.push_back(invalidCandidate);
      ClusterMachinePeerAddress missingCandidate = {};
      missingCandidate.address.assign("fd00:10::99"_ctv);
      lookupCandidates.push_back(missingCandidate);
      lookupCandidates.push_back(validCandidate);

      suite.expect(brain.testFindBrainViewByPeerAddresses(lookupCandidates) == &byCandidate, "find_brain_view_by_peer_addresses_skips_invalid_candidates");
      suite.expect(brain.testFindBrainViewByPeerAddresses(Vector<ClusterMachinePeerAddress>{}) == nullptr, "find_brain_view_by_peer_addresses_returns_null_for_empty_input");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView inactivePeer = {};
      inactivePeer.connected = false;
      inactivePeer.isFixedFile = true;
      inactivePeer.fslot = 31;
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"fd00:10::91"_ctv, 64});
      brain.testQueueLocalPeerAddressCandidates(&inactivePeer);
      suite.expect(inactivePeer.pendingSend == false, "queue_local_peer_candidates_rejects_inactive_peer");
      suite.expect(inactivePeer.wBuffer.empty(), "queue_local_peer_candidates_leaves_inactive_peer_buffer_empty");

      BrainView missingLocalCandidatesPeer = {};
      missingLocalCandidatesPeer.connected = true;
      missingLocalCandidatesPeer.isFixedFile = true;
      missingLocalCandidatesPeer.fslot = 32;
      brain.localBrainPeerAddresses.clear();
      brain.localBrainPeerAddress = {};
      brain.localBrainPeerAddressText.clear();
      NeuronBase *savedNeuron = thisNeuron;
      thisNeuron = nullptr;
      brain.testQueueLocalPeerAddressCandidates(&missingLocalCandidatesPeer);
      thisNeuron = savedNeuron;
      suite.expect(missingLocalCandidatesPeer.pendingSend == false, "queue_local_peer_candidates_rejects_missing_local_candidates");
      suite.expect(missingLocalCandidatesPeer.wBuffer.empty(), "queue_local_peer_candidates_keeps_missing_local_candidates_buffer_empty");

      BrainView activePeer = {};
      activePeer.connected = true;
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"fd00:10::92"_ctv, 64});
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"2001:db8::92"_ctv, 64});
      ScopedSocketPair activeSockets = {};
      if (activeSockets.create(suite, "queue_local_peer_candidates_creates_active_socketpair"))
      {
         activePeer.isFixedFile = true;
         activePeer.fslot = activeSockets.adoptLeftIntoFixedFileSlot();
         suite.expect(activePeer.fslot >= 0, "queue_local_peer_candidates_adopts_fixed_slot");
         if (activePeer.fslot >= 0)
         {
            brain.testQueueLocalPeerAddressCandidates(&activePeer);
            suite.expect(activePeer.wBuffer.size() >= Message::headerBytes, "queue_local_peer_candidates_serializes_message_for_active_peer");
            if (activePeer.wBuffer.size() >= Message::headerBytes)
            {
               auto *message = reinterpret_cast<Message *>(activePeer.wBuffer.data());
               suite.expect(message->topic == static_cast<uint16_t>(BrainTopic::peerAddressCandidates), "queue_local_peer_candidates_uses_peer_candidate_topic");
               suite.expect(message->payloadSize() > 0, "queue_local_peer_candidates_serializes_candidates");
            }
         }
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView peer = {};
      Machine machine = {};
      peer.machine = &machine;

      String invalidSerialized = "not-bitsery"_ctv;
      String invalidBuffer = {};
      Message::construct(invalidBuffer, BrainTopic::peerAddressCandidates, invalidSerialized);
      brain.testBrainHandler(&peer, reinterpret_cast<Message *>(invalidBuffer.data()));
      suite.expect(peer.peerAddresses.empty(), "peer_address_candidates_handler_ignores_invalid_payload");
      suite.expect(machine.privateAddress.empty(), "peer_address_candidates_handler_keeps_machine_state_on_invalid_payload");

      Vector<ClusterMachinePeerAddress> candidates = {};
      candidates.push_back(ClusterMachinePeerAddress{"fd00:10::93"_ctv, 64});
      candidates.push_back(ClusterMachinePeerAddress{"2001:db8::93"_ctv, 64});
      String serializedCandidates = {};
      BitseryEngine::serialize(serializedCandidates, candidates);
      String validBuffer = {};
      Message::construct(validBuffer, BrainTopic::peerAddressCandidates, serializedCandidates);
      brain.testBrainHandler(&peer, reinterpret_cast<Message *>(validBuffer.data()));
      suite.expect(peer.peerAddresses.size() == 2, "peer_address_candidates_handler_applies_valid_payload");
      suite.expect(peer.peerAddressText == "fd00:10::93"_ctv, "peer_address_candidates_handler_prefers_first_valid_candidate");
      suite.expect(machine.privateAddress == "fd00:10::93"_ctv, "peer_address_candidates_handler_updates_machine_private_address");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      neuron.private4 = {};

      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"fd00:10::10"_ctv, 64});
      BrainView peerByText = {};
      peerByText.peerAddressText.assign("fd00:10::29"_ctv);
      suite.expect(brain.shouldWeConnectToBrain(&peerByText), "should_we_connect_to_brain_uses_peer_address_text_fallback");

      brain.localBrainPeerAddresses.clear();
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"fd00:10::40"_ctv, 64});
      BrainView peerByAddress = {};
      peerByAddress.peerAddress = IPAddress("fd00:10::20", true);
      suite.expect(brain.shouldWeConnectToBrain(&peerByAddress) == false, "should_we_connect_to_brain_uses_peer_address_fallback");

      brain.localBrainPeerAddresses.clear();
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"10.0.0.10"_ctv, 24});
      BrainView peerByPrivate4 = {};
      peerByPrivate4.private4 = IPAddress("10.0.0.20", false).v4;
      suite.expect(brain.shouldWeConnectToBrain(&peerByPrivate4), "should_we_connect_to_brain_uses_private4_fallback");

      brain.localBrainPeerAddresses.clear();
      ClusterMachinePeerAddress invalidLocalCandidate = {};
      invalidLocalCandidate.address.assign("not-an-ip"_ctv);
      brain.localBrainPeerAddresses.push_back(invalidLocalCandidate);
      brain.localBrainPeerAddress = IPAddress("fd00:10::10", true);
      brain.localBrainPeerAddressText = "fd00:10::10"_ctv;
      BrainView peerByInvalidCandidates = {};
      ClusterMachinePeerAddress invalidPeerCandidate = {};
      invalidPeerCandidate.address.assign("still-not-an-ip"_ctv);
      peerByInvalidCandidates.peerAddresses.push_back(invalidPeerCandidate);
      peerByInvalidCandidates.peerAddress = IPAddress("fd00:10::20", true);
      suite.expect(brain.shouldWeConnectToBrain(&peerByInvalidCandidates), "should_we_connect_to_brain_falls_back_after_invalid_candidates");

      brain.localBrainPeerAddresses.clear();
      brain.localBrainPeerAddresses.push_back(invalidLocalCandidate);
      brain.localBrainPeerAddress = {};
      brain.localBrainPeerAddressText.clear();
      neuron.private4 = {};
      BrainView peerByUUID = {};
      peerByUUID.uuid = neuron.uuid + 1;
      suite.expect(brain.shouldWeConnectToBrain(&peerByUUID), "should_we_connect_to_brain_falls_back_to_uuid_order");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      Vector<ClusterMachinePeerAddress> candidates = {};
      ClusterMachinePeerAddress valid = {};
      valid.address.assign("fd00:10::55"_ctv);
      valid.cidr = 64;
      candidates.push_back(valid);

      suite.expect(brain.updateBrainPeerAddressCandidates(nullptr, candidates) == false, "update_peer_candidates_rejects_null_brain");
      BrainView emptyPeer = {};
      Vector<ClusterMachinePeerAddress> emptyCandidates = {};
      suite.expect(brain.updateBrainPeerAddressCandidates(&emptyPeer, emptyCandidates) == false, "update_peer_candidates_rejects_empty_input");

      BrainView invalidOnlyPeer = {};
      Vector<ClusterMachinePeerAddress> invalidOnly = {};
      ClusterMachinePeerAddress invalid = {};
      invalid.address.assign(""_ctv);
      invalidOnly.push_back(invalid);
      suite.expect(brain.updateBrainPeerAddressCandidates(&invalidOnlyPeer, invalidOnly) == false, "update_peer_candidates_rejects_unusable_candidates");

      BrainView unchangedPeer = {};
      unchangedPeer.peerAddresses = candidates;
      suite.expect(brain.updateBrainPeerAddressCandidates(&unchangedPeer, candidates) == false, "update_peer_candidates_rejects_unchanged_candidates");

      BrainView runtimePeer = {};
      Machine runtimeMachine = {};
      runtimePeer.machine = &runtimeMachine;
      suite.expect(brain.updateBrainPeerAddressCandidates(&runtimePeer, candidates), "update_peer_candidates_updates_runtime_machine_without_master");
      suite.expect(runtimeMachine.peerAddresses.size() == 1, "update_peer_candidates_updates_runtime_machine_candidates");
      suite.expect(runtimeMachine.privateAddress == "fd00:10::55"_ctv, "update_peer_candidates_updates_runtime_machine_private_address");

      TestBrain masterBrain = {};
      masterBrain.iaas = new NoopBrainIaaS();
      masterBrain.weAreMaster = true;
      BrainView masterPeer = {};
      suite.expect(masterBrain.updateBrainPeerAddressCandidates(&masterPeer, candidates), "update_peer_candidates_master_without_stored_topology_returns_true");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      Vector<IPAddress> localAddresses = {};
      localAddresses.push_back(IPAddress("fd00:10::99", true));
      NeuronBase *savedNeuron = thisNeuron;
      thisNeuron = nullptr;
      brain.testCollectLocalBrainCandidateAddresses(localAddresses);
      suite.expect(localAddresses.empty(), "collect_local_brain_candidate_addresses_clears_output_without_local_neuron");
      suite.expect(brain.testLocalBrainAddressMatches(IPAddress("fd00:10::99", true)) == false, "local_brain_address_matches_rejects_when_local_neuron_missing");

      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"fd00:10::77"_ctv, 64});
      brain.testRefreshLocalBrainPeerAddresses();
      suite.expect(brain.localBrainPeerAddresses.empty(), "refresh_local_brain_peer_addresses_clears_candidates_without_local_neuron");
      thisNeuron = savedNeuron;
   }

   {
      TestBrain brain = {};
      suite.expect(brain.testResolveLocalBrainPeerAddressFromIaaS() == false, "resolve_local_brain_peer_address_from_iaas_rejects_missing_iaas");

      auto *iaas = new NoopBrainIaaS();
      brain.iaas = iaas;
      suite.expect(brain.testResolveLocalBrainPeerAddressFromIaaS() == false, "resolve_local_brain_peer_address_from_iaas_rejects_unconfigured_iaas");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      ClusterTopology topology = {};
      topology.machines.push_back(makeBrainMachine("fd00:10::10"_ctv, false, neuron.uuid));
      topology.machines.push_back(makeBrainMachine("fd00:10::29"_ctv, false, 0x222));

      suite.expect(brain.restoreBrainsFromClusterTopology(topology), "restore_ipv6_private_topology");
      suite.expect(brain.localBrainPeerAddress.equals(IPAddress("fd00:10::10", true)), "restore_ipv6_private_self_peer_address");
      suite.expect(brain.brains.size() == 1, "restore_ipv6_private_peer_count");

      BrainView *peer = firstBrainPeer(brain);
      suite.expect(peer != nullptr, "restore_ipv6_private_peer_present");
      if (peer != nullptr)
      {
         suite.expect(peer->peerAddress.equals(IPAddress("fd00:10::29", true)), "restore_ipv6_private_peer_address");
         suite.expect(peer->uuid == 0x222, "restore_ipv6_private_peer_uuid");
         suite.expect(peer->private4 == 0, "restore_ipv6_private_peer_private4_zero");
         suite.expect(brain.shouldWeConnectToBrain(peer), "restore_ipv6_private_connector_order");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView trackedByPrivate4 = {};
      trackedByPrivate4.uuid = 0x661;
      trackedByPrivate4.private4 = 0x0a000029;

      BrainView ignoredWithPeerText = {};
      ignoredWithPeerText.uuid = 0x662;
      ignoredWithPeerText.private4 = trackedByPrivate4.private4;
      ignoredWithPeerText.peerAddressText.assign("10.0.0.29"_ctv);

      BrainView ignoredWithPeerAddress = {};
      ignoredWithPeerAddress.uuid = 0x663;
      ignoredWithPeerAddress.private4 = trackedByPrivate4.private4;
      ignoredWithPeerAddress.peerAddress = IPAddress("fd00:10::29", true);

      brain.brains.insert(&trackedByPrivate4);
      brain.brains.insert(&ignoredWithPeerText);
      brain.brains.insert(&ignoredWithPeerAddress);

      suite.expect(brain.testUpdateSelfPeerTrackingKey(nullptr) == 0, "update_self_peer_tracking_key_null_brain_zero");
      suite.expect(brain.testUpdateSelfPeerTrackingKey(&trackedByPrivate4) == uint128_t(trackedByPrivate4.private4), "update_self_peer_tracking_key_prefers_private4");
      suite.expect(brain.testFindBrainViewByPrivate4(trackedByPrivate4.private4) == &trackedByPrivate4, "find_brain_view_by_private4_requires_blank_peer_state");
      suite.expect(brain.testFindBrainViewByPrivate4(0x0a00002a) == nullptr, "find_brain_view_by_private4_returns_null_for_missing_private4");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView trackedByPeerAddress = {};
      trackedByPeerAddress.uuid = 0x671;
      trackedByPeerAddress.peerAddress = IPAddress("10.0.0.41", false);

      BrainView trackedByPeerCandidates = {};
      trackedByPeerCandidates.uuid = 0x672;
      ClusterMachinePeerAddress invalidCandidate = {};
      invalidCandidate.address.assign("not-an-ip"_ctv);
      ClusterMachinePeerAddress validCandidate = {};
      validCandidate.address.assign("fd00:10::42"_ctv);
      trackedByPeerCandidates.peerAddresses.push_back(invalidCandidate);
      trackedByPeerCandidates.peerAddresses.push_back(validCandidate);

      BrainView trackedByUUID = {};
      trackedByUUID.uuid = 0x673;

      brain.brains.insert(&trackedByPeerAddress);
      brain.brains.insert(&trackedByPeerCandidates);
      brain.brains.insert(&trackedByUUID);

      uint128_t peerAddressKey = makePeerTrackingKey(trackedByPeerAddress.peerAddress);
      suite.expect(brain.testUpdateSelfPeerTrackingKey(&trackedByPeerAddress) == peerAddressKey, "update_self_peer_tracking_key_uses_peer_address");
      suite.expect(brain.testFindBrainViewByUpdateSelfPeerKey(peerAddressKey) == &trackedByPeerAddress, "find_brain_view_by_update_self_peer_key_matches_peer_address");

      uint128_t candidateKey = makePeerTrackingKey(IPAddress("fd00:10::42", true));
      suite.expect(brain.testUpdateSelfPeerTrackingKey(&trackedByPeerCandidates) == candidateKey, "update_self_peer_tracking_key_uses_first_parseable_candidate");
      suite.expect(brain.testFindBrainViewByUpdateSelfPeerKey(candidateKey) == &trackedByPeerCandidates, "find_brain_view_by_update_self_peer_key_matches_candidate");

      suite.expect(brain.testUpdateSelfPeerTrackingKey(&trackedByUUID) == trackedByUUID.uuid, "update_self_peer_tracking_key_falls_back_to_uuid");
      suite.expect(brain.testFindBrainViewByUpdateSelfPeerKey(trackedByUUID.uuid) == &trackedByUUID, "find_brain_view_by_update_self_peer_key_matches_uuid_fallback");
      suite.expect(brain.testFindBrainViewByUpdateSelfPeerKey(0) == nullptr, "find_brain_view_by_update_self_peer_key_zero_returns_null");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      neuron.private4 = IPAddress("10.0.0.10", false);
      suite.expect(brain.testUpdateSelfLocalPeerTrackingKey() == uint128_t(neuron.private4.v4), "update_self_local_peer_tracking_key_prefers_local_private4");

      neuron.private4 = {};
      brain.localBrainPeerAddress = IPAddress("10.0.0.11", false);
      suite.expect(brain.testUpdateSelfLocalPeerTrackingKey() == makePeerTrackingKey(brain.localBrainPeerAddress), "update_self_local_peer_tracking_key_uses_local_peer_address");

      brain.localBrainPeerAddress = {};
      ClusterMachinePeerAddress invalidCandidate = {};
      invalidCandidate.address.assign("bad-address"_ctv);
      ClusterMachinePeerAddress validCandidate = {};
      validCandidate.address.assign("fd00:10::12"_ctv);
      brain.localBrainPeerAddresses.push_back(invalidCandidate);
      brain.localBrainPeerAddresses.push_back(validCandidate);
      suite.expect(brain.testUpdateSelfLocalPeerTrackingKey() == makePeerTrackingKey(IPAddress("fd00:10::12", true)), "update_self_local_peer_tracking_key_uses_local_candidate");

      brain.localBrainPeerAddresses.clear();
      suite.expect(brain.testUpdateSelfLocalPeerTrackingKey() == brain.selfBrainUUID(), "update_self_local_peer_tracking_key_falls_back_to_uuid");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      brain.testAdoptLocalBrainPeerAddress(IPAddress("fd00:10::50", true), ""_ctv);
      suite.expect(brain.localBrainPeerAddress.equals(IPAddress("fd00:10::50", true)), "adopt_local_brain_peer_address_sets_address");
      suite.expect(brain.localBrainPeerAddressText == "fd00:10::50"_ctv, "adopt_local_brain_peer_address_renders_text");
      suite.expect(brain.localBrainPeerAddresses.size() == 1, "adopt_local_brain_peer_address_adds_single_candidate");
      suite.expect(brain.localBrainPeerAddresses[0].address == "fd00:10::50"_ctv, "adopt_local_brain_peer_address_candidate_matches_rendered_text");

      brain.testAdoptLocalBrainPeerAddress(IPAddress("fd00:10::50", true), ""_ctv);
      suite.expect(brain.localBrainPeerAddresses.size() == 1, "adopt_local_brain_peer_address_deduplicates_candidates");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("fd00:10::99", true);
      brain.localBrainPeerAddressText = "fd00:10::99"_ctv;

      Vector<ClusterMachinePeerAddress> candidates = {};
      ClusterMachinePeerAddress invalid = {};
      invalid.address.assign("bad-address"_ctv);
      candidates.push_back(invalid);
      ClusterMachinePeerAddress valid = {};
      valid.address.assign("fd00:10::55"_ctv);
      valid.cidr = 64;
      candidates.push_back(valid);

      brain.testAdoptLocalBrainPeerAddresses(candidates);
      suite.expect(brain.localBrainPeerAddresses.size() == 1, "adopt_local_brain_peer_addresses_discards_invalid_candidates");
      suite.expect(brain.localBrainPeerAddress.equals(IPAddress("fd00:10::55", true)), "adopt_local_brain_peer_addresses_uses_first_parseable_candidate");
      suite.expect(brain.localBrainPeerAddressText == "fd00:10::55"_ctv, "adopt_local_brain_peer_addresses_tracks_selected_candidate_text");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("fd00:10::77", true);
      brain.localBrainPeerAddressText = "fd00:10::77"_ctv;

      Vector<ClusterMachinePeerAddress> candidates = {};
      ClusterMachinePeerAddress current = {};
      current.address.assign("fd00:10::77"_ctv);
      current.cidr = 64;
      candidates.push_back(current);
      ClusterMachinePeerAddress alternate = {};
      alternate.address.assign("fd00:10::88"_ctv);
      alternate.cidr = 64;
      candidates.push_back(alternate);

      brain.testAdoptLocalBrainPeerAddresses(candidates);
      suite.expect(brain.localBrainPeerAddress.equals(IPAddress("fd00:10::77", true)), "adopt_local_brain_peer_addresses_keeps_current_selection_when_still_present");
      suite.expect(brain.localBrainPeerAddresses.size() == 2, "adopt_local_brain_peer_addresses_refreshes_candidate_set_when_current_present");
   }

   {
      TestBrain brain = {};
      auto *iaas = new NoopBrainIaaS();
      iaas->shouldResolveLocalPeerAddress = true;
      iaas->resolvedLocalPeerAddress = IPAddress("2001:db8::123", true);
      brain.iaas = iaas;

      suite.expect(brain.testResolveLocalBrainPeerAddressFromIaaS(), "resolve_local_brain_peer_address_from_iaas_accepts_configured_address");
      suite.expect(brain.localBrainPeerAddress.equals(IPAddress("2001:db8::123", true)), "resolve_local_brain_peer_address_from_iaas_sets_address");
      suite.expect(brain.localBrainPeerAddressText == "2001:db8::123"_ctv, "resolve_local_brain_peer_address_from_iaas_renders_missing_text");
      suite.expect(brain.localBrainPeerAddresses.size() == 1, "resolve_local_brain_peer_address_from_iaas_adds_candidate");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      suite.expect(brain.testGetExistingMasterUUID() == 0, "get_existing_master_uuid_returns_zero_without_master");

      brain.weAreMaster = true;
      suite.expect(brain.testGetExistingMasterUUID() == neuron.uuid, "get_existing_master_uuid_returns_self_when_we_are_master");

      brain.weAreMaster = false;
      brain.noMasterYet = false;
      BrainView peerMaster = {};
      peerMaster.uuid = 0x888;
      peerMaster.isMasterBrain = true;
      brain.brains.insert(&peerMaster);
      suite.expect(brain.testGetExistingMasterUUID() == peerMaster.uuid, "get_existing_master_uuid_returns_master_peer_uuid");
      brain.brains.erase(&peerMaster);
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      ClusterTopology topology = {};
      topology.version = 7;
      topology.machines.push_back(makeMultihomedBrainMachine(neuron.uuid, {{"fd00:10::10", 64}}));
      topology.machines.push_back(makeMultihomedBrainMachine(0x444, {{"fd00:10::29", 64}, {"2001:db8::29", 64}}));

      suite.expect(brain.restoreBrainsFromClusterTopology(topology), "restore_multihomed_topology");
      BrainView *peer = firstBrainPeer(brain);
      suite.expect(peer != nullptr, "restore_multihomed_peer_present");
      if (peer != nullptr)
      {
         suite.expect(peer->peerAddresses.size() == 2, "restore_multihomed_peer_candidate_count");
         suite.expect(peer->peerAddressText == "fd00:10::29"_ctv, "restore_multihomed_prefers_first_candidate");
         suite.expect(brain.findBrainViewByPeerAddress(IPAddress("2001:db8::29", true)) == peer, "restore_multihomed_matches_alternate_candidate");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView existing = {};
      existing.uuid = 0x601;
      existing.peerAddress = IPAddress("fd00:10::149", true);
      existing.peerAddressText = "fd00:10::149"_ctv;
      existing.peerAddresses.push_back(ClusterMachinePeerAddress{"fd00:10::150"_ctv, 64});
      brain.brains.insert(&existing);

      ClusterTopology topology = {};
      topology.machines.push_back(makeMultihomedBrainMachine(0x701, {{"fd00:10::150", 64}, {"2001:db8::150", 64}}));

      suite.expect(brain.restoreBrainsFromClusterTopology(topology), "restore_brain_matches_existing_peer_candidates");
      suite.expect(firstBrainPeer(brain) == &existing, "restore_brain_matches_existing_peer_candidates_reuses_brain_view");
      suite.expect(existing.uuid == 0x701, "restore_brain_matches_existing_peer_candidates_updates_uuid");
      suite.expect(existing.peerAddressText == "fd00:10::150"_ctv, "restore_brain_matches_existing_peer_candidates_updates_preferred_text");
      suite.expect(existing.peerAddresses.size() == 2, "restore_brain_matches_existing_peer_candidates_refreshes_candidates");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView existing = {};
      existing.uuid = 0x702;
      existing.peerAddress = IPAddress("fd00:10::199", true);
      existing.peerAddressText = "fd00:10::199"_ctv;
      existing.peerAddresses.push_back(ClusterMachinePeerAddress{"fd00:10::199"_ctv, 64});
      brain.brains.insert(&existing);

      ClusterTopology topology = {};
      ClusterMachine uuidOnly = {};
      uuidOnly.source = ClusterMachineSource::adopted;
      uuidOnly.backing = ClusterMachineBacking::owned;
      uuidOnly.lifetime = MachineLifetime::owned;
      uuidOnly.isBrain = true;
      uuidOnly.uuid = 0x702;
      uuidOnly.creationTimeMs = 1;
      topology.machines.push_back(uuidOnly);

      suite.expect(brain.restoreBrainsFromClusterTopology(topology), "restore_brain_matches_existing_uuid_without_peer_address");
      suite.expect(firstBrainPeer(brain) == &existing, "restore_brain_matches_existing_uuid_without_peer_address_reuses_brain_view");
      suite.expect(existing.peerAddress.isNull(), "restore_brain_matches_existing_uuid_without_peer_address_clears_peer_address");
      suite.expect(existing.peerAddressText.empty(), "restore_brain_matches_existing_uuid_without_peer_address_clears_peer_text");
      suite.expect(existing.peerAddresses.empty(), "restore_brain_matches_existing_uuid_without_peer_address_clears_candidates");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView existing = {};
      existing.uuid = 0;
      existing.private4 = IPAddress("10.0.0.88", false).v4;
      brain.brains.insert(&existing);

      ClusterTopology topology = {};
      topology.machines.push_back(makeBrainMachine("10.0.0.88"_ctv, false, 0));

      suite.expect(brain.restoreBrainsFromClusterTopology(topology), "restore_brain_matches_existing_private4");
      suite.expect(firstBrainPeer(brain) == &existing, "restore_brain_matches_existing_private4_reuses_brain_view");
      suite.expect(existing.peerAddress.equals(IPAddress("10.0.0.88", false)), "restore_brain_matches_existing_private4_sets_peer_address");
      suite.expect(existing.peerAddressText == "10.0.0.88"_ctv, "restore_brain_matches_existing_private4_sets_peer_text");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      ClusterTopology initialTopology = {};
      initialTopology.machines.push_back(makeBrainMachine("10.0.0.89"_ctv, false, 0x704));
      suite.expect(brain.restoreBrainsFromClusterTopology(initialTopology), "restore_brain_preserves_runtime_uuid_initial_restore");

      BrainView *peer = firstBrainPeer(brain);
      suite.expect(peer != nullptr, "restore_brain_preserves_runtime_uuid_initial_peer_present");
      if (peer != nullptr)
      {
         suite.expect(peer->uuid == 0x704, "restore_brain_preserves_runtime_uuid_initial_uuid");
      }

      ClusterTopology zeroUUIDTopology = {};
      zeroUUIDTopology.machines.push_back(makeBrainMachine("10.0.0.89"_ctv, false, 0));
      suite.expect(brain.restoreBrainsFromClusterTopology(zeroUUIDTopology), "restore_brain_preserves_runtime_uuid_zero_uuid_replay");
      suite.expect(firstBrainPeer(brain) == peer, "restore_brain_preserves_runtime_uuid_reuses_peer");
      if (peer != nullptr)
      {
         suite.expect(peer->uuid == 0x704, "restore_brain_preserves_runtime_uuid_keeps_existing_uuid");
         suite.expect(peer->peerAddressText == "10.0.0.89"_ctv, "restore_brain_preserves_runtime_uuid_keeps_peer_text");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      ClusterTopology topology = {};
      topology.machines.push_back(makeBrainMachine("fd00:10::201"_ctv, false, 0x703));

      suite.expect(brain.restoreBrainsFromClusterTopology(topology), "restore_brain_allocates_new_peer_when_no_match_exists");
      BrainView *peer = firstBrainPeer(brain);
      suite.expect(peer != nullptr, "restore_brain_allocates_new_peer_when_no_match_exists_peer_present");
      if (peer != nullptr)
      {
         suite.expect(peer->uuid == 0x703, "restore_brain_allocates_new_peer_when_no_match_exists_sets_uuid");
         suite.expect(peer->peerAddressText == "fd00:10::201"_ctv, "restore_brain_allocates_new_peer_when_no_match_exists_sets_peer_text");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.haveStoredTopology = true;
      brain.storedTopology.version = 9;
      brain.storedTopology.machines.push_back(makeMultihomedBrainMachine(neuron.uuid, {{"2001:db8::10", 64}}));
      brain.storedTopology.machines.push_back(makeMultihomedBrainMachine(0x555, {{"2001:db8::29", 64}}));

      suite.expect(brain.restoreBrainsFromClusterTopology(brain.storedTopology), "restore_master_candidate_topology");
      BrainView *peer = firstBrainPeer(brain);
      suite.expect(peer != nullptr, "restore_master_candidate_peer_present");
      if (peer != nullptr)
      {
         Vector<ClusterMachinePeerAddress> publishedCandidates;
         ClusterMachinePeerAddress privateCandidate = {};
         privateCandidate.address.assign("fd00:10::29"_ctv);
         privateCandidate.cidr = 64;
         publishedCandidates.push_back(privateCandidate);
         ClusterMachinePeerAddress publicCandidate = {};
         publicCandidate.address.assign("2001:db8::29"_ctv);
         publicCandidate.cidr = 64;
         publishedCandidates.push_back(publicCandidate);

         suite.expect(brain.updateBrainPeerAddressCandidates(peer, publishedCandidates), "update_peer_candidates_master_applies");
         suite.expect(peer->peerAddresses.size() == 2, "update_peer_candidates_master_runtime_count");
         suite.expect(peer->peerAddressText == "fd00:10::29"_ctv, "update_peer_candidates_master_runtime_prefers_private");
         suite.expect(brain.storedTopology.version == 10, "update_peer_candidates_master_persists_version");
         suite.expect(brain.storedTopology.machines[1].addresses.privateAddresses.size() == 1 && brain.storedTopology.machines[1].addresses.publicAddresses.size() == 1, "update_peer_candidates_master_persists_count");
         suite.expect(brain.storedTopology.machines[1].addresses.privateAddresses[0].address == "fd00:10::29"_ctv, "update_peer_candidates_master_persists_private_first");
         suite.expect(brain.storedTopology.machines[1].addresses.publicAddresses[0].address == "2001:db8::29"_ctv, "update_peer_candidates_master_persists_public_fallback");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.haveStoredTopology = true;
      brain.storedTopology.version = 11;
      ClusterMachine ignoredNonBrain = makeBrainMachine("fd00:10::70"_ctv, false, 0x660);
      ignoredNonBrain.isBrain = false;
      ClusterMachine identityMatch = makeBrainMachine("fd00:10::71"_ctv, false, 0);
      identityMatch.cloud.cloudID = "brain-identity"_ctv;
      brain.storedTopology.machines.push_back(ignoredNonBrain);
      brain.storedTopology.machines.push_back(identityMatch);

      BrainView peer = {};
      Machine runtimeMachine = {};
      runtimeMachine.cloudID = "brain-identity"_ctv;
      peer.machine = &runtimeMachine;

      Vector<ClusterMachinePeerAddress> publishedCandidates = {};
      publishedCandidates.push_back(ClusterMachinePeerAddress{"fd00:10::72"_ctv, 64});
      publishedCandidates.push_back(ClusterMachinePeerAddress{"2001:db8::72"_ctv, 64});

      suite.expect(brain.updateBrainPeerAddressCandidates(&peer, publishedCandidates), "update_peer_candidates_master_matches_machine_identity");
      suite.expect(brain.storedTopology.version == 12, "update_peer_candidates_master_identity_match_persists_version");
      suite.expect(brain.storedTopology.machines[1].addresses.privateAddresses.size() == 1, "update_peer_candidates_master_identity_match_persists_private_candidate");
      suite.expect(brain.storedTopology.machines[1].addresses.privateAddresses[0].address == "fd00:10::72"_ctv, "update_peer_candidates_master_identity_match_rewrites_private_candidate");
      suite.expect(brain.storedTopology.machines[1].addresses.publicAddresses.size() == 1, "update_peer_candidates_master_identity_match_persists_public_candidate");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.haveStoredTopology = true;
      brain.storedTopology.version = 4;
      brain.storedTopology.machines.push_back(makeMultihomedBrainMachine(0x777, {{"2001:db8::81", 64}}));

      BrainView peer = {};
      Vector<ClusterMachinePeerAddress> publishedCandidates = {};
      publishedCandidates.push_back(ClusterMachinePeerAddress{"2001:db8::81"_ctv, 64});
      publishedCandidates.push_back(ClusterMachinePeerAddress{"fd00:10::81"_ctv, 64});

      suite.expect(brain.updateBrainPeerAddressCandidates(&peer, publishedCandidates), "update_peer_candidates_master_matches_candidate_address");
      suite.expect(brain.storedTopology.version == 5, "update_peer_candidates_master_candidate_match_persists_version");
      suite.expect(brain.storedTopology.machines[0].addresses.privateAddresses.size() == 1, "update_peer_candidates_master_candidate_match_adds_private_address");
      suite.expect(brain.storedTopology.machines[0].addresses.privateAddresses[0].address == "fd00:10::81"_ctv, "update_peer_candidates_master_candidate_match_reorders_private_first");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.haveStoredTopology = true;
      brain.storedTopology.version = 6;
      brain.storedTopology.machines.push_back(makeBrainMachine("fd00:10::90"_ctv, false, 0x990));

      BrainView peer = {};
      Vector<ClusterMachinePeerAddress> publishedCandidates = {};
      publishedCandidates.push_back(ClusterMachinePeerAddress{"fd00:10::91"_ctv, 64});

      suite.expect(brain.updateBrainPeerAddressCandidates(&peer, publishedCandidates), "update_peer_candidates_master_returns_true_when_topology_has_no_match");
      suite.expect(brain.storedTopology.version == 6, "update_peer_candidates_master_no_match_preserves_version");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.haveStoredTopology = true;
      brain.persistTopologyShouldFail = true;
      brain.storedTopology.version = 8;
      brain.storedTopology.machines.push_back(makeMultihomedBrainMachine(0x888, {{"2001:db8::88", 64}}));

      BrainView peer = {};
      Vector<ClusterMachinePeerAddress> publishedCandidates = {};
      publishedCandidates.push_back(ClusterMachinePeerAddress{"2001:db8::88"_ctv, 64});
      publishedCandidates.push_back(ClusterMachinePeerAddress{"fd00:10::88"_ctv, 64});

      suite.expect(brain.updateBrainPeerAddressCandidates(&peer, publishedCandidates) == false, "update_peer_candidates_master_propagates_persist_failure");
      suite.expect(brain.storedTopology.version == 8, "update_peer_candidates_master_persist_failure_keeps_stored_version");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      ClusterTopology topology = {};
      topology.machines.push_back(makeBrainMachine("2602:fac0:0:12ab:34cd::10"_ctv, true, neuron.uuid));
      topology.machines.push_back(makeBrainMachine("2602:fac0:0:12ab:34cd::29"_ctv, true, 0x333));

      suite.expect(brain.restoreBrainsFromClusterTopology(topology), "restore_ipv6_public_topology");
      suite.expect(brain.localBrainPeerAddress.equals(IPAddress("2602:fac0:0:12ab:34cd::10", true)), "restore_ipv6_public_self_peer_address");
      suite.expect(brain.brains.size() == 1, "restore_ipv6_public_peer_count");

      BrainView *peer = firstBrainPeer(brain);
      suite.expect(peer != nullptr, "restore_ipv6_public_peer_present");
      if (peer != nullptr)
      {
         suite.expect(peer->peerAddress.equals(IPAddress("2602:fac0:0:12ab:34cd::29", true)), "restore_ipv6_public_peer_address");
         suite.expect(peer->peerAddressText == "2602:fac0:0:12ab:34cd::29"_ctv, "restore_ipv6_public_peer_text");
         suite.expect(peer->uuid == 0x333, "restore_ipv6_public_peer_uuid");
         suite.expect(peer->private4 == 0, "restore_ipv6_public_peer_private4_zero");
         suite.expect(brain.shouldWeConnectToBrain(peer), "restore_ipv6_public_connector_order");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView higherBootLowerUUID = {};
      higherBootLowerUUID.uuid = 0x222;
      higherBootLowerUUID.boottimens = 200;

      BrainView lowerBootHigherUUID = {};
      lowerBootHigherUUID.uuid = 0x333;
      lowerBootHigherUUID.boottimens = 100;

      brain.brains.insert(&higherBootLowerUUID);
      brain.brains.insert(&lowerBootHigherUUID);

      suite.expect(brain.deriveRegisteredMasterUUID() == 0x111, "derive_registered_master_uuid_includes_self");

      neuron.uuid = 0x999;
      suite.expect(brain.deriveRegisteredMasterUUID() == 0x222, "derive_registered_master_uuid_prefers_lowest_uuid_over_boottime");
      neuron.uuid = 0x111;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView peerA = {};
      peerA.uuid = 0x444;
      peerA.boottimens = 10;
      peerA.existingMasterUUID = 0x444;

      BrainView peerB = {};
      peerB.uuid = 0x222;
      peerB.boottimens = 20;
      peerB.existingMasterUUID = 0x444;

      brain.brains.insert(&peerA);
      brain.brains.insert(&peerB);

      suite.expect(brain.resolveConsistentExistingMasterUUID() == 0x444, "resolve_consistent_existing_master_uuid");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView peerA = {};
      peerA.uuid = 0x444;
      peerA.boottimens = 10;
      peerA.existingMasterUUID = 0x444;

      BrainView peerB = {};
      peerB.uuid = 0x222;
      peerB.boottimens = 20;
      peerB.existingMasterUUID = 0x222;

      brain.brains.insert(&peerA);
      brain.brains.insert(&peerB);

      suite.expect(brain.resolveConsistentExistingMasterUUID() == 0, "resolve_conflicting_existing_master_uuid_returns_zero");
   }

   {
      int64_t nowMs = Time::now<TimeResolution::ms>();
      suite.expect(BrainBase::machineBootstrapLifecycleState(nowMs) == MachineState::deploying, "bootstrap_lifecycle_state_fresh_machine_deploying");
      suite.expect(BrainBase::machineBootstrapLifecycleState(nowMs - Time::minsToMs(8)) == MachineState::unknown, "bootstrap_lifecycle_state_stale_machine_unknown");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      ClusterTopology initialTopology = {};
      initialTopology.machines.push_back(makeBrainMachine("10.0.0.91"_ctv, false, 0x571));
      suite.expect(brain.restoreMachinesFromClusterTopology(initialTopology), "restore_machine_preserves_runtime_uuid_initial_restore");

      Machine *machine = findMachineByUUID(brain, 0x571);
      suite.expect(machine != nullptr, "restore_machine_preserves_runtime_uuid_initial_present");
      if (machine != nullptr)
      {
         suite.expect(machine->private4 == IPAddress("10.0.0.91", false).v4, "restore_machine_preserves_runtime_uuid_initial_private4");
      }

      ClusterTopology zeroUUIDTopology = {};
      zeroUUIDTopology.machines.push_back(makeBrainMachine("10.0.0.91"_ctv, false, 0));
      suite.expect(brain.restoreMachinesFromClusterTopology(zeroUUIDTopology), "restore_machine_preserves_runtime_uuid_zero_uuid_replay");

      Machine *preserved = findMachineByUUID(brain, 0x571);
      suite.expect(preserved == machine, "restore_machine_preserves_runtime_uuid_reuses_machine");
      if (preserved != nullptr)
      {
         suite.expect(preserved->uuid == 0x571, "restore_machine_preserves_runtime_uuid_keeps_existing_uuid");
         suite.expect(preserved->private4 == IPAddress("10.0.0.91", false).v4, "restore_machine_preserves_runtime_uuid_keeps_private4");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      ClusterTopology topology = {};
      ClusterMachine fresh = makeBrainMachine("fd00:10::41"_ctv, false, 0x551);
      fresh.creationTimeMs = Time::now<TimeResolution::ms>();
      ClusterMachine stale = makeBrainMachine("fd00:10::42"_ctv, false, 0x552);
      stale.creationTimeMs = Time::now<TimeResolution::ms>() - Time::minsToMs(8);
      topology.machines.push_back(fresh);
      topology.machines.push_back(stale);

      suite.expect(brain.restoreMachinesFromClusterTopology(topology), "restore_machine_lifecycle_states");

      Machine *freshMachine = findMachineByUUID(brain, 0x551);
      Machine *staleMachine = findMachineByUUID(brain, 0x552);
      suite.expect(freshMachine != nullptr, "restore_machine_lifecycle_fresh_present");
      suite.expect(staleMachine != nullptr, "restore_machine_lifecycle_stale_present");
      if (freshMachine != nullptr)
      {
         suite.expect(freshMachine->state == MachineState::deploying, "restore_machine_lifecycle_fresh_deploying");
      }
      if (staleMachine != nullptr)
      {
         suite.expect(staleMachine->state == MachineState::unknown, "restore_machine_lifecycle_stale_unknown");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.brainConfig.runtimeEnvironment.test.enabled = true;

      ClusterTopology topology = {};
      ClusterMachine self = makeBrainMachine("10.0.0.10"_ctv, false, neuron.uuid);
      ClusterMachine workerA = makeBrainMachine("10.0.0.11"_ctv, false, 0x561);
      workerA.isBrain = false;
      ClusterMachine workerB = makeBrainMachine("10.0.0.12"_ctv, false, 0x562);
      workerB.isBrain = false;
      topology.machines.push_back(self);
      topology.machines.push_back(workerA);
      topology.machines.push_back(workerB);

      suite.expect(brain.restoreMachinesFromClusterTopology(topology), "restore_machine_test_runtime_synthesizes_missing_racks");

      Machine *selfMachine = findMachineByUUID(brain, neuron.uuid);
      Machine *workerAMachine = findMachineByUUID(brain, 0x561);
      Machine *workerBMachine = findMachineByUUID(brain, 0x562);
      suite.expect(selfMachine != nullptr, "restore_machine_test_runtime_self_present");
      suite.expect(workerAMachine != nullptr, "restore_machine_test_runtime_worker_a_present");
      suite.expect(workerBMachine != nullptr, "restore_machine_test_runtime_worker_b_present");
      if (selfMachine != nullptr && workerAMachine != nullptr && workerBMachine != nullptr)
      {
         suite.expect(selfMachine->rackUUID != 0, "restore_machine_test_runtime_self_rack_nonzero");
         suite.expect(workerAMachine->rackUUID != 0, "restore_machine_test_runtime_worker_a_rack_nonzero");
         suite.expect(workerBMachine->rackUUID != 0, "restore_machine_test_runtime_worker_b_rack_nonzero");
         suite.expect(selfMachine->rackUUID != workerAMachine->rackUUID, "restore_machine_test_runtime_self_and_worker_a_racks_distinct");
         suite.expect(selfMachine->rackUUID != workerBMachine->rackUUID, "restore_machine_test_runtime_self_and_worker_b_racks_distinct");
         suite.expect(workerAMachine->rackUUID != workerBMachine->rackUUID, "restore_machine_test_runtime_worker_racks_distinct");
         suite.expect(selfMachine->rack != workerAMachine->rack, "restore_machine_test_runtime_self_and_worker_a_rack_objects_distinct");
         suite.expect(selfMachine->rack != workerBMachine->rack, "restore_machine_test_runtime_self_and_worker_b_rack_objects_distinct");
         suite.expect(workerAMachine->rack != workerBMachine->rack, "restore_machine_test_runtime_worker_rack_objects_distinct");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.haveStoredTopology = true;

      neuron.haveLatestHardware = true;
      neuron.latestHardware = {};
      neuron.latestHardware.inventoryComplete = true;
      neuron.latestHardware.collectedAtMs = 777;
      neuron.latestHardware.cpu.logicalCores = 2;
      neuron.latestHardware.memory.totalMB = 3910;
      MachineDiskHardwareProfile disk = {};
      disk.sizeMB = 20480;
      neuron.latestHardware.disks.push_back(disk);

      ClusterTopology topology = {};
      ClusterMachine self = makeBrainMachine("10.128.0.41"_ctv, false, neuron.uuid);
      self.source = ClusterMachineSource::created;
      self.backing = ClusterMachineBacking::cloud;
      self.lifetime = MachineLifetime::ondemand;
      self.kind = MachineConfig::MachineKind::vm;
      self.cloud.schema = "e2-medium"_ctv;
      self.cloud.providerMachineType = "e2-medium"_ctv;
      self.cloud.cloudID = "gcp-seed"_ctv;
      self.ssh.address = "34.30.210.167"_ctv;
      self.ssh.user = "root"_ctv;
      self.creationTimeMs = Time::now<TimeResolution::ms>();
      topology.machines.push_back(self);

      suite.expect(brain.restoreMachinesFromClusterTopology(topology), "restore_machine_replays_local_hardware_inventory");
      Machine *selfMachine = findMachineByUUID(brain, neuron.uuid);
      suite.expect(selfMachine != nullptr, "restore_machine_replays_local_hardware_inventory_present");
      if (selfMachine != nullptr)
      {
         suite.expect(selfMachine->isThisMachine, "restore_machine_replays_local_hardware_inventory_marks_self");
         suite.expect(selfMachine->hardware.inventoryComplete, "restore_machine_replays_local_hardware_inventory_complete");
         suite.expect(selfMachine->hardware.collectedAtMs == 777, "restore_machine_replays_local_hardware_inventory_timestamp");
         suite.expect(selfMachine->totalLogicalCores == 2, "restore_machine_replays_local_hardware_inventory_cores");
         suite.expect(selfMachine->totalMemoryMB == 3910, "restore_machine_replays_local_hardware_inventory_memory");
         suite.expect(selfMachine->totalStorageMB == 20480, "restore_machine_replays_local_hardware_inventory_storage");
         suite.expect(selfMachine->state != MachineState::healthy, "restore_machine_replays_local_hardware_inventory_requires_self_neuron_control");

         selfMachine->neuron.isFixedFile = true;
         selfMachine->neuron.fslot = 13;
         selfMachine->neuron.connected = true;
         brain.replayLocalMachineHardwareProfileIfReady();
         suite.expect(selfMachine->state == MachineState::healthy, "restore_machine_replays_local_hardware_inventory_marks_self_healthy_after_neuron_control");
      }

      neuron.haveLatestHardware = false;
      neuron.latestHardware = {};
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.haveStoredTopology = true;

      neuron.deferredProgressCalled = false;
      neuron.haveLatestHardware = false;
      neuron.latestHardware = {};
      neuron.haveDeferredHardware = true;
      neuron.deferredHardware = {};
      neuron.deferredHardware.inventoryComplete = true;
      neuron.deferredHardware.collectedAtMs = 999;
      neuron.deferredHardware.cpu.logicalCores = 4;
      neuron.deferredHardware.memory.totalMB = 8192;
      MachineDiskHardwareProfile disk = {};
      disk.sizeMB = 40960;
      neuron.deferredHardware.disks.push_back(disk);

      ClusterTopology topology = {};
      ClusterMachine self = makeBrainMachine("10.128.0.41"_ctv, false, neuron.uuid);
      self.source = ClusterMachineSource::created;
      self.backing = ClusterMachineBacking::cloud;
      self.lifetime = MachineLifetime::ondemand;
      self.kind = MachineConfig::MachineKind::vm;
      self.cloud.schema = "e2-medium"_ctv;
      self.cloud.providerMachineType = "e2-medium"_ctv;
      self.cloud.cloudID = "gcp-seed-deferred"_ctv;
      self.ssh.address = "34.30.210.169"_ctv;
      self.ssh.user = "root"_ctv;
      self.creationTimeMs = Time::now<TimeResolution::ms>();
      topology.machines.push_back(self);

      suite.expect(brain.restoreMachinesFromClusterTopology(topology), "restore_machine_polls_deferred_local_hardware_inventory");
      suite.expect(neuron.deferredProgressCalled, "restore_machine_polls_deferred_local_hardware_inventory_calls_progress");
      Machine *selfMachine = findMachineByUUID(brain, neuron.uuid);
      suite.expect(selfMachine != nullptr, "restore_machine_polls_deferred_local_hardware_inventory_present");
      if (selfMachine != nullptr)
      {
         suite.expect(selfMachine->hardware.inventoryComplete, "restore_machine_polls_deferred_local_hardware_inventory_complete");
         suite.expect(selfMachine->hardware.collectedAtMs == 999, "restore_machine_polls_deferred_local_hardware_inventory_timestamp");
         suite.expect(selfMachine->totalLogicalCores == 4, "restore_machine_polls_deferred_local_hardware_inventory_cores");
         suite.expect(selfMachine->totalMemoryMB == 8192, "restore_machine_polls_deferred_local_hardware_inventory_memory");
         suite.expect(selfMachine->totalStorageMB == 40960, "restore_machine_polls_deferred_local_hardware_inventory_storage");
         suite.expect(selfMachine->state != MachineState::healthy, "restore_machine_polls_deferred_local_hardware_inventory_requires_self_neuron_control");

         selfMachine->neuron.isFixedFile = true;
         selfMachine->neuron.fslot = 15;
         selfMachine->neuron.connected = true;
         brain.replayLocalMachineHardwareProfileIfReady();
         suite.expect(selfMachine->state == MachineState::healthy, "restore_machine_polls_deferred_local_hardware_inventory_marks_self_healthy_after_neuron_control");
      }

      neuron.haveDeferredHardware = false;
      neuron.deferredHardware = {};
      neuron.haveLatestHardware = false;
      neuron.latestHardware = {};
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.haveStoredTopology = true;

      ClusterTopology topology = {};
      ClusterMachine self = makeBrainMachine("10.128.0.41"_ctv, false, neuron.uuid);
      self.source = ClusterMachineSource::created;
      self.backing = ClusterMachineBacking::cloud;
      self.lifetime = MachineLifetime::ondemand;
      self.kind = MachineConfig::MachineKind::vm;
      self.cloud.schema = "e2-medium"_ctv;
      self.cloud.providerMachineType = "e2-medium"_ctv;
      self.cloud.cloudID = "gcp-seed-late"_ctv;
      self.ssh.address = "34.30.210.168"_ctv;
      self.ssh.user = "root"_ctv;
      self.creationTimeMs = Time::now<TimeResolution::ms>();
      topology.machines.push_back(self);
      brain.storedTopology = topology;

      suite.expect(brain.restoreMachinesFromClusterTopology(topology), "restore_machine_accepts_late_local_hardware_inventory");
      Machine *selfMachine = findMachineByUUID(brain, neuron.uuid);
      suite.expect(selfMachine != nullptr, "restore_machine_accepts_late_local_hardware_inventory_present");
      if (selfMachine != nullptr)
      {
         suite.expect(selfMachine->hardware.inventoryComplete == false, "restore_machine_accepts_late_local_hardware_inventory_starts_empty");

         MachineHardwareProfile lateHardware = {};
         lateHardware.inventoryComplete = true;
         lateHardware.collectedAtMs = 888;
         lateHardware.cpu.logicalCores = 3;
         lateHardware.memory.totalMB = 4096;
         MachineDiskHardwareProfile disk = {};
         disk.sizeMB = 30720;
         lateHardware.disks.push_back(disk);

         brain.adoptLocalMachineHardwareProfile(lateHardware);
         suite.expect(selfMachine->hardware.inventoryComplete, "restore_machine_accepts_late_local_hardware_inventory_complete");
         suite.expect(selfMachine->hardware.collectedAtMs == 888, "restore_machine_accepts_late_local_hardware_inventory_timestamp");
         suite.expect(selfMachine->totalLogicalCores == 3, "restore_machine_accepts_late_local_hardware_inventory_cores");
         suite.expect(selfMachine->totalMemoryMB == 4096, "restore_machine_accepts_late_local_hardware_inventory_memory");
         suite.expect(selfMachine->totalStorageMB == 30720, "restore_machine_accepts_late_local_hardware_inventory_storage");
         suite.expect(selfMachine->state != MachineState::healthy, "restore_machine_accepts_late_local_hardware_inventory_requires_self_neuron_control");

         selfMachine->neuron.isFixedFile = true;
         selfMachine->neuron.fslot = 17;
         selfMachine->neuron.connected = true;
         brain.adoptLocalMachineHardwareProfile(lateHardware);
         suite.expect(selfMachine->state == MachineState::healthy, "restore_machine_accepts_late_local_hardware_inventory_marks_self_healthy_after_neuron_control");
      }
   }

   {
      TestBrain brain = {};
      NoopBrainIaaS iaas = {};
      brain.iaas = &iaas;

      Machine active = {};
      active.uuid = uint128_t(0x9101);
      active.neuron.isFixedFile = true;
      active.neuron.fslot = 11;
      active.neuron.connected = true;

      Machine inactive = {};
      inactive.uuid = uint128_t(0x9102);
      inactive.neuron.isFixedFile = true;
      inactive.neuron.fslot = 12;
      inactive.neuron.connected = false;

      brain.machines.insert(&active);
      brain.machines.insert(&inactive);

      DistributableExternalSubnet subnet = {};
      subnet.uuid = uint128_t(0xA001);
      subnet.name.assign("switchboard-pinned"_ctv);
      subnet.subnet.network = IPAddress("2001:db8:100::", true);
      subnet.subnet.cidr = 64;
      subnet.routing = ExternalSubnetRouting::switchboardPinnedRoute;
      brain.brainConfig.distributableExternalSubnets.push_back(subnet);

      brain.testSendNeuronSwitchboardRoutableSubnets();

      bool sawRoutableSubnets = false;
      forEachMessageInBuffer(active.neuron.wBuffer, [&] (Message *message) {
         if (NeuronTopic(message->topic) != NeuronTopic::configureSwitchboardRoutableSubnets)
         {
            return;
         }

         String payload = {};
         uint8_t *args = message->args;
         Message::extractToStringView(args, payload);
         Vector<DistributableExternalSubnet> decoded = {};
         if (BitseryEngine::deserializeSafe(payload, decoded)
            && decoded.size() == 1
            && decoded[0].uuid == subnet.uuid
            && decoded[0].subnet.cidr == 64)
         {
            sawRoutableSubnets = true;
         }
      });

      suite.expect(sawRoutableSubnets, "send_switchboard_routable_subnets_serializes_to_active_neuron");
      suite.expect(inactive.neuron.wBuffer.size() == 0, "send_switchboard_routable_subnets_skips_inactive_neuron");
   }

   {
      TestBrain brain = {};
      NoopBrainIaaS iaas = {};
      brain.iaas = &iaas;

      Machine active = {};
      active.uuid = uint128_t(0x9201);
      active.neuron.isFixedFile = true;
      active.neuron.fslot = 13;
      active.neuron.connected = true;

      Machine inactive = {};
      inactive.uuid = uint128_t(0x9202);
      inactive.neuron.isFixedFile = true;
      inactive.neuron.fslot = 14;
      inactive.neuron.connected = false;

      brain.machines.insert(&active);
      brain.machines.insert(&inactive);

      RegisteredRoutableAddress hosted = {};
      hosted.uuid = uint128_t(0xB001);
      hosted.name.assign("hosted-route"_ctv);
      hosted.kind = RoutableAddressKind::testFakeAddress;
      hosted.family = ExternalAddressFamily::ipv6;
      hosted.machineUUID = active.uuid;
      hosted.address = IPAddress("2602:fac0:0:12ab:34cd::77", true);
      brain.brainConfig.routableAddresses.push_back(hosted);

      RegisteredRoutableAddress duplicate = hosted;
      duplicate.uuid = uint128_t(0xB002);
      brain.brainConfig.routableAddresses.push_back(duplicate);

      RegisteredRoutableAddress foreign = hosted;
      foreign.uuid = uint128_t(0xB003);
      foreign.machineUUID = inactive.uuid;
      foreign.address = IPAddress("2602:fac0:0:12ab:34cd::99", true);
      brain.brainConfig.routableAddresses.push_back(foreign);

      RegisteredRoutableAddress empty = hosted;
      empty.uuid = uint128_t(0xB004);
      empty.address = {};
      brain.brainConfig.routableAddresses.push_back(empty);

      Vector<IPPrefix> prefixes = {};
      brain.testBuildHostedSwitchboardIngressPrefixes(&active, prefixes);
      suite.expect(prefixes.size() == 1, "build_hosted_switchboard_ingress_prefixes_dedupes");
      if (prefixes.size() == 1)
      {
         suite.expect(prefixes[0].cidr == 128, "build_hosted_switchboard_ingress_prefixes_uses_host_prefix");
         suite.expect(prefixes[0].containsAddress(hosted.address), "build_hosted_switchboard_ingress_prefixes_matches_registered_address");
      }

      brain.testBuildHostedSwitchboardIngressPrefixes(nullptr, prefixes);
      suite.expect(prefixes.empty(), "build_hosted_switchboard_ingress_prefixes_null_machine_clears_output");

      brain.testSendNeuronSwitchboardHostedIngressPrefixes();

      bool sawHostedPrefixes = false;
      forEachMessageInBuffer(active.neuron.wBuffer, [&] (Message *message) {
         if (NeuronTopic(message->topic) != NeuronTopic::configureSwitchboardHostedIngressPrefixes)
         {
            return;
         }

         String payload = {};
         uint8_t *args = message->args;
         Message::extractToStringView(args, payload);
         Vector<IPPrefix> decoded = {};
         if (BitseryEngine::deserializeSafe(payload, decoded)
            && decoded.size() == 1
            && decoded[0].cidr == 128
            && decoded[0].containsAddress(hosted.address))
         {
            sawHostedPrefixes = true;
         }
      });

      suite.expect(sawHostedPrefixes, "send_switchboard_hosted_ingress_prefixes_serializes_to_active_neuron");
      suite.expect(inactive.neuron.wBuffer.size() == 0, "send_switchboard_hosted_ingress_prefixes_skips_inactive_neuron");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      Machine owner = {};
      owner.uuid = uint128_t(0x9251);

      Machine target = {};
      target.uuid = uint128_t(0x9252);

      ContainerView container = {};
      container.machine = &target;

      Whitehole valid = {};
      valid.hasAddress = true;
      valid.address = IPAddress("203.0.113.77", false);
      valid.sourcePort = 55123;
      valid.bindingNonce = 99;

      suite.expect(brain.testWhiteholeTargetsNeuronMachine(&container, &target, valid), "whitehole_targets_neuron_machine_accepts_container_machine");
      suite.expect(brain.testWhiteholeTargetsNeuronMachine(&container, &owner, valid) == false, "whitehole_targets_neuron_machine_rejects_other_machine");
      suite.expect(brain.testWhiteholeTargetsNeuronMachine(nullptr, &target, valid) == false, "whitehole_targets_neuron_machine_rejects_null_container");
      suite.expect(brain.testWhiteholeTargetsNeuronMachine(&container, nullptr, valid) == false, "whitehole_targets_neuron_machine_rejects_null_target");

      Whitehole missingAddress = valid;
      missingAddress.hasAddress = false;
      Whitehole nullAddress = valid;
      nullAddress.address = {};
      Whitehole zeroPort = valid;
      zeroPort.sourcePort = 0;
      Whitehole zeroNonce = valid;
      zeroNonce.bindingNonce = 0;

      Vector<Whitehole> sourceWhiteholes = {};
      sourceWhiteholes.push_back(missingAddress);
      sourceWhiteholes.push_back(nullAddress);
      sourceWhiteholes.push_back(zeroPort);
      sourceWhiteholes.push_back(zeroNonce);
      sourceWhiteholes.push_back(valid);
      Vector<Whitehole> collected = {};
      brain.testCollectWhiteholesForNeuronMachine(&container, &target, sourceWhiteholes, collected);
      suite.expect(collected.size() == 1, "collect_whiteholes_for_neuron_machine_filters_invalid_entries");
      if (collected.size() == 1)
      {
         suite.expect(collected[0].address.equals(valid.address), "collect_whiteholes_for_neuron_machine_keeps_valid_address");
         suite.expect(collected[0].sourcePort == valid.sourcePort, "collect_whiteholes_for_neuron_machine_keeps_valid_port");
         suite.expect(collected[0].bindingNonce == valid.bindingNonce, "collect_whiteholes_for_neuron_machine_keeps_valid_nonce");
      }

      brain.testCollectWhiteholesForNeuronMachine(nullptr, &target, sourceWhiteholes, collected);
      suite.expect(collected.empty(), "collect_whiteholes_for_neuron_machine_null_container_clears_output");
   }

   {
      TestBrain brain = {};
      NoopBrainIaaS iaas = {};
      brain.iaas = &iaas;

      Machine active = {};
      active.uuid = uint128_t(0x9301);
      active.neuron.isFixedFile = true;
      active.neuron.fslot = 15;
      active.neuron.connected = true;

      Machine inactive = {};
      inactive.uuid = uint128_t(0x9302);
      inactive.neuron.isFixedFile = true;
      inactive.neuron.fslot = 16;
      inactive.neuron.connected = false;

      brain.machines.insert(&active);
      brain.machines.insert(&inactive);
      brain.brainConfig.runtimeEnvironment.test.enabled = true;

      brain.testSendNeuronRuntimeEnvironmentConfig();

      bool sawRuntimeEnvironment = false;
      forEachMessageInBuffer(active.neuron.wBuffer, [&] (Message *message) {
         if (NeuronTopic(message->topic) != NeuronTopic::configureRuntimeEnvironment)
         {
            return;
         }

         String payload = {};
         uint8_t *args = message->args;
         Message::extractToStringView(args, payload);
         ProdigyRuntimeEnvironmentConfig decoded = {};
         if (BitseryEngine::deserializeSafe(payload, decoded) && decoded.test.enabled)
         {
            sawRuntimeEnvironment = true;
         }
      });

      suite.expect(sawRuntimeEnvironment, "send_runtime_environment_config_serializes_to_active_neuron");
      suite.expect(inactive.neuron.wBuffer.size() == 0, "send_runtime_environment_config_skips_inactive_neuron");
   }

   {
      TestBrain brain = {};
      NoopBrainIaaS iaas = {};
      brain.iaas = &iaas;

      DistributableExternalSubnet pinned = {};
      pinned.uuid = uint128_t(0xC001);
      pinned.name.assign("overlay-subnet"_ctv);
      pinned.subnet.network = IPAddress("2001:db8:200::", true);
      pinned.subnet.cidr = 64;
      pinned.routing = ExternalSubnetRouting::switchboardPinnedRoute;
      brain.brainConfig.distributableExternalSubnets.push_back(pinned);

      DistributableExternalSubnet bgp = pinned;
      bgp.uuid = uint128_t(0xC002);
      bgp.routing = ExternalSubnetRouting::switchboardBGP;
      bgp.subnet.network = IPAddress("2001:db8:201::", true);
      brain.brainConfig.distributableExternalSubnets.push_back(bgp);

      SwitchboardOverlayRoutingConfig nullConfig = {};
      suite.expect(brain.testBuildSwitchboardOverlayRoutingConfig(nullptr, nullConfig), "build_overlay_routing_config_accepts_null_machine");
      suite.expect(nullConfig.containerNetworkViaOverlay, "build_overlay_routing_config_enables_container_overlay_without_bgp");
      suite.expect(nullConfig.overlaySubnets.size() == 1, "build_overlay_routing_config_keeps_only_pinned_subnets");

      iaas.bgpEnabled = true;
      SwitchboardOverlayRoutingConfig bgpConfig = {};
      suite.expect(brain.testBuildSwitchboardOverlayRoutingConfig(nullptr, bgpConfig), "build_overlay_routing_config_accepts_null_machine_with_bgp");
      suite.expect(bgpConfig.containerNetworkViaOverlay, "build_overlay_routing_config_keeps_container_overlay_enabled_when_bgp_enabled");
      iaas.bgpEnabled = false;

      Machine local = {};
      local.uuid = uint128_t(0x9401);
      local.fragment = 0x11;
      local.neuron.isFixedFile = true;
      local.neuron.fslot = 17;
      local.neuron.connected = true;
      ClusterMachinePeerAddress localPrivate = {};
      localPrivate.address.assign("fd00:10::10"_ctv);
      localPrivate.cidr = 64;
      local.peerAddresses.push_back(localPrivate);
      ClusterMachinePeerAddress localPublic = {};
      localPublic.address.assign("2001:db8:10::10"_ctv);
      localPublic.cidr = 64;
      local.peerAddresses.push_back(localPublic);
      local.hardware.inventoryComplete = true;
      local.hardware.cpu.logicalCores = 4;
      local.hardware.memory.totalMB = 4096;
      local.hardware.network.nics.push_back(makeNic("bond0", "5e:b7:78:2a:48:7b", "fd00:10::10/64"));

      Machine remote = {};
      remote.uuid = uint128_t(0x9402);
      remote.fragment = 0x22;
      remote.neuron.isFixedFile = true;
      remote.neuron.fslot = 18;
      remote.neuron.connected = false;
      ClusterMachinePeerAddress invalidRemote = {};
      invalidRemote.address.assign("not-an-ip"_ctv);
      remote.peerAddresses.push_back(invalidRemote);
      ClusterMachinePeerAddress remotePrivate = {};
      remotePrivate.address.assign("fd00:10::20"_ctv);
      remotePrivate.cidr = 64;
      remote.peerAddresses.push_back(remotePrivate);
      remote.hardware.inventoryComplete = true;
      remote.hardware.cpu.logicalCores = 4;
      remote.hardware.memory.totalMB = 4096;
      remote.hardware.network.nics.push_back(makeNic("bond0", "fa:6d:18:7d:9f:5e", "fd00:10::20/64"));

      brain.machines.insert(&local);
      brain.machines.insert(&remote);

      RegisteredRoutableAddress hostedIngress = {};
      hostedIngress.uuid = uint128_t(0x9901);
      hostedIngress.name.assign("nametag"_ctv);
      hostedIngress.kind = RoutableAddressKind::testFakeAddress;
      hostedIngress.family = ExternalAddressFamily::ipv6;
      hostedIngress.machineUUID = remote.uuid;
      hostedIngress.address = IPAddress("2001:db8:100::c", true);
      brain.brainConfig.routableAddresses.push_back(hostedIngress);

      SwitchboardOverlayRoutingConfig config = {};
      suite.expect(brain.testBuildSwitchboardOverlayRoutingConfig(&local, config), "build_overlay_routing_config_builds_routes");
      suite.expect(config.containerNetworkViaOverlay, "build_overlay_routing_config_machine_enables_container_overlay");
      suite.expect(config.overlaySubnets.size() == 1, "build_overlay_routing_config_machine_keeps_single_pinned_subnet");
      suite.expect(config.machineRoutes.size() == 1, "build_overlay_routing_config_machine_adds_remote_route");
      suite.expect(config.hostedIngressRoutes.size() == 1, "build_overlay_routing_config_machine_adds_remote_hosted_ingress_route");
      if (config.machineRoutes.size() == 1)
      {
         suite.expect(config.machineRoutes[0].machineFragment == remote.fragment, "build_overlay_routing_config_machine_route_fragment");
         suite.expect(config.machineRoutes[0].nextHop.equals(IPAddress("fd00:10::20", true)), "build_overlay_routing_config_machine_route_next_hop");
         suite.expect(config.machineRoutes[0].sourceAddress.equals(IPAddress("fd00:10::10", true)), "build_overlay_routing_config_machine_route_source");
         suite.expect(config.machineRoutes[0].useGatewayMAC == false, "build_overlay_routing_config_machine_route_prefers_direct_mac");
         suite.expect(config.machineRoutes[0].nextHopMAC == "fa:6d:18:7d:9f:5e"_ctv, "build_overlay_routing_config_machine_route_uses_remote_nic_mac");
      }
      if (config.hostedIngressRoutes.size() == 1)
      {
         suite.expect(config.hostedIngressRoutes[0].machineFragment == remote.fragment, "build_overlay_routing_config_machine_hosted_ingress_fragment");
         suite.expect(config.hostedIngressRoutes[0].prefix.equals(IPPrefix("2001:db8:100::c", true, 128)), "build_overlay_routing_config_machine_hosted_ingress_prefix");
      }

      brain.testSendNeuronSwitchboardOverlayRoutes();

      bool sawOverlayConfig = false;
      forEachMessageInBuffer(local.neuron.wBuffer, [&] (Message *message) {
         if (NeuronTopic(message->topic) != NeuronTopic::configureSwitchboardOverlayRoutes)
         {
            return;
         }

         String payload = {};
         uint8_t *args = message->args;
         Message::extractToStringView(args, payload);
         SwitchboardOverlayRoutingConfig decoded = {};
         if (BitseryEngine::deserializeSafe(payload, decoded)
            && decoded.containerNetworkViaOverlay
            && decoded.overlaySubnets.size() == 1
            && decoded.machineRoutes.size() == 1
            && decoded.machineRoutes[0].machineFragment == remote.fragment
            && decoded.hostedIngressRoutes.size() == 1
            && decoded.hostedIngressRoutes[0].machineFragment == remote.fragment)
         {
            sawOverlayConfig = true;
         }
      });

      suite.expect(sawOverlayConfig, "send_switchboard_overlay_routes_serializes_to_active_neuron");
      suite.expect(remote.neuron.wBuffer.size() == 0, "send_switchboard_overlay_routes_skips_inactive_neuron");
   }

   {
      TestBrain brain = {};
      NoopBrainIaaS iaas = {};
      brain.iaas = &iaas;

      Machine local = {};
      local.uuid = uint128_t(0x9441);
      local.fragment = 0x41;
      ClusterMachinePeerAddress localPrivate4 = {};
      localPrivate4.address.assign("10.0.0.10"_ctv);
      localPrivate4.cidr = 24;
      local.peerAddresses.push_back(localPrivate4);
      ClusterMachinePeerAddress localPrivate6 = {};
      localPrivate6.address.assign("fd00:10::10"_ctv);
      localPrivate6.cidr = 64;
      local.peerAddresses.push_back(localPrivate6);
      local.hardware.inventoryComplete = true;
      local.hardware.cpu.logicalCores = 4;
      local.hardware.memory.totalMB = 4096;
      local.hardware.network.nics.push_back(makeNic("bond0", "5e:b7:78:2a:48:7b", "fd00:10::10/64"));

      Machine remote = {};
      remote.uuid = uint128_t(0x9442);
      remote.fragment = 0x42;
      ClusterMachinePeerAddress remotePrivate4 = {};
      remotePrivate4.address.assign("10.0.0.20"_ctv);
      remotePrivate4.cidr = 24;
      remote.peerAddresses.push_back(remotePrivate4);
      ClusterMachinePeerAddress remotePrivate6 = {};
      remotePrivate6.address.assign("fd00:10::20"_ctv);
      remotePrivate6.cidr = 64;
      remote.peerAddresses.push_back(remotePrivate6);
      remote.hardware.inventoryComplete = true;
      remote.hardware.cpu.logicalCores = 4;
      remote.hardware.memory.totalMB = 4096;
      remote.hardware.network.nics.push_back(makeNic("bond0", "fa:6d:18:7d:9f:5e", "fd00:10::20/64"));

      brain.machines.insert(&local);
      brain.machines.insert(&remote);

      SwitchboardOverlayRoutingConfig config = {};
      suite.expect(brain.testBuildSwitchboardOverlayRoutingConfig(&local, config), "build_overlay_routing_config_dual_stack_accepts_machine");
      suite.expect(config.machineRoutes.size() == 1, "build_overlay_routing_config_dual_stack_builds_single_route");
      if (config.machineRoutes.size() == 1)
      {
         suite.expect(config.machineRoutes[0].nextHop.equals(IPAddress("fd00:10::20", true)), "build_overlay_routing_config_dual_stack_prefers_private6_next_hop");
         suite.expect(config.machineRoutes[0].sourceAddress.equals(IPAddress("fd00:10::10", true)), "build_overlay_routing_config_dual_stack_prefers_private6_source");
         suite.expect(config.machineRoutes[0].useGatewayMAC == false, "build_overlay_routing_config_dual_stack_prefers_direct_mac");
      }
   }

   {
      TestBrain brain = {};
      NoopBrainIaaS iaas = {};
      brain.iaas = &iaas;

      Machine local = {};
      local.uuid = uint128_t(0x9451);
      local.fragment = 0x31;
      ClusterMachinePeerAddress localPrivate = {};
      localPrivate.address.assign("fd00:20::10"_ctv);
      localPrivate.cidr = 64;
      local.peerAddresses.push_back(localPrivate);
      local.hardware.inventoryComplete = true;
      local.hardware.cpu.logicalCores = 4;
      local.hardware.memory.totalMB = 4096;
      local.hardware.network.nics.push_back(makeNic("bond0", "5e:b7:78:2a:48:7b", "fd00:20::10/64"));

      Machine parseFailRemote = {};
      parseFailRemote.uuid = uint128_t(0x9452);
      parseFailRemote.fragment = 0x32;
      ClusterMachinePeerAddress invalidRemote = {};
      invalidRemote.address.assign("not-an-ip"_ctv);
      parseFailRemote.peerAddresses.push_back(invalidRemote);

      Machine sourceMismatchRemote = {};
      sourceMismatchRemote.uuid = uint128_t(0x9453);
      sourceMismatchRemote.fragment = 0x33;
      ClusterMachinePeerAddress ipv4Remote = {};
      ipv4Remote.address.assign("10.20.0.20"_ctv);
      ipv4Remote.cidr = 24;
      sourceMismatchRemote.peerAddresses.push_back(ipv4Remote);

      brain.machines.insert(&local);
      brain.machines.insert(&parseFailRemote);
      brain.machines.insert(&sourceMismatchRemote);

      SwitchboardOverlayRoutingConfig config = {};
      suite.expect(brain.testBuildSwitchboardOverlayRoutingConfig(&local, config), "build_overlay_routing_config_tolerates_unroutable_peers");
      suite.expect(config.machineRoutes.empty(), "build_overlay_routing_config_skips_parse_and_source_failures");
   }

   {
      TestBrain brain = {};
      NoopBrainIaaS iaas = {};
      brain.iaas = &iaas;

      Machine local = {};
      local.uuid = uint128_t(0x9461);
      local.fragment = 0x51;
      ClusterMachinePeerAddress localPrivate = {};
      localPrivate.address.assign("fd00:30::10"_ctv);
      localPrivate.cidr = 64;
      local.peerAddresses.push_back(localPrivate);
      local.hardware.inventoryComplete = true;
      local.hardware.cpu.logicalCores = 4;
      local.hardware.memory.totalMB = 4096;
      local.hardware.network.nics.push_back(makeNic("bond0", "5e:b7:78:2a:48:7b", "fd00:30::10/64"));

      Machine remote = {};
      remote.uuid = uint128_t(0x9462);
      remote.fragment = 0x52;
      ClusterMachinePeerAddress remotePeer = {};
      remotePeer.address.assign("fd00:40::20"_ctv);
      remotePeer.cidr = 64;
      remotePeer.gateway.assign("fd00:30::1"_ctv);
      remote.peerAddresses.push_back(remotePeer);
      remote.hardware.inventoryComplete = true;
      remote.hardware.cpu.logicalCores = 4;
      remote.hardware.memory.totalMB = 4096;
      remote.hardware.network.nics.push_back(makeNic("bond0", "fa:6d:18:7d:9f:5e", "fd00:40::20/64"));

      brain.machines.insert(&local);
      brain.machines.insert(&remote);

      SwitchboardOverlayRoutingConfig config = {};
      suite.expect(brain.testBuildSwitchboardOverlayRoutingConfig(&local, config), "build_overlay_routing_config_accepts_gateway_peer");
      suite.expect(config.machineRoutes.size() == 1, "build_overlay_routing_config_builds_gateway_peer_route");
      if (config.machineRoutes.size() == 1)
      {
         suite.expect(config.machineRoutes[0].nextHop.equals(IPAddress("fd00:30::1", true)), "build_overlay_routing_config_uses_gateway_next_hop");
         suite.expect(config.machineRoutes[0].useGatewayMAC, "build_overlay_routing_config_marks_gateway_mac_route");
         suite.expect(config.machineRoutes[0].nextHopMAC.size() == 0, "build_overlay_routing_config_keeps_gateway_mac_route_unbound");
      }
   }

   thisNeuron = nullptr;

   if (createdRing)
   {
      Ring::shutdownForExec();
   }

   if (suite.failed != 0)
   {
      basics_log("prodigy_brain_ipv6_topology_unit failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("prodigy_brain_ipv6_topology_unit ok\n");
   return EXIT_SUCCESS;
}
