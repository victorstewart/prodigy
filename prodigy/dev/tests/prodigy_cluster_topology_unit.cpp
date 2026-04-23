#include <networking/includes.h>
#include <services/debug.h>
#include <services/prodigy.h>
#include <prodigy/brain/base.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/routable.address.helpers.h>
#include <prodigy/types.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      std::fprintf(stderr, "%s: %s\n", condition ? "PASS" : "FAIL", name);
      if (condition == false)
      {
         failed += 1;
      }
   }
};

class TestBrainBase final : public BrainBase
{
public:

   bool allowNeuronControl = false;
   bool armMachineNeuronControlCalled = false;

   void respinApplication(ApplicationDeployment *deployment) override
   {
      (void)deployment;
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

   void spinApplicationFin(ApplicationDeployment *deployment) override
   {
      (void)deployment;
   }

   void requestMachines(MachineTicket *ticket, ApplicationDeployment *deployment, ApplicationLifetime lifetime, uint32_t nMore) override
   {
      (void)ticket;
      (void)deployment;
      (void)lifetime;
      (void)nMore;
   }

   bool canControlNeurons(void) const override
   {
      return allowNeuronControl;
   }

protected:

   void armMachineNeuronControl(Machine *machine) override
   {
      (void)machine;
      armMachineNeuronControlCalled = true;
   }
};

class TestNeuronBase final : public NeuronBase
{
public:

   void pushContainer(Container *container) override
   {
      (void)container;
   }

   void popContainer(Container *container) override
   {
      (void)container;
   }

   bool ensureHostNetworkingReady(String *failureReport = nullptr) override
   {
      if (failureReport)
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

class TestReconnector final : public Reconnector
{
};

int main(void)
{
   TestSuite suite;

   auto appendPrivateAddress = [] (ClusterMachine& machine, const char *address, uint8_t cidr = 0, const char *gateway = "") -> void {
      String literal = {};
      literal.assign(address);
      String gatewayText = {};
      gatewayText.assign(gateway);
      prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, literal, cidr, gatewayText);
   };

   auto appendPublicAddress = [] (ClusterMachine& machine, const char *address, uint8_t cidr = 0, const char *gateway = "") -> void {
      String literal = {};
      literal.assign(address);
      String gatewayText = {};
      gatewayText.assign(gateway);
      prodigyAppendUniqueClusterMachineAddress(machine.addresses.publicAddresses, literal, cidr, gatewayText);
   };

   auto appendPeerCandidate = [] (ClusterMachine& machine, const char *address, uint8_t cidr) -> void {
      ClusterMachinePeerAddress candidate = {};
      candidate.address.assign(address);
      candidate.cidr = cidr;
      if (prodigyClusterMachinePeerAddressIsPrivate(candidate))
      {
         prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, candidate.address, cidr);
      }
      else
      {
         prodigyAppendUniqueClusterMachineAddress(machine.addresses.publicAddresses, candidate.address, cidr);
      }
   };

   auto makeSubnet = [] (const char *cidr) -> DistributableExternalSubnet {

      const char *slash = std::strrchr(cidr, '/');
      if (slash == nullptr)
      {
         std::fprintf(stderr, "unable to parse cidr: %s\n", cidr);
         std::abort();
      }

      DistributableExternalSubnet subnet = {};
      String addressText = {};
      addressText.assign(cidr, uint64_t(slash - cidr));
      if (ClusterMachine::parseIPAddressLiteral(addressText, subnet.subnet.network) == false)
      {
         std::fprintf(stderr, "unable to parse subnet address: %s\n", cidr);
         std::abort();
      }

      subnet.subnet.cidr = uint8_t(std::strtoul(slash + 1, nullptr, 10));
      subnet.subnet.canonicalize();
      return subnet;
   };

   ClusterTopology topology = {};
   topology.version = 7;

   ClusterMachine adopted = {};
   adopted.source = ClusterMachineSource::adopted;
   adopted.backing = ClusterMachineBacking::cloud;
   adopted.kind = MachineConfig::MachineKind::bareMetal;
   adopted.lifetime = MachineLifetime::owned;
   adopted.isBrain = true;
   adopted.cloud.schema = "vm-brain"_ctv;
   adopted.cloud.providerMachineType = "vm-brain"_ctv;
   adopted.cloud.cloudID = "789654123000123"_ctv;
   adopted.ssh.address = "10.0.0.10"_ctv;
   adopted.ssh.user = "root"_ctv;
   adopted.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   appendPrivateAddress(adopted, "10.0.0.10", 24, "10.0.0.1");
   adopted.uuid = uint128_t(0x1111);
   adopted.totalLogicalCores = 32;
   adopted.totalMemoryMB = 131072;
   adopted.totalStorageMB = 1024000;
   adopted.ownership.mode = ClusterMachineOwnershipMode::percentages;
   adopted.ownership.nLogicalCoresBasisPoints = 5000;
   adopted.ownership.nMemoryBasisPoints = 7500;
   adopted.ownership.nStorageBasisPoints = 2500;
   adopted.ownedLogicalCores = 16;
   adopted.ownedMemoryMB = 65536;
   adopted.ownedStorageMB = 512000;
   topology.machines.push_back(adopted);

   ClusterMachine created = {};
   created.source = ClusterMachineSource::created;
   created.backing = ClusterMachineBacking::cloud;
   created.kind = MachineConfig::MachineKind::vm;
   created.lifetime = MachineLifetime::ondemand;
   created.isBrain = false;
   created.cloud.schema = "vm-worker"_ctv;
   created.cloud.providerMachineType = "c3-standard-8"_ctv;
   created.cloud.cloudID = "789654123000456"_ctv;
   appendPrivateAddress(created, "10.0.0.11", 24, "10.0.0.1");
   created.uuid = uint128_t(0x2222);
   created.totalLogicalCores = 8;
   created.totalMemoryMB = 32768;
   created.totalStorageMB = 204800;
   created.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   created.ownedLogicalCores = 6;
   created.ownedMemoryMB = 28672;
   created.ownedStorageMB = 200704;
   topology.machines.push_back(created);

   String serializedTopology;
   BitseryEngine::serialize(serializedTopology, topology);

   ClusterTopology decodedTopology = {};
   suite.expect(BitseryEngine::deserializeSafe(serializedTopology, decodedTopology), "cluster_topology_deserialize");
   suite.expect(decodedTopology == topology, "cluster_topology_roundtrip");
   suite.expect(clusterTopologyBrainCount(decodedTopology) == 1, "cluster_topology_brain_count");
   suite.expect(clusterTopologyBrainCountSatisfiesQuorum(3), "cluster_topology_quorum_valid");
   suite.expect(clusterTopologyBrainCountSatisfiesQuorum(2) == false, "cluster_topology_quorum_even_invalid");
   suite.expect(clusterTopologyBrainCountSatisfiesQuorum(1) == false, "cluster_topology_quorum_small_invalid");

   suite.expect(routableExternalSubnetHasSupportedBreadth(makeSubnet("0.0.0.0/4")), "routable_subnet_breadth_ipv4_accepts_slash4");
   suite.expect(routableExternalSubnetHasSupportedBreadth(makeSubnet("0.0.0.0/3")) == false, "routable_subnet_breadth_ipv4_rejects_broader_than_slash4");
   suite.expect(routableExternalSubnetHasSupportedBreadth(makeSubnet("203.0.113.0/24")), "routable_subnet_breadth_ipv4_accepts_slash24");
   suite.expect(routableExternalSubnetHasSupportedBreadth(makeSubnet("203.0.113.17/25")) == false, "routable_subnet_breadth_ipv4_rejects_more_specific_than_slash24");
   suite.expect(routableExternalSubnetHasSupportedBreadth(makeSubnet("2000::/4")), "routable_subnet_breadth_ipv6_accepts_slash4");
   suite.expect(routableExternalSubnetHasSupportedBreadth(makeSubnet("2000::/3")) == false, "routable_subnet_breadth_ipv6_rejects_broader_than_slash4");
   suite.expect(routableExternalSubnetHasSupportedBreadth(makeSubnet("2001:db8::/48")), "routable_subnet_breadth_ipv6_accepts_slash48");
   suite.expect(routableExternalSubnetHasSupportedBreadth(makeSubnet("2001:db8::17/49")) == false, "routable_subnet_breadth_ipv6_rejects_more_specific_than_slash48");
   suite.expect(distributableExternalSubnetCanAllocateAddresses(makeSubnet("198.18.0.0/16")), "routable_subnet_ipv4_allocatable_host_bits");
   suite.expect(distributableExternalSubnetCanAllocateAddresses(makeSubnet("198.18.0.0/24")) == false, "routable_subnet_ipv4_rejects_insufficient_host_bits_for_distribution");
   suite.expect(distributableExternalSubnetCanAllocateAddresses(makeSubnet("2001:db8::/88")), "routable_subnet_ipv6_allocatable_host_bits");
   suite.expect(distributableExternalSubnetCanAllocateAddresses(makeSubnet("2001:db8::/96")) == false, "routable_subnet_ipv6_rejects_insufficient_host_bits_for_distribution");
   {
      DistributableExternalSubnet wormholeOnly = makeSubnet("198.18.0.0/16");
      wormholeOnly.usage = ExternalSubnetUsage::wormholes;
      suite.expect(distributableExternalSubnetAllowsWormholes(wormholeOnly), "routable_subnet_usage_wormholes_allows_wormholes");
      suite.expect(distributableExternalSubnetAllowsWhiteholes(wormholeOnly) == false, "routable_subnet_usage_wormholes_rejects_whiteholes");

      DistributableExternalSubnet whiteholeOnly = makeSubnet("198.19.0.0/16");
      whiteholeOnly.usage = ExternalSubnetUsage::whiteholes;
      suite.expect(distributableExternalSubnetAllowsWhiteholes(whiteholeOnly), "routable_subnet_usage_whiteholes_allows_whiteholes");
      suite.expect(distributableExternalSubnetAllowsWormholes(whiteholeOnly) == false, "routable_subnet_usage_whiteholes_rejects_wormholes");

      DistributableExternalSubnet both = makeSubnet("2001:db8::/88");
      both.usage = ExternalSubnetUsage::both;
      suite.expect(distributableExternalSubnetAllowsWormholes(both), "routable_subnet_usage_both_allows_wormholes");
      suite.expect(distributableExternalSubnetAllowsWhiteholes(both), "routable_subnet_usage_both_allows_whiteholes");
      suite.expect(externalSubnetUsageIsValid(both.usage), "routable_subnet_usage_both_valid");
   }

   RoutableAddressKind parsedRoutableAddressKind = RoutableAddressKind::testFakeAddress;
   suite.expect(parseRoutableAddressKind("routeToAny"_ctv, parsedRoutableAddressKind), "routable_address_kind_parse_route_to_any");
   suite.expect(parsedRoutableAddressKind == RoutableAddressKind::anyHostPublicAddress, "routable_address_kind_parse_route_to_any_kind");
   suite.expect(parseRoutableAddressKind("elasticAddress"_ctv, parsedRoutableAddressKind), "routable_address_kind_parse_elastic_address");
   suite.expect(parsedRoutableAddressKind == RoutableAddressKind::providerElasticAddress, "routable_address_kind_parse_elastic_address_kind");

   {
      IPPrefix hostedIPv4Prefix = {};
      suite.expect(makeHostedIngressPrefixForAddress(IPAddress("203.0.113.7", false), hostedIPv4Prefix), "hosted_ingress_prefix_ipv4_generated");
      suite.expect(hostedIPv4Prefix.cidr == 32, "hosted_ingress_prefix_ipv4_exact_cidr");
      suite.expect(hostedIPv4Prefix.network.equals(IPAddress("203.0.113.7", false)), "hosted_ingress_prefix_ipv4_exact_address");
   }

   {
      IPPrefix hostedIPv6Prefix = {};
      suite.expect(makeHostedIngressPrefixForAddress(IPAddress("2001:db8::77", true), hostedIPv6Prefix), "hosted_ingress_prefix_ipv6_generated");
      suite.expect(hostedIPv6Prefix.cidr == 128, "hosted_ingress_prefix_ipv6_exact_cidr");
      suite.expect(hostedIPv6Prefix.network.equals(IPAddress("2001:db8::77", true)), "hosted_ingress_prefix_ipv6_exact_address");
   }

   {
      Vector<RegisteredRoutableAddress> existingAddresses = {};
      RegisteredRoutableAddress occupied = {};
      occupied.address = IPAddress("198.18.0.1", false);
      existingAddresses.push_back(occupied);

      IPPrefix fakePrefix = {};
      fakePrefix.network = IPAddress("198.18.0.0", false);
      fakePrefix.cidr = 29;
      fakePrefix.canonicalize();

      IPAddress allocated = {};
      suite.expect(allocateUniqueRegisteredAddressFromPrefix(fakePrefix, existingAddresses, allocated), "routable_address_allocate_ipv4_from_fake_prefix");
      suite.expect(allocated.equals(IPAddress("198.18.0.2", false)), "routable_address_allocate_ipv4_skips_existing");
      suite.expect(findRegisteredRoutableAddressByConcreteAddress(existingAddresses, occupied.address) == &existingAddresses[0], "routable_address_find_by_concrete_ipv4_address");
   }

   {
      Vector<RegisteredRoutableAddress> existingAddresses = {};
      RegisteredRoutableAddress occupied = {};
      occupied.address = IPAddress("2602:fac0:0:12ab:34cd::1", true);
      existingAddresses.push_back(occupied);

      IPPrefix fakePrefix = {};
      fakePrefix.network = IPAddress("2602:fac0:0:12ab:34cd::", true);
      fakePrefix.cidr = 124;
      fakePrefix.canonicalize();

      IPAddress allocated = {};
      suite.expect(allocateUniqueRegisteredAddressFromPrefix(fakePrefix, existingAddresses, allocated), "routable_address_allocate_ipv6_from_fake_prefix");
      suite.expect(allocated.equals(IPAddress("2602:fac0:0:12ab:34cd::2", true)), "routable_address_allocate_ipv6_skips_existing");
      suite.expect(findRegisteredRoutableAddressByConcreteAddress(existingAddresses, occupied.address) == &existingAddresses[0], "routable_address_find_by_concrete_ipv6_address");
   }

   {
      Vector<RegisteredRoutableAddress> registeredAddresses = {};
      RegisteredRoutableAddress registered = {};
      registered.uuid = uint128_t(0xABCDEF);
      registered.family = ExternalAddressFamily::ipv4;
      registered.machineUUID = uint128_t(0x123456);
      registered.address = IPAddress("203.0.113.45", false);
      registeredAddresses.push_back(registered);

      Wormhole wormhole = {};
      wormhole.source = ExternalAddressSource::registeredRoutableAddress;
      wormhole.routableAddressUUID = registered.uuid;

      String resolveFailure = {};
      suite.expect(resolveWormholeRegisteredRoutableAddress(registeredAddresses, wormhole, &resolveFailure), "wormhole_routable_address_uuid_resolves");
      suite.expect(wormhole.externalAddress.equals(registered.address), "wormhole_routable_address_uuid_sets_external_address");

      Wormhole missing = {};
      missing.source = ExternalAddressSource::registeredRoutableAddress;
      missing.routableAddressUUID = uint128_t(0x1234);
      resolveFailure.clear();
      suite.expect(resolveWormholeRegisteredRoutableAddress(registeredAddresses, missing, &resolveFailure) == false, "wormhole_routable_address_uuid_rejects_missing_registration");
      suite.expect(resolveFailure.size() > 0, "wormhole_routable_address_uuid_missing_registration_failure");

   }

   ClusterMachine adoptedIdentityByUUID = {};
   adoptedIdentityByUUID.uuid = adopted.uuid;
   suite.expect(adopted.sameIdentityAs(adoptedIdentityByUUID), "cluster_machine_identity_uuid_equality");

   ClusterMachine adoptedIdentityByPrivateAddress = {};
   adoptedIdentityByPrivateAddress.addresses.privateAddresses = adopted.addresses.privateAddresses;
   suite.expect(adopted.sameIdentityAs(adoptedIdentityByPrivateAddress), "cluster_machine_identity_private_address_equality");

   ClusterMachine distinctIdentity = {};
   distinctIdentity.cloud.cloudID = "789654123000999"_ctv;
   appendPrivateAddress(distinctIdentity, "10.0.0.99");
   suite.expect(adopted.sameIdentityAs(distinctIdentity) == false, "cluster_machine_identity_distinct");

   {
      ClusterMachine authoritative = {};
      authoritative.source = ClusterMachineSource::created;
      authoritative.backing = ClusterMachineBacking::cloud;
      authoritative.kind = MachineConfig::MachineKind::vm;
      authoritative.lifetime = MachineLifetime::ondemand;
      authoritative.isBrain = true;
      authoritative.cloud.schema = "aws-brain"_ctv;
      authoritative.cloud.providerMachineType = "c7i.large"_ctv;
      authoritative.cloud.cloudID = "i-seed"_ctv;
      authoritative.ssh.address = "44.195.24.29"_ctv;
      authoritative.ssh.port = 22;
      authoritative.ssh.user = "root"_ctv;
      authoritative.ssh.privateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      appendPrivateAddress(authoritative, "172.31.7.37", 20, "172.31.0.1");
      appendPublicAddress(authoritative, "44.195.24.29");
      authoritative.uuid = uint128_t(0x5151);
      authoritative.creationTimeMs = 123456789;
      authoritative.hasInternetAccess = true;
      authoritative.totalLogicalCores = 2;
      authoritative.totalMemoryMB = 4096;
      authoritative.totalStorageMB = 65536;
      authoritative.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
      authoritative.ownedLogicalCores = 2;
      authoritative.ownedMemoryMB = 4096;
      authoritative.ownedStorageMB = 65536;

      ClusterMachine capturedLive = {};
      capturedLive.source = ClusterMachineSource::adopted;
      capturedLive.backing = ClusterMachineBacking::owned;
      capturedLive.kind = MachineConfig::MachineKind::vm;
      capturedLive.lifetime = MachineLifetime::owned;
      capturedLive.isBrain = true;
      appendPrivateAddress(capturedLive, "172.31.7.37", 20, "172.31.0.1");
      appendPublicAddress(capturedLive, "44.195.24.29");
      capturedLive.uuid = authoritative.uuid;

      prodigyBackfillClusterMachineFromAuthoritativeRecord(capturedLive, authoritative);

      suite.expect(capturedLive.source == ClusterMachineSource::created, "cluster_machine_backfill_preserves_created_source");
      suite.expect(capturedLive.backing == ClusterMachineBacking::cloud, "cluster_machine_backfill_preserves_cloud_backing");
      suite.expect(capturedLive.cloudPresent(), "cluster_machine_backfill_restores_cloud_presence");
      suite.expect(capturedLive.cloud.cloudID == "i-seed"_ctv, "cluster_machine_backfill_restores_cloud_id");
      suite.expect(capturedLive.ssh.address == "44.195.24.29"_ctv, "cluster_machine_backfill_restores_ssh_address");
      suite.expect(capturedLive.ssh.user == "root"_ctv, "cluster_machine_backfill_restores_ssh_user");
      suite.expect(capturedLive.ssh.privateKeyPath.equals(prodigyTestBootstrapSeedSSHPrivateKeyPath()), "cluster_machine_backfill_restores_ssh_key");
      suite.expect(capturedLive.lifetime == MachineLifetime::ondemand, "cluster_machine_backfill_restores_lifetime");
      suite.expect(capturedLive.creationTimeMs == 123456789, "cluster_machine_backfill_restores_creation_time");
   }

   {
      ClusterTopology authoritativeTopology = {};
      ClusterMachine authoritative = {};
      authoritative.source = ClusterMachineSource::created;
      authoritative.backing = ClusterMachineBacking::cloud;
      authoritative.kind = MachineConfig::MachineKind::vm;
      authoritative.lifetime = MachineLifetime::ondemand;
      authoritative.isBrain = true;
      authoritative.cloud.schema = "c7i-flex.large"_ctv;
      authoritative.cloud.providerMachineType = "c7i-flex.large"_ctv;
      authoritative.cloud.cloudID = "i-seed"_ctv;
      appendPrivateAddress(authoritative, "172.31.9.251", 20, "172.31.0.1");
      appendPublicAddress(authoritative, "44.201.19.38");
      authoritative.ssh.address = "44.201.19.38"_ctv;
      authoritative.ssh.port = 22;
      authoritative.ssh.user = "root"_ctv;
      authoritative.ssh.privateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      authoritativeTopology.machines.push_back(authoritative);

      Machine sparseLiveMachine = {};
      sparseLiveMachine.private4 = IPAddress("172.31.9.251", false).v4;
      sparseLiveMachine.privateAddress = "172.31.9.251"_ctv;
      sparseLiveMachine.publicAddress = "44.201.19.38"_ctv;
      sparseLiveMachine.isBrain = true;

      const ClusterMachine *matched = prodigyFindAuthoritativeClusterMachineForMachine(authoritativeTopology, sparseLiveMachine);
      suite.expect(matched != nullptr, "cluster_machine_authoritative_match_for_sparse_live_machine_found");
      if (matched != nullptr)
      {
         suite.expect(matched->source == ClusterMachineSource::created, "cluster_machine_authoritative_match_preserves_created_source");
         suite.expect(matched->backing == ClusterMachineBacking::cloud, "cluster_machine_authoritative_match_preserves_cloud_backing");
         suite.expect(matched->cloud.cloudID.equals("i-seed"_ctv), "cluster_machine_authoritative_match_preserves_cloud_id");
      }
   }

   ClusterMachine explicitAddressA = {};
   appendPrivateAddress(explicitAddressA, "fd00:1::10");
   ClusterMachine explicitAddressB = {};
   appendPrivateAddress(explicitAddressB, "fd00:1::11");
   suite.expect(explicitAddressA.sameIdentityAs(explicitAddressB) == false, "cluster_machine_identity_rejects_mismatched_explicit_addresses");

   Machine explicitMachine = {};
   explicitMachine.private4 = IPAddress("10.0.0.10", false).v4;
   explicitMachine.privateAddress = "fd00:1::20"_ctv;
   suite.expect(prodigyClusterMachineMatchesMachineIdentity(explicitAddressA, explicitMachine) == false, "cluster_machine_helper_rejects_machine_private4_override_when_cluster_addresses_differ");

   Machine legacyMachineA = {};
   legacyMachineA.private4 = IPAddress("10.0.0.42", false).v4;
   Machine legacyMachineB = {};
   legacyMachineB.private4 = legacyMachineA.private4;
   suite.expect(prodigyMachinesShareIdentity(legacyMachineA, legacyMachineB), "machine_identity_private4_legacy_fallback");

   Machine explicitMachineA = {};
   explicitMachineA.private4 = legacyMachineA.private4;
   explicitMachineA.peerAddresses.push_back(ClusterMachinePeerAddress{"fd00:1::42"_ctv, 64});
   Machine explicitMachineB = {};
   explicitMachineB.private4 = legacyMachineA.private4;
   explicitMachineB.peerAddresses.push_back(ClusterMachinePeerAddress{"fd00:1::43"_ctv, 64});
   suite.expect(prodigyMachinesShareIdentity(explicitMachineA, explicitMachineB) == false, "machine_identity_rejects_private4_override_when_peer_addresses_differ");

   Machine ipv6PeerMachine = {};
   ipv6PeerMachine.privateAddress = "fd00:2::20"_ctv;
   ipv6PeerMachine.sshAddress = "2001:db8::20"_ctv;
   ipv6PeerMachine.sshPort = 2222;
   suite.expect(prodigyMachineProvisioningReady(ipv6PeerMachine), "machine_provisioning_ready_accepts_ipv6_peer_and_ssh");

   IPAddress resolvedSSHAddress = {};
   uint16_t resolvedSSHPort = 0;
   String resolvedSSHText = {};
   suite.expect(prodigyResolveMachineSSHSocketAddress(ipv6PeerMachine, resolvedSSHAddress, resolvedSSHPort, &resolvedSSHText), "machine_ssh_socket_resolution_accepts_ipv6");
   suite.expect(resolvedSSHAddress.is6, "machine_ssh_socket_resolution_accepts_ipv6_family");
   suite.expect(resolvedSSHPort == 2222, "machine_ssh_socket_resolution_preserves_port");
   suite.expect(resolvedSSHText == "2001:db8::20"_ctv, "machine_ssh_socket_resolution_accepts_ipv6_text");

   {
      TCPSocket listener = {};
      listener.setIPVersion(AF_INET);
      listener.setSaddr(IPAddress("127.0.0.1", false), 0);
      listener.bindThenListen();

      struct sockaddr_in boundAddress = {};
      socklen_t boundAddressLen = sizeof(boundAddress);
      suite.expect(::getsockname(listener.fd, reinterpret_cast<struct sockaddr *>(&boundAddress), &boundAddressLen) == 0, "machine_ssh_accepting_getsockname");

      Machine acceptingSSHMachine = {};
      acceptingSSHMachine.privateAddress = "10.0.0.50"_ctv;
      acceptingSSHMachine.sshAddress = "127.0.0.1"_ctv;
      acceptingSSHMachine.sshPort = ntohs(boundAddress.sin_port);

      suite.expect(prodigyMachineSSHSocketAcceptingConnections(acceptingSSHMachine, 200), "machine_ssh_accepting_connections_when_listener_present");
      suite.expect(prodigyMachineProvisioningReady(acceptingSSHMachine), "machine_provisioning_ready_does_not_require_connectable_listener");
      suite.expect(prodigyMachineProvisioningSSHReady(acceptingSSHMachine, 200), "machine_provisioning_ssh_ready_requires_connectable_listener");

      listener.close();
      listener.fd = -1;

      suite.expect(prodigyMachineSSHSocketAcceptingConnections(acceptingSSHMachine, 50) == false, "machine_ssh_accepting_connections_rejects_missing_listener");
      suite.expect(prodigyMachineProvisioningSSHReady(acceptingSSHMachine, 50) == false, "machine_provisioning_ssh_ready_rejects_missing_listener");
   }

   {
      RingDispatcher dispatcher(false);
      RingDispatcher *previousDispatcher = RingDispatcher::dispatcher;
      RingDispatcher::dispatcher = &dispatcher;

      TestBrainBase brain = {};
      Machine machine = {};
      machine.rackUUID = 1;
      brain.allowNeuronControl = true;

      brain.finishMachineConfig(&machine);
      suite.expect(brain.armMachineNeuronControlCalled, "brain_finish_machine_config_arms_neuron_control_when_allowed");
      suite.expect(machine.neuron.connectTimeoutMs == prodigyBrainControlPlaneConnectTimeoutMs, "brain_finish_machine_config_sets_neuron_connect_timeout_ms");
      suite.expect(machine.neuron.nDefaultAttemptsBudget == prodigyBrainControlPlaneConnectAttempts, "brain_finish_machine_config_sets_neuron_connect_attempt_budget");

      RingDispatcher::dispatcher = previousDispatcher;
   }

   {
      uint32_t baselineWindowMs = BrainBase::machineInitialConnectAttemptTimeMs(0, prodigyBrainControlPlaneConnectTimeoutMs, prodigyBrainControlPlaneConnectAttempts);
      uint32_t recentWindowMs = BrainBase::machineInitialConnectAttemptTimeMs(Time::now<TimeResolution::ms>(), prodigyBrainControlPlaneConnectTimeoutMs, prodigyBrainControlPlaneConnectAttempts);
      uint32_t baselineSoftEscalationMs = BrainBase::machineBootstrapSoftEscalationTimeoutMs(0, prodigyBrainControlPlaneConnectTimeoutMs, prodigyBrainControlPlaneConnectAttempts);
      uint32_t recentSoftEscalationMs = BrainBase::machineBootstrapSoftEscalationTimeoutMs(Time::now<TimeResolution::ms>(), prodigyBrainControlPlaneConnectTimeoutMs, prodigyBrainControlPlaneConnectAttempts);
      suite.expect(baselineWindowMs == 750, "brain_machine_initial_connect_window_baseline");
      suite.expect(recentWindowMs > baselineWindowMs, "brain_machine_initial_connect_window_extends_recent_machine_grace");
      suite.expect(baselineSoftEscalationMs == prodigyBrainControlPlaneSoftEscalationFloorMs, "brain_machine_bootstrap_soft_escalation_baseline");
      suite.expect(recentSoftEscalationMs > baselineSoftEscalationMs, "brain_machine_bootstrap_soft_escalation_extends_recent_machine_grace");
      suite.expect(BrainBase::controlPlaneIgnitionTimeoutMs() == prodigyBrainControlPlaneSoftEscalationFloorMs, "brain_control_plane_ignition_timeout_matches_baseline_window");
   }

   {
      TestReconnector reconnector = {};
      reconnector.connectTimeoutMs = 1000;
      reconnector.nDefaultAttemptsBudget = 1;
      reconnector.attemptForMs(20);

      suite.expect(reconnector.connectAttemptFailed() == false, "reconnector_time_budget_ignores_immediate_refusal_before_deadline");

      std::this_thread::sleep_for(std::chrono::milliseconds(30));

      suite.expect(reconnector.connectAttemptFailed(), "reconnector_time_budget_expires_after_deadline");
      suite.expect(reconnector.reconnectAfterClose == false, "reconnector_time_budget_disarms_after_deadline");
   }

   {
      RingDispatcher dispatcher(false);
      RingDispatcher *previousDispatcher = RingDispatcher::dispatcher;
      RingDispatcher::dispatcher = &dispatcher;
      Ring::createRing(8, 8, 32, 32, -1, -1, 0);
      Machine machine = {};
      machine.neuron.fd = 17;
      suite.expect(BrainBase::neuronControlSocketArmed(&machine) == false, "brain_neuron_control_socket_armed_rejects_dormant_process_fd");
      suite.expect(BrainBase::neuronControlStreamActive(&machine) == false, "brain_neuron_control_stream_active_rejects_dormant_process_fd");

      machine.neuron.fd = -1;
      machine.neuron.isFixedFile = true;
      machine.neuron.fslot = 7;
      suite.expect(BrainBase::neuronControlSocketArmed(&machine), "brain_neuron_control_socket_armed_accepts_fixed_file_socket");
      machine.neuron.connected = false;
      suite.expect(BrainBase::neuronControlStreamActive(&machine) == false, "brain_neuron_control_stream_active_requires_connected_state");

      machine.neuron.connected = true;
      suite.expect(BrainBase::neuronControlStreamActive(&machine), "brain_neuron_control_stream_active_accepts_connected_fixed_file_stream");
      Ring::shutdownForExec();
      RingDispatcher::dispatcher = previousDispatcher;
   }

   {
      TestNeuronBase neuron = {};
      neuron.private4 = IPAddress("10.0.0.10", false);
      neuron.configuredInterContainerMTU = 9000;

      Machine machine = {};
      machine.privateAddress = "10.0.0.22"_ctv;
      machine.peerAddresses.push_back(ClusterMachinePeerAddress{"10.0.0.22"_ctv, 24});
      machine.neuron.setIPVersion(AF_INET);

      prodigyConfigureMachineNeuronEndpoint(machine, &neuron);

      int configuredMaxSegmentSize = 0;
      socklen_t configuredMaxSegmentSizeLen = sizeof(configuredMaxSegmentSize);
      suite.expect(
         machine.neuron.fd >= 0,
         "machine_neuron_endpoint_creates_tcp_socket_for_non_fixed_stream");
      suite.expect(
         ::getsockopt(machine.neuron.fd, SOL_TCP, TCP_MAXSEG, &configuredMaxSegmentSize, &configuredMaxSegmentSizeLen) == 0,
         "machine_neuron_endpoint_reads_applied_tcp_maxseg");
      suite.expect(
         uint32_t(configuredMaxSegmentSize) == prodigyTCPMaxSegmentSizeForMTU(9000u, AF_INET),
         "machine_neuron_endpoint_applies_inter_container_tcp_maxseg");
      machine.neuron.close();
   }

   {
      TestNeuronBase neuron = {};
      neuron.private4 = IPAddress("10.0.0.10", false);
      neuron.configuredInterContainerMTU = 9000;

      Machine machine = {};
      machine.privateAddress = "10.0.0.22"_ctv;
      machine.peerAddresses.push_back(ClusterMachinePeerAddress{"10.0.0.22"_ctv, 24});
      machine.neuron.isFixedFile = true;
      machine.neuron.fslot = 7;

      prodigyConfigureMachineNeuronEndpoint(machine, &neuron);

      suite.expect(machine.neuron.isFixedFile, "machine_neuron_endpoint_preserves_fixed_file_state");
      suite.expect(machine.neuron.fslot == 7, "machine_neuron_endpoint_preserves_fixed_file_slot");
   }

   Machine orderByAddressA = {};
   orderByAddressA.private4 = IPAddress("10.0.0.9", false).v4;
   orderByAddressA.peerAddresses.push_back(ClusterMachinePeerAddress{"fd00:3::b"_ctv, 64});
   Machine orderByAddressB = {};
   orderByAddressB.private4 = IPAddress("10.0.0.1", false).v4;
   orderByAddressB.peerAddresses.push_back(ClusterMachinePeerAddress{"fd00:3::a"_ctv, 64});
   suite.expect(prodigyMachineIdentityComesBefore(orderByAddressB, orderByAddressA), "machine_identity_order_prefers_peer_address_before_private4");

   ClusterTopology orderedTopology = {};
   ClusterMachine orderedSelf = {};
   orderedSelf.isBrain = true;
   orderedSelf.uuid = 0x3001;
   appendPeerCandidate(orderedSelf, "10.2.0.10", 24);
   orderedTopology.machines.push_back(orderedSelf);

   ClusterMachine orderedPeer = {};
   orderedPeer.isBrain = true;
   orderedPeer.uuid = 0x3002;
   appendPeerCandidate(orderedPeer, "198.51.100.29", 24);
   appendPeerCandidate(orderedPeer, "10.1.0.29", 24);
   appendPeerCandidate(orderedPeer, "10.2.0.29", 24);
   orderedTopology.machines.push_back(orderedPeer);

   ClusterMachine orderedPeerSibling = {};
   orderedPeerSibling.isBrain = true;
   orderedPeerSibling.uuid = 0x3003;
   appendPeerCandidate(orderedPeerSibling, "10.2.0.11", 24);
   orderedTopology.machines.push_back(orderedPeerSibling);

   prodigyNormalizeClusterTopologyPeerAddresses(orderedTopology);
   {
      Vector<ClusterMachinePeerAddress> orderedCandidates = {};
      prodigyCollectClusterMachinePeerAddresses(orderedTopology.machines[1], orderedCandidates);
      suite.expect(orderedCandidates.size() == 3, "peer_candidate_ordering_candidate_count");
      suite.expect(orderedCandidates[0].address == "10.2.0.29"_ctv, "peer_candidate_ordering_shared_private_subnet_first");
      suite.expect(orderedCandidates[1].address == "10.1.0.29"_ctv, "peer_candidate_ordering_remaining_private_before_public");
      suite.expect(orderedCandidates[2].address == "198.51.100.29"_ctv, "peer_candidate_ordering_public_last");
   }

   Vector<ClusterMachinePeerAddress> localSourceCandidates = {};
   localSourceCandidates.push_back(ClusterMachinePeerAddress{"fd00:10::31"_ctv, 64});
   localSourceCandidates.push_back(ClusterMachinePeerAddress{"2602:fac0:0:12ab:34cd::31"_ctv, 64});
   localSourceCandidates.push_back(ClusterMachinePeerAddress{"10.0.0.31"_ctv, 24});
   IPAddress resolvedSourceAddress = {};
   String resolvedSourceText = {};
   suite.expect(
      prodigyResolvePreferredLocalSourceAddress(
         localSourceCandidates,
         ClusterMachinePeerAddress{"fd00:10::29"_ctv, 64},
         resolvedSourceAddress,
         &resolvedSourceText),
      "peer_source_selection_private6_resolves");
   suite.expect(resolvedSourceAddress.is6, "peer_source_selection_private6_family");
   suite.expect(resolvedSourceText == "fd00:10::31"_ctv, "peer_source_selection_private6_prefers_matching_private_subnet");
   suite.expect(
      prodigyResolvePreferredLocalSourceAddress(
         localSourceCandidates,
         ClusterMachinePeerAddress{"2602:fac0:0:12ab:34cd::29"_ctv, 64},
         resolvedSourceAddress,
         &resolvedSourceText),
      "peer_source_selection_public6_resolves");
   suite.expect(resolvedSourceAddress.is6, "peer_source_selection_public6_family");
   suite.expect(resolvedSourceText == "2602:fac0:0:12ab:34cd::31"_ctv, "peer_source_selection_public6_prefers_matching_public_subnet");

   MachineConfig adoptedConfig = {};
   adoptedConfig.slug = "vm-brain"_ctv;
   adoptedConfig.nLogicalCores = 32;
   adoptedConfig.nMemoryMB = 131072;
   adoptedConfig.nStorageMB = 1024000;

   ClusterMachine adoptedResolved = adopted;
   suite.expect(clusterMachineApplyOwnedResourcesFromConfig(adoptedResolved, adoptedConfig), "cluster_machine_percentages_resolve");
   suite.expect(adoptedResolved.totalLogicalCores == 32, "cluster_machine_percentages_total_cores");
   suite.expect(adoptedResolved.totalMemoryMB == 131072, "cluster_machine_percentages_total_memory");
   suite.expect(adoptedResolved.totalStorageMB == 1024000, "cluster_machine_percentages_total_storage");
   suite.expect(adoptedResolved.ownedLogicalCores == 16, "cluster_machine_percentages_resolve_cores");
   suite.expect(adoptedResolved.ownedMemoryMB == 98304, "cluster_machine_percentages_resolve_memory");
   suite.expect(adoptedResolved.ownedStorageMB == 256000, "cluster_machine_percentages_resolve_storage");

   ClusterMachine wholeMachineResolved = created;
   suite.expect(clusterMachineApplyOwnedResourcesFromConfig(wholeMachineResolved, MachineConfig {
      .kind = MachineConfig::MachineKind::vm,
      .slug = "vm-worker"_ctv,
      .nLogicalCores = 8,
      .nMemoryMB = 32768,
      .nStorageMB = 204800
   }), "cluster_machine_whole_machine_resolve");
   suite.expect(wholeMachineResolved.totalLogicalCores == 8, "cluster_machine_whole_machine_total_cores");
   suite.expect(wholeMachineResolved.totalMemoryMB == 32768, "cluster_machine_whole_machine_total_memory");
   suite.expect(wholeMachineResolved.totalStorageMB == 204800, "cluster_machine_whole_machine_total_storage");
   suite.expect(wholeMachineResolved.ownedLogicalCores == 6, "cluster_machine_whole_machine_resolve_cores");
   suite.expect(wholeMachineResolved.ownedMemoryMB == 28672, "cluster_machine_whole_machine_resolve_memory");
   suite.expect(wholeMachineResolved.ownedStorageMB == 200704, "cluster_machine_whole_machine_resolve_storage");

   ClusterMachine invalidPercentages = adopted;
   invalidPercentages.ownership.nMemoryBasisPoints = 0;
   suite.expect(clusterMachineApplyOwnedResourcesFromConfig(invalidPercentages, adoptedConfig) == false, "cluster_machine_invalid_percentages_rejected");

   ClusterMachine hardCapsResolved = created;
   hardCapsResolved.ownership.mode = ClusterMachineOwnershipMode::hardCaps;
    hardCapsResolved.ownership.nLogicalCoresCap = 16;
   hardCapsResolved.ownership.nMemoryMBCap = 64000;
   hardCapsResolved.ownership.nStorageMBCap = 250000;
   suite.expect(clusterMachineApplyOwnedResourcesFromConfig(hardCapsResolved, MachineConfig {
      .kind = MachineConfig::MachineKind::vm,
      .slug = "vm-worker"_ctv,
      .nLogicalCores = 8,
      .nMemoryMB = 32768,
      .nStorageMB = 204800
   }), "cluster_machine_hard_caps_resolve");
   suite.expect(hardCapsResolved.ownedLogicalCores == 6, "cluster_machine_hard_caps_resolve_cores");
   suite.expect(hardCapsResolved.ownedMemoryMB == 28672, "cluster_machine_hard_caps_resolve_memory");
   suite.expect(hardCapsResolved.ownedStorageMB == 200704, "cluster_machine_hard_caps_resolve_storage");

   ClusterMachine percentageClampResolved = created;
   percentageClampResolved.ownership.mode = ClusterMachineOwnershipMode::percentages;
   percentageClampResolved.ownership.nLogicalCoresBasisPoints = 10000;
   percentageClampResolved.ownership.nMemoryBasisPoints = 10000;
   percentageClampResolved.ownership.nStorageBasisPoints = 10000;
   suite.expect(clusterMachineApplyOwnedResourcesFromConfig(percentageClampResolved, MachineConfig {
      .kind = MachineConfig::MachineKind::vm,
      .slug = "vm-worker"_ctv,
      .nLogicalCores = 8,
      .nMemoryMB = 32768,
      .nStorageMB = 204800
   }), "cluster_machine_percentages_clamp_resolve");
   suite.expect(percentageClampResolved.ownedLogicalCores == 6, "cluster_machine_percentages_clamp_resolve_cores");
   suite.expect(percentageClampResolved.ownedMemoryMB == 28672, "cluster_machine_percentages_clamp_resolve_memory");
   suite.expect(percentageClampResolved.ownedStorageMB == 200704, "cluster_machine_percentages_clamp_resolve_storage");

   AddMachines payload = {};
   payload.bootstrapSshUser = "root"_ctv;
   payload.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
   payload.remoteProdigyPath = "/root/prodigy"_ctv;
   payload.controlSocketPath = "/run/prodigy/control.sock"_ctv;
   payload.adoptedMachines.push_back(adopted);

   payload.isProgress = true;
   MachineProvisioningProgress progress = {};
   progress.cloud = ClusterMachineCloud{
      .schema = "vm-brain"_ctv,
      .providerMachineType = "c3-standard-8"_ctv,
      .cloudID = "789654123000789"_ctv
   };
   progress.ssh = ClusterMachineSSH{
      .address = "34.82.0.10"_ctv
   };
   prodigyAppendUniqueClusterMachineAddress(progress.addresses.privateAddresses, "10.0.0.20"_ctv, 24, "10.0.0.1"_ctv);
   prodigyAppendUniqueClusterMachineAddress(progress.addresses.publicAddresses, "34.82.0.10"_ctv, 24, "34.82.0.1"_ctv);
   progress.providerName = "ntg-vm-brain-1"_ctv;
   progress.status = "waiting-for-running"_ctv;
   progress.ready = false;
   payload.provisioningProgress.push_back(progress);
   payload.success = true;
   payload.hasTopology = true;
   payload.topology = topology;

   String serializedPayload;
   BitseryEngine::serialize(serializedPayload, payload);

   AddMachines decodedPayload = {};
   suite.expect(BitseryEngine::deserializeSafe(serializedPayload, decodedPayload), "add_machines_deserialize");
   suite.expect(decodedPayload == payload, "add_machines_roundtrip");

   return (suite.failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
