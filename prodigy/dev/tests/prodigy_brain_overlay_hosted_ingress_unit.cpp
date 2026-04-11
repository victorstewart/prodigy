#include <prodigy/prodigy.h>
#include <prodigy/brain/brain.h>
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
         std::fprintf(stderr, "FAIL: %s\n", name);
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
   }
};

static bool containsHostedIngressRoute(const Vector<SwitchboardOverlayHostedIngressRoute>& routes,
   const char *cidr,
   uint32_t machineFragment)
{
   const char *slash = std::strrchr(cidr, '/');
   if (slash == nullptr)
   {
      std::fprintf(stderr, "unable to parse hosted ingress cidr: %s\n", cidr);
      std::abort();
   }

   String addressText = {};
   addressText.assign(cidr, uint64_t(slash - cidr));

   IPPrefix prefix = {};
   if (ClusterMachine::parseIPAddressLiteral(addressText, prefix.network) == false)
   {
      std::fprintf(stderr, "unable to parse hosted ingress address: %s\n", cidr);
      std::abort();
   }

   prefix.cidr = uint8_t(std::strtoul(slash + 1, nullptr, 10));

   for (const SwitchboardOverlayHostedIngressRoute& route : routes)
   {
      if (route.machineFragment == machineFragment && route.prefix.equals(prefix))
      {
         return true;
      }
   }

   return false;
}

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

class NoopBrainIaaS final : public BrainIaaS
{
public:

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
      return false;
   }

   bool resolveLocalBrainPeerAddress(IPAddress& address, String& addressText) const override
   {
      address = {};
      addressText.clear();
      return false;
   }
};

class TestBrain final : public Brain
{
public:

   bool testBuildSwitchboardOverlayRoutingConfig(Machine *machine, SwitchboardOverlayRoutingConfig& config) const
   {
      return buildSwitchboardOverlayRoutingConfig(machine, config);
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
      topology = {};
      return false;
   }

   bool persistAuthoritativeClusterTopology(const ClusterTopology& topology) override
   {
      (void)topology;
      return true;
   }
};

int main(void)
{
   TestSuite suite = {};

   TestBrain brain = {};
   NoopBrainIaaS iaas = {};
   brain.iaas = &iaas;

   Machine local = {};
   local.uuid = uint128_t(0x9441);
   local.fragment = 0x41;
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
   ClusterMachinePeerAddress remotePrivate6 = {};
   remotePrivate6.address.assign("fd00:10::20"_ctv);
   remotePrivate6.cidr = 64;
   remote.peerAddresses.push_back(remotePrivate6);
   ClusterMachinePeerAddress remotePublic6 = {};
   remotePublic6.address.assign("2001:db8:100::e"_ctv);
   remotePublic6.cidr = 64;
   remote.peerAddresses.push_back(remotePublic6);
   remote.publicAddress.assign("2001:db8:100::d"_ctv);
   remote.hardware.inventoryComplete = true;
   remote.hardware.cpu.logicalCores = 4;
   remote.hardware.memory.totalMB = 4096;
   remote.hardware.network.nics.push_back(makeNic("bond0", "fa:6d:18:7d:9f:5e", "fd00:10::20/64"));

   brain.machines.insert(&local);
   brain.machines.insert(&remote);

   RegisteredRoutableAddress localIngress = {};
   localIngress.uuid = uint128_t(0x9901);
   localIngress.name.assign("nametag-local"_ctv);
   localIngress.kind = RoutableAddressKind::testFakeAddress;
   localIngress.family = ExternalAddressFamily::ipv6;
   localIngress.machineUUID = local.uuid;
   localIngress.address = IPAddress("2001:db8:100::b", true);
   brain.brainConfig.routableAddresses.push_back(localIngress);

   RegisteredRoutableAddress remoteIngress = {};
   remoteIngress.uuid = uint128_t(0x9902);
   remoteIngress.name.assign("nametag-remote"_ctv);
   remoteIngress.kind = RoutableAddressKind::testFakeAddress;
   remoteIngress.family = ExternalAddressFamily::ipv6;
   remoteIngress.machineUUID = remote.uuid;
   remoteIngress.address = IPAddress("2001:db8:100::c", true);
   brain.brainConfig.routableAddresses.push_back(remoteIngress);

   SwitchboardOverlayRoutingConfig config = {};
   suite.expect(brain.testBuildSwitchboardOverlayRoutingConfig(&local, config), "build_overlay_routing_config_accepts_machine");
   suite.expect(config.containerNetworkViaOverlay, "build_overlay_routing_config_keeps_container_overlay_enabled");
   suite.expect(config.machineRoutes.size() == 1, "build_overlay_routing_config_builds_peer_machine_route");
   suite.expect(config.hostedIngressRoutes.size() == 3, "build_overlay_routing_config_builds_remote_hosted_ingress_routes");
   if (config.machineRoutes.size() == 1)
   {
      suite.expect(config.machineRoutes[0].machineFragment == remote.fragment, "build_overlay_routing_config_preserves_peer_machine_fragment");
      suite.expect(config.machineRoutes[0].useGatewayMAC == false, "build_overlay_routing_config_direct_peer_route_uses_mac");
      suite.expect(config.machineRoutes[0].nextHopMAC == "fa:6d:18:7d:9f:5e"_ctv, "build_overlay_routing_config_preserves_peer_machine_mac");
   }

   suite.expect(containsHostedIngressRoute(config.hostedIngressRoutes, "2001:db8:100::c/128", remote.fragment),
      "build_overlay_routing_config_hosted_ingress_preserves_registered_routable_prefix");
   suite.expect(containsHostedIngressRoute(config.hostedIngressRoutes, "2001:db8:100::d/128", remote.fragment),
      "build_overlay_routing_config_hosted_ingress_includes_remote_machine_public_address");
   suite.expect(containsHostedIngressRoute(config.hostedIngressRoutes, "2001:db8:100::e/128", remote.fragment),
      "build_overlay_routing_config_hosted_ingress_includes_remote_machine_public_peer_address");

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
