#include <prodigy/prodigy.h>
#include <prodigy/brain/brain.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <unistd.h>

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

static ProdigyNametagQualificationApplicationReceipt makeQualificationReceipt(
    uint128_t clusterUUID, uint64_t deploymentID, uint128_t containerUUID)
{
  ProdigyNametagQualificationApplicationReceipt receipt = {};
  receipt.runUUID = uint128_t(0x9711);
  receipt.row = uint8_t(MothershipNametagQualificationRow::sequentialUserKeyWrites);
  receipt.direction = uint8_t(MothershipNametagQualificationDirection::injection);
  receipt.rowID.assign("sequential-user-key-writes"_ctv);
  receipt.localClusterUUID = clusterUUID;
  receipt.deploymentID = deploymentID;
  receipt.localContainerUUID = containerUUID;
  receipt.startedAtMilliseconds = 1000;
  receipt.deadlineAtMilliseconds = 121000;
  receipt.convergenceDeadlineAtMilliseconds = 91000;
  receipt.observedAtMilliseconds = 2000;
  receipt.canonicalApplicationReceipt.assign("authenticated-app6-probe-observation"_ctv);
  receipt.canonicalDataDigest.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  receipt.hotDigest.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  receipt.coldDigest.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
  receipt.radarDigest.assign("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv);
  receipt.pulseDigest.assign("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"_ctv);
  receipt.truthDigest.assign("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_ctv);
  receipt.conflictWinnerDigest.assign("1111111111111111111111111111111111111111111111111111111111111111"_ctv);
  receipt.conflictWinnerClusterUUID = clusterUUID;
  receipt.perUserIsolation = true;
  receipt.sessionFence = true;
  receipt.truthClaimUniqueness = true;
  receipt.radarMutationAccepted = true;
  receipt.pulseMutationAccepted = true;
  receipt.pass = true;
  return receipt;
}

static MothershipNametagQualificationSiteRequest makeQualificationSiteRequest(
    uint128_t clusterUUID, uint64_t app6DeploymentID, uint64_t probeDeploymentID)
{
  MothershipNametagQualificationSiteRequest request = {};
  request.intent.runUUID = uint128_t(0x9711);
  request.intent.row = MothershipNametagQualificationRow::sequentialUserKeyWrites;
  request.intent.direction = MothershipNametagQualificationDirection::injection;
  request.intent.rowID.assign("sequential-user-key-writes"_ctv);
  request.intent.allMastersOperationUUID = uint128_t(0x9712);
  request.intent.deadlineSeconds = 120;
  request.intent.convergenceSeconds = 90;
  request.intent.startedAtMilliseconds = 1000;
  request.intent.deadlineAtMilliseconds = 121000;
  request.intent.convergenceDeadlineAtMilliseconds = 91000;
  request.intent.probeTargets.push_back({clusterUUID, probeDeploymentID});
  request.intent.probeTargets.push_back({uint128_t(0x9722), uint64_t(0x9722)});
  request.intent.probeTargets.push_back({uint128_t(0x9723), uint64_t(0x9723)});
  request.targetClusterUUID = clusterUUID;
  request.targetApp6DeploymentID = app6DeploymentID;
  request.targetProbeDeploymentID = probeDeploymentID;
  request.action = MothershipNametagQualificationSiteAction::query;
  return request;
}

class NoopBrainIaaS final : public BrainIaaS {
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

  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines, String& failure) override
  {
    (void)coro;
    (void)metro;
    (void)machines;
  }

  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains, String& failure) override
  {
    (void)coro;
    (void)selfUUID;
    (void)brains;
    selfIsBrain = false;
  }

  void hardRebootMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    (void)coro;
    (void)cloudID;
    failure.clear();
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

  void destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    (void)coro;
    (void)cloudID;
    failure.clear();
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

class TestBrain final : public Brain {
public:

  bool testBuildSwitchboardOverlayRoutingConfig(Machine *machine, SwitchboardOverlayRoutingConfig& config) const
  {
    return buildSwitchboardOverlayRoutingConfig(machine, config);
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

class ScopedRing final {
public:

  bool created = false;

  ScopedRing()
  {
    if (Ring::getRingFD() <= 0)
    {
      Ring::createRing(8, 8, 32, 32, -1, -1, 0);
      created = true;
    }
  }

  ~ScopedRing()
  {
    if (created) Ring::shutdownForExec();
  }
};

static bool installQualificationNeuronSocket(TestBrain& brain, Machine& machine, int& peerFD)
{
  int sockets[2] = {-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
  RingDispatcher::installMultiplexee(&machine.neuron, &brain);
  machine.neuron.fd = sockets[0];
  Ring::installFDIntoFixedFileSlot(&machine.neuron);
  peerFD = sockets[1];
  return true;
}

static uint32_t countQualificationCommandFrames(const String& buffer)
{
  uint32_t count = 0;
  uint8_t *cursor = const_cast<uint8_t *>(buffer.data());
  uint8_t *end = cursor + buffer.size();
  while (cursor < end)
  {
    Message *message = reinterpret_cast<Message *>(cursor);
    if (NeuronTopic(message->topic) == NeuronTopic::nametagQualificationApplicationCommand) count += 1;
    cursor = message->terminal();
  }
  return cursor == end ? count : UINT32_MAX;
}

int main(void)
{
  TestSuite suite = {};

  TestBrain brain = {};
  brain.brainConfig.datacenterFragment = 1;
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
  ClusterMachinePeerAddress recoveredContainer6 = {};
  recoveredContainer6.address.assign("fdf8:d94c:7c33:e26e:ca4b:f501:0:a00"_ctv);
  recoveredContainer6.cidr = 120;
  remote.peerAddresses.push_back(recoveredContainer6);
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

  DistributableExternalSubnet localIngress = {};
  localIngress.uuid = uint128_t(0x9901);
  localIngress.name.assign("nametag-local"_ctv);
  localIngress.machineUUID = local.uuid;
  localIngress.ingressScope = RoutableIngressScope::singleMachine;
  localIngress.usage = ExternalSubnetUsage::wormholes;
  localIngress.subnet = IPPrefix("2001:db8:100::b", true, 128);
  brain.brainConfig.distributableExternalSubnets.push_back(localIngress);

  DistributableExternalSubnet remoteIngress = {};
  remoteIngress.uuid = uint128_t(0x9902);
  remoteIngress.name.assign("nametag-remote"_ctv);
  remoteIngress.machineUUID = remote.uuid;
  remoteIngress.ingressScope = RoutableIngressScope::singleMachine;
  remoteIngress.usage = ExternalSubnetUsage::wormholes;
  remoteIngress.subnet = IPPrefix("2001:db8:100::c", true, 128);
  brain.brainConfig.distributableExternalSubnets.push_back(remoteIngress);

  SwitchboardOverlayRoutingConfig config = {};
  suite.expect(brain.testBuildSwitchboardOverlayRoutingConfig(&local, config), "build_overlay_routing_config_accepts_machine");
  suite.expect(config.containerNetworkViaOverlay, "build_overlay_routing_config_keeps_container_overlay_enabled");
  suite.expect(config.machineRoutes.size() == 1, "build_overlay_routing_config_builds_peer_machine_route");
  suite.expect(config.hostedIngressRoutes.size() == 3, "build_overlay_routing_config_builds_remote_hosted_ingress_routes");
  if (config.machineRoutes.size() == 1)
  {
    suite.expect(config.machineRoutes[0].machineFragment == switchboardMakeOverlayMachineIdentity(1, remote.fragment), "build_overlay_routing_config_projects_peer_machine_identity");
    suite.expect(config.machineRoutes[0].useGatewayMAC == false, "build_overlay_routing_config_direct_peer_route_uses_mac");
    suite.expect(config.machineRoutes[0].nextHopMAC == "fa:6d:18:7d:9f:5e"_ctv, "build_overlay_routing_config_preserves_peer_machine_mac");
    suite.expect(config.machineRoutes[0].nextHop.equals(IPAddress("fd00:10::20", true)), "build_overlay_routing_config_prefers_direct_underlay_after_recovery");
    suite.expect(config.machineRoutes[0].sourceAddress.equals(IPAddress("fd00:10::10", true)), "build_overlay_routing_config_preserves_direct_underlay_source_after_recovery");
  }

  suite.expect(containsHostedIngressRoute(config.hostedIngressRoutes, "2001:db8:100::c/128", switchboardMakeOverlayMachineIdentity(1, remote.fragment)),
               "build_overlay_routing_config_hosted_ingress_preserves_registered_routable_prefix");
  suite.expect(containsHostedIngressRoute(config.hostedIngressRoutes, "2001:db8:100::d/128", switchboardMakeOverlayMachineIdentity(1, remote.fragment)),
               "build_overlay_routing_config_hosted_ingress_includes_remote_machine_public_address");
  suite.expect(containsHostedIngressRoute(config.hostedIngressRoutes, "2001:db8:100::e/128", switchboardMakeOverlayMachineIdentity(1, remote.fragment)),
               "build_overlay_routing_config_hosted_ingress_includes_remote_machine_public_peer_address");

  // A qualification response is a current authenticated application observation,
  // never a cached global-health conclusion.  The authority epoch and control
  // stream incarnation fence the observation before it can leave this Brain.
  ScopedRing qualificationRing = {};
  TestBrain qualificationBrain = {};
  qualificationBrain.weAreMaster = true;
  qualificationBrain.masterAuthorityEpoch = 44;
  qualificationBrain.brainConfig.clusterUUID = uint128_t(0x9710);
  Machine qualificationMachine = {};
  qualificationMachine.uuid = uint128_t(0x9713);
  qualificationMachine.neuron.machine = &qualificationMachine;
  qualificationMachine.neuron.ioGeneration = 8;
  qualificationMachine.neuron.connected = true;
  qualificationBrain.machines.insert(&qualificationMachine);
  int qualificationPeerFD = -1;
  const bool qualificationSocketInstalled =
      installQualificationNeuronSocket(qualificationBrain, qualificationMachine, qualificationPeerFD);
  suite.expect(qualificationSocketInstalled, "qualification_execute_installs_authenticated_neuron_stream");

  ApplicationDeployment app6 = {};
  app6.plan.config.applicationID = 6;
  app6.plan.config.versionID = 1;
  ApplicationDeployment probe = {};
  probe.plan.config.applicationID = 11;
  probe.plan.config.versionID = 1;
  const uint64_t app6DeploymentID = app6.plan.config.deploymentID();
  const uint64_t probeDeploymentID = probe.plan.config.deploymentID();
  qualificationBrain.deployments.insert_or_assign(app6DeploymentID, &app6);
  qualificationBrain.deployments.insert_or_assign(probeDeploymentID, &probe);

  ContainerView qualificationContainer = {};
  qualificationContainer.uuid = uint128_t(0x9714);
  qualificationContainer.machine = &qualificationMachine;
  qualificationContainer.deploymentID = probeDeploymentID;
  qualificationContainer.applicationID = 11;
  qualificationContainer.runtimeReady = true;
  qualificationBrain.containers.insert_or_assign(qualificationContainer.uuid, &qualificationContainer);
  auto qualificationReceipt = makeQualificationReceipt(qualificationBrain.brainConfig.clusterUUID,
      probeDeploymentID, qualificationContainer.uuid);
  auto qualificationRequest = makeQualificationSiteRequest(qualificationBrain.brainConfig.clusterUUID,
      app6DeploymentID, probeDeploymentID);
  qualificationBrain.receiveNametagQualificationApplicationReceipt(&qualificationMachine.neuron, qualificationReceipt);
  MothershipNametagQualificationSiteResponse qualificationResponse = {};
  suite.expect(qualificationBrain.mothershipNametagQualificationSiteResponse(qualificationRequest, qualificationResponse) &&
                   mothershipNametagQualificationSiteResponseValid(qualificationRequest, qualificationResponse),
               "qualification_response_requires_current_authenticated_probe_receipt");

  qualificationMachine.neuron.ioGeneration += 1;
  qualificationResponse = {};
  suite.expect(!qualificationBrain.mothershipNametagQualificationSiteResponse(qualificationRequest, qualificationResponse),
               "qualification_response_rejects_stale_neuron_generation");
  qualificationBrain.receiveNametagQualificationApplicationReceipt(&qualificationMachine.neuron, qualificationReceipt);
  qualificationResponse = {};
  suite.expect(qualificationBrain.mothershipNametagQualificationSiteResponse(qualificationRequest, qualificationResponse),
               "qualification_response_accepts_reauthenticated_current_generation");
  qualificationRequest.targetApp6DeploymentID = probeDeploymentID;
  qualificationResponse = {};
  suite.expect(!qualificationBrain.mothershipNametagQualificationSiteResponse(qualificationRequest, qualificationResponse),
               "qualification_response_rejects_invalid_live_app6_binding");
  qualificationRequest.targetApp6DeploymentID = app6DeploymentID;
  qualificationRequest.action = MothershipNametagQualificationSiteAction::execute;
  qualificationMachine.neuron.wBuffer.clear();
  qualificationResponse = {};
  suite.expect(qualificationSocketInstalled &&
                   qualificationBrain.mothershipNametagQualificationSiteResponse(qualificationRequest, qualificationResponse) &&
                   mothershipNametagQualificationSiteResponseValid(qualificationRequest, qualificationResponse) &&
                   qualificationBrain.nametagQualificationApplicationCommandDispatches.size() == 1 &&
                   countQualificationCommandFrames(qualificationMachine.neuron.wBuffer) == 1,
               "qualification_execute_dispatches_one_exact_probe_command");
  qualificationMachine.neuron.wBuffer.clear();
  qualificationResponse = {};
  suite.expect(qualificationSocketInstalled &&
                   qualificationBrain.mothershipNametagQualificationSiteResponse(qualificationRequest, qualificationResponse) &&
                   qualificationBrain.nametagQualificationApplicationCommandDispatches.size() == 1 &&
                   qualificationMachine.neuron.wBuffer.empty(),
               "qualification_execute_retry_is_idempotent_for_current_tuple");
  qualificationMachine.neuron.ioGeneration += 1;
  qualificationResponse = {};
  suite.expect(!qualificationBrain.mothershipNametagQualificationSiteResponse(qualificationRequest, qualificationResponse),
               "qualification_execute_rejects_reused_tuple_on_neuron_generation_change");
  if (qualificationMachine.neuron.isFixedFile) Ring::uninstallFromFixedFileSlot(&qualificationMachine.neuron);
  if (qualificationPeerFD >= 0) ::close(qualificationPeerFD);

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
