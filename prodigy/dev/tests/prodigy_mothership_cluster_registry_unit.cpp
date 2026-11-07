#include <prodigy/mothership/mothership.cluster.registry.h>
#include <services/debug.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>

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
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

static bool stringContains(const String& haystack, const char *needle)
{
  size_t needleLength = std::strlen(needle);
  if (needleLength == 0)
  {
    return true;
  }

  return std::search(haystack.data(),
                     haystack.data() + haystack.size(),
                     needle,
                     needle + needleLength) != (haystack.data() + haystack.size());
}

static bool equalControls(const Vector<MothershipProdigyClusterControl>& lhs, const Vector<MothershipProdigyClusterControl>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    if (lhs[index].kind != rhs[index].kind || lhs[index].path.equals(rhs[index].path) == false)
    {
      return false;
    }
  }

  return true;
}

static bool equalMothershipConnectivity(const MothershipConnectivity& lhs, const MothershipConnectivity& rhs)
{
  const MothershipTunnelProviderSpec& lt = lhs.tunnelProvider;
  const MothershipTunnelProviderSpec& rt = rhs.tunnelProvider;
  if (lhs.kind != rhs.kind || lt.artifactSha256.equals(rt.artifactSha256) == false || lt.artifactBytes != rt.artifactBytes || lt.dialEndpoint.equals(rt.dialEndpoint) == false || lt.egress.address4 != rt.egress.address4 || lt.egress.port != rt.egress.port)
  {
    return false;
  }

  const MothershipTunnelGatewayClientAuth& la = lt.clientAuth;
  const MothershipTunnelGatewayClientAuth& ra = rt.clientAuth;
  if (la.rootCertPem.equals(ra.rootCertPem) == false || la.clientCertPem.equals(ra.clientCertPem) == false || la.clientKeyPem.equals(ra.clientKeyPem) == false)
  {
    return false;
  }

  return true;
}

static bool equalMachineSchemas(const Vector<MothershipProdigyClusterMachineSchema>& lhs, const Vector<MothershipProdigyClusterMachineSchema>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    if (lhs[index].schema.equals(rhs[index].schema) == false || lhs[index].kind != rhs[index].kind || lhs[index].lifetime != rhs[index].lifetime || lhs[index].cpu != rhs[index].cpu || lhs[index].ipxeScriptURL.equals(rhs[index].ipxeScriptURL) == false || lhs[index].vmImageURI.equals(rhs[index].vmImageURI) == false || lhs[index].gcpInstanceTemplate.equals(rhs[index].gcpInstanceTemplate) == false || lhs[index].gcpInstanceTemplateSpot.equals(rhs[index].gcpInstanceTemplateSpot) == false || lhs[index].providerMachineType.equals(rhs[index].providerMachineType) == false || lhs[index].providerReservationID.equals(rhs[index].providerReservationID) == false || lhs[index].region.equals(rhs[index].region) == false || lhs[index].zone.equals(rhs[index].zone) == false || lhs[index].budget != rhs[index].budget)
    {
      return false;
    }
  }

  return true;
}

static bool equalMachines(const Vector<MothershipProdigyClusterMachine>& lhs, const Vector<MothershipProdigyClusterMachine>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    if (lhs[index].source != rhs[index].source || lhs[index].backing != rhs[index].backing || lhs[index].kind != rhs[index].kind || lhs[index].lifetime != rhs[index].lifetime || lhs[index].isBrain != rhs[index].isBrain || lhs[index].cloud != rhs[index].cloud || lhs[index].ssh != rhs[index].ssh || lhs[index].addresses != rhs[index].addresses || lhs[index].ownership != rhs[index].ownership || lhs[index].uuid != rhs[index].uuid || lhs[index].rackUUID != rhs[index].rackUUID)
    {
      return false;
    }
  }

  return true;
}

static bool equalEnvironmentBGP(const ProdigyEnvironmentBGPConfig& lhs, const ProdigyEnvironmentBGPConfig& rhs)
{
  return lhs == rhs;
}

static bool equalIPPrefixes(const Vector<IPPrefix>& lhs, const Vector<IPPrefix>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }
  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    if (lhs[index].equals(rhs[index]) == false)
    {
      return false;
    }
  }
  return true;
}

static bool equalOSUpdatePolicies(const Vector<OperatingSystemUpdatePolicy>& lhs, const Vector<OperatingSystemUpdatePolicy>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    if (lhs[index].osID.equals(rhs[index].osID) == false || lhs[index].targetVersionID.equals(rhs[index].targetVersionID) == false || lhs[index].command.equals(rhs[index].command) == false || lhs[index].includeVMs != rhs[index].includeVMs)
    {
      return false;
    }
  }

  return true;
}

static bool equalTestConfig(const MothershipProdigyClusterTestConfig& lhs, const MothershipProdigyClusterTestConfig& rhs)
{
  return lhs.specified == rhs.specified && lhs.workspaceRoot.equals(rhs.workspaceRoot) && lhs.machineCount == rhs.machineCount && lhs.spareMachineCount == rhs.spareMachineCount && lhs.machineLogicalCores == rhs.machineLogicalCores && lhs.machineMemoryMB == rhs.machineMemoryMB && lhs.machineStorageMB == rhs.machineStorageMB && lhs.storageDeviceCount == rhs.storageDeviceCount && lhs.storageDeviceMB == rhs.storageDeviceMB && lhs.brainBootstrapFamily == rhs.brainBootstrapFamily && lhs.enableFakeIpv4Boundary == rhs.enableFakeIpv4Boundary && lhs.interContainerMTU == rhs.interContainerMTU;
}

static bool equalGcpConfig(const MothershipProdigyClusterGcpConfig& lhs, const MothershipProdigyClusterGcpConfig& rhs)
{
  return lhs.serviceAccountEmail.equals(rhs.serviceAccountEmail) && lhs.network.equals(rhs.network) && lhs.subnetwork.equals(rhs.subnetwork);
}

static bool equalAwsConfig(const MothershipProdigyClusterAwsConfig& lhs, const MothershipProdigyClusterAwsConfig& rhs)
{
  return lhs.instanceProfileName.equals(rhs.instanceProfileName) && lhs.instanceProfileArn.equals(rhs.instanceProfileArn);
}

static bool equalAzureConfig(const MothershipProdigyClusterAzureConfig& lhs, const MothershipProdigyClusterAzureConfig& rhs)
{
  return lhs.managedIdentityName.equals(rhs.managedIdentityName) && lhs.managedIdentityResourceID.equals(rhs.managedIdentityResourceID);
}

static bool equalACMEConfig(const ProdigyACMEConfig& lhs, const ProdigyACMEConfig& rhs)
{
  return lhs == rhs;
}

static const String& fixtureSSHDHostPublicKey(void)
{
  static String hostPublicKey = []() -> String {
    String loaded = {};
    String failure = {};
    if (prodigyReadBootstrapSSHPublicKey(prodigyTestSSHDHostPrivateKeyPath(), loaded, &failure) == false)
    {
      std::fprintf(stderr, "failed to load fixture ssh host public key: %s\n", failure.c_str());
      std::exit(EXIT_FAILURE);
    }

    return loaded;
  }();

  return hostPublicKey;
}

static ClusterMachineSSH makeMachineSSH(const String& address, uint16_t port = 0, const String& user = {}, const String& privateKeyPath = {}, const String& hostPublicKeyOpenSSH = {})
{
  ClusterMachineSSH ssh = {};
  ssh.address = address;
  ssh.port = port;
  ssh.user = user;
  ssh.privateKeyPath = privateKeyPath;
  ssh.hostPublicKeyOpenSSH = hostPublicKeyOpenSSH.size() > 0 ? hostPublicKeyOpenSSH : fixtureSSHDHostPublicKey();
  return ssh;
}

static ClusterMachineAddresses makeMachineAddresses(const String& privateAddress = {}, const String& publicAddress = {})
{
  ClusterMachineAddresses addresses = {};
  if (privateAddress.size() > 0)
  {
    prodigyAppendUniqueClusterMachineAddress(addresses.privateAddresses, privateAddress);
  }
  if (publicAddress.size() > 0)
  {
    prodigyAppendUniqueClusterMachineAddress(addresses.publicAddresses, publicAddress);
  }
  return addresses;
}

static void renderExpectedManagedGcpTemplateBase(const MothershipProdigyCluster& cluster, String& templateBase)
{
  templateBase.snprintf<"prodigy-{itoa}-gcp-template"_ctv>(uint64_t(cluster.clusterUUID));
}

static MothershipProdigyClusterMachineSchema makeMachineSchemaFromConfig(const MachineConfig& config)
{
  MothershipProdigyClusterMachineSchema schema = {};
  schema.schema = config.slug;
  schema.kind = config.kind;
  schema.ipxeScriptURL = config.ipxeScriptURL;
  schema.vmImageURI = config.vmImageURI;
  schema.gcpInstanceTemplate = config.gcpInstanceTemplate;
  schema.gcpInstanceTemplateSpot = config.gcpInstanceTemplateSpot;
  return schema;
}

static void appendMachineSchema(MothershipProdigyCluster& cluster, const MothershipProdigyClusterMachineSchema& schema)
{
  for (MothershipProdigyClusterMachineSchema& existing : cluster.machineSchemas)
  {
    if (existing.schema.equals(schema.schema) == false)
    {
      continue;
    }

    existing.kind = schema.kind;
    existing.lifetime = schema.lifetime;
    if (schema.ipxeScriptURL.size() > 0)
    {
      existing.ipxeScriptURL = schema.ipxeScriptURL;
    }
    if (schema.vmImageURI.size() > 0)
    {
      existing.vmImageURI = schema.vmImageURI;
    }
    if (schema.gcpInstanceTemplate.size() > 0)
    {
      existing.gcpInstanceTemplate = schema.gcpInstanceTemplate;
    }
    if (schema.gcpInstanceTemplateSpot.size() > 0)
    {
      existing.gcpInstanceTemplateSpot = schema.gcpInstanceTemplateSpot;
    }
    if (schema.providerMachineType.size() > 0)
    {
      existing.providerMachineType = schema.providerMachineType;
    }
    if (schema.providerReservationID.size() > 0)
    {
      existing.providerReservationID = schema.providerReservationID;
    }
    if (schema.region.size() > 0)
    {
      existing.region = schema.region;
    }
    if (schema.zone.size() > 0)
    {
      existing.zone = schema.zone;
    }
    existing.budget = schema.budget;
    return;
  }

  cluster.machineSchemas.push_back(schema);
}

static void appendClusterMachineConfig(MothershipProdigyCluster& cluster, const MachineConfig& config)
{
  appendMachineSchema(cluster, makeMachineSchemaFromConfig(config));
}

static void setRemoteClusterArchitecture(MothershipProdigyCluster& cluster, MachineCpuArchitecture architecture)
{
  cluster.architecture = architecture;
  for (MothershipProdigyClusterMachineSchema& schema : cluster.machineSchemas)
  {
    schema.cpu.architecture = architecture;
  }
}

static NeuronBGPPeerConfig makeEnvironmentBGPPeer(const char *peerAddress, const char *sourceAddress, uint16_t peerASN, const char *md5Password, uint8_t hopLimit)
{
  NeuronBGPPeerConfig peer = {};
  peer.peerASN = peerASN;
  peer.peerAddress = IPAddress(peerAddress, std::strchr(peerAddress, ':') != nullptr);
  peer.sourceAddress = IPAddress(sourceAddress, std::strchr(sourceAddress, ':') != nullptr);
  peer.md5Password.assign(md5Password);
  peer.hopLimit = hopLimit;
  return peer;
}

static bool equalClusters(const MothershipProdigyCluster& lhs, const MothershipProdigyCluster& rhs)
{
  return lhs.name.equals(rhs.name) && lhs.clusterUUID == rhs.clusterUUID && lhs.deploymentMode == rhs.deploymentMode && lhs.architecture == rhs.architecture && lhs.includeLocalMachine == rhs.includeLocalMachine && lhs.provider == rhs.provider && lhs.providerScope.equals(rhs.providerScope) && lhs.providerCredentialName.equals(rhs.providerCredentialName) && lhs.propagateProviderCredentialToProdigy == rhs.propagateProviderCredentialToProdigy && lhs.dnsProvider == rhs.dnsProvider && lhs.dnsProviderCredentialName.equals(rhs.dnsProviderCredentialName) && equalACMEConfig(lhs.acme, rhs.acme) && equalAwsConfig(lhs.aws, rhs.aws) && equalGcpConfig(lhs.gcp, rhs.gcp) && equalAzureConfig(lhs.azure, rhs.azure) && equalControls(lhs.controls, rhs.controls) && equalMothershipConnectivity(lhs.mothershipConnectivity, rhs.mothershipConnectivity) && lhs.nBrains == rhs.nBrains && equalMachineSchemas(lhs.machineSchemas, rhs.machineSchemas) && equalMachines(lhs.machines, rhs.machines) && lhs.topology == rhs.topology && lhs.bootstrapSshUser.equals(rhs.bootstrapSshUser) && lhs.bootstrapSshKeyPackage == rhs.bootstrapSshKeyPackage && lhs.bootstrapSshHostKeyPackage == rhs.bootstrapSshHostKeyPackage && lhs.bootstrapSshPrivateKeyPath.equals(rhs.bootstrapSshPrivateKeyPath) && lhs.remoteProdigyPath.equals(rhs.remoteProdigyPath) && lhs.sharedCPUOvercommitPermille == rhs.sharedCPUOvercommitPermille && lhs.machineReservedResources == rhs.machineReservedResources && lhs.osUpdatesEnabled == rhs.osUpdatesEnabled && equalOSUpdatePolicies(lhs.osUpdatePolicies, rhs.osUpdatePolicies) && lhs.maxOSDrains == rhs.maxOSDrains && lhs.machineUpdateCadenceMins == rhs.machineUpdateCadenceMins && equalEnvironmentBGP(lhs.bgp, rhs.bgp) && lhs.providerManagedBGP == rhs.providerManagedBGP && equalIPPrefixes(lhs.bgpAuthorizedOriginPrefixes, rhs.bgpAuthorizedOriginPrefixes) && equalTestConfig(lhs.test, rhs.test) && lhs.desiredEnvironment == rhs.desiredEnvironment && lhs.environmentConfigured == rhs.environmentConfigured && lhs.lastRefreshMs == rhs.lastRefreshMs && lhs.lastRefreshFailure.equals(rhs.lastRefreshFailure);
}

static void assignFixtureBootstrapSSHKeyPackage(MothershipProdigyCluster& cluster)
{
  String failure = {};
  if (prodigyReadSSHKeyPackageFromPrivateKeyPath(
          prodigyTestBootstrapSeedSSHPrivateKeyPath(),
          cluster.bootstrapSshKeyPackage,
          &failure) == false)
  {
    std::fprintf(stderr, "failed to load fixture bootstrap ssh key package for test cluster %s: %s\n", cluster.name.c_str(), failure.c_str());
    std::exit(EXIT_FAILURE);
  }

  if (prodigyReadSSHKeyPackageFromPrivateKeyPath(
          prodigyTestSSHDHostPrivateKeyPath(),
          cluster.bootstrapSshHostKeyPackage,
          &failure) == false)
  {
    std::fprintf(stderr, "failed to load fixture bootstrap ssh host key package for test cluster %s: %s\n", cluster.name.c_str(), failure.c_str());
    std::exit(EXIT_FAILURE);
  }
}

int main(void)
{
  TestSuite suite;

  char scratch[] = "/tmp/nametag-mothership-registry-XXXXXX";
  char *created = mkdtemp(scratch);
  suite.expect(created != nullptr, "mkdtemp_created");
  if (created == nullptr)
  {
    return EXIT_FAILURE;
  }

  String dbPath;
  dbPath.assign(created);
  String pathFaultReopenPath;
  ProdigyCrossClusterPathFaultGatewayLifecycleRecord pathFaultReopenExpected = {};
  bool pathFaultReopenExpectedRecorded = false;

  // The graph placement owner reads the existing durable COUSIN route/receipt
  // registry.  Exercise absent, malformed-scope, restart, stale-generation,
  // and withdrawn-route cases without synthesizing a graph-specific registry.
  {
    String graphRoutePath; graphRoutePath.snprintf<"{}/graph-routes"_ctv>(dbPath);
    String failure;
    constexpr uint128_t owner = 0x5101, replica = 0x5102;
    const int64_t now = Time::now<TimeResolution::ms>();
    auto makeRoute = [&](uint128_t id, uint16_t app, uint8_t role, uint16_t slot, bool reverse) {
      CousinRouteRecord route = {};
      route.routeUUID = id; route.operationUUID = id + 0x100; route.pairUUID = 0x5201;
      route.logicalWorkloadUUID = 0x5301; route.logicalServiceUUID = id + 0x200;
      route.sourceClusterUUID = reverse ? owner : replica; route.destinationClusterUUID = reverse ? replica : owner;
      route.sourceApplicationID = route.destinationApplicationID = app;
      route.sourceCousinServicePrefix = route.destinationCousinServicePrefix = prodigyRuntimeStatefulServicePrefix(app, role);
      route.slots.insert(slot); route.destinationRoutablePrefixUUID = id + 0x300;
      route.destinationPublicAddress = IPAddress("2001:db8:510::1", true); route.destinationPublicAddress.v6[15] = uint8_t(id);
      route.destinationTCPPort = 443; route.sourcePermissionUUID = id + 0x400; route.destinationPermissionUUID = id + 0x500;
      route.transportProtocol = IPPROTO_TCP; route.destinationCIDR = 64; route.pathMTU = 1500;
      route.generation = 1; route.issuedAtMs = now - 1; route.expiresAtMs = now + 60'000; route.keyEpoch = 1; route.rootGeneration = 1;
      return route;
    };
    auto recordRoute = [&](MothershipClusterRegistry& routes, CousinRouteRecord route) {
      CousinRouteRecord recorded = {}; bool resumed = false;
      return routes.recordCousinRoute(route, recorded, resumed, &failure) && !resumed;
    };
    auto recordReceipts = [&](MothershipClusterRegistry& routes, const CousinRouteRecord& route) {
      for (const auto half : {CousinRouteHalf::source, CousinRouteHalf::destination}) {
        CousinRouteApplyReceipt receipt = {};
        receipt.routeUUID = route.routeUUID; receipt.generation = route.generation;
        if (!cousinRouteAuthorizationDigest(route, receipt.authorizationSHA256)) return false;
        receipt.localClusterUUID = half == CousinRouteHalf::source ? route.sourceClusterUUID : route.destinationClusterUUID;
        receipt.localHalf = half; receipt.keyEpoch = route.keyEpoch;
        receipt.localRuntimeRevision = route.generation * 10 + (half == CousinRouteHalf::source ? 1 : 2);
        receipt.installedState = route.state;
        CousinRouteApplyReceipt recorded = {}; bool resumed = false;
        if (!routes.recordCousinRouteApplyReceipt(receipt, recorded, resumed, &failure)) return false;
      }
      return true;
    };
    Vector<MothershipGraphReplicaRouteBinding> bindings;
    const auto sibling = makeRoute(0x5405, 5, 2, 0, false);
    const auto seeding = makeRoute(0x5406, 5, 4, 0, false);
    {
      MothershipClusterRegistry routes(graphRoutePath);
      suite.expect(!routes.loadGraphReplicaRouteBindings(5, owner, replica, now, bindings, &failure), "graph_route_absent_rejected");
      suite.expect(recordRoute(routes, makeRoute(0x5401, 2, 2, 0, false)) &&
          !routes.loadGraphReplicaRouteBindings(5, owner, replica, now, bindings, &failure), "graph_route_wrong_app_rejected");
      suite.expect(recordRoute(routes, makeRoute(0x5402, 5, 2, 1, false)) &&
          !routes.loadGraphReplicaRouteBindings(5, owner, replica, now, bindings, &failure), "graph_route_wrong_group_rejected");
      suite.expect(recordRoute(routes, makeRoute(0x5403, 5, 3, 0, false)) &&
          !routes.loadGraphReplicaRouteBindings(5, owner, replica, now, bindings, &failure), "graph_route_wrong_purpose_rejected");
      suite.expect(recordRoute(routes, makeRoute(0x5404, 5, 2, 0, true)) &&
          !routes.loadGraphReplicaRouteBindings(5, owner, replica, now, bindings, &failure), "graph_route_wrong_direction_rejected");
      suite.expect(recordRoute(routes, sibling) && recordReceipts(routes, sibling) &&
          recordRoute(routes, seeding) && recordReceipts(routes, seeding) &&
          routes.loadGraphReplicaRouteBindings(5, owner, replica, now, bindings, &failure) && bindings.size() == 2,
          "graph_route_exact_active_accepted");
    }
    MothershipClusterRegistry resumedRoutes(graphRoutePath);
    bindings.clear();
    suite.expect(resumedRoutes.loadGraphReplicaRouteBindings(5, owner, replica, now, bindings, &failure) && bindings.size() == 2,
        "graph_route_restart_resume_accepted");
    auto stale = sibling; stale.generation = 2; stale.operationUUID++; stale.issuedAtMs = now; stale.expiresAtMs = now + 60'000;
    suite.expect(recordRoute(resumedRoutes, stale) && !resumedRoutes.loadGraphReplicaRouteBindings(5, owner, replica, now, bindings, &failure),
        "graph_route_stale_receipt_rejected");
    suite.expect(recordReceipts(resumedRoutes, stale), "graph_route_new_generation_receipts_recorded");
    auto withdrawn = stale; withdrawn.generation = 3; withdrawn.operationUUID++; withdrawn.issuedAtMs = now + 1;
    withdrawn.expiresAtMs = now + 60'000; withdrawn.state = CousinRouteState::withdrawn;
    withdrawn.withdrawalGeneration = withdrawn.generation; withdrawn.withdrawnAtMs = now + 1;
    suite.expect(recordRoute(resumedRoutes, withdrawn) && !resumedRoutes.loadGraphReplicaRouteBindings(5, owner, replica, now + 2, bindings, &failure),
        "graph_route_loss_rejected");
  }

  MothershipProdigyCluster local = {};
  local.name = "local-alpha"_ctv;
  local.deploymentMode = MothershipClusterDeploymentMode::local;
  local.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/tmp/prodigy-alpha.sock"_ctv});
  appendClusterMachineConfig(local, MachineConfig {
                                        .kind = MachineConfig::MachineKind::bareMetal,
                                        .slug = "local-dev"_ctv,
                                        .nLogicalCores = 8,
                                        .nMemoryMB = 16'384,
                                        .nStorageMB = 131'072});
  local.bgp.specified = true;
  local.desiredEnvironment = ProdigyEnvironmentKind::dev;
  local.lastRefreshMs = 42;
  local.lastRefreshFailure = "connection refused"_ctv;

  MothershipProdigyCluster storedLocal = local;
  storedLocal.architecture = nametagCurrentBuildMachineArchitecture();

  MothershipProdigyCluster localAdopted = {};
  localAdopted.name = "local-homelab"_ctv;
  localAdopted.deploymentMode = MothershipClusterDeploymentMode::local;
  localAdopted.includeLocalMachine = false;
  localAdopted.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/local-homelab.sock"_ctv});
  appendClusterMachineConfig(localAdopted, MachineConfig {
                                               .kind = MachineConfig::MachineKind::bareMetal,
                                               .slug = "homelab-brain"_ctv,
                                               .nLogicalCores = 16,
                                               .nMemoryMB = 65'536,
                                               .nStorageMB = 524'288});
  appendClusterMachineConfig(localAdopted, MachineConfig {
                                               .kind = MachineConfig::MachineKind::vm,
                                               .slug = "homelab-worker"_ctv,
                                               .nLogicalCores = 8,
                                               .nMemoryMB = 32'768,
                                               .nStorageMB = 262'144});
  localAdopted.nBrains = 2;
  localAdopted.sharedCPUOvercommitPermille = 1500;
  localAdopted.machineReservedResources = prodigySmokeMachineReservedResources;
  localAdopted.bootstrapSshPrivateKeyPath = "/root/.ssh/homelab"_ctv;
  localAdopted.bgp.specified = true;
  localAdopted.bgp.config.enabled = true;
  localAdopted.bgp.config.ourBGPID = inet_addr("192.168.10.11");
  localAdopted.bgp.config.community = (uint32_t(64'512) << 16) | 321u;
  localAdopted.bgp.config.nextHop4 = IPAddress("192.168.10.1", false);
  localAdopted.bgp.config.nextHop6 = IPAddress("2001:db8:10::1", true);
  localAdopted.bgp.config.peers.push_back(makeEnvironmentBGPPeer("169.254.1.1", "192.168.10.11", 64'512, "homelab-md5-v4", 2));
  localAdopted.bgp.config.peers.push_back(makeEnvironmentBGPPeer("2001:19f0:ffff::1", "2001:db8:10::11", 64'512, "homelab-md5-v6", 2));
  localAdopted.desiredEnvironment = ProdigyEnvironmentKind::dev;
  localAdopted.machines.push_back(MothershipProdigyClusterMachine {
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::owned,
      .kind = MachineConfig::MachineKind::bareMetal,
      .lifetime = MachineLifetime::owned,
      .isBrain = true,
      .ssh = makeMachineSSH("192.168.10.11"_ctv, 0),
      .addresses = makeMachineAddresses("192.168.10.11"_ctv),
      .ownership = ClusterMachineOwnership {
          .mode = ClusterMachineOwnershipMode::wholeMachine}});
  localAdopted.machines.push_back(MothershipProdigyClusterMachine {
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::owned,
      .kind = MachineConfig::MachineKind::bareMetal,
      .lifetime = MachineLifetime::owned,
      .isBrain = true,
      .ssh = makeMachineSSH("192.168.10.12"_ctv, 2222, "ops"_ctv, "/tmp/homelab-b"_ctv),
      .addresses = makeMachineAddresses("192.168.10.12"_ctv),
      .ownership = ClusterMachineOwnership {
          .mode = ClusterMachineOwnershipMode::wholeMachine}});
  localAdopted.machines.push_back(MothershipProdigyClusterMachine {
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::owned,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::owned,
      .isBrain = false,
      .ssh = makeMachineSSH("192.168.10.13"_ctv, 0),
      .addresses = makeMachineAddresses("192.168.10.13"_ctv),
      .ownership = ClusterMachineOwnership {
                                            .mode = ClusterMachineOwnershipMode::percentages,
                                            .nLogicalCoresBasisPoints = 5000,
                                            .nMemoryBasisPoints = 5000,
                                            .nStorageBasisPoints = 5000}
  });

  localAdopted.machines[0].rackUUID = 101;
  localAdopted.machines[1].rackUUID = 202;
  localAdopted.machines[2].rackUUID = 303;
  localAdopted.machines[1].uuid = (uint128_t(0x5a02) << 64) | uint128_t(0x5a03);
  assignFixtureBootstrapSSHKeyPackage(localAdopted);

  MothershipProdigyCluster storedLocalAdopted = localAdopted;
  storedLocalAdopted.architecture = nametagCurrentBuildMachineArchitecture();
  storedLocalAdopted.bootstrapSshUser = defaultMothershipClusterSSHUser();
  storedLocalAdopted.remoteProdigyPath = defaultMothershipRemoteProdigyPath();
  storedLocalAdopted.machines[0].ssh.port = 22;
  storedLocalAdopted.machines[0].ssh.user = defaultMothershipClusterSSHUser();
  storedLocalAdopted.machines[0].ssh.privateKeyPath = localAdopted.bootstrapSshPrivateKeyPath;
  storedLocalAdopted.machines[2].ssh.port = 22;
  storedLocalAdopted.machines[2].ssh.user = defaultMothershipClusterSSHUser();
  storedLocalAdopted.machines[2].ssh.privateKeyPath = localAdopted.bootstrapSshPrivateKeyPath;

  {
    // Generated by the unmodified f2f7f2d8 registry serializer in the verified
    // seed guest. Keep this literal V2 record independent from the V4 writer.
    static constexpr uint8_t legacyV2Record[] = {
        0x50, 0x52, 0x4f, 0x44, 0x49, 0x47, 0x59, 0x2d, 0x4d, 0x4f, 0x54, 0x48,
        0x45, 0x52, 0x53, 0x48, 0x49, 0x50, 0x2d, 0x43, 0x4c, 0x55, 0x53, 0x54,
        0x45, 0x52, 0x0a, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x32,
        0x0a, 0x0a, 0x1b, 0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2d, 0x76, 0x32,
        0x2d, 0x61, 0x64, 0x6f, 0x70, 0x74, 0x65, 0x64, 0x2d, 0x72, 0x61, 0x63,
        0x6b, 0x2d, 0x7a, 0x65, 0x72, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x03, 0x01, 0x00, 0x0a, 0x31, 0x39,
        0x32, 0x2e, 0x30, 0x2e, 0x32, 0x2e, 0x31, 0x30, 0x16, 0x00, 0x04, 0x72,
        0x6f, 0x6f, 0x74, 0x00, 0x00, 0x01, 0x0a, 0x31, 0x39, 0x32, 0x2e, 0x30,
        0x2e, 0x32, 0x2e, 0x31, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    constexpr auto legacyName = "legacy-v2-adopted-rack-zero"_ctv;
    String legacyRecord = {};
    legacyRecord.append(legacyV2Record, sizeof(legacyV2Record));

    String legacyDbPath = {};
    legacyDbPath.snprintf<"{}/legacy-v2"_ctv>(dbPath);
    String failure = {};
    {
      TidesDB legacyDatabase(legacyDbPath);
      bool wroteLegacyFixture = legacyDatabase.write("clusters"_ctv, legacyName, legacyRecord, &failure);
      suite.expect(wroteLegacyFixture, "rack_v2_fixture_written");
      suite.expect(failure.size() == 0, "rack_v2_fixture_write_no_failure");
    }

    MothershipClusterRegistry legacyRegistry(legacyDbPath);
    MothershipProdigyCluster loadedLegacyFixture = {};
    loadedLegacyFixture.machines.push_back(MothershipProdigyClusterMachine {.rackUUID = 77});
    bool loadedLegacyFixtureOK = legacyRegistry.getCluster(legacyName, loadedLegacyFixture, &failure);
    suite.expect(loadedLegacyFixtureOK, "rack_v2_fixture_decodes");
    suite.expect(loadedLegacyFixture.machines.size() == 1, "rack_v2_fixture_machine_count");
    if (loadedLegacyFixture.machines.size() == 1)
    {
      suite.expect(loadedLegacyFixture.machines[0].rackUUID == 0, "rack_v2_fixture_defaults_zero");
      suite.expect(loadedLegacyFixture.machines[0].uuid == 0, "adopted_uuid_v2_fixture_defaults_zero");
    }
  }

  MothershipProdigyCluster remoteCreated = {};
  remoteCreated.name = "managed-aws"_ctv;
  remoteCreated.deploymentMode = MothershipClusterDeploymentMode::remote;
  remoteCreated.provider = MothershipClusterProvider::aws;
  remoteCreated.providerCredentialName = "aws-prod"_ctv;
  remoteCreated.providerScope = "acct-prod/us-east-1"_ctv;
  remoteCreated.dnsProvider = MothershipClusterProvider::cloudflare;
  remoteCreated.dnsProviderCredentialName = "cloudflare-prod"_ctv;
  remoteCreated.acme.accountEmail = "ops@example.com"_ctv;
  remoteCreated.acme.termsAgreed = true;
  remoteCreated.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
  remoteCreated.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/managed-aws.sock"_ctv});
  appendClusterMachineConfig(remoteCreated, MachineConfig {
                                                .kind = MachineConfig::MachineKind::vm,
                                                .slug = "aws-brain-vm"_ctv,
                                                .vmImageURI = "ami://aws-brain"_ctv,
                                                .nLogicalCores = 4,
                                                .nMemoryMB = 16'384,
                                                .nStorageMB = 131'072});
  appendClusterMachineConfig(remoteCreated, MachineConfig {
                                                .kind = MachineConfig::MachineKind::bareMetal,
                                                .slug = "aws-brain-metal"_ctv,
                                                .nLogicalCores = 32,
                                                .nMemoryMB = 131'072,
                                                .nStorageMB = 1'048'576});
  remoteCreated.nBrains = 3;
  appendMachineSchema(remoteCreated, MothershipProdigyClusterMachineSchema {
                                         .schema = "aws-brain-vm"_ctv,
                                         .kind = MachineConfig::MachineKind::vm,
                                         .lifetime = MachineLifetime::ondemand,
                                         .providerMachineType = "c7i.large"_ctv,
                                         .budget = 2});
  appendMachineSchema(remoteCreated, MothershipProdigyClusterMachineSchema {
                                         .schema = "aws-brain-metal"_ctv,
                                         .kind = MachineConfig::MachineKind::bareMetal,
                                         .lifetime = MachineLifetime::reserved,
                                         .providerMachineType = "i3.metal"_ctv,
                                         .budget = 1});
  setRemoteClusterArchitecture(remoteCreated, MachineCpuArchitecture::x86_64);
  remoteCreated.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
  assignFixtureBootstrapSSHKeyPackage(remoteCreated);
  remoteCreated.desiredEnvironment = ProdigyEnvironmentKind::aws;
  remoteCreated.lastRefreshMs = 123'456'789;

  MothershipProdigyCluster storedRemoteCreated = remoteCreated;
  storedRemoteCreated.includeLocalMachine = false;
  storedRemoteCreated.bootstrapSshUser = defaultMothershipClusterSSHUser();
  storedRemoteCreated.remoteProdigyPath = defaultMothershipRemoteProdigyPath();
  storedRemoteCreated.acme.certbotInstall = "bundle"_ctv;
  storedRemoteCreated.acme.certbotPath = "/opt/prodigy/certbot/bin/certbot"_ctv;
  storedRemoteCreated.acme.certbotVersion = "5.6.0"_ctv;

  MothershipProdigyCluster remoteAdopted = {};
  remoteAdopted.name = "adopted-gcp"_ctv;
  remoteAdopted.deploymentMode = MothershipClusterDeploymentMode::remote;
  remoteAdopted.provider = MothershipClusterProvider::gcp;
  remoteAdopted.providerCredentialName = "gcp-prod"_ctv;
  remoteAdopted.providerScope = "projects/prod-cluster"_ctv;
  remoteAdopted.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/adopted-gcp.sock"_ctv});
  appendClusterMachineConfig(remoteAdopted, MachineConfig {
                                                .kind = MachineConfig::MachineKind::vm,
                                                .slug = "gcp-brain"_ctv,
                                                .vmImageURI = "projects/prod/global/images/brain"_ctv,
                                                .gcpInstanceTemplate = "brain-template"_ctv,
                                                .gcpInstanceTemplateSpot = "brain-template-spot"_ctv,
                                                .nLogicalCores = 4,
                                                .nMemoryMB = 16'384,
                                                .nStorageMB = 131'072});
  appendMachineSchema(remoteAdopted, MothershipProdigyClusterMachineSchema {
                                         .schema = "gcp-brain"_ctv,
                                         .kind = MachineConfig::MachineKind::vm,
                                         .lifetime = MachineLifetime::reserved,
                                         .providerMachineType = "n2-standard-4"_ctv});
  setRemoteClusterArchitecture(remoteAdopted, MachineCpuArchitecture::x86_64);
  remoteAdopted.nBrains = 2;
  remoteAdopted.bootstrapSshPrivateKeyPath = "/root/.ssh/adopted"_ctv;
  assignFixtureBootstrapSSHKeyPackage(remoteAdopted);
  remoteAdopted.desiredEnvironment = ProdigyEnvironmentKind::gcp;
  remoteAdopted.machines.push_back(MothershipProdigyClusterMachine {
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::cloud,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .isBrain = true,
      .cloud = ClusterMachineCloud {
                                    .schema = "gcp-brain"_ctv,
                                    .providerMachineType = "n2-standard-4"_ctv,
                                    .cloudID = "789654123000111"_ctv},
      .ssh = makeMachineSSH("35.1.2.3"_ctv, 0),
      .addresses = makeMachineAddresses("10.0.0.2"_ctv, "35.1.2.3"_ctv),
      .ownership = ClusterMachineOwnership {.mode = ClusterMachineOwnershipMode::wholeMachine}
  });
  remoteAdopted.machines.push_back(MothershipProdigyClusterMachine {
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::cloud,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .isBrain = true,
      .cloud = ClusterMachineCloud {
                                    .schema = "gcp-brain"_ctv,
                                    .providerMachineType = "n2-standard-4"_ctv,
                                    .cloudID = "789654123000222"_ctv},
      .ssh = makeMachineSSH("35.1.2.4"_ctv, 2202, "ubuntu"_ctv, "/tmp/adopted-b"_ctv),
      .addresses = makeMachineAddresses("10.0.0.3"_ctv, "35.1.2.4"_ctv),
      .ownership = ClusterMachineOwnership {.mode = ClusterMachineOwnershipMode::hardCaps, .nLogicalCoresCap = 2, .nMemoryMBCap = 4096, .nStorageMBCap = 8192}
  });

  MothershipProdigyCluster storedRemoteAdopted = remoteAdopted;
  storedRemoteAdopted.includeLocalMachine = false;
  storedRemoteAdopted.bootstrapSshUser = defaultMothershipClusterSSHUser();
  storedRemoteAdopted.remoteProdigyPath = defaultMothershipRemoteProdigyPath();
  storedRemoteAdopted.machines[0].ssh.port = 22;
  storedRemoteAdopted.machines[0].ssh.user = defaultMothershipClusterSSHUser();
  storedRemoteAdopted.machines[0].ssh.privateKeyPath = remoteAdopted.bootstrapSshPrivateKeyPath;

  MothershipProdigyCluster remoteManagedGcp = {};
  remoteManagedGcp.name = "managed-gcp"_ctv;
  remoteManagedGcp.deploymentMode = MothershipClusterDeploymentMode::remote;
  remoteManagedGcp.provider = MothershipClusterProvider::gcp;
  remoteManagedGcp.providerCredentialName = "gcp-prod"_ctv;
  remoteManagedGcp.providerScope = "projects/prod-cluster/zones/us-central1-a"_ctv;
  remoteManagedGcp.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/managed-gcp.sock"_ctv});
  remoteManagedGcp.gcp.serviceAccountEmail = "prodigy-brain@prod-cluster.iam.gserviceaccount.com"_ctv;
  appendMachineSchema(remoteManagedGcp, MothershipProdigyClusterMachineSchema {
                                            .schema = "gcp-brain-vm"_ctv,
                                            .kind = MachineConfig::MachineKind::vm,
                                            .lifetime = MachineLifetime::ondemand,
                                            .vmImageURI = "projects/prod-cluster/global/images/prodigy-brain"_ctv,
                                            .providerMachineType = "e2-medium"_ctv,
                                            .budget = 3});
  appendMachineSchema(remoteManagedGcp, MothershipProdigyClusterMachineSchema {
                                            .schema = "gcp-worker-vm"_ctv,
                                            .kind = MachineConfig::MachineKind::vm,
                                            .lifetime = MachineLifetime::spot,
                                            .vmImageURI = "projects/prod-cluster/global/images/prodigy-worker"_ctv,
                                            .providerMachineType = "e2-medium"_ctv,
                                            .budget = 2});
  setRemoteClusterArchitecture(remoteManagedGcp, MachineCpuArchitecture::x86_64);
  remoteManagedGcp.nBrains = 3;
  remoteManagedGcp.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
  assignFixtureBootstrapSSHKeyPackage(remoteManagedGcp);
  remoteManagedGcp.desiredEnvironment = ProdigyEnvironmentKind::gcp;

  MothershipProdigyCluster storedRemoteManagedGcp = remoteManagedGcp;
  storedRemoteManagedGcp.includeLocalMachine = false;
  storedRemoteManagedGcp.bootstrapSshUser = defaultMothershipClusterSSHUser();
  storedRemoteManagedGcp.remoteProdigyPath = defaultMothershipRemoteProdigyPath();
  storedRemoteManagedGcp.gcp.network = "global/networks/default"_ctv;

  MothershipProdigyCluster remoteMixed = {};
  remoteMixed.name = "hybrid-azure"_ctv;
  remoteMixed.deploymentMode = MothershipClusterDeploymentMode::remote;
  remoteMixed.provider = MothershipClusterProvider::azure;
  remoteMixed.providerCredentialName = "azure-prod"_ctv;
  remoteMixed.providerScope = "subscriptions/sub-prod/resourceGroups/rg-prod/locations/westus"_ctv;
  remoteMixed.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/hybrid-azure.sock"_ctv});
  appendClusterMachineConfig(remoteMixed, MachineConfig {
                                              .kind = MachineConfig::MachineKind::vm,
                                              .slug = "azure-brain-vm"_ctv,
                                              .vmImageURI = "image://azure-brain"_ctv,
                                              .nLogicalCores = 4,
                                              .nMemoryMB = 16'384,
                                              .nStorageMB = 131'072});
  appendClusterMachineConfig(remoteMixed, MachineConfig {
                                              .kind = MachineConfig::MachineKind::vm,
                                              .slug = "azure-worker-vm"_ctv,
                                              .vmImageURI = "image://azure-worker"_ctv,
                                              .nLogicalCores = 4,
                                              .nMemoryMB = 8192,
                                              .nStorageMB = 65'536});
  remoteMixed.nBrains = 3;
  remoteMixed.bootstrapSshPrivateKeyPath = "/root/.ssh/hybrid"_ctv;
  assignFixtureBootstrapSSHKeyPackage(remoteMixed);
  remoteMixed.machines.push_back(MothershipProdigyClusterMachine {
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::cloud,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .isBrain = true,
      .cloud = ClusterMachineCloud {
                                    .schema = "azure-brain-vm"_ctv,
                                    .providerMachineType = "Standard_D4s_v5"_ctv,
                                    .cloudID = "874563210000111"_ctv},
      .ssh = makeMachineSSH("203.0.113.44"_ctv, 22, "azureuser"_ctv, "/root/.ssh/hybrid"_ctv),
      .addresses = makeMachineAddresses("10.1.0.4"_ctv, "203.0.113.44"_ctv),
      .ownership = ClusterMachineOwnership {.mode = ClusterMachineOwnershipMode::wholeMachine}
  });
  appendMachineSchema(remoteMixed, MothershipProdigyClusterMachineSchema {
                                       .schema = "azure-brain-vm"_ctv,
                                       .kind = MachineConfig::MachineKind::vm,
                                       .lifetime = MachineLifetime::ondemand,
                                       .providerMachineType = "Standard_D4s_v5"_ctv,
                                       .budget = 3});
  appendMachineSchema(remoteMixed, MothershipProdigyClusterMachineSchema {
                                       .schema = "azure-worker-vm"_ctv,
                                       .kind = MachineConfig::MachineKind::vm,
                                       .lifetime = MachineLifetime::ondemand,
                                       .providerMachineType = "Standard_D2s_v5"_ctv,
                                       .budget = 2});
  setRemoteClusterArchitecture(remoteMixed, MachineCpuArchitecture::x86_64);

  MothershipProdigyCluster storedRemoteMixed = remoteMixed;
  storedRemoteMixed.includeLocalMachine = false;
  storedRemoteMixed.bootstrapSshUser = defaultMothershipClusterSSHUser();
  storedRemoteMixed.remoteProdigyPath = defaultMothershipRemoteProdigyPath();

  MothershipProdigyCluster testLocal = {};
  testLocal.name = "test-local"_ctv;
  testLocal.deploymentMode = MothershipClusterDeploymentMode::test;
  testLocal.nBrains = 2;
  testLocal.test.specified = true;
  testLocal.test.workspaceRoot = "/tmp/nametag-test-local"_ctv;
  testLocal.test.machineCount = 3;
  testLocal.test.storageDeviceCount = 2;
  testLocal.test.storageDeviceMB = 768;
  testLocal.test.brainBootstrapFamily = MothershipClusterTestBootstrapFamily::private6;
  testLocal.test.enableFakeIpv4Boundary = false;
  testLocal.sharedCPUOvercommitPermille = 1250;
  testLocal.bgp.specified = true;
  testLocal.bgp.config.enabled = false;
  testLocal.desiredEnvironment = ProdigyEnvironmentKind::dev;

  MothershipProdigyCluster storedTestLocal = testLocal;
  storedTestLocal.architecture = nametagCurrentBuildMachineArchitecture();
  storedTestLocal.includeLocalMachine = false;
  mothershipResolveTestClusterControlRecord(storedTestLocal.controls, storedTestLocal);


  MothershipProdigyCluster invalidLocalProvider = local;
  invalidLocalProvider.name = "local-invalid"_ctv;
  invalidLocalProvider.provider = MothershipClusterProvider::aws;

  MothershipProdigyCluster invalidLocalAdoptedProvider = localAdopted;
  invalidLocalAdoptedProvider.name = "local-adopted-provider-invalid"_ctv;
  invalidLocalAdoptedProvider.provider = MothershipClusterProvider::aws;

  MothershipProdigyCluster invalidLocalAdoptedMissingMachines = localAdopted;
  invalidLocalAdoptedMissingMachines.name = "local-adopted-missing-machines"_ctv;
  invalidLocalAdoptedMissingMachines.machines.clear();

  MothershipProdigyCluster invalidLocalAdoptedBootstrapUser = localAdopted;
  invalidLocalAdoptedBootstrapUser.name = "local-adopted-bootstrap-user-invalid"_ctv;
  invalidLocalAdoptedBootstrapUser.bootstrapSshUser = "ubuntu"_ctv;

  MothershipProdigyCluster invalidLocalAdoptedCapacity = localAdopted;
  invalidLocalAdoptedCapacity.name = "local-adopted-capacity"_ctv;
  invalidLocalAdoptedCapacity.nBrains = 4;

  MothershipProdigyCluster invalidRemoteMissingCredential = {};
  invalidRemoteMissingCredential.name = "remote-missing-credential"_ctv;
  invalidRemoteMissingCredential.deploymentMode = MothershipClusterDeploymentMode::remote;
  invalidRemoteMissingCredential.provider = MothershipClusterProvider::aws;
  invalidRemoteMissingCredential.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/missing-api.sock"_ctv});
  appendClusterMachineConfig(invalidRemoteMissingCredential, MachineConfig {
                                                                 .kind = MachineConfig::MachineKind::vm,
                                                                 .slug = "aws-brain-vm"_ctv,
                                                                 .vmImageURI = "ami://aws-brain"_ctv,
                                                                 .nLogicalCores = 4,
                                                                 .nMemoryMB = 16'384,
                                                                 .nStorageMB = 131'072});
  invalidRemoteMissingCredential.nBrains = 1;
  appendMachineSchema(invalidRemoteMissingCredential, MothershipProdigyClusterMachineSchema {
                                                          .schema = "aws-brain-vm"_ctv,
                                                          .kind = MachineConfig::MachineKind::vm,
                                                          .lifetime = MachineLifetime::reserved,
                                                          .providerMachineType = "c7i.large"_ctv,
                                                          .budget = 1});
  setRemoteClusterArchitecture(invalidRemoteMissingCredential, MachineCpuArchitecture::x86_64);
  invalidRemoteMissingCredential.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
  invalidRemoteMissingCredential.desiredEnvironment = ProdigyEnvironmentKind::aws;

  MothershipProdigyCluster invalidRemoteBootstrapUser = remoteCreated;
  invalidRemoteBootstrapUser.name = "remote-bootstrap-user-invalid"_ctv;
  invalidRemoteBootstrapUser.bootstrapSshUser = "ubuntu"_ctv;

  MothershipProdigyCluster invalidRemoteMissingShape = remoteCreated;
  invalidRemoteMissingShape.name = "remote-missing-shape"_ctv;
  invalidRemoteMissingShape.machines.clear();
  invalidRemoteMissingShape.machineSchemas.clear();

  MothershipProdigyCluster invalidRemoteMissingPropagation = remoteCreated;
  invalidRemoteMissingPropagation.name = "remote-missing-instance-profile"_ctv;
  invalidRemoteMissingPropagation.aws.instanceProfileName.reset();

  MothershipProdigyCluster invalidRemoteMissingProviderMachineType = remoteCreated;
  invalidRemoteMissingProviderMachineType.name = "remote-missing-provider-machine-type"_ctv;
  if (invalidRemoteMissingProviderMachineType.machineSchemas.size() > 0)
  {
    invalidRemoteMissingProviderMachineType.machineSchemas[0].providerMachineType.reset();
  }

  MothershipProdigyCluster invalidRemoteAwsPropagation = remoteCreated;
  invalidRemoteAwsPropagation.name = "managed-aws-propagation-invalid"_ctv;
  invalidRemoteAwsPropagation.propagateProviderCredentialToProdigy = true;

  MothershipProdigyCluster invalidRemoteGcpMissingServiceAccount = remoteManagedGcp;
  invalidRemoteGcpMissingServiceAccount.name = "managed-gcp-missing-service-account"_ctv;
  invalidRemoteGcpMissingServiceAccount.gcp.serviceAccountEmail.reset();

  MothershipProdigyCluster invalidRemoteGcpPropagation = remoteManagedGcp;
  invalidRemoteGcpPropagation.name = "managed-gcp-propagation-invalid"_ctv;
  invalidRemoteGcpPropagation.propagateProviderCredentialToProdigy = true;

  MothershipProdigyCluster invalidRemoteGcpSharedTemplate = remoteManagedGcp;
  invalidRemoteGcpSharedTemplate.name = "managed-gcp-shared-template-invalid"_ctv;
  invalidRemoteGcpSharedTemplate.machineSchemas[0].gcpInstanceTemplate = "shared-template"_ctv;
  invalidRemoteGcpSharedTemplate.machineSchemas[1].gcpInstanceTemplateSpot = "shared-template"_ctv;

  MothershipProdigyCluster invalidNonGcpWithGcpConfig = remoteCreated;
  invalidNonGcpWithGcpConfig.name = "managed-aws-with-gcp-config"_ctv;
  invalidNonGcpWithGcpConfig.gcp.serviceAccountEmail = "prodigy-brain@prod-cluster.iam.gserviceaccount.com"_ctv;

  MothershipProdigyCluster invalidRemoteOwnedLifetime = remoteCreated;
  invalidRemoteOwnedLifetime.name = "remote-owned-lifetime"_ctv;
  invalidRemoteOwnedLifetime.machineSchemas[1].lifetime = MachineLifetime::owned;

  MothershipProdigyCluster invalidRemoteBGP = remoteCreated;
  invalidRemoteBGP.name = "remote-bgp-invalid"_ctv;
  invalidRemoteBGP.bgp = localAdopted.bgp;

  MothershipProdigyCluster invalidACMENoDNS = remoteManagedGcp;
  invalidACMENoDNS.name = "remote-acme-no-dns"_ctv;
  invalidACMENoDNS.acme.accountEmail = "ops@example.com"_ctv;
  invalidACMENoDNS.acme.termsAgreed = true;

  MothershipProdigyCluster invalidACMENoTerms = remoteCreated;
  invalidACMENoTerms.name = "remote-acme-no-terms"_ctv;
  invalidACMENoTerms.acme.termsAgreed = false;

  MothershipProdigyCluster invalidACMESystemCertbot = remoteCreated;
  invalidACMESystemCertbot.name = "remote-acme-system-certbot"_ctv;
  invalidACMESystemCertbot.acme.certbotInstall = "system"_ctv;

  MothershipProdigyCluster remoteVultrBGP = remoteCreated;
  remoteVultrBGP.name = "remote-vultr-bgp"_ctv;
  remoteVultrBGP.provider = MothershipClusterProvider::vultr;
  remoteVultrBGP.providerCredentialName = "vultr-prod"_ctv;
  remoteVultrBGP.providerScope = "ewr"_ctv;
  remoteVultrBGP.aws = {};
  remoteVultrBGP.propagateProviderCredentialToProdigy = true;
  remoteVultrBGP.providerManagedBGP = true;
  remoteVultrBGP.bgpAuthorizedOriginPrefixes.push_back(IPPrefix("2602:fac0::", true, 40));
  remoteVultrBGP.desiredEnvironment = ProdigyEnvironmentKind::vultr;
  remoteVultrBGP.lastRefreshMs = 0;

  suite.expect(mothershipClusterUsesProviderManagedBGP(remoteVultrBGP),
               "remote_vultr_provider_managed_bgp_marker_recognized");

  MothershipProdigyCluster omittedVultrBGP = remoteVultrBGP;
  omittedVultrBGP.providerManagedBGP = false;
  suite.expect(!mothershipClusterUsesProviderManagedBGP(omittedVultrBGP),
               "remote_vultr_provider_managed_bgp_requires_explicit_marker");

  MothershipProdigyCluster staticVultrBGP = remoteVultrBGP;
  staticVultrBGP.bgp = localAdopted.bgp;
  suite.expect(!mothershipClusterUsesProviderManagedBGP(staticVultrBGP),
               "remote_vultr_provider_managed_bgp_rejects_static_field");

  MothershipProdigyCluster unsupportedProviderBGP = remoteVultrBGP;
  unsupportedProviderBGP.provider = MothershipClusterProvider::aws;
  suite.expect(!mothershipClusterUsesProviderManagedBGP(unsupportedProviderBGP),
               "remote_provider_managed_bgp_rejects_unsupported_provider");

  MothershipProdigyCluster localVultrBGP = remoteVultrBGP;
  localVultrBGP.deploymentMode = MothershipClusterDeploymentMode::local;
  suite.expect(!mothershipClusterUsesProviderManagedBGP(localVultrBGP),
               "local_vultr_provider_managed_bgp_not_recognized");

  MothershipProdigyCluster unpropagatedVultrBGP = remoteVultrBGP;
  unpropagatedVultrBGP.propagateProviderCredentialToProdigy = false;
  suite.expect(!mothershipClusterUsesProviderManagedBGP(unpropagatedVultrBGP),
               "remote_vultr_provider_managed_bgp_requires_propagation");

  MothershipProdigyCluster storedRemoteVultrBGP = remoteVultrBGP;
  storedRemoteVultrBGP.includeLocalMachine = false;
  storedRemoteVultrBGP.bootstrapSshUser = defaultMothershipClusterSSHUser();
  storedRemoteVultrBGP.remoteProdigyPath = defaultMothershipRemoteProdigyPath();
  storedRemoteVultrBGP.acme.certbotInstall = "bundle"_ctv;
  storedRemoteVultrBGP.acme.certbotPath = "/opt/prodigy/certbot/bin/certbot"_ctv;
  storedRemoteVultrBGP.acme.certbotVersion = "5.6.0"_ctv;

  MothershipProdigyCluster invalidSharedCPUOvercommit = local;
  invalidSharedCPUOvercommit.name = "local-invalid-overcommit"_ctv;
  invalidSharedCPUOvercommit.sharedCPUOvercommitPermille = 999;

  MothershipProdigyCluster invalidOSUpdatesEnabledWithoutPolicies = local;
  invalidOSUpdatesEnabledWithoutPolicies.name = "local-os-updates-without-policies"_ctv;
  invalidOSUpdatesEnabledWithoutPolicies.osUpdatesEnabled = true;
  invalidOSUpdatesEnabledWithoutPolicies.osUpdatePolicies.clear();

  MothershipProdigyCluster invalidTestProvider = testLocal;
  invalidTestProvider.name = "test-provider-invalid"_ctv;
  invalidTestProvider.provider = MothershipClusterProvider::aws;

  MothershipProdigyCluster invalidTestControls = testLocal;
  invalidTestControls.name = "test-controls-invalid"_ctv;
  invalidTestControls.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/tmp/manual.sock"_ctv});

  MothershipProdigyCluster invalidTestMachineCount = testLocal;
  invalidTestMachineCount.name = "test-machine-count-invalid"_ctv;
  invalidTestMachineCount.test.machineCount = 1;

  MothershipProdigyCluster invalidTestSpareCount = testLocal;
  invalidTestSpareCount.name = "test-spare-count-invalid"_ctv;
  invalidTestSpareCount.test.spareMachineCount = 2;

  MothershipProdigyCluster invalidTestSpareCapacity = testLocal;
  invalidTestSpareCapacity.name = "test-spare-capacity-invalid"_ctv;
  invalidTestSpareCapacity.test.machineCount = 2;
  invalidTestSpareCapacity.test.spareMachineCount = 1;
  invalidTestSpareCapacity.test.storageDeviceCount = 0;

  MothershipProdigyCluster invalidNonTestWithTestConfig = local;
  invalidNonTestWithTestConfig.name = "local-with-test-config"_ctv;
  invalidNonTestWithTestConfig.test.specified = true;
  invalidNonTestWithTestConfig.test.workspaceRoot = "/tmp/not-allowed"_ctv;
  invalidNonTestWithTestConfig.test.machineCount = 1;

  MothershipProdigyCluster invalidRemoteMixedCapacity = {};
  invalidRemoteMixedCapacity.name = "remote-mixed-invalid"_ctv;
  invalidRemoteMixedCapacity.deploymentMode = MothershipClusterDeploymentMode::remote;
  invalidRemoteMixedCapacity.provider = MothershipClusterProvider::azure;
  invalidRemoteMixedCapacity.providerCredentialName = "azure-prod"_ctv;
  invalidRemoteMixedCapacity.providerScope = "subscriptions/sub-prod/resourceGroups/rg-prod/locations/westus"_ctv;
  invalidRemoteMixedCapacity.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/hybrid-invalid.sock"_ctv});
  appendClusterMachineConfig(invalidRemoteMixedCapacity, MachineConfig {
                                                             .kind = MachineConfig::MachineKind::vm,
                                                             .slug = "azure-brain-vm"_ctv,
                                                             .vmImageURI = "image://azure-brain"_ctv,
                                                             .nLogicalCores = 4,
                                                             .nMemoryMB = 16'384,
                                                             .nStorageMB = 131'072});
  invalidRemoteMixedCapacity.nBrains = 4;
  invalidRemoteMixedCapacity.bootstrapSshPrivateKeyPath = "/root/.ssh/hybrid"_ctv;
  assignFixtureBootstrapSSHKeyPackage(invalidRemoteMixedCapacity);
  appendMachineSchema(invalidRemoteMixedCapacity, MothershipProdigyClusterMachineSchema {
                                                      .schema = "azure-brain-vm"_ctv,
                                                      .kind = MachineConfig::MachineKind::vm,
                                                      .lifetime = MachineLifetime::reserved,
                                                      .providerMachineType = "Standard_D4s_v5"_ctv,
                                                      .budget = 1});
  setRemoteClusterArchitecture(invalidRemoteMixedCapacity, MachineCpuArchitecture::x86_64);
  invalidRemoteMixedCapacity.machines.push_back(MothershipProdigyClusterMachine {
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::cloud,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .isBrain = true,
      .cloud = ClusterMachineCloud {
                                    .schema = "azure-brain-vm"_ctv,
                                    .providerMachineType = "Standard_D4s_v5"_ctv,
                                    .cloudID = "874563210000111"_ctv},
      .ssh = makeMachineSSH("203.0.113.44"_ctv, 22, "azureuser"_ctv, "/root/.ssh/hybrid"_ctv),
      .addresses = makeMachineAddresses("10.1.0.4"_ctv, "203.0.113.44"_ctv),
      .ownership = ClusterMachineOwnership {.mode = ClusterMachineOwnershipMode::wholeMachine}
  });

  {
    Vector<MothershipProdigyClusterMachineSchema> machineSchemas = {};
    String schemaFailure = {};
    bool createdSchema = false;
    MothershipProdigyClusterMachineSchemaPatch patch = {};
    patch.schema = "schema-a"_ctv;
    patch.hasKind = true;
    patch.kind = MachineConfig::MachineKind::vm;
    patch.hasLifetime = true;
    patch.lifetime = MachineLifetime::reserved;
    patch.hasProviderMachineType = true;
    patch.providerMachineType = "c7i.large"_ctv;
    patch.hasRegion = true;
    patch.region = "us-east-1"_ctv;
    patch.hasZone = true;
    patch.zone = "us-east-1a"_ctv;
    patch.hasBudget = true;
    patch.budget = 3;
    suite.expect(mothershipUpsertClusterMachineSchema(machineSchemas, patch, &createdSchema, &schemaFailure), "machine_schema_upsert_create");
    suite.expect(createdSchema, "machine_schema_upsert_create_marks_created");
    suite.expect(machineSchemas.size() == 1, "machine_schema_upsert_create_size");
    suite.expect(machineSchemas[0].budget == 3, "machine_schema_upsert_create_budget");

    patch = {};
    patch.schema = "schema-a"_ctv;
    patch.hasZone = true;
    patch.zone = "us-east-1b"_ctv;
    suite.expect(mothershipUpsertClusterMachineSchema(machineSchemas, patch, &createdSchema, &schemaFailure), "machine_schema_upsert_partial");
    suite.expect(createdSchema == false, "machine_schema_upsert_partial_not_created");
    suite.expect(machineSchemas[0].zone.equals("us-east-1b"_ctv), "machine_schema_upsert_partial_zone_overwritten");
    suite.expect(machineSchemas[0].region.equals("us-east-1"_ctv), "machine_schema_upsert_partial_region_preserved");

    uint32_t finalBudget = 0;
    suite.expect(mothershipDeltaClusterMachineBudget(machineSchemas, "schema-a"_ctv, -99, &finalBudget, &schemaFailure), "machine_schema_delta_clamps");
    suite.expect(finalBudget == 0, "machine_schema_delta_clamps_to_zero");
    suite.expect(machineSchemas[0].budget == 0, "machine_schema_delta_updates_budget");

    bool removedSchema = false;
    suite.expect(mothershipDeleteClusterMachineSchema(machineSchemas, "schema-a"_ctv, &removedSchema, &schemaFailure), "machine_schema_delete");
    suite.expect(removedSchema, "machine_schema_delete_removed");
    suite.expect(machineSchemas.empty(), "machine_schema_delete_empty");
  }
  {
    MothershipClusterRegistry registry(dbPath);
    String failure;
    MothershipProdigyCluster createdCluster = {};

    bool createLocal = registry.createCluster(local, &createdCluster, &failure);
    if (!createLocal)
    {
      basics_log("detail create_local: %s\n", failure.c_str());
    }
    suite.expect(createLocal, "create_local");
    suite.expect(createdCluster.clusterUUID != 0, "create_local_cluster_uuid_generated");
    suite.expect(createdCluster.mothershipConnectivity.kind == MothershipConnectivityKind::ssh, "create_local_defaults_ssh_connectivity");
    suite.expect(createdCluster.mothershipConnectivity.tunnelProvider.artifactSha256.size() == 0, "create_local_default_ssh_has_no_tunnel_artifact");
    storedLocal.clusterUUID = createdCluster.clusterUUID;
    storedLocal.datacenterFragment = createdCluster.datacenterFragment;
    suite.expect(equalClusters(storedLocal, createdCluster), "create_local_normalized");

    bool createRemoteCreated = registry.createCluster(remoteCreated, &createdCluster, &failure);
    if (!createRemoteCreated)
    {
      basics_log("detail create_remote_created: %s\n", failure.c_str());
    }
    suite.expect(createRemoteCreated, "create_remote_created");
    suite.expect(createdCluster.clusterUUID != 0, "create_remote_created_cluster_uuid_generated");
    storedRemoteCreated.clusterUUID = createdCluster.clusterUUID;
    storedRemoteCreated.datacenterFragment = createdCluster.datacenterFragment;
    suite.expect(equalClusters(storedRemoteCreated, createdCluster), "create_remote_created_normalized");

    bool createLocalAdopted = registry.createCluster(localAdopted, &createdCluster, &failure);
    if (!createLocalAdopted)
    {
      basics_log("detail create_local_adopted: %s\n", failure.c_str());
    }
    suite.expect(createLocalAdopted, "create_local_adopted");
    suite.expect(createdCluster.clusterUUID != 0, "create_local_adopted_cluster_uuid_generated");
    storedLocalAdopted.clusterUUID = createdCluster.clusterUUID;
    storedLocalAdopted.datacenterFragment = createdCluster.datacenterFragment;
    suite.expect(equalClusters(storedLocalAdopted, createdCluster), "create_local_adopted_normalized");

    bool createRemoteAdopted = registry.createCluster(remoteAdopted, &createdCluster, &failure);
    if (!createRemoteAdopted)
    {
      basics_log("detail create_remote_adopted: %s\n", failure.c_str());
    }
    suite.expect(createRemoteAdopted, "create_remote_adopted");
    suite.expect(createdCluster.clusterUUID != 0, "create_remote_adopted_cluster_uuid_generated");
    storedRemoteAdopted.clusterUUID = createdCluster.clusterUUID;
    storedRemoteAdopted.datacenterFragment = createdCluster.datacenterFragment;
    suite.expect(equalClusters(storedRemoteAdopted, createdCluster), "create_remote_adopted_normalized");

    bool createRemoteManagedGcp = registry.createCluster(remoteManagedGcp, &createdCluster, &failure);
    if (!createRemoteManagedGcp)
    {
      basics_log("detail create_remote_managed_gcp: %s\n", failure.c_str());
    }
    suite.expect(createRemoteManagedGcp, "create_remote_managed_gcp");
    suite.expect(createdCluster.clusterUUID != 0, "create_remote_managed_gcp_cluster_uuid_generated");
    storedRemoteManagedGcp.clusterUUID = createdCluster.clusterUUID;
    storedRemoteManagedGcp.datacenterFragment = createdCluster.datacenterFragment;
    {
      String templateBase = {};
      renderExpectedManagedGcpTemplateBase(storedRemoteManagedGcp, templateBase);
      storedRemoteManagedGcp.machineSchemas[0].gcpInstanceTemplate.snprintf<"{}-standard"_ctv>(templateBase);
      storedRemoteManagedGcp.machineSchemas[1].gcpInstanceTemplateSpot.snprintf<"{}-spot"_ctv>(templateBase);
      suite.expect(storedRemoteManagedGcp.machineSchemas[0].gcpInstanceTemplate.size() <= 63, "create_remote_managed_gcp_standard_template_length");
      suite.expect(storedRemoteManagedGcp.machineSchemas[1].gcpInstanceTemplateSpot.size() <= 63, "create_remote_managed_gcp_spot_template_length");
    }
    suite.expect(equalClusters(storedRemoteManagedGcp, createdCluster), "create_remote_managed_gcp_normalized");

    bool createRemoteMixed = registry.createCluster(remoteMixed, &createdCluster, &failure);
    if (!createRemoteMixed)
    {
      basics_log("detail create_remote_mixed: %s\n", failure.c_str());
    }
    suite.expect(createRemoteMixed, "create_remote_mixed");
    suite.expect(createdCluster.clusterUUID != 0, "create_remote_mixed_cluster_uuid_generated");
    storedRemoteMixed.clusterUUID = createdCluster.clusterUUID;
    storedRemoteMixed.datacenterFragment = createdCluster.datacenterFragment;
    storedRemoteMixed.azure.managedIdentityName.snprintf<"prodigy-{itoa}-azure-mi"_ctv>(uint64_t(storedRemoteMixed.clusterUUID));
    storedRemoteMixed.azure.managedIdentityResourceID.snprintf<
        "/subscriptions/sub-prod/resourceGroups/rg-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{}"_ctv>(
        storedRemoteMixed.azure.managedIdentityName);
    suite.expect(equalClusters(storedRemoteMixed, createdCluster), "create_remote_mixed_normalized");

    bool createTestLocal = registry.createCluster(testLocal, &createdCluster, &failure);
    if (!createTestLocal)
    {
      basics_log("detail create_test_local: %s\n", failure.c_str());
    }
    suite.expect(createTestLocal, "create_test_local");
    suite.expect(createdCluster.clusterUUID != 0, "create_test_local_cluster_uuid_generated");
    storedTestLocal.clusterUUID = createdCluster.clusterUUID;
    storedTestLocal.datacenterFragment = createdCluster.datacenterFragment;
    mothershipResolveTestClusterControlRecord(storedTestLocal.controls, storedTestLocal);
    suite.expect(equalClusters(storedTestLocal, createdCluster), "create_test_local_normalized");

    MothershipProdigyCluster secondTestLocal = testLocal;
    secondTestLocal.name = "test-local-second"_ctv;
    secondTestLocal.test.workspaceRoot = "/tmp/nametag-test-local-second"_ctv;
    MothershipProdigyCluster storedSecondTestLocal = {};
    bool createSecondTestLocal = registry.createCluster(secondTestLocal, &storedSecondTestLocal, &failure);
    suite.expect(createSecondTestLocal, "create_second_test_local");
    suite.expect(storedSecondTestLocal.datacenterFragment != 0 &&
                     storedSecondTestLocal.datacenterFragment != storedTestLocal.datacenterFragment,
                 "create_second_test_local_allocates_distinct_network_fragment");
    String secondControlSocketPath = {};
    mothershipResolveTestClusterControlSocketPath(storedSecondTestLocal, secondControlSocketPath);
    suite.expect(secondControlSocketPath != storedTestLocal.controls[0].path,
                 "create_second_test_local_uses_distinct_provider_control_path");
    Vector<MothershipProdigyClusterControl> expectedSecondTestControls = {};
    mothershipResolveTestClusterControlRecord(expectedSecondTestControls, storedSecondTestLocal);
    suite.expect(equalControls(storedSecondTestLocal.controls, expectedSecondTestControls),
                 "create_second_test_local_persists_fragment_resolved_controls");

    {
      String globalLeaseDbPath = {};
      globalLeaseDbPath.snprintf<"{}/global-datacenter-fragments"_ctv>(dbPath);
      MothershipClusterRegistry globalLeaseRegistry(globalLeaseDbPath);
      MothershipProdigyCluster ewr = remoteCreated;
      ewr.name = "vultr-ewr"_ctv;
      ewr.providerScope = "vultr/ewr"_ctv;
      ewr.datacenterFragment = 47;
      MothershipProdigyCluster storedEwr = {};
      suite.expect(globalLeaseRegistry.createCluster(ewr, &storedEwr, &failure),
                   "global_datacenter_fragment_create_vultr_ewr");

      MothershipProdigyCluster ord = remoteCreated;
      ord.name = "vultr-ord"_ctv;
      ord.providerScope = "vultr/ord"_ctv;
      ord.datacenterFragment = 0;
      MothershipProdigyCluster storedOrd = {};
      suite.expect(globalLeaseRegistry.createCluster(ord, &storedOrd, &failure),
                   "global_datacenter_fragment_auto_allocates_vultr_ord");

      MothershipProdigyCluster lan = remoteCreated;
      lan.name = "retained-lan"_ctv;
      lan.providerScope = "retained/lan"_ctv;
      MothershipProdigyCluster storedLan = {};
      suite.expect(globalLeaseRegistry.createCluster(lan, &storedLan, &failure),
                   "global_datacenter_fragment_auto_allocates_retained_lan_default");
      suite.expect(storedEwr.datacenterFragment != 0 &&
                       storedEwr.datacenterFragment != storedOrd.datacenterFragment &&
                       storedEwr.datacenterFragment != storedLan.datacenterFragment &&
                       storedOrd.datacenterFragment != storedLan.datacenterFragment,
                   "global_datacenter_fragment_remote_sites_are_unique");

      MothershipProdigyCluster testCollision = testLocal;
      testCollision.name = "test-collides-with-ewr"_ctv;
      testCollision.test.workspaceRoot = "/tmp/prodigy-test-collides-with-ewr"_ctv;
      testCollision.datacenterFragment = storedEwr.datacenterFragment;
      suite.expect(!globalLeaseRegistry.createCluster(testCollision, nullptr, &failure) &&
                       failure.equals("cluster datacenter fragment already leased"_ctv),
                   "global_datacenter_fragment_rejects_remote_test_collision");

      MothershipProdigyCluster changedEwr = storedEwr;
      changedEwr.datacenterFragment = storedLan.datacenterFragment;
      changedEwr.lastRefreshMs = 444;
      MothershipProdigyCluster persistedEwr = {};
      suite.expect(globalLeaseRegistry.upsertCluster(changedEwr, &persistedEwr, &failure) &&
                       persistedEwr.datacenterFragment == storedEwr.datacenterFragment &&
                       persistedEwr.lastRefreshMs == 444,
                   "global_datacenter_fragment_existing_lease_is_immutable");
      MothershipProdigyCluster reloadedEwr = {};
      suite.expect(globalLeaseRegistry.getCluster("vultr-ewr"_ctv, reloadedEwr, &failure) &&
                       reloadedEwr.datacenterFragment == storedEwr.datacenterFragment &&
                       reloadedEwr.lastRefreshMs == 444,
                   "global_datacenter_fragment_existing_lease_persists");
    }

    MothershipProdigyCluster duplicateTestWorkspace = testLocal;
    duplicateTestWorkspace.name = "test-local-duplicate-workspace"_ctv;
    suite.expect(!registry.createCluster(duplicateTestWorkspace, nullptr, &failure),
                 "create_test_duplicate_workspace_rejected");
    suite.expect(failure.equals("test workspace overlaps another cluster"_ctv),
                 "create_test_duplicate_workspace_reason");

    duplicateTestWorkspace.test.workspaceRoot.append("/child"_ctv);
    suite.expect(!registry.createCluster(duplicateTestWorkspace, nullptr, &failure),
                 "create_test_nested_workspace_rejected");
    suite.expect(failure.equals("test workspace overlaps another cluster"_ctv),
                 "create_test_nested_workspace_reason");
    {
      String isolatedRegistryPath = {};
      isolatedRegistryPath.snprintf<"{}/fake-boundary-overlap"_ctv>(dbPath);
      MothershipClusterRegistry isolatedRegistry(isolatedRegistryPath);
      MothershipProdigyCluster isolatedFake = testLocal;
      isolatedFake.test.workspaceRoot = "/tmp/prodigy-fake-boundary/owner/child"_ctv;
      isolatedFake.test.enableFakeIpv4Boundary = true;
      suite.expect(isolatedRegistry.createCluster(isolatedFake, nullptr, &failure),
                   "create_isolated_fake_boundary");
      MothershipProdigyCluster contender = secondTestLocal;
      contender.test.workspaceRoot = "/tmp/prodigy-fake-boundary/owner"_ctv;
      suite.expect(!isolatedRegistry.createCluster(contender, nullptr, &failure) &&
                       failure.equals("test workspace overlaps another cluster"_ctv),
                   "create_test_ancestor_workspace_rejected");
      contender.test.workspaceRoot = "/tmp/prodigy-without-fake-boundary"_ctv;
      suite.expect(!isolatedRegistry.createCluster(contender, nullptr, &failure) &&
                       failure.equals("test fake IPv4 boundary is single-tenant until its public boundary domain is virtualized"_ctv),
                   "create_normal_test_with_existing_fake_boundary_rejected");
    }

    MothershipProdigyCluster fakeBoundaryTest = secondTestLocal;
    fakeBoundaryTest.name = "test-fake-boundary"_ctv;
    fakeBoundaryTest.test.workspaceRoot = "/tmp/test-fake-boundary"_ctv;
    fakeBoundaryTest.test.enableFakeIpv4Boundary = true;
    suite.expect(!registry.createCluster(fakeBoundaryTest, nullptr, &failure),
                 "create_test_fake_boundary_with_existing_cluster_rejected");
    suite.expect(failure.equals("test fake IPv4 boundary is single-tenant until its public boundary domain is virtualized"_ctv),
                 "create_test_fake_boundary_with_existing_cluster_reason");

    MothershipProdigyCluster enableExistingFakeBoundary = storedTestLocal;
    enableExistingFakeBoundary.test.enableFakeIpv4Boundary = true;
    suite.expect(!registry.upsertCluster(enableExistingFakeBoundary, nullptr, &failure),
                 "update_test_enable_shared_fake_boundary_rejected");
    suite.expect(failure.equals("test fake IPv4 boundary is single-tenant until its public boundary domain is virtualized"_ctv),
                 "update_test_enable_shared_fake_boundary_reason");

    MothershipProdigyCluster updatedSecondTestLocal = storedSecondTestLocal;
    updatedSecondTestLocal.lastRefreshMs = 848'484;
    updatedSecondTestLocal.datacenterFragment = storedTestLocal.datacenterFragment;
    suite.expect(registry.upsertCluster(updatedSecondTestLocal, &updatedSecondTestLocal, &failure),
                 "update_test_preserves_network_fragment");
    suite.expect(updatedSecondTestLocal.datacenterFragment == storedSecondTestLocal.datacenterFragment,
                 "update_test_cannot_replace_allocated_fragment");
    Vector<MothershipProdigyClusterControl> expectedUpdatedSecondTestControls = {};
    mothershipResolveTestClusterControlRecord(expectedUpdatedSecondTestControls, updatedSecondTestLocal);
    suite.expect(equalControls(updatedSecondTestLocal.controls, expectedUpdatedSecondTestControls),
                 "update_test_retains_fragment_resolved_controls");

    MothershipProdigyCluster duplicateRemoteUUID = remoteCreated;
    duplicateRemoteUUID.name = "managed-aws-duplicate-uuid"_ctv;
    duplicateRemoteUUID.clusterUUID = storedRemoteCreated.clusterUUID;
    bool createDuplicateUUID = registry.createCluster(duplicateRemoteUUID, nullptr, &failure);
    suite.expect(createDuplicateUUID == false, "create_duplicate_cluster_uuid_rejected");
    suite.expect(failure.equals("clusterUUID already exists"_ctv), "create_duplicate_cluster_uuid_reason");

    MothershipProdigyCluster duplicateMachineIdentity = remoteAdopted;
    duplicateMachineIdentity.name = "adopted-gcp-duplicate-machine"_ctv;
    bool createDuplicateMachineIdentity = registry.createCluster(duplicateMachineIdentity, nullptr, &failure);
    suite.expect(createDuplicateMachineIdentity == false, "create_duplicate_machine_identity_rejected");
    suite.expect(stringContains(failure, "already belongs to cluster 'adopted-gcp'"), "create_duplicate_machine_identity_reason");

    MothershipProdigyCluster duplicateMachineAddress = remoteAdopted;
    duplicateMachineAddress.name = "adopted-gcp-duplicate-address"_ctv;
    duplicateMachineAddress.machines[0].cloud.cloudID = "789654123009999"_ctv;
    bool createDuplicateMachineAddress = registry.createCluster(duplicateMachineAddress, nullptr, &failure);
    suite.expect(createDuplicateMachineAddress == false, "create_duplicate_machine_address_rejected");
    suite.expect(stringContains(failure, "already belongs to cluster 'adopted-gcp'"), "create_duplicate_machine_address_reason");

    MothershipProdigyCluster duplicateIdentityWithinCluster = localAdopted;
    duplicateIdentityWithinCluster.name = "local-homelab-duplicate-identity"_ctv;
    duplicateIdentityWithinCluster.machines[1] = duplicateIdentityWithinCluster.machines[0];
    duplicateIdentityWithinCluster.machines[1].ssh.privateKeyPath = "/tmp/duplicate"_ctv;
    bool createDuplicateIdentityWithinCluster = registry.createCluster(duplicateIdentityWithinCluster, nullptr, &failure);
    suite.expect(createDuplicateIdentityWithinCluster == false, "create_duplicate_identity_within_cluster_rejected");
    suite.expect(stringContains(failure, "cluster machines contain duplicate identity"), "create_duplicate_identity_within_cluster_reason");

    MothershipProdigyCluster refreshedRemoteAdopted = storedRemoteAdopted;
    refreshedRemoteAdopted.lastRefreshMs = 424'242;
    bool upsertExistingRemoteAdopted = registry.upsertCluster(refreshedRemoteAdopted, &refreshedRemoteAdopted, &failure);
    suite.expect(upsertExistingRemoteAdopted, "upsert_existing_remote_adopted");
    suite.expect(refreshedRemoteAdopted.lastRefreshMs == 424'242, "upsert_existing_remote_adopted_refresh_ms");
    storedRemoteAdopted = refreshedRemoteAdopted;

    MothershipProdigyCluster initialDNSACMEEnabled = {};
    bool enableInitialDNSACME = registry.enableInitialDNSACME(
        storedRemoteAdopted.name,
        storedRemoteCreated.dnsProvider,
        storedRemoteCreated.dnsProviderCredentialName,
        storedRemoteCreated.acme,
        &initialDNSACMEEnabled,
        &failure);
    suite.expect(enableInitialDNSACME, "enable_initial_dns_acme_for_existing_unconfigured_cluster");
    suite.expect(initialDNSACMEEnabled.dnsProvider == storedRemoteCreated.dnsProvider &&
                     initialDNSACMEEnabled.dnsProviderCredentialName.equals(storedRemoteCreated.dnsProviderCredentialName) &&
                     initialDNSACMEEnabled.acme == storedRemoteCreated.acme,
                 "enable_initial_dns_acme_persists_complete_identity");
    storedRemoteAdopted = initialDNSACMEEnabled;
    MothershipProdigyCluster repeatedDNSACMEEnablement = {};
    suite.expect(!registry.enableInitialDNSACME(storedRemoteAdopted.name,
                                                 storedRemoteCreated.dnsProvider,
                                                 storedRemoteCreated.dnsProviderCredentialName,
                                                 storedRemoteCreated.acme,
                                                 &repeatedDNSACMEEnablement,
                                                 &failure) &&
                     failure.equals("cluster DNS/ACME is already configured"_ctv),
                 "enable_initial_dns_acme_rejects_second_change");
    MothershipProdigyCluster ordinaryInitialDNSACME = storedSecondTestLocal;
    ordinaryInitialDNSACME.dnsProvider = storedRemoteCreated.dnsProvider;
    ordinaryInitialDNSACME.dnsProviderCredentialName = storedRemoteCreated.dnsProviderCredentialName;
    ordinaryInitialDNSACME.acme = storedRemoteCreated.acme;
    suite.expect(!registry.upsertCluster(ordinaryInitialDNSACME, nullptr, &failure) &&
                     failure.equals("dnsProvider is immutable for an existing cluster"_ctv),
                 "ordinary_upsert_cannot_enable_initial_dns_acme");
    MothershipProdigyCluster incompleteDNSACMEEnablement = {};
    ProdigyACMEConfig noACME = {};
    suite.expect(!registry.enableInitialDNSACME(storedSecondTestLocal.name,
                                                 MothershipClusterProvider::cloudflare,
                                                 "cloudflare-prod"_ctv,
                                                 noACME,
                                                 &incompleteDNSACMEEnablement,
                                                 &failure) &&
                     failure.equals("initial DNS/ACME enablement requires complete DNS and ACME configuration"_ctv),
                 "enable_initial_dns_acme_rejects_partial_identity");

    MothershipProdigyCluster changedDNSProvider = storedRemoteCreated;
    changedDNSProvider.dnsProvider = MothershipClusterProvider::route53;
    changedDNSProvider.dnsProviderCredentialName = "route53-prod"_ctv;
    bool upsertChangedDNSProvider = registry.upsertCluster(changedDNSProvider, nullptr, &failure);
    suite.expect(upsertChangedDNSProvider == false, "upsert_existing_dns_provider_change_rejected");
    suite.expect(failure.equals("dnsProvider is immutable for an existing cluster"_ctv), "upsert_existing_dns_provider_change_reason");

    MothershipProdigyCluster changedDNSCredential = storedRemoteCreated;
    changedDNSCredential.dnsProviderCredentialName = "cloudflare-rotated"_ctv;
    bool upsertChangedDNSCredential = registry.upsertCluster(changedDNSCredential, nullptr, &failure);
    suite.expect(upsertChangedDNSCredential, "upsert_existing_dns_credential_change_allowed");
    storedRemoteCreated = changedDNSCredential;

    MothershipProdigyCluster changedACME = storedRemoteCreated;
    changedACME.acme.accountEmail = "security@example.com"_ctv;
    bool upsertChangedACME = registry.upsertCluster(changedACME, nullptr, &failure);
    suite.expect(upsertChangedACME == false, "upsert_existing_acme_change_rejected");
    suite.expect(failure.equals("acme config is immutable for an existing cluster"_ctv), "upsert_existing_acme_change_reason");

    MothershipProdigyCluster topologyOwner = remoteCreated;
    topologyOwner.name = "topology-owner"_ctv;
    topologyOwner.topology.version = 7;
    topologyOwner.topology.machines.push_back(ClusterMachine {});
    ClusterMachine& topologyClaim = topologyOwner.topology.machines.back();
    topologyClaim.source = ClusterMachineSource::created;
    topologyClaim.backing = ClusterMachineBacking::cloud;
    topologyClaim.kind = MachineConfig::MachineKind::vm;
    topologyClaim.lifetime = MachineLifetime::ondemand;
    topologyClaim.isBrain = true;
    topologyClaim.cloud.schema = "aws-brain-vm"_ctv;
    topologyClaim.cloud.providerMachineType = "c7i.large"_ctv;
    topologyClaim.cloud.cloudID = "topology-owner-claim"_ctv;
    topologyClaim.ssh.address = "44.0.0.44"_ctv;
    topologyClaim.ssh.port = 22;
    topologyClaim.ssh.user = "root"_ctv;
    topologyClaim.ssh.privateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
    topologyClaim.ssh.hostPublicKeyOpenSSH = fixtureSSHDHostPublicKey();
    topologyClaim.addresses = makeMachineAddresses("10.9.0.44"_ctv, "44.0.0.44"_ctv);
    topologyClaim.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
    bool createTopologyOwner = registry.createCluster(topologyOwner, &createdCluster, &failure);
    if (!createTopologyOwner)
    {
      basics_log("detail create_topology_owner: %s\n", failure.c_str());
    }
    suite.expect(createTopologyOwner, "create_topology_owner");

    MothershipProdigyCluster duplicateTopologyClaim = remoteAdopted;
    duplicateTopologyClaim.name = "duplicate-topology-claim"_ctv;
    duplicateTopologyClaim.nBrains = 1;
    duplicateTopologyClaim.machines.resize(1);
    duplicateTopologyClaim.machines[0].cloud.cloudID = topologyClaim.cloud.cloudID;
    duplicateTopologyClaim.machines[0].ssh = topologyClaim.ssh;
    duplicateTopologyClaim.machines[0].addresses = topologyClaim.addresses;
    bool createDuplicateTopologyClaim = registry.createCluster(duplicateTopologyClaim, nullptr, &failure);
    suite.expect(createDuplicateTopologyClaim == false, "create_duplicate_topology_claim_rejected");
    suite.expect(stringContains(failure, "already belongs to cluster 'topology-owner'"), "create_duplicate_topology_claim_reason");

    bool createLocalProvider = registry.createCluster(invalidLocalProvider, nullptr, &failure);
    suite.expect(createLocalProvider == false, "create_local_provider_rejected");
    suite.expect(failure.equals("local clusters must not include provider"_ctv), "create_local_provider_reason");

    bool createLocalAdoptedProvider = registry.createCluster(invalidLocalAdoptedProvider, nullptr, &failure);
    suite.expect(createLocalAdoptedProvider == false, "create_local_adopted_provider_rejected");
    suite.expect(failure.equals("local clusters must not include provider"_ctv), "create_local_adopted_provider_reason");

    bool createLocalAdoptedMissingMachines = registry.createCluster(invalidLocalAdoptedMissingMachines, nullptr, &failure);
    suite.expect(createLocalAdoptedMissingMachines == false, "create_local_adopted_missing_machines_rejected");
    suite.expect(failure.equals("local clusters without includeLocalMachine require adopted machines"_ctv), "create_local_adopted_missing_machines_reason");

    bool createLocalAdoptedBootstrapUser = registry.createCluster(invalidLocalAdoptedBootstrapUser, nullptr, &failure);
    suite.expect(createLocalAdoptedBootstrapUser == false, "create_local_adopted_bootstrap_user_rejected");
    suite.expect(failure.equals("automatic bootstrap requires bootstrapSshUser=root"_ctv), "create_local_adopted_bootstrap_user_reason");

    bool createLocalAdoptedCapacity = registry.createCluster(invalidLocalAdoptedCapacity, nullptr, &failure);
    suite.expect(createLocalAdoptedCapacity == false, "create_local_adopted_capacity_rejected");
    suite.expect(failure.equals("brain capacity is below nBrains"_ctv), "create_local_adopted_capacity_reason");

    bool createRemoteMissingCredential = registry.createCluster(invalidRemoteMissingCredential, nullptr, &failure);
    suite.expect(createRemoteMissingCredential == false, "create_remote_missing_credential_rejected");
    suite.expect(failure.equals("remote clusters require providerCredentialName"_ctv), "create_remote_missing_credential_reason");

    bool createRemoteBootstrapUser = registry.createCluster(invalidRemoteBootstrapUser, nullptr, &failure);
    suite.expect(createRemoteBootstrapUser == false, "create_remote_bootstrap_user_rejected");
    suite.expect(failure.equals("automatic bootstrap requires bootstrapSshUser=root"_ctv), "create_remote_bootstrap_user_reason");

    bool createRemoteMissingShape = registry.createCluster(invalidRemoteMissingShape, nullptr, &failure);
    suite.expect(createRemoteMissingShape == false, "create_remote_missing_shape_rejected");
    suite.expect(failure.equals("remote clusters require adopted machines or machineSchemas"_ctv), "create_remote_missing_shape_reason");

    bool createRemoteMissingPropagation = registry.createCluster(invalidRemoteMissingPropagation, nullptr, &failure);
    suite.expect(createRemoteMissingPropagation == false, "create_remote_missing_propagation_rejected");
    suite.expect(failure.equals("aws remote machineSchemas require aws.instanceProfileName or aws.instanceProfileArn"_ctv), "create_remote_missing_propagation_reason");

    bool createRemoteMissingProviderMachineType = registry.createCluster(invalidRemoteMissingProviderMachineType, nullptr, &failure);
    suite.expect(createRemoteMissingProviderMachineType == false, "create_remote_missing_provider_machine_type_rejected");
    suite.expect(failure.equals("cluster machineSchemas require providerMachineType"_ctv), "create_remote_missing_provider_machine_type_reason");

    bool createRemoteAwsPropagation = registry.createCluster(invalidRemoteAwsPropagation, nullptr, &failure);
    suite.expect(createRemoteAwsPropagation == false, "create_remote_aws_propagation_rejected");
    suite.expect(failure.equals("aws remote clusters must not propagate provider credentials to Prodigy"_ctv), "create_remote_aws_propagation_reason");

    bool createRemoteGcpMissingServiceAccount = registry.createCluster(invalidRemoteGcpMissingServiceAccount, nullptr, &failure);
    suite.expect(createRemoteGcpMissingServiceAccount == false, "create_remote_gcp_missing_service_account_rejected");
    suite.expect(failure.equals("gcp remote machineSchemas require gcp.serviceAccountEmail"_ctv), "create_remote_gcp_missing_service_account_reason");

    bool createRemoteGcpPropagation = registry.createCluster(invalidRemoteGcpPropagation, nullptr, &failure);
    suite.expect(createRemoteGcpPropagation == false, "create_remote_gcp_propagation_rejected");
    suite.expect(failure.equals("gcp remote clusters must not propagate provider credentials to Prodigy"_ctv), "create_remote_gcp_propagation_reason");

    bool createRemoteGcpSharedTemplate = registry.createCluster(invalidRemoteGcpSharedTemplate, nullptr, &failure);
    suite.expect(createRemoteGcpSharedTemplate == false, "create_remote_gcp_shared_template_rejected");
    suite.expect(failure.equals("gcp standard and spot machineSchemas require distinct template names"_ctv), "create_remote_gcp_shared_template_reason");

    bool createNonGcpWithGcpConfig = registry.createCluster(invalidNonGcpWithGcpConfig, nullptr, &failure);
    suite.expect(createNonGcpWithGcpConfig == false, "create_non_gcp_with_gcp_config_rejected");
    suite.expect(failure.equals("non-gcp clusters must not include gcp config"_ctv), "create_non_gcp_with_gcp_config_reason");

    bool createRemoteOwnedLifetime = registry.createCluster(invalidRemoteOwnedLifetime, nullptr, &failure);
    suite.expect(createRemoteOwnedLifetime == false, "create_remote_owned_lifetime_rejected");
    suite.expect(failure.equals("cluster machineSchemas must not use lifetime=owned"_ctv), "create_remote_owned_lifetime_reason");

    bool createRemoteBGP = registry.createCluster(invalidRemoteBGP, nullptr, &failure);
    suite.expect(createRemoteBGP == false, "create_remote_bgp_rejected");
    suite.expect(failure.equals("remote cluster provider does not support bgp"_ctv), "create_remote_bgp_reason");

    bool createInvalidACMENoDNS = registry.createCluster(invalidACMENoDNS, nullptr, &failure);
    suite.expect(createInvalidACMENoDNS == false, "create_invalid_acme_no_dns_rejected");
    suite.expect(failure.equals("cluster ACME requires cluster DNS"_ctv), "create_invalid_acme_no_dns_reason");

    bool createInvalidACMENoTerms = registry.createCluster(invalidACMENoTerms, nullptr, &failure);
    suite.expect(createInvalidACMENoTerms == false, "create_invalid_acme_no_terms_rejected");
    suite.expect(failure.equals("cluster ACME requires acme.termsAgreed=true"_ctv), "create_invalid_acme_no_terms_reason");

    bool createInvalidACMESystemCertbot = registry.createCluster(invalidACMESystemCertbot, nullptr, &failure);
    suite.expect(createInvalidACMESystemCertbot == false, "create_invalid_acme_system_certbot_rejected");
    suite.expect(failure.equals("cluster ACME certbotInstall must be bundle"_ctv), "create_invalid_acme_system_certbot_reason");

    bool createRemoteVultrBGP = registry.createCluster(remoteVultrBGP, &createdCluster, &failure);
    if (!createRemoteVultrBGP)
    {
      basics_log("detail create_remote_vultr_bgp: %s\n", failure.c_str());
    }
    suite.expect(createRemoteVultrBGP, "create_remote_vultr_bgp");
    suite.expect(createdCluster.clusterUUID != 0, "create_remote_vultr_bgp_cluster_uuid_generated");
    storedRemoteVultrBGP.clusterUUID = createdCluster.clusterUUID;
    storedRemoteVultrBGP.datacenterFragment = createdCluster.datacenterFragment;
    suite.expect(equalClusters(storedRemoteVultrBGP, createdCluster), "create_remote_vultr_bgp_normalized");
    suite.expect(!mothershipProviderBGPOriginPrefixAllowed(IPPrefix("fd5a:4d53:1::", true, 96)) &&
                     !mothershipProviderBGPOriginPrefixAllowed(IPPrefix("fc00::", true, 7)) &&
                     mothershipProviderBGPOriginPrefixAllowed(IPPrefix("203.0.113.0", false, 24)) &&
                     mothershipProviderBGPOriginPrefixAllowed(IPPrefix("2602:fac0::", true, 40)),
                 "provider_bgp_origin_policy_separates_ula_from_public_prefixes");

    MothershipProdigyCluster ulaBGPOrigin = createdCluster;
    ulaBGPOrigin.bgpAuthorizedOriginPrefixes[0] = IPPrefix("fd5a:4d53:1::", true, 96);
    {
      MothershipClusterRegistry::BGPOriginPolicyLock ulaPolicyLock = {};
      suite.expect(registry.lockBGPOriginPolicy(ulaPolicyLock, &failure) &&
                       !registry.upsertClusterBGPOriginPolicy(ulaBGPOrigin, ulaPolicyLock, nullptr, &failure) &&
                       failure.equals("BGP origin authorization prefixes must not be ULA"_ctv),
                   "upsert_rejects_generated_site_ula_bgp_origin_prefix");
    }

    MothershipProdigyCluster duplicateBGPOrigin = createdCluster;
    duplicateBGPOrigin.bgpAuthorizedOriginPrefixes.push_back(
        duplicateBGPOrigin.bgpAuthorizedOriginPrefixes[0]);
    {
      MothershipClusterRegistry::BGPOriginPolicyLock duplicatePolicyLock = {};
      suite.expect(registry.lockBGPOriginPolicy(duplicatePolicyLock, &failure) &&
                       !registry.upsertClusterBGPOriginPolicy(duplicateBGPOrigin, duplicatePolicyLock, nullptr, &failure) &&
                       failure.equals("BGP origin authorization prefixes must be unique"_ctv),
                   "upsert_rejects_duplicate_bgp_origin_prefix");
    }

    MothershipProdigyCluster noncanonicalBGPOrigin = createdCluster;
    noncanonicalBGPOrigin.bgpAuthorizedOriginPrefixes[0] = IPPrefix("2602:fac0::1", true, 40);
    {
      MothershipClusterRegistry::BGPOriginPolicyLock noncanonicalPolicyLock = {};
      suite.expect(registry.lockBGPOriginPolicy(noncanonicalPolicyLock, &failure) &&
                       !registry.upsertClusterBGPOriginPolicy(noncanonicalBGPOrigin, noncanonicalPolicyLock, nullptr, &failure) &&
                       failure.equals("BGP origin authorization prefixes must be canonical"_ctv),
                   "upsert_rejects_noncanonical_bgp_origin_prefix");
    }

    MothershipProdigyCluster disabledBGPOrigin = createdCluster;
    disabledBGPOrigin.providerManagedBGP = false;
    suite.expect(!registry.upsertCluster(disabledBGPOrigin, nullptr, &failure) &&
                     failure.equals("BGP origin authorization requires an enabled BGP configuration and at most 256 prefixes"_ctv),
                 "upsert_rejects_bgp_origin_policy_when_bgp_disabled");

    MothershipProdigyCluster staleOrdinaryUpdate = createdCluster;
    staleOrdinaryUpdate.bgpAuthorizedOriginPrefixes.clear();
    MothershipProdigyCluster preservedOrdinaryUpdate = {};
    suite.expect(registry.upsertCluster(staleOrdinaryUpdate, &preservedOrdinaryUpdate, &failure) &&
                     equalIPPrefixes(preservedOrdinaryUpdate.bgpAuthorizedOriginPrefixes,
                                     createdCluster.bgpAuthorizedOriginPrefixes),
                 "ordinary_upsert_preserves_durable_bgp_origin_policy");

    bool createInvalidSharedCPUOvercommit = registry.createCluster(invalidSharedCPUOvercommit, nullptr, &failure);
    suite.expect(createInvalidSharedCPUOvercommit == false, "create_invalid_shared_cpu_overcommit_rejected");
    suite.expect(failure.equals("sharedCpuOvercommit must be in 1.0..2.0"_ctv), "create_invalid_shared_cpu_overcommit_reason");

    bool createInvalidOSUpdatesEnabledWithoutPolicies = registry.createCluster(invalidOSUpdatesEnabledWithoutPolicies, nullptr, &failure);
    suite.expect(createInvalidOSUpdatesEnabledWithoutPolicies == false, "create_invalid_os_updates_enabled_without_policies_rejected");
    suite.expect(failure.equals("osUpdatesEnabled requires osUpdatePolicies"_ctv), "create_invalid_os_updates_enabled_without_policies_reason");

    bool createTestProvider = registry.createCluster(invalidTestProvider, nullptr, &failure);
    suite.expect(createTestProvider == false, "create_test_provider_rejected");
    suite.expect(failure.equals("test clusters must not include provider"_ctv), "create_test_provider_reason");

    bool createTestControls = registry.createCluster(invalidTestControls, nullptr, &failure);
    suite.expect(createTestControls == false, "create_test_controls_rejected");
    suite.expect(failure.equals("test clusters manage controls automatically"_ctv), "create_test_controls_reason");

    bool createTestMachineCount = registry.createCluster(invalidTestMachineCount, nullptr, &failure);
    suite.expect(createTestMachineCount == false, "create_test_machine_count_rejected");
    suite.expect(failure.equals("test.machineCount minus spareMachineCount is below nBrains"_ctv), "create_test_machine_count_reason");

    bool createTestSpareCount = registry.createCluster(invalidTestSpareCount, nullptr, &failure);
    suite.expect(createTestSpareCount == false, "create_test_spare_count_rejected");
    suite.expect(failure.equals("test.spareMachineCount must be 0 or 1"_ctv), "create_test_spare_count_reason");

    bool createTestSpareCapacity = registry.createCluster(invalidTestSpareCapacity, nullptr, &failure);
    suite.expect(createTestSpareCapacity == false, "create_test_spare_capacity_rejected");
    suite.expect(failure.equals("test.machineCount minus spareMachineCount is below nBrains"_ctv), "create_test_spare_capacity_reason");

    bool createNonTestWithTestConfig = registry.createCluster(invalidNonTestWithTestConfig, nullptr, &failure);
    suite.expect(createNonTestWithTestConfig == false, "create_non_test_with_test_config_rejected");
    suite.expect(failure.equals("non-test clusters must not include test config"_ctv), "create_non_test_with_test_config_reason");

    bool createInvalidRemoteMixedCapacity = registry.createCluster(invalidRemoteMixedCapacity, nullptr, &failure);
    suite.expect(createInvalidRemoteMixedCapacity == false, "create_remote_mixed_capacity_rejected");
    suite.expect(failure.equals("brain capacity is below nBrains"_ctv), "create_remote_mixed_capacity_reason");

    Vector<MothershipProdigyCluster> clusters;
    bool listClusters = registry.listClusters(clusters, &failure);
    if (!listClusters)
    {
      basics_log("detail list_clusters: %s\n", failure.c_str());
    }
    suite.expect(listClusters, "list_clusters");
    suite.expect(clusters.size() == 10, "list_clusters_count");
  }

  {
    constexpr auto v7Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=7\n\n"_ctv;
    String staticDbPath = {};
    staticDbPath.snprintf<"{}/static-v7"_ctv>(dbPath);
    MothershipProdigyClusterRecordV7 staticRecord = {};
    staticRecord.cluster = storedRemoteVultrBGP;
    staticRecord.cluster.providerManagedBGP = false;
    staticRecord.cluster.bgp = localAdopted.bgp;
    staticRecord.internalTransportProfile = staticRecord.cluster.internalTransportProfile;
    staticRecord.bgpAuthorizedOriginPrefixes = staticRecord.cluster.bgpAuthorizedOriginPrefixes;
    for (const auto& machine : staticRecord.cluster.machines)
    {
      staticRecord.adoptedMachineRackUUIDs.push_back(machine.rackUUID);
      staticRecord.adoptedMachineUUIDs.push_back(machine.uuid);
    }
    String payload = {};
    BitseryEngine::serialize(payload, staticRecord);
    String encoded = {};
    encoded.assign(v7Header);
    encoded.append(payload);
    String failure = {};
    {
      TidesDB database(staticDbPath);
      suite.expect(database.write("clusters"_ctv, "static-v7"_ctv, encoded, &failure),
                   "static_bgp_v7_record_written");
    }
    MothershipProdigyCluster loaded = {};
    suite.expect(MothershipClusterRegistry(staticDbPath).getCluster("static-v7"_ctv, loaded, &failure) &&
                     !loaded.providerManagedBGP && mothershipClusterBGPEnabled(loaded) &&
                     mothershipClusterAuthorizesBGPOriginPrefix(loaded, IPPrefix("2602:fac0::", true, 40)),
                 "static_bgp_v7_remains_explicit_static_configuration");
  }

  {
    constexpr auto v8Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=8\n\n"_ctv;
    String encoded = {};
    String failure = {};
    {
      TidesDB database(dbPath);
      suite.expect(database.read("clusters"_ctv, remoteVultrBGP.name, encoded, &failure),
                   "provider_managed_bgp_v8_record_read");
    }
    const bool hasV8Header = encoded.size() >= v8Header.size() &&
        std::memcmp(encoded.data(), v8Header.data(), v8Header.size()) == 0;
    suite.expect(hasV8Header, "provider_managed_bgp_v8_header");

    MothershipProdigyCluster loaded = {};
    suite.expect(MothershipClusterRegistry(dbPath).getCluster(remoteVultrBGP.name, loaded, &failure) &&
                     equalClusters(storedRemoteVultrBGP, loaded),
                 "provider_managed_bgp_v8_roundtrip");
    suite.expect(mothershipClusterAuthorizesBGPOriginPrefix(
                     loaded, IPPrefix("2602:fac0::", true, 40)),
                 "bgp_origin_policy_authorizes_exact_prefix");
    suite.expect(!mothershipClusterAuthorizesBGPOriginPrefix(
                     loaded, IPPrefix("2602:fac0:1::", true, 48)),
                 "bgp_origin_policy_rejects_more_specific_prefix");
    suite.expect(!mothershipClusterAuthorizesBGPOriginPrefix(
                     loaded, IPPrefix("2001:db8::", true, 32)),
                 "bgp_origin_policy_rejects_foreign_prefix");
    suite.expect(mothershipClusterBGPEnabled(loaded) &&
                     mothershipClusterAuthorizesBGPOriginPrefix(
                         loaded, IPPrefix("2602:fac0::", true, 40)),
                 "provider_managed_bgp_authorizes_effective_origin");

    String malformedDbPath = {};
    malformedDbPath.snprintf<"{}/malformed-v8"_ctv>(dbPath);
    auto writeAndRejectV8 = [&](const String& key, MothershipProdigyClusterRecordV8& record) {
      String payload = {};
      BitseryEngine::serialize(payload, record);
      String value = {};
      value.assign(v8Header);
      value.append(payload);
      {
        TidesDB database(malformedDbPath);
        suite.expect(database.write("clusters"_ctv, key, value, &failure),
                     "provider_managed_bgp_malformed_v8_written");
      }
      MothershipProdigyCluster ignored = {};
      return !MothershipClusterRegistry(malformedDbPath).getCluster(key, ignored, &failure);
    };
    auto makeV8 = [&]() {
      MothershipProdigyClusterRecordV8 record = {};
      record.cluster = storedRemoteVultrBGP;
      record.internalTransportProfile = storedRemoteVultrBGP.internalTransportProfile;
      record.spareMachineCount = storedRemoteVultrBGP.test.spareMachineCount;
      for (const auto& machine : storedRemoteVultrBGP.machines)
      {
        record.adoptedMachineRackUUIDs.push_back(machine.rackUUID);
        record.adoptedMachineUUIDs.push_back(machine.uuid);
      }
      record.bgpAuthorizedOriginPrefixes = storedRemoteVultrBGP.bgpAuthorizedOriginPrefixes;
      record.providerManagedBGP = true;
      return record;
    };

    MothershipProdigyClusterRecordV8 duplicate = makeV8();
    duplicate.bgpAuthorizedOriginPrefixes.push_back(duplicate.bgpAuthorizedOriginPrefixes[0]);
    suite.expect(writeAndRejectV8("duplicate-prefix-v8"_ctv, duplicate),
                 "provider_managed_bgp_v8_rejects_duplicate_prefix");

    MothershipProdigyClusterRecordV8 noncanonical = makeV8();
    noncanonical.bgpAuthorizedOriginPrefixes[0] = IPPrefix("2602:fac0::1", true, 40);
    suite.expect(writeAndRejectV8("noncanonical-prefix-v8"_ctv, noncanonical),
                 "provider_managed_bgp_v8_rejects_noncanonical_prefix");

    MothershipProdigyClusterRecordV8 ulaPrefix = makeV8();
    ulaPrefix.bgpAuthorizedOriginPrefixes[0] = IPPrefix("fd5a:4d53:1::", true, 96);
    suite.expect(writeAndRejectV8("ula-prefix-v8"_ctv, ulaPrefix),
                 "provider_managed_bgp_v8_rejects_restored_ula_prefix");

    MothershipProdigyClusterRecordV8 staticBGP = makeV8();
    staticBGP.cluster.bgp = localAdopted.bgp;
    suite.expect(writeAndRejectV8("static-bgp-v8"_ctv, staticBGP),
                 "provider_managed_bgp_v8_rejects_static_bgp");

    MothershipProdigyClusterRecordV8 unsupportedProvider = makeV8();
    unsupportedProvider.cluster.provider = MothershipClusterProvider::aws;
    suite.expect(writeAndRejectV8("unsupported-provider-v8"_ctv, unsupportedProvider),
                 "provider_managed_bgp_v8_rejects_unsupported_provider");

    MothershipProdigyClusterRecordV8 missingPropagation = makeV8();
    missingPropagation.cluster.propagateProviderCredentialToProdigy = false;
    suite.expect(writeAndRejectV8("missing-propagation-v8"_ctv, missingPropagation),
                 "provider_managed_bgp_v8_rejects_missing_propagation");

    MothershipProdigyClusterRecordV8 localDeployment = makeV8();
    localDeployment.cluster.deploymentMode = MothershipClusterDeploymentMode::local;
    suite.expect(writeAndRejectV8("local-deployment-v8"_ctv, localDeployment),
                 "provider_managed_bgp_v8_rejects_local_deployment");

    MothershipProdigyClusterRecordV8 incompatibleEnvironment = makeV8();
    incompatibleEnvironment.cluster.desiredEnvironment = ProdigyEnvironmentKind::dev;
    suite.expect(writeAndRejectV8("incompatible-environment-v8"_ctv, incompatibleEnvironment),
                 "provider_managed_bgp_v8_rejects_incompatible_environment");

    MothershipProdigyClusterRecordV8 falseIntent = makeV8();
    falseIntent.providerManagedBGP = false;
    suite.expect(writeAndRejectV8("false-intent-v8"_ctv, falseIntent),
                 "provider_managed_bgp_v8_rejects_false_intent_tail");

    MothershipProdigyClusterRecordV8 invalidSpare = makeV8();
    invalidSpare.spareMachineCount = 1;
    suite.expect(writeAndRejectV8("invalid-spare-v8"_ctv, invalidSpare),
                 "provider_managed_bgp_v8_rejects_invalid_spare_sidecar");
  }

  {
    constexpr auto v6Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=6\n\n"_ctv;
    String spareDbPath = {};
    spareDbPath.snprintf<"{}/test-spare-v6"_ctv>(dbPath);
    MothershipProdigyCluster spare = testLocal;
    spare.name = "test-spare-v6"_ctv;
    spare.test.workspaceRoot = "/tmp/nametag-test-spare-v6"_ctv;
    spare.test.spareMachineCount = 1;
    spare.test.storageDeviceCount = 0;
    spare.internalTransportProfile = MothershipInternalTransportProfile::aegisX25519V1;
    MothershipProdigyCluster storedSpare = {};
    String failure = {};
    MothershipProdigyCluster unsupportedSpare = spare;
    unsupportedSpare.test.storageDeviceCount = 1;
    suite.expect(!MothershipClusterRegistry(spareDbPath).createCluster(unsupportedSpare, nullptr, &failure), "test_spare_rejects_extra_storage");
    unsupportedSpare.test.storageDeviceCount = 0;
    unsupportedSpare.test.enableFakeIpv4Boundary = true;
    suite.expect(!MothershipClusterRegistry(spareDbPath).createCluster(unsupportedSpare, nullptr, &failure), "test_spare_rejects_fake_boundary");
    suite.expect(MothershipClusterRegistry(spareDbPath).createCluster(spare, &storedSpare, &failure), "create_test_spare_v6");
    suite.expect(storedSpare.test.spareMachineCount == 1, "create_test_spare_preserves_count");
    suite.expect(storedSpare.bootstrapSshUser.equals(defaultMothershipClusterSSHUser()), "create_test_spare_defaults_root_user");
    suite.expect(storedSpare.bootstrapSshPrivateKeyPath.equals(prodigyDefaultBootstrapSSHPrivateKeyPath()), "create_test_spare_defaults_private_path");
    suite.expect(prodigyBootstrapSSHKeyPackageConfigured(storedSpare.bootstrapSshKeyPackage), "create_test_spare_generates_client_key");
    suite.expect(prodigyBootstrapSSHKeyPackageConfigured(storedSpare.bootstrapSshHostKeyPackage), "create_test_spare_generates_host_key");
    suite.expect(storedSpare.remoteProdigyPath.equals(defaultMothershipRemoteProdigyPath()), "create_test_spare_defaults_remote_path");

    String encoded = {};
    {
      TidesDB database(spareDbPath);
      suite.expect(database.read("clusters"_ctv, spare.name, encoded, &failure), "test_spare_v6_record_read");
    }
    const bool hasV6Header = encoded.size() >= v6Header.size() && std::memcmp(encoded.data(), v6Header.data(), v6Header.size()) == 0;
    suite.expect(hasV6Header, "test_spare_v6_header");
    MothershipProdigyCluster loadedSpare = {};
    suite.expect(MothershipClusterRegistry(spareDbPath).getCluster(spare.name, loadedSpare, &failure) && equalClusters(storedSpare, loadedSpare), "test_spare_v6_roundtrip");
    suite.expect(loadedSpare.bgpAuthorizedOriginPrefixes.empty(), "test_spare_v6_defaults_empty_bgp_origin_policy");
    suite.expect(!loadedSpare.providerManagedBGP, "legacy_v6_defaults_provider_managed_bgp_false");

    MothershipProdigyClusterRecordV6 invalidV6 = {};
    invalidV6.cluster = storedSpare;
    invalidV6.internalTransportProfile = storedSpare.internalTransportProfile;
    invalidV6.spareMachineCount = 0;
    String invalidPayload = {};
    BitseryEngine::serialize(invalidPayload, invalidV6);
    String invalidEncoded = {};
    invalidEncoded.append(v6Header);
    invalidEncoded.append(invalidPayload);
    {
      TidesDB database(spareDbPath);
      suite.expect(database.write("clusters"_ctv, "invalid-spare-v6"_ctv, invalidEncoded, &failure), "test_spare_v6_invalid_record_written");
    }
    MothershipProdigyCluster ignored = {};
    suite.expect(!MothershipClusterRegistry(spareDbPath).getCluster("invalid-spare-v6"_ctv, ignored, &failure), "test_spare_v6_rejects_zero_tail");

    invalidV6 = {};
    invalidV6.cluster = storedSpare;
    invalidV6.cluster.deploymentMode = MothershipClusterDeploymentMode::local;
    invalidV6.internalTransportProfile = storedSpare.internalTransportProfile;
    invalidV6.spareMachineCount = 1;
    BitseryEngine::serialize(invalidPayload, invalidV6);
    invalidEncoded.assign(v6Header);
    invalidEncoded.append(invalidPayload);
    {
      TidesDB database(spareDbPath);
      suite.expect(database.write("clusters"_ctv, "invalid-spare-v6-deployment"_ctv, invalidEncoded, &failure), "test_spare_v6_invalid_deployment_written");
    }
    suite.expect(!MothershipClusterRegistry(spareDbPath).getCluster("invalid-spare-v6-deployment"_ctv, ignored, &failure), "test_spare_v6_rejects_non_test_deployment");
  }

  {
    constexpr auto v3Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=3\n\n"_ctv;
    MothershipProdigyClusterRecordV3 malformedRecord = {};
    malformedRecord.cluster = storedLocalAdopted;
    malformedRecord.adoptedMachineRackUUIDs.push_back(storedLocalAdopted.machines[0].rackUUID);
    String malformedPayload = {};
    BitseryEngine::serialize(malformedPayload, malformedRecord);
    String malformedValue = {};
    malformedValue.assign(v3Header);
    malformedValue.append(malformedPayload);
    String malformedDbPath = {};
    malformedDbPath.snprintf<"{}/malformed-v3"_ctv>(dbPath);
    String failure = {};
    {
      TidesDB database(malformedDbPath);
      suite.expect(database.write("clusters"_ctv, "rack-v3-malformed"_ctv, malformedValue, &failure), "rack_v3_malformed_record_written");
      suite.expect(failure.size() == 0, "rack_v3_malformed_record_write_no_failure");
    }
    MothershipClusterRegistry malformedRegistry(malformedDbPath);
    MothershipProdigyCluster ignored = {};
    bool decodedMalformed = malformedRegistry.getCluster("rack-v3-malformed"_ctv, ignored, &failure);
    suite.expect(decodedMalformed == false, "rack_v3_sidecar_length_rejected");
    suite.expect(failure.equals("cluster record decode failed"_ctv), "rack_v3_sidecar_length_rejection_reason");
  }

  {
    String failure = {};
    String encodedOriginal = {};
    {
      TidesDB database(dbPath);
      bool readV4 = database.read("clusters"_ctv, "local-homelab"_ctv, encodedOriginal, &failure);
      suite.expect(readV4, "adopted_uuid_v4_record_read");
      suite.expect(failure.size() == 0, "adopted_uuid_v4_record_read_no_failure");
    }
    constexpr auto v5Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=5\n\n"_ctv;
    constexpr auto v4Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=4\n\n"_ctv;
    bool hasV4Header = encodedOriginal.size() >= v4Header.size() &&
                       std::memcmp(encodedOriginal.data(), v4Header.data(), v4Header.size()) == 0;
    suite.expect(hasV4Header, "tls_profile_retains_v4_record_header");

    MothershipProdigyClusterRecordV5 aegisRecord = {};
    aegisRecord.cluster = storedLocalAdopted;
    aegisRecord.internalTransportProfile = MothershipInternalTransportProfile::aegisX25519V1;
    for (const auto& machine : storedLocalAdopted.machines)
    {
      aegisRecord.adoptedMachineRackUUIDs.push_back(machine.rackUUID);
      aegisRecord.adoptedMachineUUIDs.push_back(machine.uuid);
    }
    String aegisPayload = {};
    BitseryEngine::serialize(aegisPayload, aegisRecord);
    String aegisEncoded = {};
    aegisEncoded.append(v5Header);
    aegisEncoded.append(aegisPayload);
    String profileDbPath;
    profileDbPath.snprintf<"{}/transport-profile"_ctv>(dbPath);
    auto writeProfile = [&](const String& encoded) {
      failure.clear();
      TidesDB database(profileDbPath);
      return database.write("clusters"_ctv, "local-homelab"_ctv, encoded, &failure);
    };
    auto readProfile = [&](MothershipProdigyCluster& value) {
      failure.clear();
      MothershipClusterRegistry registry(profileDbPath);
      return registry.getCluster("local-homelab"_ctv, value, &failure);
    };
    suite.expect(writeProfile(aegisEncoded),
                 "aegis_profile_v5_record_written");
    MothershipProdigyCluster aegisLoaded = {};
    suite.expect(readProfile(aegisLoaded) &&
                     aegisLoaded.internalTransportProfile == MothershipInternalTransportProfile::aegisX25519V1,
                 "aegis_profile_v5_roundtrip");
    suite.expect(aegisLoaded.bgpAuthorizedOriginPrefixes.empty(),
                 "aegis_profile_v5_defaults_empty_bgp_origin_policy");

    aegisRecord.internalTransportProfile = MothershipInternalTransportProfile(99);
    BitseryEngine::serialize(aegisPayload, aegisRecord);
    aegisEncoded.assign(v5Header);
    aegisEncoded.append(aegisPayload);
    suite.expect(writeProfile(aegisEncoded) &&
                     !readProfile(aegisLoaded),
                 "aegis_profile_v5_rejects_unknown_profile");
    MothershipProdigyClusterRecordV4 legacyProfileRecord;
    legacyProfileRecord.cluster = storedLocalAdopted;
    legacyProfileRecord.cluster.internalTransportProfile = MothershipInternalTransportProfile::aegisX25519V1;
    legacyProfileRecord.adoptedMachineRackUUIDs = aegisRecord.adoptedMachineRackUUIDs;
    legacyProfileRecord.adoptedMachineUUIDs = aegisRecord.adoptedMachineUUIDs;
    BitseryEngine::serialize(aegisPayload, legacyProfileRecord);
    aegisEncoded.assign(v4Header);
    aegisEncoded.append(aegisPayload);
    suite.expect(writeProfile(aegisEncoded) &&
                     readProfile(aegisLoaded) &&
                     aegisLoaded.internalTransportProfile == MothershipInternalTransportProfile::tls,
                 "aegis_profile_v4_defaults_tls");
    suite.expect(aegisLoaded.bgpAuthorizedOriginPrefixes.empty(),
                 "aegis_profile_v4_defaults_empty_bgp_origin_policy");
    failure.clear();

    MothershipProdigyClusterRecordV4 malformedRecord = {};
    malformedRecord.cluster = storedLocalAdopted;
    for (const MothershipProdigyClusterMachine& machine : storedLocalAdopted.machines)
    {
      malformedRecord.adoptedMachineRackUUIDs.push_back(machine.rackUUID);
    }
    malformedRecord.adoptedMachineUUIDs.push_back(storedLocalAdopted.machines[0].uuid);
    String malformedPayload = {};
    BitseryEngine::serialize(malformedPayload, malformedRecord);
    String malformedValue = {};
    malformedValue.assign(v4Header);
    malformedValue.append(malformedPayload);
    String malformedDbPath = {};
    malformedDbPath.snprintf<"{}/malformed-v4"_ctv>(dbPath);
    {
      TidesDB database(malformedDbPath);
      bool wroteMalformed = database.write("clusters"_ctv, "adopted-uuid-v4-malformed"_ctv, malformedValue, &failure);
      suite.expect(wroteMalformed, "adopted_uuid_v4_malformed_record_written");
      suite.expect(failure.size() == 0, "adopted_uuid_v4_malformed_record_write_no_failure");
    }
    MothershipClusterRegistry malformedRegistry(malformedDbPath);
    MothershipProdigyCluster ignored = {};
    bool decodedMalformed = malformedRegistry.getCluster("adopted-uuid-v4-malformed"_ctv, ignored, &failure);
    suite.expect(decodedMalformed == false, "adopted_uuid_v4_uuid_sidecar_length_rejected");
    suite.expect(failure.equals("cluster record decode failed"_ctv), "adopted_uuid_v4_uuid_sidecar_length_rejection_reason");

    MothershipProdigyClusterRecordV4 malformedRackRecord = {};
    malformedRackRecord.cluster = storedLocalAdopted;
    malformedRackRecord.adoptedMachineRackUUIDs.push_back(storedLocalAdopted.machines[0].rackUUID);
    for (const MothershipProdigyClusterMachine& machine : storedLocalAdopted.machines)
    {
      malformedRackRecord.adoptedMachineUUIDs.push_back(machine.uuid);
    }
    malformedPayload.clear();
    BitseryEngine::serialize(malformedPayload, malformedRackRecord);
    malformedValue.assign(v4Header);
    malformedValue.append(malformedPayload);
    malformedDbPath.snprintf<"{}/malformed-v4-rack"_ctv>(dbPath);
    failure.clear();
    {
      TidesDB database(malformedDbPath);
      suite.expect(database.write("clusters"_ctv, "adopted-uuid-v4-rack-malformed"_ctv, malformedValue, &failure), "adopted_uuid_v4_rack_malformed_record_written");
      suite.expect(failure.size() == 0, "adopted_uuid_v4_rack_malformed_record_write_no_failure");
    }
    MothershipClusterRegistry malformedRackRegistry(malformedDbPath);
    failure.clear();
    bool decodedMalformedRack = malformedRackRegistry.getCluster("adopted-uuid-v4-rack-malformed"_ctv, ignored, &failure);
    suite.expect(decodedMalformedRack == false, "adopted_uuid_v4_rack_sidecar_length_rejected");
    suite.expect(failure.equals("cluster record decode failed"_ctv), "adopted_uuid_v4_rack_sidecar_length_rejection_reason");
  }

  {
    constexpr auto v3Header = "PRODIGY-MOTHERSHIP-CLUSTER\nversion=3\n\n"_ctv;
    MothershipProdigyClusterRecordV3 legacyRecord = {};
    legacyRecord.cluster = storedLocalAdopted;
    for (uint32_t index = 0; index < legacyRecord.cluster.machines.size(); ++index)
    {
      legacyRecord.adoptedMachineRackUUIDs.push_back(legacyRecord.cluster.machines[index].rackUUID);
      legacyRecord.cluster.machines[index].uuid = 0;
    }
    String legacyPayload = {};
    BitseryEngine::serialize(legacyPayload, legacyRecord);
    String legacyValue = {};
    legacyValue.assign(v3Header);
    legacyValue.append(legacyPayload);
    String legacyDbPath = {};
    legacyDbPath.snprintf<"{}/legacy-v3"_ctv>(dbPath);
    String failure = {};
    {
      TidesDB database(legacyDbPath);
      suite.expect(database.write("clusters"_ctv, "adopted-uuid-v3"_ctv, legacyValue, &failure), "adopted_uuid_v3_fixture_written");
      suite.expect(failure.size() == 0, "adopted_uuid_v3_fixture_write_no_failure");
    }
    MothershipClusterRegistry legacyRegistry(legacyDbPath);
    MothershipProdigyCluster decoded = {};
    suite.expect(legacyRegistry.getCluster("adopted-uuid-v3"_ctv, decoded, &failure), "adopted_uuid_v3_fixture_decodes");
    suite.expect(decoded.machines.size() == storedLocalAdopted.machines.size(), "adopted_uuid_v3_fixture_machine_count");
    if (decoded.machines.size() == storedLocalAdopted.machines.size())
    {
      suite.expect(decoded.machines[0].rackUUID == 101 && decoded.machines[1].rackUUID == 202 && decoded.machines[2].rackUUID == 303,
                   "adopted_uuid_v3_fixture_preserves_racks");
      suite.expect(decoded.machines[0].uuid == 0 && decoded.machines[1].uuid == 0 && decoded.machines[2].uuid == 0,
                   "adopted_uuid_v3_fixture_defaults_uuids_zero");
    }
  }

  {
    MothershipClusterRegistry registry(dbPath);
    String failure;

    MothershipProdigyCluster loadedLocal = {};
    MothershipProdigyCluster loadedLocalAdopted = {};
    MothershipProdigyCluster loadedRemoteCreated = {};
    MothershipProdigyCluster loadedRemoteAdopted = {};
    MothershipProdigyCluster loadedRemoteManagedGcp = {};
    MothershipProdigyCluster loadedRemoteMixed = {};
    MothershipProdigyCluster loadedRemoteVultrBGP = {};
    MothershipProdigyCluster loadedTestLocal = {};

    bool reopenGetLocal = registry.getCluster("local-alpha"_ctv, loadedLocal, &failure);
    if (!reopenGetLocal)
    {
      basics_log("detail reopen_get_local: %s\n", failure.c_str());
    }
    suite.expect(reopenGetLocal, "reopen_get_local");

    bool reopenGetRemoteCreated = registry.getCluster("managed-aws"_ctv, loadedRemoteCreated, &failure);
    if (!reopenGetRemoteCreated)
    {
      basics_log("detail reopen_get_remote_created: %s\n", failure.c_str());
    }
    suite.expect(reopenGetRemoteCreated, "reopen_get_remote_created");

    bool reopenGetLocalAdopted = registry.getCluster("local-homelab"_ctv, loadedLocalAdopted, &failure);
    if (!reopenGetLocalAdopted)
    {
      basics_log("detail reopen_get_local_adopted: %s\n", failure.c_str());
    }
    suite.expect(reopenGetLocalAdopted, "reopen_get_local_adopted");

    bool reopenGetRemoteAdopted = registry.getCluster("adopted-gcp"_ctv, loadedRemoteAdopted, &failure);
    if (!reopenGetRemoteAdopted)
    {
      basics_log("detail reopen_get_remote_adopted: %s\n", failure.c_str());
    }
    suite.expect(reopenGetRemoteAdopted, "reopen_get_remote_adopted");

    bool reopenGetRemoteManagedGcp = registry.getCluster("managed-gcp"_ctv, loadedRemoteManagedGcp, &failure);
    if (!reopenGetRemoteManagedGcp)
    {
      basics_log("detail reopen_get_remote_managed_gcp: %s\n", failure.c_str());
    }
    suite.expect(reopenGetRemoteManagedGcp, "reopen_get_remote_managed_gcp");

    bool reopenGetRemoteMixed = registry.getCluster("hybrid-azure"_ctv, loadedRemoteMixed, &failure);
    if (!reopenGetRemoteMixed)
    {
      basics_log("detail reopen_get_remote_mixed: %s\n", failure.c_str());
    }
    suite.expect(reopenGetRemoteMixed, "reopen_get_remote_mixed");

    bool reopenGetRemoteVultrBGP = registry.getCluster("remote-vultr-bgp"_ctv, loadedRemoteVultrBGP, &failure);
    if (!reopenGetRemoteVultrBGP)
    {
      basics_log("detail reopen_get_remote_vultr_bgp: %s\n", failure.c_str());
    }
    suite.expect(reopenGetRemoteVultrBGP, "reopen_get_remote_vultr_bgp");

    bool reopenGetTestLocal = registry.getCluster("test-local"_ctv, loadedTestLocal, &failure);
    if (!reopenGetTestLocal)
    {
      basics_log("detail reopen_get_test_local: %s\n", failure.c_str());
    }
    suite.expect(reopenGetTestLocal, "reopen_get_test_local");

    MothershipProdigyCluster loadedRemoteCreatedByUUID = {};
    String remoteCreatedIdentity = {};
    remoteCreatedIdentity.assignItoh(storedRemoteCreated.clusterUUID);
    bool reopenGetRemoteCreatedByUUID = registry.getClusterByIdentity(remoteCreatedIdentity, loadedRemoteCreatedByUUID, &failure);
    if (!reopenGetRemoteCreatedByUUID)
    {
      basics_log("detail reopen_get_remote_created_uuid: %s\n", failure.c_str());
    }
    suite.expect(reopenGetRemoteCreatedByUUID, "reopen_get_remote_created_by_uuid");

    MothershipProdigyCluster loadedRemoteMixedByUUID = {};
    String remoteMixedIdentity = {};
    remoteMixedIdentity.assignItoh(storedRemoteMixed.clusterUUID);
    bool reopenGetRemoteMixedByUUID = registry.getClusterByIdentity(remoteMixedIdentity, loadedRemoteMixedByUUID, &failure);
    if (!reopenGetRemoteMixedByUUID)
    {
      basics_log("detail reopen_get_remote_mixed_uuid: %s\n", failure.c_str());
    }
    suite.expect(reopenGetRemoteMixedByUUID, "reopen_get_remote_mixed_by_uuid");

    suite.expect(equalClusters(storedLocal, loadedLocal), "reopen_local_roundtrip");
    suite.expect(equalClusters(storedLocalAdopted, loadedLocalAdopted), "reopen_local_adopted_roundtrip");
    if (loadedLocalAdopted.machines.size() == 3)
    {
      suite.expect(loadedLocalAdopted.machines[0].rackUUID == 101 &&
                       loadedLocalAdopted.machines[1].rackUUID == 202 &&
                       loadedLocalAdopted.machines[2].rackUUID == 303,
                   "rack_v3_values_preserved");
    }
    else
    {
      suite.expect(false, "rack_v3_values_preserved");
    }
    suite.expect(equalClusters(storedTestLocal, loadedTestLocal), "reopen_test_local_roundtrip");
    suite.expect(loadedTestLocal.test.spareMachineCount == 0, "reopen_v4_test_record_defaults_spare_zero");
    suite.expect(equalClusters(storedRemoteCreated, loadedRemoteCreated), "reopen_remote_created_roundtrip");
    suite.expect(equalClusters(storedRemoteCreated, loadedRemoteCreatedByUUID), "reopen_remote_created_uuid_roundtrip");
    suite.expect(equalClusters(storedRemoteAdopted, loadedRemoteAdopted), "reopen_remote_adopted_roundtrip");
    suite.expect(equalClusters(storedRemoteManagedGcp, loadedRemoteManagedGcp), "reopen_remote_managed_gcp_roundtrip");
    suite.expect(equalClusters(storedRemoteMixed, loadedRemoteMixed), "reopen_remote_mixed_roundtrip");
    suite.expect(equalClusters(storedRemoteVultrBGP, loadedRemoteVultrBGP), "reopen_remote_vultr_bgp_roundtrip");
    suite.expect(equalClusters(storedRemoteMixed, loadedRemoteMixedByUUID), "reopen_remote_mixed_uuid_roundtrip");

    loadedTestLocal.desiredEnvironment = ProdigyEnvironmentKind::unknown;
    loadedTestLocal.environmentConfigured = true;
    loadedTestLocal.lastRefreshMs = 123'456'789;
    MothershipProdigyCluster refreshedTestLocal = {};
    bool upsertExistingTestLocal = registry.upsertCluster(loadedTestLocal, &refreshedTestLocal, &failure);
    if (!upsertExistingTestLocal)
    {
      basics_log("detail upsert_existing_test_local: %s\n", failure.c_str());
    }
    suite.expect(upsertExistingTestLocal, "upsert_existing_test_local");
    suite.expect(equalControls(storedTestLocal.controls, refreshedTestLocal.controls), "upsert_existing_test_local_controls");
    suite.expect(refreshedTestLocal.desiredEnvironment == ProdigyEnvironmentKind::dev, "upsert_existing_test_local_desired_environment_defaulted");
    suite.expect(refreshedTestLocal.lastRefreshMs == loadedTestLocal.lastRefreshMs, "upsert_existing_test_local_refresh_ms");

    bool removeLocal = registry.removeCluster("local-alpha"_ctv, &failure);
    if (!removeLocal)
    {
      basics_log("detail remove_local: %s\n", failure.c_str());
    }
    suite.expect(removeLocal, "remove_local");

    bool removeRemoteCreated = registry.removeCluster("managed-aws"_ctv, &failure);
    if (!removeRemoteCreated)
    {
      basics_log("detail remove_remote_created: %s\n", failure.c_str());
    }
    suite.expect(removeRemoteCreated, "remove_remote_created");

    bool removeLocalAdopted = registry.removeCluster("local-homelab"_ctv, &failure);
    if (!removeLocalAdopted)
    {
      basics_log("detail remove_local_adopted: %s\n", failure.c_str());
    }
    suite.expect(removeLocalAdopted, "remove_local_adopted");

    bool removeRemoteAdopted = registry.removeCluster("adopted-gcp"_ctv, &failure);
    if (!removeRemoteAdopted)
    {
      basics_log("detail remove_remote_adopted: %s\n", failure.c_str());
    }
    suite.expect(removeRemoteAdopted, "remove_remote_adopted");

    bool removeRemoteManagedGcp = registry.removeCluster("managed-gcp"_ctv, &failure);
    if (!removeRemoteManagedGcp)
    {
      basics_log("detail remove_remote_managed_gcp: %s\n", failure.c_str());
    }
    suite.expect(removeRemoteManagedGcp, "remove_remote_managed_gcp");

    bool removeRemoteMixed = registry.removeClusterByIdentity(remoteMixedIdentity, &failure);
    if (!removeRemoteMixed)
    {
      basics_log("detail remove_remote_mixed: %s\n", failure.c_str());
    }
    suite.expect(removeRemoteMixed, "remove_remote_mixed_by_uuid");

    bool removeRemoteVultrBGP = registry.removeCluster("remote-vultr-bgp"_ctv, &failure);
    if (!removeRemoteVultrBGP)
    {
      basics_log("detail remove_remote_vultr_bgp: %s\n", failure.c_str());
    }
    suite.expect(removeRemoteVultrBGP, "remove_remote_vultr_bgp");

    bool removeTopologyOwner = registry.removeCluster("topology-owner"_ctv, &failure);
    if (!removeTopologyOwner)
    {
      basics_log("detail remove_topology_owner: %s\n", failure.c_str());
    }
    suite.expect(removeTopologyOwner, "remove_topology_owner");

    bool removeSecondTestLocal = registry.removeCluster("test-local-second"_ctv, &failure);
    if (!removeSecondTestLocal)
    {
      basics_log("detail remove_second_test_local: %s\n", failure.c_str());
    }
    suite.expect(removeSecondTestLocal, "remove_second_test_local");

    bool removeTestLocal = registry.removeCluster("test-local"_ctv, &failure);
    if (!removeTestLocal)
    {
      basics_log("detail remove_test_local: %s\n", failure.c_str());
    }
    suite.expect(removeTestLocal, "remove_test_local");

    MothershipProdigyCluster recreatedRemoteMixed = remoteMixed;
    recreatedRemoteMixed.name = "hybrid-azure-recreated"_ctv;
    recreatedRemoteMixed.clusterUUID = storedRemoteMixed.clusterUUID;
    MothershipProdigyCluster recreatedStoredRemoteMixed = {};
    bool recreateRemoteMixedByFreedUUID = registry.createCluster(recreatedRemoteMixed, &recreatedStoredRemoteMixed, &failure);
    if (!recreateRemoteMixedByFreedUUID)
    {
      basics_log("detail recreate_remote_mixed_uuid: %s\n", failure.c_str());
    }
    suite.expect(recreateRemoteMixedByFreedUUID, "recreate_remote_mixed_with_freed_uuid");
    suite.expect(recreatedStoredRemoteMixed.clusterUUID == storedRemoteMixed.clusterUUID, "recreate_remote_mixed_with_freed_uuid_value");

    bool removeRecreatedRemoteMixed = registry.removeClusterByIdentity(remoteMixedIdentity, &failure);
    if (!removeRecreatedRemoteMixed)
    {
      basics_log("detail remove_recreated_remote_mixed: %s\n", failure.c_str());
    }
    suite.expect(removeRecreatedRemoteMixed, "remove_recreated_remote_mixed_by_uuid");

    Vector<MothershipProdigyCluster> clusters;
    bool listClustersEmpty = registry.listClusters(clusters, &failure);
    if (!listClustersEmpty)
    {
      basics_log("detail list_clusters_empty: %s\n", failure.c_str());
    }
    suite.expect(listClustersEmpty, "list_clusters_empty");
    suite.expect(clusters.size() == 0, "list_clusters_empty_count");
  }

  {
    String tunnelDbPath = {};
    tunnelDbPath.snprintf<"{}/tunnel"_ctv>(dbPath);
    MothershipClusterRegistry registry(tunnelDbPath);
    String failure = {};

    MothershipProdigyCluster tunnel = local;
    tunnel.name = "local-tunnel"_ctv;
    tunnel.clusterUUID = 0x7001;
    tunnel.mothershipConnectivity.kind = MothershipConnectivityKind::tunnelProvider;
    tunnel.mothershipConnectivity.tunnelProvider.artifactSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
    tunnel.mothershipConnectivity.tunnelProvider.artifactBytes = 256;
    tunnel.mothershipConnectivity.tunnelProvider.dialEndpoint = "control.example.net:443"_ctv;
    tunnel.mothershipConnectivity.tunnelProvider.egress.address4 = 0x01010101;
    tunnel.mothershipConnectivity.tunnelProvider.egress.port = 443;
    auto reissueTunnelClientAuth = [&](MothershipProdigyCluster& candidate, uint128_t clusterUUID, const char *testName) {
      MothershipTunnelGatewayAuth ignored = {};
      candidate.clusterUUID = clusterUUID;
      candidate.mothershipConnectivity.tunnelProvider.clientAuth = {};
      suite.expect(mothershipGenerateTunnelGatewayAuth(candidate.mothershipConnectivity.tunnelProvider.clientAuth, ignored, &failure), testName);
    };
    reissueTunnelClientAuth(tunnel, tunnel.clusterUUID, "create_tunnel_provider_generates_client_auth");

    MothershipProdigyCluster storedTunnel = {};
    bool createTunnel = registry.createCluster(tunnel, &storedTunnel, &failure);
    suite.expect(createTunnel, "create_tunnel_provider_connectivity");
    suite.expect(storedTunnel.mothershipConnectivity.kind == MothershipConnectivityKind::tunnelProvider, "create_tunnel_provider_kind_preserved");
    suite.expect(storedTunnel.mothershipConnectivity.tunnelProvider.clientAuth.configured(), "create_tunnel_provider_client_auth_persisted");
    MothershipProdigyCluster loadedTunnel = {};
    suite.expect(registry.getCluster("local-tunnel"_ctv, loadedTunnel, &failure), "load_tunnel_provider_connectivity");
    suite.expect(equalMothershipConnectivity(storedTunnel.mothershipConnectivity, loadedTunnel.mothershipConnectivity), "load_tunnel_provider_connectivity_matches");

    MothershipProdigyCluster invalidClientAuth = tunnel;
    invalidClientAuth.name = "local-tunnel-invalid-client-auth"_ctv;
    invalidClientAuth.mothershipConnectivity.tunnelProvider.clientAuth.clientKeyPem.assign("not-a-key"_ctv);
    bool createInvalidClientAuth = registry.createCluster(invalidClientAuth, nullptr, &failure);
    suite.expect(createInvalidClientAuth == false, "create_tunnel_provider_invalid_client_auth_rejected");
    suite.expect(failure.equals("tunnelProvider.clientAuth certificate material invalid"_ctv), "create_tunnel_provider_invalid_client_auth_reason");

    MothershipProdigyCluster missingEndpoint = tunnel;
    missingEndpoint.name = "local-tunnel-missing-endpoint"_ctv;
    missingEndpoint.mothershipConnectivity.tunnelProvider.dialEndpoint.clear();
    bool createMissingEndpoint = registry.createCluster(missingEndpoint, nullptr, &failure);
    suite.expect(createMissingEndpoint == false, "create_tunnel_provider_missing_endpoint_rejected");
    suite.expect(failure.equals("mothership tunnel-provider dial config invalid"_ctv), "create_tunnel_provider_missing_endpoint_reason");

    MothershipProdigyCluster missingEgress = tunnel;
    missingEgress.name = "local-tunnel-missing-egress"_ctv;
    missingEgress.mothershipConnectivity.tunnelProvider.egress.address4 = 0;
    bool createMissingEgress = registry.createCluster(missingEgress, nullptr, &failure);
    suite.expect(createMissingEgress == false, "create_tunnel_provider_missing_egress_rejected");
    suite.expect(failure.equals("mothership tunnel-provider egress endpoint invalid"_ctv), "create_tunnel_provider_missing_egress_reason");

    MothershipProdigyCluster zeroPort = tunnel;
    zeroPort.name = "local-tunnel-zero-port"_ctv;
    zeroPort.mothershipConnectivity.tunnelProvider.egress.port = 0;
    bool createZeroPort = registry.createCluster(zeroPort, nullptr, &failure);
    suite.expect(createZeroPort == false, "create_tunnel_provider_zero_port_rejected");

    const char *deniedEgressHosts[] = {
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1"};
    for (uint32_t index = 0; index < sizeof(deniedEgressHosts) / sizeof(deniedEgressHosts[0]); ++index)
    {
      MothershipProdigyCluster deniedEgress = tunnel;
      deniedEgress.name = String();
      deniedEgress.name.snprintf<"local-tunnel-denied-egress-{itoa}"_ctv>(uint64_t(index));
      (void)prodigySystemEgressIPv4Literal(String(deniedEgressHosts[index]), deniedEgress.mothershipConnectivity.tunnelProvider.egress.address4);
      bool createDeniedEgress = registry.createCluster(deniedEgress, nullptr, &failure);
      suite.expect(createDeniedEgress == false, "create_tunnel_provider_denied_literal_egress_rejected");
      suite.expect(failure.equals("mothership tunnel-provider egress literal denied"_ctv), "create_tunnel_provider_denied_literal_egress_reason");
    }

    MothershipProdigyCluster missingAuth = tunnel;
    missingAuth.name = "local-tunnel-missing-auth"_ctv;
    missingAuth.mothershipConnectivity.tunnelProvider.clientAuth = {};
    bool createMissingAuth = registry.createCluster(missingAuth, nullptr, &failure);
    suite.expect(createMissingAuth == false, "create_tunnel_provider_missing_auth_rejected");
    suite.expect(failure.equals("tunnelProvider.clientAuth certificate material invalid"_ctv), "create_tunnel_provider_missing_auth_reason");

  }

  {
    String masquePath; masquePath.snprintf<"{}/masque"_ctv>(dbPath);
    MothershipClusterRegistry registry(masquePath); String failure = {};
    ProdigyClusterPairEnrollment enrollment = {}; enrollment.pairUUID = 0x9001; enrollment.localClusterUUID = 0x9002; enrollment.peerClusterUUID = 0x9003; enrollment.operationUUID = 0x9007; enrollment.rootGeneration = 7; enrollment.agreedKeyEpoch = 9; enrollment.localAuthorityGeneration = 11; enrollment.state = ProdigyClusterPairEnrollmentState::active;
    MothershipProdigyCluster local = {}, peer = {};
    local.clusterUUID = enrollment.localClusterUUID; local.datacenterFragment = 17; local.topology.version = 1;
    peer.clusterUUID = enrollment.peerClusterUUID; peer.datacenterFragment = 29; peer.topology.version = 1;
    ClusterMachine localMachine = {}, peerMachine = {};
    localMachine.uuid = 0x9005; localMachine.isBrain = true;
    localMachine.addresses.publicAddresses.push_back(ClusterMachineAddress {"2001:db8::1"_ctv, 128, {}});
    peerMachine.uuid = 0x9006; peerMachine.isBrain = true;
    peerMachine.addresses.publicAddresses.push_back(ClusterMachineAddress {"2001:db8::2"_ctv, 128, {}});
    local.topology.machines.push_back(localMachine); peer.topology.machines.push_back(peerMachine);
    CrossClusterMasqueGatewayAuthority requested = {};
    requested.localMachineUUID = localMachine.uuid; requested.peerMachineUUID = peerMachine.uuid;
    requested.artifactSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
    // The enrolled Vault mints TLS identities; '-' requests those exact derived
    // digests instead of pretending the artifact digest identifies a certificate.
    requested.localIdentitySHA256 = "-"_ctv; requested.peerIdentitySHA256 = "-"_ctv;
    requested.peerTrustSHA256 = "-"_ctv; requested.artifactBytes = 1;
    requested.listenerPublicUDPEndpoint = IPAddress("2001:db8::1", true); requested.listenerPublicUDPPort = 443;
    requested.localRole = CrossClusterMasqueGatewayRole::listener; requested.generation = 1;
    requested.gatewaySlot = 1; requested.tunnelSlot = 2;
    // MASQUE credentials are derived from the durable enrollment root.  The
    // registry must not silently synthesize this private authority when it is
    // absent, so install the matching immutable pair intent first.
    MothershipClusterPairEnrollmentIntent privateIntent = {};
    privateIntent.pairUUID = enrollment.pairUUID; privateIntent.operationUUID = enrollment.operationUUID;
    privateIntent.firstClusterUUID = enrollment.localClusterUUID; privateIntent.secondClusterUUID = enrollment.peerClusterUUID;
    privateIntent.rootGeneration = enrollment.rootGeneration; privateIntent.keyEpoch = enrollment.agreedKeyEpoch;
    privateIntent.firstObservedAuthorityGeneration = enrollment.localAuthorityGeneration;
    privateIntent.secondObservedAuthorityGeneration = enrollment.localAuthorityGeneration;
    for (uint32_t index = 0; index < sizeof(privateIntent.root); ++index) privateIntent.root[index] = uint8_t(index + 1);
    ClusterPairControlEndpoint localEndpoint = {};
    localEndpoint.clusterUUID = enrollment.localClusterUUID; localEndpoint.nodeUUID = localMachine.uuid;
    localEndpoint.role = ClusterPairControlNodeRole::switchboard; localEndpoint.address = IPAddress("fd42:4242:4242:1::1", true);
    localEndpoint.port = mothershipPairControlBoundaryPort;
    ClusterPairControlEndpoint peerEndpoint = localEndpoint;
    peerEndpoint.clusterUUID = enrollment.peerClusterUUID; peerEndpoint.nodeUUID = peerMachine.uuid;
    peerEndpoint.address = IPAddress("fd42:4242:4242:2::1", true);
    privateIntent.firstEndpoints.push_back(localEndpoint); privateIntent.secondEndpoints.push_back(peerEndpoint);
    MothershipClusterPairEnrollmentIntent recordedIntent = {}; bool intentResumed = false;
    suite.expect(registry.recordClusterPairEnrollmentIntent(privateIntent, recordedIntent, intentResumed, &failure) && !intentResumed,
                 "masque_gateway_pair_root_durable");
    CrossClusterMasqueGatewayAuthority recorded = {}; bool resumed = false;
    suite.expect(registry.putCrossClusterMasqueGateway(requested, enrollment, local, peer, recorded, resumed, &failure) && !resumed, "masque_gateway_put_durable");
    suite.expect(recorded.pairUUID == enrollment.pairUUID && recorded.pairOperationUUID == enrollment.operationUUID && recorded.localDatacenterFragment == local.datacenterFragment && recorded.peerDatacenterFragment == peer.datacenterFragment && recorded.localSitePrefix.equals(prodigyContainerDatacenterSitePrefix(local.datacenterFragment)) && recorded.peerSitePrefix.equals(prodigyContainerDatacenterSitePrefix(peer.datacenterFragment)), "masque_gateway_derives_pair_and_site_authority");
    suite.expect(recorded.gatewaySlot == 1 && recorded.tunnelSlot == 2 &&
                     recorded.privateTunnelInterface.size() != 0 && recorded.privateTunnelInterface.size() <= 15 &&
                     recorded.privateTunnelLocalIPv6.is6 && recorded.privateTunnelPeerIPv6.is6 &&
                     !recorded.privateTunnelLocalIPv6.equals(recorded.privateTunnelPeerIPv6) &&
                     recorded.privateLocalASN != 0 && recorded.privatePeerASN != 0 &&
                     prodigyIsSHA256HexDigest(recorded.privateSessionCredentialSHA256),
                 "masque_gateway_derives_private_bgp_tuple_not_cli_input");
    CrossClusterMasqueGatewayAuthority loaded = {}; suite.expect(registry.loadCrossClusterMasqueGateway(recorded.pairUUID, requested.localMachineUUID, loaded, &failure) && loaded.generation == 1, "masque_gateway_load_durable");
    suite.expect(registry.putCrossClusterMasqueGateway(requested, enrollment, local, peer, recorded, resumed, &failure) && resumed, "masque_gateway_put_idempotent_resume");
    auto wrongTLSIdentity = requested;
    wrongTLSIdentity.localIdentitySHA256 = requested.artifactSHA256;
    CrossClusterMasqueGatewayAuthority rejectedTLSIdentity;
    suite.expect(!registry.putCrossClusterMasqueGateway(wrongTLSIdentity, enrollment, local, peer,
        rejectedTLSIdentity, resumed, &failure) &&
        failure.equals("cross-cluster MASQUE gateway TLS identity digest does not match Vault material"_ctv),
        "masque_gateway_rejects_fabricated_tls_identity_digest");
    ProdigyCrossClusterPathFaultGatewayLifecycleRecord lifecycle = {};
    lifecycle.request.operationUUID = 0x9010; lifecycle.request.authority = recorded;
    lifecycle.request.scope = prodigyCrossClusterPathFaultScope(recorded);
    prodigyCrossClusterPathFaultFlowIdentity(lifecycle.request.scope, lifecycle.request.flowIdentity);
    lifecycle.admittedPlan.kind = SystemContainerKind::crossClusterMasqueGateway;
    lifecycle.admittedPlan.artifact.sha256 = recorded.artifactSHA256;
    lifecycle.admittedPlan.artifact.bytes = recorded.artifactBytes;
    lifecycle.admittedPlan.gatewayPairUUID = recorded.pairUUID;
    lifecycle.admittedPlan.gatewayLocalClusterUUID = recorded.localClusterUUID;
    lifecycle.admittedPlan.gatewayLocalMachineUUID = recorded.localMachineUUID;
    lifecycle.admittedPlan.gatewayKeyEpoch = recorded.keyGeneration;
    lifecycle.admittedPlan.gatewayAuthorityGeneration = recorded.pairAuthorityGeneration;
    lifecycle.admittedPlan.gatewayGeneration = recorded.generation;
    lifecycle.admittedPlan.gatewayTunnelInterface = recorded.privateTunnelInterface;
    lifecycle.admittedPlan.egress.peerIsIPv6 = true; lifecycle.admittedPlan.egress.protocol = IPPROTO_UDP;
    lifecycle.admittedPlan.egress.port = recorded.listenerPublicUDPPort;
    std::memcpy(lifecycle.admittedPlan.egress.address6, recorded.listenerPublicUDPEndpoint.v6, sizeof(lifecycle.admittedPlan.egress.address6));
    lifecycle.admittedPlan.egress.allowIngressFromPeer = true;
    ClusterMachine::renderIPAddressLiteral(recorded.listenerPublicUDPEndpoint, lifecycle.admittedPlan.gatewayEndpoint);
    lifecycle.admittedPlan.gatewayLocalIdentity = recorded.localIdentitySHA256;
    lifecycle.admittedPlan.gatewayPeerIdentity = recorded.peerIdentitySHA256;
    lifecycle.admittedPlan.gatewayPeerTrust = recorded.peerTrustSHA256;
    lifecycle.retiringContainerUUID = 0x9011; lifecycle.admittedLaunchGeneration = 17;
    ProdigyCrossClusterPathFaultGatewayLifecycleRecord lifecycleRecorded = {}; bool lifecycleResumed = false;
    suite.expect(registry.putCrossClusterPathFaultLifecycle(lifecycle, lifecycleRecorded, lifecycleResumed, &failure) && !lifecycleResumed,
                 "masque_gateway_path_fault_lifecycle_writes_ahead_before_retirement");
    suite.expect(registry.putCrossClusterPathFaultLifecycle(lifecycle, lifecycleRecorded, lifecycleResumed, &failure) && lifecycleResumed,
                 "masque_gateway_path_fault_lifecycle_prepared_replay_is_exact");
    auto secondLifecycle = lifecycle; ++secondLifecycle.request.operationUUID;
    suite.expect(!registry.putCrossClusterPathFaultLifecycle(secondLifecycle, lifecycleRecorded, lifecycleResumed, &failure),
                 "masque_gateway_path_fault_lifecycle_rejects_second_active_scope");
    lifecycle.phase = ProdigyCrossClusterPathFaultGatewayLifecyclePhase::suspended;
    suite.expect(registry.advanceCrossClusterPathFaultLifecycle(lifecycle, lifecycleRecorded, lifecycleResumed, &failure) && !lifecycleResumed,
                 "masque_gateway_path_fault_lifecycle_advances_prepared_to_suspended");
    lifecycle.phase = ProdigyCrossClusterPathFaultGatewayLifecyclePhase::restoreNeeded;
    suite.expect(registry.advanceCrossClusterPathFaultLifecycle(lifecycle, lifecycleRecorded, lifecycleResumed, &failure) && !lifecycleResumed,
                 "masque_gateway_path_fault_lifecycle_records_restore_needed");
    lifecycle.phase = ProdigyCrossClusterPathFaultGatewayLifecyclePhase::restored;
    lifecycle.replacementContainerUUID = 0x9012;
    suite.expect(registry.advanceCrossClusterPathFaultLifecycle(lifecycle, lifecycleRecorded, lifecycleResumed, &failure) && !lifecycleResumed,
                 "masque_gateway_path_fault_lifecycle_advances_to_restored");
    ProdigyCrossClusterPathFaultGatewayLifecycleRecord reopenedLifecycle = {};
    suite.expect(registry.loadCrossClusterPathFaultLifecycle(lifecycle.request, reopenedLifecycle, &failure) &&
                     MothershipClusterRegistry::crossClusterPathFaultLifecycleEqual(reopenedLifecycle, lifecycle),
                 "masque_gateway_path_fault_lifecycle_loads_exact_restored_record");
    pathFaultReopenPath = masquePath;
    pathFaultReopenExpected = lifecycle;
    pathFaultReopenExpectedRecorded = true;
    auto wrongPrefix = requested; wrongPrefix.generation = 2; wrongPrefix.peerSitePrefix = prodigyContainerDatacenterSitePrefix(3);
    suite.expect(!registry.putCrossClusterMasqueGateway(wrongPrefix, enrollment, local, peer, recorded, resumed, &failure), "masque_gateway_rejects_prefix_datacenter_mismatch");
    auto stalePair = requested; stalePair.generation = 2; stalePair.pairAuthorityGeneration += 1;
    suite.expect(!registry.putCrossClusterMasqueGateway(stalePair, enrollment, local, peer, recorded, resumed, &failure), "masque_gateway_rejects_stale_pair_authority");
    auto staleKey = requested; staleKey.generation = 2; staleKey.keyGeneration += 1;
    suite.expect(!registry.putCrossClusterMasqueGateway(staleKey, enrollment, local, peer, recorded, resumed, &failure), "masque_gateway_rejects_stale_key_epoch");
    auto changedScope = requested; changedScope.generation = 2; changedScope.peerMachineUUID += 1;
    suite.expect(!registry.putCrossClusterMasqueGateway(changedScope, enrollment, local, peer, recorded, resumed, &failure), "masque_gateway_rejects_scope_change");
    auto unregisteredListener = requested; unregisteredListener.localMachineUUID = 0x9999;
    suite.expect(!registry.putCrossClusterMasqueGateway(unregisteredListener, enrollment, local, peer, recorded, resumed, &failure), "masque_gateway_rejects_unregistered_machine");
    auto wrongEndpoint = requested; wrongEndpoint.listenerPublicUDPEndpoint = IPAddress("2001:db8::9", true);
    suite.expect(!registry.putCrossClusterMasqueGateway(wrongEndpoint, enrollment, local, peer, recorded, resumed, &failure), "masque_gateway_rejects_unregistered_listener_endpoint");
    suite.expect(registry.loadCrossClusterMasqueGateway(enrollment.pairUUID, localMachine.uuid, recorded, &failure),
                  "masque_gateway_reload_before_bilateral_withdrawal");
    auto replacement = recorded; replacement.generation = 2;
    suite.expect(prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(recorded, replacement),
                 "masque_gateway_active_replacement_is_monotone");
    auto peerRequested = requested; peerRequested.localMachineUUID = peerMachine.uuid;
    peerRequested.peerMachineUUID = localMachine.uuid; peerRequested.localRole = CrossClusterMasqueGatewayRole::connector;
    auto peerEnrollment = enrollment; peerEnrollment.localClusterUUID = enrollment.peerClusterUUID;
    peerEnrollment.peerClusterUUID = enrollment.localClusterUUID;
    CrossClusterMasqueGatewayAuthority peerRecorded = {};
    suite.expect(registry.putCrossClusterMasqueGateway(peerRequested, peerEnrollment, peer, local, peerRecorded, resumed, &failure),
                  "masque_gateway_reciprocal_scope_durable");
    ProdigyPairPrivateBGPSecretScope localScope = {};
    localScope.pairUUID = enrollment.pairUUID; localScope.operationUUID = enrollment.operationUUID;
    localScope.keyEpoch = enrollment.agreedKeyEpoch; localScope.tunnelSlot = requested.tunnelSlot;
    localScope.clusterUUID = local.clusterUUID; localScope.machineUUID = localMachine.uuid;
    localScope.authorityGeneration = enrollment.localAuthorityGeneration; localScope.gatewayGeneration = 1;
    auto peerScope = localScope; peerScope.clusterUUID = peer.clusterUUID; peerScope.machineUUID = peerMachine.uuid;
    bool deleted = false;
    suite.expect(registry.acknowledgeCrossClusterPrivateBGPSecretRevocation(localScope, deleted) && !deleted,
                  "masque_gateway_local_secret_revoked_first");
    CrossClusterMasqueGatewayAuthority withdrawn = {};
    suite.expect(registry.withdrawCrossClusterMasqueGateway(enrollment.pairUUID, localMachine.uuid, 2, withdrawn, &failure) &&
                      withdrawn.state == CrossClusterMasqueGatewayState::withdrawn,
                  "masque_gateway_withdraw_monotone");
    suite.expect(registry.withdrawCrossClusterMasqueGateway(enrollment.pairUUID, localMachine.uuid, 2, withdrawn, &failure),
                 "masque_gateway_withdraw_idempotent_resume");
    suite.expect(!registry.withdrawCrossClusterMasqueGateway(enrollment.pairUUID, localMachine.uuid, 1, withdrawn, &failure),
                 "masque_gateway_rejects_stale_withdrawal");
    suite.expect(registry.acknowledgeCrossClusterPrivateBGPSecretRevocation(peerScope, deleted) && deleted,
                  "masque_gateway_bilateral_revocation_deletes_secret");
    CrossClusterMasqueGatewayAuthority peerWithdrawn = {};
    suite.expect(registry.withdrawCrossClusterMasqueGateway(enrollment.pairUUID, peerMachine.uuid, 2, peerWithdrawn, &failure),
                  "masque_gateway_peer_withdraw_monotone");
    auto nextActive = recorded; nextActive.state = CrossClusterMasqueGatewayState::active; nextActive.generation = 3;
    auto rotated = nextActive;
    rotated.privateSessionCredentialSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv;
    suite.expect(prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(withdrawn, rotated),
                 "masque_gateway_reactivation_accepts_fresh_vault_credential");
    suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(recorded, rotated),
                 "masque_gateway_active_replacement_rejects_credential_rotation");
    auto staleReactivation = rotated; staleReactivation.generation = withdrawn.generation;
    suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(withdrawn, staleReactivation),
                 "masque_gateway_reactivation_rejects_equal_generation");
    --staleReactivation.generation;
    suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(withdrawn, staleReactivation),
                 "masque_gateway_reactivation_rejects_older_generation");
    auto changedIdentity = rotated; ++changedIdentity.peerMachineUUID;
    suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(withdrawn, changedIdentity),
                 "masque_gateway_reactivation_rejects_changed_machine");
    auto changedSlot = rotated; ++changedSlot.gatewaySlot;
    suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(withdrawn, changedSlot),
                 "masque_gateway_reactivation_rejects_changed_slot");
    auto repeatedWithdrawal = withdrawn; ++repeatedWithdrawal.generation;
    suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(withdrawn, repeatedWithdrawal),
                 "masque_gateway_reactivation_rejects_withdrawn_to_withdrawn");

    {
      // A cluster replacement preserves the enrolled pair but removes the
      // retired peer before its withdrawn local authority can be reactivated.
      String replacementPath = {}; replacementPath.snprintf<"{}/masque-peer-replacement"_ctv>(dbPath);
      MothershipClusterRegistry replacementRegistry(replacementPath); String replacementFailure = {};
      auto replacementEnrollment = enrollment; replacementEnrollment.pairUUID = 0xa001;
      replacementEnrollment.operationUUID = 0xa007;
      auto replacementIntent = privateIntent; replacementIntent.pairUUID = replacementEnrollment.pairUUID;
      replacementIntent.operationUUID = replacementEnrollment.operationUUID;
      MothershipClusterPairEnrollmentIntent replacementIntentRecorded = {}; bool replacementIntentResumed = false;
      suite.expect(replacementRegistry.recordClusterPairEnrollmentIntent(replacementIntent, replacementIntentRecorded,
                       replacementIntentResumed, &replacementFailure) && !replacementIntentResumed,
                   "masque_gateway_peer_replacement_pair_root_durable");

      auto replacementRequested = requested; replacementRequested.generation = 1;
      CrossClusterMasqueGatewayAuthority replacementInitial = {}; bool replacementResumed = false;
      suite.expect(replacementRegistry.putCrossClusterMasqueGateway(replacementRequested, replacementEnrollment,
                       local, peer, replacementInitial, replacementResumed, &replacementFailure) && !replacementResumed,
                   "masque_gateway_peer_replacement_initial_local_durable");
      auto replacementPeerRequested = peerRequested; replacementPeerRequested.generation = 1;
      auto replacementPeerEnrollment = peerEnrollment; replacementPeerEnrollment.pairUUID = replacementEnrollment.pairUUID;
      replacementPeerEnrollment.operationUUID = replacementEnrollment.operationUUID;
      CrossClusterMasqueGatewayAuthority replacementPeerInitial = {};
      suite.expect(replacementRegistry.putCrossClusterMasqueGateway(replacementPeerRequested, replacementPeerEnrollment,
                       peer, local, replacementPeerInitial, replacementResumed, &replacementFailure) && !replacementResumed,
                   "masque_gateway_peer_replacement_initial_peer_durable");

      ProdigyPairPrivateBGPSecretScope replacementLocalScope = {};
      replacementLocalScope.pairUUID = replacementEnrollment.pairUUID;
      replacementLocalScope.operationUUID = replacementEnrollment.operationUUID;
      replacementLocalScope.keyEpoch = replacementEnrollment.agreedKeyEpoch;
      replacementLocalScope.tunnelSlot = replacementRequested.tunnelSlot;
      replacementLocalScope.clusterUUID = local.clusterUUID; replacementLocalScope.machineUUID = localMachine.uuid;
      replacementLocalScope.authorityGeneration = replacementEnrollment.localAuthorityGeneration;
      replacementLocalScope.gatewayGeneration = 1;
      auto replacementPeerScope = replacementLocalScope;
      replacementPeerScope.clusterUUID = peer.clusterUUID; replacementPeerScope.machineUUID = peerMachine.uuid;
      bool replacementDeleted = false;
      suite.expect(replacementRegistry.acknowledgeCrossClusterPrivateBGPSecretRevocation(
                       replacementLocalScope, replacementDeleted) && !replacementDeleted,
                   "masque_gateway_peer_replacement_local_secret_revoked");
      CrossClusterMasqueGatewayAuthority replacementWithdrawn = {};
      suite.expect(replacementRegistry.withdrawCrossClusterMasqueGateway(replacementEnrollment.pairUUID,
                       localMachine.uuid, 2, replacementWithdrawn, &replacementFailure) &&
                       replacementWithdrawn.state == CrossClusterMasqueGatewayState::withdrawn,
                   "masque_gateway_peer_replacement_local_withdrawn");
      suite.expect(replacementRegistry.acknowledgeCrossClusterPrivateBGPSecretRevocation(
                       replacementPeerScope, replacementDeleted) && replacementDeleted,
                   "masque_gateway_peer_replacement_bilateral_secret_deleted");
      CrossClusterMasqueGatewayAuthority replacementPeerWithdrawn = {};
      suite.expect(replacementRegistry.withdrawCrossClusterMasqueGateway(replacementEnrollment.pairUUID,
                       peerMachine.uuid, 2, replacementPeerWithdrawn, &replacementFailure),
                   "masque_gateway_peer_replacement_peer_withdrawn");

      ClusterMachine replacementPeerMachine = peerMachine; replacementPeerMachine.uuid = 0x9008;
      replacementPeerMachine.addresses.publicAddresses.clear();
      replacementPeerMachine.addresses.publicAddresses.push_back(ClusterMachineAddress {"2001:db8::8"_ctv, 128, {}});
      auto peerWithRetiredMachine = peer; peerWithRetiredMachine.topology.machines.push_back(replacementPeerMachine);
      auto replacementPeerRequest = replacementRequested;
      replacementPeerRequest.peerMachineUUID = replacementPeerMachine.uuid; replacementPeerRequest.generation = 3;
      CrossClusterMasqueGatewayAuthority replacementRecorded = {};
      suite.expect(!replacementRegistry.putCrossClusterMasqueGateway(replacementPeerRequest, replacementEnrollment,
                       local, peerWithRetiredMachine, replacementRecorded, replacementResumed, &replacementFailure) &&
                       replacementFailure.equals("cross-cluster MASQUE gateway replacement peer remains commissioned"_ctv),
                   "masque_gateway_peer_replacement_rejects_retained_peer");
      auto peerAfterReplacement = peer;
      peerAfterReplacement.topology.machines[0] = replacementPeerMachine;
      suite.expect(replacementRegistry.putCrossClusterMasqueGateway(replacementPeerRequest, replacementEnrollment,
                       local, peerAfterReplacement, replacementRecorded, replacementResumed, &replacementFailure) &&
                       !replacementResumed && replacementRecorded.generation == 3 &&
                       replacementRecorded.peerMachineUUID == replacementPeerMachine.uuid,
                   "masque_gateway_peer_replacement_reactivates_with_current_commissioned_peer");
      suite.expect(prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementWithdrawn, replacementRecorded),
                   "masque_gateway_peer_replacement_is_shared_monotone_transition");
      CrossClusterMasqueGatewayAuthority replacementReloaded = {};
      suite.expect(replacementRegistry.putCrossClusterMasqueGateway(replacementPeerRequest, replacementEnrollment,
                       local, peerAfterReplacement, replacementReloaded, replacementResumed, &replacementFailure) &&
                       replacementResumed,
                   "masque_gateway_peer_replacement_exact_retry");
      suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementInitial, replacementRecorded),
                   "masque_gateway_peer_replacement_rejects_active_predecessor");
      auto equalReplacement = replacementRecorded; equalReplacement.generation = replacementWithdrawn.generation;
      suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementWithdrawn, equalReplacement),
                   "masque_gateway_peer_replacement_rejects_equal_generation");
      --equalReplacement.generation;
      suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementWithdrawn, equalReplacement),
                   "masque_gateway_peer_replacement_rejects_stale_generation");
      auto changedLocal = replacementRecorded; ++changedLocal.localMachineUUID;
      { const String credential = changedLocal.privateSessionCredentialSHA256;
        (void)prodigyDeriveCrossClusterMasquePrivateBGPTuple(changedLocal);
        changedLocal.privateSessionCredentialSHA256 = credential; }
      suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementWithdrawn, changedLocal),
                   "masque_gateway_peer_replacement_rejects_local_machine_change");
      auto changedPair = replacementRecorded; ++changedPair.pairUUID;
      { const String credential = changedPair.privateSessionCredentialSHA256;
        (void)prodigyDeriveCrossClusterMasquePrivateBGPTuple(changedPair);
        changedPair.privateSessionCredentialSHA256 = credential; }
      suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementWithdrawn, changedPair),
                   "masque_gateway_peer_replacement_rejects_pair_change");
      auto changedSlot = replacementRecorded; ++changedSlot.gatewaySlot;
      { const String credential = changedSlot.privateSessionCredentialSHA256;
        (void)prodigyDeriveCrossClusterMasquePrivateBGPTuple(changedSlot);
        changedSlot.privateSessionCredentialSHA256 = credential; }
      suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementWithdrawn, changedSlot),
                   "masque_gateway_peer_replacement_rejects_slot_change");
      auto changedRole = replacementRecorded;
      changedRole.localRole = CrossClusterMasqueGatewayRole::connector;
      suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementWithdrawn, changedRole),
                   "masque_gateway_peer_replacement_rejects_role_change");
      auto malformedTuple = replacementRecorded; ++malformedTuple.privatePeerBGPID;
      suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(replacementWithdrawn, malformedTuple),
                   "masque_gateway_peer_replacement_rejects_noncanonical_tuple");
    }
    const String priorCredentialDigest = recorded.privateSessionCredentialSHA256;
    auto restart = requested; restart.generation = 3;
    suite.expect(registry.putCrossClusterMasqueGateway(restart, enrollment, local, peer, recorded, resumed, &failure) &&
                     !resumed && recorded.generation == 3 && recorded.state == CrossClusterMasqueGatewayState::active,
                 "masque_gateway_reactivation_persists_same_scope");
    suite.expect(recorded.privateSessionCredentialSHA256 != priorCredentialDigest,
                 "masque_gateway_reactivation_mints_new_vault_credential");
    suite.expect(registry.putCrossClusterMasqueGateway(restart, enrollment, local, peer, loaded, resumed, &failure) && resumed,
                 "masque_gateway_reactivation_exact_retry");
    suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(recorded, withdrawn),
                 "masque_gateway_reactivation_rejects_stale_withdrawn_authority");
  }

  {
    MothershipClusterRegistry reopened(pathFaultReopenPath);
    ProdigyCrossClusterPathFaultGatewayLifecycleRecord lifecycle = {};
    String failure = {};
    suite.expect(pathFaultReopenExpectedRecorded &&
                     reopened.loadCrossClusterPathFaultLifecycle(
                         pathFaultReopenExpected.request, lifecycle, &failure) &&
                     MothershipClusterRegistry::crossClusterPathFaultLifecycleEqual(
                         lifecycle, pathFaultReopenExpected),
                 "masque_gateway_path_fault_lifecycle_reopens_exact_restored_record");
  }

  std::error_code cleanupError;
  std::filesystem::remove_all(std::string(reinterpret_cast<const char *>(dbPath.data()), dbPath.size()), cleanupError);
  suite.expect(!cleanupError, "cleanup_registry_directory");

  return (suite.failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
