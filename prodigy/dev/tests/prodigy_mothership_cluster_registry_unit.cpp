#include <prodigy/mothership/mothership.cluster.registry.h>
#include <services/debug.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>

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
      if (lhs[index].kind != rhs[index].kind
         || lhs[index].path.equals(rhs[index].path) == false)
      {
         return false;
      }
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
      if (lhs[index].schema.equals(rhs[index].schema) == false
         || lhs[index].kind != rhs[index].kind
         || lhs[index].lifetime != rhs[index].lifetime
         || lhs[index].cpu != rhs[index].cpu
         || lhs[index].ipxeScriptURL.equals(rhs[index].ipxeScriptURL) == false
         || lhs[index].vmImageURI.equals(rhs[index].vmImageURI) == false
         || lhs[index].gcpInstanceTemplate.equals(rhs[index].gcpInstanceTemplate) == false
         || lhs[index].gcpInstanceTemplateSpot.equals(rhs[index].gcpInstanceTemplateSpot) == false
         || lhs[index].providerMachineType.equals(rhs[index].providerMachineType) == false
         || lhs[index].providerReservationID.equals(rhs[index].providerReservationID) == false
         || lhs[index].region.equals(rhs[index].region) == false
         || lhs[index].zone.equals(rhs[index].zone) == false
         || lhs[index].budget != rhs[index].budget)
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
      if (lhs[index].source != rhs[index].source
         || lhs[index].backing != rhs[index].backing
         || lhs[index].kind != rhs[index].kind
         || lhs[index].lifetime != rhs[index].lifetime
         || lhs[index].isBrain != rhs[index].isBrain
         || lhs[index].cloud != rhs[index].cloud
         || lhs[index].ssh != rhs[index].ssh
         || lhs[index].addresses != rhs[index].addresses
         || lhs[index].ownership != rhs[index].ownership)
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

static bool equalTestHost(const MothershipProdigyClusterTestHost& lhs, const MothershipProdigyClusterTestHost& rhs)
{
   return lhs.mode == rhs.mode
      && lhs.ssh == rhs.ssh;
}

static bool equalTestConfig(const MothershipProdigyClusterTestConfig& lhs, const MothershipProdigyClusterTestConfig& rhs)
{
   return lhs.specified == rhs.specified
      && equalTestHost(lhs.host, rhs.host)
      && lhs.workspaceRoot.equals(rhs.workspaceRoot)
      && lhs.machineCount == rhs.machineCount
      && lhs.brainBootstrapFamily == rhs.brainBootstrapFamily
      && lhs.enableFakeIpv4Boundary == rhs.enableFakeIpv4Boundary
      && lhs.interContainerMTU == rhs.interContainerMTU;
}

static bool equalGcpConfig(const MothershipProdigyClusterGcpConfig& lhs, const MothershipProdigyClusterGcpConfig& rhs)
{
   return lhs.serviceAccountEmail.equals(rhs.serviceAccountEmail)
      && lhs.network.equals(rhs.network)
      && lhs.subnetwork.equals(rhs.subnetwork);
}

static bool equalAwsConfig(const MothershipProdigyClusterAwsConfig& lhs, const MothershipProdigyClusterAwsConfig& rhs)
{
   return lhs.instanceProfileName.equals(rhs.instanceProfileName)
      && lhs.instanceProfileArn.equals(rhs.instanceProfileArn);
}

static bool equalAzureConfig(const MothershipProdigyClusterAzureConfig& lhs, const MothershipProdigyClusterAzureConfig& rhs)
{
   return lhs.managedIdentityName.equals(rhs.managedIdentityName)
      && lhs.managedIdentityResourceID.equals(rhs.managedIdentityResourceID);
}

static const String& fixtureSSHDHostPublicKey(void)
{
   static String hostPublicKey = [] () -> String {
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
      if (schema.ipxeScriptURL.size() > 0) existing.ipxeScriptURL = schema.ipxeScriptURL;
      if (schema.vmImageURI.size() > 0) existing.vmImageURI = schema.vmImageURI;
      if (schema.gcpInstanceTemplate.size() > 0) existing.gcpInstanceTemplate = schema.gcpInstanceTemplate;
      if (schema.gcpInstanceTemplateSpot.size() > 0) existing.gcpInstanceTemplateSpot = schema.gcpInstanceTemplateSpot;
      if (schema.providerMachineType.size() > 0) existing.providerMachineType = schema.providerMachineType;
      if (schema.providerReservationID.size() > 0) existing.providerReservationID = schema.providerReservationID;
      if (schema.region.size() > 0) existing.region = schema.region;
      if (schema.zone.size() > 0) existing.zone = schema.zone;
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
   return lhs.name.equals(rhs.name)
      && lhs.clusterUUID == rhs.clusterUUID
      && lhs.deploymentMode == rhs.deploymentMode
      && lhs.architecture == rhs.architecture
      && lhs.includeLocalMachine == rhs.includeLocalMachine
      && lhs.provider == rhs.provider
      && lhs.providerScope.equals(rhs.providerScope)
      && lhs.providerCredentialName.equals(rhs.providerCredentialName)
      && lhs.propagateProviderCredentialToProdigy == rhs.propagateProviderCredentialToProdigy
      && equalAwsConfig(lhs.aws, rhs.aws)
      && equalGcpConfig(lhs.gcp, rhs.gcp)
      && equalAzureConfig(lhs.azure, rhs.azure)
      && equalControls(lhs.controls, rhs.controls)
      && lhs.nBrains == rhs.nBrains
      && equalMachineSchemas(lhs.machineSchemas, rhs.machineSchemas)
      && equalMachines(lhs.machines, rhs.machines)
      && lhs.topology == rhs.topology
      && lhs.bootstrapSshUser.equals(rhs.bootstrapSshUser)
      && lhs.bootstrapSshKeyPackage == rhs.bootstrapSshKeyPackage
      && lhs.bootstrapSshHostKeyPackage == rhs.bootstrapSshHostKeyPackage
      && lhs.bootstrapSshPrivateKeyPath.equals(rhs.bootstrapSshPrivateKeyPath)
      && lhs.remoteProdigyPath.equals(rhs.remoteProdigyPath)
      && lhs.sharedCPUOvercommitPermille == rhs.sharedCPUOvercommitPermille
      && equalEnvironmentBGP(lhs.bgp, rhs.bgp)
      && equalTestConfig(lhs.test, rhs.test)
      && lhs.desiredEnvironment == rhs.desiredEnvironment
      && lhs.environmentConfigured == rhs.environmentConfigured
      && lhs.lastRefreshMs == rhs.lastRefreshMs
      && lhs.lastRefreshFailure.equals(rhs.lastRefreshFailure);
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

   MothershipProdigyCluster local = {};
   local.name = "local-alpha"_ctv;
   local.deploymentMode = MothershipClusterDeploymentMode::local;
   local.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/tmp/prodigy-alpha.sock"_ctv
   });
   appendClusterMachineConfig(local, MachineConfig{
      .kind = MachineConfig::MachineKind::bareMetal,
      .slug = "local-dev"_ctv,
      .nLogicalCores = 8,
      .nMemoryMB = 16384,
      .nStorageMB = 131072
   });
   local.bgp.specified = true;
   local.desiredEnvironment = ProdigyEnvironmentKind::dev;
   local.lastRefreshMs = 42;
   local.lastRefreshFailure = "connection refused"_ctv;

   MothershipProdigyCluster storedLocal = local;

   MothershipProdigyCluster localAdopted = {};
   localAdopted.name = "local-homelab"_ctv;
   localAdopted.deploymentMode = MothershipClusterDeploymentMode::local;
   localAdopted.includeLocalMachine = false;
   localAdopted.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/local-homelab.sock"_ctv
   });
   appendClusterMachineConfig(localAdopted, MachineConfig{
      .kind = MachineConfig::MachineKind::bareMetal,
      .slug = "homelab-brain"_ctv,
      .nLogicalCores = 16,
      .nMemoryMB = 65536,
      .nStorageMB = 524288
   });
   appendClusterMachineConfig(localAdopted, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "homelab-worker"_ctv,
      .nLogicalCores = 8,
      .nMemoryMB = 32768,
      .nStorageMB = 262144
   });
   localAdopted.nBrains = 2;
   localAdopted.sharedCPUOvercommitPermille = 1500;
   localAdopted.bootstrapSshPrivateKeyPath = "/root/.ssh/homelab"_ctv;
   localAdopted.bgp.specified = true;
   localAdopted.bgp.config.enabled = true;
   localAdopted.bgp.config.ourBGPID = inet_addr("192.168.10.11");
   localAdopted.bgp.config.community = (uint32_t(64512) << 16) | 321u;
   localAdopted.bgp.config.nextHop4 = IPAddress("192.168.10.1", false);
   localAdopted.bgp.config.nextHop6 = IPAddress("2001:db8:10::1", true);
   localAdopted.bgp.config.peers.push_back(makeEnvironmentBGPPeer("169.254.1.1", "192.168.10.11", 64512, "homelab-md5-v4", 2));
   localAdopted.bgp.config.peers.push_back(makeEnvironmentBGPPeer("2001:19f0:ffff::1", "2001:db8:10::11", 64512, "homelab-md5-v6", 2));
   localAdopted.desiredEnvironment = ProdigyEnvironmentKind::dev;
   localAdopted.machines.push_back(MothershipProdigyClusterMachine{
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::owned,
      .kind = MachineConfig::MachineKind::bareMetal,
      .lifetime = MachineLifetime::owned,
      .isBrain = true,
      .ssh = makeMachineSSH("192.168.10.11"_ctv, 0),
      .addresses = makeMachineAddresses("192.168.10.11"_ctv),
      .ownership = ClusterMachineOwnership{
         .mode = ClusterMachineOwnershipMode::wholeMachine
      }
   });
   localAdopted.machines.push_back(MothershipProdigyClusterMachine{
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::owned,
      .kind = MachineConfig::MachineKind::bareMetal,
      .lifetime = MachineLifetime::owned,
      .isBrain = true,
      .ssh = makeMachineSSH("192.168.10.12"_ctv, 2222, "ops"_ctv, "/tmp/homelab-b"_ctv),
      .addresses = makeMachineAddresses("192.168.10.12"_ctv),
      .ownership = ClusterMachineOwnership{
         .mode = ClusterMachineOwnershipMode::wholeMachine
      }
   });
   localAdopted.machines.push_back(MothershipProdigyClusterMachine{
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::owned,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::owned,
      .isBrain = false,
      .ssh = makeMachineSSH("192.168.10.13"_ctv, 0),
      .addresses = makeMachineAddresses("192.168.10.13"_ctv),
      .ownership = ClusterMachineOwnership{
         .mode = ClusterMachineOwnershipMode::percentages,
         .nLogicalCoresBasisPoints = 5000,
         .nMemoryBasisPoints = 5000,
         .nStorageBasisPoints = 5000
      }
   });

   MothershipProdigyCluster storedLocalAdopted = localAdopted;
   storedLocalAdopted.bootstrapSshUser = defaultMothershipClusterSSHUser();
   storedLocalAdopted.remoteProdigyPath = defaultMothershipRemoteProdigyPath();
   storedLocalAdopted.machines[0].ssh.port = 22;
   storedLocalAdopted.machines[0].ssh.user = defaultMothershipClusterSSHUser();
   storedLocalAdopted.machines[0].ssh.privateKeyPath = localAdopted.bootstrapSshPrivateKeyPath;
   storedLocalAdopted.machines[2].ssh.port = 22;
   storedLocalAdopted.machines[2].ssh.user = defaultMothershipClusterSSHUser();
   storedLocalAdopted.machines[2].ssh.privateKeyPath = localAdopted.bootstrapSshPrivateKeyPath;

   MothershipProdigyCluster remoteCreated = {};
   remoteCreated.name = "managed-aws"_ctv;
   remoteCreated.deploymentMode = MothershipClusterDeploymentMode::remote;
   remoteCreated.provider = MothershipClusterProvider::aws;
   remoteCreated.providerCredentialName = "aws-prod"_ctv;
   remoteCreated.providerScope = "acct-prod/us-east-1"_ctv;
   remoteCreated.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
   remoteCreated.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/managed-aws.sock"_ctv
   });
   appendClusterMachineConfig(remoteCreated, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "aws-brain-vm"_ctv,
      .vmImageURI = "ami://aws-brain"_ctv,
      .nLogicalCores = 4,
      .nMemoryMB = 16384,
      .nStorageMB = 131072
   });
   appendClusterMachineConfig(remoteCreated, MachineConfig{
      .kind = MachineConfig::MachineKind::bareMetal,
      .slug = "aws-brain-metal"_ctv,
      .nLogicalCores = 32,
      .nMemoryMB = 131072,
      .nStorageMB = 1048576
   });
   remoteCreated.nBrains = 3;
   appendMachineSchema(remoteCreated, MothershipProdigyClusterMachineSchema{
      .schema = "aws-brain-vm"_ctv,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::ondemand,
      .providerMachineType = "c7i.large"_ctv,
      .budget = 2
   });
   appendMachineSchema(remoteCreated, MothershipProdigyClusterMachineSchema{
      .schema = "aws-brain-metal"_ctv,
      .kind = MachineConfig::MachineKind::bareMetal,
      .lifetime = MachineLifetime::reserved,
      .providerMachineType = "i3.metal"_ctv,
      .budget = 1
   });
   setRemoteClusterArchitecture(remoteCreated, MachineCpuArchitecture::x86_64);
   remoteCreated.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
   assignFixtureBootstrapSSHKeyPackage(remoteCreated);
   remoteCreated.desiredEnvironment = ProdigyEnvironmentKind::aws;
   remoteCreated.lastRefreshMs = 123456789;

   MothershipProdigyCluster storedRemoteCreated = remoteCreated;
   storedRemoteCreated.includeLocalMachine = false;
   storedRemoteCreated.bootstrapSshUser = defaultMothershipClusterSSHUser();
   storedRemoteCreated.remoteProdigyPath = defaultMothershipRemoteProdigyPath();

   MothershipProdigyCluster remoteAdopted = {};
   remoteAdopted.name = "adopted-gcp"_ctv;
   remoteAdopted.deploymentMode = MothershipClusterDeploymentMode::remote;
   remoteAdopted.provider = MothershipClusterProvider::gcp;
   remoteAdopted.providerCredentialName = "gcp-prod"_ctv;
   remoteAdopted.providerScope = "projects/prod-cluster"_ctv;
   remoteAdopted.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/adopted-gcp.sock"_ctv
   });
   appendClusterMachineConfig(remoteAdopted, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "gcp-brain"_ctv,
      .vmImageURI = "projects/prod/global/images/brain"_ctv,
      .gcpInstanceTemplate = "brain-template"_ctv,
      .gcpInstanceTemplateSpot = "brain-template-spot"_ctv,
      .nLogicalCores = 4,
      .nMemoryMB = 16384,
      .nStorageMB = 131072
   });
   appendMachineSchema(remoteAdopted, MothershipProdigyClusterMachineSchema{
      .schema = "gcp-brain"_ctv,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .providerMachineType = "n2-standard-4"_ctv
   });
   setRemoteClusterArchitecture(remoteAdopted, MachineCpuArchitecture::x86_64);
   remoteAdopted.nBrains = 2;
   remoteAdopted.bootstrapSshPrivateKeyPath = "/root/.ssh/adopted"_ctv;
   assignFixtureBootstrapSSHKeyPackage(remoteAdopted);
   remoteAdopted.desiredEnvironment = ProdigyEnvironmentKind::gcp;
   remoteAdopted.machines.push_back(MothershipProdigyClusterMachine{
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::cloud,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .isBrain = true,
      .cloud = ClusterMachineCloud{
         .schema = "gcp-brain"_ctv,
         .providerMachineType = "n2-standard-4"_ctv,
         .cloudID = "789654123000111"_ctv
      },
      .ssh = makeMachineSSH("35.1.2.3"_ctv, 0),
      .addresses = makeMachineAddresses("10.0.0.2"_ctv, "35.1.2.3"_ctv),
      .ownership = ClusterMachineOwnership{
         .mode = ClusterMachineOwnershipMode::wholeMachine
      }
   });
   remoteAdopted.machines.push_back(MothershipProdigyClusterMachine{
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::cloud,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .isBrain = true,
      .cloud = ClusterMachineCloud{
         .schema = "gcp-brain"_ctv,
         .providerMachineType = "n2-standard-4"_ctv,
         .cloudID = "789654123000222"_ctv
      },
      .ssh = makeMachineSSH("35.1.2.4"_ctv, 2202, "ubuntu"_ctv, "/tmp/adopted-b"_ctv),
      .addresses = makeMachineAddresses("10.0.0.3"_ctv, "35.1.2.4"_ctv),
      .ownership = ClusterMachineOwnership{
         .mode = ClusterMachineOwnershipMode::hardCaps,
         .nLogicalCoresCap = 2,
         .nMemoryMBCap = 4096,
         .nStorageMBCap = 8192
      }
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
   remoteManagedGcp.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/managed-gcp.sock"_ctv
   });
   remoteManagedGcp.gcp.serviceAccountEmail = "prodigy-brain@prod-cluster.iam.gserviceaccount.com"_ctv;
   appendMachineSchema(remoteManagedGcp, MothershipProdigyClusterMachineSchema{
      .schema = "gcp-brain-vm"_ctv,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::ondemand,
      .vmImageURI = "projects/prod-cluster/global/images/prodigy-brain"_ctv,
      .providerMachineType = "e2-medium"_ctv,
      .budget = 3
   });
   appendMachineSchema(remoteManagedGcp, MothershipProdigyClusterMachineSchema{
      .schema = "gcp-worker-vm"_ctv,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::spot,
      .vmImageURI = "projects/prod-cluster/global/images/prodigy-worker"_ctv,
      .providerMachineType = "e2-medium"_ctv,
      .budget = 2
   });
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
   remoteMixed.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/hybrid-azure.sock"_ctv
   });
   appendClusterMachineConfig(remoteMixed, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "azure-brain-vm"_ctv,
      .vmImageURI = "image://azure-brain"_ctv,
      .nLogicalCores = 4,
      .nMemoryMB = 16384,
      .nStorageMB = 131072
   });
   appendClusterMachineConfig(remoteMixed, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "azure-worker-vm"_ctv,
      .vmImageURI = "image://azure-worker"_ctv,
      .nLogicalCores = 4,
      .nMemoryMB = 8192,
      .nStorageMB = 65536
   });
   remoteMixed.nBrains = 3;
   remoteMixed.bootstrapSshPrivateKeyPath = "/root/.ssh/hybrid"_ctv;
   assignFixtureBootstrapSSHKeyPackage(remoteMixed);
   remoteMixed.machines.push_back(MothershipProdigyClusterMachine{
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::cloud,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .isBrain = true,
      .cloud = ClusterMachineCloud{
         .schema = "azure-brain-vm"_ctv,
         .providerMachineType = "Standard_D4s_v5"_ctv,
         .cloudID = "874563210000111"_ctv
      },
      .ssh = makeMachineSSH("203.0.113.44"_ctv, 22, "azureuser"_ctv, "/root/.ssh/hybrid"_ctv),
      .addresses = makeMachineAddresses("10.1.0.4"_ctv, "203.0.113.44"_ctv),
      .ownership = ClusterMachineOwnership{
         .mode = ClusterMachineOwnershipMode::wholeMachine
      }
   });
   appendMachineSchema(remoteMixed, MothershipProdigyClusterMachineSchema{
      .schema = "azure-brain-vm"_ctv,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::ondemand,
      .providerMachineType = "Standard_D4s_v5"_ctv,
      .budget = 3
   });
   appendMachineSchema(remoteMixed, MothershipProdigyClusterMachineSchema{
      .schema = "azure-worker-vm"_ctv,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::ondemand,
      .providerMachineType = "Standard_D2s_v5"_ctv,
      .budget = 2
   });
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
   testLocal.test.host.mode = MothershipClusterTestHostMode::local;
   testLocal.test.workspaceRoot = "/tmp/nametag-test-local"_ctv;
   testLocal.test.machineCount = 3;
   testLocal.test.brainBootstrapFamily = MothershipClusterTestBootstrapFamily::private6;
   testLocal.test.enableFakeIpv4Boundary = false;
   testLocal.sharedCPUOvercommitPermille = 1250;
   testLocal.bgp.specified = true;
   testLocal.bgp.config.enabled = false;
   testLocal.desiredEnvironment = ProdigyEnvironmentKind::dev;

   MothershipProdigyCluster storedTestLocal = testLocal;
   storedTestLocal.includeLocalMachine = false;
   mothershipResolveTestClusterControlRecord(storedTestLocal.controls, storedTestLocal);

   MothershipProdigyCluster testRemote = {};
   testRemote.name = "test-remote"_ctv;
   testRemote.deploymentMode = MothershipClusterDeploymentMode::test;
   testRemote.nBrains = 3;
   testRemote.remoteProdigyPath = "/root/prodigy"_ctv;
   testRemote.test.specified = true;
   testRemote.test.host.mode = MothershipClusterTestHostMode::ssh;
   testRemote.test.host.ssh.address = "203.0.113.90"_ctv;
   testRemote.test.host.ssh.port = 22;
   testRemote.test.host.ssh.user = "root"_ctv;
   testRemote.test.host.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   testRemote.test.host.ssh.hostPublicKeyOpenSSH = fixtureSSHDHostPublicKey();
   testRemote.test.workspaceRoot = "/root/prodigy-test-remote"_ctv;
   testRemote.test.machineCount = 4;
   testRemote.test.brainBootstrapFamily = MothershipClusterTestBootstrapFamily::multihome6;
   testRemote.test.enableFakeIpv4Boundary = false;
   testRemote.desiredEnvironment = ProdigyEnvironmentKind::dev;

   MothershipProdigyCluster storedTestRemote = testRemote;
   storedTestRemote.includeLocalMachine = false;
   mothershipResolveTestClusterControlRecord(storedTestRemote.controls, storedTestRemote);

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
   invalidRemoteMissingCredential.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/missing-api.sock"_ctv
   });
   appendClusterMachineConfig(invalidRemoteMissingCredential, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "aws-brain-vm"_ctv,
      .vmImageURI = "ami://aws-brain"_ctv,
      .nLogicalCores = 4,
      .nMemoryMB = 16384,
      .nStorageMB = 131072
   });
   invalidRemoteMissingCredential.nBrains = 1;
   appendMachineSchema(invalidRemoteMissingCredential, MothershipProdigyClusterMachineSchema{
      .schema = "aws-brain-vm"_ctv,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .providerMachineType = "c7i.large"_ctv,
      .budget = 1
   });
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

   MothershipProdigyCluster invalidNonGcpWithGcpConfig = remoteCreated;
   invalidNonGcpWithGcpConfig.name = "managed-aws-with-gcp-config"_ctv;
   invalidNonGcpWithGcpConfig.gcp.serviceAccountEmail = "prodigy-brain@prod-cluster.iam.gserviceaccount.com"_ctv;

   MothershipProdigyCluster invalidRemoteOwnedLifetime = remoteCreated;
   invalidRemoteOwnedLifetime.name = "remote-owned-lifetime"_ctv;
   invalidRemoteOwnedLifetime.machineSchemas[1].lifetime = MachineLifetime::owned;

   MothershipProdigyCluster invalidRemoteBGP = remoteCreated;
   invalidRemoteBGP.name = "remote-bgp-invalid"_ctv;
   invalidRemoteBGP.bgp = localAdopted.bgp;

   MothershipProdigyCluster remoteVultrBGP = remoteCreated;
   remoteVultrBGP.name = "remote-vultr-bgp"_ctv;
   remoteVultrBGP.provider = MothershipClusterProvider::vultr;
   remoteVultrBGP.providerCredentialName = "vultr-prod"_ctv;
   remoteVultrBGP.providerScope = "ewr"_ctv;
   remoteVultrBGP.aws = {};
   remoteVultrBGP.propagateProviderCredentialToProdigy = true;
   remoteVultrBGP.bgp = localAdopted.bgp;
   remoteVultrBGP.desiredEnvironment = ProdigyEnvironmentKind::vultr;
   remoteVultrBGP.lastRefreshMs = 0;

   MothershipProdigyCluster storedRemoteVultrBGP = remoteVultrBGP;
   storedRemoteVultrBGP.includeLocalMachine = false;
   storedRemoteVultrBGP.bootstrapSshUser = defaultMothershipClusterSSHUser();
   storedRemoteVultrBGP.remoteProdigyPath = defaultMothershipRemoteProdigyPath();

   MothershipProdigyCluster invalidSharedCPUOvercommit = local;
   invalidSharedCPUOvercommit.name = "local-invalid-overcommit"_ctv;
   invalidSharedCPUOvercommit.sharedCPUOvercommitPermille = 999;

   MothershipProdigyCluster invalidTestProvider = testLocal;
   invalidTestProvider.name = "test-provider-invalid"_ctv;
   invalidTestProvider.provider = MothershipClusterProvider::aws;

   MothershipProdigyCluster invalidTestControls = testLocal;
   invalidTestControls.name = "test-controls-invalid"_ctv;
   invalidTestControls.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/tmp/manual.sock"_ctv
   });

   MothershipProdigyCluster invalidTestMachineCount = testLocal;
   invalidTestMachineCount.name = "test-machine-count-invalid"_ctv;
   invalidTestMachineCount.test.machineCount = 1;

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
   invalidRemoteMixedCapacity.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/hybrid-invalid.sock"_ctv
   });
   appendClusterMachineConfig(invalidRemoteMixedCapacity, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "azure-brain-vm"_ctv,
      .vmImageURI = "image://azure-brain"_ctv,
      .nLogicalCores = 4,
      .nMemoryMB = 16384,
      .nStorageMB = 131072
   });
   invalidRemoteMixedCapacity.nBrains = 4;
   invalidRemoteMixedCapacity.bootstrapSshPrivateKeyPath = "/root/.ssh/hybrid"_ctv;
   assignFixtureBootstrapSSHKeyPackage(invalidRemoteMixedCapacity);
   appendMachineSchema(invalidRemoteMixedCapacity, MothershipProdigyClusterMachineSchema{
      .schema = "azure-brain-vm"_ctv,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .providerMachineType = "Standard_D4s_v5"_ctv,
      .budget = 1
   });
   setRemoteClusterArchitecture(invalidRemoteMixedCapacity, MachineCpuArchitecture::x86_64);
   invalidRemoteMixedCapacity.machines.push_back(MothershipProdigyClusterMachine{
      .source = MothershipClusterMachineSource::adopted,
      .backing = ClusterMachineBacking::cloud,
      .kind = MachineConfig::MachineKind::vm,
      .lifetime = MachineLifetime::reserved,
      .isBrain = true,
      .cloud = ClusterMachineCloud{
         .schema = "azure-brain-vm"_ctv,
         .providerMachineType = "Standard_D4s_v5"_ctv,
         .cloudID = "874563210000111"_ctv
      },
      .ssh = makeMachineSSH("203.0.113.44"_ctv, 22, "azureuser"_ctv, "/root/.ssh/hybrid"_ctv),
      .addresses = makeMachineAddresses("10.1.0.4"_ctv, "203.0.113.44"_ctv),
      .ownership = ClusterMachineOwnership{
         .mode = ClusterMachineOwnershipMode::wholeMachine
      }
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
      if (!createLocal) basics_log("detail create_local: %s\n", failure.c_str());
      suite.expect(createLocal, "create_local");
      suite.expect(createdCluster.clusterUUID != 0, "create_local_cluster_uuid_generated");
      storedLocal.clusterUUID = createdCluster.clusterUUID;
      suite.expect(equalClusters(storedLocal, createdCluster), "create_local_normalized");

      bool createRemoteCreated = registry.createCluster(remoteCreated, &createdCluster, &failure);
      if (!createRemoteCreated) basics_log("detail create_remote_created: %s\n", failure.c_str());
      suite.expect(createRemoteCreated, "create_remote_created");
      suite.expect(createdCluster.clusterUUID != 0, "create_remote_created_cluster_uuid_generated");
      storedRemoteCreated.clusterUUID = createdCluster.clusterUUID;
      suite.expect(equalClusters(storedRemoteCreated, createdCluster), "create_remote_created_normalized");

      bool createLocalAdopted = registry.createCluster(localAdopted, &createdCluster, &failure);
      if (!createLocalAdopted) basics_log("detail create_local_adopted: %s\n", failure.c_str());
      suite.expect(createLocalAdopted, "create_local_adopted");
      suite.expect(createdCluster.clusterUUID != 0, "create_local_adopted_cluster_uuid_generated");
      storedLocalAdopted.clusterUUID = createdCluster.clusterUUID;
      suite.expect(equalClusters(storedLocalAdopted, createdCluster), "create_local_adopted_normalized");

      bool createRemoteAdopted = registry.createCluster(remoteAdopted, &createdCluster, &failure);
      if (!createRemoteAdopted) basics_log("detail create_remote_adopted: %s\n", failure.c_str());
      suite.expect(createRemoteAdopted, "create_remote_adopted");
      suite.expect(createdCluster.clusterUUID != 0, "create_remote_adopted_cluster_uuid_generated");
      storedRemoteAdopted.clusterUUID = createdCluster.clusterUUID;
      suite.expect(equalClusters(storedRemoteAdopted, createdCluster), "create_remote_adopted_normalized");

      bool createRemoteManagedGcp = registry.createCluster(remoteManagedGcp, &createdCluster, &failure);
      if (!createRemoteManagedGcp) basics_log("detail create_remote_managed_gcp: %s\n", failure.c_str());
      suite.expect(createRemoteManagedGcp, "create_remote_managed_gcp");
      suite.expect(createdCluster.clusterUUID != 0, "create_remote_managed_gcp_cluster_uuid_generated");
      storedRemoteManagedGcp.clusterUUID = createdCluster.clusterUUID;
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
      if (!createRemoteMixed) basics_log("detail create_remote_mixed: %s\n", failure.c_str());
      suite.expect(createRemoteMixed, "create_remote_mixed");
      suite.expect(createdCluster.clusterUUID != 0, "create_remote_mixed_cluster_uuid_generated");
      storedRemoteMixed.clusterUUID = createdCluster.clusterUUID;
      storedRemoteMixed.azure.managedIdentityName.snprintf<"prodigy-{itoa}-azure-mi"_ctv>(uint64_t(storedRemoteMixed.clusterUUID));
      storedRemoteMixed.azure.managedIdentityResourceID.snprintf<
         "/subscriptions/sub-prod/resourceGroups/rg-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{}"_ctv>(
            storedRemoteMixed.azure.managedIdentityName);
      suite.expect(equalClusters(storedRemoteMixed, createdCluster), "create_remote_mixed_normalized");

      bool createTestLocal = registry.createCluster(testLocal, &createdCluster, &failure);
      if (!createTestLocal) basics_log("detail create_test_local: %s\n", failure.c_str());
      suite.expect(createTestLocal, "create_test_local");
      suite.expect(createdCluster.clusterUUID != 0, "create_test_local_cluster_uuid_generated");
      storedTestLocal.clusterUUID = createdCluster.clusterUUID;
      suite.expect(equalClusters(storedTestLocal, createdCluster), "create_test_local_normalized");

      bool createTestRemote = registry.createCluster(testRemote, &createdCluster, &failure);
      if (!createTestRemote) basics_log("detail create_test_remote: %s\n", failure.c_str());
      suite.expect(createTestRemote, "create_test_remote");
      suite.expect(createdCluster.clusterUUID != 0, "create_test_remote_cluster_uuid_generated");
      storedTestRemote.clusterUUID = createdCluster.clusterUUID;
      suite.expect(equalClusters(storedTestRemote, createdCluster), "create_test_remote_normalized");

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
      refreshedRemoteAdopted.lastRefreshMs = 424242;
      bool upsertExistingRemoteAdopted = registry.upsertCluster(refreshedRemoteAdopted, &refreshedRemoteAdopted, &failure);
      suite.expect(upsertExistingRemoteAdopted, "upsert_existing_remote_adopted");
      suite.expect(refreshedRemoteAdopted.lastRefreshMs == 424242, "upsert_existing_remote_adopted_refresh_ms");
      storedRemoteAdopted = refreshedRemoteAdopted;

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
      if (!createTopologyOwner) basics_log("detail create_topology_owner: %s\n", failure.c_str());
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

      bool createNonGcpWithGcpConfig = registry.createCluster(invalidNonGcpWithGcpConfig, nullptr, &failure);
      suite.expect(createNonGcpWithGcpConfig == false, "create_non_gcp_with_gcp_config_rejected");
      suite.expect(failure.equals("non-gcp clusters must not include gcp config"_ctv), "create_non_gcp_with_gcp_config_reason");

      bool createRemoteOwnedLifetime = registry.createCluster(invalidRemoteOwnedLifetime, nullptr, &failure);
      suite.expect(createRemoteOwnedLifetime == false, "create_remote_owned_lifetime_rejected");
      suite.expect(failure.equals("cluster machineSchemas must not use lifetime=owned"_ctv), "create_remote_owned_lifetime_reason");

      bool createRemoteBGP = registry.createCluster(invalidRemoteBGP, nullptr, &failure);
      suite.expect(createRemoteBGP == false, "create_remote_bgp_rejected");
      suite.expect(failure.equals("remote cluster provider does not support bgp"_ctv), "create_remote_bgp_reason");

      bool createRemoteVultrBGP = registry.createCluster(remoteVultrBGP, &createdCluster, &failure);
      if (!createRemoteVultrBGP) basics_log("detail create_remote_vultr_bgp: %s\n", failure.c_str());
      suite.expect(createRemoteVultrBGP, "create_remote_vultr_bgp");
      suite.expect(createdCluster.clusterUUID != 0, "create_remote_vultr_bgp_cluster_uuid_generated");
      storedRemoteVultrBGP.clusterUUID = createdCluster.clusterUUID;
      suite.expect(equalClusters(storedRemoteVultrBGP, createdCluster), "create_remote_vultr_bgp_normalized");

      bool createInvalidSharedCPUOvercommit = registry.createCluster(invalidSharedCPUOvercommit, nullptr, &failure);
      suite.expect(createInvalidSharedCPUOvercommit == false, "create_invalid_shared_cpu_overcommit_rejected");
      suite.expect(failure.equals("sharedCpuOvercommit must be in 1.0..2.0"_ctv), "create_invalid_shared_cpu_overcommit_reason");

      bool createTestProvider = registry.createCluster(invalidTestProvider, nullptr, &failure);
      suite.expect(createTestProvider == false, "create_test_provider_rejected");
      suite.expect(failure.equals("test clusters must not include provider"_ctv), "create_test_provider_reason");

      bool createTestControls = registry.createCluster(invalidTestControls, nullptr, &failure);
      suite.expect(createTestControls == false, "create_test_controls_rejected");
      suite.expect(failure.equals("test clusters manage controls automatically"_ctv), "create_test_controls_reason");

      bool createTestMachineCount = registry.createCluster(invalidTestMachineCount, nullptr, &failure);
      suite.expect(createTestMachineCount == false, "create_test_machine_count_rejected");
      suite.expect(failure.equals("test.machineCount is below nBrains"_ctv), "create_test_machine_count_reason");

      bool createNonTestWithTestConfig = registry.createCluster(invalidNonTestWithTestConfig, nullptr, &failure);
      suite.expect(createNonTestWithTestConfig == false, "create_non_test_with_test_config_rejected");
      suite.expect(failure.equals("non-test clusters must not include test config"_ctv), "create_non_test_with_test_config_reason");

      bool createInvalidRemoteMixedCapacity = registry.createCluster(invalidRemoteMixedCapacity, nullptr, &failure);
      suite.expect(createInvalidRemoteMixedCapacity == false, "create_remote_mixed_capacity_rejected");
      suite.expect(failure.equals("brain capacity is below nBrains"_ctv), "create_remote_mixed_capacity_reason");

      Vector<MothershipProdigyCluster> clusters;
      bool listClusters = registry.listClusters(clusters, &failure);
      if (!listClusters) basics_log("detail list_clusters: %s\n", failure.c_str());
      suite.expect(listClusters, "list_clusters");
      suite.expect(clusters.size() == 10, "list_clusters_count");
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
      MothershipProdigyCluster loadedTestRemote = {};

      bool reopenGetLocal = registry.getCluster("local-alpha"_ctv, loadedLocal, &failure);
      if (!reopenGetLocal) basics_log("detail reopen_get_local: %s\n", failure.c_str());
      suite.expect(reopenGetLocal, "reopen_get_local");

      bool reopenGetRemoteCreated = registry.getCluster("managed-aws"_ctv, loadedRemoteCreated, &failure);
      if (!reopenGetRemoteCreated) basics_log("detail reopen_get_remote_created: %s\n", failure.c_str());
      suite.expect(reopenGetRemoteCreated, "reopen_get_remote_created");

      bool reopenGetLocalAdopted = registry.getCluster("local-homelab"_ctv, loadedLocalAdopted, &failure);
      if (!reopenGetLocalAdopted) basics_log("detail reopen_get_local_adopted: %s\n", failure.c_str());
      suite.expect(reopenGetLocalAdopted, "reopen_get_local_adopted");

      bool reopenGetRemoteAdopted = registry.getCluster("adopted-gcp"_ctv, loadedRemoteAdopted, &failure);
      if (!reopenGetRemoteAdopted) basics_log("detail reopen_get_remote_adopted: %s\n", failure.c_str());
      suite.expect(reopenGetRemoteAdopted, "reopen_get_remote_adopted");

      bool reopenGetRemoteManagedGcp = registry.getCluster("managed-gcp"_ctv, loadedRemoteManagedGcp, &failure);
      if (!reopenGetRemoteManagedGcp) basics_log("detail reopen_get_remote_managed_gcp: %s\n", failure.c_str());
      suite.expect(reopenGetRemoteManagedGcp, "reopen_get_remote_managed_gcp");

      bool reopenGetRemoteMixed = registry.getCluster("hybrid-azure"_ctv, loadedRemoteMixed, &failure);
      if (!reopenGetRemoteMixed) basics_log("detail reopen_get_remote_mixed: %s\n", failure.c_str());
      suite.expect(reopenGetRemoteMixed, "reopen_get_remote_mixed");

      bool reopenGetRemoteVultrBGP = registry.getCluster("remote-vultr-bgp"_ctv, loadedRemoteVultrBGP, &failure);
      if (!reopenGetRemoteVultrBGP) basics_log("detail reopen_get_remote_vultr_bgp: %s\n", failure.c_str());
      suite.expect(reopenGetRemoteVultrBGP, "reopen_get_remote_vultr_bgp");

      bool reopenGetTestLocal = registry.getCluster("test-local"_ctv, loadedTestLocal, &failure);
      if (!reopenGetTestLocal) basics_log("detail reopen_get_test_local: %s\n", failure.c_str());
      suite.expect(reopenGetTestLocal, "reopen_get_test_local");

      bool reopenGetTestRemote = registry.getCluster("test-remote"_ctv, loadedTestRemote, &failure);
      if (!reopenGetTestRemote) basics_log("detail reopen_get_test_remote: %s\n", failure.c_str());
      suite.expect(reopenGetTestRemote, "reopen_get_test_remote");

      MothershipProdigyCluster loadedRemoteCreatedByUUID = {};
      String remoteCreatedIdentity = {};
      remoteCreatedIdentity.assignItoh(storedRemoteCreated.clusterUUID);
      bool reopenGetRemoteCreatedByUUID = registry.getClusterByIdentity(remoteCreatedIdentity, loadedRemoteCreatedByUUID, &failure);
      if (!reopenGetRemoteCreatedByUUID) basics_log("detail reopen_get_remote_created_uuid: %s\n", failure.c_str());
      suite.expect(reopenGetRemoteCreatedByUUID, "reopen_get_remote_created_by_uuid");

      MothershipProdigyCluster loadedRemoteMixedByUUID = {};
      String remoteMixedIdentity = {};
      remoteMixedIdentity.assignItoh(storedRemoteMixed.clusterUUID);
      bool reopenGetRemoteMixedByUUID = registry.getClusterByIdentity(remoteMixedIdentity, loadedRemoteMixedByUUID, &failure);
      if (!reopenGetRemoteMixedByUUID) basics_log("detail reopen_get_remote_mixed_uuid: %s\n", failure.c_str());
      suite.expect(reopenGetRemoteMixedByUUID, "reopen_get_remote_mixed_by_uuid");

      suite.expect(equalClusters(storedLocal, loadedLocal), "reopen_local_roundtrip");
      suite.expect(equalClusters(storedLocalAdopted, loadedLocalAdopted), "reopen_local_adopted_roundtrip");
      suite.expect(equalClusters(storedTestLocal, loadedTestLocal), "reopen_test_local_roundtrip");
      suite.expect(equalClusters(storedTestRemote, loadedTestRemote), "reopen_test_remote_roundtrip");
      suite.expect(equalClusters(storedRemoteCreated, loadedRemoteCreated), "reopen_remote_created_roundtrip");
      suite.expect(equalClusters(storedRemoteCreated, loadedRemoteCreatedByUUID), "reopen_remote_created_uuid_roundtrip");
      suite.expect(equalClusters(storedRemoteAdopted, loadedRemoteAdopted), "reopen_remote_adopted_roundtrip");
      suite.expect(equalClusters(storedRemoteManagedGcp, loadedRemoteManagedGcp), "reopen_remote_managed_gcp_roundtrip");
      suite.expect(equalClusters(storedRemoteMixed, loadedRemoteMixed), "reopen_remote_mixed_roundtrip");
      suite.expect(equalClusters(storedRemoteVultrBGP, loadedRemoteVultrBGP), "reopen_remote_vultr_bgp_roundtrip");
      suite.expect(equalClusters(storedRemoteMixed, loadedRemoteMixedByUUID), "reopen_remote_mixed_uuid_roundtrip");

      loadedTestLocal.desiredEnvironment = ProdigyEnvironmentKind::unknown;
      loadedTestLocal.environmentConfigured = true;
      loadedTestLocal.lastRefreshMs = 123456789;
      MothershipProdigyCluster refreshedTestLocal = {};
      bool upsertExistingTestLocal = registry.upsertCluster(loadedTestLocal, &refreshedTestLocal, &failure);
      if (!upsertExistingTestLocal) basics_log("detail upsert_existing_test_local: %s\n", failure.c_str());
      suite.expect(upsertExistingTestLocal, "upsert_existing_test_local");
      suite.expect(equalControls(storedTestLocal.controls, refreshedTestLocal.controls), "upsert_existing_test_local_controls");
      suite.expect(refreshedTestLocal.desiredEnvironment == ProdigyEnvironmentKind::dev, "upsert_existing_test_local_desired_environment_defaulted");
      suite.expect(refreshedTestLocal.lastRefreshMs == loadedTestLocal.lastRefreshMs, "upsert_existing_test_local_refresh_ms");

      bool removeLocal = registry.removeCluster("local-alpha"_ctv, &failure);
      if (!removeLocal) basics_log("detail remove_local: %s\n", failure.c_str());
      suite.expect(removeLocal, "remove_local");

      bool removeRemoteCreated = registry.removeCluster("managed-aws"_ctv, &failure);
      if (!removeRemoteCreated) basics_log("detail remove_remote_created: %s\n", failure.c_str());
      suite.expect(removeRemoteCreated, "remove_remote_created");

      bool removeLocalAdopted = registry.removeCluster("local-homelab"_ctv, &failure);
      if (!removeLocalAdopted) basics_log("detail remove_local_adopted: %s\n", failure.c_str());
      suite.expect(removeLocalAdopted, "remove_local_adopted");

      bool removeRemoteAdopted = registry.removeCluster("adopted-gcp"_ctv, &failure);
      if (!removeRemoteAdopted) basics_log("detail remove_remote_adopted: %s\n", failure.c_str());
      suite.expect(removeRemoteAdopted, "remove_remote_adopted");

      bool removeRemoteManagedGcp = registry.removeCluster("managed-gcp"_ctv, &failure);
      if (!removeRemoteManagedGcp) basics_log("detail remove_remote_managed_gcp: %s\n", failure.c_str());
      suite.expect(removeRemoteManagedGcp, "remove_remote_managed_gcp");

      bool removeRemoteMixed = registry.removeClusterByIdentity(remoteMixedIdentity, &failure);
      if (!removeRemoteMixed) basics_log("detail remove_remote_mixed: %s\n", failure.c_str());
      suite.expect(removeRemoteMixed, "remove_remote_mixed_by_uuid");

      bool removeRemoteVultrBGP = registry.removeCluster("remote-vultr-bgp"_ctv, &failure);
      if (!removeRemoteVultrBGP) basics_log("detail remove_remote_vultr_bgp: %s\n", failure.c_str());
      suite.expect(removeRemoteVultrBGP, "remove_remote_vultr_bgp");

      bool removeTopologyOwner = registry.removeCluster("topology-owner"_ctv, &failure);
      if (!removeTopologyOwner) basics_log("detail remove_topology_owner: %s\n", failure.c_str());
      suite.expect(removeTopologyOwner, "remove_topology_owner");

      bool removeTestLocal = registry.removeCluster("test-local"_ctv, &failure);
      if (!removeTestLocal) basics_log("detail remove_test_local: %s\n", failure.c_str());
      suite.expect(removeTestLocal, "remove_test_local");

      bool removeTestRemote = registry.removeCluster("test-remote"_ctv, &failure);
      if (!removeTestRemote) basics_log("detail remove_test_remote: %s\n", failure.c_str());
      suite.expect(removeTestRemote, "remove_test_remote");

      MothershipProdigyCluster recreatedRemoteMixed = remoteMixed;
      recreatedRemoteMixed.name = "hybrid-azure-recreated"_ctv;
      recreatedRemoteMixed.clusterUUID = storedRemoteMixed.clusterUUID;
      MothershipProdigyCluster recreatedStoredRemoteMixed = {};
      bool recreateRemoteMixedByFreedUUID = registry.createCluster(recreatedRemoteMixed, &recreatedStoredRemoteMixed, &failure);
      if (!recreateRemoteMixedByFreedUUID) basics_log("detail recreate_remote_mixed_uuid: %s\n", failure.c_str());
      suite.expect(recreateRemoteMixedByFreedUUID, "recreate_remote_mixed_with_freed_uuid");
      suite.expect(recreatedStoredRemoteMixed.clusterUUID == storedRemoteMixed.clusterUUID, "recreate_remote_mixed_with_freed_uuid_value");

      bool removeRecreatedRemoteMixed = registry.removeClusterByIdentity(remoteMixedIdentity, &failure);
      if (!removeRecreatedRemoteMixed) basics_log("detail remove_recreated_remote_mixed: %s\n", failure.c_str());
      suite.expect(removeRecreatedRemoteMixed, "remove_recreated_remote_mixed_by_uuid");

      Vector<MothershipProdigyCluster> clusters;
      bool listClustersEmpty = registry.listClusters(clusters, &failure);
      if (!listClustersEmpty) basics_log("detail list_clusters_empty: %s\n", failure.c_str());
      suite.expect(listClustersEmpty, "list_clusters_empty");
      suite.expect(clusters.size() == 0, "list_clusters_empty_count");
   }

   std::error_code cleanupError;
   std::filesystem::remove_all(std::string(reinterpret_cast<const char *>(dbPath.data()), dbPath.size()), cleanupError);
   suite.expect(!cleanupError, "cleanup_registry_directory");

   return (suite.failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
