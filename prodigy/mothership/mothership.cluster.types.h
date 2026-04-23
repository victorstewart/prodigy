#pragma once

#include <cstdint>
#include <cstdlib>

#include <enums/datacenter.h>
#include <prodigy/runtime.environment.h>
#include <services/prodigy.h>
#include <prodigy/types.h>

enum class MothershipClusterDeploymentMode : uint8_t
{
   local = 0,
   remote = 1,
   test = 2
};

enum class MothershipClusterProvider : uint8_t
{
   unknown = 0,
   gcp = 1,
   aws = 2,
   azure = 3,
   vultr = 4
};

enum class MothershipClusterControlKind : uint8_t
{
   unixSocket = 0
};

enum class MothershipClusterMachineSource : uint8_t
{
   adopted = 0,
   created = 1
};

enum class MothershipClusterTestHostMode : uint8_t
{
   local = 0,
   ssh = 1
};

enum class MothershipClusterTestBootstrapFamily : uint8_t
{
   ipv4 = 0,
   private6 = 1,
   public6 = 2,
   multihome6 = 3
};

class MothershipProdigyClusterControl
{
public:

   MothershipClusterControlKind kind = MothershipClusterControlKind::unixSocket;
   String path;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterControl& control)
{
   serializer.value1b(control.kind);
   serializer.text1b(control.path, UINT32_MAX);
}

class MothershipProdigyClusterGcpConfig
{
public:

   String serviceAccountEmail;
   String network;
   String subnetwork;

   bool configured(void) const
   {
      return serviceAccountEmail.size() > 0
         || network.size() > 0
         || subnetwork.size() > 0;
   }
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterGcpConfig& config)
{
   serializer.text1b(config.serviceAccountEmail, UINT32_MAX);
   serializer.text1b(config.network, UINT32_MAX);
   serializer.text1b(config.subnetwork, UINT32_MAX);
}

class MothershipProdigyClusterAwsConfig
{
public:

   String instanceProfileName;
   String instanceProfileArn;

   bool configured(void) const
   {
      return instanceProfileName.size() > 0
         || instanceProfileArn.size() > 0;
   }
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterAwsConfig& config)
{
   serializer.text1b(config.instanceProfileName, UINT32_MAX);
   serializer.text1b(config.instanceProfileArn, UINT32_MAX);
}

class MothershipProdigyClusterAzureConfig
{
public:

   String managedIdentityName;
   String managedIdentityResourceID;

   bool configured(void) const
   {
      return managedIdentityName.size() > 0
         || managedIdentityResourceID.size() > 0;
   }
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterAzureConfig& config)
{
   serializer.text1b(config.managedIdentityName, UINT32_MAX);
   serializer.text1b(config.managedIdentityResourceID, UINT32_MAX);
}

class MothershipProdigyClusterTestHost
{
public:

   MothershipClusterTestHostMode mode = MothershipClusterTestHostMode::local;
   ClusterMachineSSH ssh;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterTestHost& host)
{
   serializer.value1b(host.mode);
   serializer.object(host.ssh);
}

class MothershipProdigyClusterTestConfig
{
public:

   bool specified = false;
   MothershipProdigyClusterTestHost host;
   String workspaceRoot;
   uint32_t machineCount = 0;
   MothershipClusterTestBootstrapFamily brainBootstrapFamily = MothershipClusterTestBootstrapFamily::ipv4;
   bool enableFakeIpv4Boundary = false;
   uint32_t interContainerMTU = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterTestConfig& config)
{
   serializer.value1b(config.specified);
   serializer.object(config.host);
   serializer.text1b(config.workspaceRoot, UINT32_MAX);
   serializer.value4b(config.machineCount);
   serializer.value1b(config.brainBootstrapFamily);
   serializer.value1b(config.enableFakeIpv4Boundary);
   serializer.value4b(config.interContainerMTU);
}

class MothershipProdigyClusterMachineSchema
{
public:

   String schema;
   MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
   MachineLifetime lifetime = MachineLifetime::reserved;
   String ipxeScriptURL;
   String vmImageURI;
   String gcpInstanceTemplate;
   String gcpInstanceTemplateSpot;
   String providerMachineType;
   String providerReservationID;
   String region;
   String zone;
   MachineSchemaCpuCapability cpu;
   uint32_t budget = 0;

   bool operator==(const MothershipProdigyClusterMachineSchema& other) const
   {
      return schema.equals(other.schema)
         && kind == other.kind
         && lifetime == other.lifetime
         && ipxeScriptURL.equals(other.ipxeScriptURL)
         && vmImageURI.equals(other.vmImageURI)
         && gcpInstanceTemplate.equals(other.gcpInstanceTemplate)
         && gcpInstanceTemplateSpot.equals(other.gcpInstanceTemplateSpot)
         && providerMachineType.equals(other.providerMachineType)
         && providerReservationID.equals(other.providerReservationID)
         && region.equals(other.region)
         && zone.equals(other.zone)
         && cpu == other.cpu
         && budget == other.budget;
   }

   bool operator!=(const MothershipProdigyClusterMachineSchema& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterMachineSchema& schema)
{
   serializer.text1b(schema.schema, UINT32_MAX);
   serializer.value1b(schema.kind);
   serializer.value1b(schema.lifetime);
   serializer.text1b(schema.ipxeScriptURL, UINT32_MAX);
   serializer.text1b(schema.vmImageURI, UINT32_MAX);
   serializer.text1b(schema.gcpInstanceTemplate, UINT32_MAX);
   serializer.text1b(schema.gcpInstanceTemplateSpot, UINT32_MAX);
   serializer.text1b(schema.providerMachineType, UINT32_MAX);
   serializer.text1b(schema.providerReservationID, UINT32_MAX);
   serializer.text1b(schema.region, UINT32_MAX);
   serializer.text1b(schema.zone, UINT32_MAX);
   serializer.object(schema.cpu);
   serializer.value4b(schema.budget);
}

class MothershipProdigyClusterMachine
{
public:

   MothershipClusterMachineSource source = MothershipClusterMachineSource::adopted;
   ClusterMachineBacking backing = ClusterMachineBacking::cloud;
   MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
   MachineLifetime lifetime = MachineLifetime::reserved;
   bool isBrain = true;

   bool hasCloud = false;
   ClusterMachineCloud cloud;
   ClusterMachineSSH ssh;
   ClusterMachineAddresses addresses;
   ClusterMachineOwnership ownership;

   bool cloudPresent(void) const
   {
      return hasCloud
         || cloud.schema.size() > 0
         || cloud.providerMachineType.size() > 0
         || cloud.cloudID.size() > 0;
   }
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterMachine& machine)
{
   serializer.value1b(machine.source);
   serializer.value1b(machine.backing);
   serializer.value1b(machine.kind);
   serializer.value1b(machine.lifetime);
   serializer.value1b(machine.isBrain);
   bool hasCloud = machine.cloudPresent();
   serializer.value1b(hasCloud);
   machine.hasCloud = hasCloud;
   if (hasCloud)
   {
      serializer.object(machine.cloud);
   }
   else
   {
      machine.cloud = {};
   }
   serializer.object(machine.ssh);
   serializer.object(machine.addresses);
   serializer.object(machine.ownership);
}

class MothershipProdigyCluster
{
public:

   String name;
   uint128_t clusterUUID = 0;
   MothershipClusterDeploymentMode deploymentMode = MothershipClusterDeploymentMode::local;
   bool includeLocalMachine = true;
   MothershipClusterProvider provider = MothershipClusterProvider::unknown;
   MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
   String providerScope;
   String providerCredentialName;
   bool propagateProviderCredentialToProdigy = false;
   MothershipProdigyClusterAwsConfig aws;
   MothershipProdigyClusterGcpConfig gcp;
   MothershipProdigyClusterAzureConfig azure;

   Vector<MothershipProdigyClusterControl> controls;
   uint8_t datacenterFragment = 1;
   uint32_t autoscaleIntervalSeconds = 180;

   uint32_t nBrains = 1;
   Vector<MothershipProdigyClusterMachineSchema> machineSchemas;
   Vector<MothershipProdigyClusterMachine> machines;
   ClusterTopology topology;

   String bootstrapSshUser;
   Vault::SSHKeyPackage bootstrapSshKeyPackage;
   Vault::SSHKeyPackage bootstrapSshHostKeyPackage;
   String bootstrapSshPrivateKeyPath;
   String remoteProdigyPath;
   uint16_t sharedCPUOvercommitPermille = 1000;
   ProdigyEnvironmentBGPConfig bgp;
   MothershipProdigyClusterTestConfig test;

   ProdigyEnvironmentKind desiredEnvironment = ProdigyEnvironmentKind::unknown;
   bool environmentConfigured = false;

   int64_t lastRefreshMs = 0;
   String lastRefreshFailure;
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyCluster& cluster)
{
   serializer.text1b(cluster.name, UINT32_MAX);
   serializer.value16b(cluster.clusterUUID);
   serializer.value1b(cluster.deploymentMode);
   serializer.value1b(cluster.includeLocalMachine);
   serializer.value1b(cluster.provider);
   serializer.value1b(cluster.architecture);
   serializer.text1b(cluster.providerScope, UINT32_MAX);
   serializer.text1b(cluster.providerCredentialName, UINT32_MAX);
   serializer.value1b(cluster.propagateProviderCredentialToProdigy);
   serializer.object(cluster.aws);
   serializer.object(cluster.gcp);
   serializer.object(cluster.azure);
   serializer.container(cluster.controls, UINT32_MAX);
   serializer.value1b(cluster.datacenterFragment);
   serializer.value4b(cluster.autoscaleIntervalSeconds);
   serializer.value4b(cluster.nBrains);
   serializer.container(cluster.machineSchemas, UINT32_MAX);
   serializer.container(cluster.machines, UINT32_MAX);
   serializer.object(cluster.topology);
   serializer.text1b(cluster.bootstrapSshUser, UINT32_MAX);
   serializer.object(cluster.bootstrapSshKeyPackage);
   serializer.object(cluster.bootstrapSshHostKeyPackage);
   serializer.text1b(cluster.bootstrapSshPrivateKeyPath, UINT32_MAX);
   serializer.text1b(cluster.remoteProdigyPath, UINT32_MAX);
   serializer.value2b(cluster.sharedCPUOvercommitPermille);
   serializer.object(cluster.bgp);
   serializer.object(cluster.test);
   serializer.value1b(cluster.desiredEnvironment);
   serializer.value1b(cluster.environmentConfigured);
   serializer.value8b(cluster.lastRefreshMs);
   serializer.text1b(cluster.lastRefreshFailure, UINT32_MAX);
}

static inline const char *mothershipClusterDeploymentModeName(MothershipClusterDeploymentMode mode)
{
   switch (mode)
   {
      case MothershipClusterDeploymentMode::local:
      {
         return "local";
      }
      case MothershipClusterDeploymentMode::remote:
      {
         return "remote";
      }
      case MothershipClusterDeploymentMode::test:
      {
         return "test";
      }
   }

   return "unknown";
}

static inline bool mothershipClusterIncludesLocalMachine(const MothershipProdigyCluster& cluster)
{
   return cluster.deploymentMode == MothershipClusterDeploymentMode::local && cluster.includeLocalMachine;
}

static inline MothershipProdigyClusterMachineSchema *mothershipFindClusterMachineSchema(Vector<MothershipProdigyClusterMachineSchema>& machineSchemas, const String& schema)
{
   for (MothershipProdigyClusterMachineSchema& candidate : machineSchemas)
   {
      if (candidate.schema.equals(schema))
      {
         return &candidate;
      }
   }

   return nullptr;
}

static inline bool mothershipEqualClusterMachineSchemas(
   const Vector<MothershipProdigyClusterMachineSchema>& lhs,
   const Vector<MothershipProdigyClusterMachineSchema>& rhs)
{
   if (lhs.size() != rhs.size())
   {
      return false;
   }

   for (uint32_t index = 0; index < lhs.size(); ++index)
   {
      if (lhs[index] != rhs[index])
      {
         return false;
      }
   }

   return true;
}

static inline const MothershipProdigyClusterMachineSchema *mothershipFindClusterMachineSchema(const Vector<MothershipProdigyClusterMachineSchema>& machineSchemas, const String& schema)
{
   for (const MothershipProdigyClusterMachineSchema& candidate : machineSchemas)
   {
      if (candidate.schema.equals(schema))
      {
         return &candidate;
      }
   }

   return nullptr;
}

class MothershipProdigyClusterMachineSchemaPatch
{
public:

   String schema;
   bool hasKind = false;
   MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
   bool hasLifetime = false;
   MachineLifetime lifetime = MachineLifetime::reserved;
   bool hasIpxeScriptURL = false;
   String ipxeScriptURL;
   bool hasVmImageURI = false;
   String vmImageURI;
   bool hasGcpInstanceTemplate = false;
   String gcpInstanceTemplate;
   bool hasGcpInstanceTemplateSpot = false;
   String gcpInstanceTemplateSpot;
   bool hasProviderMachineType = false;
   String providerMachineType;
   bool hasProviderReservationID = false;
   String providerReservationID;
   bool hasRegion = false;
   String region;
   bool hasZone = false;
   String zone;
   bool hasCpu = false;
   MachineSchemaCpuCapability cpu;
   bool hasBudget = false;
   uint32_t budget = 0;
};

static inline bool mothershipUpsertClusterMachineSchema(
   Vector<MothershipProdigyClusterMachineSchema>& machineSchemas,
   const MothershipProdigyClusterMachineSchemaPatch& patch,
   bool *created = nullptr,
   String *failure = nullptr)
{
   if (created) *created = false;
   if (failure) failure->clear();

   if (patch.schema.size() == 0)
   {
      if (failure) failure->assign("schema required"_ctv);
      return false;
   }

   MothershipProdigyClusterMachineSchema *existing = mothershipFindClusterMachineSchema(machineSchemas, patch.schema);
   if (existing == nullptr)
   {
      machineSchemas.push_back(MothershipProdigyClusterMachineSchema{});
      existing = &machineSchemas.back();
      existing->schema = patch.schema;
      if (created) *created = true;
   }

   if (patch.hasKind) existing->kind = patch.kind;
   if (patch.hasLifetime) existing->lifetime = patch.lifetime;
   if (patch.hasIpxeScriptURL) existing->ipxeScriptURL = patch.ipxeScriptURL;
   if (patch.hasVmImageURI) existing->vmImageURI = patch.vmImageURI;
   if (patch.hasGcpInstanceTemplate) existing->gcpInstanceTemplate = patch.gcpInstanceTemplate;
   if (patch.hasGcpInstanceTemplateSpot) existing->gcpInstanceTemplateSpot = patch.gcpInstanceTemplateSpot;
   if (patch.hasProviderMachineType) existing->providerMachineType = patch.providerMachineType;
   if (patch.hasProviderReservationID) existing->providerReservationID = patch.providerReservationID;
   if (patch.hasRegion) existing->region = patch.region;
   if (patch.hasZone) existing->zone = patch.zone;
   if (patch.hasCpu) existing->cpu = patch.cpu;
   if (patch.hasBudget) existing->budget = patch.budget;
   return true;
}

static inline void mothershipBuildMachineConfigFromSchema(const MothershipProdigyClusterMachineSchema& schema, MachineConfig& config)
{
   config = {};
   config.kind = schema.kind;
   config.slug.assign(schema.schema);
   config.ipxeScriptURL.assign(schema.ipxeScriptURL);
   config.vmImageURI.assign(schema.vmImageURI);
   config.gcpInstanceTemplate.assign(schema.gcpInstanceTemplate);
   config.gcpInstanceTemplateSpot.assign(schema.gcpInstanceTemplateSpot);
   config.providerMachineType.assign(schema.providerMachineType);
   config.cpu = schema.cpu;
}

static inline bool mothershipDeltaClusterMachineBudget(
   Vector<MothershipProdigyClusterMachineSchema>& machineSchemas,
   const String& schema,
   int64_t delta,
   uint32_t *finalBudget = nullptr,
   String *failure = nullptr)
{
   if (finalBudget) *finalBudget = 0;
   if (failure) failure->clear();

   MothershipProdigyClusterMachineSchema *existing = mothershipFindClusterMachineSchema(machineSchemas, schema);
   if (existing == nullptr)
   {
      if (failure) failure->snprintf<"machine schema '{}' not found"_ctv>(schema);
      return false;
   }

   int64_t nextBudget = int64_t(existing->budget) + delta;
   if (nextBudget < 0)
   {
      nextBudget = 0;
   }
   else if (nextBudget > INT32_MAX)
   {
      nextBudget = INT32_MAX;
   }

   existing->budget = uint32_t(nextBudget);
   if (finalBudget) *finalBudget = existing->budget;
   return true;
}

static inline bool mothershipDeleteClusterMachineSchema(
   Vector<MothershipProdigyClusterMachineSchema>& machineSchemas,
   const String& schema,
   bool *removed = nullptr,
   String *failure = nullptr)
{
   if (removed) *removed = false;
   if (failure) failure->clear();

   if (schema.size() == 0)
   {
      if (failure) failure->assign("schema required"_ctv);
      return false;
   }

   for (auto it = machineSchemas.begin(); it != machineSchemas.end(); ++it)
   {
      if (it->schema.equals(schema))
      {
         machineSchemas.erase(it);
         if (removed) *removed = true;
         return true;
      }
   }

   if (failure) failure->snprintf<"machine schema '{}' not found"_ctv>(schema);
   return false;
}

static inline bool mothershipClusterProviderSupportsManagedBGP(MothershipClusterProvider provider)
{
   return provider == MothershipClusterProvider::vultr;
}

static inline const char *mothershipClusterProviderName(MothershipClusterProvider provider)
{
   switch (provider)
   {
      case MothershipClusterProvider::unknown:
      {
         return "unknown";
      }
      case MothershipClusterProvider::gcp:
      {
         return "gcp";
      }
      case MothershipClusterProvider::aws:
      {
         return "aws";
      }
      case MothershipClusterProvider::azure:
      {
         return "azure";
      }
      case MothershipClusterProvider::vultr:
      {
         return "vultr";
      }
   }

   return "unknown";
}

static inline bool parseMothershipClusterProvider(const String& value, MothershipClusterProvider& provider)
{
   if (value.equal("gcp"_ctv))
   {
      provider = MothershipClusterProvider::gcp;
      return true;
   }

   if (value.equal("aws"_ctv))
   {
      provider = MothershipClusterProvider::aws;
      return true;
   }

   if (value.equal("azure"_ctv))
   {
      provider = MothershipClusterProvider::azure;
      return true;
   }

   if (value.equal("vultr"_ctv))
   {
      provider = MothershipClusterProvider::vultr;
      return true;
   }

   if (value.equal("unknown"_ctv))
   {
      provider = MothershipClusterProvider::unknown;
      return true;
   }

   return false;
}

static inline const char *mothershipClusterControlKindName(MothershipClusterControlKind kind)
{
   switch (kind)
   {
      case MothershipClusterControlKind::unixSocket:
      {
         return "unixSocket";
      }
   }

   return "unknown";
}

static inline const char *mothershipClusterMachineSourceName(MothershipClusterMachineSource source)
{
   switch (source)
   {
      case MothershipClusterMachineSource::adopted:
      {
         return "adopted";
      }
      case MothershipClusterMachineSource::created:
      {
         return "created";
      }
   }

   return "unknown";
}

static inline const char *mothershipClusterTestHostModeName(MothershipClusterTestHostMode mode)
{
   switch (mode)
   {
      case MothershipClusterTestHostMode::local:
      {
         return "local";
      }
      case MothershipClusterTestHostMode::ssh:
      {
         return "ssh";
      }
   }

   return "unknown";
}

static inline const char *mothershipClusterTestBootstrapFamilyName(MothershipClusterTestBootstrapFamily family)
{
   switch (family)
   {
      case MothershipClusterTestBootstrapFamily::ipv4:
      {
         return "ipv4";
      }
      case MothershipClusterTestBootstrapFamily::private6:
      {
         return "private6";
      }
      case MothershipClusterTestBootstrapFamily::public6:
      {
         return "public6";
      }
      case MothershipClusterTestBootstrapFamily::multihome6:
      {
         return "multihome6";
      }
   }

   return "unknown";
}

static inline const char *machineKindName(MachineConfig::MachineKind kind)
{
   switch (kind)
   {
      case MachineConfig::MachineKind::bareMetal:
      {
         return "bareMetal";
      }
      case MachineConfig::MachineKind::vm:
      {
         return "vm";
      }
   }

   return "unknown";
}

static inline const char *defaultMothershipClusterSSHUser(void)
{
   return "root";
}

static inline const char *defaultMothershipRemoteProdigyPath(void)
{
   return "/root/prodigy";
}
