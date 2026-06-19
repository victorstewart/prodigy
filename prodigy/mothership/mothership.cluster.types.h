#pragma once

#include <cstdint>
#include <cstdlib>
#include <memory>

#include <prodigy/bundle.artifact.h>
#include <prodigy/enums/datacenter.h>
#include <prodigy/container.contract.h>
#include <prodigy/runtime.environment.h>
#include <services/random.h>
#include <services/prodigy.h>
#include <prodigy/types.h>

using MothershipTunnelX509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using MothershipTunnelPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

enum class MothershipClusterDeploymentMode : uint8_t {
  local = 0,
  remote = 1,
  test = 2
};

enum class MothershipClusterProvider : uint8_t {
  unknown = 0,
  gcp = 1,
  aws = 2,
  azure = 3,
  vultr = 4,
  cloudflare = 5,
  route53 = 6,
  gcpCloudDNS = 7,
  azureDNS = 8,
  vultrDNS = 9
};

enum class MothershipClusterControlKind : uint8_t {
  unixSocket = 0
};

enum class MothershipConnectivityKind : uint8_t {
  ssh = 0,
  tunnelProvider = 1
};

enum class MothershipClusterMachineSource : uint8_t {
  adopted = 0,
  created = 1
};

enum class MothershipClusterTestHostMode : uint8_t {
  local = 0,
  ssh = 1
};

enum class MothershipClusterTestBootstrapFamily : uint8_t {
  ipv4 = 0,
  private6 = 1,
  public6 = 2,
  multihome6 = 3
};

class MothershipProdigyClusterControl {
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

static inline bool mothershipTunnelProviderEgressIPv4HostAddressIsDenied(uint32_t address)
{
  return isRFC1918Private4(htonl(address)) ||
      (address >> 24) == 0 ||
      (address >> 24) == 127 ||
      (address >> 24) >= 224 ||
      (address & 0xffff0000u) == 0xa9fe0000u ||
      (address & 0xffc00000u) == 0x64400000u ||
      (address & 0xffffff00u) == 0xc0000000u ||
      (address & 0xffffff00u) == 0xc0000200u ||
      (address & 0xffffff00u) == 0xc0586300u ||
      (address & 0xfffe0000u) == 0xc6120000u ||
      (address & 0xffffff00u) == 0xc6336400u ||
      (address & 0xffffff00u) == 0xcb007100u;
}

static inline bool mothershipTunnelProviderEgressIPv4Literal(const String& host, uint32_t& address)
{
  String ownedHost = {};
  ownedHost.assign(host);
  struct in_addr ipv4 = {};
  if (inet_pton(AF_INET, ownedHost.c_str(), &ipv4) != 1)
  {
    address = 0;
    return false;
  }
  address = ntohl(ipv4.s_addr);
  return true;
}

struct MothershipTunnelGatewayClientAuth {
  String rootCertPem;
  String clientCertPem;
  String clientKeyPem;

  bool configured(void) const
  {
    return rootCertPem.size() > 0 && clientCertPem.size() > 0 && clientKeyPem.size() > 0;
  }
};

template <typename S>
static void serialize(S&& serializer, MothershipTunnelGatewayClientAuth& auth)
{
  serializer.text1b(auth.rootCertPem, UINT32_MAX);
  serializer.text1b(auth.clientCertPem, UINT32_MAX);
  serializer.text1b(auth.clientKeyPem, UINT32_MAX);
}

struct MothershipTunnelGatewayAuth {
  String rootCertPem;
  String serverCertPem;
  String serverKeyPem;

  bool configured(void) const
  {
    return rootCertPem.size() > 0 && serverCertPem.size() > 0 && serverKeyPem.size() > 0;
  }
};

template <typename S>
static void serialize(S&& serializer, MothershipTunnelGatewayAuth& auth)
{
  serializer.text1b(auth.rootCertPem, UINT32_MAX);
  serializer.text1b(auth.serverCertPem, UINT32_MAX);
  serializer.text1b(auth.serverKeyPem, UINT32_MAX);
}

static inline bool mothershipTunnelGatewayLeafIssuedByRoot(X509 *rootCert, EVP_PKEY *rootPublicKey, X509 *leafCert)
{
  return rootCert != nullptr && rootPublicKey != nullptr && leafCert != nullptr &&
      X509_check_issued(rootCert, leafCert) == X509_V_OK &&
      X509_verify(leafCert, rootPublicKey) == 1;
}

static inline bool mothershipTunnelGatewayLeafHasExtendedKeyUsage(X509 *leafCert, int nid)
{
  EXTENDED_KEY_USAGE *usage = leafCert == nullptr ? nullptr : static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(leafCert, NID_ext_key_usage, nullptr, nullptr));
  if (usage == nullptr)
  {
    return false;
  }

  bool found = false;
  for (int index = 0; index < sk_ASN1_OBJECT_num(usage); ++index)
  {
    const ASN1_OBJECT *object = sk_ASN1_OBJECT_value(usage, index);
    if (object != nullptr && OBJ_obj2nid(object) == nid)
    {
      found = true;
      break;
    }
  }
  sk_ASN1_OBJECT_pop_free(usage, ASN1_OBJECT_free);
  return found;
}

static inline bool mothershipTunnelGatewayLeafKeyMatches(X509 *rootCert, EVP_PKEY *rootPublicKey, X509 *leafCert, EVP_PKEY *leafKey, int extendedKeyUsageNid)
{
  return leafCert != nullptr && leafKey != nullptr &&
      X509_check_private_key(leafCert, leafKey) == 1 &&
      mothershipTunnelGatewayLeafIssuedByRoot(rootCert, rootPublicKey, leafCert) &&
      mothershipTunnelGatewayLeafHasExtendedKeyUsage(leafCert, extendedKeyUsageNid);
}

static inline bool mothershipTunnelGatewayClientAuthMaterialValid(const MothershipTunnelGatewayClientAuth& auth, String *failure = nullptr)
{
  MothershipTunnelX509Ptr rootCert(VaultPem::x509FromPem(auth.rootCertPem), X509_free);
  MothershipTunnelX509Ptr clientCert(VaultPem::x509FromPem(auth.clientCertPem), X509_free);
  MothershipTunnelPKeyPtr clientKey(VaultPem::privateKeyFromPem(auth.clientKeyPem), EVP_PKEY_free);
  MothershipTunnelPKeyPtr rootPublicKey(rootCert ? X509_get_pubkey(rootCert.get()) : nullptr, EVP_PKEY_free);
  bool ok = auth.configured() && mothershipTunnelGatewayLeafKeyMatches(rootCert.get(), rootPublicKey.get(), clientCert.get(), clientKey.get(), NID_client_auth);

  if (ok == false)
  {
    if (failure)
    {
      failure->assign("mothership tunnel gateway client auth certificate material invalid"_ctv);
    }
    return false;
  }

  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelGatewayAuthMaterialValid(const MothershipTunnelGatewayAuth& auth, String *failure = nullptr)
{
  MothershipTunnelX509Ptr rootCert(VaultPem::x509FromPem(auth.rootCertPem), X509_free);
  MothershipTunnelX509Ptr serverCert(VaultPem::x509FromPem(auth.serverCertPem), X509_free);
  MothershipTunnelPKeyPtr serverKey(VaultPem::privateKeyFromPem(auth.serverKeyPem), EVP_PKEY_free);
  MothershipTunnelPKeyPtr rootPublicKey(rootCert ? X509_get_pubkey(rootCert.get()) : nullptr, EVP_PKEY_free);
  bool ok = auth.configured() &&
      rootCert != nullptr &&
      mothershipTunnelGatewayLeafKeyMatches(rootCert.get(), rootPublicKey.get(), serverCert.get(), serverKey.get(), NID_server_auth);

  if (ok == false)
  {
    if (failure)
    {
      failure->assign("mothership tunnel gateway auth certificate material invalid"_ctv);
    }
    return false;
  }

  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelGatewayAuthorizeClientCertificate(const MothershipTunnelGatewayAuth& auth, const String& presentedClientCertPem, String *failure = nullptr)
{
  if (mothershipTunnelGatewayAuthMaterialValid(auth, failure) == false)
  {
    return false;
  }

  MothershipTunnelX509Ptr rootCert(VaultPem::x509FromPem(auth.rootCertPem), X509_free);
  MothershipTunnelX509Ptr clientCert(VaultPem::x509FromPem(presentedClientCertPem), X509_free);
  MothershipTunnelPKeyPtr rootPublicKey(rootCert ? X509_get_pubkey(rootCert.get()) : nullptr, EVP_PKEY_free);
  bool validClient = mothershipTunnelGatewayLeafIssuedByRoot(rootCert.get(), rootPublicKey.get(), clientCert.get()) && mothershipTunnelGatewayLeafHasExtendedKeyUsage(clientCert.get(), NID_client_auth);

  if (validClient == false)
  {
    if (failure)
    {
      failure->assign("mothership tunnel gateway client certificate invalid"_ctv);
    }
    return false;
  }
  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipIssueTunnelGatewayLeaf(
    const String& rootCertPem,
    const String& rootKeyPem,
    uint128_t uuid,
    bool serverAuth,
    bool clientAuth,
    String& certPem,
    String& keyPem,
    String *failure = nullptr)
{
  certPem.clear();
  keyPem.clear();
  String commonName = {};
  if (Vault::buildNodeCommonName(uuid, commonName) == false)
  {
    if (failure)
    {
      failure->assign("invalid mothership tunnel gateway auth uuid"_ctv);
    }
    return false;
  }

  MothershipTunnelX509Ptr rootCert(VaultPem::x509FromPem(rootCertPem), X509_free);
  MothershipTunnelPKeyPtr rootKey(VaultPem::privateKeyFromPem(rootKeyPem), EVP_PKEY_free);
  X509 *rawCert = nullptr;
  EVP_PKEY *rawKey = nullptr;
  Vector<String> ipAddresses = {};
  bool ok = rootCert != nullptr && rootKey != nullptr &&
      Vault::issueTransportCertificateEd25519(
          commonName,
          "Prodigy Mothership Tunnel"_ctv,
          false,
          serverAuth,
          clientAuth,
          825,
          ipAddresses,
          rootCert.get(),
          rootKey.get(),
          rawCert,
          rawKey,
          failure) &&
      VaultPem::x509ToPem(rawCert, certPem) &&
      VaultPem::privateKeyToPem(rawKey, keyPem);
  MothershipTunnelX509Ptr cert(rawCert, X509_free);
  MothershipTunnelPKeyPtr key(rawKey, EVP_PKEY_free);

  if (ok == false)
  {
    certPem.clear();
    keyPem.clear();
    if (failure && failure->size() == 0)
    {
      failure->assign("failed to issue mothership tunnel gateway certificate"_ctv);
    }
    return false;
  }

  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipGenerateTunnelGatewayAuth(
    MothershipTunnelGatewayClientAuth& clientAuth,
    MothershipTunnelGatewayAuth& gatewayAuth,
    String *failure = nullptr)
{
  clientAuth = {};
  gatewayAuth = {};

  Vault::TransportCertificateOptions options = {};
  options.subjectOrganization = "Prodigy Mothership Tunnel"_ctv;
  options.rootCommonName = "mothership-tunnel-gateway-root"_ctv;
  String rootKeyPem = {};
  if (Vault::generateTransportRootCertificateEd25519(gatewayAuth.rootCertPem, rootKeyPem, options, failure) == false)
  {
    return false;
  }

  clientAuth.rootCertPem = gatewayAuth.rootCertPem;

  if (mothershipIssueTunnelGatewayLeaf(gatewayAuth.rootCertPem, rootKeyPem, Random::generateNumberWithNBits<128, uint128_t>(), false, true, clientAuth.clientCertPem, clientAuth.clientKeyPem, failure) == false ||
      mothershipIssueTunnelGatewayLeaf(gatewayAuth.rootCertPem, rootKeyPem, Random::generateNumberWithNBits<128, uint128_t>(), true, false, gatewayAuth.serverCertPem, gatewayAuth.serverKeyPem, failure) == false)
  {
    clientAuth = {};
    gatewayAuth = {};
    Vault::secureClearString(rootKeyPem);
    return false;
  }
  Vault::secureClearString(rootKeyPem);

  if (failure)
  {
    failure->clear();
  }
  return true;
}

struct MothershipTunnelProviderSpec {
  String artifactSha256;
  uint64_t artifactBytes = 0;
  String dialEndpoint;
  String egressHost;
  uint16_t egressPort = 0;
  MothershipTunnelGatewayClientAuth clientAuth;

  // Create-time inputs only. These fields are intentionally omitted from
  // serialization so the registry stores only stable client-side metadata.
  String providerContainerBlobPath;
  MothershipTunnelGatewayAuth gatewayAuth;
};

template <typename S>
static void serialize(S&& serializer, MothershipTunnelProviderSpec& spec)
{
  serializer.text1b(spec.artifactSha256, 64);
  serializer.value8b(spec.artifactBytes);
  serializer.text1b(spec.dialEndpoint, UINT32_MAX);
  serializer.text1b(spec.egressHost, UINT32_MAX);
  serializer.value2b(spec.egressPort);
  serializer.object(spec.clientAuth);
}

struct MothershipConnectivity {
  MothershipConnectivityKind kind = MothershipConnectivityKind::ssh;
  MothershipTunnelProviderSpec tunnelProvider;
};

template <typename S>
static void serialize(S&& serializer, MothershipConnectivity& connectivity)
{
  serializer.value1b(connectivity.kind);
  serializer.object(connectivity.tunnelProvider);
}

using MothershipConnectivityRuntimeConfig = MothershipConnectivity;

constexpr static auto mothershipTunnelProviderContainerKindValue = "mothershipTunnelProvider"_ctv;
constexpr static auto mothershipTunnelProviderMothershipSocketPath = "/run/prodigy/mothership.sock"_ctv;
constexpr static auto mothershipTunnelProviderHostGatewaySocketPath = "/run/prodigy/mothership-tunnel-gateway.sock"_ctv;

struct MothershipTunnelProviderRuntimeState {
  uint128_t localContainerUUID = 0;
  String lastFailure;
};

static inline bool mothershipTunnelProviderSpecValid(const MothershipTunnelProviderSpec& spec, String *failure = nullptr)
{
  if (prodigyIsSHA256HexDigest(spec.artifactSha256) == false || spec.artifactBytes == 0)
  {
    if (failure)
    {
      failure->assign("mothership tunnel-provider artifact identity invalid"_ctv);
    }
    return false;
  }

  if (spec.dialEndpoint.size() == 0)
  {
    if (failure)
    {
      failure->assign("mothership tunnel-provider dial config invalid"_ctv);
    }
    return false;
  }

  if (spec.egressHost.size() == 0 || spec.egressPort == 0)
  {
    if (failure)
    {
      failure->assign("mothership tunnel-provider egress endpoint invalid"_ctv);
    }
    return false;
  }
  uint32_t egressAddress = 0;
  if (mothershipTunnelProviderEgressIPv4Literal(spec.egressHost, egressAddress) == false)
  {
    if (failure)
    {
      failure->assign("mothership tunnel-provider egress literal invalid"_ctv);
    }
    return false;
  }
  if (mothershipTunnelProviderEgressIPv4HostAddressIsDenied(egressAddress))
  {
    if (failure)
    {
      failure->assign("mothership tunnel-provider egress literal denied"_ctv);
    }
    return false;
  }

  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline void mothershipStripMothershipOnlyConnectivityFields(MothershipConnectivityRuntimeConfig& config)
{
  if (config.kind != MothershipConnectivityKind::tunnelProvider)
  {
    config.tunnelProvider = {};
    return;
  }

  config.tunnelProvider.clientAuth = {};
  config.tunnelProvider.providerContainerBlobPath.clear();
  config.tunnelProvider.gatewayAuth = {};
}

static inline bool mothershipConnectivityRuntimeConfigValid(const MothershipConnectivityRuntimeConfig& config, String *failure = nullptr)
{
  if (config.kind == MothershipConnectivityKind::ssh)
  {
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  if (config.kind != MothershipConnectivityKind::tunnelProvider)
  {
    if (failure)
    {
      failure->assign("mothership connectivity kind invalid"_ctv);
    }
    return false;
  }

  if (config.tunnelProvider.clientAuth.configured() || config.tunnelProvider.providerContainerBlobPath.size() > 0 || config.tunnelProvider.gatewayAuth.configured())
  {
    if (failure)
    {
      failure->assign("mothership tunnel-provider runtime config contains mothership-only fields"_ctv);
    }
    return false;
  }

  return mothershipTunnelProviderSpecValid(config.tunnelProvider, failure);
}

static inline bool mothershipBuildMothershipConnectivityRuntimeConfig(const MothershipConnectivity& connectivity, MothershipConnectivityRuntimeConfig& config, String *failure = nullptr)
{
  config = connectivity;
  mothershipStripMothershipOnlyConnectivityFields(config);
  return mothershipConnectivityRuntimeConfigValid(config, failure);
}

static inline void mothershipOwnConnectivityRuntimeConfig(const MothershipConnectivityRuntimeConfig& source, MothershipConnectivityRuntimeConfig& owned)
{
  owned = source;
  mothershipStripMothershipOnlyConnectivityFields(owned);
}

class MothershipProdigyClusterGcpConfig {
public:

  String serviceAccountEmail;
  String network;
  String subnetwork;

  bool configured(void) const
  {
    return serviceAccountEmail.size() > 0 || network.size() > 0 || subnetwork.size() > 0;
  }
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterGcpConfig& config)
{
  serializer.text1b(config.serviceAccountEmail, UINT32_MAX);
  serializer.text1b(config.network, UINT32_MAX);
  serializer.text1b(config.subnetwork, UINT32_MAX);
}

class MothershipProdigyClusterAwsConfig {
public:

  String instanceProfileName;
  String instanceProfileArn;

  bool configured(void) const
  {
    return instanceProfileName.size() > 0 || instanceProfileArn.size() > 0;
  }
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterAwsConfig& config)
{
  serializer.text1b(config.instanceProfileName, UINT32_MAX);
  serializer.text1b(config.instanceProfileArn, UINT32_MAX);
}

class MothershipProdigyClusterAzureConfig {
public:

  String managedIdentityName;
  String managedIdentityResourceID;

  bool configured(void) const
  {
    return managedIdentityName.size() > 0 || managedIdentityResourceID.size() > 0;
  }
};

template <typename S>
static void serialize(S&& serializer, MothershipProdigyClusterAzureConfig& config)
{
  serializer.text1b(config.managedIdentityName, UINT32_MAX);
  serializer.text1b(config.managedIdentityResourceID, UINT32_MAX);
}

class MothershipProdigyClusterTestHost {
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

class MothershipProdigyClusterTestConfig {
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

class MothershipProdigyClusterMachineSchema {
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
    return schema.equals(other.schema) && kind == other.kind && lifetime == other.lifetime && ipxeScriptURL.equals(other.ipxeScriptURL) && vmImageURI.equals(other.vmImageURI) && gcpInstanceTemplate.equals(other.gcpInstanceTemplate) && gcpInstanceTemplateSpot.equals(other.gcpInstanceTemplateSpot) && providerMachineType.equals(other.providerMachineType) && providerReservationID.equals(other.providerReservationID) && region.equals(other.region) && zone.equals(other.zone) && cpu == other.cpu && budget == other.budget;
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

class MothershipProdigyClusterMachine {
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
    return hasCloud || cloud.schema.size() > 0 || cloud.providerMachineType.size() > 0 || cloud.cloudID.size() > 0;
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

class MothershipProdigyCluster {
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
  MothershipClusterProvider dnsProvider = MothershipClusterProvider::unknown;
  String dnsProviderCredentialName;
  ProdigyACMEConfig acme;
  MothershipProdigyClusterAwsConfig aws;
  MothershipProdigyClusterGcpConfig gcp;
  MothershipProdigyClusterAzureConfig azure;

  Vector<MothershipProdigyClusterControl> controls;
  MothershipConnectivity mothershipConnectivity;
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
  ProdigyMachineReservedResources machineReservedResources;
  bool osUpdatesEnabled = false;
  Vector<OperatingSystemUpdatePolicy> osUpdatePolicies;
  uint32_t maxOSDrains = 1;
  uint32_t machineUpdateCadenceMins = 15;
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
  serializer.value1b(cluster.dnsProvider);
  serializer.text1b(cluster.dnsProviderCredentialName, UINT32_MAX);
  serializer.object(cluster.acme);
  serializer.object(cluster.aws);
  serializer.object(cluster.gcp);
  serializer.object(cluster.azure);
  serializer.container(cluster.controls, UINT32_MAX);
  serializer.object(cluster.mothershipConnectivity);
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
  serializer.object(cluster.machineReservedResources);
  serializer.value1b(cluster.osUpdatesEnabled);
  serializer.container(cluster.osUpdatePolicies, UINT32_MAX);
  serializer.value4b(cluster.maxOSDrains);
  serializer.value4b(cluster.machineUpdateCadenceMins);
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

class MothershipProdigyClusterMachineSchemaPatch {
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
  if (created)
  {
    *created = false;
  }
  if (failure)
  {
    failure->clear();
  }

  if (patch.schema.size() == 0)
  {
    if (failure)
    {
      failure->assign("schema required"_ctv);
    }
    return false;
  }

  MothershipProdigyClusterMachineSchema *existing = mothershipFindClusterMachineSchema(machineSchemas, patch.schema);
  if (existing == nullptr)
  {
    machineSchemas.push_back(MothershipProdigyClusterMachineSchema {});
    existing = &machineSchemas.back();
    existing->schema = patch.schema;
    if (created)
    {
      *created = true;
    }
  }

  if (patch.hasKind)
  {
    existing->kind = patch.kind;
  }
  if (patch.hasLifetime)
  {
    existing->lifetime = patch.lifetime;
  }
  if (patch.hasIpxeScriptURL)
  {
    existing->ipxeScriptURL = patch.ipxeScriptURL;
  }
  if (patch.hasVmImageURI)
  {
    existing->vmImageURI = patch.vmImageURI;
  }
  if (patch.hasGcpInstanceTemplate)
  {
    existing->gcpInstanceTemplate = patch.gcpInstanceTemplate;
  }
  if (patch.hasGcpInstanceTemplateSpot)
  {
    existing->gcpInstanceTemplateSpot = patch.gcpInstanceTemplateSpot;
  }
  if (patch.hasProviderMachineType)
  {
    existing->providerMachineType = patch.providerMachineType;
  }
  if (patch.hasProviderReservationID)
  {
    existing->providerReservationID = patch.providerReservationID;
  }
  if (patch.hasRegion)
  {
    existing->region = patch.region;
  }
  if (patch.hasZone)
  {
    existing->zone = patch.zone;
  }
  if (patch.hasCpu)
  {
    existing->cpu = patch.cpu;
  }
  if (patch.hasBudget)
  {
    existing->budget = patch.budget;
  }
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
  if (finalBudget)
  {
    *finalBudget = 0;
  }
  if (failure)
  {
    failure->clear();
  }

  MothershipProdigyClusterMachineSchema *existing = mothershipFindClusterMachineSchema(machineSchemas, schema);
  if (existing == nullptr)
  {
    if (failure)
    {
      failure->snprintf<"machine schema '{}' not found"_ctv>(schema);
    }
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
  if (finalBudget)
  {
    *finalBudget = existing->budget;
  }
  return true;
}

static inline bool mothershipDeleteClusterMachineSchema(
    Vector<MothershipProdigyClusterMachineSchema>& machineSchemas,
    const String& schema,
    bool *removed = nullptr,
    String *failure = nullptr)
{
  if (removed)
  {
    *removed = false;
  }
  if (failure)
  {
    failure->clear();
  }

  if (schema.size() == 0)
  {
    if (failure)
    {
      failure->assign("schema required"_ctv);
    }
    return false;
  }

  for (auto it = machineSchemas.begin(); it != machineSchemas.end(); ++it)
  {
    if (it->schema.equals(schema))
    {
      machineSchemas.erase(it);
      if (removed)
      {
        *removed = true;
      }
      return true;
    }
  }

  if (failure)
  {
    failure->snprintf<"machine schema '{}' not found"_ctv>(schema);
  }
  return false;
}

static inline bool mothershipClusterProviderSupportsManagedBGP(MothershipClusterProvider provider)
{
  return provider == MothershipClusterProvider::vultr;
}

static inline bool mothershipClusterProviderIsIaaS(MothershipClusterProvider provider)
{
  return provider == MothershipClusterProvider::gcp || provider == MothershipClusterProvider::aws || provider == MothershipClusterProvider::azure || provider == MothershipClusterProvider::vultr;
}

static inline bool mothershipClusterProviderIsDNS(MothershipClusterProvider provider)
{
  return provider == MothershipClusterProvider::cloudflare || provider == MothershipClusterProvider::route53 || provider == MothershipClusterProvider::gcpCloudDNS || provider == MothershipClusterProvider::azureDNS || provider == MothershipClusterProvider::vultrDNS;
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
    case MothershipClusterProvider::cloudflare:
      {
        return "cloudflare";
      }
    case MothershipClusterProvider::route53:
      {
        return "route53";
      }
    case MothershipClusterProvider::gcpCloudDNS:
      {
        return "gcp-cloud-dns";
      }
    case MothershipClusterProvider::azureDNS:
      {
        return "azure-dns";
      }
    case MothershipClusterProvider::vultrDNS:
      {
        return "vultr-dns";
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

  if (value.equal("cloudflare"_ctv))
  {
    provider = MothershipClusterProvider::cloudflare;
    return true;
  }

  if (value.equal("route53"_ctv) || value.equal("aws-route53"_ctv))
  {
    provider = MothershipClusterProvider::route53;
    return true;
  }

  if (value.equal("gcp-cloud-dns"_ctv) || value.equal("google-cloud-dns"_ctv))
  {
    provider = MothershipClusterProvider::gcpCloudDNS;
    return true;
  }

  if (value.equal("azure-dns"_ctv))
  {
    provider = MothershipClusterProvider::azureDNS;
    return true;
  }

  if (value.equal("vultr-dns"_ctv))
  {
    provider = MothershipClusterProvider::vultrDNS;
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

static inline const char *mothershipConnectivityKindName(MothershipConnectivityKind kind)
{
  switch (kind)
  {
    case MothershipConnectivityKind::ssh:
      {
        return "ssh";
      }
    case MothershipConnectivityKind::tunnelProvider:
      {
        return "tunnelProvider";
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
