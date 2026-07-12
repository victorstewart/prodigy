#pragma once

#include <algorithm>
#include <cctype>
#include <type_traits>
#include <utility>

#include <prodigy/machine.hardware.types.h>
#include <prodigy/runtime.environment.h>
#include <prodigy/enums/datacenter.h>
#include <networking/private4.h>
#include <services/prodigy.h>
#include <services/vault.h>
#include <prodigy/container.contract.h>
#include <prodigy/biphasal.key.h>
#include <prodigy/server.state.h>
#include <switchboard/common/constants.h>

#ifndef PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
#define PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION PRODIGY_DEBUG
#endif

class MothershipResponse {
public:

  bool success;
  String failure; // string failure response
};

template <typename S>
static void serialize(S&& serializer, MothershipResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
}

namespace Vault {

static inline bool operator==(const SSHKeyPackage& lhs, const SSHKeyPackage& rhs)
{
  return lhs.privateKeyOpenSSH.equals(rhs.privateKeyOpenSSH) && lhs.publicKeyOpenSSH.equals(rhs.publicKeyOpenSSH);
}

static inline bool operator!=(const SSHKeyPackage& lhs, const SSHKeyPackage& rhs)
{
  return (lhs == rhs) == false;
}

template <typename S>
static void serialize(S&& serializer, SSHKeyPackage& package)
{
  serializer.text1b(package.privateKeyOpenSSH, UINT32_MAX);
  serializer.text1b(package.publicKeyOpenSSH, UINT32_MAX);
}

} // namespace Vault

enum class MothershipConnectivityKind : uint8_t {
  ssh = 0,
  tunnelProvider = 1
};

enum class TunnelProviderPhase : uint8_t {
  disabled,
  awaitingMaterial,
  awaitingSession,
  healthy,
  backoff
};

static inline const char *tunnelProviderPhaseName(TunnelProviderPhase phase)
{
  switch (phase)
  {
    case TunnelProviderPhase::disabled:
      return "disabled";
    case TunnelProviderPhase::awaitingMaterial:
      return "awaitingMaterial";
    case TunnelProviderPhase::awaitingSession:
      return "awaitingSession";
    case TunnelProviderPhase::healthy:
      return "healthy";
    case TunnelProviderPhase::backoff:
      return "backoff";
  }
  return "unknown";
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

static inline bool operator==(const MothershipTunnelGatewayClientAuth& lhs, const MothershipTunnelGatewayClientAuth& rhs)
{
  return lhs.rootCertPem.equal(rhs.rootCertPem) &&
         lhs.clientCertPem.equal(rhs.clientCertPem) &&
         lhs.clientKeyPem.equal(rhs.clientKeyPem);
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

static inline bool operator==(const MothershipTunnelGatewayAuth& lhs, const MothershipTunnelGatewayAuth& rhs)
{
  return lhs.rootCertPem.equal(rhs.rootCertPem) &&
         lhs.serverCertPem.equal(rhs.serverCertPem) &&
         lhs.serverKeyPem.equal(rhs.serverKeyPem);
}

struct MothershipTunnelProviderSpec {
  String artifactSha256;
  uint64_t artifactBytes = 0;
  String dialEndpoint;
  SystemContainerEgressPolicy egress;
  MothershipTunnelGatewayClientAuth clientAuth;
};

template <typename S>
static void serialize(S&& serializer, MothershipTunnelProviderSpec& spec)
{
  serializer.text1b(spec.artifactSha256, 64);
  serializer.value8b(spec.artifactBytes);
  serializer.text1b(spec.dialEndpoint, UINT32_MAX);
  serializer.object(spec.egress);
  serializer.object(spec.clientAuth);
}

static inline bool operator==(const MothershipTunnelProviderSpec& lhs, const MothershipTunnelProviderSpec& rhs)
{
  return lhs.artifactSha256.equal(rhs.artifactSha256) &&
         lhs.artifactBytes == rhs.artifactBytes &&
         lhs.dialEndpoint.equal(rhs.dialEndpoint) &&
         lhs.egress.address4 == rhs.egress.address4 &&
         lhs.egress.port == rhs.egress.port &&
         lhs.clientAuth == rhs.clientAuth;
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

static inline bool operator==(const MothershipConnectivity& lhs, const MothershipConnectivity& rhs)
{
  return lhs.kind == rhs.kind &&
         (lhs.kind != MothershipConnectivityKind::tunnelProvider || lhs.tunnelProvider == rhs.tunnelProvider);
}

struct MothershipTunnelProviderDesiredState {
  MothershipConnectivity connectivity;
  MothershipTunnelGatewayAuth gatewayAuth;
};

template <typename S>
static void serialize(S&& serializer, MothershipTunnelProviderDesiredState& state)
{
  serializer.object(state.connectivity);
  serializer.object(state.gatewayAuth);
}

static inline bool operator==(const MothershipTunnelProviderDesiredState& lhs, const MothershipTunnelProviderDesiredState& rhs)
{
  return lhs.connectivity == rhs.connectivity && lhs.gatewayAuth == rhs.gatewayAuth;
}

struct SystemContainerArtifactRef {
  String sha256;
  uint64_t bytes = 0;
};

template <typename S>
static void serialize(S&& serializer, SystemContainerArtifactRef& ref)
{
  serializer.text1b(ref.sha256, 64);
  serializer.value8b(ref.bytes);
}

struct SystemContainerRuntimePlan {
  SystemContainerKind kind = SystemContainerKind::none;
  SystemContainerArtifactRef artifact;
  SystemContainerEgressPolicy egress;

  bool configured(void) const
  {
    return kind != SystemContainerKind::none;
  }
};

template <typename S>
static void serialize(S&& serializer, SystemContainerRuntimePlan& plan)
{
  serializer.value1b(plan.kind);
  serializer.object(plan.artifact);
  serializer.object(plan.egress);
}

class BrainReconcileStateRequest {
public:

  Vector<uint64_t> deploymentIDs;
  SystemContainerArtifactRef systemArtifact;
};

template <typename S>
static void serialize(S&& serializer, BrainReconcileStateRequest& request)
{
  serializer.object(request.deploymentIDs);
  serializer.object(request.systemArtifact);
}

static inline const char *machineCpuArchitectureName(MachineCpuArchitecture architecture)
{
  switch (architecture)
  {
    case MachineCpuArchitecture::x86_64:
      {
        return "x86_64";
      }
    case MachineCpuArchitecture::aarch64:
      {
        return "aarch64";
      }
    case MachineCpuArchitecture::arm:
      {
        return "arm";
      }
    case MachineCpuArchitecture::riscv64:
      {
        return "riscv64";
      }
    case MachineCpuArchitecture::unknown:
    default:
      {
        return "unknown";
      }
  }
}

static inline bool parseMachineCpuArchitecture(const String& text, MachineCpuArchitecture& architecture)
{
  architecture = MachineCpuArchitecture::unknown;

  if (text.equal("x86_64"_ctv) || text.equal("amd64"_ctv))
  {
    architecture = MachineCpuArchitecture::x86_64;
    return true;
  }

  if (text.equal("aarch64"_ctv) || text.equal("arm64"_ctv))
  {
    architecture = MachineCpuArchitecture::aarch64;
    return true;
  }

  if (text.equal("arm"_ctv))
  {
    architecture = MachineCpuArchitecture::arm;
    return true;
  }

  if (text.equal("riscv64"_ctv) || text.equal("riscv"_ctv))
  {
    architecture = MachineCpuArchitecture::riscv64;
    return true;
  }

  return false;
}

static inline bool prodigyMachineCpuArchitectureSupportedTarget(MachineCpuArchitecture architecture)
{
  return architecture == MachineCpuArchitecture::x86_64 || architecture == MachineCpuArchitecture::aarch64 || architecture == MachineCpuArchitecture::riscv64;
}

static inline void prodigyNormalizeIsaFeature(const String& source, String& normalized)
{
  normalized.clear();
  normalized.reserve(source.size());
  for (uint64_t index = 0; index < source.size(); ++index)
  {
    normalized.append(char(std::tolower(unsigned(source[index]))));
  }

  if (normalized.equal("avx512"_ctv))
  {
    normalized.assign("avx512f"_ctv);
  }
  else if (normalized.equal("neon"_ctv))
  {
    normalized.assign("asimd"_ctv);
  }
}

static inline void prodigyAppendNormalizedIsaFeature(Vector<String>& features, const String& feature)
{
  String normalized = {};
  prodigyNormalizeIsaFeature(feature, normalized);
  if (normalized.size() == 0)
  {
    return;
  }

  for (const String& existing : features)
  {
    if (existing.equals(normalized))
    {
      return;
    }
  }

  features.push_back(std::move(normalized));
}

static inline bool prodigyIsaFeaturesContain(const Vector<String>& features, const String& requiredFeature)
{
  String normalized = {};
  prodigyNormalizeIsaFeature(requiredFeature, normalized);
  for (const String& candidate : features)
  {
    if (candidate.equals(normalized))
    {
      return true;
    }
  }

  return false;
}

static inline bool prodigyIsaFeaturesMeetRequirements(const Vector<String>& available, const Vector<String>& required)
{
  for (const String& requiredFeature : required)
  {
    if (prodigyIsaFeaturesContain(available, requiredFeature) == false)
    {
      return false;
    }
  }

  return true;
}

enum class MachineSchemaCpuCapabilityProvenance : uint8_t {
  unavailable = 0,
  providerAuthoritative = 1,
  observedMachineHardware = 2
};

class MachineSchemaCpuCapability {
public:

  MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
  String cpuPlatform;
  Vector<String> isaFeatures;
  MachineSchemaCpuCapabilityProvenance provenance = MachineSchemaCpuCapabilityProvenance::unavailable;

  bool authoritative(void) const
  {
    return provenance == MachineSchemaCpuCapabilityProvenance::providerAuthoritative || provenance == MachineSchemaCpuCapabilityProvenance::observedMachineHardware;
  }

  bool operator==(const MachineSchemaCpuCapability& other) const
  {
    if (architecture != other.architecture || cpuPlatform.equals(other.cpuPlatform) == false || provenance != other.provenance || isaFeatures.size() != other.isaFeatures.size())
    {
      return false;
    }

    for (uint32_t index = 0; index < isaFeatures.size(); ++index)
    {
      if (isaFeatures[index].equals(other.isaFeatures[index]) == false)
      {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const MachineSchemaCpuCapability& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, MachineSchemaCpuCapability& capability)
{
  serializer.value1b(capability.architecture);
  serializer.text1b(capability.cpuPlatform, UINT32_MAX);
  serializer.container(capability.isaFeatures, UINT32_MAX);
  serializer.value1b(capability.provenance);
}

enum class ExternalAddressTransport : uint8_t {

  tcp = 0,
  quic = 1
};

enum class ExternalAddressFamily : uint8_t {

  ipv4 = 0,
  ipv6 = 1
};

enum class ExternalAddressSource : uint8_t {

  distributableSubnet = 0,
  hostPublicAddress = 1,
  registeredRoutablePrefix = 2
};

enum class ExternalSubnetRouting : uint8_t {

  switchboardBGP = 0,
  switchboardPinnedRoute = 1
};

enum class ExternalSubnetUsage : uint8_t {

  wormholes = 0,
  whiteholes = 1,
  both = 2
};

enum class RoutableIngressScope : uint8_t {

  switchboardFleet = 0,
  singleMachine = 1
};

enum class RoutablePrefixKind : uint8_t {

  BGP = 0,
  elastic = 1
};

enum class ElasticPrefixIntent : uint8_t {

  any = 0,
  create = 1,
  anyOrCreate = 2
};

class Whitehole {
public:

  ExternalAddressTransport transport = ExternalAddressTransport::tcp;
  ExternalAddressFamily family = ExternalAddressFamily::ipv6;
  ExternalAddressSource source = ExternalAddressSource::registeredRoutablePrefix;
  bool hasAddress = false;
  IPAddress address;
  uint16_t sourcePort = 0;
  uint64_t bindingNonce = 0;
};

static inline bool whiteholeDeclarationValid(const Whitehole& whitehole)
{
  return (whitehole.transport == ExternalAddressTransport::tcp || whitehole.transport == ExternalAddressTransport::quic) &&
         (whitehole.family == ExternalAddressFamily::ipv4 || whitehole.family == ExternalAddressFamily::ipv6) &&
         (whitehole.source == ExternalAddressSource::hostPublicAddress ||
          whitehole.source == ExternalAddressSource::registeredRoutablePrefix);
}

static inline bool resolvedWhiteholesValid(const Vector<Whitehole>& whiteholes)
{
  if (whiteholes.empty() || whiteholes.size() > MAX_WHITEHOLE_BINDINGS)
  {
    return false;
  }

  class WhiteholeTupleKey {
  public:

    uint32_t address[4] = {};
    uint32_t attributes = 0;

    explicit WhiteholeTupleKey(const Whitehole& whitehole)
    {
      memcpy(address, whitehole.address.v6, sizeof(address));
      attributes = uint32_t(whitehole.sourcePort) |
                   (uint32_t(whitehole.transport) << 16) |
                   (uint32_t(whitehole.address.is6) << 24);
    }

    uint64_t hash(void) const
    {
      return Hasher::hash<Hasher::SeedPolicy::thread_shared>(reinterpret_cast<const uint8_t *>(this), sizeof(*this));
    }

    bool equals(const WhiteholeTupleKey& other) const
    {
      return memcmp(address, other.address, sizeof(address)) == 0 && attributes == other.attributes;
    }
  };
  static_assert(sizeof(WhiteholeTupleKey) == 20);

  bytell_hash_set<WhiteholeTupleKey> tuples = {};
  tuples.reserve(whiteholes.size());
  for (const Whitehole& whitehole : whiteholes)
  {
    if (whiteholeDeclarationValid(whitehole) == false || whitehole.hasAddress == false ||
        whitehole.address.isNull() || whitehole.sourcePort == 0 || whitehole.bindingNonce == 0 ||
        whitehole.address.is6 != (whitehole.family == ExternalAddressFamily::ipv6))
    {
      return false;
    }
    if (tuples.emplace(WhiteholeTupleKey(whitehole)).second == false)
    {
      return false;
    }
  }
  return true;
}

template <typename S>
static void serialize(S&& serializer, Whitehole& need)
{
  serializer.value1b(need.transport);
  serializer.value1b(need.family);
  serializer.value1b(need.source);
  serializer.value1b(need.hasAddress);
  serializer.object(need.address);
  serializer.value2b(need.sourcePort);
  serializer.value8b(need.bindingNonce);
}

class DistributableExternalSubnet {
public:

  uint128_t uuid = 0;
  String name;
  RoutablePrefixKind kind = RoutablePrefixKind::BGP;
  IPPrefix subnet;
  IPPrefix deliverySubnet;
  ExternalSubnetRouting routing = ExternalSubnetRouting::switchboardBGP;
  ExternalSubnetUsage usage = ExternalSubnetUsage::wormholes;
  RoutableIngressScope ingressScope = RoutableIngressScope::switchboardFleet;
  uint128_t machineUUID = 0;
  String providerPool;
  String providerAllocationID;
  String providerAssociationID;
  bool releaseOnRemove = false;
};

template <typename S>
static void serialize(S&& serializer, DistributableExternalSubnet& subnet)
{
  serializer.value16b(subnet.uuid);
  serializer.text1b(subnet.name, UINT32_MAX);
  serializer.value1b(subnet.kind);
  serializer.object(subnet.subnet);
  serializer.object(subnet.deliverySubnet);
  serializer.value1b(subnet.routing);
  serializer.value1b(subnet.usage);
  serializer.value1b(subnet.ingressScope);
  serializer.value16b(subnet.machineUUID);
  serializer.text1b(subnet.providerPool, UINT32_MAX);
  serializer.text1b(subnet.providerAllocationID, UINT32_MAX);
  serializer.text1b(subnet.providerAssociationID, UINT32_MAX);
  serializer.value1b(subnet.releaseOnRemove);
}

class ProdigyPendingElasticAddressRelease {
public:

  constexpr static uint8_t currentVersion = 1;

  uint8_t version = currentVersion;
  uint64_t operationID = 0;
  uint64_t transitionGeneration = 0;
  uint128_t transactionNonce = 0;
  DistributableExternalSubnet prefix;
  uint32_t attempts = 0;
  int64_t nextAttemptMs = 0;
  String lastFailure;

  bool operator==(const ProdigyPendingElasticAddressRelease& other) const
  {
    return version == other.version && operationID == other.operationID &&
           transitionGeneration == other.transitionGeneration &&
           transactionNonce == other.transactionNonce &&
           prefix.uuid == other.prefix.uuid && prefix.name.equals(other.prefix.name) &&
           prefix.kind == other.prefix.kind && prefix.subnet.equals(other.prefix.subnet) &&
           prefix.deliverySubnet.equals(other.prefix.deliverySubnet) &&
           prefix.routing == other.prefix.routing && prefix.usage == other.prefix.usage &&
           prefix.ingressScope == other.prefix.ingressScope &&
           prefix.machineUUID == other.prefix.machineUUID &&
           prefix.providerPool.equals(other.prefix.providerPool) &&
           prefix.providerAllocationID.equals(other.prefix.providerAllocationID) &&
           prefix.providerAssociationID.equals(other.prefix.providerAssociationID) &&
           prefix.releaseOnRemove == other.prefix.releaseOnRemove &&
           attempts == other.attempts && nextAttemptMs == other.nextAttemptMs &&
           lastFailure.equals(other.lastFailure);
  }

  bool operator!=(const ProdigyPendingElasticAddressRelease& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPendingElasticAddressRelease& release)
{
  serializer.value1b(release.version);
  serializer.value8b(release.operationID);
  serializer.value8b(release.transitionGeneration);
  serializer.value16b(release.transactionNonce);
  serializer.object(release.prefix);
  serializer.value4b(release.attempts);
  serializer.value8b(release.nextAttemptMs);
  serializer.text1b(release.lastFailure, UINT32_MAX);
}

class RoutableSubnetRegistration {
public:

  DistributableExternalSubnet subnet;
  ExternalAddressFamily family = ExternalAddressFamily::ipv4;
  ElasticPrefixIntent elasticIntent = ElasticPrefixIntent::create;
  String requestedAddress;
  bool success = false;
  bool created = false;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, RoutableSubnetRegistration& payload)
{
  serializer.object(payload.subnet);
  serializer.value1b(payload.family);
  serializer.value1b(payload.elasticIntent);
  serializer.text1b(payload.requestedAddress, UINT32_MAX);
  serializer.value1b(payload.success);
  serializer.value1b(payload.created);
  serializer.text1b(payload.failure, UINT32_MAX);
}

class ProdigyPendingElasticAddressAssignment {
public:

  constexpr static uint8_t currentVersion = 1;

  uint8_t version = currentVersion;
  uint64_t operationID = 0;
  uint64_t transitionGeneration = 0;
  uint128_t transactionNonce = 0;
  uint128_t machineUUID = 0;
  String machineCloudID;
  IPPrefix expectedDeliveryPrefix;
  RoutableSubnetRegistration registration;
  String providerPlan;
  String providerPlanBindingDigest;
  bool compensating = false;
  uint32_t attempts = 0;
  int64_t nextAttemptMs = 0;
  String lastFailure;

  bool operator==(const ProdigyPendingElasticAddressAssignment& other) const
  {
    return version == other.version && operationID == other.operationID &&
           transitionGeneration == other.transitionGeneration &&
           transactionNonce == other.transactionNonce && machineUUID == other.machineUUID &&
           machineCloudID.equals(other.machineCloudID) &&
           expectedDeliveryPrefix.equals(other.expectedDeliveryPrefix) &&
           registration.subnet.uuid == other.registration.subnet.uuid &&
           registration.subnet.name.equals(other.registration.subnet.name) &&
           registration.subnet.kind == other.registration.subnet.kind &&
           registration.subnet.subnet.equals(other.registration.subnet.subnet) &&
           registration.subnet.deliverySubnet.equals(other.registration.subnet.deliverySubnet) &&
           registration.subnet.routing == other.registration.subnet.routing &&
           registration.subnet.usage == other.registration.subnet.usage &&
           registration.subnet.ingressScope == other.registration.subnet.ingressScope &&
           registration.subnet.machineUUID == other.registration.subnet.machineUUID &&
           registration.subnet.providerPool.equals(other.registration.subnet.providerPool) &&
           registration.subnet.providerAllocationID.equals(other.registration.subnet.providerAllocationID) &&
           registration.subnet.providerAssociationID.equals(other.registration.subnet.providerAssociationID) &&
           registration.subnet.releaseOnRemove == other.registration.subnet.releaseOnRemove &&
           registration.family == other.registration.family &&
           registration.elasticIntent == other.registration.elasticIntent &&
           registration.requestedAddress.equals(other.registration.requestedAddress) &&
           registration.success == other.registration.success &&
           registration.created == other.registration.created &&
           registration.failure.equals(other.registration.failure) &&
           providerPlan.equals(other.providerPlan) &&
           providerPlanBindingDigest.equals(other.providerPlanBindingDigest) &&
           compensating == other.compensating &&
           attempts == other.attempts && nextAttemptMs == other.nextAttemptMs &&
           lastFailure.equals(other.lastFailure);
  }

  bool operator!=(const ProdigyPendingElasticAddressAssignment& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPendingElasticAddressAssignment& assignment)
{
  serializer.value1b(assignment.version);
  serializer.value8b(assignment.operationID);
  serializer.value8b(assignment.transitionGeneration);
  serializer.value16b(assignment.transactionNonce);
  serializer.value16b(assignment.machineUUID);
  serializer.text1b(assignment.machineCloudID, UINT32_MAX);
  serializer.object(assignment.expectedDeliveryPrefix);
  serializer.object(assignment.registration);
  serializer.text1b(assignment.providerPlan, UINT32_MAX);
  serializer.text1b(assignment.providerPlanBindingDigest, UINT32_MAX);
  serializer.value1b(assignment.compensating);
  serializer.value4b(assignment.attempts);
  serializer.value8b(assignment.nextAttemptMs);
  serializer.text1b(assignment.lastFailure, UINT32_MAX);
}

class RoutableSubnetUnregistration {
public:

  String name;
  bool success = false;
  bool removed = false;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, RoutableSubnetUnregistration& payload)
{
  serializer.text1b(payload.name, UINT32_MAX);
  serializer.value1b(payload.success);
  serializer.value1b(payload.removed);
  serializer.text1b(payload.failure, UINT32_MAX);
}

class RoutableSubnetRegistryReport {
public:

  Vector<DistributableExternalSubnet> subnets;
  bool success = false;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, RoutableSubnetRegistryReport& payload)
{
  serializer.object(payload.subnets);
  serializer.value1b(payload.success);
  serializer.text1b(payload.failure, UINT32_MAX);
}

class SwitchboardOverlayMachineRoute {
public:

  uint32_t machineFragment = 0;
  IPAddress nextHop = {};
  IPAddress sourceAddress = {};
  bool useGatewayMAC = false;
  String nextHopMAC;

  bool operator==(const SwitchboardOverlayMachineRoute& other) const
  {
    return machineFragment == other.machineFragment && nextHop.equals(other.nextHop) && sourceAddress.equals(other.sourceAddress) && useGatewayMAC == other.useGatewayMAC && nextHopMAC.equals(other.nextHopMAC);
  }

  bool operator!=(const SwitchboardOverlayMachineRoute& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, SwitchboardOverlayMachineRoute& route)
{
  serializer.value4b(route.machineFragment);
  serializer.object(route.nextHop);
  serializer.object(route.sourceAddress);
  serializer.value1b(route.useGatewayMAC);
  serializer.text1b(route.nextHopMAC, UINT32_MAX);
}

class SwitchboardOverlayHostedIngressRoute {
public:

  IPPrefix prefix;
  uint32_t machineFragment = 0;

  bool operator==(const SwitchboardOverlayHostedIngressRoute& other) const
  {
    return machineFragment == other.machineFragment && prefix.equals(other.prefix);
  }

  bool operator!=(const SwitchboardOverlayHostedIngressRoute& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, SwitchboardOverlayHostedIngressRoute& route)
{
  serializer.object(route.prefix);
  serializer.value4b(route.machineFragment);
}

class SwitchboardOverlayRoutingConfig {
public:

  bool containerNetworkViaOverlay = false;
  Vector<IPPrefix> overlaySubnets;
  Vector<SwitchboardOverlayMachineRoute> machineRoutes;
  Vector<SwitchboardOverlayHostedIngressRoute> hostedIngressRoutes;

  bool operator==(const SwitchboardOverlayRoutingConfig& other) const
  {
    if (containerNetworkViaOverlay != other.containerNetworkViaOverlay || overlaySubnets.size() != other.overlaySubnets.size() || machineRoutes.size() != other.machineRoutes.size() || hostedIngressRoutes.size() != other.hostedIngressRoutes.size())
    {
      return false;
    }

    for (uint32_t index = 0; index < overlaySubnets.size(); ++index)
    {
      if (overlaySubnets[index].equals(other.overlaySubnets[index]) == false)
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < machineRoutes.size(); ++index)
    {
      if (machineRoutes[index] != other.machineRoutes[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < hostedIngressRoutes.size(); ++index)
    {
      if (hostedIngressRoutes[index] != other.hostedIngressRoutes[index])
      {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const SwitchboardOverlayRoutingConfig& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, SwitchboardOverlayRoutingConfig& config)
{
  serializer.value1b(config.containerNetworkViaOverlay);
  serializer.container(config.overlaySubnets, UINT32_MAX);
  serializer.container(config.machineRoutes, UINT32_MAX);
  serializer.container(config.hostedIngressRoutes, UINT32_MAX);
}

class MachineConfig {
public:

  enum class MachineKind : uint8_t {
    bareMetal = 0,
    vm = 1
  };

  MachineKind kind = MachineKind::bareMetal;
  String slug;
  String ipxeScriptURL;
  String vmImageURI;
  String gcpInstanceTemplate;
  String gcpInstanceTemplateSpot;
  String providerMachineType;
  MachineSchemaCpuCapability cpu;

  // These are total machine resources for this machine type. The distributable
  // pool can be smaller after ownership limits and Prodigy/OS reserves.
  uint32_t nLogicalCores;
  uint32_t nMemoryMB;
  uint32_t nStorageMB;
  bool providesHostPublic4 = false;
  bool providesHostPublic6 = false;
};

template <typename S>
static void serialize(S&& serializer, MachineConfig& config)
{
  serializer.value1b(config.kind);
  serializer.text1b(config.slug, UINT32_MAX);
  serializer.text1b(config.ipxeScriptURL, UINT32_MAX);
  serializer.text1b(config.vmImageURI, UINT32_MAX);
  serializer.text1b(config.gcpInstanceTemplate, UINT32_MAX);
  serializer.text1b(config.gcpInstanceTemplateSpot, UINT32_MAX);
  serializer.text1b(config.providerMachineType, UINT32_MAX);
  serializer.object(config.cpu);
  serializer.value4b(config.nLogicalCores);
  serializer.value4b(config.nMemoryMB);
  serializer.value4b(config.nStorageMB);
  serializer.value1b(config.providesHostPublic4);
  serializer.value1b(config.providesHostPublic6);
}

static inline bool machineConfigProvidesHostPublicFamily(const MachineConfig& config, ExternalAddressFamily family)
{
  return (family == ExternalAddressFamily::ipv4) ? config.providesHostPublic4 : config.providesHostPublic6;
}

enum class ClusterMachineSource : uint8_t {

  adopted = 0,
  created = 1
};

enum class ClusterMachineBacking : uint8_t {

  owned = 0,
  cloud = 1
};

static inline const char *clusterMachineBackingName(ClusterMachineBacking backing)
{
  switch (backing)
  {
    case ClusterMachineBacking::owned:
      {
        return "owned";
      }
    case ClusterMachineBacking::cloud:
      {
        return "cloud";
      }
  }

  return "unknown";
}

enum class ClusterMachineOwnershipMode : uint8_t {

  wholeMachine = 0,
  hardCaps = 1,
  percentages = 2
};

class ClusterMachineOwnership {
public:

  ClusterMachineOwnershipMode mode = ClusterMachineOwnershipMode::wholeMachine;

  uint32_t nLogicalCoresCap = 0;
  uint32_t nMemoryMBCap = 0;
  uint32_t nStorageMBCap = 0;

  uint16_t nLogicalCoresBasisPoints = 0;
  uint16_t nMemoryBasisPoints = 0;
  uint16_t nStorageBasisPoints = 0;

  bool operator==(const ClusterMachineOwnership& other) const
  {
    return mode == other.mode && nLogicalCoresCap == other.nLogicalCoresCap && nMemoryMBCap == other.nMemoryMBCap && nStorageMBCap == other.nStorageMBCap && nLogicalCoresBasisPoints == other.nLogicalCoresBasisPoints && nMemoryBasisPoints == other.nMemoryBasisPoints && nStorageBasisPoints == other.nStorageBasisPoints;
  }

  bool operator!=(const ClusterMachineOwnership& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterMachineOwnership& ownership)
{
  serializer.value1b(ownership.mode);
  serializer.value4b(ownership.nLogicalCoresCap);
  serializer.value4b(ownership.nMemoryMBCap);
  serializer.value4b(ownership.nStorageMBCap);
  serializer.value2b(ownership.nLogicalCoresBasisPoints);
  serializer.value2b(ownership.nMemoryBasisPoints);
  serializer.value2b(ownership.nStorageBasisPoints);
}

class ClusterMachineCloud {
public:

  String schema;
  String providerMachineType;
  String cloudID;

  bool operator==(const ClusterMachineCloud& other) const
  {
    return schema.equals(other.schema) && providerMachineType.equals(other.providerMachineType) && cloudID.equals(other.cloudID);
  }

  bool operator!=(const ClusterMachineCloud& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterMachineCloud& cloud)
{
  serializer.text1b(cloud.schema, UINT32_MAX);
  serializer.text1b(cloud.providerMachineType, UINT32_MAX);
  serializer.text1b(cloud.cloudID, UINT32_MAX);
}

class ClusterMachinePeerAddress {
public:

  String address;
  uint8_t cidr = 0;
  String gateway;

  bool operator==(const ClusterMachinePeerAddress& other) const
  {
    return address.equals(other.address) && cidr == other.cidr && gateway.equals(other.gateway);
  }

  bool operator!=(const ClusterMachinePeerAddress& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterMachinePeerAddress& peerAddress)
{
  serializer.text1b(peerAddress.address, UINT32_MAX);
  serializer.value1b(peerAddress.cidr);
  serializer.text1b(peerAddress.gateway, UINT32_MAX);
}

class ClusterMachineSSH {
public:

  String address;
  uint16_t port = 22;
  String user;
  String privateKeyPath;
  String hostPublicKeyOpenSSH;

  bool operator==(const ClusterMachineSSH& other) const
  {
    return address.equals(other.address) && port == other.port && user.equals(other.user) && privateKeyPath.equals(other.privateKeyPath) && hostPublicKeyOpenSSH.equals(other.hostPublicKeyOpenSSH);
  }

  bool operator!=(const ClusterMachineSSH& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterMachineSSH& ssh)
{
  serializer.text1b(ssh.address, UINT32_MAX);
  serializer.value2b(ssh.port);
  serializer.text1b(ssh.user, UINT32_MAX);
  serializer.text1b(ssh.privateKeyPath, UINT32_MAX);
  serializer.text1b(ssh.hostPublicKeyOpenSSH, UINT32_MAX);
}

class ClusterMachineAddress {
public:

  String address;
  uint8_t cidr = 0;
  String gateway;

  bool operator==(const ClusterMachineAddress& other) const
  {
    return address.equals(other.address) && cidr == other.cidr && gateway.equals(other.gateway);
  }

  bool operator!=(const ClusterMachineAddress& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterMachineAddress& address)
{
  serializer.text1b(address.address, UINT32_MAX);
  serializer.value1b(address.cidr);
  serializer.text1b(address.gateway, UINT32_MAX);
}

class ClusterMachineAddresses {
public:

  Vector<ClusterMachineAddress> privateAddresses;
  Vector<ClusterMachineAddress> publicAddresses;

  bool operator==(const ClusterMachineAddresses& other) const
  {
    if (privateAddresses.size() != other.privateAddresses.size() || publicAddresses.size() != other.publicAddresses.size())
    {
      return false;
    }

    for (uint32_t index = 0; index < privateAddresses.size(); ++index)
    {
      if (privateAddresses[index] != other.privateAddresses[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < publicAddresses.size(); ++index)
    {
      if (publicAddresses[index] != other.publicAddresses[index])
      {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const ClusterMachineAddresses& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterMachineAddresses& addresses)
{
  serializer.container(addresses.privateAddresses, UINT32_MAX, [](S& serializer, ClusterMachineAddress& value) {
    serializer.object(value);
  });
  serializer.container(addresses.publicAddresses, UINT32_MAX, [](S& serializer, ClusterMachineAddress& value) {
    serializer.object(value);
  });
}

class ClusterMachine {
public:

  ClusterMachineSource source = ClusterMachineSource::adopted;
  ClusterMachineBacking backing = ClusterMachineBacking::owned;
  MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
  MachineLifetime lifetime = MachineLifetime::reserved;
  bool isBrain = false;

  bool hasCloud = false;
  ClusterMachineCloud cloud;
  ClusterMachineSSH ssh;
  ClusterMachineAddresses addresses;
  Vector<ClusterMachinePeerAddress> peerAddresses;

  uint128_t uuid = 0;
  uint32_t rackUUID = 0;
  int64_t creationTimeMs = 0;
  bool hasInternetAccess = false;

  uint32_t totalLogicalCores = 0;
  uint32_t totalMemoryMB = 0;
  uint32_t totalStorageMB = 0;
  MachineHardwareProfile hardware;
  String vmImageURI;

  ClusterMachineOwnership ownership;
  uint32_t ownedLogicalCores = 0;
  uint32_t ownedMemoryMB = 0;
  uint32_t ownedStorageMB = 0;

  static bool parseIPAddressLiteral(const String& text, IPAddress& address)
  {
    String ownedText = {};
    ownedText.assign(text);

    struct in_addr parsedIPv4 = {};
    if (inet_pton(AF_INET, ownedText.c_str(), &parsedIPv4) == 1)
    {
      address = {};
      address.v4 = parsedIPv4.s_addr;
      address.is6 = false;
      return true;
    }

    struct in6_addr address6 = {};
    if (inet_pton(AF_INET6, ownedText.c_str(), &address6) == 1)
    {
      address = {};
      memcpy(address.v6, &address6, sizeof(address6));
      address.is6 = true;
      return true;
    }

    return false;
  }

  static uint32_t hashIdentityBytes(const uint8_t *bytes, uint64_t size)
  {
    uint32_t hash = 0;

    for (uint64_t index = 0; index < size; ++index)
    {
      hash = (hash * 131u) + bytes[index];
    }

    if (hash == 0)
    {
      hash = 1;
    }

    return hash;
  }

  static bool renderIPAddressLiteral(const IPAddress& address, String& text)
  {
    char buffer[INET6_ADDRSTRLEN] = {};

    if (address.is6)
    {
      if (inet_ntop(AF_INET6, address.v6, buffer, sizeof(buffer)) == nullptr)
      {
        return false;
      }
    }
    else
    {
      if (inet_ntop(AF_INET, &address.v4, buffer, sizeof(buffer)) == nullptr)
      {
        return false;
      }
    }

    text.assign(buffer);
    return true;
  }

  bool resolvePrivate4(uint32_t& resolvedPrivate4) const
  {
    for (const ClusterMachineAddress& candidate : addresses.privateAddresses)
    {
      if (candidate.address.size() == 0)
      {
        continue;
      }

      struct in_addr parsedIPv4 = {};
      String privateAddressText = {};
      privateAddressText.assign(candidate.address);
      if (inet_pton(AF_INET, privateAddressText.c_str(), &parsedIPv4) == 1)
      {
        resolvedPrivate4 = parsedIPv4.s_addr;
        return true;
      }
    }

    return false;
  }

  bool resolvePrivate4Gateway(uint32_t& resolvedGatewayPrivate4) const
  {
    for (const ClusterMachineAddress& candidate : addresses.privateAddresses)
    {
      if (candidate.address.size() == 0 || candidate.gateway.size() == 0)
      {
        continue;
      }

      struct in_addr parsedIPv4 = {};
      struct in_addr parsedGatewayIPv4 = {};
      String privateAddressText = {};
      String gatewayText = {};
      privateAddressText.assign(candidate.address);
      gatewayText.assign(candidate.gateway);
      if (inet_pton(AF_INET, privateAddressText.c_str(), &parsedIPv4) == 1 && inet_pton(AF_INET, gatewayText.c_str(), &parsedGatewayIPv4) == 1)
      {
        resolvedGatewayPrivate4 = parsedGatewayIPv4.s_addr;
        return true;
      }
    }

    return false;
  }

  bool resolvePeerAddressCandidate(const ClusterMachinePeerAddress& candidate, IPAddress& resolvedAddress, String *resolvedAddressText = nullptr) const
  {
    resolvedAddress = {};

    if (candidate.address.size() == 0 || parseIPAddressLiteral(candidate.address, resolvedAddress) == false)
    {
      return false;
    }

    if (resolvedAddressText)
    {
      resolvedAddressText->assign(candidate.address);
    }

    return true;
  }

  bool peerAddressMatches(const IPAddress& address, const String *addressText = nullptr) const
  {
    if (address.isNull())
    {
      return false;
    }

    auto matchesLiteral = [&](const String& literal) -> bool {
      if (literal.size() == 0)
      {
        return false;
      }

      if (addressText && literal.equals(*addressText))
      {
        return true;
      }

      IPAddress parsed = {};
      return parseIPAddressLiteral(literal, parsed) && parsed.equals(address);
    };

    for (const ClusterMachinePeerAddress& candidate : peerAddresses)
    {
      if (matchesLiteral(candidate.address))
      {
        return true;
      }
    }

    for (const ClusterMachineAddress& candidate : addresses.privateAddresses)
    {
      if (matchesLiteral(candidate.address))
      {
        return true;
      }
    }

    for (const ClusterMachineAddress& candidate : addresses.publicAddresses)
    {
      if (matchesLiteral(candidate.address))
      {
        return true;
      }
    }

    if (matchesLiteral(ssh.address))
    {
      return true;
    }

    if (address.is6 == false)
    {
      uint32_t resolvedPrivate4 = 0;
      if (resolvePrivate4(resolvedPrivate4) && resolvedPrivate4 == address.v4)
      {
        return true;
      }
    }

    return false;
  }

  bool resolvePeerAddress(IPAddress& resolvedAddress, String *resolvedAddressText = nullptr) const
  {
    auto tryTextAddress = [&](const String& text) -> bool {
      if (text.size() == 0)
      {
        return false;
      }

      if (parseIPAddressLiteral(text, resolvedAddress) == false)
      {
        return false;
      }

      if (resolvedAddressText)
      {
        resolvedAddressText->assign(text);
      }

      return true;
    };

    for (const ClusterMachinePeerAddress& candidate : peerAddresses)
    {
      if (tryTextAddress(candidate.address))
      {
        return true;
      }
    }

    for (const ClusterMachineAddress& candidate : addresses.privateAddresses)
    {
      if (tryTextAddress(candidate.address))
      {
        return true;
      }
    }

    // `ssh.address` can carry an external route used by Mothership. For
    // brain-to-brain traffic, only fall back to it after private connectivity.
    if (tryTextAddress(ssh.address))
    {
      return true;
    }

    for (const ClusterMachineAddress& candidate : addresses.publicAddresses)
    {
      if (tryTextAddress(candidate.address))
      {
        return true;
      }
    }

    return false;
  }

  bool sameIdentityAs(const ClusterMachine& other) const
  {
    if (uuid != 0 && other.uuid != 0 && uuid == other.uuid)
    {
      return true;
    }

    IPAddress resolvedAddress = {};
    bool havePeerAddress = resolvePeerAddress(resolvedAddress);
    if (havePeerAddress && other.peerAddressMatches(resolvedAddress))
    {
      return true;
    }

    IPAddress otherResolvedAddress = {};
    bool otherHasPeerAddress = other.resolvePeerAddress(otherResolvedAddress);
    if (otherHasPeerAddress && peerAddressMatches(otherResolvedAddress))
    {
      return true;
    }

    if (cloudPresent() && other.cloudPresent() && cloud.cloudID.size() > 0 && other.cloud.cloudID.size() > 0 && cloud.cloudID.equals(other.cloud.cloudID))
    {
      return true;
    }

    if (ssh.address.size() > 0 && other.ssh.address.size() > 0 && ssh.address.equals(other.ssh.address))
    {
      return true;
    }

    uint32_t resolvedPrivate4 = 0;
    uint32_t otherResolvedPrivate4 = 0;
    if ((havePeerAddress == false || otherHasPeerAddress == false) && resolvePrivate4(resolvedPrivate4) && other.resolvePrivate4(otherResolvedPrivate4) && resolvedPrivate4 == otherResolvedPrivate4)
    {
      return true;
    }

    return false;
  }

  bool operator==(const ClusterMachine& other) const
  {
    if (cloudPresent() != other.cloudPresent())
    {
      return false;
    }

    if (peerAddresses.size() != other.peerAddresses.size())
    {
      return false;
    }

    for (uint32_t index = 0; index < peerAddresses.size(); ++index)
    {
      if (peerAddresses[index] != other.peerAddresses[index])
      {
        return false;
      }
    }

    return source == other.source && backing == other.backing && kind == other.kind && lifetime == other.lifetime && isBrain == other.isBrain && (cloudPresent() == false || cloud == other.cloud) && ssh == other.ssh && addresses == other.addresses && uuid == other.uuid && rackUUID == other.rackUUID && creationTimeMs == other.creationTimeMs && hasInternetAccess == other.hasInternetAccess && totalLogicalCores == other.totalLogicalCores && totalMemoryMB == other.totalMemoryMB && totalStorageMB == other.totalStorageMB && hardware == other.hardware && vmImageURI.equals(other.vmImageURI) && ownership == other.ownership && ownedLogicalCores == other.ownedLogicalCores && ownedMemoryMB == other.ownedMemoryMB && ownedStorageMB == other.ownedStorageMB;
  }

  bool operator!=(const ClusterMachine& other) const
  {
    return (*this == other) == false;
  }

  void renderIdentityLabel(String& label) const
  {
    label.clear();

    if (cloudPresent() && cloud.cloudID.size() > 0)
    {
      label.assign(cloud.cloudID);
      return;
    }

    for (const ClusterMachineAddress& candidate : addresses.privateAddresses)
    {
      if (candidate.address.size() > 0)
      {
        label.assign(candidate.address);
        return;
      }
    }

    if (ssh.address.size() > 0)
    {
      label.assign(ssh.address);
      return;
    }

    for (const ClusterMachineAddress& candidate : addresses.publicAddresses)
    {
      if (candidate.address.size() > 0)
      {
        label.assign(candidate.address);
        return;
      }
    }

    if (creationTimeMs > 0)
    {
      label.snprintf<"machine-{itoa}"_ctv>(creationTimeMs);
      return;
    }

    label.assign("unknown-machine"_ctv);
  }

  bool cloudPresent(void) const
  {
    return hasCloud || cloud.schema.size() > 0 || cloud.providerMachineType.size() > 0 || cloud.cloudID.size() > 0;
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterMachine& machine)
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
  serializer.container(machine.peerAddresses, UINT32_MAX, [](S& serializer, ClusterMachinePeerAddress& value) {
    serializer.object(value);
  });
  serializer.value16b(machine.uuid);
  serializer.value4b(machine.rackUUID);
  serializer.value8b(machine.creationTimeMs);
  serializer.value1b(machine.hasInternetAccess);
  serializer.value4b(machine.totalLogicalCores);
  serializer.value4b(machine.totalMemoryMB);
  serializer.value4b(machine.totalStorageMB);
  serializer.object(machine.hardware);
  serializer.text1b(machine.vmImageURI, UINT32_MAX);
  serializer.object(machine.ownership);
  serializer.value4b(machine.ownedLogicalCores);
  serializer.value4b(machine.ownedMemoryMB);
  serializer.value4b(machine.ownedStorageMB);
}

class ClusterTopology {
public:

  uint64_t version = 0;
  Vector<ClusterMachine> machines;

  bool operator==(const ClusterTopology& other) const
  {
    if (version != other.version || machines.size() != other.machines.size())
    {
      return false;
    }

    for (uint32_t index = 0; index < machines.size(); ++index)
    {
      if (machines[index] != other.machines[index])
      {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const ClusterTopology& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterTopology& topology)
{
  serializer.value8b(topology.version);
  serializer.object(topology.machines);
}

static inline bool prodigyNormalizeClusterMachinePeerAddress(const ClusterMachinePeerAddress& input, ClusterMachinePeerAddress& normalized)
{
  normalized = {};

  IPAddress address = {};
  if (input.address.size() == 0 || ClusterMachine::parseIPAddressLiteral(input.address, address) == false)
  {
    return false;
  }

  if (ClusterMachine::renderIPAddressLiteral(address, normalized.address) == false)
  {
    return false;
  }

  uint8_t maxCidr = address.is6 ? uint8_t(128) : uint8_t(32);
  normalized.cidr = input.cidr > maxCidr ? maxCidr : input.cidr;

  if (input.gateway.size() > 0)
  {
    IPAddress gateway = {};
    if (ClusterMachine::parseIPAddressLiteral(input.gateway, gateway) == false || gateway.is6 != address.is6 || ClusterMachine::renderIPAddressLiteral(gateway, normalized.gateway) == false)
    {
      return false;
    }
  }

  return true;
}

static inline bool prodigyClusterMachinePeerAddressIsPrivate(const ClusterMachinePeerAddress& candidate)
{
  ClusterMachinePeerAddress normalized = {};
  if (prodigyNormalizeClusterMachinePeerAddress(candidate, normalized) == false)
  {
    return false;
  }

  IPAddress address = {};
  if (ClusterMachine::parseIPAddressLiteral(normalized.address, address) == false)
  {
    return false;
  }

  if (address.is6)
  {
    return (address.v6[0] & 0xfe) == 0xfc;
  }

  uint32_t hostOrder = ntohl(address.v4);
  return (hostOrder & 0xff000000u) == 0x0a000000u || (hostOrder & 0xfff00000u) == 0xac100000u || (hostOrder & 0xffff0000u) == 0xc0a80000u;
}

static inline bool prodigyClusterMachinePeerAddressSubnetKey(const ClusterMachinePeerAddress& candidate, String& subnetKey, bool privateOnly = false)
{
  subnetKey.clear();

  ClusterMachinePeerAddress normalized = {};
  if (prodigyNormalizeClusterMachinePeerAddress(candidate, normalized) == false || normalized.cidr == 0)
  {
    return false;
  }

  if (privateOnly && prodigyClusterMachinePeerAddressIsPrivate(normalized) == false)
  {
    return false;
  }

  IPAddress address = {};
  if (ClusterMachine::parseIPAddressLiteral(normalized.address, address) == false)
  {
    return false;
  }

  if (address.is6)
  {
    uint8_t masked[16] = {};
    memcpy(masked, address.v6, sizeof(masked));
    uint8_t bitsRemaining = normalized.cidr;
    for (uint32_t index = 0; index < 16; ++index)
    {
      if (bitsRemaining >= 8)
      {
        bitsRemaining -= 8;
        continue;
      }

      if (bitsRemaining == 0)
      {
        masked[index] = 0;
      }
      else
      {
        masked[index] &= uint8_t(0xffu << (8 - bitsRemaining));
        bitsRemaining = 0;
      }
    }

    IPAddress maskedAddress = {};
    memcpy(maskedAddress.v6, masked, sizeof(masked));
    maskedAddress.is6 = true;
    if (ClusterMachine::renderIPAddressLiteral(maskedAddress, subnetKey) == false)
    {
      subnetKey.clear();
      return false;
    }
  }
  else
  {
    uint32_t hostOrder = ntohl(address.v4);
    uint32_t mask = (normalized.cidr == 32) ? 0xffffffffu : (0xffffffffu << (32 - normalized.cidr));
    uint32_t maskedHostOrder = hostOrder & mask;

    IPAddress maskedAddress = {};
    maskedAddress.v4 = htonl(maskedHostOrder);
    maskedAddress.is6 = false;
    if (ClusterMachine::renderIPAddressLiteral(maskedAddress, subnetKey) == false)
    {
      subnetKey.clear();
      return false;
    }
  }

  subnetKey.append('/');
  String prefixText = {};
  prefixText.snprintf<"{itoa}"_ctv>(unsigned(normalized.cidr));
  subnetKey.append(prefixText);
  return true;
}

static inline void prodigyAppendUniqueClusterMachinePeerAddress(Vector<ClusterMachinePeerAddress>& candidates, const ClusterMachinePeerAddress& candidate)
{
  ClusterMachinePeerAddress normalized = {};
  if (prodigyNormalizeClusterMachinePeerAddress(candidate, normalized) == false)
  {
    return;
  }

  for (ClusterMachinePeerAddress& existing : candidates)
  {
    if (existing.address.equals(normalized.address))
    {
      if (existing.cidr == 0 || (normalized.cidr > 0 && normalized.cidr < existing.cidr))
      {
        existing.cidr = normalized.cidr;
      }

      if (existing.gateway.size() == 0 && normalized.gateway.size() > 0)
      {
        existing.gateway = normalized.gateway;
      }
      return;
    }
  }

  candidates.push_back(normalized);
}

static inline bool prodigyClusterMachinePeerAddressesEqual(const Vector<ClusterMachinePeerAddress>& lhs, const Vector<ClusterMachinePeerAddress>& rhs)
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

static inline bool prodigyNormalizeClusterMachineAddressLiteral(const String& input, String& normalized)
{
  normalized.clear();

  IPAddress address = {};
  if (input.size() == 0 || ClusterMachine::parseIPAddressLiteral(input, address) == false)
  {
    return false;
  }

  return ClusterMachine::renderIPAddressLiteral(address, normalized);
}

static inline bool prodigyNormalizeClusterMachineAddress(const ClusterMachineAddress& input, ClusterMachineAddress& normalized)
{
  normalized = {};

  IPAddress address = {};
  if (input.address.size() == 0 || ClusterMachine::parseIPAddressLiteral(input.address, address) == false)
  {
    return false;
  }

  if (ClusterMachine::renderIPAddressLiteral(address, normalized.address) == false)
  {
    return false;
  }

  uint8_t maxCidr = address.is6 ? uint8_t(128) : uint8_t(32);
  normalized.cidr = input.cidr > maxCidr ? maxCidr : input.cidr;

  if (input.gateway.size() > 0)
  {
    IPAddress gateway = {};
    if (ClusterMachine::parseIPAddressLiteral(input.gateway, gateway) == false || gateway.is6 != address.is6 || ClusterMachine::renderIPAddressLiteral(gateway, normalized.gateway) == false)
    {
      return false;
    }
  }

  return true;
}

static inline void prodigyAppendUniqueClusterMachineAddress(Vector<ClusterMachineAddress>& addresses, const ClusterMachineAddress& candidate)
{
  ClusterMachineAddress normalized = {};
  if (prodigyNormalizeClusterMachineAddress(candidate, normalized) == false)
  {
    return;
  }

  for (ClusterMachineAddress& existing : addresses)
  {
    if (existing.address.equals(normalized.address))
    {
      if (existing.cidr == 0 || (normalized.cidr > 0 && normalized.cidr < existing.cidr))
      {
        existing.cidr = normalized.cidr;
      }

      if (existing.gateway.size() == 0 && normalized.gateway.size() > 0)
      {
        existing.gateway = normalized.gateway;
      }
      return;
    }
  }

  addresses.push_back(normalized);
}

static inline void prodigyAppendUniqueClusterMachineAddress(Vector<ClusterMachineAddress>& addresses, const String& candidate, uint8_t cidr = 0, const String& gateway = {})
{
  ClusterMachineAddress address = {};
  address.address = candidate;
  address.cidr = cidr;
  address.gateway = gateway;
  prodigyAppendUniqueClusterMachineAddress(addresses, address);
}

static inline const ClusterMachineAddress *prodigyFirstClusterMachineAddress(const Vector<ClusterMachineAddress>& addresses)
{
  for (const ClusterMachineAddress& candidate : addresses)
  {
    if (candidate.address.size() > 0)
    {
      return &candidate;
    }
  }

  return nullptr;
}

static inline bool prodigyResolveFirstClusterMachineAddressLiteral(const Vector<ClusterMachineAddress>& addresses, String& literal)
{
  literal.clear();

  const ClusterMachineAddress *candidate = prodigyFirstClusterMachineAddress(addresses);
  if (candidate == nullptr)
  {
    return false;
  }

  literal.assign(candidate->address);
  return true;
}

static inline void prodigyAssignClusterMachineAddressesFromPeerCandidates(ClusterMachineAddresses& addresses, const Vector<ClusterMachinePeerAddress>& candidates)
{
  addresses.privateAddresses.clear();
  addresses.publicAddresses.clear();

  for (const ClusterMachinePeerAddress& candidate : candidates)
  {
    ClusterMachinePeerAddress normalized = {};
    if (prodigyNormalizeClusterMachinePeerAddress(candidate, normalized) == false)
    {
      continue;
    }

    if (prodigyClusterMachinePeerAddressIsPrivate(normalized))
    {
      prodigyAppendUniqueClusterMachineAddress(addresses.privateAddresses, normalized.address, normalized.cidr, normalized.gateway);
    }
    else
    {
      prodigyAppendUniqueClusterMachineAddress(addresses.publicAddresses, normalized.address, normalized.cidr, normalized.gateway);
    }
  }
}

static inline void prodigyCollectClusterMachinePeerAddresses(const ClusterMachine& machine, Vector<ClusterMachinePeerAddress>& candidates)
{
  candidates.clear();

  if (machine.peerAddresses.empty() == false)
  {
    for (const ClusterMachinePeerAddress& candidate : machine.peerAddresses)
    {
      prodigyAppendUniqueClusterMachinePeerAddress(candidates, candidate);
    }
    return;
  }

  for (const ClusterMachineAddress& address : machine.addresses.privateAddresses)
  {
    prodigyAppendUniqueClusterMachinePeerAddress(candidates, ClusterMachinePeerAddress {address.address, address.cidr, address.gateway});
  }

  for (const ClusterMachineAddress& address : machine.addresses.publicAddresses)
  {
    prodigyAppendUniqueClusterMachinePeerAddress(candidates, ClusterMachinePeerAddress {address.address, address.cidr, address.gateway});
  }

  if (machine.ssh.address.size() > 0)
  {
    prodigyAppendUniqueClusterMachinePeerAddress(candidates, ClusterMachinePeerAddress {machine.ssh.address, 0});
  }
}

static inline void prodigyNormalizeClusterTopologyPeerAddresses(ClusterTopology& topology)
{
  bytell_hash_map<String, uint32_t> privateSubnetCounts;
  bytell_hash_map<String, uint32_t> subnetCounts;
  Vector<Vector<ClusterMachinePeerAddress>> normalizedCandidates;
  Vector<uint8_t> machineHasExplicitPeerAddresses;
  normalizedCandidates.resize(topology.machines.size());
  machineHasExplicitPeerAddresses.resize(topology.machines.size());

  for (uint32_t machineIndex = 0; machineIndex < topology.machines.size(); ++machineIndex)
  {
    const ClusterMachine& machine = topology.machines[machineIndex];
    machineHasExplicitPeerAddresses[machineIndex] = machine.peerAddresses.empty() ? uint8_t(0) : uint8_t(1);
    prodigyCollectClusterMachinePeerAddresses(machine, normalizedCandidates[machineIndex]);

    Vector<String> seenPrivateSubnets;
    Vector<String> seenSubnets;
    for (const ClusterMachinePeerAddress& candidate : normalizedCandidates[machineIndex])
    {
      String privateSubnetKey = {};
      if (prodigyClusterMachinePeerAddressSubnetKey(candidate, privateSubnetKey, true))
      {
        bool duplicate = false;
        for (const String& existing : seenPrivateSubnets)
        {
          if (existing == privateSubnetKey)
          {
            duplicate = true;
            break;
          }
        }

        if (duplicate == false)
        {
          seenPrivateSubnets.push_back(privateSubnetKey);
          privateSubnetCounts[privateSubnetKey] += 1;
        }
      }

      String subnetKey = {};
      if (prodigyClusterMachinePeerAddressSubnetKey(candidate, subnetKey, false))
      {
        bool duplicate = false;
        for (const String& existing : seenSubnets)
        {
          if (existing == subnetKey)
          {
            duplicate = true;
            break;
          }
        }

        if (duplicate == false)
        {
          seenSubnets.push_back(subnetKey);
          subnetCounts[subnetKey] += 1;
        }
      }
    }
  }

  auto compareAddressLiterals = [](const String& lhs, const String& rhs) -> bool {
    return std::lexicographical_compare(lhs.data(), lhs.data() + lhs.size(), rhs.data(), rhs.data() + rhs.size());
  };

  for (uint32_t machineIndex = 0; machineIndex < topology.machines.size(); ++machineIndex)
  {
    Vector<ClusterMachinePeerAddress>& candidates = normalizedCandidates[machineIndex];

    std::sort(candidates.begin(), candidates.end(), [&](const ClusterMachinePeerAddress& lhs, const ClusterMachinePeerAddress& rhs) {
      String lhsPrivateSubnet = {};
      String rhsPrivateSubnet = {};
      uint32_t lhsPrivateSubnetCount = prodigyClusterMachinePeerAddressSubnetKey(lhs, lhsPrivateSubnet, true) ? privateSubnetCounts[lhsPrivateSubnet] : 0;
      uint32_t rhsPrivateSubnetCount = prodigyClusterMachinePeerAddressSubnetKey(rhs, rhsPrivateSubnet, true) ? privateSubnetCounts[rhsPrivateSubnet] : 0;
      if (lhsPrivateSubnetCount != rhsPrivateSubnetCount)
      {
        return lhsPrivateSubnetCount > rhsPrivateSubnetCount;
      }

      bool lhsIsPrivate = prodigyClusterMachinePeerAddressIsPrivate(lhs);
      bool rhsIsPrivate = prodigyClusterMachinePeerAddressIsPrivate(rhs);
      if (lhsIsPrivate != rhsIsPrivate)
      {
        return lhsIsPrivate;
      }

      String lhsSubnet = {};
      String rhsSubnet = {};
      uint32_t lhsSubnetCount = prodigyClusterMachinePeerAddressSubnetKey(lhs, lhsSubnet, false) ? subnetCounts[lhsSubnet] : 0;
      uint32_t rhsSubnetCount = prodigyClusterMachinePeerAddressSubnetKey(rhs, rhsSubnet, false) ? subnetCounts[rhsSubnet] : 0;
      if (lhsSubnetCount != rhsSubnetCount)
      {
        return lhsSubnetCount > rhsSubnetCount;
      }

      bool lhsHasPrefix = lhs.cidr > 0;
      bool rhsHasPrefix = rhs.cidr > 0;
      if (lhsHasPrefix != rhsHasPrefix)
      {
        return lhsHasPrefix;
      }

      if (lhs.address.equals(rhs.address) == false)
      {
        return compareAddressLiterals(lhs.address, rhs.address);
      }

      if (lhs.cidr != rhs.cidr)
      {
        return lhs.cidr < rhs.cidr;
      }

      return false;
    });

    if (machineHasExplicitPeerAddresses[machineIndex])
    {
      topology.machines[machineIndex].peerAddresses.clear();
      for (const ClusterMachinePeerAddress& candidate : candidates)
      {
        prodigyAppendUniqueClusterMachinePeerAddress(topology.machines[machineIndex].peerAddresses, candidate);
      }

      ClusterMachineAddresses normalizedAddresses = {};
      for (const ClusterMachineAddress& address : topology.machines[machineIndex].addresses.privateAddresses)
      {
        prodigyAppendUniqueClusterMachineAddress(normalizedAddresses.privateAddresses, address);
      }
      for (const ClusterMachineAddress& address : topology.machines[machineIndex].addresses.publicAddresses)
      {
        prodigyAppendUniqueClusterMachineAddress(normalizedAddresses.publicAddresses, address);
      }
      topology.machines[machineIndex].addresses = std::move(normalizedAddresses);
    }
    else
    {
      prodigyAssignClusterMachineAddressesFromPeerCandidates(topology.machines[machineIndex].addresses, candidates);
    }
  }
}

static inline uint32_t clusterTopologyBrainCount(const ClusterTopology& topology)
{
  uint32_t nBrains = 0;

  for (const ClusterMachine& machine : topology.machines)
  {
    if (machine.isBrain)
    {
      nBrains += 1;
    }
  }

  return nBrains;
}

static inline bool clusterTopologyBrainCountSatisfiesQuorum(uint32_t nBrains)
{
  return (nBrains >= 3) && ((nBrains % 2) == 1);
}

class ProdigyMachineReservedResources {
public:

  uint32_t logicalCores = 2;
  uint32_t memoryMB = 4096;
  uint32_t storageMB = 4096;

  bool operator==(const ProdigyMachineReservedResources& other) const
  {
    return logicalCores == other.logicalCores && memoryMB == other.memoryMB && storageMB == other.storageMB;
  }
};

constexpr static ProdigyMachineReservedResources prodigyMachineReservedResources = {};
constexpr static ProdigyMachineReservedResources prodigySmokeMachineReservedResources = {0, 0, 0};

static inline const char *prodigyMachineReservedResourcesProfileName(const ProdigyMachineReservedResources& resources)
{
  if (resources == prodigyMachineReservedResources)
  {
    return "production";
  }
  if (resources == prodigySmokeMachineReservedResources)
  {
    return "smoke";
  }
  return "custom";
}

template <typename S>
static void serialize(S&& serializer, ProdigyMachineReservedResources& resources)
{
  serializer.value4b(resources.logicalCores);
  serializer.value4b(resources.memoryMB);
  serializer.value4b(resources.storageMB);
}

class ProdigyContainerRuntimeLimits {
public:

  uint32_t maxPids = 4096;
  uint32_t maxIsolatedChildMemoryMB = 1024;
  uint32_t maxIsolatedChildCgroups = 64;
  uint64_t maxCompressedBlobBytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
  uint64_t maxArtifactBytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
  uint64_t maxLaunchMetadataBytes = 64ULL * 1024ULL;
  uint64_t maxPendingCreateMarkerBytes = 256ULL;
  uint32_t maxLaunchMetadataArrayEntries = 256;
  uint32_t maxLaunchMetadataEntryBytes = 4096;
  uint32_t maxLaunchMetadataPathBytes = 4096;
  uint32_t maxLaunchMetadataArchitectureBytes = 64;
  uint32_t maxArtifactEntries = 65'536;
};

constexpr static ProdigyContainerRuntimeLimits prodigyContainerRuntimeLimits = {};

static inline uint32_t clusterMachineResolveDistributableResourcePool(uint32_t total, uint32_t reserve)
{
  return (total > reserve) ? (total - reserve) : 0;
}

static inline uint32_t clusterMachineResolvePercentageShare(uint32_t total, uint16_t basisPoints)
{
  if (total == 0)
  {
    return 0;
  }

  uint64_t scaled = (uint64_t(total) * uint64_t(basisPoints)) / 10'000ULL;
  if (scaled == 0)
  {
    scaled = 1;
  }

  return uint32_t(scaled);
}

static inline bool clusterMachineResolveOwnedResources(const ClusterMachineOwnership& ownership, uint32_t totalLogicalCores, uint32_t totalMemoryMB, uint32_t totalStorageMB, uint32_t& nLogicalCores, uint32_t& nMemoryMB, uint32_t& nStorageMB, const ProdigyMachineReservedResources& reservedResources, String *failure = nullptr)
{
  nLogicalCores = 0;
  nMemoryMB = 0;
  nStorageMB = 0;

  const uint32_t logicalCoresPool = clusterMachineResolveDistributableResourcePool(totalLogicalCores, reservedResources.logicalCores);
  const uint32_t memoryMBPool = clusterMachineResolveDistributableResourcePool(totalMemoryMB, reservedResources.memoryMB);
  const uint32_t storageMBPool = clusterMachineResolveDistributableResourcePool(totalStorageMB, reservedResources.storageMB);

  switch (ownership.mode)
  {
    case ClusterMachineOwnershipMode::wholeMachine:
      {
        nLogicalCores = logicalCoresPool;
        nMemoryMB = memoryMBPool;
        nStorageMB = storageMBPool;
        return true;
      }
    case ClusterMachineOwnershipMode::hardCaps:
      {
        if (ownership.nLogicalCoresCap == 0 || ownership.nMemoryMBCap == 0 || ownership.nStorageMBCap == 0)
        {
          if (failure)
          {
            failure->assign("hardCaps ownership requires all resource caps"_ctv);
          }
          return false;
        }

        nLogicalCores = std::min(logicalCoresPool, ownership.nLogicalCoresCap);
        nMemoryMB = std::min(memoryMBPool, ownership.nMemoryMBCap);
        nStorageMB = std::min(storageMBPool, ownership.nStorageMBCap);
        return true;
      }
    case ClusterMachineOwnershipMode::percentages:
      {
        auto validBasisPoints = [](uint16_t basisPoints) -> bool {
          return basisPoints > 0 && basisPoints <= 10'000;
        };

        if (validBasisPoints(ownership.nLogicalCoresBasisPoints) == false || validBasisPoints(ownership.nMemoryBasisPoints) == false || validBasisPoints(ownership.nStorageBasisPoints) == false)
        {
          if (failure)
          {
            failure->assign("percentages ownership requires basis points in (0, 10000]"_ctv);
          }
          return false;
        }

        nLogicalCores = std::min(logicalCoresPool, clusterMachineResolvePercentageShare(totalLogicalCores, ownership.nLogicalCoresBasisPoints));
        nMemoryMB = std::min(memoryMBPool, clusterMachineResolvePercentageShare(totalMemoryMB, ownership.nMemoryBasisPoints));
        nStorageMB = std::min(storageMBPool, clusterMachineResolvePercentageShare(totalStorageMB, ownership.nStorageBasisPoints));
        return true;
      }
  }

  if (failure)
  {
    failure->assign("unknown ownership mode"_ctv);
  }
  return false;
}

static inline bool clusterMachineResolveOwnedResources(const ClusterMachineOwnership& ownership, uint32_t totalLogicalCores, uint32_t totalMemoryMB, uint32_t totalStorageMB, uint32_t& nLogicalCores, uint32_t& nMemoryMB, uint32_t& nStorageMB, String *failure = nullptr)
{
  return clusterMachineResolveOwnedResources(ownership, totalLogicalCores, totalMemoryMB, totalStorageMB, nLogicalCores, nMemoryMB, nStorageMB, prodigyMachineReservedResources, failure);
}

static inline bool clusterMachineResolveOwnedResourcesFromConfig(const ClusterMachineOwnership& ownership, const MachineConfig& config, uint32_t& nLogicalCores, uint32_t& nMemoryMB, uint32_t& nStorageMB, const ProdigyMachineReservedResources& reservedResources, String *failure = nullptr)
{
  return clusterMachineResolveOwnedResources(ownership, config.nLogicalCores, config.nMemoryMB, config.nStorageMB, nLogicalCores, nMemoryMB, nStorageMB, reservedResources, failure);
}

static inline bool clusterMachineResolveOwnedResourcesFromConfig(const ClusterMachineOwnership& ownership, const MachineConfig& config, uint32_t& nLogicalCores, uint32_t& nMemoryMB, uint32_t& nStorageMB, String *failure = nullptr)
{
  return clusterMachineResolveOwnedResources(ownership, config.nLogicalCores, config.nMemoryMB, config.nStorageMB, nLogicalCores, nMemoryMB, nStorageMB, failure);
}

static inline bool clusterMachineApplyOwnedResourcesFromTotals(ClusterMachine& machine, uint32_t totalLogicalCores, uint32_t totalMemoryMB, uint32_t totalStorageMB, const ProdigyMachineReservedResources& reservedResources, String *failure = nullptr)
{
  machine.totalLogicalCores = totalLogicalCores;
  machine.totalMemoryMB = totalMemoryMB;
  machine.totalStorageMB = totalStorageMB;
  return clusterMachineResolveOwnedResources(machine.ownership, totalLogicalCores, totalMemoryMB, totalStorageMB, machine.ownedLogicalCores, machine.ownedMemoryMB, machine.ownedStorageMB, reservedResources, failure);
}

static inline bool clusterMachineApplyOwnedResourcesFromTotals(ClusterMachine& machine, uint32_t totalLogicalCores, uint32_t totalMemoryMB, uint32_t totalStorageMB, String *failure = nullptr)
{
  return clusterMachineApplyOwnedResourcesFromTotals(machine, totalLogicalCores, totalMemoryMB, totalStorageMB, prodigyMachineReservedResources, failure);
}

static inline bool clusterMachineApplyOwnedResourcesFromConfig(ClusterMachine& machine, const MachineConfig& config, const ProdigyMachineReservedResources& reservedResources, String *failure = nullptr)
{
  return clusterMachineApplyOwnedResourcesFromTotals(machine, config.nLogicalCores, config.nMemoryMB, config.nStorageMB, reservedResources, failure);
}

static inline bool clusterMachineApplyOwnedResourcesFromConfig(ClusterMachine& machine, const MachineConfig& config, String *failure = nullptr)
{
  return clusterMachineApplyOwnedResourcesFromTotals(machine, config.nLogicalCores, config.nMemoryMB, config.nStorageMB, failure);
}

class CreateMachinesInstruction {
public:

  MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
  MachineLifetime lifetime = MachineLifetime::reserved;
  ClusterMachineBacking backing = ClusterMachineBacking::cloud;
  ClusterMachineCloud cloud;
  uint32_t count = 0;
  bool isBrain = false;
  String region;
  String zone;

  bool operator==(const CreateMachinesInstruction& other) const
  {
    return kind == other.kind && lifetime == other.lifetime && backing == other.backing && cloud == other.cloud && count == other.count && isBrain == other.isBrain && region.equals(other.region) && zone.equals(other.zone);
  }

  bool operator!=(const CreateMachinesInstruction& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, CreateMachinesInstruction& instruction)
{
  serializer.value1b(instruction.kind);
  serializer.value1b(instruction.lifetime);
  serializer.value1b(instruction.backing);
  serializer.object(instruction.cloud);
  serializer.value4b(instruction.count);
  serializer.value1b(instruction.isBrain);
  serializer.text1b(instruction.region, UINT32_MAX);
  serializer.text1b(instruction.zone, UINT32_MAX);
}

class ProdigyManagedMachineSchema {
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

  bool operator==(const ProdigyManagedMachineSchema& other) const
  {
    return schema.equals(other.schema) && kind == other.kind && lifetime == other.lifetime && ipxeScriptURL.equals(other.ipxeScriptURL) && vmImageURI.equals(other.vmImageURI) && gcpInstanceTemplate.equals(other.gcpInstanceTemplate) && gcpInstanceTemplateSpot.equals(other.gcpInstanceTemplateSpot) && providerMachineType.equals(other.providerMachineType) && providerReservationID.equals(other.providerReservationID) && region.equals(other.region) && zone.equals(other.zone) && cpu == other.cpu && budget == other.budget;
  }

  bool operator!=(const ProdigyManagedMachineSchema& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyManagedMachineSchema& schema)
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

class ProdigyManagedMachineSchemaPatch {
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

template <typename S>
static void serialize(S&& serializer, ProdigyManagedMachineSchemaPatch& patch)
{
  serializer.text1b(patch.schema, UINT32_MAX);
  serializer.value1b(patch.hasKind);
  serializer.value1b(patch.kind);
  serializer.value1b(patch.hasLifetime);
  serializer.value1b(patch.lifetime);
  serializer.value1b(patch.hasIpxeScriptURL);
  serializer.text1b(patch.ipxeScriptURL, UINT32_MAX);
  serializer.value1b(patch.hasVmImageURI);
  serializer.text1b(patch.vmImageURI, UINT32_MAX);
  serializer.value1b(patch.hasGcpInstanceTemplate);
  serializer.text1b(patch.gcpInstanceTemplate, UINT32_MAX);
  serializer.value1b(patch.hasGcpInstanceTemplateSpot);
  serializer.text1b(patch.gcpInstanceTemplateSpot, UINT32_MAX);
  serializer.value1b(patch.hasProviderMachineType);
  serializer.text1b(patch.providerMachineType, UINT32_MAX);
  serializer.value1b(patch.hasProviderReservationID);
  serializer.text1b(patch.providerReservationID, UINT32_MAX);
  serializer.value1b(patch.hasRegion);
  serializer.text1b(patch.region, UINT32_MAX);
  serializer.value1b(patch.hasZone);
  serializer.text1b(patch.zone, UINT32_MAX);
  serializer.value1b(patch.hasCpu);
  serializer.object(patch.cpu);
  serializer.value1b(patch.hasBudget);
  serializer.value4b(patch.budget);
}

static inline ProdigyManagedMachineSchema *prodigyFindManagedMachineSchema(Vector<ProdigyManagedMachineSchema>& machineSchemas, const String& schema)
{
  for (ProdigyManagedMachineSchema& candidate : machineSchemas)
  {
    if (candidate.schema.equals(schema))
    {
      return &candidate;
    }
  }

  return nullptr;
}

static inline const ProdigyManagedMachineSchema *prodigyFindManagedMachineSchema(const Vector<ProdigyManagedMachineSchema>& machineSchemas, const String& schema)
{
  for (const ProdigyManagedMachineSchema& candidate : machineSchemas)
  {
    if (candidate.schema.equals(schema))
    {
      return &candidate;
    }
  }

  return nullptr;
}

static inline bool prodigyUpsertManagedMachineSchema(
    Vector<ProdigyManagedMachineSchema>& machineSchemas,
    const ProdigyManagedMachineSchemaPatch& patch,
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

  ProdigyManagedMachineSchema *existing = prodigyFindManagedMachineSchema(machineSchemas, patch.schema);
  if (existing == nullptr)
  {
    machineSchemas.push_back(ProdigyManagedMachineSchema {});
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

static inline void prodigyBuildMachineConfigFromManagedMachineSchema(const ProdigyManagedMachineSchema& schema, MachineConfig& config)
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

static inline bool prodigyDeltaManagedMachineBudget(
    Vector<ProdigyManagedMachineSchema>& machineSchemas,
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

  ProdigyManagedMachineSchema *existing = prodigyFindManagedMachineSchema(machineSchemas, schema);
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

static inline bool prodigyDeleteManagedMachineSchema(
    Vector<ProdigyManagedMachineSchema>& machineSchemas,
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
    if (it->schema == schema)
    {
      machineSchemas.erase(it);
      if (removed)
      {
        *removed = true;
      }
      return true;
    }
  }

  return true;
}

class MachineProvisioningProgress {
public:

  ClusterMachineCloud cloud;
  ClusterMachineSSH ssh;
  ClusterMachineAddresses addresses;
  String providerName;
  String status;
  bool ready = false;

  bool operator==(const MachineProvisioningProgress& other) const
  {
    return cloud == other.cloud && ssh == other.ssh && addresses == other.addresses && providerName.equals(other.providerName) && status.equals(other.status) && ready == other.ready;
  }

  bool operator!=(const MachineProvisioningProgress& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, MachineProvisioningProgress& progress)
{
  serializer.object(progress.cloud);
  serializer.object(progress.ssh);
  serializer.object(progress.addresses);
  serializer.text1b(progress.providerName, UINT32_MAX);
  serializer.text1b(progress.status, UINT32_MAX);
  serializer.value1b(progress.ready);
}

class ProdigyTimingAttribution {
public:

  uint64_t providerWaitNs = 0;
  uint64_t runtimeOwnedNs = 0;

  bool operator==(const ProdigyTimingAttribution& other) const
  {
    return providerWaitNs == other.providerWaitNs && runtimeOwnedNs == other.runtimeOwnedNs;
  }

  bool operator!=(const ProdigyTimingAttribution& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyTimingAttribution& attribution)
{
  serializer.value8b(attribution.providerWaitNs);
  serializer.value8b(attribution.runtimeOwnedNs);
}

static inline uint64_t prodigyTimingAttributionTotalNs(const ProdigyTimingAttribution& attribution)
{
  return attribution.providerWaitNs + attribution.runtimeOwnedNs;
}

static inline void prodigyFinalizeTimingAttribution(uint64_t totalNs, uint64_t providerWaitNs, ProdigyTimingAttribution& attribution)
{
  attribution = {};
  attribution.providerWaitNs = std::min<uint64_t>(providerWaitNs, totalNs);
  attribution.runtimeOwnedNs = totalNs - attribution.providerWaitNs;
}

static inline void prodigyAccumulateTimingAttribution(ProdigyTimingAttribution& destination, const ProdigyTimingAttribution& source)
{
  destination.providerWaitNs += source.providerWaitNs;
  destination.runtimeOwnedNs += source.runtimeOwnedNs;
}

class BrainReachabilityProbeResult {
public:

  String brainLabel;
  bool reachable = false;
  uint32_t latencyMs = 0;
  String failure;

  bool operator==(const BrainReachabilityProbeResult& other) const
  {
    return brainLabel.equals(other.brainLabel) && reachable == other.reachable && latencyMs == other.latencyMs && failure.equals(other.failure);
  }

  bool operator!=(const BrainReachabilityProbeResult& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, BrainReachabilityProbeResult& result)
{
  serializer.text1b(result.brainLabel, UINT32_MAX);
  serializer.value1b(result.reachable);
  serializer.value4b(result.latencyMs);
  serializer.text1b(result.failure, UINT32_MAX);
}

constexpr static const char *prodigyCertbotManagedInstall = "bundle";
constexpr static const char *prodigyCertbotManagedPath = "/opt/prodigy/certbot/bin/certbot";
constexpr static const char *prodigyCertbotManagedVersion = "5.6.0";
constexpr static const char *prodigyCertbotManagedWheelhouse = "prodigy.certbot-5.6.0.wheelhouse.tar.zst";

class ProdigyACMEConfig {
public:

  String accountEmail;
  String certbotInstall;
  String certbotPath;
  String certbotVersion;
  bool termsAgreed = false;

  bool configured(void) const
  {
    return accountEmail.size() > 0 || certbotInstall.size() > 0 || certbotPath.size() > 0 || certbotVersion.size() > 0 || termsAgreed;
  }

  bool operator==(const ProdigyACMEConfig& other) const
  {
    return accountEmail.equals(other.accountEmail) && certbotInstall.equals(other.certbotInstall) && certbotPath.equals(other.certbotPath) && certbotVersion.equals(other.certbotVersion) && termsAgreed == other.termsAgreed;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyACMEConfig& config)
{
  serializer.text1b(config.accountEmail, UINT32_MAX);
  serializer.text1b(config.certbotInstall, UINT32_MAX);
  serializer.text1b(config.certbotPath, UINT32_MAX);
  serializer.text1b(config.certbotVersion, UINT32_MAX);
  serializer.value1b(config.termsAgreed);
}

class AddMachines {
public:

  String bootstrapSshUser;
  Vault::SSHKeyPackage bootstrapSshKeyPackage;
  Vault::SSHKeyPackage bootstrapSshHostKeyPackage;
  String bootstrapSshPrivateKeyPath;
  String remoteProdigyPath;
  String controlSocketPath;
  ProdigyACMEConfig acme;
  uint128_t clusterUUID = 0;
  MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
  Vector<ClusterMachine> adoptedMachines;
  Vector<ClusterMachine> readyMachines;
  Vector<ClusterMachine> removedMachines;

  bool isProgress = false;
  Vector<MachineProvisioningProgress> provisioningProgress;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
  bool hasTimingAttribution = false;
  ProdigyTimingAttribution timingAttribution;
#endif
  String reachabilityProbeAddress;
  Vector<BrainReachabilityProbeResult> reachabilityResults;
  bool success = false;
  bool hasTopology = false;
  ClusterTopology topology;
  String failure;

  bool operator==(const AddMachines& other) const
  {
    if (adoptedMachines.size() != other.adoptedMachines.size() || readyMachines.size() != other.readyMachines.size() || removedMachines.size() != other.removedMachines.size() || provisioningProgress.size() != other.provisioningProgress.size() || reachabilityResults.size() != other.reachabilityResults.size() || bootstrapSshUser.equals(other.bootstrapSshUser) == false || bootstrapSshKeyPackage != other.bootstrapSshKeyPackage || bootstrapSshHostKeyPackage != other.bootstrapSshHostKeyPackage || bootstrapSshPrivateKeyPath.equals(other.bootstrapSshPrivateKeyPath) == false || remoteProdigyPath.equals(other.remoteProdigyPath) == false || controlSocketPath.equals(other.controlSocketPath) == false || !(acme == other.acme) || clusterUUID != other.clusterUUID || architecture != other.architecture || isProgress != other.isProgress
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
        || hasTimingAttribution != other.hasTimingAttribution || timingAttribution != other.timingAttribution
#endif
        || reachabilityProbeAddress.equals(other.reachabilityProbeAddress) == false || success != other.success || hasTopology != other.hasTopology || topology != other.topology || failure.equals(other.failure) == false)
    {
      return false;
    }

    for (uint32_t index = 0; index < adoptedMachines.size(); ++index)
    {
      if (adoptedMachines[index] != other.adoptedMachines[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < readyMachines.size(); ++index)
    {
      if (readyMachines[index] != other.readyMachines[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < removedMachines.size(); ++index)
    {
      if (removedMachines[index] != other.removedMachines[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < provisioningProgress.size(); ++index)
    {
      if (provisioningProgress[index] != other.provisioningProgress[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < reachabilityResults.size(); ++index)
    {
      if (reachabilityResults[index] != other.reachabilityResults[index])
      {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const AddMachines& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, AddMachines& payload)
{
  serializer.text1b(payload.bootstrapSshUser, UINT32_MAX);
  serializer.object(payload.bootstrapSshKeyPackage);
  serializer.object(payload.bootstrapSshHostKeyPackage);
  serializer.text1b(payload.bootstrapSshPrivateKeyPath, UINT32_MAX);
  serializer.text1b(payload.remoteProdigyPath, UINT32_MAX);
  serializer.text1b(payload.controlSocketPath, UINT32_MAX);
  serializer.object(payload.acme);
  serializer.value16b(payload.clusterUUID);
  serializer.value1b(payload.architecture);
  serializer.object(payload.adoptedMachines);
  serializer.object(payload.readyMachines);
  serializer.object(payload.removedMachines);
  serializer.value1b(payload.isProgress);
  serializer.object(payload.provisioningProgress);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
  serializer.value1b(payload.hasTimingAttribution);
  serializer.object(payload.timingAttribution);
#endif
  serializer.text1b(payload.reachabilityProbeAddress, UINT32_MAX);
  serializer.object(payload.reachabilityResults);
  serializer.value1b(payload.success);
  serializer.value1b(payload.hasTopology);
  serializer.object(payload.topology);
  serializer.text1b(payload.failure, UINT32_MAX);
}

class OperatingSystemUpdatePolicy {
public:

  String osID;
  String targetVersionID;
  String command;
  bool includeVMs = false;
};

template <typename S>
static void serialize(S&& serializer, OperatingSystemUpdatePolicy& policy)
{
  serializer.text1b(policy.osID, UINT32_MAX);
  serializer.text1b(policy.targetVersionID, UINT32_MAX);
  serializer.text1b(policy.command, UINT32_MAX);
  serializer.value1b(policy.includeVMs);
}

class ApiCredential {
public:

  String name;
  String provider;
  uint64_t generation = 0;
  int64_t expiresAtMs = 0;
  int64_t activeFromMs = 0;
  int64_t sunsetAtMs = 0;
  String material;
  bytell_hash_map<String, String> metadata;
};

template <typename S>
static void serialize(S&& serializer, ApiCredential& credential)
{
  serializer.text1b(credential.name, UINT32_MAX);
  serializer.text1b(credential.provider, UINT32_MAX);
  serializer.value8b(credential.generation);
  serializer.value8b(credential.expiresAtMs);
  serializer.value8b(credential.activeFromMs);
  serializer.value8b(credential.sunsetAtMs);
  serializer.text1b(credential.material, UINT32_MAX);
  serializer.ext(credential.metadata, bitsery::ext::BytellHashMap {}, [](S& serializer, String& key, String& value) {
    serializer.text1b(key, UINT32_MAX);
    serializer.text1b(value, UINT32_MAX);
  });
}

class BrainConfig {
public:

  bytell_hash_map<String, MachineConfig> configBySlug;
  uint128_t clusterUUID = 0;
  uint8_t datacenterFragment = 0;
  uint32_t autoscaleIntervalSeconds = 180;
  uint16_t sharedCPUOvercommitPermille = 1000;
  ProdigyMachineReservedResources machineReservedResources;
  uint32_t requiredBrainCount = 0;
  MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
  String bootstrapSshUser;
  Vault::SSHKeyPackage bootstrapSshKeyPackage;
  Vault::SSHKeyPackage bootstrapSshHostKeyPackage;
  String bootstrapSshPrivateKeyPath;
  String remoteProdigyPath;
  String controlSocketPath;
  Vector<DistributableExternalSubnet> distributableExternalSubnets;
  String dnsProvider;
  ApiCredential dnsCredential;
  ProdigyACMEConfig acme;

  // Generic VM image URI for cloud providers (e.g., GCP: projects/<p>/global/images/<image>)
  String vmImageURI;
  bool osUpdatesEnabled = false;
  Vector<OperatingSystemUpdatePolicy> osUpdatePolicies;
  uint32_t maxOSDrains = 1;
  uint32_t machineUpdateCadenceMins = 15;
  ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
};

template <typename S>
static void serialize(S&& serializer, BrainConfig& config)
{
  serializer.object(config.configBySlug);
  serializer.value16b(config.clusterUUID);
  serializer.value1b(config.datacenterFragment);
  serializer.value4b(config.autoscaleIntervalSeconds);
  serializer.value2b(config.sharedCPUOvercommitPermille);
  serializer.object(config.machineReservedResources);
  serializer.value4b(config.requiredBrainCount);
  serializer.value1b(config.architecture);
  serializer.text1b(config.bootstrapSshUser, UINT32_MAX);
  serializer.object(config.bootstrapSshKeyPackage);
  serializer.object(config.bootstrapSshHostKeyPackage);
  serializer.text1b(config.bootstrapSshPrivateKeyPath, UINT32_MAX);
  serializer.text1b(config.remoteProdigyPath, UINT32_MAX);
  serializer.text1b(config.controlSocketPath, UINT32_MAX);
  serializer.object(config.distributableExternalSubnets);
  serializer.text1b(config.dnsProvider, UINT32_MAX);
  serializer.object(config.dnsCredential);
  serializer.object(config.acme);
  serializer.text1b(config.vmImageURI, UINT32_MAX);
  serializer.value1b(config.osUpdatesEnabled);
  serializer.container(config.osUpdatePolicies, UINT32_MAX);
  serializer.value4b(config.maxOSDrains);
  serializer.value4b(config.machineUpdateCadenceMins);
  serializer.object(config.runtimeEnvironment);
}

class UpsertMachineSchemas {
public:

  Vector<ProdigyManagedMachineSchemaPatch> patches;
  uint32_t upserted = 0;
  uint32_t created = 0;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
  bool hasTimingAttribution = false;
  ProdigyTimingAttribution timingAttribution;
#endif
  bool success = false;
  bool hasTopology = false;
  ClusterTopology topology;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, UpsertMachineSchemas& payload)
{
  serializer.object(payload.patches);
  serializer.value4b(payload.upserted);
  serializer.value4b(payload.created);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
  serializer.value1b(payload.hasTimingAttribution);
  serializer.object(payload.timingAttribution);
#endif
  serializer.value1b(payload.success);
  serializer.value1b(payload.hasTopology);
  serializer.object(payload.topology);
  serializer.text1b(payload.failure, UINT32_MAX);
}

class DeltaMachineBudget {
public:

  String schema;
  int64_t delta = 0;
  uint32_t budget = 0;
  bool success = false;
  bool hasTopology = false;
  ClusterTopology topology;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, DeltaMachineBudget& payload)
{
  serializer.text1b(payload.schema, UINT32_MAX);
  serializer.value8b(payload.delta);
  serializer.value4b(payload.budget);
  serializer.value1b(payload.success);
  serializer.value1b(payload.hasTopology);
  serializer.object(payload.topology);
  serializer.text1b(payload.failure, UINT32_MAX);
}

class DeleteMachineSchema {
public:

  String schema;
  bool removed = false;
  bool success = false;
  bool hasTopology = false;
  ClusterTopology topology;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, DeleteMachineSchema& payload)
{
  serializer.text1b(payload.schema, UINT32_MAX);
  serializer.value1b(payload.removed);
  serializer.value1b(payload.success);
  serializer.value1b(payload.hasTopology);
  serializer.object(payload.topology);
  serializer.text1b(payload.failure, UINT32_MAX);
}

// HSE needs 256 2MB pages for max performance, all other memory is file-backed 4K pages

class ApplicationConfigBase { // maybe if we garauntee only ever dealing with current or last version, we can write a simple translation
public:

  uint64_t config_version = 0;
};

enum class ApplicationCPUMode : uint8_t {
  isolated = 0,
  shared = 1
};

constexpr static uint32_t prodigyCPUUnitsPerCore = 1000u;
constexpr static uint16_t prodigySharedCPUOvercommitMinPermille = 1000u;
constexpr static uint16_t prodigySharedCPUOvercommitMaxPermille = 2000u;

static inline uint32_t prodigyRoundUpDivideU64(uint64_t numerator, uint64_t denominator)
{
  if (denominator == 0)
  {
    return 0;
  }

  return uint32_t((numerator + denominator - 1u) / denominator);
}

class ApplicationConfig : public ApplicationConfigBase {
public:

  ApplicationType type;
  TaskExecutionPolicy taskExecutionPolicy = TaskExecutionPolicy::runOnce;

  bytell_hash_set<int> capabilities;

  static uint16_t extractApplicationID(uint64_t deploymentID)
  {
    return deploymentID >> 48;
  }

  uint16_t applicationID;
  uint64_t versionID; // this is only 48 bits max
  MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
  Vector<String> requiredIsaFeatures;
  String containerBlobSHA256;
  uint64_t containerBlobBytes = 0;

  uint64_t deploymentID(void) const
  {
    return (((uint64_t)applicationID) << 48) | versionID;
  }

  // maximum storage space required including size of the initial filesystem
  // once quota-ing is enabled, a scan will initiate that takes 30-60 seconds to do (but maybe only when using clear which is 200+MB)
  // but eventaully it will come into sync
  uint32_t filesystemMB;
  uint32_t storageMB; // always mounted at /storage

  uint32_t totalStorageMB(void) const
  {
    return filesystemMB + storageMB;
  }

  uint32_t memoryMB; // standard container memory request

  uint32_t totalMemoryMB(void) const
  {
    return memoryMB;
  }

  uint32_t nLogicalCores;
  uint32_t maxPids = prodigyContainerRuntimeLimits.maxPids;
  uint32_t isolatedChildMemoryMB = 0;
  ApplicationCPUMode cpuMode = ApplicationCPUMode::isolated;
  uint32_t sharedCPUMillis = 0;
  uint32_t msTilHealthy; // plus grace period
  uint32_t sTilHealthcheck;
  uint32_t sTilKillable; // upon being instructed to stop, if the container hasn't stopped by these many seconds kill it
  uint32_t minGPUs = 0;
  uint32_t gpuMemoryGB = 0;
  uint32_t nicSpeedGbps = 0;
  uint32_t minInternetDownloadMbps = 0;
  uint32_t minInternetUploadMbps = 0;
  uint32_t maxInternetLatencyMs = 0;
};

static inline bool applicationUsesSharedCPUs(const ApplicationConfig& config)
{
  return config.cpuMode == ApplicationCPUMode::shared;
}

static inline bool applicationUsesIsolatedCPUs(const ApplicationConfig& config)
{
  return applicationUsesSharedCPUs(config) == false;
}

static inline uint32_t applicationRequestedCPUMillis(const ApplicationConfig& config)
{
  if (applicationUsesSharedCPUs(config))
  {
    if (config.sharedCPUMillis > 0)
    {
      return config.sharedCPUMillis;
    }
  }

  return config.nLogicalCores * prodigyCPUUnitsPerCore;
}

static inline uint32_t applicationSharedCPUCoreHint(const ApplicationConfig& config)
{
  if (applicationUsesSharedCPUs(config))
  {
    if (config.nLogicalCores > 0)
    {
      return config.nLogicalCores;
    }

    return prodigyRoundUpDivideU64(applicationRequestedCPUMillis(config), prodigyCPUUnitsPerCore);
  }

  return config.nLogicalCores;
}

static inline uint32_t applicationRequiredIsolatedCores(const ApplicationConfig& config)
{
  return applicationUsesIsolatedCPUs(config) ? config.nLogicalCores : 0u;
}

static inline uint32_t prodigyStatefulWorkerCountForLogicalCores(uint32_t nLogicalCores)
{
  if (nLogicalCores <= 2)
  {
    return 1;
  }

  return (nLogicalCores - 2);
}

static inline bool prodigyStatefulCoreChangeRequiresTopologyUpgrade(bool isStateful,
                                                                    uint32_t currentLogicalCores,
                                                                    uint32_t targetLogicalCores)
{
  return (isStateful && currentLogicalCores != targetLogicalCores);
}

template <typename S>
static void serialize(S&& serializer, ApplicationConfig& config)
{
  serializer.value8b(config.config_version);
  serializer.value8b(config.type);
  serializer.object(config.capabilities);
  serializer.value2b(config.applicationID);
  serializer.value8b(config.versionID);
  serializer.value1b(config.architecture);
  serializer.container(config.requiredIsaFeatures, UINT32_MAX);
  serializer.text1b(config.containerBlobSHA256, 64);
  serializer.value8b(config.containerBlobBytes);
  serializer.value4b(config.filesystemMB);
  serializer.value4b(config.storageMB);
  serializer.value4b(config.memoryMB);
  serializer.value4b(config.nLogicalCores);
  serializer.value4b(config.maxPids);
  serializer.value4b(config.isolatedChildMemoryMB);
  serializer.value1b(config.cpuMode);
  serializer.value4b(config.sharedCPUMillis);
  serializer.value4b(config.msTilHealthy);
  serializer.value4b(config.sTilHealthcheck);
  serializer.value4b(config.sTilKillable);
  serializer.value4b(config.minGPUs);
  serializer.value4b(config.gpuMemoryGB);
  serializer.value4b(config.nicSpeedGbps);
  serializer.value4b(config.minInternetDownloadMbps);
  serializer.value4b(config.minInternetUploadMbps);
  serializer.value4b(config.maxInternetLatencyMs);
  serializer.value1b(config.taskExecutionPolicy);
}

constexpr static int64_t prodigyTaskExecutionRecordRetentionMs = 24LL * 60LL * 60LL * 1000LL;
constexpr static uint32_t prodigyTaskResultMaxBytes = 64u * 1024u;

constexpr static const char *prodigyTaskExecutionPolicyName(TaskExecutionPolicy policy)
{
  switch (policy)
  {
    case TaskExecutionPolicy::runOnce:
      return "runOnce";
    case TaskExecutionPolicy::untilSucceeded:
      return "untilSucceeded";
  }

  return "unknown";
}

constexpr static const char *prodigyTaskExecutionStateName(TaskExecutionState state)
{
  switch (state)
  {
    case TaskExecutionState::accepted:
      return "accepted";
    case TaskExecutionState::assigned:
      return "assigned";
    case TaskExecutionState::running:
      return "running";
    case TaskExecutionState::retrying:
      return "retrying";
    case TaskExecutionState::succeeded:
      return "succeeded";
    case TaskExecutionState::failed:
      return "failed";
    case TaskExecutionState::cancelled:
      return "cancelled";
    case TaskExecutionState::lost:
      return "lost";
  }

  return "unknown";
}

constexpr static const char *prodigyTaskTerminationKindName(TaskTerminationKind kind)
{
  switch (kind)
  {
    case TaskTerminationKind::none:
      return "none";
    case TaskTerminationKind::exited:
      return "exited";
    case TaskTerminationKind::signaled:
      return "signaled";
    case TaskTerminationKind::oomKilled:
      return "oomKilled";
    case TaskTerminationKind::startupFailed:
      return "startupFailed";
    case TaskTerminationKind::placementFailed:
      return "placementFailed";
    case TaskTerminationKind::cancelled:
      return "cancelled";
    case TaskTerminationKind::lost:
      return "lost";
  }

  return "unknown";
}

constexpr static const char *prodigyTaskAttemptJournalStateName(TaskAttemptJournalState state)
{
  switch (state)
  {
    case TaskAttemptJournalState::accepted:
      return "accepted";
    case TaskAttemptJournalState::running:
      return "running";
    case TaskAttemptJournalState::terminal:
      return "terminal";
    case TaskAttemptJournalState::acknowledged:
      return "acknowledged";
  }

  return "unknown";
}

constexpr static bool taskExecutionTerminal(TaskExecutionState state)
{
  return state == TaskExecutionState::succeeded || state == TaskExecutionState::failed || state == TaskExecutionState::cancelled || state == TaskExecutionState::lost;
}

constexpr static bool taskTerminationSucceeded(TaskTerminationKind kind, int32_t exitCode)
{
  return kind == TaskTerminationKind::exited && exitCode == 0;
}

class TaskTermination {
public:

  TaskTerminationKind kind = TaskTerminationKind::none;
  int32_t exitCode = 0;
  int32_t signal = 0;
  bool oomKilled = false;
  int64_t observedAtMs = 0;
  String summary;
  String result;

  bool succeeded(void) const
  {
    return taskTerminationSucceeded(kind, exitCode);
  }

  bool operator==(const TaskTermination& other) const
  {
    return kind == other.kind && exitCode == other.exitCode && signal == other.signal && oomKilled == other.oomKilled && observedAtMs == other.observedAtMs && summary == other.summary && result == other.result;
  }
};

template <typename S>
static void serialize(S&& serializer, TaskTermination& termination)
{
  serializer.value1b(termination.kind);
  serializer.value4b(termination.exitCode);
  serializer.value4b(termination.signal);
  serializer.value1b(termination.oomKilled);
  serializer.value8b(termination.observedAtMs);
  serializer.text1b(termination.summary, UINT32_MAX);
  serializer.text1b(termination.result, prodigyTaskResultMaxBytes);
}

class TaskAttemptRecord {
public:

  uint32_t attemptNumber = 0;
  uint128_t containerUUID = 0;
  uint32_t machinePrivate4 = 0;
  TaskExecutionState state = TaskExecutionState::accepted;
  int64_t acceptedAtMs = 0;
  int64_t assignedAtMs = 0;
  int64_t startedAtMs = 0;
  int64_t completedAtMs = 0;
  TaskTermination termination;
  bool noRelaunchTombstone = false;

  bool terminal(void) const
  {
    return taskExecutionTerminal(state);
  }

  bool operator==(const TaskAttemptRecord& other) const
  {
    return attemptNumber == other.attemptNumber && containerUUID == other.containerUUID && machinePrivate4 == other.machinePrivate4 && state == other.state && acceptedAtMs == other.acceptedAtMs && assignedAtMs == other.assignedAtMs && startedAtMs == other.startedAtMs && completedAtMs == other.completedAtMs && termination == other.termination && noRelaunchTombstone == other.noRelaunchTombstone;
  }
};

template <typename S>
static void serialize(S&& serializer, TaskAttemptRecord& attempt)
{
  serializer.value4b(attempt.attemptNumber);
  serializer.value16b(attempt.containerUUID);
  serializer.value4b(attempt.machinePrivate4);
  serializer.value1b(attempt.state);
  serializer.value8b(attempt.acceptedAtMs);
  serializer.value8b(attempt.assignedAtMs);
  serializer.value8b(attempt.startedAtMs);
  serializer.value8b(attempt.completedAtMs);
  serializer.object(attempt.termination);
  serializer.value1b(attempt.noRelaunchTombstone);
}

static inline uint128_t prodigyTaskAttemptJournalKey(uint64_t deploymentID, uint32_t attemptNumber)
{
  return (uint128_t(deploymentID) << 64) | uint128_t(attemptNumber);
}

class TaskAttemptJournalRecord {
public:

  uint64_t deploymentID = 0;
  uint32_t attemptNumber = 0;
  uint128_t containerUUID = 0;
  TaskAttemptJournalState state = TaskAttemptJournalState::accepted;
  int64_t updatedAtMs = 0;
  int64_t expiresAtMs = 0;
  bool hasTermination = false;
  TaskTermination termination;

  uint128_t key(void) const
  {
    return prodigyTaskAttemptJournalKey(deploymentID, attemptNumber);
  }

  bool terminalOutbox(void) const
  {
    return state == TaskAttemptJournalState::terminal && hasTermination;
  }

  bool expired(int64_t nowMs) const
  {
    return state == TaskAttemptJournalState::acknowledged && expiresAtMs > 0 && nowMs >= expiresAtMs;
  }

  bool operator==(const TaskAttemptJournalRecord& other) const
  {
    return deploymentID == other.deploymentID && attemptNumber == other.attemptNumber && containerUUID == other.containerUUID && state == other.state && updatedAtMs == other.updatedAtMs && expiresAtMs == other.expiresAtMs && hasTermination == other.hasTermination && termination == other.termination;
  }
};

template <typename S>
static void serialize(S&& serializer, TaskAttemptJournalRecord& record)
{
  serializer.value8b(record.deploymentID);
  serializer.value4b(record.attemptNumber);
  serializer.value16b(record.containerUUID);
  serializer.value1b(record.state);
  serializer.value8b(record.updatedAtMs);
  serializer.value8b(record.expiresAtMs);
  serializer.value1b(record.hasTermination);
  serializer.object(record.termination);
}

class TaskExecutionRecord {
public:

  uint64_t executionID = 0;
  uint16_t applicationID = 0;
  uint64_t versionID = 0;
  TaskExecutionPolicy policy = TaskExecutionPolicy::runOnce;
  TaskExecutionState state = TaskExecutionState::accepted;
  String fingerprint;
  uint32_t currentAttemptNumber = 0;
  uint32_t attemptsStarted = 0;
  uint32_t attemptsSucceeded = 0;
  uint32_t attemptsFailed = 0;
  uint32_t attemptsLost = 0;
  uint32_t attemptsCancelled = 0;
  int64_t acceptedAtMs = 0;
  int64_t updatedAtMs = 0;
  int64_t completedAtMs = 0;
  int64_t expiresAtMs = 0;
  bool hasLatestNonSuccessAttempt = false;
  TaskAttemptRecord latestNonSuccessAttempt;
  bool hasFinalAttempt = false;
  TaskAttemptRecord finalAttempt;

  bool terminal(void) const
  {
    return taskExecutionTerminal(state);
  }

  bool expired(int64_t nowMs) const
  {
    return terminal() && expiresAtMs > 0 && nowMs >= expiresAtMs;
  }

  bool operator==(const TaskExecutionRecord& other) const
  {
    return executionID == other.executionID && applicationID == other.applicationID && versionID == other.versionID && policy == other.policy && state == other.state && fingerprint == other.fingerprint && currentAttemptNumber == other.currentAttemptNumber && attemptsStarted == other.attemptsStarted && attemptsSucceeded == other.attemptsSucceeded && attemptsFailed == other.attemptsFailed && attemptsLost == other.attemptsLost && attemptsCancelled == other.attemptsCancelled && acceptedAtMs == other.acceptedAtMs && updatedAtMs == other.updatedAtMs && completedAtMs == other.completedAtMs && expiresAtMs == other.expiresAtMs && hasLatestNonSuccessAttempt == other.hasLatestNonSuccessAttempt && latestNonSuccessAttempt == other.latestNonSuccessAttempt && hasFinalAttempt == other.hasFinalAttempt && finalAttempt == other.finalAttempt;
  }
};

template <typename S>
static void serialize(S&& serializer, TaskExecutionRecord& record)
{
  serializer.value8b(record.executionID);
  serializer.value2b(record.applicationID);
  serializer.value8b(record.versionID);
  serializer.value1b(record.policy);
  serializer.value1b(record.state);
  serializer.text1b(record.fingerprint, UINT32_MAX);
  serializer.value4b(record.currentAttemptNumber);
  serializer.value4b(record.attemptsStarted);
  serializer.value4b(record.attemptsSucceeded);
  serializer.value4b(record.attemptsFailed);
  serializer.value4b(record.attemptsLost);
  serializer.value4b(record.attemptsCancelled);
  serializer.value8b(record.acceptedAtMs);
  serializer.value8b(record.updatedAtMs);
  serializer.value8b(record.completedAtMs);
  serializer.value8b(record.expiresAtMs);
  serializer.value1b(record.hasLatestNonSuccessAttempt);
  serializer.object(record.latestNonSuccessAttempt);
  serializer.value1b(record.hasFinalAttempt);
  serializer.object(record.finalAttempt);
}

static inline bool taskExecutionStateTransitionAllowed(TaskExecutionState from, TaskExecutionState to)
{
  if (from == to)
  {
    return true;
  }

  if (taskExecutionTerminal(from))
  {
    return false;
  }

  switch (from)
  {
    case TaskExecutionState::accepted:
      return to == TaskExecutionState::assigned || to == TaskExecutionState::failed || to == TaskExecutionState::cancelled || to == TaskExecutionState::lost;
    case TaskExecutionState::assigned:
      return to == TaskExecutionState::running || to == TaskExecutionState::succeeded || to == TaskExecutionState::failed || to == TaskExecutionState::cancelled || to == TaskExecutionState::lost || to == TaskExecutionState::retrying;
    case TaskExecutionState::running:
      return to == TaskExecutionState::succeeded || to == TaskExecutionState::failed || to == TaskExecutionState::cancelled || to == TaskExecutionState::lost || to == TaskExecutionState::retrying;
    case TaskExecutionState::retrying:
      return to == TaskExecutionState::assigned || to == TaskExecutionState::cancelled || to == TaskExecutionState::lost;
    case TaskExecutionState::succeeded:
    case TaskExecutionState::failed:
    case TaskExecutionState::cancelled:
    case TaskExecutionState::lost:
      return false;
  }

  return false;
}

static inline bool taskExecutionTransition(TaskExecutionRecord& record, TaskExecutionState next, int64_t nowMs, String *failure = nullptr)
{
  if (taskExecutionStateTransitionAllowed(record.state, next) == false)
  {
    if (failure)
    {
      failure->snprintf<"invalid task execution transition from {} to {}"_ctv>(String(prodigyTaskExecutionStateName(record.state)), String(prodigyTaskExecutionStateName(next)));
    }
    return false;
  }

  record.state = next;
  record.updatedAtMs = nowMs;
  if (taskExecutionTerminal(next) && record.completedAtMs == 0)
  {
    record.completedAtMs = nowMs;
    record.expiresAtMs = nowMs + prodigyTaskExecutionRecordRetentionMs;
  }

  return true;
}

static inline TaskExecutionState taskExecutionStateForAttemptTermination(TaskExecutionPolicy policy, const TaskTermination& termination)
{
  if (termination.succeeded())
  {
    return TaskExecutionState::succeeded;
  }
  if (termination.kind == TaskTerminationKind::cancelled)
  {
    return TaskExecutionState::cancelled;
  }
  if (termination.kind == TaskTerminationKind::lost && policy == TaskExecutionPolicy::runOnce)
  {
    return TaskExecutionState::lost;
  }
  if (policy == TaskExecutionPolicy::untilSucceeded)
  {
    return TaskExecutionState::retrying;
  }
  if (termination.kind == TaskTerminationKind::lost)
  {
    return TaskExecutionState::lost;
  }

  return TaskExecutionState::failed;
}

static inline bool taskExecutionCommitAttempt(TaskExecutionRecord& record, const TaskAttemptRecord& attempt, int64_t nowMs, String *failure = nullptr)
{
  if (attempt.attemptNumber == 0)
  {
    if (failure)
    {
      failure->assign("task attempt number must be nonzero"_ctv);
    }
    return false;
  }
  if (record.currentAttemptNumber != 0 && attempt.attemptNumber < record.currentAttemptNumber)
  {
    if (failure)
    {
      failure->assign("task attempt number moved backwards"_ctv);
    }
    return false;
  }

  TaskExecutionState next = taskExecutionStateForAttemptTermination(record.policy, attempt.termination);
  if (taskExecutionTransition(record, next, nowMs, failure) == false)
  {
    return false;
  }

  record.currentAttemptNumber = attempt.attemptNumber;
  record.hasFinalAttempt = taskExecutionTerminal(record.state);
  if (record.hasFinalAttempt)
  {
    record.finalAttempt = attempt;
  }

  if (attempt.termination.succeeded())
  {
    record.attemptsSucceeded += 1;
  }
  else if (attempt.termination.kind == TaskTerminationKind::cancelled)
  {
    record.attemptsCancelled += 1;
    record.hasLatestNonSuccessAttempt = true;
    record.latestNonSuccessAttempt = attempt;
  }
  else if (attempt.termination.kind == TaskTerminationKind::lost)
  {
    record.attemptsLost += 1;
    record.hasLatestNonSuccessAttempt = true;
    record.latestNonSuccessAttempt = attempt;
  }
  else
  {
    record.attemptsFailed += 1;
    record.hasLatestNonSuccessAttempt = true;
    record.latestNonSuccessAttempt = attempt;
  }

  return true;
}

class StatefulDeploymentPlan {
public:

  // 1 member of a shard group per rack (implies 1 per machine)
  // 1 member of a shard group per machine

  // always 3 per group

  // if no previous deployment, start with 1 shard group

  uint64_t clientPrefix;
  uint64_t siblingPrefix;
  uint64_t cousinPrefix;
  uint64_t seedingPrefix;
  uint64_t shardingPrefix;

  bool allowUpdateInPlace; // for some versions we might not allow this so that we can change data formats etc

  // Only changelog/update-style construction consults this flag. Genesis launch still starts empty without
  // requesting seeding. Ephemeral, in-memory-only databases like graph services need restart/update construction
  // to seed from siblings because changelog replay alone cannot rebuild them.
  bool seedingAlways;

  // if we autoscaled the resources when (neverShard == true) then we'd have to include logic about what to do when the instances don't fit on any machine type
  // and then also when a new application version was submitted we'd have to choose the larger of the two
  bool neverShard;

  // every instance accepts writes and reads
  bool allMasters;
};

template <typename S>
static void serialize(S&& serializer, StatefulDeploymentPlan& plan)
{
  serializer.value8b(plan.clientPrefix);
  serializer.value8b(plan.siblingPrefix);
  serializer.value8b(plan.cousinPrefix);
  serializer.value8b(plan.seedingPrefix);
  serializer.value8b(plan.shardingPrefix);

  serializer.value1b(plan.allowUpdateInPlace);
  serializer.value1b(plan.seedingAlways);
  serializer.value1b(plan.neverShard);
  serializer.value1b(plan.allMasters);
}

static inline uint64_t prodigyRuntimeStatefulServicePrefix(uint16_t applicationID, uint8_t serviceID)
{
  return (uint64_t(applicationID) << 48) | (uint64_t(serviceID) << 40) | (uint64_t(nShardsPerStatefulApplication) - 1);
}

static inline uint64_t prodigyDefaultStatefulTopologyBridgePrefix(uint16_t applicationID)
{
  if (applicationID == 0)
  {
    return 0;
  }

  return prodigyRuntimeStatefulServicePrefix(applicationID, 6);
}

enum class StatefulMeshRole : uint8_t {
  none,
  client,
  sibling,
  cousin,
  seeding,
  sharding,
  topologyBridge
};

class StatefulMeshRoles {
public:

  uint64_t client = 0;
  uint64_t sibling = 0;
  uint64_t cousin = 0;
  uint64_t seeding = 0;
  uint64_t sharding = 0;
  uint64_t topologyBridge = 0;

  StatefulMeshRole classify(uint64_t service) const
  {
    if (client != 0 && (client == service || MeshRegistry::prefixContains(client, service)))
    {
      return StatefulMeshRole::client;
    }

    if (sibling != 0 && (sibling == service || MeshRegistry::prefixContains(sibling, service)))
    {
      return StatefulMeshRole::sibling;
    }

    if (cousin != 0 && (cousin == service || MeshRegistry::prefixContains(cousin, service)))
    {
      return StatefulMeshRole::cousin;
    }

    if (seeding != 0 && (seeding == service || MeshRegistry::prefixContains(seeding, service)))
    {
      return StatefulMeshRole::seeding;
    }

    if (sharding != 0 && (sharding == service || MeshRegistry::prefixContains(sharding, service)))
    {
      return StatefulMeshRole::sharding;
    }

    if (topologyBridge != 0 && (topologyBridge == service || MeshRegistry::prefixContains(topologyBridge, service)))
    {
      return StatefulMeshRole::topologyBridge;
    }

    return StatefulMeshRole::none;
  }

  static StatefulMeshRoles forShardGroup(const StatefulDeploymentPlan& plan, uint16_t applicationID, uint32_t shardGroup)
  {
    StatefulMeshRoles roles;
    if (plan.clientPrefix != 0)
    {
      roles.client = MeshServices::constrainPrefixToGroup(plan.clientPrefix, shardGroup);
    }

    if (plan.siblingPrefix != 0)
    {
      roles.sibling = MeshServices::constrainPrefixToGroup(plan.siblingPrefix, shardGroup);
    }

    if (plan.cousinPrefix != 0)
    {
      roles.cousin = MeshServices::constrainPrefixToGroup(plan.cousinPrefix, shardGroup);
    }

    if (plan.seedingPrefix != 0)
    {
      roles.seeding = MeshServices::constrainPrefixToGroup(plan.seedingPrefix, shardGroup);
    }

    if (plan.shardingPrefix != 0)
    {
      roles.sharding = MeshServices::constrainPrefixToGroup(plan.shardingPrefix, shardGroup);
    }

    if (uint64_t topologyBridgePrefix = prodigyDefaultStatefulTopologyBridgePrefix(applicationID); topologyBridgePrefix != 0)
    {
      roles.topologyBridge = MeshServices::constrainPrefixToGroup(topologyBridgePrefix, shardGroup);
    }
    return roles;
  }

  static StatefulMeshRoles forShardGroup(const StatefulDeploymentPlan& plan, uint32_t shardGroup)
  {
    return forShardGroup(plan, 0, shardGroup);
  }
};

static inline bool prodigyStatefulMeshRolesConfigured(const StatefulMeshRoles& roles)
{
  return (roles.client != 0 || roles.sibling != 0 || roles.cousin != 0 || roles.seeding != 0 || roles.sharding != 0 || roles.topologyBridge != 0);
}

template <typename S>
static void serialize(S&& serializer, StatefulMeshRoles& roles)
{
  serializer.value8b(roles.client);
  serializer.value8b(roles.sibling);
  serializer.value8b(roles.cousin);
  serializer.value8b(roles.seeding);
  serializer.value8b(roles.sharding);
  serializer.value8b(roles.topologyBridge);
}

enum class StatefulTopologyServingMode : uint8_t {
  none,
  serve,
  catchupOnly,
  drainOnly
};

enum class StatefulTopologyBridgeMode : uint8_t {
  none,
  sourceToTarget,
  targetToSource,
  bidirectional
};

enum class StatefulWorkerTopologyUpgradePhase : uint8_t {
  none,
  greenBootstrap,
  blueDraining
};

class StatefulTopology {
public:

  uint64_t operationID = 0;
  uint32_t shardGroup = 0;
  uint32_t topologyEpoch = 0;
  uint32_t workerCount = 0;
  StatefulTopologyServingMode servingMode = StatefulTopologyServingMode::none;
  uint32_t sourceEpoch = 0;
  uint32_t targetEpoch = 0;
  StatefulTopologyBridgeMode bridgeMode = StatefulTopologyBridgeMode::none;

  bool configured(void) const
  {
    return (operationID != 0 || topologyEpoch != 0 || workerCount != 0 || servingMode != StatefulTopologyServingMode::none || sourceEpoch != 0 || targetEpoch != 0 || bridgeMode != StatefulTopologyBridgeMode::none);
  }
};

template <typename S>
static void serialize(S&& serializer, StatefulTopology& topology)
{
  serializer.value8b(topology.operationID);
  serializer.value4b(topology.shardGroup);
  serializer.value4b(topology.topologyEpoch);
  serializer.value4b(topology.workerCount);
  serializer.value1b(topology.servingMode);
  serializer.value4b(topology.sourceEpoch);
  serializer.value4b(topology.targetEpoch);
  serializer.value1b(topology.bridgeMode);
}

static inline void prodigyPopulateDefaultStatefulTopology(StatefulTopology& topology, uint32_t shardGroup, const ApplicationConfig& config)
{
  topology.shardGroup = shardGroup;

  if (topology.workerCount == 0)
  {
    topology.workerCount = prodigyStatefulWorkerCountForLogicalCores(config.nLogicalCores);
  }

  if (topology.topologyEpoch == 0)
  {
    topology.topologyEpoch = topology.workerCount;
  }

  if (topology.sourceEpoch == 0)
  {
    topology.sourceEpoch = topology.topologyEpoch;
  }

  if (topology.targetEpoch == 0)
  {
    topology.targetEpoch = topology.topologyEpoch;
  }

  if (topology.servingMode == StatefulTopologyServingMode::none)
  {
    topology.servingMode = StatefulTopologyServingMode::serve;
  }
}

static inline bool prodigyStatefulTopologyServesClients(const StatefulTopology& topology)
{
  return (topology.servingMode == StatefulTopologyServingMode::serve);
}

static inline bool prodigyStatefulTopologyShouldAdvertiseBridge(const StatefulTopology& topology)
{
  switch (topology.bridgeMode)
  {
    case StatefulTopologyBridgeMode::sourceToTarget:
      {
        return (topology.topologyEpoch != 0 && topology.topologyEpoch == topology.sourceEpoch);
      }
    case StatefulTopologyBridgeMode::targetToSource:
      {
        return (topology.topologyEpoch != 0 && topology.topologyEpoch == topology.targetEpoch);
      }
    case StatefulTopologyBridgeMode::bidirectional:
      {
        return (topology.topologyEpoch != 0 && (topology.topologyEpoch == topology.sourceEpoch || topology.topologyEpoch == topology.targetEpoch));
      }
    case StatefulTopologyBridgeMode::none:
    default:
      {
        return false;
      }
  }
}

static inline bool prodigyStatefulTopologyShouldSubscribeBridge(const StatefulTopology& topology)
{
  switch (topology.bridgeMode)
  {
    case StatefulTopologyBridgeMode::sourceToTarget:
      {
        return (topology.topologyEpoch != 0 && topology.topologyEpoch == topology.targetEpoch);
      }
    case StatefulTopologyBridgeMode::targetToSource:
      {
        return (topology.topologyEpoch != 0 && topology.topologyEpoch == topology.sourceEpoch);
      }
    case StatefulTopologyBridgeMode::bidirectional:
      {
        return (topology.topologyEpoch != 0 && (topology.topologyEpoch == topology.sourceEpoch || topology.topologyEpoch == topology.targetEpoch));
      }
    case StatefulTopologyBridgeMode::none:
    default:
      {
        return false;
      }
  }
}

class ProdigyStatefulWorkerTopologyUpgradeOperation {
public:

  uint64_t deploymentID = 0;
  uint16_t applicationID = 0;
  uint64_t operationID = 0;
  StatefulWorkerTopologyUpgradePhase phase = StatefulWorkerTopologyUpgradePhase::none;
  uint32_t sourceWorkerCount = 0;
  uint32_t targetWorkerCount = 0;
  uint32_t sourceEpoch = 0;
  uint32_t targetEpoch = 0;
  uint16_t targetLogicalCores = 0;
  uint32_t targetMemoryMB = 0;
  uint32_t targetStorageMB = 0;
  Vector<uint32_t> lockedShardGroups;
  int64_t updatedAtMs = 0;

  bool operator==(const ProdigyStatefulWorkerTopologyUpgradeOperation& other) const
  {
    if (deploymentID != other.deploymentID || applicationID != other.applicationID || operationID != other.operationID || phase != other.phase || sourceWorkerCount != other.sourceWorkerCount || targetWorkerCount != other.targetWorkerCount || sourceEpoch != other.sourceEpoch || targetEpoch != other.targetEpoch || targetLogicalCores != other.targetLogicalCores || targetMemoryMB != other.targetMemoryMB || targetStorageMB != other.targetStorageMB || updatedAtMs != other.updatedAtMs || lockedShardGroups.size() != other.lockedShardGroups.size())
    {
      return false;
    }

    for (uint32_t index = 0; index < lockedShardGroups.size(); ++index)
    {
      if (lockedShardGroups[index] != other.lockedShardGroups[index])
      {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const ProdigyStatefulWorkerTopologyUpgradeOperation& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyStatefulWorkerTopologyUpgradeOperation& operation)
{
  serializer.value8b(operation.deploymentID);
  serializer.value2b(operation.applicationID);
  serializer.value8b(operation.operationID);
  serializer.value1b(operation.phase);
  serializer.value4b(operation.sourceWorkerCount);
  serializer.value4b(operation.targetWorkerCount);
  serializer.value4b(operation.sourceEpoch);
  serializer.value4b(operation.targetEpoch);
  serializer.value2b(operation.targetLogicalCores);
  serializer.value4b(operation.targetMemoryMB);
  serializer.value4b(operation.targetStorageMB);
  serializer.object(operation.lockedShardGroups);
  serializer.value8b(operation.updatedAtMs);
}

class ProdigyDeferredStatefulScaleIntent {
public:

  uint64_t deploymentID = 0;
  uint16_t applicationID = 0;
  uint32_t targetShardGroups = 0;
  uint16_t targetLogicalCores = 0;
  uint32_t targetMemoryMB = 0;
  uint32_t targetStorageMB = 0;
  int64_t updatedAtMs = 0;

  bool operator==(const ProdigyDeferredStatefulScaleIntent& other) const
  {
    return (deploymentID == other.deploymentID && applicationID == other.applicationID && targetShardGroups == other.targetShardGroups && targetLogicalCores == other.targetLogicalCores && targetMemoryMB == other.targetMemoryMB && targetStorageMB == other.targetStorageMB && updatedAtMs == other.updatedAtMs);
  }

  bool operator!=(const ProdigyDeferredStatefulScaleIntent& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyDeferredStatefulScaleIntent& intent)
{
  serializer.value8b(intent.deploymentID);
  serializer.value2b(intent.applicationID);
  serializer.value4b(intent.targetShardGroups);
  serializer.value2b(intent.targetLogicalCores);
  serializer.value4b(intent.targetMemoryMB);
  serializer.value4b(intent.targetStorageMB);
  serializer.value8b(intent.updatedAtMs);
}

class StatelessDeploymentPlan {
public:

  uint32_t nBase;

  // assume 5 racks each with 1 machine, and a concentration limit of 35% (to give some wiggle room... allowing stateless application to only deploy 3 instances.. yet this would subject them to movability?? they'd only be movable to other reserved machines though...)

  /* case study

     assume 35% maxPerRackRatio and 3 application server base instances... each rack (and machine) would have 33% concentration

     during normal operation

        these instances could be moved to any other reserved machine. every instance could be moved in the same operation, so we'd have to be careful that the moves don't occur
        simultaneously or all instances could be killed at the same time.

        when surge instances are added, they'd be added to the other 2 reserved machines, each machine now having 20% concentration. when the 6th is added, it could be added to any
        machine, which would now have 2/6 or 33%. the point is we need to make sure when this 2/6 occurs, that we aren't over the concentration limit. if we only had 4 racks, the
        concentration limit would need to be 40% and if we had 3 racks it would need to be 50%.

        but as soon as we add another machine (spot or reserved), if it landed on an existing rack... it's possible that rack is already at the concentration limit due to unbalanced
        scheduling. and even if distribution were equal... thus 20% on each... we still couldn't fill that machine with the same number of instances as the other because then we'd be at 40% rack concentration.

        so maybe we do both machine and rack concentrations... but set the rack concentration to at least 41% and the machine concentration to 34%

        but it's possible we were only scheduled onto say 4 of the 5 reserved machines... so each machine is now 25%

        not a complete analysis but approximately we should be fine!!! because if we failed to schedule, we'd attempt compaction, which would ensure rebalancing..

     if one machine failed

        we could lose at most the concentration limit

     if one failed they'd jump to 50%. no action would be taken when the  concentration is breached. and those instances could not be moved either.
  */

  // maxPerMachineRatio < maxPerRackRatio
  // if there is only 1 machine per rack, the maxPerMachineRatio is always breached before maxPerRackRatio
  // if there are 2 machines per rack, then maxPerRackRatio imposes the bound
  // as we scale, we'll drastically lower these ratios to single digits
  float maxPerRackRatio;
  float maxPerMachineRatio; // relative to rack %

  bool moveableDuringCompaction;
};

template <typename S>
static void serialize(S&& serializer, StatelessDeploymentPlan& plan)
{
  serializer.value4b(plan.nBase);
  serializer.value4b(plan.maxPerRackRatio);
  serializer.value4b(plan.maxPerMachineRatio);

  serializer.value1b(plan.moveableDuringCompaction);
}

class FailureReport {
public:

  uint128_t containerUUID;
  String report; // maybe sometimes coredumps, maybe sometimes traces, maybe sometimes messages
  int64_t approxTimeMs;
  uint32_t nthCrash;
  int signal;
  bool restarted;
  bool wasCanary;

  void stringify(String& string, uint8_t nTabs) const
  {
    string.appendTabs(nTabs);
    string.append("Failure Report:\n"_ctv);

    string.snprintf_tab_add<"\tnreport: {}\n"_ctv>(nTabs, report);
    string.snprintf_tab_add<"\tnapproxTime: {}\n"_ctv>(nTabs, String::epochMsToDateTime(approxTimeMs));
    string.snprintf_tab_add<"\tnnthCrash: {itoa}\n"_ctv>(nTabs, nthCrash);
    string.snprintf_tab_add<"\tnsignal: {itoa}\n"_ctv>(nTabs, signal);
    string.snprintf_tab_add<"\tnrestarted: {}\n"_ctv>(nTabs, restarted ? String("true"_ctv) : String("false"_ctv));
    string.snprintf_tab_add<"\tnwasCanary: {}\n"_ctv>(nTabs, wasCanary ? String("true"_ctv) : String("false"_ctv));
  }
};

template <typename S>
static void serialize(S&& serializer, FailureReport& freport)
{
  serializer.value16b(freport.containerUUID);
  serializer.text1b(freport.report, UINT32_MAX);
  serializer.value8b(freport.approxTimeMs);
  serializer.value4b(freport.nthCrash);
  serializer.value4b(freport.signal);
  serializer.value1b(freport.restarted);
  serializer.value1b(freport.wasCanary);
}

class ScalerState {
public:

  String name;
  double value;
  int64_t queryTimeMs;

  ScalerState()
      : value(0),
        queryTimeMs(0)
  {}
  ScalerState(const String& _name, double _value, int64_t _queryTimeMs)
      : name(_name),
        value(_value),
        queryTimeMs(_queryTimeMs)
  {}

  void stringify(String& string, uint8_t nTabs) const
  {
    string.appendTabs(nTabs);
    string.append("Scaler:\n"_ctv);

    string.snprintf_tab_add<"\tname: {}\n"_ctv>(nTabs, name);
    string.snprintf_tab_add<"\tnvalue: {dtoa:2}\n"_ctv>(nTabs, value);
    string.snprintf_tab_add<"\tnqueryTime: {}\n"_ctv>(nTabs, String::epochMsToDateTime(queryTimeMs));
  }
};

template <typename S>
static void serialize(S&& serializer, ScalerState& state)
{
  serializer.text1b(state.name, UINT32_MAX);
  serializer.value8b(state.value);
  serializer.value8b(state.queryTimeMs);
}

class DeploymentStatusReport {
public:

  uint64_t versionID;

  DeploymentState state = DeploymentState::none;
  int64_t stateSinceMs;

  bool isStateful;
  uint32_t nShardGroups;

  uint32_t nTarget;
  uint32_t nTargetBase;
  uint32_t nTargetSurge;

  uint32_t nDeployed;
  uint32_t nDeployedCanary;
  uint32_t nDeployedBase;
  uint32_t nDeployedSurge;

  uint32_t nHealthy;
  uint32_t nHealthyCanary;
  uint32_t nHealthyBase;
  uint32_t nHealthySurge;

  uint32_t nCrashes;
  uint32_t nTlsIdentityExpected;
  uint32_t nTlsIdentityFresh;
  uint32_t nTlsIdentityStale;
  uint32_t nTlsIdentityPending;

  Vector<ScalerState> lastScalerStates;
  Vector<FailureReport> failureReports;

  // Per-container runtime resources (reported by brain from neuron runtime state)
  class ContainerRuntime {
  public:

    uint128_t uuid;
    uint16_t nLogicalCores;
    uint32_t memoryMB;
    uint32_t storageMB;

    ContainerRuntime() = default;
    ContainerRuntime(uint128_t _uuid, uint16_t _cores, uint32_t _memMB, uint32_t _storMB)
        : uuid(_uuid),
          nLogicalCores(_cores),
          memoryMB(_memMB),
          storageMB(_storMB)
    {}

    void stringify(String& string, uint8_t nTabs) const
    {
      string.appendTabs(nTabs);
      string.snprintf_tab_add<"containerRuntime: cores={itoa} memMB={itoa} storMB={itoa}\n"_ctv>(nTabs, nLogicalCores, memoryMB, storageMB);
    }
  };

  template <typename S>
  friend void serialize(S&& serializer, DeploymentStatusReport::ContainerRuntime& rt);

  // Bitsery serialize for nested ContainerRuntime
  template <typename S>
  static void serialize(S&& serializer, ContainerRuntime& rt)
  {
    serializer.value16b(rt.uuid);
    serializer.value2b(rt.nLogicalCores);
    serializer.value4b(rt.memoryMB);
    serializer.value4b(rt.storageMB);
  }

  Vector<ContainerRuntime> containerRuntimes;

  void stringify(String& string, uint8_t nTabs) const
  {
    string.appendTabs(nTabs);
    string.snprintf_tab_add<"versionID: {itoa}\n"_ctv>(nTabs, versionID);

    string.appendTabs(nTabs);
    string.append("state: "_ctv);

    switch (state)
    {
      case DeploymentState::none:
        {
          string.append("DeploymentState::none\n"_ctv);
          break;
        }
      case DeploymentState::waitingToDeploy:
        {
          string.append("DeploymentState::waitingToDeploy\n"_ctv);
          break;
        }
      case DeploymentState::canaries:
        {
          string.append("DeploymentState::canaries\n"_ctv);
          break;
        }
      case DeploymentState::deploying:
        {
          string.append("DeploymentState::deploying\n"_ctv);
          break;
        }
      case DeploymentState::running:
        {
          string.append("DeploymentState::running\n"_ctv);
          break;
        }
      case DeploymentState::decommissioning:
        {
          string.append("DeploymentState::decommissioning\n"_ctv);
          break;
        }
      case DeploymentState::failed:
        {
          string.append("DeploymentState::failed\n"_ctv);
          break;
        }
    }

    string.snprintf_tab_add<"stateSince: {}\n"_ctv>(nTabs, String::epochMsToDateTime(stateSinceMs));

    string.appendTabs(nTabs);

    if (isStateful)
    {
      string.append("isStateful: true"_ctv);
      string.snprintf_tab_add<"nShardGroups: {itoa}\n"_ctv>(nTabs, nShardGroups);
    }
    else
    {
      string.append("isStateful: false"_ctv);
    }

    string.snprintf_tab_add<"nTarget: {itoa}\n"_ctv>(nTabs, nTarget);
    string.snprintf_tab_add<"nTargetBase: {itoa}\n"_ctv>(nTabs, nTargetBase);
    string.snprintf_tab_add<"nTargetSurge: {itoa}\n"_ctv>(nTabs, nTargetSurge);

    string.snprintf_tab_add<"nDeployed: {itoa}\n"_ctv>(nTabs, nDeployed);
    string.snprintf_tab_add<"nDeployedCanary: {itoa}\n"_ctv>(nTabs, nDeployedCanary);
    string.snprintf_tab_add<"nDeployedBase: {itoa}\n"_ctv>(nTabs, nDeployedBase);
    string.snprintf_tab_add<"nDeployedSurge: {itoa}\n"_ctv>(nTabs, nDeployedSurge);

    string.snprintf_tab_add<"nHealthy: {itoa}\n"_ctv>(nTabs, nHealthy);
    string.snprintf_tab_add<"nHealthyCanary: {itoa}\n"_ctv>(nTabs, nHealthyCanary);
    string.snprintf_tab_add<"nHealthyBase: {itoa}\n"_ctv>(nTabs, nHealthyBase);
    string.snprintf_tab_add<"nHealthySurge: {itoa}\n"_ctv>(nTabs, nHealthySurge);

    string.appendTabs(nTabs);
    string.append("containerRuntimes:\n"_ctv);

    for (const ContainerRuntime& runtime : containerRuntimes)
    {
      runtime.stringify(string, nTabs + 1);
    }

    for (const ScalerState& scalerState : lastScalerStates)
    {
      scalerState.stringify(string, nTabs);
    }

    string.snprintf_tab_add<"nCrashes: {itoa}\n"_ctv>(nTabs, nCrashes);
    if (nTlsIdentityExpected > 0 || nTlsIdentityFresh > 0 || nTlsIdentityStale > 0 || nTlsIdentityPending > 0)
    {
      string.snprintf_tab_add<"tlsIdentities expected={itoa} fresh={itoa} stale={itoa} pending={itoa}\n"_ctv>(
          nTabs,
          nTlsIdentityExpected,
          nTlsIdentityFresh,
          nTlsIdentityStale,
          nTlsIdentityPending);
    }

    for (const FailureReport& report : failureReports)
    {
      report.stringify(string, nTabs);
    }
  }
};

template <typename S>
void serialize(S&& serializer, DeploymentStatusReport::ContainerRuntime& rt)
{
  serializer.value16b(rt.uuid);
  serializer.value2b(rt.nLogicalCores);
  serializer.value4b(rt.memoryMB);
  serializer.value4b(rt.storageMB);
}

template <typename S>
static void serialize(S&& serializer, DeploymentStatusReport& report)
{
  serializer.value8b(report.versionID);

  serializer.value1b(report.state);
  serializer.value8b(report.stateSinceMs);

  serializer.value1b(report.isStateful);
  serializer.value4b(report.nShardGroups);

  serializer.value4b(report.nTarget);
  serializer.value4b(report.nTargetBase);
  serializer.value4b(report.nTargetSurge);

  serializer.value4b(report.nDeployed);
  serializer.value4b(report.nDeployedCanary);
  serializer.value4b(report.nDeployedBase);
  serializer.value4b(report.nDeployedSurge);

  serializer.value4b(report.nHealthy);
  serializer.value4b(report.nHealthyCanary);
  serializer.value4b(report.nHealthyBase);
  serializer.value4b(report.nHealthySurge);

  serializer.value4b(report.nCrashes);
  serializer.value4b(report.nTlsIdentityExpected);
  serializer.value4b(report.nTlsIdentityFresh);
  serializer.value4b(report.nTlsIdentityStale);
  serializer.value4b(report.nTlsIdentityPending);

  serializer.object(report.failureReports);
  serializer.object(report.lastScalerStates);
  serializer.object(report.containerRuntimes);
}

class ApplicationStatusReport {
public:

  uint16_t applicationID;
  String applicationName;
  Vector<DeploymentStatusReport> deploymentReports;

  void stringify(String& string, uint8_t nTabs = 0) const
  {
    string.appendTabs(nTabs);
    if (applicationName.size())
    {
      string.snprintf_tab_add<"Application: {}\n"_ctv>(nTabs, applicationName);
    }
    else if (auto it = MeshRegistry::applicationNameMappings.find(applicationID); it != MeshRegistry::applicationNameMappings.end())
    {
      string.snprintf_tab_add<"Application: {}\n"_ctv>(nTabs, it->second);
    }
    else
    {
      string.snprintf_tab_add<"Application: {itoa}\n"_ctv>(nTabs, applicationID);
    }

    for (const DeploymentStatusReport& dreport : deploymentReports)
    {
      dreport.stringify(string, nTabs + 1);
      string.append("\n");
    }
  }
};

template <typename S>
static void serialize(S&& serializer, ApplicationStatusReport& report)
{
  serializer.value2b(report.applicationID);
  serializer.text1b(report.applicationName, UINT32_MAX);
  serializer.object(report.deploymentReports);
}

static inline bool prodigyReportRenderIPAddressLiteral(const IPAddress& address, String& text)
{
  char buffer[INET6_ADDRSTRLEN] = {};

  if (address.is6)
  {
    if (inet_ntop(AF_INET6, address.v6, buffer, sizeof(buffer)) == nullptr)
    {
      return false;
    }
  }
  else
  {
    if (inet_ntop(AF_INET, &address.v4, buffer, sizeof(buffer)) == nullptr)
    {
      return false;
    }
  }

  text.assign(buffer);
  return true;
}

static inline void prodigyStringifyMachineToolCaptures(const Vector<MachineToolCapture>& captures, String& string, uint8_t nTabs)
{
  for (const MachineToolCapture& capture : captures)
  {
    string.appendTabs(nTabs);
    string.snprintf_add<"tool={} phase={} attempted={itoa} succeeded={itoa} exitCode={itoa}\n"_ctv>(
        capture.tool,
        capture.phase,
        capture.attempted ? 1u : 0u,
        capture.succeeded ? 1u : 0u,
        uint32_t(capture.exitCode >= 0 ? capture.exitCode : 0));

    if (capture.failure.size() > 0)
    {
      string.appendTabs(nTabs + 1);
      string.snprintf_add<"failure={}\n"_ctv>(capture.failure);
    }

    if (capture.command.size() > 0)
    {
      string.appendTabs(nTabs + 1);
      string.snprintf_add<"command={}\n"_ctv>(capture.command);
    }

    if (capture.output.size() > 0)
    {
      string.appendTabs(nTabs + 1);
      string.append("output:\n"_ctv);
      string.appendTabs(nTabs + 2);
      string.append(capture.output);
      if (capture.output[capture.output.size() - 1] != '\n')
      {
        string.append('\n');
      }
    }
  }
}

static inline void prodigyStringifyMachineHardwareProfile(const MachineHardwareProfile& hardware, String& string, uint8_t nTabs)
{
  string.appendTabs(nTabs);
  string.snprintf_add<"collectedAtMs={itoa} inventoryComplete={itoa} benchmarksComplete={itoa}\n"_ctv>(
      uint32_t(hardware.collectedAtMs > 0 ? hardware.collectedAtMs : 0),
      hardware.inventoryComplete ? 1u : 0u,
      hardware.benchmarksComplete ? 1u : 0u);

  string.appendTabs(nTabs);
  string.snprintf_add<"cpu: model={} vendor={} arch={} logicalCores={itoa} physicalCores={itoa} sockets={itoa} numaNodes={itoa} threadsPerCore={itoa} l3CacheMB={itoa} singleThreadScore={itoa} multiThreadScore={itoa}\n"_ctv>(
      hardware.cpu.model,
      hardware.cpu.vendor,
      hardware.cpu.architectureVersion,
      hardware.cpu.logicalCores,
      hardware.cpu.physicalCores,
      hardware.cpu.sockets,
      hardware.cpu.numaNodes,
      hardware.cpu.threadsPerCore,
      hardware.cpu.l3CacheMB,
      uint32_t(hardware.cpu.singleThreadScore > UINT32_MAX ? UINT32_MAX : hardware.cpu.singleThreadScore),
      uint32_t(hardware.cpu.multiThreadScore > UINT32_MAX ? UINT32_MAX : hardware.cpu.multiThreadScore));
  if (hardware.cpu.isaFeatures.empty() == false)
  {
    string.appendTabs(nTabs + 1);
    string.append("isaFeatures="_ctv);
    for (uint32_t i = 0; i < hardware.cpu.isaFeatures.size(); ++i)
    {
      if (i != 0)
      {
        string.append(","_ctv);
      }
      string.append(hardware.cpu.isaFeatures[i]);
    }
    string.append('\n');
  }
  prodigyStringifyMachineToolCaptures(hardware.cpu.captures, string, nTabs + 1);

  string.appendTabs(nTabs);
  string.snprintf_add<"memory: totalMB={itoa} latencyNs={itoa} readBandwidthMBps={itoa} writeBandwidthMBps={itoa}\n"_ctv>(
      hardware.memory.totalMB,
      hardware.memory.latencyNs,
      hardware.memory.readBandwidthMBps,
      hardware.memory.writeBandwidthMBps);
  for (const MachineMemoryModuleHardwareProfile& module : hardware.memory.modules)
  {
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"module locator={} sizeMB={itoa} speedMTps={itoa} manufacturer={} partNumber={}\n"_ctv>(
        module.locator,
        module.sizeMB,
        module.speedMTps,
        module.manufacturer,
        module.partNumber);
  }
  prodigyStringifyMachineToolCaptures(hardware.memory.captures, string, nTabs + 1);

  string.appendTabs(nTabs);
  string.snprintf_add<"disks={itoa}\n"_ctv>(uint32_t(hardware.disks.size()));
  for (const MachineDiskHardwareProfile& disk : hardware.disks)
  {
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"disk name={} path={} model={} sizeMB={itoa} mountPath={} pcieLink={}\n"_ctv>(
        disk.name,
        disk.path,
        disk.model,
        uint32_t(disk.sizeMB > UINT32_MAX ? UINT32_MAX : disk.sizeMB),
        disk.mountPath,
        disk.pcieLink);
    string.appendTabs(nTabs + 2);
    string.snprintf_add<"benchmark seqReadMBps={itoa} seqWriteMBps={itoa} randReadIops={itoa} randWriteIops={itoa} randReadP99Us={itoa} randWriteP99Us={itoa}\n"_ctv>(
        disk.benchmark.sequentialReadMBps,
        disk.benchmark.sequentialWriteMBps,
        disk.benchmark.randomReadIops,
        disk.benchmark.randomWriteIops,
        disk.benchmark.randomReadLatencyP99Us,
        disk.benchmark.randomWriteLatencyP99Us);
    prodigyStringifyMachineToolCaptures(disk.captures, string, nTabs + 2);
    prodigyStringifyMachineToolCaptures(disk.benchmark.captures, string, nTabs + 2);
  }

  string.appendTabs(nTabs);
  String internetSourceAddress = {};
  if (hardware.network.internet.sourceAddress.isNull() == false)
  {
    (void)ClusterMachine::renderIPAddressLiteral(hardware.network.internet.sourceAddress, internetSourceAddress);
  }
  string.snprintf_add<"internet latencyMs={itoa} downloadMbps={itoa} uploadMbps={itoa} server={} interface={} source={}\n"_ctv>(
      hardware.network.internet.latencyMs,
      hardware.network.internet.downloadMbps,
      hardware.network.internet.uploadMbps,
      hardware.network.internet.serverName,
      hardware.network.internet.interfaceName,
      internetSourceAddress);
  prodigyStringifyMachineToolCaptures(hardware.network.captures, string, nTabs + 1);
  prodigyStringifyMachineToolCaptures(hardware.network.internet.captures, string, nTabs + 1);
  for (const MachineNicHardwareProfile& nic : hardware.network.nics)
  {
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"nic name={} driver={} model={} mac={} busAddress={} linkSpeedMbps={itoa} up={itoa}\n"_ctv>(
        nic.name,
        nic.driver,
        nic.model,
        nic.mac,
        nic.busAddress,
        nic.linkSpeedMbps,
        nic.up ? 1u : 0u);
    for (const MachineNicSubnetHardwareProfile& subnet : nic.subnets)
    {
      String addressText = {};
      String networkText = {};
      String gatewayText = {};
      (void)prodigyReportRenderIPAddressLiteral(subnet.address, addressText);
      (void)prodigyReportRenderIPAddressLiteral(subnet.subnet.network, networkText);
      (void)prodigyReportRenderIPAddressLiteral(subnet.gateway, gatewayText);
      string.appendTabs(nTabs + 2);
      string.snprintf_add<"subnet address={} network={}/{} gateway={} internetReachable={itoa}\n"_ctv>(
          addressText,
          networkText,
          subnet.subnet.cidr,
          gatewayText,
          subnet.internetReachable ? 1u : 0u);
    }
    prodigyStringifyMachineToolCaptures(nic.captures, string, nTabs + 2);
  }

  string.appendTabs(nTabs);
  string.snprintf_add<"gpus={itoa}\n"_ctv>(uint32_t(hardware.gpus.size()));
  for (const MachineGpuHardwareProfile& gpu : hardware.gpus)
  {
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"gpu vendor={} model={} busAddress={} memoryMB={itoa}\n"_ctv>(
        gpu.vendor,
        gpu.model,
        gpu.busAddress,
        gpu.memoryMB);
    prodigyStringifyMachineToolCaptures(gpu.captures, string, nTabs + 2);
  }

  if (hardware.captures.empty() == false)
  {
    string.appendTabs(nTabs);
    string.append("globalCaptures:\n"_ctv);
    prodigyStringifyMachineToolCaptures(hardware.captures, string, nTabs + 1);
  }
}

static inline void prodigyAppendCommaSeparatedTextList(const Vector<String>& values, String& string)
{
  for (uint32_t index = 0; index < values.size(); ++index)
  {
    if (index != 0)
    {
      string.append(","_ctv);
    }

    string.append(values[index]);
  }
}

static inline void prodigyAppendClusterMachineAddressSummary(const ClusterMachineAddress& value, String& string)
{
  string.append(value.address);

  if (value.cidr > 0)
  {
    String cidrText = {};
    cidrText.snprintf<"/{itoa}"_ctv>(unsigned(value.cidr));
    string.append(cidrText);
  }

  if (value.gateway.size() > 0)
  {
    string.append(" via "_ctv);
    string.append(value.gateway);
  }
}

static inline void prodigyAppendCommaSeparatedClusterMachineAddressList(const Vector<ClusterMachineAddress>& values, String& string)
{
  for (uint32_t index = 0; index < values.size(); ++index)
  {
    if (index != 0)
    {
      string.append(","_ctv);
    }

    prodigyAppendClusterMachineAddressSummary(values[index], string);
  }
}

class MachineStatusReport {
public:

  String state;
  bool isBrain = false;
  bool controlPlaneReachable = false;
  bool runtimeReady = false;
  bool currentMaster = false;
  bool decommissioning = false;
  bool rebooting = false;
  bool updatingOS = false;
  bool hardwareFailure = false;
  int64_t bootTimeMs = 0;
  int64_t uptimeMs = 0;
  String machineUUID;
  String source;
  String backing;
  String lifetime;
  String provider;
  String region;
  String zone;
  uint32_t rackUUID = 0;
  bool hasCloud = false;
  ClusterMachineCloud cloud;
  ClusterMachineSSH ssh;
  ClusterMachineAddresses addresses;
  uint32_t totalLogicalCores = 0;
  uint32_t totalMemoryMB = 0;
  uint32_t totalStorageMB = 0;
  uint32_t ownedLogicalCores = 0;
  uint32_t ownedMemoryMB = 0;
  uint32_t ownedStorageMB = 0;
  Vector<String> deployedContainers;
  Vector<String> applicationNames;
  Vector<String> deploymentIDs;
  Vector<String> shardGroups;
  uint32_t activeContainers = 0;
  uint32_t reservedContainers = 0;
  uint32_t activeIsolatedLogicalCores = 0;
  uint32_t reservedIsolatedLogicalCores = 0;
  uint32_t activeSharedCPUMillis = 0;
  uint32_t reservedSharedCPUMillis = 0;
  uint32_t activeMemoryMB = 0;
  uint32_t reservedMemoryMB = 0;
  uint32_t activeStorageMB = 0;
  uint32_t reservedStorageMB = 0;
  String runningProdigyVersion;
  String approvedBundleSHA256;
  String updateStage;
  String stagedBundleSHA256;
  MachineHardwareProfile hardware;

  void stringify(String& string, uint8_t nTabs = 0) const
  {
    String roleText = {};
    if (isBrain)
    {
      roleText.assign("brain"_ctv);
    }
    else
    {
      roleText.assign("worker"_ctv);
    }

    string.appendTabs(nTabs);
    String privateAddressesText = {};
    String publicAddressesText = {};
    prodigyAppendCommaSeparatedClusterMachineAddressList(addresses.privateAddresses, privateAddressesText);
    prodigyAppendCommaSeparatedClusterMachineAddressList(addresses.publicAddresses, publicAddressesText);
    if (cloudPresent())
    {
      string.snprintf_add<"Machine: state={} role={} cloudSchema={} providerMachineType={} cloudID={} publicAddresses={} privateAddresses={}\n"_ctv>(
          state,
          roleText,
          cloud.schema,
          cloud.providerMachineType,
          cloud.cloudID,
          publicAddressesText,
          privateAddressesText);
    }
    else
    {
      string.snprintf_add<"Machine: state={} role={} publicAddresses={} privateAddresses={}\n"_ctv>(
          state,
          roleText,
          publicAddressesText,
          privateAddressesText);
    }
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"identity uuid={} source={} backing={} lifetime={} provider={} region={} zone={} rackUUID={itoa} sshAddress={} sshPort={itoa}\n"_ctv>(
        machineUUID,
        source,
        backing,
        lifetime,
        provider,
        region,
        zone,
        rackUUID,
        ssh.address,
        unsigned(ssh.port));
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"lifecycle controlPlaneReachable={itoa} runtimeReady={itoa} currentMaster={itoa} decommissioning={itoa} rebooting={itoa} updatingOS={itoa} hardwareFailure={itoa} bootTimeMs={itoa} uptimeMs={itoa}\n"_ctv>(
        controlPlaneReachable ? 1u : 0u,
        runtimeReady ? 1u : 0u,
        currentMaster ? 1u : 0u,
        decommissioning ? 1u : 0u,
        rebooting ? 1u : 0u,
        updatingOS ? 1u : 0u,
        hardwareFailure ? 1u : 0u,
        uint64_t(bootTimeMs > 0 ? bootTimeMs : 0),
        uint64_t(uptimeMs > 0 ? uptimeMs : 0));
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"owned logicalCores={itoa}/{itoa} memoryMB={itoa}/{itoa} storageMB={itoa}/{itoa}\n"_ctv>(
        ownedLogicalCores,
        totalLogicalCores,
        ownedMemoryMB,
        totalMemoryMB,
        ownedStorageMB,
        totalStorageMB);
    string.appendTabs(nTabs + 1);
    string.append("placement containers="_ctv);
    prodigyAppendCommaSeparatedTextList(deployedContainers, string);
    string.append(" applications="_ctv);
    prodigyAppendCommaSeparatedTextList(applicationNames, string);
    string.append(" deploymentIDs="_ctv);
    prodigyAppendCommaSeparatedTextList(deploymentIDs, string);
    string.append(" shardGroups="_ctv);
    prodigyAppendCommaSeparatedTextList(shardGroups, string);
    string.append('\n');
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"capacity active containers={itoa} isolatedLogicalCores={itoa} sharedCPUMillis={itoa} memoryMB={itoa} storageMB={itoa} reserved containers={itoa} isolatedLogicalCores={itoa} sharedCPUMillis={itoa} memoryMB={itoa} storageMB={itoa}\n"_ctv>(
        activeContainers,
        activeIsolatedLogicalCores,
        activeSharedCPUMillis,
        activeMemoryMB,
        activeStorageMB,
        reservedContainers,
        reservedIsolatedLogicalCores,
        reservedSharedCPUMillis,
        reservedMemoryMB,
        reservedStorageMB);
    string.appendTabs(nTabs + 1);
    string.snprintf_add<"maintenance runningProdigyVersion={} approvedBundleSHA256={} updateStage={} stagedBundleSHA256={}\n"_ctv>(
        runningProdigyVersion,
        approvedBundleSHA256,
        updateStage,
        stagedBundleSHA256);
    prodigyStringifyMachineHardwareProfile(hardware, string, nTabs + 1);
  }

  bool cloudPresent(void) const
  {
    return hasCloud || cloud.schema.size() > 0 || cloud.providerMachineType.size() > 0 || cloud.cloudID.size() > 0;
  }
};

template <typename S>
static void serialize(S&& serializer, MachineStatusReport& report)
{
  serializer.text1b(report.state, UINT32_MAX);
  serializer.value1b(report.isBrain);
  serializer.value1b(report.controlPlaneReachable);
  serializer.value1b(report.runtimeReady);
  serializer.value1b(report.currentMaster);
  serializer.value1b(report.decommissioning);
  serializer.value1b(report.rebooting);
  serializer.value1b(report.updatingOS);
  serializer.value1b(report.hardwareFailure);
  serializer.value8b(report.bootTimeMs);
  serializer.value8b(report.uptimeMs);
  serializer.text1b(report.machineUUID, UINT32_MAX);
  serializer.text1b(report.source, UINT32_MAX);
  serializer.text1b(report.backing, UINT32_MAX);
  serializer.text1b(report.lifetime, UINT32_MAX);
  serializer.text1b(report.provider, UINT32_MAX);
  serializer.text1b(report.region, UINT32_MAX);
  serializer.text1b(report.zone, UINT32_MAX);
  serializer.value4b(report.rackUUID);
  bool hasCloud = report.cloudPresent();
  serializer.value1b(hasCloud);
  report.hasCloud = hasCloud;
  if (hasCloud)
  {
    serializer.object(report.cloud);
  }
  else
  {
    report.cloud = {};
  }
  serializer.object(report.ssh);
  serializer.object(report.addresses);
  serializer.value4b(report.totalLogicalCores);
  serializer.value4b(report.totalMemoryMB);
  serializer.value4b(report.totalStorageMB);
  serializer.value4b(report.ownedLogicalCores);
  serializer.value4b(report.ownedMemoryMB);
  serializer.value4b(report.ownedStorageMB);
  serializer.container(report.deployedContainers, UINT32_MAX, [](S& serializer, String& value) {
    serializer.text1b(value, UINT32_MAX);
  });
  serializer.container(report.applicationNames, UINT32_MAX, [](S& serializer, String& value) {
    serializer.text1b(value, UINT32_MAX);
  });
  serializer.container(report.deploymentIDs, UINT32_MAX, [](S& serializer, String& value) {
    serializer.text1b(value, UINT32_MAX);
  });
  serializer.container(report.shardGroups, UINT32_MAX, [](S& serializer, String& value) {
    serializer.text1b(value, UINT32_MAX);
  });
  serializer.value4b(report.activeContainers);
  serializer.value4b(report.reservedContainers);
  serializer.value4b(report.activeIsolatedLogicalCores);
  serializer.value4b(report.reservedIsolatedLogicalCores);
  serializer.value4b(report.activeSharedCPUMillis);
  serializer.value4b(report.reservedSharedCPUMillis);
  serializer.value4b(report.activeMemoryMB);
  serializer.value4b(report.reservedMemoryMB);
  serializer.value4b(report.activeStorageMB);
  serializer.value4b(report.reservedStorageMB);
  serializer.text1b(report.runningProdigyVersion, UINT32_MAX);
  serializer.text1b(report.approvedBundleSHA256, UINT32_MAX);
  serializer.text1b(report.updateStage, UINT32_MAX);
  serializer.text1b(report.stagedBundleSHA256, UINT32_MAX);
  serializer.object(report.hardware);
}

struct MothershipConnectivityStatusReport {
  String kind;
  TunnelProviderPhase tunnelProviderPhase = TunnelProviderPhase::disabled;
  String lastFailure;

  void stringify(String& string) const
  {
    if (kind.size() > 0)
    {
      string.snprintf_add<"mothershipConnectivity kind={} phase={} lastFailure={}\n"_ctv>(kind, String(tunnelProviderPhaseName(tunnelProviderPhase)), lastFailure);
    }
  }
};

template <typename S>
static void serialize(S&& serializer, MothershipConnectivityStatusReport& report)
{
  serializer.text1b(report.kind, UINT32_MAX);
  serializer.value1b(report.tunnelProviderPhase);
  serializer.text1b(report.lastFailure, UINT32_MAX);
}

class ClusterStatusReport {
public:

  bool hasTopology = false;
  ClusterTopology topology;
  uint32_t nMachines;
  uint32_t nSpotMachines;

  uint32_t nApplications;
  Vector<MachineStatusReport> machineReports;
  Vector<ApplicationStatusReport> applicationReports;
  MothershipConnectivityStatusReport mothershipConnectivity;

  void stringify(String& string) const
  {
    string.snprintf_add<"hasTopology: {itoa}\n"_ctv>(hasTopology ? 1u : 0u);
    if (hasTopology)
    {
      string.snprintf_add<"topologyVersion: {itoa}\n"_ctv>(topology.version);
      string.snprintf_add<"topologyMachines: {itoa}\n"_ctv>(uint32_t(topology.machines.size()));
    }
    string.snprintf_add<"nMachines: {itoa}\n"_ctv>(nMachines);
    string.snprintf_add<"nSpotMachines: {itoa}\n"_ctv>(nSpotMachines);
    string.snprintf_add<"nApplications: {itoa}\n"_ctv>(nApplications);
    mothershipConnectivity.stringify(string);

    for (const MachineStatusReport& mreport : machineReports)
    {
      mreport.stringify(string, 1);
    }

    for (const ApplicationStatusReport& areport : applicationReports)
    {
      areport.stringify(string, 1);
    }
  }
};

template <typename S>
static void serialize(S&& serializer, ClusterStatusReport& report)
{
  serializer.value1b(report.hasTopology);
  serializer.object(report.topology);
  serializer.value4b(report.nMachines);
  serializer.value4b(report.nSpotMachines);
  serializer.value4b(report.nApplications);
  serializer.object(report.machineReports);
  serializer.object(report.applicationReports);
  serializer.object(report.mothershipConnectivity);
}

static inline void prodigyStripMachineHardwareCapturesForClusterReport(MachineHardwareProfile& hardware)
{
  hardware.captures.clear();
  hardware.cpu.captures.clear();
  hardware.memory.captures.clear();

  for (MachineDiskHardwareProfile& disk : hardware.disks)
  {
    disk.captures.clear();
    disk.benchmark.captures.clear();
  }

  hardware.network.captures.clear();
  hardware.network.internet.captures.clear();
  for (MachineNicHardwareProfile& nic : hardware.network.nics)
  {
    nic.captures.clear();
  }

  for (MachineGpuHardwareProfile& gpu : hardware.gpus)
  {
    gpu.captures.clear();
  }
}

static inline void prodigyStripMachineHardwareCapturesFromClusterTopology(ClusterTopology& topology)
{
  for (ClusterMachine& machine : topology.machines)
  {
    prodigyStripMachineHardwareCapturesForClusterReport(machine.hardware);
  }
}

static inline void prodigyPrepareClusterStatusReportForTransport(ClusterStatusReport& report)
{
  prodigyStripMachineHardwareCapturesFromClusterTopology(report.topology);

  for (MachineStatusReport& machine : report.machineReports)
  {
    prodigyStripMachineHardwareCapturesForClusterReport(machine.hardware);
  }
}

class ServiceUserCapacity {
public:

  uint32_t minimum = 0; // normal planned user capacity; services may exceed this under overload
  uint32_t maximum = 0; // hard cap when nonzero
};

template <typename S>
static void serialize(S&& serializer, ServiceUserCapacity& capacity)
{
  serializer.value4b(capacity.minimum);
  serializer.value4b(capacity.maximum);
}

static inline uint32_t serviceUserCapacityPlanningWeight(const ServiceUserCapacity& capacity)
{
  if (capacity.minimum > 0)
  {
    return capacity.minimum;
  }

  if (capacity.maximum > 0)
  {
    return capacity.maximum;
  }

  return 1;
}

class WormholeDNSConfig {
public:

  String provider;
  String credentialName;
  String zone;
  String name;
  String bindingName;
  String type;
  uint32_t ttl = 0;
  bool allowSingleMachine = false;
};

template <typename S>
static void serialize(S&& serializer, WormholeDNSConfig& config)
{
  serializer.text1b(config.provider, UINT32_MAX);
  serializer.text1b(config.credentialName, UINT32_MAX);
  serializer.text1b(config.zone, UINT32_MAX);
  serializer.text1b(config.name, UINT32_MAX);
  serializer.text1b(config.bindingName, UINT32_MAX);
  serializer.text1b(config.type, UINT32_MAX);
  serializer.value4b(config.ttl);
  serializer.value1b(config.allowSingleMachine);
}

constexpr static uint16_t prodigyDefaultCertificateRenewAfterLifetimePermille = 667;

static inline bool prodigySafePathSegment(const String& value)
{
  if (value.size() == 0 || value.equal("."_ctv) || value.equal(".."_ctv))
  {
    return false;
  }
  for (uint64_t index = 0; index < value.size(); index += 1)
  {
    const unsigned char c = static_cast<unsigned char>(value[index]);
    if (std::isalnum(c) == false && c != '_' && c != '-' && c != '.')
    {
      return false;
    }
  }
  return true;
}

class WormholePublicTLSConfig {
public:

  String wormholeName;
  String identityName;
  Vector<String> domains;
  String issuer;
  String keyType;
  bool staging = false;
  uint16_t renewAfterLifetimePermille = prodigyDefaultCertificateRenewAfterLifetimePermille;

  WormholePublicTLSConfig()
  {
    issuer.assign("letsencrypt"_ctv);
    keyType.assign("ecdsa"_ctv);
  }
};

template <typename S>
static void serialize(S&& serializer, WormholePublicTLSConfig& config)
{
  serializer.text1b(config.wormholeName, UINT32_MAX);
  serializer.text1b(config.identityName, UINT32_MAX);
  serializer.container(config.domains, UINT32_MAX, [](S& serializer, String& domain) {
    serializer.text1b(domain, UINT32_MAX);
  });
  serializer.text1b(config.issuer, UINT32_MAX);
  serializer.text1b(config.keyType, UINT32_MAX);
  serializer.value1b(config.staging);
  serializer.value2b(config.renewAfterLifetimePermille);
}

static inline bool normalizeDNSRecordType(String& type)
{
  String normalized = {};
  for (uint32_t index = 0; index < type.size(); ++index)
  {
    normalized.append(char(std::toupper(static_cast<unsigned char>(type[index]))));
  }
  type = std::move(normalized);

  return type.equal("A"_ctv) || type.equal("AAAA"_ctv) || type.equal("CNAME"_ctv) || type.equal("TXT"_ctv);
}

struct Wormhole {

  String name;
  IPAddress externalAddress; // will include whether ipv6 or not
  IPAddress deliveryAddress;
  uint16_t externalPort;
  uint16_t containerPort;
  uint8_t layer4; // tcp or udp
  bool isQuic; // if udp, is this quic
  ServiceUserCapacity userCapacity;
  bool hasQuicCidKeyState = false;
  ExternalAddressSource source = ExternalAddressSource::distributableSubnet;
  uint128_t routablePrefixUUID = 0;
  bool hasTlsResumptionConfig = false;
  TlsResumptionWormholeConfig tlsResumption;
  bool hasDNSConfig = false;
  WormholeDNSConfig dns;
  class QuicCidKeyState {
  public:

    uint32_t rotationHours = 24;
    uint8_t activeKeyIndex = 0;
    int64_t rotatedAtMs = 0;
    uint128_t keyMaterialByIndex[2] = {};
  } quicCidKeyState;
};

template <typename S>
static void serialize(S&& serializer, Wormhole::QuicCidKeyState& state)
{
  serializer.value4b(state.rotationHours);
  serializer.value1b(state.activeKeyIndex);
  serializer.value8b(state.rotatedAtMs);
  serializer.value16b(state.keyMaterialByIndex[0]);
  serializer.value16b(state.keyMaterialByIndex[1]);
}

template <typename S>
static void serialize(S&& serializer, Wormhole& wormhole)
{
  serializer.text1b(wormhole.name, UINT32_MAX);
  serializer.object(wormhole.externalAddress);
  serializer.object(wormhole.deliveryAddress);
  serializer.value2b(wormhole.externalPort);
  serializer.value2b(wormhole.containerPort);
  serializer.value1b(wormhole.layer4);
  serializer.value1b(wormhole.isQuic);
  serializer.object(wormhole.userCapacity);
  serializer.value1b(wormhole.hasQuicCidKeyState);
  serializer.value1b(wormhole.source);
  serializer.value16b(wormhole.routablePrefixUUID);
  serializer.value1b(wormhole.hasTlsResumptionConfig);
  serializer.object(wormhole.tlsResumption);
  serializer.value1b(wormhole.hasDNSConfig);
  serializer.object(wormhole.dns);
  serializer.object(wormhole.quicCidKeyState);
}

static inline bool wormholeDNSRecordType(const Wormhole& wormhole, String& type, String *failure = nullptr)
{
  type = wormhole.dns.type;
  if (type.size() == 0)
  {
    if (wormhole.externalAddress.is6)
    {
      type.assign("AAAA"_ctv);
    }
    else
    {
      type.assign("A"_ctv);
    }
  }
  if (normalizeDNSRecordType(type) == false)
  {
    if (failure)
    {
      failure->assign("wormhole DNS record type must be A, AAAA, CNAME, or TXT"_ctv);
    }
    return false;
  }
  if ((type.equal("A"_ctv) && wormhole.externalAddress.is6) || (type.equal("AAAA"_ctv) && wormhole.externalAddress.is6 == false) || type.equal("CNAME"_ctv) || type.equal("TXT"_ctv))
  {
    if (failure)
    {
      failure->assign("wormhole DNS record type must match the claimed address family"_ctv);
    }
    return false;
  }
  return true;
}

static inline bool wormholeUsesQuicCidEncryption(const Wormhole& wormhole)
{
  return wormhole.isQuic && wormhole.layer4 == IPPROTO_UDP;
}

static inline bool wormholeSupportsTlsResumption(const Wormhole& wormhole)
{
  return wormhole.layer4 == IPPROTO_TCP ||
         (wormhole.layer4 == IPPROTO_UDP && wormhole.isQuic);
}

static inline uint8_t wormholeQuicCidInactiveKeyIndex(const Wormhole::QuicCidKeyState& state)
{
  return (state.activeKeyIndex == 0) ? 1 : 0;
}

static inline void wormholeQuicCidExtractKeyBytes(uint128_t keyMaterial, uint8_t key[16])
{
  if (key == nullptr)
  {
    return;
  }

  memcpy(key, &keyMaterial, 16);
}

static inline void wormholeQuicCidStoreKeyBytes(uint128_t& keyMaterial, const uint8_t key[16])
{
  if (key == nullptr)
  {
    keyMaterial = 0;
    return;
  }

  memcpy(&keyMaterial, key, 16);
}

static inline uint8_t wormholeQuicCidKeyMaterialPhase(uint128_t keyMaterial)
{
  uint8_t key[16] = {};
  wormholeQuicCidExtractKeyBytes(keyMaterial, key);
  return prodigyBiphasalKeyPhase(key);
}

static inline bool wormholeQuicCidForceKeyMaterialPhase(uint128_t& keyMaterial, uint8_t phase)
{
  uint8_t key[16] = {};
  wormholeQuicCidExtractKeyBytes(keyMaterial, key);
  uint8_t before = prodigyBiphasalKeyPhase(key);
  prodigyForceBiphasalKeyPhase(key, phase);
  wormholeQuicCidStoreKeyBytes(keyMaterial, key);
  return before != (phase & 0x01u);
}

static inline bool distributableExternalSubnetMatchesFamily(const DistributableExternalSubnet& subnet, ExternalAddressFamily family)
{
  return subnet.subnet.network.is6 == (family == ExternalAddressFamily::ipv6);
}

static inline bool distributableExternalSubnetContainsAddress(const DistributableExternalSubnet& subnet, const IPAddress& address)
{
  return subnet.subnet.network.is6 == address.is6 && subnet.subnet.containsAddress(address);
}

static inline const IPPrefix& distributableExternalSubnetSwitchboardSubnet(const DistributableExternalSubnet& subnet)
{
  return subnet.deliverySubnet.network.isNull() ? subnet.subnet : subnet.deliverySubnet;
}

static inline const IPAddress& wormholeSwitchboardAddress(const Wormhole& wormhole)
{
  return wormhole.deliveryAddress.isNull() ? wormhole.externalAddress : wormhole.deliveryAddress;
}

static inline bool distributableExternalSubnetIsHostPrefix(const DistributableExternalSubnet& subnet)
{
  return subnet.subnet.cidr == (subnet.subnet.network.is6 ? 128 : 32);
}

static inline bool ipPrefixesOverlap(const IPPrefix& lhs, const IPPrefix& rhs)
{
  if (lhs.network.is6 != rhs.network.is6)
  {
    return false;
  }

  uint8_t maxCidr = lhs.network.is6 ? 128 : 32;
  if (lhs.cidr > maxCidr || rhs.cidr > maxCidr)
  {
    return false;
  }

  IPPrefix a = lhs.canonicalized();
  IPPrefix b = rhs.canonicalized();
  return a.containsAddress(b.network) || b.containsAddress(a.network);
}

static inline uint8_t distributableExternalSubnetRequiredHostBits(ExternalAddressFamily family)
{
  if (family == ExternalAddressFamily::ipv6)
  {
    return 40;
  }

  return 16;
}

static inline bool routableExternalSubnetHasSupportedBreadth(const DistributableExternalSubnet& subnet)
{
  return subnet.subnet.cidr <= (subnet.subnet.network.is6 ? 128 : 32);
}

static inline bool distributableExternalSubnetCanAllocateAddresses(const DistributableExternalSubnet& subnet)
{
  return subnet.subnet.hostBits() >= distributableExternalSubnetRequiredHostBits(
                                         subnet.subnet.network.is6 ? ExternalAddressFamily::ipv6 : ExternalAddressFamily::ipv4);
}

static inline bool distributableExternalSubnetAllowsWormholes(const DistributableExternalSubnet& subnet)
{
  return subnet.usage == ExternalSubnetUsage::wormholes || subnet.usage == ExternalSubnetUsage::both;
}

static inline bool distributableExternalSubnetAllowsWhiteholes(const DistributableExternalSubnet& subnet)
{
  return subnet.usage == ExternalSubnetUsage::whiteholes || subnet.usage == ExternalSubnetUsage::both;
}

static inline bool externalSubnetUsageIsValid(ExternalSubnetUsage usage)
{
  return usage == ExternalSubnetUsage::wormholes || usage == ExternalSubnetUsage::whiteholes || usage == ExternalSubnetUsage::both;
}

static inline bool routableIngressScopeIsValid(RoutableIngressScope scope)
{
  return scope == RoutableIngressScope::switchboardFleet || scope == RoutableIngressScope::singleMachine;
}

static inline bool routablePrefixKindIsValid(RoutablePrefixKind kind)
{
  return kind == RoutablePrefixKind::BGP || kind == RoutablePrefixKind::elastic;
}

static inline bool elasticPrefixIntentIsValid(ElasticPrefixIntent intent)
{
  return intent == ElasticPrefixIntent::any || intent == ElasticPrefixIntent::create || intent == ElasticPrefixIntent::anyOrCreate;
}

class TlsIdentity {
public:

  String name;
  uint64_t generation = 0;
  int64_t notBeforeMs = 0;
  int64_t notAfterMs = 0;
  String certPem;
  String keyPem;
  String chainPem;
  Vector<String> dnsSans;
  Vector<IPAddress> ipSans;
  Vector<String> tags;
};

template <typename S>
static void serialize(S&& serializer, TlsIdentity& identity)
{
  serializer.text1b(identity.name, UINT32_MAX);
  serializer.value8b(identity.generation);
  serializer.value8b(identity.notBeforeMs);
  serializer.value8b(identity.notAfterMs);
  serializer.text1b(identity.certPem, UINT32_MAX);
  serializer.text1b(identity.keyPem, UINT32_MAX);
  serializer.text1b(identity.chainPem, UINT32_MAX);

  serializer.container(identity.dnsSans, UINT32_MAX, [](S& serializer, String& san) {
    serializer.text1b(san, UINT32_MAX);
  });
  serializer.object(identity.ipSans);
  serializer.container(identity.tags, UINT32_MAX, [](S& serializer, String& tag) {
    serializer.text1b(tag, UINT32_MAX);
  });
}

static inline bool prodigyStringVectorsEqual(const Vector<String>& lhs, const Vector<String>& rhs)
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

static inline bool prodigyIPVectorsEqual(const Vector<IPAddress>& lhs, const Vector<IPAddress>& rhs)
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

static inline bool prodigyTlsIdentitiesEqual(const TlsIdentity& lhs, const TlsIdentity& rhs)
{
  return lhs.name.equals(rhs.name) &&
         lhs.generation == rhs.generation &&
         lhs.notBeforeMs == rhs.notBeforeMs &&
         lhs.notAfterMs == rhs.notAfterMs &&
         lhs.certPem.equals(rhs.certPem) &&
         lhs.keyPem.equals(rhs.keyPem) &&
         lhs.chainPem.equals(rhs.chainPem) &&
         prodigyStringVectorsEqual(lhs.dnsSans, rhs.dnsSans) &&
         prodigyIPVectorsEqual(lhs.ipSans, rhs.ipSans) &&
         prodigyStringVectorsEqual(lhs.tags, rhs.tags);
}

class CredentialBundle {
public:

  Vector<TlsIdentity> tlsIdentities;
  Vector<ApiCredential> apiCredentials;
  Vector<TlsResumptionSnapshot> tlsResumptionSnapshots;
  uint64_t bundleGeneration = 0;
};

template <typename S>
static void serialize(S&& serializer, CredentialBundle& bundle)
{
  serializer.object(bundle.tlsIdentities);
  serializer.object(bundle.apiCredentials);
  serializer.object(bundle.tlsResumptionSnapshots);
  serializer.value8b(bundle.bundleGeneration);
}

class CredentialDelta {
public:

  uint64_t bundleGeneration = 0;
  Vector<TlsIdentity> updatedTls;
  Vector<String> removedTlsNames;
  Vector<ApiCredential> updatedApi;
  Vector<String> removedApiNames;
  Vector<TlsResumptionSnapshot> updatedResumptionSnapshots;
  Vector<String> removedResumptionWormholeNames;
  String reason;
};

template <typename S>
static void serialize(S&& serializer, CredentialDelta& delta)
{
  serializer.value8b(delta.bundleGeneration);
  serializer.object(delta.updatedTls);
  serializer.container(delta.removedTlsNames, UINT32_MAX, [](S& serializer, String& name) {
    serializer.text1b(name, UINT32_MAX);
  });
  serializer.object(delta.updatedApi);
  serializer.container(delta.removedApiNames, UINT32_MAX, [](S& serializer, String& name) {
    serializer.text1b(name, UINT32_MAX);
  });
  serializer.object(delta.updatedResumptionSnapshots);
  serializer.container(delta.removedResumptionWormholeNames, UINT32_MAX, [](S& serializer, String& name) {
    serializer.text1b(name, UINT32_MAX);
  });
  serializer.text1b(delta.reason, UINT32_MAX);
}

class TlsResumptionApplyAck {
public:

  Vector<TlsResumptionApplyResult> results;
};

template <typename S>
static void serialize(S&& serializer, TlsResumptionApplyAck& ack)
{
  serializer.object(ack.results);
}

class TlsIdentityApplyResult {
public:

  String identityName;
  uint64_t generation = 0;
  bool success = false;
  String failureReason;
};

template <typename S>
static void serialize(S&& serializer, TlsIdentityApplyResult& result)
{
  serializer.text1b(result.identityName, UINT32_MAX);
  serializer.value8b(result.generation);
  serializer.value1b(result.success);
  serializer.text1b(result.failureReason, UINT32_MAX);
}

class CredentialApplyAck {
public:

  Vector<TlsIdentityApplyResult> tlsResults;
  Vector<TlsResumptionApplyResult> resumptionResults;
};

template <typename S>
static void serialize(S&& serializer, CredentialApplyAck& ack)
{
  serializer.object(ack.tlsResults);
  serializer.object(ack.resumptionResults);
}

static void applyCredentialDelta(CredentialBundle& bundle, const CredentialDelta& delta)
{
  auto eraseTlsByName = [&](const String& name) {
    for (auto it = bundle.tlsIdentities.begin(); it != bundle.tlsIdentities.end();)
    {
      if (it->name.equal(name))
      {
        it = bundle.tlsIdentities.erase(it);
      }
      else
      {
        ++it;
      }
    }
  };

  auto eraseApiByName = [&](const String& name) {
    for (auto it = bundle.apiCredentials.begin(); it != bundle.apiCredentials.end();)
    {
      if (it->name.equal(name))
      {
        it = bundle.apiCredentials.erase(it);
      }
      else
      {
        ++it;
      }
    }
  };

  auto eraseResumptionByWormholeName = [&](const String& wormholeName) {
    for (auto it = bundle.tlsResumptionSnapshots.begin(); it != bundle.tlsResumptionSnapshots.end();)
    {
      if (it->wormholeName.equal(wormholeName))
      {
        it = bundle.tlsResumptionSnapshots.erase(it);
      }
      else
      {
        ++it;
      }
    }
  };

  for (const String& name : delta.removedTlsNames)
  {
    eraseTlsByName(name);
  }

  for (const String& name : delta.removedApiNames)
  {
    eraseApiByName(name);
  }

  for (const String& wormholeName : delta.removedResumptionWormholeNames)
  {
    eraseResumptionByWormholeName(wormholeName);
  }

  for (const TlsIdentity& identity : delta.updatedTls)
  {
    eraseTlsByName(identity.name);
    bundle.tlsIdentities.push_back(identity);
  }

  for (const ApiCredential& credential : delta.updatedApi)
  {
    eraseApiByName(credential.name);
    bundle.apiCredentials.push_back(credential);
  }

  for (const TlsResumptionSnapshot& snapshot : delta.updatedResumptionSnapshots)
  {
    eraseResumptionByWormholeName(snapshot.wormholeName);
    bundle.tlsResumptionSnapshots.push_back(snapshot);
  }

  bundle.bundleGeneration = delta.bundleGeneration;
}

static inline bool applyCredentialBundleResumptionLocally(
    ProdigyResumptionRegistry& registry,
    const CredentialBundle& bundle,
    TlsResumptionApplyAck& ack)
{
  ack = {};
  bool sawResumption = false;

  for (const TlsResumptionSnapshot& snapshot : bundle.tlsResumptionSnapshots)
  {
    TlsResumptionApplyResult applyResult = {};
    (void)registry.applySnapshot(snapshot, &applyResult);
    ack.results.push_back(applyResult);
    sawResumption = true;
  }

  return sawResumption;
}

static inline bool applyCredentialDeltaResumptionLocally(
    ProdigyResumptionRegistry& registry,
    CredentialBundle& bundle,
    const CredentialDelta& delta,
    TlsResumptionApplyAck& ack)
{
  ack = {};
  bool sawResumption = delta.updatedResumptionSnapshots.empty() == false ||
                       delta.removedResumptionWormholeNames.empty() == false;

  if (sawResumption)
  {
    if (registry.applyDelta(
            delta.updatedResumptionSnapshots,
            delta.removedResumptionWormholeNames,
            delta.bundleGeneration,
            &ack.results) == false)
    {
      return true;
    }
  }

  applyCredentialDelta(bundle, delta);
  return sawResumption;
}

class ApplicationIDReserveRequest {
public:

  String applicationName;
  uint16_t requestedApplicationID = 0; // 0 => auto-assign next available
  bool createIfMissing = true;
};

template <typename S>
static void serialize(S&& serializer, ApplicationIDReserveRequest& request)
{
  serializer.text1b(request.applicationName, UINT32_MAX);
  serializer.value2b(request.requestedApplicationID);
  serializer.value1b(request.createIfMissing);
}

class ApplicationIDReserveResponse : public MothershipResponse {
public:

  String applicationName;
  uint16_t applicationID = 0;
  bool created = false;
};

template <typename S>
static void serialize(S&& serializer, ApplicationIDReserveResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
  serializer.text1b(response.applicationName, UINT32_MAX);
  serializer.value2b(response.applicationID);
  serializer.value1b(response.created);
}

class ApplicationServiceIdentity {
public:

  enum class Kind : uint8_t {
    unspecified = 0,
    stateless = 1,
    stateful = 2
  };

  uint16_t applicationID = 0;
  String serviceName;
  uint8_t serviceSlot = 0; // 1..255
  Kind kind = Kind::unspecified;
};

template <typename S>
static void serialize(S&& serializer, ApplicationServiceIdentity& identity)
{
  serializer.value2b(identity.applicationID);
  serializer.text1b(identity.serviceName, UINT32_MAX);
  serializer.value1b(identity.serviceSlot);
  serializer.value1b(identity.kind);
}

class ApplicationServiceReserveRequest {
public:

  String applicationName;
  uint16_t applicationID = 0;
  String serviceName;
  uint8_t requestedServiceSlot = 0; // 0 => auto-assign next available
  ApplicationServiceIdentity::Kind kind = ApplicationServiceIdentity::Kind::unspecified;
  bool createIfMissing = true;
};

template <typename S>
static void serialize(S&& serializer, ApplicationServiceReserveRequest& request)
{
  serializer.text1b(request.applicationName, UINT32_MAX);
  serializer.value2b(request.applicationID);
  serializer.text1b(request.serviceName, UINT32_MAX);
  serializer.value1b(request.requestedServiceSlot);
  serializer.value1b(request.kind);
  serializer.value1b(request.createIfMissing);
}

class ApplicationServiceReserveResponse : public MothershipResponse {
public:

  String applicationName;
  uint16_t applicationID = 0;
  String serviceName;
  uint64_t service = 0;
  uint8_t serviceSlot = 0;
  ApplicationServiceIdentity::Kind kind = ApplicationServiceIdentity::Kind::unspecified;
  bool created = false;
};

template <typename S>
static void serialize(S&& serializer, ApplicationServiceReserveResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
  serializer.text1b(response.applicationName, UINT32_MAX);
  serializer.value2b(response.applicationID);
  serializer.text1b(response.serviceName, UINT32_MAX);
  serializer.value8b(response.service);
  serializer.value1b(response.serviceSlot);
  serializer.value1b(response.kind);
  serializer.value1b(response.created);
}

class ApplicationTlsVaultFactory {
public:

  uint16_t applicationID = 0;
  uint64_t factoryGeneration = 0;
  uint8_t keySourceMode = 0; // 0=generate, 1=import
  uint8_t scheme = 0; // CryptoScheme
  String rootCertPem;
  String rootKeyPem;
  String intermediateCertPem;
  String intermediateKeyPem;
  uint32_t defaultLeafValidityDays = 15;
  int64_t createdAtMs = 0;
  int64_t updatedAtMs = 0;
};

enum class ProdigyCertificateLifecycleMode : uint8_t {
  managed = 0,
  externalManual = 1,
};

class PublicTlsCertificateSpec {
public:

  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  String wormholeName;
  String identityName;
  Vector<String> domains;
  String issuer;
  String keyType;
  bool staging = false;
  String dnsProvider;
  String dnsCredentialName;
  String dnsZone;
  uint32_t dnsTTL = 0;
  uint16_t renewAfterLifetimePermille = prodigyDefaultCertificateRenewAfterLifetimePermille;
};

template <typename S>
static void serialize(S&& serializer, PublicTlsCertificateSpec& spec)
{
  serializer.value2b(spec.applicationID);
  serializer.value8b(spec.deploymentID);
  serializer.text1b(spec.wormholeName, UINT32_MAX);
  serializer.text1b(spec.identityName, UINT32_MAX);
  serializer.container(spec.domains, UINT32_MAX, [](S& serializer, String& domain) {
    serializer.text1b(domain, UINT32_MAX);
  });
  serializer.text1b(spec.issuer, UINT32_MAX);
  serializer.text1b(spec.keyType, UINT32_MAX);
  serializer.value1b(spec.staging);
  serializer.text1b(spec.dnsProvider, UINT32_MAX);
  serializer.text1b(spec.dnsCredentialName, UINT32_MAX);
  serializer.text1b(spec.dnsZone, UINT32_MAX);
  serializer.value4b(spec.dnsTTL);
  serializer.value2b(spec.renewAfterLifetimePermille);
}

static inline bool prodigyPublicTlsCertificateSpecsEqual(const PublicTlsCertificateSpec& lhs, const PublicTlsCertificateSpec& rhs)
{
  return lhs.applicationID == rhs.applicationID &&
         lhs.deploymentID == rhs.deploymentID &&
         lhs.wormholeName.equals(rhs.wormholeName) &&
         lhs.identityName.equals(rhs.identityName) &&
         prodigyStringVectorsEqual(lhs.domains, rhs.domains) &&
         lhs.issuer.equals(rhs.issuer) &&
         lhs.keyType.equals(rhs.keyType) &&
         lhs.staging == rhs.staging &&
         lhs.dnsProvider.equals(rhs.dnsProvider) &&
         lhs.dnsCredentialName.equals(rhs.dnsCredentialName) &&
         lhs.dnsZone.equals(rhs.dnsZone) &&
         lhs.dnsTTL == rhs.dnsTTL &&
         lhs.renewAfterLifetimePermille == rhs.renewAfterLifetimePermille;
}

class AcmeDNS01ChallengeState {
public:

  String provider;
  String credentialName;
  String zone;
  String name;
  String validation;
  uint32_t ttl = 0;
};

template <typename S>
static void serialize(S&& serializer, AcmeDNS01ChallengeState& state)
{
  serializer.text1b(state.provider, UINT32_MAX);
  serializer.text1b(state.credentialName, UINT32_MAX);
  serializer.text1b(state.zone, UINT32_MAX);
  serializer.text1b(state.name, UINT32_MAX);
  serializer.text1b(state.validation, UINT32_MAX);
  serializer.value4b(state.ttl);
}

static inline bool prodigyACMEDNS01ChallengeStatesEqual(const AcmeDNS01ChallengeState& lhs, const AcmeDNS01ChallengeState& rhs)
{
  return lhs.provider.equals(rhs.provider) &&
         lhs.credentialName.equals(rhs.credentialName) &&
         lhs.zone.equals(rhs.zone) &&
         lhs.name.equals(rhs.name) &&
         lhs.validation.equals(rhs.validation) &&
         lhs.ttl == rhs.ttl;
}

static inline bool prodigyACMEDNS01ChallengeStateVectorsEqual(const Vector<AcmeDNS01ChallengeState>& lhs, const Vector<AcmeDNS01ChallengeState>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }
  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    if (prodigyACMEDNS01ChallengeStatesEqual(lhs[index], rhs[index]) == false)
    {
      return false;
    }
  }
  return true;
}

class PublicTlsCertificateState {
public:

  PublicTlsCertificateSpec spec;
  TlsIdentity identity;
  String certbotCertName;
  String lineagePath;
  uint64_t generation = 0;
  int64_t nextRenewAtMs = 0;
  int64_t lastAttemptMs = 0;
  int64_t lastSuccessMs = 0;
  uint32_t failureCount = 0;
  String lastFailure;
  Vector<AcmeDNS01ChallengeState> pendingDNS01Challenges;
  bool releasePending = false;
};

template <typename S>
static void serialize(S&& serializer, PublicTlsCertificateState& state)
{
  serializer.object(state.spec);
  serializer.object(state.identity);
  serializer.text1b(state.certbotCertName, UINT32_MAX);
  serializer.text1b(state.lineagePath, UINT32_MAX);
  serializer.value8b(state.generation);
  serializer.value8b(state.nextRenewAtMs);
  serializer.value8b(state.lastAttemptMs);
  serializer.value8b(state.lastSuccessMs);
  serializer.value4b(state.failureCount);
  serializer.text1b(state.lastFailure, UINT32_MAX);
  serializer.object(state.pendingDNS01Challenges);
  serializer.value1b(state.releasePending);
}

static inline bool prodigyPublicTlsCertificateStatesEqual(const PublicTlsCertificateState& lhs, const PublicTlsCertificateState& rhs)
{
  return prodigyPublicTlsCertificateSpecsEqual(lhs.spec, rhs.spec) &&
         prodigyTlsIdentitiesEqual(lhs.identity, rhs.identity) &&
         lhs.certbotCertName.equals(rhs.certbotCertName) &&
         lhs.lineagePath.equals(rhs.lineagePath) &&
         lhs.generation == rhs.generation &&
         lhs.nextRenewAtMs == rhs.nextRenewAtMs &&
         lhs.lastAttemptMs == rhs.lastAttemptMs &&
         lhs.lastSuccessMs == rhs.lastSuccessMs &&
         lhs.failureCount == rhs.failureCount &&
         lhs.lastFailure.equals(rhs.lastFailure) &&
         prodigyACMEDNS01ChallengeStateVectorsEqual(lhs.pendingDNS01Challenges, rhs.pendingDNS01Challenges) &&
         lhs.releasePending == rhs.releasePending;
}

static inline bool prodigyCanonicalACMEDNSIdentifier(const String& identifier, String& canonical, String *failure = nullptr)
{
  canonical.clear();
  if (failure)
  {
    failure->clear();
  }

  bool wildcard = identifier.size() > 2 && identifier[0] == '*' && identifier[1] == '.';
  uint64_t start = wildcard ? 2 : 0;
  uint64_t end = identifier.size();
  while (end > start && identifier[end - 1] == '.')
  {
    end -= 1;
  }
  if (end <= start)
  {
    if (failure)
    {
      failure->assign("ACME DNS-01 identifier is empty"_ctv);
    }
    return false;
  }

  String dnsIdentifier = {};
  for (uint64_t index = start; index < end; index += 1)
  {
    unsigned char c = static_cast<unsigned char>(identifier[index]);
    if (c > 127)
    {
      if (failure)
      {
        failure->assign("ACME DNS-01 identifier is not a valid DNS name"_ctv);
      }
      return false;
    }
    dnsIdentifier.append(char(std::tolower(c)));
  }
  IPAddress parsedAddress = {};
  if (ClusterMachine::parseIPAddressLiteral(dnsIdentifier, parsedAddress))
  {
    if (failure)
    {
      failure->assign("ACME DNS-01 identifier must be a DNS name"_ctv);
    }
    return false;
  }
  if (dnsIdentifier.size() > 253)
  {
    if (failure)
    {
      failure->assign("ACME DNS-01 identifier is not a valid DNS name"_ctv);
    }
    return false;
  }

  uint64_t labelStart = 0;
  while (labelStart < dnsIdentifier.size())
  {
    uint64_t labelEnd = labelStart;
    while (labelEnd < dnsIdentifier.size() && dnsIdentifier[labelEnd] != '.')
    {
      labelEnd += 1;
    }
    uint64_t labelSize = labelEnd - labelStart;
    if (labelSize == 0 || labelSize > 63 || dnsIdentifier[labelStart] == '-' || dnsIdentifier[labelEnd - 1] == '-')
    {
      if (failure)
      {
        failure->assign("ACME DNS-01 identifier is not a valid DNS name"_ctv);
      }
      return false;
    }
    for (uint64_t index = labelStart; index < labelEnd; index += 1)
    {
      char c = dnsIdentifier[index];
      if (std::isalnum(static_cast<unsigned char>(c)) == false && c != '-')
      {
        if (failure)
        {
          failure->assign("ACME DNS-01 identifier is not a valid DNS name"_ctv);
        }
        return false;
      }
    }
    labelStart = labelEnd + 1;
  }

  if (wildcard)
  {
    canonical.assign("*."_ctv);
  }
  canonical.append(dnsIdentifier);
  return true;
}

static inline bool prodigyACMEDNS01RecordName(const String& identifier, String& recordName, String *failure = nullptr)
{
  recordName.clear();
  String canonical = {};
  if (prodigyCanonicalACMEDNSIdentifier(identifier, canonical, failure) == false)
  {
    return false;
  }

  recordName.assign("_acme-challenge."_ctv);
  uint64_t nameStart = canonical.size() > 2 && canonical[0] == '*' && canonical[1] == '.' ? 2 : 0;
  recordName.append(canonical.data() + nameStart, canonical.size() - nameStart);
  recordName.append("."_ctv);
  return true;
}

class AcmeDNS01ChallengeRequest {
public:

  uint128_t clusterUUID = 0;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  String wormholeName;
  String certName;
  String identifier;
  String validation;
};

template <typename S>
static void serialize(S&& serializer, AcmeDNS01ChallengeRequest& request)
{
  serializer.value16b(request.clusterUUID);
  serializer.value2b(request.applicationID);
  serializer.value8b(request.deploymentID);
  serializer.text1b(request.wormholeName, UINT32_MAX);
  serializer.text1b(request.certName, UINT32_MAX);
  serializer.text1b(request.identifier, UINT32_MAX);
  serializer.text1b(request.validation, UINT32_MAX);
}

class AcmeDNS01ChallengeResponse : public MothershipResponse {
public:

  String recordName;
  String provider;
  String zone;
  uint32_t ttl = 0;
};

template <typename S>
static void serialize(S&& serializer, AcmeDNS01ChallengeResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
  serializer.text1b(response.recordName, UINT32_MAX);
  serializer.text1b(response.provider, UINT32_MAX);
  serializer.text1b(response.zone, UINT32_MAX);
  serializer.value4b(response.ttl);
}

class AcmeLineageImportRequest {
public:

  uint128_t clusterUUID = 0;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  String wormholeName;
  String certName;
  String lineagePath;
  Vector<String> renewedDomains;
};

template <typename S>
static void serialize(S&& serializer, AcmeLineageImportRequest& request)
{
  serializer.value16b(request.clusterUUID);
  serializer.value2b(request.applicationID);
  serializer.value8b(request.deploymentID);
  serializer.text1b(request.wormholeName, UINT32_MAX);
  serializer.text1b(request.certName, UINT32_MAX);
  serializer.text1b(request.lineagePath, UINT32_MAX);
  serializer.container(request.renewedDomains, UINT32_MAX, [](S& serializer, String& domain) {
    serializer.text1b(domain, UINT32_MAX);
  });
}

class AcmeLineageImportResponse : public MothershipResponse {
public:

  String certName;
  uint64_t generation = 0;
  int64_t nextRenewAtMs = 0;
};

template <typename S>
static void serialize(S&& serializer, AcmeLineageImportResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
  serializer.text1b(response.certName, UINT32_MAX);
  serializer.value8b(response.generation);
  serializer.value8b(response.nextRenewAtMs);
}

class PrivateTlsVaultLifecycleState {
public:

  uint16_t applicationID = 0;
  uint64_t factoryGeneration = 0;
  ProdigyCertificateLifecycleMode mode = ProdigyCertificateLifecycleMode::managed;
  int64_t rootNotBeforeMs = 0;
  int64_t rootNotAfterMs = 0;
  int64_t intermediateNotBeforeMs = 0;
  int64_t intermediateNotAfterMs = 0;
  int64_t leafNotBeforeMs = 0;
  int64_t leafNotAfterMs = 0;
  int64_t leafNextRenewAtMs = 0;
  int64_t nextRenewAtMs = 0;
  int64_t lastAttemptMs = 0;
  int64_t lastSuccessMs = 0;
  uint32_t failureCount = 0;
  String lastFailure;
};

template <typename S>
static void serialize(S&& serializer, PrivateTlsVaultLifecycleState& state)
{
  serializer.value2b(state.applicationID);
  serializer.value8b(state.factoryGeneration);
  serializer.value1b(state.mode);
  serializer.value8b(state.rootNotBeforeMs);
  serializer.value8b(state.rootNotAfterMs);
  serializer.value8b(state.intermediateNotBeforeMs);
  serializer.value8b(state.intermediateNotAfterMs);
  serializer.value8b(state.leafNotBeforeMs);
  serializer.value8b(state.leafNotAfterMs);
  serializer.value8b(state.leafNextRenewAtMs);
  serializer.value8b(state.nextRenewAtMs);
  serializer.value8b(state.lastAttemptMs);
  serializer.value8b(state.lastSuccessMs);
  serializer.value4b(state.failureCount);
  serializer.text1b(state.lastFailure, UINT32_MAX);
}

static inline bool prodigyPrivateTlsVaultLifecycleStatesEqual(const PrivateTlsVaultLifecycleState& lhs, const PrivateTlsVaultLifecycleState& rhs)
{
  return lhs.applicationID == rhs.applicationID &&
         lhs.factoryGeneration == rhs.factoryGeneration &&
         lhs.mode == rhs.mode &&
         lhs.rootNotBeforeMs == rhs.rootNotBeforeMs &&
         lhs.rootNotAfterMs == rhs.rootNotAfterMs &&
         lhs.intermediateNotBeforeMs == rhs.intermediateNotBeforeMs &&
         lhs.intermediateNotAfterMs == rhs.intermediateNotAfterMs &&
         lhs.leafNotBeforeMs == rhs.leafNotBeforeMs &&
         lhs.leafNotAfterMs == rhs.leafNotAfterMs &&
         lhs.leafNextRenewAtMs == rhs.leafNextRenewAtMs &&
         lhs.nextRenewAtMs == rhs.nextRenewAtMs &&
         lhs.lastAttemptMs == rhs.lastAttemptMs &&
         lhs.lastSuccessMs == rhs.lastSuccessMs &&
         lhs.failureCount == rhs.failureCount &&
         lhs.lastFailure.equals(rhs.lastFailure);
}

static inline int64_t prodigyCertificateRenewAtMs(int64_t notBeforeMs, int64_t notAfterMs, uint16_t renewAfterLifetimePermille)
{
  if (notAfterMs <= notBeforeMs)
  {
    return 0;
  }
  if (renewAfterLifetimePermille == 0 || renewAfterLifetimePermille >= 1000)
  {
    renewAfterLifetimePermille = prodigyDefaultCertificateRenewAfterLifetimePermille;
  }
  return notBeforeMs + int64_t((__int128(notAfterMs - notBeforeMs) * renewAfterLifetimePermille) / 1000);
}

static inline int64_t prodigyEarliestPositiveMs(int64_t lhs, int64_t rhs)
{
  if (lhs <= 0)
  {
    return rhs;
  }
  if (rhs <= 0)
  {
    return lhs;
  }
  return lhs < rhs ? lhs : rhs;
}

template <typename S>
static void serialize(S&& serializer, ApplicationTlsVaultFactory& factory)
{
  serializer.value2b(factory.applicationID);
  serializer.value8b(factory.factoryGeneration);
  serializer.value1b(factory.keySourceMode);
  serializer.value1b(factory.scheme);
  serializer.text1b(factory.rootCertPem, UINT32_MAX);
  serializer.text1b(factory.rootKeyPem, UINT32_MAX);
  serializer.text1b(factory.intermediateCertPem, UINT32_MAX);
  serializer.text1b(factory.intermediateKeyPem, UINT32_MAX);
  serializer.value4b(factory.defaultLeafValidityDays);
  serializer.value8b(factory.createdAtMs);
  serializer.value8b(factory.updatedAtMs);
}

class TlsVaultFactoryUpsertRequest {
public:

  uint16_t applicationID = 0;
  uint8_t mode = 0; // 0=generate, 1=import
  uint8_t scheme = 0; // CryptoScheme
  String importRootCertPem;
  String importRootKeyPem;
  String importIntermediateCertPem;
  String importIntermediateKeyPem;
  uint32_t defaultLeafValidityDays = 15;
};

template <typename S>
static void serialize(S&& serializer, TlsVaultFactoryUpsertRequest& request)
{
  serializer.value2b(request.applicationID);
  serializer.value1b(request.mode);
  serializer.value1b(request.scheme);
  serializer.text1b(request.importRootCertPem, UINT32_MAX);
  serializer.text1b(request.importRootKeyPem, UINT32_MAX);
  serializer.text1b(request.importIntermediateCertPem, UINT32_MAX);
  serializer.text1b(request.importIntermediateKeyPem, UINT32_MAX);
  serializer.value4b(request.defaultLeafValidityDays);
}

class TlsVaultFactoryUpsertResponse : public MothershipResponse {
public:

  uint16_t applicationID = 0;
  uint64_t factoryGeneration = 0;
  bool created = false;
  uint8_t mode = 0;
  String generatedRootCertPem;
  String generatedRootKeyPem;
  String generatedIntermediateCertPem;
  String generatedIntermediateKeyPem;
  uint32_t effectiveLeafValidityDays = 15;
};

template <typename S>
static void serialize(S&& serializer, TlsVaultFactoryUpsertResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
  serializer.value2b(response.applicationID);
  serializer.value8b(response.factoryGeneration);
  serializer.value1b(response.created);
  serializer.value1b(response.mode);
  serializer.text1b(response.generatedRootCertPem, UINT32_MAX);
  serializer.text1b(response.generatedRootKeyPem, UINT32_MAX);
  serializer.text1b(response.generatedIntermediateCertPem, UINT32_MAX);
  serializer.text1b(response.generatedIntermediateKeyPem, UINT32_MAX);
  serializer.value4b(response.effectiveLeafValidityDays);
}

class DeploymentTlsIssuancePolicy {
public:

  uint16_t applicationID = 0;
  bool enablePerContainerLeafs = false;
  uint32_t leafValidityDays = 0; // 0 => factory default
  Vector<String> identityNames;
  Vector<String> dnsSans;
  Vector<IPAddress> ipSans;
};

template <typename S>
static void serialize(S&& serializer, DeploymentTlsIssuancePolicy& policy)
{
  serializer.value2b(policy.applicationID);
  serializer.value1b(policy.enablePerContainerLeafs);
  serializer.value4b(policy.leafValidityDays);
  serializer.container(policy.identityNames, UINT32_MAX, [](S& serializer, String& name) {
    serializer.text1b(name, UINT32_MAX);
  });
  serializer.container(policy.dnsSans, UINT32_MAX, [](S& serializer, String& san) {
    serializer.text1b(san, UINT32_MAX);
  });
  serializer.object(policy.ipSans);
}

class ApplicationApiCredentialSet {
public:

  uint16_t applicationID = 0;
  uint64_t setGeneration = 0;
  Vector<ApiCredential> credentials;
  int64_t createdAtMs = 0;
  int64_t updatedAtMs = 0;
};

template <typename S>
static void serialize(S&& serializer, ApplicationApiCredentialSet& set)
{
  serializer.value2b(set.applicationID);
  serializer.value8b(set.setGeneration);
  serializer.object(set.credentials);
  serializer.value8b(set.createdAtMs);
  serializer.value8b(set.updatedAtMs);
}

class ApiCredentialSetUpsertRequest {
public:

  uint16_t applicationID = 0;
  Vector<ApiCredential> upsertCredentials;
  Vector<String> removeCredentialNames;
  String reason;
};

template <typename S>
static void serialize(S&& serializer, ApiCredentialSetUpsertRequest& request)
{
  serializer.value2b(request.applicationID);
  serializer.object(request.upsertCredentials);
  serializer.container(request.removeCredentialNames, UINT32_MAX, [](S& serializer, String& name) {
    serializer.text1b(name, UINT32_MAX);
  });
  serializer.text1b(request.reason, UINT32_MAX);
}

class ApiCredentialSetUpsertResponse : public MothershipResponse {
public:

  uint16_t applicationID = 0;
  uint64_t setGeneration = 0;
  Vector<String> updatedNames;
  Vector<String> removedNames;
};

template <typename S>
static void serialize(S&& serializer, ApiCredentialSetUpsertResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
  serializer.value2b(response.applicationID);
  serializer.value8b(response.setGeneration);
  serializer.container(response.updatedNames, UINT32_MAX, [](S& serializer, String& name) {
    serializer.text1b(name, UINT32_MAX);
  });
  serializer.container(response.removedNames, UINT32_MAX, [](S& serializer, String& name) {
    serializer.text1b(name, UINT32_MAX);
  });
}

class DeploymentApiCredentialPolicy {
public:

  uint16_t applicationID = 0;
  Vector<String> requiredCredentialNames;
  bool refreshPushEnabled = false;
};

template <typename S>
static void serialize(S&& serializer, DeploymentApiCredentialPolicy& policy)
{
  serializer.value2b(policy.applicationID);
  serializer.container(policy.requiredCredentialNames, UINT32_MAX, [](S& serializer, String& name) {
    serializer.text1b(name, UINT32_MAX);
  });
  serializer.value1b(policy.refreshPushEnabled);
}

class ClientTlsMintRequest {
public:

  uint16_t applicationID = 0;
  uint8_t scheme = 0; // CryptoScheme
  String name;
  String subjectCommonName;
  Vector<String> dnsSans;
  Vector<IPAddress> ipSans;
  uint32_t validityDays = 0; // 0 => factory default
  Vector<String> tags;
  String reason;
};

template <typename S>
static void serialize(S&& serializer, ClientTlsMintRequest& request)
{
  serializer.value2b(request.applicationID);
  serializer.value1b(request.scheme);
  serializer.text1b(request.name, UINT32_MAX);
  serializer.text1b(request.subjectCommonName, UINT32_MAX);
  serializer.container(request.dnsSans, UINT32_MAX, [](S& serializer, String& san) {
    serializer.text1b(san, UINT32_MAX);
  });
  serializer.object(request.ipSans);
  serializer.value4b(request.validityDays);
  serializer.container(request.tags, UINT32_MAX, [](S& serializer, String& tag) {
    serializer.text1b(tag, UINT32_MAX);
  });
  serializer.text1b(request.reason, UINT32_MAX);
}

class ClientTlsMintResponse : public MothershipResponse {
public:

  uint16_t applicationID = 0;
  String name;
  uint64_t generation = 0;
  int64_t notBeforeMs = 0;
  int64_t notAfterMs = 0;
  String certPem;
  String keyPem;
  String chainPem;
  uint64_t issuerFactoryGeneration = 0;
};

template <typename S>
static void serialize(S&& serializer, ClientTlsMintResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
  serializer.value2b(response.applicationID);
  serializer.text1b(response.name, UINT32_MAX);
  serializer.value8b(response.generation);
  serializer.value8b(response.notBeforeMs);
  serializer.value8b(response.notAfterMs);
  serializer.text1b(response.certPem, UINT32_MAX);
  serializer.text1b(response.keyPem, UINT32_MAX);
  serializer.text1b(response.chainPem, UINT32_MAX);
  serializer.value8b(response.issuerFactoryGeneration);
}

class ProdigyTransportTLSAuthority {
public:

  uint64_t generation = 0;
  String clusterRootCertPem;
  String clusterRootKeyPem;

  bool configured(void) const
  {
    return clusterRootCertPem.size() > 0;
  }

  bool canMintForCluster(void) const
  {
    return clusterRootCertPem.size() > 0 && clusterRootKeyPem.size() > 0;
  }

  bool operator==(const ProdigyTransportTLSAuthority& other) const
  {
    return generation == other.generation && clusterRootCertPem.equals(other.clusterRootCertPem) && clusterRootKeyPem.equals(other.clusterRootKeyPem);
  }

  bool operator!=(const ProdigyTransportTLSAuthority& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyTransportTLSAuthority& authority)
{
  serializer.value8b(authority.generation);
  serializer.text1b(authority.clusterRootCertPem, UINT32_MAX);
  serializer.text1b(authority.clusterRootKeyPem, UINT32_MAX);
}

class ProdigyPersistentUpdateSelfFollowerBoot {
public:

  uint128_t peerKey = 0;
  int64_t bootNs = 0;

  bool operator==(const ProdigyPersistentUpdateSelfFollowerBoot& other) const
  {
    return peerKey == other.peerKey && bootNs == other.bootNs;
  }

  bool operator!=(const ProdigyPersistentUpdateSelfFollowerBoot& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentUpdateSelfFollowerBoot& state)
{
  serializer.value16b(state.peerKey);
  serializer.value8b(state.bootNs);
}

class ProdigyPersistentUpdateSelfState {
public:

  uint8_t state = 0;
  uint32_t expectedEchos = 0;
  uint32_t bundleEchos = 0;
  uint32_t relinquishEchos = 0;
  uint128_t plannedMasterPeerKey = 0;
  uint128_t pendingDesignatedMasterPeerKey = 0;
  bool useStagedBundleOnly = false;
  String bundleBlob;
  Vector<uint128_t> bundleEchoPeerKeys;
  Vector<uint128_t> relinquishEchoPeerKeys;
  Vector<ProdigyPersistentUpdateSelfFollowerBoot> followerBootNsByPeerKey;
  Vector<uint128_t> followerRebootedPeerKeys;

  bool active(void) const
  {
    return state != 0 || expectedEchos != 0 || bundleEchos != 0 || relinquishEchos != 0 || plannedMasterPeerKey != 0 || pendingDesignatedMasterPeerKey != 0 || useStagedBundleOnly || bundleBlob.size() > 0 || bundleEchoPeerKeys.empty() == false || relinquishEchoPeerKeys.empty() == false || followerBootNsByPeerKey.empty() == false || followerRebootedPeerKeys.empty() == false;
  }

  bool operator==(const ProdigyPersistentUpdateSelfState& other) const
  {
    return state == other.state && expectedEchos == other.expectedEchos && bundleEchos == other.bundleEchos && relinquishEchos == other.relinquishEchos && plannedMasterPeerKey == other.plannedMasterPeerKey && pendingDesignatedMasterPeerKey == other.pendingDesignatedMasterPeerKey && useStagedBundleOnly == other.useStagedBundleOnly && bundleBlob.equals(other.bundleBlob) && bundleEchoPeerKeys == other.bundleEchoPeerKeys && relinquishEchoPeerKeys == other.relinquishEchoPeerKeys && followerBootNsByPeerKey == other.followerBootNsByPeerKey && followerRebootedPeerKeys == other.followerRebootedPeerKeys;
  }

  bool operator!=(const ProdigyPersistentUpdateSelfState& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentUpdateSelfState& state)
{
  serializer.value1b(state.state);
  serializer.value4b(state.expectedEchos);
  serializer.value4b(state.bundleEchos);
  serializer.value4b(state.relinquishEchos);
  serializer.value16b(state.plannedMasterPeerKey);
  serializer.value16b(state.pendingDesignatedMasterPeerKey);
  serializer.value1b(state.useStagedBundleOnly);
  serializer.text1b(state.bundleBlob, UINT32_MAX);
  serializer.object(state.bundleEchoPeerKeys);
  serializer.object(state.relinquishEchoPeerKeys);
  serializer.object(state.followerBootNsByPeerKey);
  serializer.object(state.followerRebootedPeerKeys);
}

class ProdigyPendingAddMachinesOperation {
public:

  uint64_t operationID = 0;
  AddMachines request;
  ClusterTopology plannedTopology;
  Vector<ClusterMachine> machinesToBootstrap;
  uint32_t resumeAttempts = 0;
  int64_t updatedAtMs = 0;
  String lastFailure;

  bool operator==(const ProdigyPendingAddMachinesOperation& other) const
  {
    if (operationID != other.operationID || request != other.request || plannedTopology != other.plannedTopology || machinesToBootstrap.size() != other.machinesToBootstrap.size() || resumeAttempts != other.resumeAttempts || updatedAtMs != other.updatedAtMs || lastFailure.equals(other.lastFailure) == false)
    {
      return false;
    }

    for (uint32_t index = 0; index < machinesToBootstrap.size(); ++index)
    {
      if (machinesToBootstrap[index] != other.machinesToBootstrap[index])
      {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const ProdigyPendingAddMachinesOperation& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPendingAddMachinesOperation& operation)
{
  serializer.value8b(operation.operationID);
  serializer.object(operation.request);
  serializer.object(operation.plannedTopology);
  serializer.object(operation.machinesToBootstrap);
  serializer.value4b(operation.resumeAttempts);
  serializer.value8b(operation.updatedAtMs);
  serializer.text1b(operation.lastFailure, UINT32_MAX);
}

class ProdigyPendingAutonomousProvisioningOperation {
public:

  uint64_t operationID = 0;
  uint64_t deploymentID = 0;
  uint8_t applicationLifetime = 0;
  String machineSchema;
  uint32_t count = 0;

  bool operator==(const ProdigyPendingAutonomousProvisioningOperation& other) const
  {
    return operationID == other.operationID && deploymentID == other.deploymentID &&
           applicationLifetime == other.applicationLifetime &&
           machineSchema.equals(other.machineSchema) && count == other.count;
  }

  bool operator!=(const ProdigyPendingAutonomousProvisioningOperation& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPendingAutonomousProvisioningOperation& operation)
{
  serializer.value8b(operation.operationID);
  serializer.value8b(operation.deploymentID);
  serializer.value1b(operation.applicationLifetime);
  serializer.text1b(operation.machineSchema, UINT32_MAX);
  serializer.value4b(operation.count);
}

enum class RoutableResourceLeaseKind : uint8_t {
  wormholeAddress = 0,
  whiteholeAddressPort = 1,
  dnsRecord = 2
};

class RoutableResourceLeaseOwner {
public:

  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  uint64_t lineageID = 0;
  String name;

  bool operator==(const RoutableResourceLeaseOwner& other) const
  {
    return applicationID == other.applicationID && deploymentID == other.deploymentID && lineageID == other.lineageID && name.equals(other.name);
  }
};

template <typename S>
static void serialize(S&& serializer, RoutableResourceLeaseOwner& owner)
{
  serializer.value2b(owner.applicationID);
  serializer.value8b(owner.deploymentID);
  serializer.value8b(owner.lineageID);
  serializer.text1b(owner.name, UINT32_MAX);
}

class RoutableResourceLease {
public:

  RoutableResourceLeaseKind kind = RoutableResourceLeaseKind::wormholeAddress;
  RoutableResourceLeaseOwner owner;
  uint128_t registeredPrefixUUID = 0;
  IPAddress address;
  uint16_t sourcePort = 0;
  String dnsProvider;
  String dnsCredentialName;
  String dnsZone;
  String dnsName;
  String dnsType;
  uint32_t dnsTTL = 0;
  bool dnsDeletePending = false;
  uint64_t dnsIntentRevision = 0;

  bool operator==(const RoutableResourceLease& other) const
  {
    return kind == other.kind && owner == other.owner && registeredPrefixUUID == other.registeredPrefixUUID && address.equals(other.address) && sourcePort == other.sourcePort && dnsProvider.equals(other.dnsProvider) && dnsCredentialName.equals(other.dnsCredentialName) && dnsZone.equals(other.dnsZone) && dnsName.equals(other.dnsName) && dnsType.equals(other.dnsType) && dnsTTL == other.dnsTTL && dnsDeletePending == other.dnsDeletePending && dnsIntentRevision == other.dnsIntentRevision;
  }
};

template <typename S>
static void serialize(S&& serializer, RoutableResourceLease& lease)
{
  serializer.value1b(lease.kind);
  serializer.object(lease.owner);
  serializer.value16b(lease.registeredPrefixUUID);
  serializer.object(lease.address);
  serializer.value2b(lease.sourcePort);
  serializer.text1b(lease.dnsProvider, UINT32_MAX);
  serializer.text1b(lease.dnsCredentialName, UINT32_MAX);
  serializer.text1b(lease.dnsZone, UINT32_MAX);
  serializer.text1b(lease.dnsName, UINT32_MAX);
  serializer.text1b(lease.dnsType, UINT32_MAX);
  serializer.value4b(lease.dnsTTL);
  serializer.value1b(lease.dnsDeletePending);
  serializer.value8b(lease.dnsIntentRevision);
}

class RoutableResourceLeaseReport {
public:

  Vector<RoutableResourceLease> leases;
  bool success = false;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, RoutableResourceLeaseReport& payload)
{
  serializer.object(payload.leases);
  serializer.value1b(payload.success);
  serializer.text1b(payload.failure, UINT32_MAX);
}

static inline bool routableResourceLeaseOwnersCompatible(const RoutableResourceLeaseOwner& lhs, const RoutableResourceLeaseOwner& rhs)
{
  if (lhs.deploymentID != 0 && lhs.deploymentID == rhs.deploymentID)
  {
    return true;
  }

  return lhs.applicationID != 0 && lhs.applicationID == rhs.applicationID && lhs.lineageID != 0 && lhs.lineageID == rhs.lineageID;
}

static inline bool routableResourceDNSPartEquals(const String& lhs, const String& rhs, bool trimTrailingDot)
{
  size_t lhsSize = lhs.size();
  size_t rhsSize = rhs.size();
  if (trimTrailingDot)
  {
    while (lhsSize > 0 && lhs[lhsSize - 1] == '.')
    {
      lhsSize -= 1;
    }
    while (rhsSize > 0 && rhs[rhsSize - 1] == '.')
    {
      rhsSize -= 1;
    }
  }
  if (lhsSize != rhsSize)
  {
    return false;
  }
  for (size_t index = 0; index < lhsSize; ++index)
  {
    if (std::tolower(static_cast<unsigned char>(lhs[index])) != std::tolower(static_cast<unsigned char>(rhs[index])))
    {
      return false;
    }
  }
  return true;
}

static inline bool routableResourceDNSIdentityMatches(const RoutableResourceLease& lhs, const RoutableResourceLease& rhs)
{
  return routableResourceDNSPartEquals(lhs.dnsProvider, rhs.dnsProvider, false) &&
         routableResourceDNSPartEquals(lhs.dnsZone, rhs.dnsZone, true) &&
         routableResourceDNSPartEquals(lhs.dnsName, rhs.dnsName, true) &&
         routableResourceDNSPartEquals(lhs.dnsType, rhs.dnsType, false);
}

static inline bool routableResourceLeaseResourcesIntersect(const RoutableResourceLease& lhs, const RoutableResourceLease& rhs)
{
  if (lhs.kind == RoutableResourceLeaseKind::dnsRecord && rhs.kind == RoutableResourceLeaseKind::dnsRecord)
  {
    return routableResourceDNSIdentityMatches(lhs, rhs);
  }

  if (lhs.kind == RoutableResourceLeaseKind::wormholeAddress && rhs.kind == RoutableResourceLeaseKind::wormholeAddress)
  {
    return lhs.address.isNull() == false && lhs.address.equals(rhs.address);
  }

  if (lhs.kind == RoutableResourceLeaseKind::whiteholeAddressPort && rhs.kind == RoutableResourceLeaseKind::whiteholeAddressPort)
  {
    return lhs.sourcePort != 0 && lhs.sourcePort == rhs.sourcePort && lhs.address.equals(rhs.address);
  }

  return false;
}

static inline bool routableResourceLeasesConflict(const RoutableResourceLease& lhs, const RoutableResourceLease& rhs)
{
  return routableResourceLeaseOwnersCompatible(lhs.owner, rhs.owner) == false && routableResourceLeaseResourcesIntersect(lhs, rhs);
}

enum class ProdigyDnsControlClientRole : uint8_t {
  mothership = 1,
  prodigy = 2
};

class ProdigyDnsControlPairingLease {
public:

  uint128_t leaseID = 0;
  uint128_t secret = 0;
  IPAddress clientAddress;
  uint64_t generation = 0;
  int64_t expiresAtMs = 0;
  ProdigyDnsControlClientRole role = ProdigyDnsControlClientRole::prodigy;
  bool desiredActive = true;
  bool applied = false;

  bool operator==(const ProdigyDnsControlPairingLease& other) const
  {
    return leaseID == other.leaseID && secret == other.secret &&
           clientAddress.equals(other.clientAddress) &&
           generation == other.generation &&
           expiresAtMs == other.expiresAtMs && role == other.role &&
           desiredActive == other.desiredActive && applied == other.applied;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyDnsControlPairingLease& lease)
{
  serializer.value16b(lease.leaseID);
  serializer.value16b(lease.secret);
  serializer.object(lease.clientAddress);
  serializer.value8b(lease.generation);
  serializer.value8b(lease.expiresAtMs);
  serializer.value1b(lease.role);
  serializer.value1b(lease.desiredActive);
  serializer.value1b(lease.applied);
}

enum class ProdigyDnsControlPairingAction : uint8_t {
  mint = 1,
  revoke = 2,
  reconcile = 3
};

class ProdigyDnsControlPairingOperation {
public:

  ProdigyDnsControlPairingAction action = ProdigyDnsControlPairingAction::reconcile;
  ProdigyDnsControlClientRole role = ProdigyDnsControlClientRole::prodigy;
  IPAddress clientAddress;
  int64_t lifetimeMs = 0;
  uint128_t leaseID = 0;
  uint64_t generation = 0;
  ProdigyDnsControlPairingLease lease;
  bool succeeded = false;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, ProdigyDnsControlPairingOperation& operation)
{
  serializer.value1b(operation.action);
  serializer.value1b(operation.role);
  serializer.object(operation.clientAddress);
  serializer.value8b(operation.lifetimeMs);
  serializer.value16b(operation.leaseID);
  serializer.value8b(operation.generation);
  serializer.object(operation.lease);
  serializer.value1b(operation.succeeded);
  serializer.text1b(operation.failure, 512);
}

class ProdigyMasterAuthorityRuntimeState {
public:

  uint64_t generation = 0;
  bool hasCompletedInitialMasterElection = false;
  ProdigyTransportTLSAuthority transportTLSAuthority;
  uint64_t nextMintedClientTlsGeneration = 1;
  uint64_t nextTlsResumptionGeneration = 1;
  uint64_t nextPendingAddMachinesOperationID = 1;
  uint64_t nextPendingElasticAddressOperationID = 1;
  uint64_t nextDNSIntentRevision = 1;
  uint64_t nextDnsControlPairingGeneration = 1;
  ProdigyResumptionRegistry::SnapshotMap tlsResumptionSnapshotsByWormhole;
  Vector<ProdigyPendingAddMachinesOperation> pendingAddMachinesOperations;
  Vector<ProdigyPendingAutonomousProvisioningOperation> pendingAutonomousProvisioningOperations;
  Vector<ProdigyPendingElasticAddressAssignment> pendingElasticAddressAssignments;
  Vector<ProdigyPendingElasticAddressRelease> pendingElasticAddressReleases;
  Vector<ProdigyStatefulWorkerTopologyUpgradeOperation> statefulWorkerTopologyUpgradeOperations;
  Vector<ProdigyDeferredStatefulScaleIntent> deferredStatefulScaleIntents;
  Vector<ProdigyManagedMachineSchema> machineSchemas;
  Vector<RoutableResourceLease> routableResourceLeases;
  Vector<ProdigyDnsControlPairingLease> dnsControlPairingLeases;
  Vector<PublicTlsCertificateState> publicTlsCertificates;
  Vector<PrivateTlsVaultLifecycleState> privateTlsVaultLifecycles;
  bytell_hash_map<uint64_t, TaskExecutionRecord> taskExecutions;
  MothershipTunnelProviderDesiredState mothershipTunnelProviderDesiredState;
  ProdigyPersistentUpdateSelfState updateSelf;

  bool operator==(const ProdigyMasterAuthorityRuntimeState& other) const
  {
    if (nextDnsControlPairingGeneration != other.nextDnsControlPairingGeneration ||
        dnsControlPairingLeases.size() != other.dnsControlPairingLeases.size())
    {
      return false;
    }
    if (generation != other.generation || hasCompletedInitialMasterElection != other.hasCompletedInitialMasterElection || transportTLSAuthority != other.transportTLSAuthority || nextMintedClientTlsGeneration != other.nextMintedClientTlsGeneration || nextTlsResumptionGeneration != other.nextTlsResumptionGeneration || nextPendingAddMachinesOperationID != other.nextPendingAddMachinesOperationID || nextPendingElasticAddressOperationID != other.nextPendingElasticAddressOperationID || nextDNSIntentRevision != other.nextDNSIntentRevision || tlsResumptionSnapshotsByWormhole.size() != other.tlsResumptionSnapshotsByWormhole.size() || pendingAddMachinesOperations.size() != other.pendingAddMachinesOperations.size() || pendingAutonomousProvisioningOperations.size() != other.pendingAutonomousProvisioningOperations.size() || pendingElasticAddressAssignments.size() != other.pendingElasticAddressAssignments.size() || pendingElasticAddressReleases.size() != other.pendingElasticAddressReleases.size() || statefulWorkerTopologyUpgradeOperations.size() != other.statefulWorkerTopologyUpgradeOperations.size() || deferredStatefulScaleIntents.size() != other.deferredStatefulScaleIntents.size() || machineSchemas.size() != other.machineSchemas.size() || routableResourceLeases.size() != other.routableResourceLeases.size() || publicTlsCertificates.size() != other.publicTlsCertificates.size() || privateTlsVaultLifecycles.size() != other.privateTlsVaultLifecycles.size() || taskExecutions.size() != other.taskExecutions.size() || mothershipTunnelProviderDesiredState != other.mothershipTunnelProviderDesiredState || updateSelf != other.updateSelf)
    {
      return false;
    }

    for (const auto& [key, snapshot] : tlsResumptionSnapshotsByWormhole)
    {
      auto it = other.tlsResumptionSnapshotsByWormhole.find(key);
      if (it == other.tlsResumptionSnapshotsByWormhole.end() || prodigyTlsResumptionSnapshotsEqual(it->second, snapshot) == false)
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < pendingAddMachinesOperations.size(); ++index)
    {
      if (pendingAddMachinesOperations[index] != other.pendingAddMachinesOperations[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < pendingAutonomousProvisioningOperations.size(); ++index)
    {
      if (pendingAutonomousProvisioningOperations[index] != other.pendingAutonomousProvisioningOperations[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < pendingElasticAddressReleases.size(); ++index)
    {
      if (pendingElasticAddressReleases[index] != other.pendingElasticAddressReleases[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < pendingElasticAddressAssignments.size(); ++index)
    {
      if ((pendingElasticAddressAssignments[index] == other.pendingElasticAddressAssignments[index]) == false)
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < statefulWorkerTopologyUpgradeOperations.size(); ++index)
    {
      if (statefulWorkerTopologyUpgradeOperations[index] != other.statefulWorkerTopologyUpgradeOperations[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < deferredStatefulScaleIntents.size(); ++index)
    {
      if (deferredStatefulScaleIntents[index] != other.deferredStatefulScaleIntents[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < machineSchemas.size(); ++index)
    {
      if (machineSchemas[index] != other.machineSchemas[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < routableResourceLeases.size(); ++index)
    {
      if ((routableResourceLeases[index] == other.routableResourceLeases[index]) == false)
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < dnsControlPairingLeases.size(); ++index)
    {
      if ((dnsControlPairingLeases[index] == other.dnsControlPairingLeases[index]) == false)
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < publicTlsCertificates.size(); ++index)
    {
      if (prodigyPublicTlsCertificateStatesEqual(publicTlsCertificates[index], other.publicTlsCertificates[index]) == false)
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < privateTlsVaultLifecycles.size(); ++index)
    {
      if (prodigyPrivateTlsVaultLifecycleStatesEqual(privateTlsVaultLifecycles[index], other.privateTlsVaultLifecycles[index]) == false)
      {
        return false;
      }
    }

    for (const auto& [executionID, record] : taskExecutions)
    {
      auto otherIt = other.taskExecutions.find(executionID);
      if (otherIt == other.taskExecutions.end() || (record == otherIt->second) == false)
      {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const ProdigyMasterAuthorityRuntimeState& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyMasterAuthorityRuntimeState& state)
{
  serializer.value8b(state.generation);
  serializer.value1b(state.hasCompletedInitialMasterElection);
  serializer.object(state.transportTLSAuthority);
  serializer.value8b(state.nextMintedClientTlsGeneration);
  serializer.value8b(state.nextTlsResumptionGeneration);
  serializer.value8b(state.nextPendingAddMachinesOperationID);
  serializer.value8b(state.nextPendingElasticAddressOperationID);
  serializer.value8b(state.nextDNSIntentRevision);
  serializer.value8b(state.nextDnsControlPairingGeneration);
  serializer.object(state.tlsResumptionSnapshotsByWormhole);
  serializer.object(state.pendingAddMachinesOperations);
  serializer.object(state.pendingAutonomousProvisioningOperations);
  serializer.object(state.pendingElasticAddressAssignments);
  serializer.object(state.pendingElasticAddressReleases);
  serializer.object(state.statefulWorkerTopologyUpgradeOperations);
  serializer.object(state.deferredStatefulScaleIntents);
  serializer.object(state.machineSchemas);
  serializer.object(state.routableResourceLeases);
  serializer.object(state.dnsControlPairingLeases);
  serializer.object(state.publicTlsCertificates);
  serializer.object(state.privateTlsVaultLifecycles);
  serializer.object(state.taskExecutions);
  serializer.object(state.mothershipTunnelProviderDesiredState);
  serializer.object(state.updateSelf);
}

class ProdigyMasterAuthorityStateTransitionAck {
public:

  uint64_t generation = 0;
  uint128_t peerUUID = 0;
  int64_t peerBootNs = 0;
  String transitionDigest;
};

template <typename S>
static void serialize(S&& serializer, ProdigyMasterAuthorityStateTransitionAck& ack)
{
  serializer.value8b(ack.generation);
  serializer.value16b(ack.peerUUID);
  serializer.value8b(ack.peerBootNs);
  serializer.text1b(ack.transitionDigest, 64);
}

class ProdigyMetricSample {
public:

  int64_t ms = 0;
  uint64_t deploymentID = 0;
  uint128_t containerUUID = 0;
  uint64_t metricKey = 0;
  float value = 0;

  bool operator==(const ProdigyMetricSample& other) const
  {
    return ms == other.ms && deploymentID == other.deploymentID && containerUUID == other.containerUUID && metricKey == other.metricKey && value == other.value;
  }

  bool operator!=(const ProdigyMetricSample& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyMetricSample& sample)
{
  serializer.value8b(sample.ms);
  serializer.value8b(sample.deploymentID);
  serializer.value16b(sample.containerUUID);
  serializer.value8b(sample.metricKey);
  serializer.value4b(sample.value);
}

template <typename S>
static void prodigySerializeMetricSamplesWide(S&& serializer, Vector<ProdigyMetricSample>& samples)
{
  serializer.container(samples, UINT32_MAX, [](auto& nested, ProdigyMetricSample& sample) {
    nested.object(sample);
  });
}

class ProdigyMetricSamplesSnapshot {
public:

  Vector<ProdigyMetricSample> samples;
};

template <typename S>
static void serialize(S&& serializer, ProdigyMetricSamplesSnapshot& snapshot)
{
  prodigySerializeMetricSamplesWide(serializer, snapshot.samples);
}

class Scaler {
public:

  enum class Direction : uint8_t {
    upscale = 0,
    downscale = 1
  };

  String name;
  double percentile = 0; // percentile in (0, 100]
  uint32_t lookbackSeconds;
  double threshold;
  Direction direction = Direction::upscale; // some applications (like databases) might not downscale ever
  // Hard bounds for scaler-controlled targets. Zero means "unset/unbounded".
  uint32_t minValue = 0;
  uint32_t maxValue = 0;
};

class ProdigyMetrics {
public:

  enum class Builtin : uint8_t {
    runtimeContainerCpuUtilPct = 1,
    runtimeContainerMemoryUtilPct = 2,
    runtimeContainerStorageUtilPct = 3,
    runtimeIngressQueueWaitComposite = 4,
    runtimeIngressHandlerComposite = 5
  };

  constexpr static uint32_t defaultNeuronCollectionCadenceMs = 5000;

  constexpr static const char *runtimeContainerCpuUtilPctName = "runtime.container.cpu_util_pct";
  constexpr static const char *runtimeContainerMemoryUtilPctName = "runtime.container.memory_util_pct";
  constexpr static const char *runtimeContainerStorageUtilPctName = "runtime.container.storage_util_pct";
  constexpr static const char *runtimeIngressQueueWaitCompositeName = "runtime.ingress.queue_wait_us.composite";
  constexpr static const char *runtimeIngressHandlerCompositeName = "runtime.ingress.handler_us.composite";
  constexpr static const char *runtimeStatefulTopologyCutoverReadyName = "runtime.stateful.topology.cutover.ready";
  constexpr static const char *runtimeStatefulTopologyCutoverSourceEpochName = "runtime.stateful.topology.cutover.source_epoch";
  constexpr static const char *runtimeStatefulTopologyCutoverTargetEpochName = "runtime.stateful.topology.cutover.target_epoch";

  static uint64_t stableMetricHash(const uint8_t *bytes, uint64_t length)
  {
    // Metric names must hash consistently across processes/machines.
    // Do not use randomized per-thread seeds here.
    uint64_t hash = 1'469'598'103'934'665'603ULL; // FNV-1a offset basis
    for (uint64_t i = 0; i < length; i++)
    {
      hash ^= uint64_t(bytes[i]);
      hash *= 1'099'511'628'211ULL; // FNV-1a prime
    }

    return hash;
  }

  static uint64_t metricKeyForName(const String& metricName)
  {
    return stableMetricHash(reinterpret_cast<const uint8_t *>(metricName.data()), uint64_t(metricName.size()));
  }

  static uint64_t metricKeyForName(const char *metricName)
  {
    if (metricName == nullptr)
    {
      return 0;
    }
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(metricName);
    uint64_t length = 0;
    while (bytes[length] != '\0')
    {
      length += 1;
    }
    return stableMetricHash(bytes, length);
  }

  static const char *nameForBuiltin(Builtin metric)
  {
    switch (metric)
    {
      case Builtin::runtimeContainerCpuUtilPct:
        return runtimeContainerCpuUtilPctName;
      case Builtin::runtimeContainerMemoryUtilPct:
        return runtimeContainerMemoryUtilPctName;
      case Builtin::runtimeContainerStorageUtilPct:
        return runtimeContainerStorageUtilPctName;
      case Builtin::runtimeIngressQueueWaitComposite:
        return runtimeIngressQueueWaitCompositeName;
      case Builtin::runtimeIngressHandlerComposite:
        return runtimeIngressHandlerCompositeName;
    }

    return nullptr;
  }

  static const char *nameForScalingDimension(ScalingDimension dimension)
  {
    switch (dimension)
    {
      case ScalingDimension::cpu:
        return runtimeContainerCpuUtilPctName;
      case ScalingDimension::memory:
        return runtimeContainerMemoryUtilPctName;
      case ScalingDimension::storage:
        return runtimeContainerStorageUtilPctName;
      case ScalingDimension::runtimeIngressQueueWaitComposite:
        return runtimeIngressQueueWaitCompositeName;
      case ScalingDimension::runtimeIngressHandlerComposite:
        return runtimeIngressHandlerCompositeName;
      default:
        break;
    }

    return nullptr;
  }

  static uint64_t keyForBuiltin(Builtin metric)
  {
    return metricKeyForName(nameForBuiltin(metric));
  }

  static uint64_t keyForScalingDimension(ScalingDimension dimension)
  {
    const char *metricName = nameForScalingDimension(dimension);
    if (metricName == nullptr)
    {
      return 0;
    }

    return metricKeyForName(metricName);
  }

  constexpr static uint64_t maskForScalingDimension(ScalingDimension dimension)
  {
    return (uint64_t(1) << uint8_t(dimension));
  }

  constexpr static bool maskHasScalingDimension(uint64_t mask, ScalingDimension dimension)
  {
    return (mask & maskForScalingDimension(dimension)) > 0;
  }

  static uint64_t runtimeContainerCpuUtilPctKey(void)
  {
    static const uint64_t key = keyForBuiltin(Builtin::runtimeContainerCpuUtilPct);
    return key;
  }

  static uint64_t runtimeContainerMemoryUtilPctKey(void)
  {
    static const uint64_t key = keyForBuiltin(Builtin::runtimeContainerMemoryUtilPct);
    return key;
  }

  static uint64_t runtimeContainerStorageUtilPctKey(void)
  {
    static const uint64_t key = keyForBuiltin(Builtin::runtimeContainerStorageUtilPct);
    return key;
  }

  static uint64_t runtimeIngressQueueWaitCompositeKey(void)
  {
    static const uint64_t key = keyForBuiltin(Builtin::runtimeIngressQueueWaitComposite);
    return key;
  }

  static uint64_t runtimeIngressHandlerCompositeKey(void)
  {
    static const uint64_t key = keyForBuiltin(Builtin::runtimeIngressHandlerComposite);
    return key;
  }

  static uint64_t runtimeStatefulTopologyCutoverReadyKey(void)
  {
    static const uint64_t key = metricKeyForName(runtimeStatefulTopologyCutoverReadyName);
    return key;
  }

  static uint64_t runtimeStatefulTopologyCutoverSourceEpochKey(void)
  {
    static const uint64_t key = metricKeyForName(runtimeStatefulTopologyCutoverSourceEpochName);
    return key;
  }

  static uint64_t runtimeStatefulTopologyCutoverTargetEpochKey(void)
  {
    static const uint64_t key = metricKeyForName(runtimeStatefulTopologyCutoverTargetEpochName);
    return key;
  }
};

template <typename S>
static void serialize(S&& serializer, Scaler& scaler)
{
  serializer.text1b(scaler.name, UINT32_MAX);
  serializer.value8b(scaler.percentile);
  serializer.value4b(scaler.lookbackSeconds);
  serializer.value8b(scaler.threshold);
  serializer.value1b(scaler.direction);
  serializer.value4b(scaler.minValue);
  serializer.value4b(scaler.maxValue);
}

class HorizontalScaler : public Scaler {
public:

  ApplicationLifetime lifetime; // we'll have threshold for surge and for base with varying lookback periods and statistical operations
};

template <typename S>
static void serialize(S&& serializer, HorizontalScaler& scaler)
{
  serialize(serializer, static_cast<Scaler&>(scaler));

  serializer.value1b(scaler.lifetime);
}

class VerticalScaler : public Scaler {
public:

  ScalingDimension resource;
  uint32_t increment;
};

template <typename S>
static void serialize(S&& serializer, VerticalScaler& scaler)
{
  serialize(serializer, static_cast<Scaler&>(scaler));

  serializer.value1b(scaler.resource);
  serializer.value4b(scaler.increment);
}

class SubscriptionPairing {
public:

  uint128_t secret;
  uint128_t address; // this is the address of the advertiser
  uint64_t service;
  uint16_t port; // the port on which the advertiser advertises this service

  bool operator==(const SubscriptionPairing& other) const
  {
    return (secret == other.secret) && (address == other.address) && (service == other.service) && (port == other.port);
  }

  SubscriptionPairing() = default;
  SubscriptionPairing(uint128_t _secret, uint128_t _address, uint64_t _service, uint16_t _port)
      : secret(_secret),
        address(_address),
        service(_service),
        port(_port)
  {}
};

template <typename S>
static void serialize(S&& serializer, SubscriptionPairing& pairing)
{
  serializer.value16b(pairing.secret);
  serializer.value16b(pairing.address);
  serializer.value8b(pairing.service);
  serializer.value2b(pairing.port);
}

class AdvertisementPairing {
public:

  uint128_t secret;
  uint128_t address; // this is the address of the subscriber
  uint64_t service;

  bool operator==(const AdvertisementPairing& other) const
  {
    return (secret == other.secret) && (address == other.address) && (service == other.service);
  }

  AdvertisementPairing() = default;
  AdvertisementPairing(uint128_t _secret, uint128_t _address, uint64_t _service)
      : secret(_secret),
        address(_address),
        service(_service)
  {}
};

template <typename S>
static void serialize(S&& serializer, AdvertisementPairing& pairing)
{
  serializer.value16b(pairing.secret);
  serializer.value16b(pairing.address);
  serializer.value8b(pairing.service);
}

class ServiceBlueprint {
public:

  uint64_t service;
  ContainerState startAt;
  ContainerState stopAt;

  ServiceBlueprint(uint64_t _service, ContainerState _startAt, ContainerState _stopAt)
      : service(_service),
        startAt(_startAt),
        stopAt(_stopAt)
  {}
  ServiceBlueprint() = default;
};

static inline bool serviceBlueprintActiveAtContainerState(const ServiceBlueprint& blueprint, ContainerState state)
{
  switch (state)
  {
    case ContainerState::scheduled:
    case ContainerState::crashedRestarting:
      return blueprint.startAt == ContainerState::scheduled;
    case ContainerState::healthy:
      return blueprint.startAt == ContainerState::scheduled ||
             blueprint.startAt == ContainerState::healthy;
    default:
      return false;
  }
}

template <typename S>
static void serialize(S&& serializer, ServiceBlueprint& blueprint)
{
  serializer.value8b(blueprint.service);
  serializer.value1b(blueprint.startAt);
  serializer.value1b(blueprint.stopAt);
}

class Subscription : public ServiceBlueprint {
public:

  SubscriptionNature nature; // any, some, all

  Subscription(uint64_t _service, ContainerState _startAt, ContainerState _stopAt, SubscriptionNature _nature)
      : ServiceBlueprint(_service, _startAt, _stopAt),
        nature(_nature)
  {}
  Subscription() = default;
};

template <typename S>
static void serialize(S&& serializer, Subscription& subscription)
{
  serialize(serializer, static_cast<ServiceBlueprint&>(subscription));
  serializer.value1b(subscription.nature);
}

class Advertisement : public ServiceBlueprint {
public:

  uint16_t port; // if 0, chosen dynamically
  ServiceUserCapacity userCapacity;

  Advertisement(uint64_t _service, ContainerState _startAt, ContainerState _stopAt, uint16_t _port)
      : ServiceBlueprint(_service, _startAt, _stopAt),
        port(_port)
  {}
  Advertisement() = default;
};

template <typename S>
static void serialize(S&& serializer, Advertisement& advertisement)
{
  serialize(serializer, static_cast<ServiceBlueprint&>(advertisement));
  serializer.value2b(advertisement.port);
  serializer.object(advertisement.userCapacity);
}

class AssignedGPUDevice {
public:

  String vendor;
  String model;
  String busAddress;
  uint32_t memoryMB = 0;
};

enum class ContainerNetworkAccess : uint8_t {

  unrestricted = 0,
  declaredOnly = 1
};

template <typename S>
static void serialize(S&& serializer, AssignedGPUDevice& gpu)
{
  serializer.text1b(gpu.vendor, UINT32_MAX);
  serializer.text1b(gpu.model, UINT32_MAX);
  serializer.text1b(gpu.busAddress, UINT32_MAX);
  serializer.value4b(gpu.memoryMB);
}

class ContainerPlan {
public:

  uint128_t uuid;
  ApplicationConfig config;
  bytell_hash_map<uint64_t, Subscription> subscriptions;
  bytell_hash_map<uint64_t, Advertisement> advertisements;
  bytell_hash_subvector<uint64_t, SubscriptionPairing> subscriptionPairings;
  bytell_hash_subvector<uint64_t, AdvertisementPairing> advertisementPairings;
  bool restartOnFailure;
  uint32_t taskAttemptNumber = 0;

  uint8_t fragment;
  SystemContainerRuntimePlan system;
  Vector<Wormhole> wormholes;
  Vector<Whitehole> whiteholes;
  ContainerNetworkAccess networkAccess = ContainerNetworkAccess::unrestricted;
  bool useHostNetworkNamespace = false;
  Vector<IPPrefix> addresses; // directly assigned interface addresses; currently just the container-network IPv6
  Vector<uint32_t> assignedGPUMemoryMBs; // exact whole-GPU slots assigned to this container for accounting/restore
  Vector<AssignedGPUDevice> assignedGPUDevices; // physical GPU identity carried into the neuron runtime for namespace device injection

  // not used by neuron, but stored for safe keeping for when brain retires or ever crashes
  ApplicationLifetime lifetime; // brain will update this because canary -> reserved and surge -> reserved are possible
  ContainerState state; // neuron will update this itself
  bool runtimeReady = false; // neuron will update this itself
  int64_t createdAtMs;
  uint32_t shardGroup;
  uint32_t nShardGroups = 0;

  bool requiresDatacenterUniqueTag;
  bool isStateful = false;
  StatefulMeshRoles statefulMeshRoles;
  StatefulTopology statefulTopology;

  bool hasCredentialBundle = false;
  CredentialBundle credentialBundle;

  template <typename T>
  static bool extractFixedArgBounded(uint8_t *& cursor, uint8_t *terminal, T& value)
  {
    static_assert(std::is_trivially_copyable_v<T>);

    constexpr uintptr_t alignmentMask = uintptr_t(alignof(T) - 1);
    uintptr_t aligned = (reinterpret_cast<uintptr_t>(cursor) + alignmentMask) & ~alignmentMask;
    uint8_t *alignedCursor = reinterpret_cast<uint8_t *>(aligned);

    if (alignedCursor > terminal || (terminal - alignedCursor) < ptrdiff_t(sizeof(T)))
    {
      return false;
    }

    value = *reinterpret_cast<T *>(alignedCursor);
    cursor = alignedCursor + sizeof(T);
    return true;
  }

  bool updateAdvertisement(uint8_t *args, uint8_t *terminal)
  {
    // secret(16) address(16) service(8) [applicationID(2)] activate(1)
    AdvertisementPairing pairing;
    uint16_t applicationID = 0;
    bool activate;

    if (extractFixedArgBounded(args, terminal, pairing.secret) == false)
    {
      return false;
    }
    if (extractFixedArgBounded(args, terminal, pairing.address) == false)
    {
      return false;
    }
    if (extractFixedArgBounded(args, terminal, pairing.service) == false)
    {
      return false;
    }

    // Backward/forward compatibility:
    // some senders include applicationID before activate, others do not.
    if (terminal - args >= ptrdiff_t(sizeof(uint16_t) + sizeof(bool)))
    {
      if (extractFixedArgBounded(args, terminal, applicationID) == false)
      {
        return false;
      }
    }

    if (extractFixedArgBounded(args, terminal, activate) == false)
    {
      return false;
    }
    (void)applicationID;

    return applyAdvertisementPairing(pairing, activate);
  }

  bool applyAdvertisementPairing(const AdvertisementPairing& pairing, bool activate)
  {
    if (activate)
    {
      bool replaced = false;
      if (auto existingIt = advertisementPairings.find(pairing.service); existingIt != advertisementPairings.end())
      {
        Vector<AdvertisementPairing>& existing = existingIt->second;
        for (auto it = existing.begin(); it != existing.end();)
        {
          // Treat address+service as the stable endpoint identity for advertisements.
          // If a reconnect rotates secret without a prior deactivate, replace stale entry.
          if (it->address == pairing.address &&
              it->service == pairing.service &&
              it->secret != pairing.secret)
          {
            it = existing.erase(it);
            replaced = true;
          }
          else
          {
            ++it;
          }
        }
      }

      if (advertisementPairings.hasEntryFor(pairing.service, pairing) == false)
      {
        advertisementPairings.insert(pairing.service, pairing);
        return true;
      }

      return replaced;
    }

    bool erased = false;
    while (advertisementPairings.eraseEntry(pairing.service, pairing))
    {
      erased = true;
    }

    return erased;
  }

  bool updateSubscription(uint8_t *args, uint8_t *terminal)
  {
    // secret(16) address(16) service(8) port(2) [applicationID(2)] activate(1)
    SubscriptionPairing pairing;
    uint16_t applicationID = 0;
    bool activate;

    if (extractFixedArgBounded(args, terminal, pairing.secret) == false)
    {
      return false;
    }
    if (extractFixedArgBounded(args, terminal, pairing.address) == false)
    {
      return false;
    }
    if (extractFixedArgBounded(args, terminal, pairing.service) == false)
    {
      return false;
    }
    if (extractFixedArgBounded(args, terminal, pairing.port) == false)
    {
      return false;
    }

    // Backward/forward compatibility:
    // some senders include applicationID before activate, others do not.
    if (terminal - args >= ptrdiff_t(sizeof(uint16_t) + sizeof(bool)))
    {
      if (extractFixedArgBounded(args, terminal, applicationID) == false)
      {
        return false;
      }
    }

    if (extractFixedArgBounded(args, terminal, activate) == false)
    {
      return false;
    }
    (void)applicationID;

    return applySubscriptionPairing(pairing, activate);
  }

  bool applySubscriptionPairing(const SubscriptionPairing& pairing, bool activate)
  {
    if (activate)
    {
      bool replaced = false;
      if (auto existingIt = subscriptionPairings.find(pairing.service); existingIt != subscriptionPairings.end())
      {
        Vector<SubscriptionPairing>& existing = existingIt->second;
        for (auto it = existing.begin(); it != existing.end();)
        {
          // Treat address+service+port as the stable endpoint identity for subscriptions.
          // If a reconnect rotates secret without a prior deactivate, replace stale entry.
          if (it->address == pairing.address &&
              it->service == pairing.service &&
              it->port == pairing.port &&
              it->secret != pairing.secret)
          {
            it = existing.erase(it);
            replaced = true;
          }
          else
          {
            ++it;
          }
        }
      }

      if (subscriptionPairings.hasEntryFor(pairing.service, pairing) == false)
      {
        subscriptionPairings.insert(pairing.service, pairing);
        return true;
      }

      return replaced;
    }

    bool erased = false;
    while (subscriptionPairings.eraseEntry(pairing.service, pairing))
    {
      erased = true;
    }

    return erased;
  }

  void prepareForRestartSchedule(void)
  {
    state = ContainerState::scheduled;
  }

  bool isSystemContainer(void) const
  {
    return system.configured();
  }
  bool usesSharedCPUs(void) const
  {
    return isSystemContainer() == false && applicationUsesSharedCPUs(config);
  }
  bool usesIsolatedCPUs(void) const
  {
    return usesSharedCPUs() == false;
  }
  uint32_t logicalCores(void) const
  {
    return isSystemContainer() ? 1 : config.nLogicalCores;
  }
  uint32_t memoryMB(void) const
  {
    return isSystemContainer() ? 128 : config.memoryMB;
  }
  uint32_t filesystemMB(void) const
  {
    return isSystemContainer() ? 128 : config.filesystemMB;
  }
  uint32_t stopTimeoutSeconds(void) const
  {
    return isSystemContainer() ? 30 : config.sTilKillable;
  }
};

template <typename S>
static void serialize(S&& serializer, ContainerPlan& plan)
{
  serializer.value16b(plan.uuid);
  serializer.object(plan.config);

  serializer.ext(plan.subscriptions, bitsery::ext::BytellHashMap {}, [](S& serializer, uint64_t& service, Subscription& subscription) {
    serializer.value8b(service);
    serializer.object(subscription);
  });

  serializer.ext(plan.advertisements, bitsery::ext::BytellHashMap {}, [](S& serializer, uint64_t& service, Advertisement& advertisement) {
    serializer.value8b(service);
    serializer.object(advertisement);
  });

  serializer.ext(plan.subscriptionPairings, bitsery::ext::BytellHashSubvector {}, [](S& serializer, uint64_t& service, Vector<SubscriptionPairing>& pairings) {
    serializer.value8b(service);
    serializer.container(pairings, UINT32_MAX);
  });

  serializer.ext(plan.advertisementPairings, bitsery::ext::BytellHashSubvector {}, [](S& serializer, uint64_t& service, Vector<AdvertisementPairing>& pairings) {
    serializer.value8b(service);
    serializer.container(pairings, UINT32_MAX);
  });

  serializer.value1b(plan.restartOnFailure);
  serializer.value4b(plan.taskAttemptNumber);
  serializer.value1b(plan.fragment);
  serializer.object(plan.system);
  serializer.object(plan.wormholes);
  serializer.object(plan.whiteholes);
  serializer.value1b(plan.networkAccess);
  serializer.value1b(plan.useHostNetworkNamespace);
  serializer.object(plan.addresses);
  serializer.object(plan.assignedGPUMemoryMBs);
  serializer.object(plan.assignedGPUDevices);

  serializer.value1b(plan.lifetime);
  serializer.value1b(plan.state);
  serializer.value1b(plan.runtimeReady);
  serializer.value8b(plan.createdAtMs);
  serializer.value4b(plan.shardGroup);
  serializer.value4b(plan.nShardGroups);

  serializer.value1b(plan.requiresDatacenterUniqueTag);
  serializer.value1b(plan.isStateful);
  serializer.object(plan.statefulMeshRoles);
  serializer.object(plan.statefulTopology);
  serializer.value1b(plan.hasCredentialBundle);
  serializer.object(plan.credentialBundle);
}

class NeuronContainerMetricPolicy {
public:

  uint64_t scalingDimensionsMask = 0;
  uint32_t metricsCadenceMs = 0;
};

template <typename S>
static void serialize(S&& serializer, NeuronContainerMetricPolicy& policy)
{
  serializer.value8b(policy.scalingDimensionsMask);
  serializer.value4b(policy.metricsCadenceMs);
}

class NeuronContainerBootstrap {
public:

  ContainerPlan plan;
  NeuronContainerMetricPolicy metricPolicy;
};

template <typename S>
static void serialize(S&& serializer, NeuronContainerBootstrap& bootstrap)
{
  serializer.object(bootstrap.plan);
  serializer.object(bootstrap.metricPolicy);
}

class BrainReplicatedContainerRuntimeState {
public:

  uint128_t machineUUID = 0;
  uint32_t machinePrivate4 = 0;
  ContainerPlan plan;
  uint16_t runtimeLogicalCores = 0;
  uint32_t runtimeMemoryMB = 0;
  uint32_t runtimeStorageMB = 0;
};

template <typename S>
static void serialize(S&& serializer, BrainReplicatedContainerRuntimeState& state)
{
  serializer.value16b(state.machineUUID);
  serializer.value4b(state.machinePrivate4);
  serializer.object(state.plan);
  serializer.value2b(state.runtimeLogicalCores);
  serializer.value4b(state.runtimeMemoryMB);
  serializer.value4b(state.runtimeStorageMB);
}

class DeploymentPlan {
public:

  ApplicationConfig config;

  uint32_t minimumSubscriberCapacity; // UINT32_MAX for something like application server which load balancers subscribe to them then push traffic to, where capacity does not depend on stress because only a handful of load balancers

  // applications only use one or the other, not both. if both were given only the horizontal would be followed
  Vector<HorizontalScaler> horizontalScalers;
  Vector<VerticalScaler> verticalScalers; // implies stateful.neverShard

  bool isStateful; // we can't use unions of objects so this is easiest. and even if we subclassed, we'd still have to check the type then cast.. so this is ths same process and cleaner
  StatefulDeploymentPlan stateful;
  StatelessDeploymentPlan stateless;

  // Global canary requirements for all deployments
  uint32_t canaryCount;
  uint32_t canariesMustLiveForMinutes;

  Vector<Wormhole> wormholes; // these allow access to the application via the Internet
  Vector<WormholePublicTLSConfig> publicTLS;

  Vector<Whitehole> whiteholes;
  ContainerNetworkAccess networkAccess = ContainerNetworkAccess::unrestricted;

  bool useHostNetworkNamespace = false;

  Vector<Subscription> subscriptions;
  Vector<Advertisement> advertisements; // these do not include the base stateful services

  bool moveConstructively; // whether true or false, we'll always first attempt updates in place... also used when we're moving or compacting

  // custom data injectors
  bool requiresDatacenterUniqueTag;

  // optional credential policies (validated by brain against registered state)
  bool hasTlsIssuancePolicy = false;
  DeploymentTlsIssuancePolicy tlsIssuancePolicy;
  bool hasApiCredentialPolicy = false;
  DeploymentApiCredentialPolicy apiCredentialPolicy;
};

template <typename S>
static void serialize(S&& serializer, DeploymentPlan& plan)
{
  serializer.object(plan.config);
  serializer.value4b(plan.minimumSubscriberCapacity);
  serializer.object(plan.horizontalScalers);
  serializer.object(plan.verticalScalers);

  serializer.value1b(plan.isStateful);
  serializer.object(plan.stateful);
  serializer.object(plan.stateless);

  serializer.value4b(plan.canaryCount);
  serializer.value4b(plan.canariesMustLiveForMinutes);

  serializer.object(plan.wormholes);
  serializer.object(plan.publicTLS);

  serializer.object(plan.whiteholes);
  serializer.value1b(plan.networkAccess);

  serializer.value1b(plan.useHostNetworkNamespace);

  serializer.object(plan.subscriptions);
  serializer.object(plan.advertisements);

  serializer.value1b(plan.moveConstructively);
  serializer.value1b(plan.requiresDatacenterUniqueTag);

  serializer.value1b(plan.hasTlsIssuancePolicy);
  serializer.object(plan.tlsIssuancePolicy);
  serializer.value1b(plan.hasApiCredentialPolicy);
  serializer.object(plan.apiCredentialPolicy);
}

class ProdigyPersistentMasterAuthorityPackage {
public:

  bytell_hash_map<uint16_t, ApplicationTlsVaultFactory> tlsVaultFactoriesByApp;
  bytell_hash_map<uint16_t, ApplicationApiCredentialSet> apiCredentialSetsByApp;
  bytell_hash_map<String, uint16_t> reservedApplicationIDsByName;
  bytell_hash_map<uint16_t, String> reservedApplicationNamesByID;
  Vector<ApplicationServiceIdentity> reservedApplicationServices;
  uint16_t nextReservableApplicationID = 1;
  bytell_hash_map<uint64_t, DeploymentPlan> deploymentPlans;
  bytell_hash_map<uint64_t, String> failedDeployments;
  ProdigyMasterAuthorityRuntimeState runtimeState;
};

template <typename Key, typename Value>
class ProdigyPersistentMapEntry {
public:

  Key key = {};
  Value value = {};
};

template <typename Key, typename Value>
class ProdigyPersistentMapEntryRef {
public:

  const Key *key = nullptr;
  const Value *value = nullptr;
};

template <typename T>
struct ProdigyPersistentSerializerIsWriter : std::false_type {
};

template <typename OutputAdapter, typename Context>
struct ProdigyPersistentSerializerIsWriter<bitsery::Serializer<OutputAdapter, Context>> : std::true_type {
};

static inline bool prodigyPersistentStringComesBefore(const String& lhs, const String& rhs)
{
  size_t common = std::min(lhs.size(), rhs.size());
  int cmp = std::memcmp(lhs.data(), rhs.data(), common);
  if (cmp != 0)
  {
    return cmp < 0;
  }

  return lhs.size() < rhs.size();
}

template <typename S, typename Key, typename Value, typename SerializeKey, typename SerializeValue, typename Compare>
static void prodigyWritePersistentMapAsEntries(
    S&& serializer,
    bytell_hash_map<Key, Value>& map,
    SerializeKey&& serializeKey,
    SerializeValue&& serializeValue,
    Compare&& compare)
{
  Vector<ProdigyPersistentMapEntryRef<Key, Value>> entries = {};
  entries.reserve(map.size());
  for (const auto& [key, value] : map)
  {
    entries.push_back(ProdigyPersistentMapEntryRef<Key, Value> {&key, &value});
  }

  std::sort(entries.begin(), entries.end(), [&](const auto& lhs, const auto& rhs) -> bool {
    return compare(*lhs.key, *rhs.key);
  });
  serializer.container(entries, UINT32_MAX, [&](S& serializer, ProdigyPersistentMapEntryRef<Key, Value>& entry) {
    serializeKey(serializer, const_cast<Key&>(*entry.key));
    serializeValue(serializer, const_cast<Value&>(*entry.value));
  });
}

template <typename S, typename Key, typename Value, typename SerializeKey, typename SerializeValue, typename Compare>
static void prodigyReadPersistentMapAsEntries(
    S&& serializer,
    bytell_hash_map<Key, Value>& map,
    SerializeKey&& serializeKey,
    SerializeValue&& serializeValue,
    Compare&& compare)
{
  Vector<ProdigyPersistentMapEntry<Key, Value>> entries = {};
  serializer.container(entries, UINT32_MAX, [&](S& serializer, ProdigyPersistentMapEntry<Key, Value>& entry) {
    serializeKey(serializer, entry.key);
    serializeValue(serializer, entry.value);
  });

  if (serializer.adapter().error() != bitsery::ReaderError::NoError)
  {
    return;
  }

  std::sort(entries.begin(), entries.end(), [&](const auto& lhs, const auto& rhs) -> bool {
    return compare(lhs.key, rhs.key);
  });

  bytell_hash_map<Key, Value> decoded = {};
  decoded.reserve(entries.size());
  for (ProdigyPersistentMapEntry<Key, Value>& entry : entries)
  {
    decoded.insert_or_assign(std::move(entry.key), std::move(entry.value));
  }

  map.swap(decoded);
}

template <typename S, typename Key, typename Value, typename SerializeKey, typename SerializeValue, typename Compare>
static void prodigySerializePersistentMapAsEntries(
    S&& serializer,
    bytell_hash_map<Key, Value>& map,
    SerializeKey&& serializeKey,
    SerializeValue&& serializeValue,
    Compare&& compare)
{
  using Serializer = std::remove_cv_t<std::remove_reference_t<S>>;
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    prodigyWritePersistentMapAsEntries(
        serializer,
        map,
        std::forward<SerializeKey>(serializeKey),
        std::forward<SerializeValue>(serializeValue),
        std::forward<Compare>(compare));
  }
  else
  {
    prodigyReadPersistentMapAsEntries(
        serializer,
        map,
        std::forward<SerializeKey>(serializeKey),
        std::forward<SerializeValue>(serializeValue),
        std::forward<Compare>(compare));
  }
}

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentMasterAuthorityPackage& package)
{
  const char *persistTraceValue = std::getenv("PRODIGY_PERSIST_TRACE");
  bool persistTrace = persistTraceValue != nullptr && persistTraceValue[0] != '\0' && persistTraceValue[0] != '0';

  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package tlsVaultFactoriesByApp begin\n");
    std::fflush(stderr);
  }
  serializer.object(package.tlsVaultFactoriesByApp);
  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package tlsVaultFactoriesByApp end\n");
    std::fflush(stderr);
  }

  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package apiCredentialSetsByApp begin\n");
    std::fflush(stderr);
  }
  serializer.object(package.apiCredentialSetsByApp);
  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package apiCredentialSetsByApp end\n");
    std::fflush(stderr);
  }

  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package reservedApplicationIDsByName begin\n");
    std::fflush(stderr);
  }
  prodigySerializePersistentMapAsEntries(
      serializer,
      package.reservedApplicationIDsByName,
      [](S& serializer, String& key) {
        serializer.text1b(key, UINT32_MAX);
      },
      [](S& serializer, uint16_t& value) {
        serializer.value2b(value);
      },
      [](const String& lhs, const String& rhs) -> bool {
        return prodigyPersistentStringComesBefore(lhs, rhs);
      });
  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package reservedApplicationIDsByName end\n");
    std::fflush(stderr);
  }

  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package reservedApplicationNamesByID begin\n");
    std::fflush(stderr);
  }
  prodigySerializePersistentMapAsEntries(
      serializer,
      package.reservedApplicationNamesByID,
      [](S& serializer, uint16_t& key) {
        serializer.value2b(key);
      },
      [](S& serializer, String& value) {
        serializer.text1b(value, UINT32_MAX);
      },
      [](const uint16_t& lhs, const uint16_t& rhs) -> bool {
        return lhs < rhs;
      });
  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package reservedApplicationNamesByID end\n");
    std::fflush(stderr);
  }

  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package reservedApplicationServices begin\n");
    std::fflush(stderr);
  }
  serializer.object(package.reservedApplicationServices);
  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package reservedApplicationServices end\n");
    std::fflush(stderr);
  }

  serializer.value2b(package.nextReservableApplicationID);

  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package deploymentPlans begin\n");
    std::fflush(stderr);
  }
  serializer.object(package.deploymentPlans);
  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package deploymentPlans end\n");
    std::fflush(stderr);
  }

  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package failedDeployments begin\n");
    std::fflush(stderr);
  }
  serializer.object(package.failedDeployments);
  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package failedDeployments end\n");
    std::fflush(stderr);
  }

  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package runtimeState begin\n");
    std::fflush(stderr);
  }
  serializer.object(package.runtimeState);
  if (persistTrace)
  {
    std::fprintf(stderr, "prodigy persist package runtimeState end\n");
    std::fflush(stderr);
  }
}

class ContainerParameters { // startup payload for container launch; stateful mesh and topology metadata use the full serializer path
public:

  uint128_t uuid;
  uint64_t deploymentID = 0;
  uint32_t taskAttemptNumber = 0;

  uint32_t memoryMB;
  uint32_t storageMB;
  uint16_t nLogicalCores;
  Vector<int32_t> isolatedChildCgroups;
  ApplicationCPUMode cpuMode = ApplicationCPUMode::isolated;
  uint32_t requestedCPUMillis = 0;

  int neuronFD;
  int lowCPU;
  int highCPU;

  bytell_hash_map<uint64_t, uint16_t> advertisesOnPorts;
  bytell_hash_subvector<uint64_t, SubscriptionPairing> subscriptionPairings;
  bytell_hash_subvector<uint64_t, AdvertisementPairing> advertisementPairings;

  IPPrefix private6;
  Vector<Wormhole> wormholes;
  Vector<Whitehole> whiteholes;

  bool justCrashed; // restartable containers would receive this

  uint8_t datacenterUniqueTag = 0;

  bool hasCredentialBundle = false;
  CredentialBundle credentialBundle;
  StatefulMeshRoles statefulMeshRoles;
  StatefulTopology statefulTopology;

  Vector<uint64_t> flags;
};

template <typename S>
static void serialize(S&& serializer, ContainerParameters& params)
{
  serializer.value16b(params.uuid);
  serializer.value8b(params.deploymentID);
  serializer.value4b(params.taskAttemptNumber);
  serializer.value4b(params.memoryMB);
  serializer.value4b(params.storageMB);
  serializer.value2b(params.nLogicalCores);
  serializer.container(params.isolatedChildCgroups, 64, [](S& s, int32_t& fd) {
    s.value4b(fd);
  });
  serializer.value1b(params.cpuMode);
  serializer.value4b(params.requestedCPUMillis);

  serializer.value4b(params.neuronFD);
  serializer.value4b(params.lowCPU);
  serializer.value4b(params.highCPU);

  serializer.ext(params.advertisesOnPorts, bitsery::ext::BytellHashMap {}, [](S& serializer, uint64_t& service, uint16_t& port) {
    serializer.value8b(service);
    serializer.value2b(port);
  });

  serializer.ext(params.subscriptionPairings, bitsery::ext::BytellHashSubvector {}, [](S& serializer, uint64_t& service, Vector<SubscriptionPairing>& pairings) {
    serializer.value8b(service);
    serializer.container(pairings, UINT32_MAX);
  });

  serializer.ext(params.advertisementPairings, bitsery::ext::BytellHashSubvector {}, [](S& serializer, uint64_t& service, Vector<AdvertisementPairing>& pairings) {
    serializer.value8b(service);
    serializer.container(pairings, UINT32_MAX);
  });

  serializer.object(params.private6);
  serializer.object(params.wormholes);
  serializer.object(params.whiteholes);

  serializer.value1b(params.justCrashed);
  serializer.value1b(params.datacenterUniqueTag);

  serializer.value1b(params.hasCredentialBundle);
  serializer.object(params.credentialBundle);
  serializer.object(params.statefulMeshRoles);
  serializer.object(params.statefulTopology);

  serializer.container8b(params.flags, UINT32_MAX);
}
