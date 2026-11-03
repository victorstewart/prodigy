#pragma once

// Typed contracts for bounded physical-boundary fault requests.  These are
// deliberately authorization and receipt contracts only: an executor must be
// separately sealed to these exact identities and may not accept shell, route,
// interface, namespace, or provider identifiers from a caller.

#include <cstdint>
#include <cstring>
#include <string_view>
#include <arpa/inet.h>

#include <prodigy/mothership/mothership.cluster.types.h>

constexpr static uint32_t mothershipPhysicalFaultMaximumDurationMilliseconds = 60'000;
constexpr static uint32_t mothershipPhysicalFaultRestorationSlackMilliseconds = 5'000;
constexpr static uint32_t mothershipLocalVMFaultMaximumRecoveryMilliseconds = 300'000;
constexpr static uint32_t mothershipLocalAuthorityRecoveryArmDelayMilliseconds = 60'000;
constexpr static uint32_t mothershipLocalAuthorityRecoveryReleaseGraceMilliseconds = 30'000;
constexpr static uint32_t mothershipLocalAuthorityRecoveryMinimumTimeoutMilliseconds = 120'000;
// This is a provider-owned task directory, not caller-controlled execution
// data. The sealed guest executor creates it only beneath /var/lib/prodigy
// after proving that parent is root-owned and not group/world writable.
constexpr static auto mothershipPhysicalFaultProviderStateRoot =
    "/var/lib/prodigy/mothership-physical-faults"_ctv;
constexpr static const char *mothershipVerifiedLocalVMMarkerPath = "/run/prodigy-disposable-linux";
constexpr static auto mothershipVerifiedLocalVMMarker = "prodigy-disposable-linux-v1"_ctv;

// Sealed provider interfaces use one fixed-width wire identity rather than
// the operator-facing canonical hexadecimal form (which carries a 0x prefix
// and omits leading zeroes).  Keep this formatter beside the typed provider
// contracts so local-VM, physical-fault, and production-pair owners cannot
// silently diverge at their Python execution boundaries.
static inline void mothershipAssignProviderHex128(uint128_t value, String& output)
{
  constexpr static char digits[] = "0123456789abcdef";
  output.clear();
  for (int32_t shift = 124; shift >= 0; shift -= 4)
    output.append(digits[uint8_t((value >> shift) & 0xf)]);
}

// The disposable KVM owner writes the root-only marker only after proving KVM,
// Linux machine identity, and the exact QEMU DMI UUID.  The local seed uses
// that UUID as its Prodigy machine UUID so the later outer-owner registration
// binds the topology identity to the actual guest process.
static inline bool mothershipParseVerifiedLocalVMIdentity(const String& marker,
                                                          const String& productUUID,
                                                          uint128_t& machineUUID)
{
  machineUUID = 0;
  String normalizedMarker = marker;
  while (!normalizedMarker.empty() &&
         (normalizedMarker[normalizedMarker.size() - 1] == '\n' ||
          normalizedMarker[normalizedMarker.size() - 1] == '\r'))
    normalizedMarker.resize(normalizedMarker.size() - 1);
  if (!normalizedMarker.equal(mothershipVerifiedLocalVMMarker)) return false;

  uint128_t parsed = 0;
  uint32_t digits = 0;
  for (char byte : productUUID)
  {
    if (byte == '-' || byte == '\n' || byte == '\r') continue;
    uint8_t nibble = 0;
    if (byte >= '0' && byte <= '9') nibble = uint8_t(byte - '0');
    else if (byte >= 'a' && byte <= 'f') nibble = uint8_t(byte - 'a' + 10);
    else if (byte >= 'A' && byte <= 'F') nibble = uint8_t(byte - 'A' + 10);
    else return false;
    if (++digits > 32) return false;
    parsed = (parsed << 4) | nibble;
  }
  if (digits != 32 || parsed == 0) return false;
  machineUUID = parsed;
  return true;
}

static inline bool mothershipLocalVMGuestUUIDMatches(uint128_t machineUUID,
                                                     std::string_view guestUUID)
{
  if (machineUUID == 0) return false;
  uint128_t parsed = 0;
  uint32_t digits = 0;
  for (char byte : guestUUID)
  {
    if (byte == '-') continue;
    uint8_t nibble = 0;
    if (byte >= '0' && byte <= '9') nibble = uint8_t(byte - '0');
    else if (byte >= 'a' && byte <= 'f') nibble = uint8_t(byte - 'a' + 10);
    else if (byte >= 'A' && byte <= 'F') nibble = uint8_t(byte - 'A' + 10);
    else return false;
    if (++digits > 32) return false;
    parsed = (parsed << 4) | nibble;
  }
  return digits == 32 && parsed == machineUUID;
}

enum class MothershipPhysicalFaultDirection : uint8_t {
  both = 0,
  sourceToTarget = 1,
  targetToSource = 2,
};

// A non-peer path fault must retain the admitted gateway and flow identity;
// this prevents a MASQUE or BGP request from being treated as a generic route.
enum class MothershipPhysicalFaultFlowTarget : uint8_t {
  peerHost = 0,
  masqueGateway = 1,
  bgpControlPlane = 2,
};

enum class MothershipLocalVMMachineFaultAction : uint8_t {
  crash = 0,
  coldReboot = 1,
  recoverUnreadyUpgrade = 2,
};

enum class MothershipPhysicalFaultExecutorKind : uint8_t {
  localVM = 0,
  providerCloudVM = 1,
};

// One physical service path admitted by Mothership after it has observed the
// exact active COUSIN generation on both clusters.  The runtime continues to
// own the route; this record only binds the two concrete machines on which a
// bounded fault may be installed and the receipt for that admission.
class MothershipPhysicalServiceTransitBoundary {
public:
  static constexpr uint32_t version = 3;
  uint32_t protocolVersion = version;
  uint128_t boundaryUUID = 0;
  uint128_t pairOperationUUID = 0;
  uint128_t routeUUID = 0;
  uint64_t routeGeneration = 0;
  uint128_t sourceClusterUUID = 0;
  uint128_t targetClusterUUID = 0;
  uint128_t sourceMachineUUID = 0;
  uint128_t targetMachineUUID = 0;
  MothershipPhysicalFaultExecutorKind sourceExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  MothershipPhysicalFaultExecutorKind targetExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  uint128_t sourceLocalVMBoundaryUUID = 0;
  uint128_t targetLocalVMBoundaryUUID = 0;
  String sourceCloudID;
  String targetCloudID;
  String sourceAddress;
  String targetAddress;
  uint16_t sourceTCPPort = 0;
  uint16_t targetTCPPort = 0;
  uint16_t pathMTU = 0;
  String routeAuthorizationSHA256;
  String admissionReceiptSHA256;
  String cleanupReceiptSHA256;
  int64_t admittedAtMs = 0;
  bool closed = false;
};
template <typename S>
static void serialize(S&& serializer, MothershipPhysicalServiceTransitBoundary& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.boundaryUUID);
  serializer.value16b(value.pairOperationUUID); serializer.value16b(value.routeUUID);
  serializer.value8b(value.routeGeneration); serializer.value16b(value.sourceClusterUUID);
  serializer.value16b(value.targetClusterUUID); serializer.value16b(value.sourceMachineUUID);
  serializer.value16b(value.targetMachineUUID); serializer.value1b(value.sourceExecutorKind);
  serializer.value1b(value.targetExecutorKind); serializer.value16b(value.sourceLocalVMBoundaryUUID);
  serializer.value16b(value.targetLocalVMBoundaryUUID); serializer.text1b(value.sourceCloudID, 1024);
  serializer.text1b(value.targetCloudID, 1024); serializer.text1b(value.sourceAddress, INET6_ADDRSTRLEN);
  serializer.text1b(value.targetAddress, INET6_ADDRSTRLEN); serializer.value2b(value.sourceTCPPort);
  serializer.value2b(value.targetTCPPort);
  serializer.value2b(value.pathMTU); serializer.text1b(value.routeAuthorizationSHA256, 64);
  serializer.text1b(value.admissionReceiptSHA256, 64); serializer.text1b(value.cleanupReceiptSHA256, 64);
  serializer.value8b(value.admittedAtMs);
  serializer.value1b(value.closed);
}

// The outer KVM process is deliberately distinct from the guest registered in
// the cluster.  Mothership authenticates this host with the pinned key and
// stages its embedded launcher into one sealed remote descriptor before every
// use. The persisted digest identifies Mothership-owned bytes; only the state
// path is supplied by the registering operator.
class MothershipLocalVMBoundaryDescriptor {
public:
  static constexpr uint32_t version = 2;
  uint32_t protocolVersion = version;
  uint128_t vmBoundaryUUID = 0;
  uint128_t clusterUUID = 0;
  uint128_t machineUUID = 0;
  String taskID;
  String hostAddress;
  uint16_t hostPort = 22;
  String hostUser;
  String hostPrivateKeyPath;
  String hostPublicKeyOpenSSH;
  String statePath;
  String executorSHA256;
  String immutableStateSHA256;
  int64_t registeredAtMs = 0;
  bool retired = false;
};

template <typename S>
static void serialize(S&& serializer, MothershipLocalVMBoundaryDescriptor& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.vmBoundaryUUID);
  serializer.value16b(value.clusterUUID); serializer.value16b(value.machineUUID);
  serializer.text1b(value.taskID, 63); serializer.text1b(value.hostAddress, INET6_ADDRSTRLEN);
  serializer.value2b(value.hostPort);
  serializer.text1b(value.hostUser, 64); serializer.text1b(value.hostPrivateKeyPath, 4096);
  serializer.text1b(value.hostPublicKeyOpenSSH, 1024); serializer.text1b(value.statePath, 4096);
  serializer.text1b(value.executorSHA256, 64);
  serializer.text1b(value.immutableStateSHA256, 64); serializer.value8b(value.registeredAtMs);
  serializer.value1b(value.retired);
}

static inline bool mothershipPhysicalFaultDigestValid(const String& value)
{
  if (value.size() != 64) return false;
  for (char byte : value)
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) return false;
  return true;
}

static inline bool mothershipPhysicalFaultNumericAddressValid(const String& value)
{
  String owned = value;
  struct in_addr address4 = {};
  struct in6_addr address6 = {};
  return !owned.empty() && (inet_pton(AF_INET, owned.c_str(), &address4) == 1 ||
                            inet_pton(AF_INET6, owned.c_str(), &address6) == 1);
}

static inline bool mothershipPhysicalFaultFlowTargetValid(MothershipPhysicalFaultFlowTarget value)
{
  return value == MothershipPhysicalFaultFlowTarget::peerHost ||
      value == MothershipPhysicalFaultFlowTarget::masqueGateway ||
      value == MothershipPhysicalFaultFlowTarget::bgpControlPlane;
}

static inline bool mothershipPhysicalFaultFlowIdentityValid(const String& value)
{
  if (value.empty() || value.size() > 256) return false;
  for (char byte : value)
    if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
          (byte >= '0' && byte <= '9') || byte == '.' || byte == '_' || byte == ':' ||
          byte == '@' || byte == '/' || byte == '+' || byte == '=' || byte == '-')) return false;
  return true;
}

static inline bool mothershipPhysicalFaultSafeAbsolutePath(const String& value)
{
  if (value.empty() || value.size() > 4096 || value[0] != '/') return false;
  char prior = '\0';
  for (char byte : value)
  {
    if (prior == '.' && byte == '.') return false;
    if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
          (byte >= '0' && byte <= '9') || byte == '/' || byte == '.' ||
          byte == '_' || byte == '-')) return false;
    prior = byte;
  }
  return true;
}

static inline bool mothershipPhysicalFaultProviderStateRootValid(const String& value)
{
  return value.equal(mothershipPhysicalFaultProviderStateRoot);
}

static inline bool mothershipPhysicalFaultSafeSSHUser(const String& value)
{
  if (value.empty() || value.size() > 64) return false;
  for (char byte : value)
    if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
          (byte >= '0' && byte <= '9') || byte == '_' || byte == '-')) return false;
  return true;
}

static inline bool mothershipPhysicalFaultSafeTaskID(const String& value)
{
  if (value.empty() || value.size() > 63 || value[0] < 'a' || value[0] > 'z') return false;
  for (char byte : value)
    if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '-')) return false;
  return true;
}

static inline bool mothershipPhysicalFaultCloudIDValid(const String& value)
{
  if (value.empty() || value.size() > 1024) return false;
  for (char byte : value)
    if (byte == '\0' || byte == '\n' || byte == '\r' || static_cast<unsigned char>(byte) < 0x20) return false;
  return true;
}

static inline bool mothershipPhysicalFaultExecutorIdentityValid(
    MothershipPhysicalFaultExecutorKind kind, uint128_t localVMBoundaryUUID,
    const String& cloudID)
{
  if (kind == MothershipPhysicalFaultExecutorKind::localVM)
    return localVMBoundaryUUID != 0 && cloudID.empty();
  if (kind == MothershipPhysicalFaultExecutorKind::providerCloudVM)
    return localVMBoundaryUUID == 0 && mothershipPhysicalFaultCloudIDValid(cloudID);
  return false;
}

static inline bool mothershipPhysicalServiceTransitBoundaryValid(
    const MothershipPhysicalServiceTransitBoundary& value, String *failure = nullptr)
{
  if (failure) failure->clear();
  if (value.protocolVersion != MothershipPhysicalServiceTransitBoundary::version ||
      value.boundaryUUID == 0 || value.pairOperationUUID == 0 || value.routeUUID == 0 ||
      value.routeGeneration == 0 || value.sourceClusterUUID == 0 || value.targetClusterUUID == 0 ||
      value.sourceClusterUUID == value.targetClusterUUID || value.sourceMachineUUID == 0 ||
      value.targetMachineUUID == 0 ||
      !mothershipPhysicalFaultExecutorIdentityValid(value.sourceExecutorKind,
                                                     value.sourceLocalVMBoundaryUUID,
                                                     value.sourceCloudID) ||
      !mothershipPhysicalFaultExecutorIdentityValid(value.targetExecutorKind,
                                                     value.targetLocalVMBoundaryUUID,
                                                     value.targetCloudID) ||
      !mothershipPhysicalFaultNumericAddressValid(value.sourceAddress) ||
      !mothershipPhysicalFaultNumericAddressValid(value.targetAddress) || value.sourceTCPPort == 0 ||
      value.targetTCPPort == 0 ||
      value.pathMTU < 1280 || value.pathMTU > 9000 ||
      !mothershipPhysicalFaultDigestValid(value.routeAuthorizationSHA256) ||
      !mothershipPhysicalFaultDigestValid(value.admissionReceiptSHA256) ||
      (value.closed ? !mothershipPhysicalFaultDigestValid(value.cleanupReceiptSHA256) :
                      !value.cleanupReceiptSHA256.empty()) || value.admittedAtMs <= 0)
  {
    if (failure) failure->assign("physical service transit requires an exact active route, endpoint machines, and admission receipt"_ctv);
    return false;
  }
  return true;
}

static inline bool mothershipPhysicalServiceTransitBoundaryEqual(
    const MothershipPhysicalServiceTransitBoundary& left,
    const MothershipPhysicalServiceTransitBoundary& right)
{
  String leftBytes = {}, rightBytes = {};
  auto leftCopy = left; auto rightCopy = right;
  BitseryEngine::serialize(leftBytes, leftCopy); BitseryEngine::serialize(rightBytes, rightCopy);
  return leftBytes == rightBytes;
}

static inline bool mothershipLocalVMBoundaryDescriptorValid(
    const MothershipLocalVMBoundaryDescriptor& value, String *failure = nullptr)
{
  if (failure) failure->clear();
  if (value.protocolVersion != MothershipLocalVMBoundaryDescriptor::version ||
      value.vmBoundaryUUID == 0 || value.clusterUUID == 0 || value.machineUUID == 0 ||
      !mothershipPhysicalFaultSafeTaskID(value.taskID) ||
      !mothershipPhysicalFaultNumericAddressValid(value.hostAddress) || value.hostPort == 0 ||
      !mothershipPhysicalFaultSafeSSHUser(value.hostUser) ||
      !mothershipPhysicalFaultSafeAbsolutePath(value.hostPrivateKeyPath) ||
      value.hostPublicKeyOpenSSH.size() < 32 || value.hostPublicKeyOpenSSH.size() > 1024 ||
      value.hostPublicKeyOpenSSH.size() < 12 ||
      std::memcmp(value.hostPublicKeyOpenSSH.data(), "ssh-ed25519 ", 12) != 0 ||
      !mothershipPhysicalFaultSafeAbsolutePath(value.statePath) ||
      !mothershipPhysicalFaultDigestValid(value.executorSHA256) ||
      !mothershipPhysicalFaultDigestValid(value.immutableStateSHA256) || value.registeredAtMs <= 0)
  {
    if (failure) failure->assign("local VM boundary requires exact pinned host, executor, state, cluster, and machine identities"_ctv);
    return false;
  }
  return true;
}

static inline bool mothershipLocalVMBoundaryDescriptorEqual(
    const MothershipLocalVMBoundaryDescriptor& left,
    const MothershipLocalVMBoundaryDescriptor& right)
{
  String leftBytes = {}, rightBytes = {};
  auto leftCopy = left; auto rightCopy = right;
  BitseryEngine::serialize(leftBytes, leftCopy); BitseryEngine::serialize(rightBytes, rightCopy);
  return leftBytes == rightBytes;
}

// A sealed launcher refresh is intentionally narrower than boundary
// registration: all execution identity and immutable provider-state evidence
// remains pinned, and only the proven launcher digest may rotate.
static inline bool mothershipLocalVMBoundaryDescriptorSameIdentityAndState(
    const MothershipLocalVMBoundaryDescriptor& left,
    const MothershipLocalVMBoundaryDescriptor& right)
{
  return left.protocolVersion == right.protocolVersion &&
      left.vmBoundaryUUID == right.vmBoundaryUUID && left.clusterUUID == right.clusterUUID &&
      left.machineUUID == right.machineUUID && left.taskID == right.taskID &&
      left.hostAddress == right.hostAddress && left.hostPort == right.hostPort &&
      left.hostUser == right.hostUser && left.hostPrivateKeyPath == right.hostPrivateKeyPath &&
      left.hostPublicKeyOpenSSH == right.hostPublicKeyOpenSSH && left.statePath == right.statePath &&
      left.immutableStateSHA256 == right.immutableStateSHA256 &&
      left.registeredAtMs == right.registeredAtMs && !left.retired && !right.retired;
}

static inline bool mothershipPhysicalFaultDirectionValid(MothershipPhysicalFaultDirection value)
{
  return value == MothershipPhysicalFaultDirection::both ||
      value == MothershipPhysicalFaultDirection::sourceToTarget ||
      value == MothershipPhysicalFaultDirection::targetToSource;
}

static inline bool mothershipLocalVMMachineFaultActionValid(MothershipLocalVMMachineFaultAction value)
{
  return value == MothershipLocalVMMachineFaultAction::crash ||
      value == MothershipLocalVMMachineFaultAction::coldReboot ||
      value == MothershipLocalVMMachineFaultAction::recoverUnreadyUpgrade;
}

// An observation is an opaque, versioned digest emitted by the sealed owner.
// Mothership binds it to the exact cluster/machine identity before accepting a
// receipt; it never treats a free-form executor message as proof.
class MothershipPhysicalFaultMachineObservation {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t clusterUUID = 0;
  uint128_t machineUUID = 0;
  uint64_t topologyVersion = 0;
  String stateSHA256;
};

template <typename S>
static void serialize(S&& serializer, MothershipPhysicalFaultMachineObservation& value)
{
  serializer.value4b(value.protocolVersion);
  serializer.value16b(value.clusterUUID);
  serializer.value16b(value.machineUUID);
  serializer.value8b(value.topologyVersion);
  serializer.text1b(value.stateSHA256, 64);
}

static inline bool mothershipPhysicalFaultMachineObservationValid(
    const MothershipPhysicalFaultMachineObservation& value)
{
  return value.protocolVersion == MothershipPhysicalFaultMachineObservation::version &&
      value.clusterUUID != 0 && value.machineUUID != 0 && value.topologyVersion != 0 &&
      mothershipPhysicalFaultDigestValid(value.stateSHA256);
}

static inline bool mothershipPhysicalFaultMachineObservationEqual(
    const MothershipPhysicalFaultMachineObservation& left,
    const MothershipPhysicalFaultMachineObservation& right)
{
  return left.protocolVersion == right.protocolVersion && left.clusterUUID == right.clusterUUID &&
      left.machineUUID == right.machineUUID && left.topologyVersion == right.topologyVersion &&
      left.stateSHA256 == right.stateSHA256;
}

class MothershipPhysicalClusterNetworkFaultRequest {
public:
  static constexpr uint32_t version = 3;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0; // idempotency key; never reused for another request
  uint128_t boundaryUUID = 0;  // durable, pre-admitted physical boundary
  uint128_t sourceClusterUUID = 0;
  uint128_t targetClusterUUID = 0;
  uint128_t sourceMachineUUID = 0;
  uint128_t targetMachineUUID = 0;
  MothershipPhysicalFaultDirection direction = MothershipPhysicalFaultDirection::both;
  uint32_t durationMilliseconds = 0;
  // Freshly observed, immutable authorization proof. This prevents a replay
  // from using an operation UUID after the route or endpoint address changed.
  uint128_t routeUUID = 0;
  uint64_t routeGeneration = 0;
  String routeAuthorizationSHA256;
  String sourceAddress;
  String targetAddress;
  MothershipPhysicalFaultFlowTarget flowTarget = MothershipPhysicalFaultFlowTarget::peerHost;
  String gatewayEndpoint;
  String flowIdentity;
  uint64_t sourceTopologyVersion = 0;
  uint64_t targetTopologyVersion = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipPhysicalClusterNetworkFaultRequest& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.value16b(value.boundaryUUID); serializer.value16b(value.sourceClusterUUID);
  serializer.value16b(value.targetClusterUUID); serializer.value16b(value.sourceMachineUUID);
  serializer.value16b(value.targetMachineUUID); serializer.value1b(value.direction);
  serializer.value4b(value.durationMilliseconds);
  serializer.value16b(value.routeUUID); serializer.value8b(value.routeGeneration);
  serializer.text1b(value.routeAuthorizationSHA256, 64);
  serializer.text1b(value.sourceAddress, INET6_ADDRSTRLEN);
  serializer.text1b(value.targetAddress, INET6_ADDRSTRLEN);
  serializer.value1b(value.flowTarget); serializer.text1b(value.gatewayEndpoint, INET6_ADDRSTRLEN);
  serializer.text1b(value.flowIdentity, 256);
  serializer.value8b(value.sourceTopologyVersion); serializer.value8b(value.targetTopologyVersion);
}

static inline bool mothershipPhysicalClusterNetworkFaultRequestValid(
    const MothershipPhysicalClusterNetworkFaultRequest& value, String *failure = nullptr)
{
  if (failure) failure->clear();
  if (value.protocolVersion != MothershipPhysicalClusterNetworkFaultRequest::version ||
      value.operationUUID == 0 || value.boundaryUUID == 0 || value.sourceClusterUUID == 0 ||
      value.targetClusterUUID == 0 || value.sourceClusterUUID == value.targetClusterUUID ||
      value.sourceMachineUUID == 0 || value.targetMachineUUID == 0 ||
      !mothershipPhysicalFaultDirectionValid(value.direction) || value.durationMilliseconds == 0 ||
      value.durationMilliseconds > mothershipPhysicalFaultMaximumDurationMilliseconds ||
      value.routeUUID == 0 || value.routeGeneration == 0 ||
      !mothershipPhysicalFaultDigestValid(value.routeAuthorizationSHA256) ||
      !mothershipPhysicalFaultNumericAddressValid(value.sourceAddress) ||
      !mothershipPhysicalFaultNumericAddressValid(value.targetAddress) ||
      !mothershipPhysicalFaultFlowTargetValid(value.flowTarget) ||
      (value.flowTarget == MothershipPhysicalFaultFlowTarget::peerHost ?
           (!value.gatewayEndpoint.empty() || !value.flowIdentity.empty()) :
           (!mothershipPhysicalFaultNumericAddressValid(value.gatewayEndpoint) ||
            !mothershipPhysicalFaultFlowIdentityValid(value.flowIdentity))) ||
      value.sourceTopologyVersion == 0 || value.targetTopologyVersion == 0)
  {
    if (failure) failure->assign("physical network fault requires exact distinct boundary identities and a bounded duration"_ctv);
    return false;
  }
  return true;
}

static inline bool mothershipPhysicalClusterNetworkFaultRequestEqual(
    const MothershipPhysicalClusterNetworkFaultRequest& left,
    const MothershipPhysicalClusterNetworkFaultRequest& right)
{
  return left.protocolVersion == right.protocolVersion && left.operationUUID == right.operationUUID &&
      left.boundaryUUID == right.boundaryUUID && left.sourceClusterUUID == right.sourceClusterUUID &&
      left.targetClusterUUID == right.targetClusterUUID && left.sourceMachineUUID == right.sourceMachineUUID &&
      left.targetMachineUUID == right.targetMachineUUID && left.direction == right.direction &&
      left.durationMilliseconds == right.durationMilliseconds && left.routeUUID == right.routeUUID &&
      left.routeGeneration == right.routeGeneration && left.routeAuthorizationSHA256 == right.routeAuthorizationSHA256 &&
      left.sourceAddress == right.sourceAddress && left.targetAddress == right.targetAddress &&
      left.flowTarget == right.flowTarget && left.gatewayEndpoint == right.gatewayEndpoint &&
      left.flowIdentity == right.flowIdentity &&
      left.sourceTopologyVersion == right.sourceTopologyVersion && left.targetTopologyVersion == right.targetTopologyVersion;
}

class MothershipPhysicalClusterNetworkFaultReceipt {
public:
  static constexpr uint32_t version = 3;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0;
  uint128_t boundaryUUID = 0;
  MothershipPhysicalClusterNetworkFaultRequest admission;
  MothershipPhysicalFaultMachineObservation sourceBefore;
  MothershipPhysicalFaultMachineObservation targetBefore;
  MothershipPhysicalFaultMachineObservation sourceAfter;
  MothershipPhysicalFaultMachineObservation targetAfter;
  uint64_t sourceInstalledAtMonotonicMilliseconds = 0;
  uint64_t sourceRestoredAtMonotonicMilliseconds = 0;
  uint64_t targetInstalledAtMonotonicMilliseconds = 0;
  uint64_t targetRestoredAtMonotonicMilliseconds = 0;
  bool sourceRestored = false;
  bool targetRestored = false;
  bool restored = false;
};

template <typename S>
static void serialize(S&& serializer, MothershipPhysicalClusterNetworkFaultReceipt& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.value16b(value.boundaryUUID); serializer.object(value.admission); serializer.object(value.sourceBefore);
  serializer.object(value.targetBefore); serializer.object(value.sourceAfter);
  serializer.object(value.targetAfter); serializer.value8b(value.sourceInstalledAtMonotonicMilliseconds);
  serializer.value8b(value.sourceRestoredAtMonotonicMilliseconds);
  serializer.value8b(value.targetInstalledAtMonotonicMilliseconds);
  serializer.value8b(value.targetRestoredAtMonotonicMilliseconds);
  serializer.value1b(value.sourceRestored); serializer.value1b(value.targetRestored);
  serializer.value1b(value.restored);
}

static inline bool mothershipPhysicalClusterNetworkFaultReceiptValid(
    const MothershipPhysicalClusterNetworkFaultRequest& request,
    const MothershipPhysicalClusterNetworkFaultReceipt& receipt, String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipPhysicalClusterNetworkFaultRequestValid(request, failure)) return false;
  const bool sourceRequired = request.direction == MothershipPhysicalFaultDirection::both ||
      request.direction == MothershipPhysicalFaultDirection::sourceToTarget;
  const bool targetRequired = request.direction == MothershipPhysicalFaultDirection::both ||
      request.direction == MothershipPhysicalFaultDirection::targetToSource;
  const auto sideValid = [&](bool required, bool restored, uint64_t installed, uint64_t restoredAt) {
    if (!required) return !restored && installed == 0 && restoredAt == 0;
    if (!restored || installed == 0 || restoredAt < installed) return false;
    const uint64_t elapsed = restoredAt - installed;
    return elapsed >= request.durationMilliseconds &&
        elapsed <= uint64_t(request.durationMilliseconds) + mothershipPhysicalFaultRestorationSlackMilliseconds;
  };
  if (receipt.protocolVersion != MothershipPhysicalClusterNetworkFaultReceipt::version ||
      receipt.operationUUID != request.operationUUID || receipt.boundaryUUID != request.boundaryUUID ||
      !mothershipPhysicalClusterNetworkFaultRequestEqual(receipt.admission, request) ||
      !receipt.restored ||
      !sideValid(sourceRequired, receipt.sourceRestored,
                 receipt.sourceInstalledAtMonotonicMilliseconds,
                 receipt.sourceRestoredAtMonotonicMilliseconds) ||
      !sideValid(targetRequired, receipt.targetRestored,
                 receipt.targetInstalledAtMonotonicMilliseconds,
                 receipt.targetRestoredAtMonotonicMilliseconds) ||
      !mothershipPhysicalFaultMachineObservationValid(receipt.sourceBefore) ||
      !mothershipPhysicalFaultMachineObservationValid(receipt.targetBefore) ||
      !mothershipPhysicalFaultMachineObservationValid(receipt.sourceAfter) ||
      !mothershipPhysicalFaultMachineObservationValid(receipt.targetAfter) ||
      receipt.sourceBefore.clusterUUID != request.sourceClusterUUID || receipt.sourceBefore.machineUUID != request.sourceMachineUUID ||
      receipt.targetBefore.clusterUUID != request.targetClusterUUID || receipt.targetBefore.machineUUID != request.targetMachineUUID ||
      !mothershipPhysicalFaultMachineObservationEqual(receipt.sourceBefore, receipt.sourceAfter) ||
      !mothershipPhysicalFaultMachineObservationEqual(receipt.targetBefore, receipt.targetAfter))
  {
    if (failure) failure->assign("physical network fault receipt does not prove exact bounded restoration"_ctv);
    return false;
  }
  return true;
}

class MothershipLocalVMMachineFaultRequest {
public:
  static constexpr uint32_t legacyVersion = 1;
  static constexpr uint32_t unreadyUpgradeRecoveryVersion = 2;
  static constexpr uint32_t version = unreadyUpgradeRecoveryVersion;
  uint32_t protocolVersion = legacyVersion;
  uint128_t operationUUID = 0;
  uint128_t vmBoundaryUUID = 0; // explicit VM-isolation owner, never an ambient host
  uint128_t clusterUUID = 0;
  uint128_t machineUUID = 0;
  MothershipLocalVMMachineFaultAction action = MothershipLocalVMMachineFaultAction::crash;
  uint32_t durationMilliseconds = 0;
  String expectedBootSHA256;
  // Version two is a distinct recovery authorization, not a relaxed fault.
  // It binds the exact admitted upgrade, registered boundary, live QEMU
  // process, and Linux guest identity which was observed unready.
  uint128_t upgradeOperationUUID = 0;
  String targetBundleSHA256;
  String targetContractSHA256;
  String upgradeAdmissionSHA256;
  String expectedBoundarySHA256;
  String expectedLinuxMachineID;
  String expectedLinuxBootID;
  uint64_t expectedQemuPID = 0;
  String expectedQemuStarttime;
  uint64_t incompleteObservationReceiptVersion = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipLocalVMMachineFaultRequest& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.value16b(value.vmBoundaryUUID); serializer.value16b(value.clusterUUID);
  serializer.value16b(value.machineUUID); serializer.value1b(value.action);
  serializer.value4b(value.durationMilliseconds); serializer.text1b(value.expectedBootSHA256, 64);
  if (value.protocolVersion >= MothershipLocalVMMachineFaultRequest::unreadyUpgradeRecoveryVersion)
  {
    serializer.value16b(value.upgradeOperationUUID);
    serializer.text1b(value.targetBundleSHA256, 64);
    serializer.text1b(value.targetContractSHA256, 64);
    serializer.text1b(value.upgradeAdmissionSHA256, 64);
    serializer.text1b(value.expectedBoundarySHA256, 64);
    serializer.text1b(value.expectedLinuxMachineID, 32);
    serializer.text1b(value.expectedLinuxBootID, 36);
    serializer.value8b(value.expectedQemuPID);
    serializer.text1b(value.expectedQemuStarttime, 64);
    serializer.value8b(value.incompleteObservationReceiptVersion);
  }
}

static inline bool mothershipLocalVMLinuxMachineIDValid(const String& value)
{
  if (value.size() != 32) return false;
  for (char byte : value)
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) return false;
  return true;
}

static inline bool mothershipLocalVMLinuxBootIDValid(const String& value)
{
  if (value.size() != 36) return false;
  for (uint32_t index = 0; index < value.size(); ++index)
  {
    if (index == 8 || index == 13 || index == 18 || index == 23)
    { if (value[index] != '-') return false; }
    else if (!((value[index] >= '0' && value[index] <= '9') ||
               (value[index] >= 'a' && value[index] <= 'f'))) return false;
  }
  return true;
}

static inline bool mothershipLocalVMProcessStarttimeValid(const String& value)
{
  if (value.empty() || value.size() > 64) return false;
  for (char byte : value) if (byte < '0' || byte > '9') return false;
  return true;
}

static inline bool mothershipLocalVMMachineFaultRequestValid(const MothershipLocalVMMachineFaultRequest& value,
                                                              String *failure = nullptr)
{
  if (failure) failure->clear();
  const bool legacy = value.protocolVersion == MothershipLocalVMMachineFaultRequest::legacyVersion &&
      (value.action == MothershipLocalVMMachineFaultAction::crash ||
       value.action == MothershipLocalVMMachineFaultAction::coldReboot) &&
      value.upgradeOperationUUID == 0 && value.targetBundleSHA256.empty() &&
      value.targetContractSHA256.empty() && value.upgradeAdmissionSHA256.empty() &&
      value.expectedBoundarySHA256.empty() && value.expectedLinuxMachineID.empty() &&
      value.expectedLinuxBootID.empty() && value.expectedQemuPID == 0 &&
      value.expectedQemuStarttime.empty() && value.incompleteObservationReceiptVersion == 0;
  const bool unreadyUpgrade =
      value.protocolVersion == MothershipLocalVMMachineFaultRequest::unreadyUpgradeRecoveryVersion &&
      value.action == MothershipLocalVMMachineFaultAction::recoverUnreadyUpgrade &&
      value.upgradeOperationUUID != 0 &&
      mothershipPhysicalFaultDigestValid(value.targetBundleSHA256) &&
      mothershipPhysicalFaultDigestValid(value.targetContractSHA256) &&
      mothershipPhysicalFaultDigestValid(value.upgradeAdmissionSHA256) &&
      mothershipPhysicalFaultDigestValid(value.expectedBoundarySHA256) &&
      mothershipLocalVMLinuxMachineIDValid(value.expectedLinuxMachineID) &&
      mothershipLocalVMLinuxBootIDValid(value.expectedLinuxBootID) &&
      value.expectedQemuPID != 0 && mothershipLocalVMProcessStarttimeValid(value.expectedQemuStarttime) &&
      value.incompleteObservationReceiptVersion != 0;
  if ((!legacy && !unreadyUpgrade) || value.operationUUID == 0 ||
      value.vmBoundaryUUID == 0 || value.clusterUUID == 0 || value.machineUUID == 0 ||
      !mothershipLocalVMMachineFaultActionValid(value.action) || value.durationMilliseconds == 0 ||
      value.durationMilliseconds > mothershipLocalVMFaultMaximumRecoveryMilliseconds ||
      !mothershipPhysicalFaultDigestValid(value.expectedBootSHA256))
  {
    if (failure) failure->assign("local VM fault requires exact VM boundary, machine identity, boot identity, and bounded duration"_ctv);
    return false;
  }
  return true;
}

static inline bool mothershipLocalVMMachineFaultRequestEqual(const MothershipLocalVMMachineFaultRequest& left,
                                                              const MothershipLocalVMMachineFaultRequest& right)
{
  return left.protocolVersion == right.protocolVersion && left.operationUUID == right.operationUUID &&
      left.vmBoundaryUUID == right.vmBoundaryUUID && left.clusterUUID == right.clusterUUID &&
      left.machineUUID == right.machineUUID && left.action == right.action &&
      left.durationMilliseconds == right.durationMilliseconds && left.expectedBootSHA256 == right.expectedBootSHA256 &&
      left.upgradeOperationUUID == right.upgradeOperationUUID &&
      left.targetBundleSHA256 == right.targetBundleSHA256 &&
      left.targetContractSHA256 == right.targetContractSHA256 &&
      left.upgradeAdmissionSHA256 == right.upgradeAdmissionSHA256 &&
      left.expectedBoundarySHA256 == right.expectedBoundarySHA256 &&
      left.expectedLinuxMachineID == right.expectedLinuxMachineID &&
      left.expectedLinuxBootID == right.expectedLinuxBootID &&
      left.expectedQemuPID == right.expectedQemuPID &&
      left.expectedQemuStarttime == right.expectedQemuStarttime &&
      left.incompleteObservationReceiptVersion == right.incompleteObservationReceiptVersion;
}

class MothershipLocalVMMachineFaultReceipt {
public:
  static constexpr uint32_t legacyVersion = 1;
  static constexpr uint32_t unreadyUpgradeRecoveryVersion = 2;
  static constexpr uint32_t version = unreadyUpgradeRecoveryVersion;
  uint32_t protocolVersion = legacyVersion;
  uint128_t operationUUID = 0;
  uint128_t vmBoundaryUUID = 0;
  MothershipPhysicalFaultMachineObservation before;
  MothershipPhysicalFaultMachineObservation after;
  String restoredBootSHA256;
  uint64_t faultedAtMonotonicMilliseconds = 0;
  uint64_t restoredAtMonotonicMilliseconds = 0;
  bool restored = false;
  String beforeLinuxMachineID;
  String beforeLinuxBootID;
  uint64_t beforeQemuPID = 0;
  String beforeQemuStarttime;
  String afterLinuxMachineID;
  String afterLinuxBootID;
  uint64_t afterQemuPID = 0;
  String afterQemuStarttime;
  uint64_t completedObservationReceiptVersion = 0;
  String completedUpgradeReportSHA256;
};

template <typename S>
static void serialize(S&& serializer, MothershipLocalVMMachineFaultReceipt& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.value16b(value.vmBoundaryUUID); serializer.object(value.before); serializer.object(value.after);
  serializer.text1b(value.restoredBootSHA256, 64); serializer.value8b(value.faultedAtMonotonicMilliseconds);
  serializer.value8b(value.restoredAtMonotonicMilliseconds); serializer.value1b(value.restored);
  if (value.protocolVersion >= MothershipLocalVMMachineFaultReceipt::unreadyUpgradeRecoveryVersion)
  {
    serializer.text1b(value.beforeLinuxMachineID, 32);
    serializer.text1b(value.beforeLinuxBootID, 36);
    serializer.value8b(value.beforeQemuPID);
    serializer.text1b(value.beforeQemuStarttime, 64);
    serializer.text1b(value.afterLinuxMachineID, 32);
    serializer.text1b(value.afterLinuxBootID, 36);
    serializer.value8b(value.afterQemuPID);
    serializer.text1b(value.afterQemuStarttime, 64);
    serializer.value8b(value.completedObservationReceiptVersion);
    serializer.text1b(value.completedUpgradeReportSHA256, 64);
  }
}

static inline bool mothershipLocalVMMachineFaultReceiptValid(const MothershipLocalVMMachineFaultRequest& request,
                                                              const MothershipLocalVMMachineFaultReceipt& receipt,
                                                              String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipLocalVMMachineFaultRequestValid(request, failure)) return false;
  const uint64_t elapsed = receipt.restoredAtMonotonicMilliseconds - receipt.faultedAtMonotonicMilliseconds;
  const bool legacy = request.protocolVersion == MothershipLocalVMMachineFaultRequest::legacyVersion &&
      receipt.protocolVersion == MothershipLocalVMMachineFaultReceipt::legacyVersion &&
      receipt.beforeLinuxMachineID.empty() && receipt.beforeLinuxBootID.empty() && receipt.beforeQemuPID == 0 &&
      receipt.beforeQemuStarttime.empty() && receipt.afterLinuxMachineID.empty() &&
      receipt.afterLinuxBootID.empty() && receipt.afterQemuPID == 0 && receipt.afterQemuStarttime.empty() &&
      receipt.completedObservationReceiptVersion == 0 && receipt.completedUpgradeReportSHA256.empty();
  const bool unreadyUpgrade =
      request.protocolVersion == MothershipLocalVMMachineFaultRequest::unreadyUpgradeRecoveryVersion &&
      receipt.protocolVersion == MothershipLocalVMMachineFaultReceipt::unreadyUpgradeRecoveryVersion &&
      receipt.beforeLinuxMachineID == request.expectedLinuxMachineID &&
      receipt.beforeLinuxBootID == request.expectedLinuxBootID &&
      receipt.beforeQemuPID == request.expectedQemuPID &&
      receipt.beforeQemuStarttime == request.expectedQemuStarttime &&
      receipt.afterLinuxMachineID == request.expectedLinuxMachineID &&
      mothershipLocalVMLinuxBootIDValid(receipt.afterLinuxBootID) &&
      receipt.afterLinuxBootID != request.expectedLinuxBootID && receipt.afterQemuPID != 0 &&
      mothershipLocalVMProcessStarttimeValid(receipt.afterQemuStarttime) &&
      (receipt.afterQemuPID != request.expectedQemuPID ||
       receipt.afterQemuStarttime != request.expectedQemuStarttime) &&
      receipt.completedObservationReceiptVersion > request.incompleteObservationReceiptVersion &&
      mothershipPhysicalFaultDigestValid(receipt.completedUpgradeReportSHA256);
  if ((!legacy && !unreadyUpgrade) ||
      receipt.operationUUID != request.operationUUID || receipt.vmBoundaryUUID != request.vmBoundaryUUID ||
      !receipt.restored || receipt.faultedAtMonotonicMilliseconds == 0 ||
      receipt.restoredAtMonotonicMilliseconds < receipt.faultedAtMonotonicMilliseconds ||
      elapsed == 0 || elapsed > uint64_t(request.durationMilliseconds) +
          mothershipPhysicalFaultRestorationSlackMilliseconds ||
      !mothershipPhysicalFaultMachineObservationValid(receipt.before) ||
      !mothershipPhysicalFaultMachineObservationValid(receipt.after) ||
      receipt.before.clusterUUID != request.clusterUUID || receipt.before.machineUUID != request.machineUUID ||
      receipt.after.clusterUUID != request.clusterUUID || receipt.after.machineUUID != request.machineUUID ||
      !mothershipPhysicalFaultDigestValid(receipt.restoredBootSHA256) ||
      receipt.before.stateSHA256 != request.expectedBootSHA256 ||
      receipt.after.stateSHA256 != receipt.restoredBootSHA256 ||
      receipt.restoredBootSHA256 == request.expectedBootSHA256)
  {
    if (failure) failure->assign("local VM fault receipt does not prove exact bounded replacement and restoration"_ctv);
    return false;
  }
  return true;
}

class MothershipPhysicalClusterNetworkFaultRecord {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  MothershipPhysicalClusterNetworkFaultRequest request;
  MothershipPhysicalFaultMachineObservation sourceAdmission;
  MothershipPhysicalFaultMachineObservation targetAdmission;
  bool hasReceipt = false;
  MothershipPhysicalClusterNetworkFaultReceipt receipt;
};

template <typename S>
static void serialize(S&& serializer, MothershipPhysicalClusterNetworkFaultRecord& value)
{
  serializer.value4b(value.protocolVersion); serializer.object(value.request);
  serializer.object(value.sourceAdmission); serializer.object(value.targetAdmission);
  serializer.value1b(value.hasReceipt); serializer.object(value.receipt);
}

static inline bool mothershipPhysicalClusterNetworkFaultRecordValid(
    const MothershipPhysicalClusterNetworkFaultRecord& value, String *failure = nullptr)
{
  if (failure) failure->clear();
  if (value.protocolVersion != MothershipPhysicalClusterNetworkFaultRecord::version ||
      !mothershipPhysicalClusterNetworkFaultRequestValid(value.request, failure) ||
      !mothershipPhysicalFaultMachineObservationValid(value.sourceAdmission) ||
      !mothershipPhysicalFaultMachineObservationValid(value.targetAdmission) ||
      value.sourceAdmission.clusterUUID != value.request.sourceClusterUUID ||
      value.sourceAdmission.machineUUID != value.request.sourceMachineUUID ||
      value.targetAdmission.clusterUUID != value.request.targetClusterUUID ||
      value.targetAdmission.machineUUID != value.request.targetMachineUUID ||
      (value.hasReceipt && !mothershipPhysicalClusterNetworkFaultReceiptValid(value.request, value.receipt, failure)))
  {
    if (failure && failure->empty()) failure->assign("physical network fault record is invalid"_ctv);
    return false;
  }
  if (!value.hasReceipt)
  {
    MothershipPhysicalClusterNetworkFaultReceipt empty = {};
    String observed = {}, expected = {};
    auto receipt = value.receipt;
    BitseryEngine::serialize(observed, receipt); BitseryEngine::serialize(expected, empty);
    if (observed != expected)
    {
      if (failure) failure->assign("physical network fault record has a premature receipt"_ctv);
      return false;
    }
  }
  return true;
}

class MothershipLocalVMMachineFaultRecord {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  MothershipLocalVMMachineFaultRequest request;
  MothershipPhysicalFaultMachineObservation admission;
  bool hasReceipt = false;
  MothershipLocalVMMachineFaultReceipt receipt;
};

template <typename S>
static void serialize(S&& serializer, MothershipLocalVMMachineFaultRecord& value)
{
  serializer.value4b(value.protocolVersion); serializer.object(value.request);
  serializer.object(value.admission);
  serializer.value1b(value.hasReceipt); serializer.object(value.receipt);
}

// A local authority recovery never delegates discovery or execution authority
// to the caller.  It only durably names the three already-proven local VM
// boundaries which must take part in one bounded recovery cohort.
enum class MothershipLocalAuthorityRecoveryPhase : uint8_t {
  admitted = 0,
  armed = 1,
  released = 2,
  recovered = 3,
};

class MothershipLocalAuthorityRecoveryExecutor {
public:
  uint128_t machineUUID = 0;
  uint128_t boundaryUUID = 0;
  uint128_t executorOperationUUID = 0; // derived by the cohort owner
  String immutableBoundarySHA256;
};
template <typename S>
static void serialize(S&& serializer, MothershipLocalAuthorityRecoveryExecutor& value)
{
  serializer.value16b(value.machineUUID); serializer.value16b(value.boundaryUUID);
  serializer.value16b(value.executorOperationUUID); serializer.text1b(value.immutableBoundarySHA256, 64);
}

// This is one retained LAN rollout, not general mixed-release admission. The
// original update remains the artifact authority; the local recovery journal
// owns only its exact registered VM runtime completion and cold reboot.
static inline uint128_t mothershipLocalInterruptedUpgradeClusterUUID() {
  return (uint128_t(0xc2f22c30ff2c2f11ULL) << 64) | 0xde9ede562c0b8383ULL;
}
static inline uint128_t mothershipLocalInterruptedUpgradeOperationUUID() {
  return (uint128_t(0x1ac3b413a9384a4dULL) << 64) | 0x9d7345f5b278210cULL;
}
static inline uint128_t mothershipLocalInterruptedUpgradePredecessorUUID() {
  return (uint128_t(0x9014af90fdfd4608ULL) << 64) | 0xbd10a431476f2bd3ULL;
}
constexpr static auto mothershipLocalInterruptedUpgradeSourceBundle =
    "74f40b16f51284616db363a0fe6ea9ac0aa93ecf7bc442ef516c3aad5725c174"_ctv;
constexpr static auto mothershipLocalInterruptedUpgradeTargetBundle =
    "1edd6afc0b7666751361fee7b59ee0efaec9b6bb0bfc415c555e13a70028e89a"_ctv;
constexpr static auto mothershipLocalInterruptedUpgradeSourceRuntime =
    "29b42dd7597e89b1763e7561878638a976468bcaf3f787c3fb5dbe70e09fe613"_ctv;
constexpr static auto mothershipLocalInterruptedUpgradeTargetRuntime =
    "5a276698e2175e3cdfd2f55067ccf523e77c6dbab6e5013399eee20785899d01"_ctv;

struct MothershipLocalRecoveryRuntimeMember {
  uint128_t machineUUID = 0;
  String linuxMachineID, beforeBootID, runtimeRoot, gatewayInventory;
  bool installRequired = false;
};
template<typename S> static void serialize(S&& s, MothershipLocalRecoveryRuntimeMember& m) {
  s.value16b(m.machineUUID); s.text1b(m.linuxMachineID,64); s.text1b(m.beforeBootID,64);
  s.text1b(m.runtimeRoot,4096); s.text1b(m.gatewayInventory,65536); s.value1b(m.installRequired);
}

// Only immutable deployment intent belongs in the recovery cohort.  Runtime
// health and placement counts are expected to change while the retained
// containers are restarted on the promoted Brain runtime.
struct MothershipLocalRecoveryWorkloadIdentity {
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  bool stateful = false;
  uint32_t shardGroups = 0;
  uint32_t target = 0, targetBase = 0, targetSurge = 0;
};
template<typename S> static void serialize(S&& s, MothershipLocalRecoveryWorkloadIdentity& w) {
  s.value2b(w.applicationID); s.value8b(w.deploymentID); s.value1b(w.stateful);
  s.value4b(w.shardGroups); s.value4b(w.target); s.value4b(w.targetBase); s.value4b(w.targetSurge);
}

// Version three retains the existing sealed recovery owner while replacing
// the historical one-cohort literals with the already-durable upgrade
// admission and exact observed workload identity.
struct MothershipLocalAdmittedRuntimeUpgradeIdentity {
  String sourceBundleSHA256, sourceContractSHA256, sourceReleaseID;
  String sourceProdigySHA256, sourceMothershipSHA256, sourceBinaryVersion;
  String targetBundleSHA256, targetReleaseID;
  String targetProdigySHA256, targetMothershipSHA256, targetBinaryVersion;
  uint64_t authorityGeneration = 0;
  uint128_t masterUUID = 0;
  int64_t masterBootNs = 0;
  String semanticObservationSHA256;
  uint32_t activeDeploymentCount = 0;
  Vector<MothershipLocalRecoveryWorkloadIdentity> workloads;
};
template<typename S> static void serialize(S&& s, MothershipLocalAdmittedRuntimeUpgradeIdentity& v) {
  s.text1b(v.sourceBundleSHA256,64); s.text1b(v.sourceContractSHA256,64);
  s.text1b(v.sourceReleaseID,256); s.text1b(v.sourceProdigySHA256,64);
  s.text1b(v.sourceMothershipSHA256,64); s.text1b(v.sourceBinaryVersion,64);
  s.text1b(v.targetBundleSHA256,64); s.text1b(v.targetReleaseID,256);
  s.text1b(v.targetProdigySHA256,64); s.text1b(v.targetMothershipSHA256,64);
  s.text1b(v.targetBinaryVersion,64); s.value8b(v.authorityGeneration);
  s.value16b(v.masterUUID); s.value8b(v.masterBootNs);
  s.text1b(v.semanticObservationSHA256,64); s.value4b(v.activeDeploymentCount);
  s.container(v.workloads,256);
}
struct MothershipLocalRecoveryRuntimeIntent {
  uint128_t upgradeOperationUUID = 0, predecessorRecoveryUUID = 0;
  String admissionSHA256, predecessorRecoverySHA256, bundlePath, targetContractSHA256;
  Vector<MothershipLocalRecoveryRuntimeMember> members;
  Vector<CrossClusterMasqueGatewayAuthority> gateways;
};
template<typename S> static void serialize(S&& s, MothershipLocalRecoveryRuntimeIntent& r) {
  s.value16b(r.upgradeOperationUUID); s.value16b(r.predecessorRecoveryUUID);
  s.text1b(r.admissionSHA256,64); s.text1b(r.predecessorRecoverySHA256,64);
  s.text1b(r.bundlePath,4096); s.text1b(r.targetContractSHA256,64);
  s.object(r.members); s.object(r.gateways);
}

class MothershipLocalAuthorityRecoveryCohortRequest {
public:
  static constexpr uint32_t version = 1;
  static constexpr uint32_t interruptedUpgradeVersion = 2;
  static constexpr uint32_t admittedRuntimeUpgradeVersion = 3;
  // Version four is byte-compatible with version three, but binds one exact
  // released predecessor whose installed target is the new source. It lets a
  // successor repair the deployment inventory that prevented the predecessor
  // from producing its final authority receipt without discarding either
  // cohort's durable audit record.
  static constexpr uint32_t admittedRuntimeSupersedingUpgradeVersion = 4;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0;
  uint128_t clusterUUID = 0;
  uint64_t topologyVersion = 0;
  uint32_t timeoutMilliseconds = 0;
  Vector<MothershipLocalAuthorityRecoveryExecutor> executors;
  MothershipLocalRecoveryRuntimeIntent runtime;
  MothershipLocalAdmittedRuntimeUpgradeIdentity admittedRuntime;
};
template <typename S>
static void serialize(S&& serializer, MothershipLocalAuthorityRecoveryCohortRequest& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.value16b(value.clusterUUID); serializer.value8b(value.topologyVersion);
  serializer.value4b(value.timeoutMilliseconds); serializer.object(value.executors);
  // Version-one bytes remain unchanged for already admitted cold recoveries.
  if (value.protocolVersion >= MothershipLocalAuthorityRecoveryCohortRequest::interruptedUpgradeVersion)
    serializer.object(value.runtime);
  if (value.protocolVersion >= MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeUpgradeVersion)
    serializer.object(value.admittedRuntime);
}

// Protocol-two records outlive the one release-specific recovery that created
// them.  Keep their durable shape independently valid so a later Mothership
// can prove a completed historical cohort without reopening that old rollout.
static inline bool mothershipLocalInterruptedRecoveryRuntimeIntentStructurallyValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& r)
{
  const auto& v = r.runtime;
  if (r.clusterUUID == 0 || v.upgradeOperationUUID == 0 || v.predecessorRecoveryUUID == 0 ||
      v.upgradeOperationUUID == v.predecessorRecoveryUUID ||
      r.operationUUID == v.upgradeOperationUUID || r.operationUUID == v.predecessorRecoveryUUID ||
      !mothershipPhysicalFaultDigestValid(v.admissionSHA256) ||
      !mothershipPhysicalFaultDigestValid(v.predecessorRecoverySHA256) ||
      !mothershipPhysicalFaultSafeAbsolutePath(v.bundlePath) ||
      !mothershipPhysicalFaultDigestValid(v.targetContractSHA256) ||
      v.members.size() != 3 || v.gateways.size() != 6 || r.executors.size() != 3 ||
      !prodigyCrossClusterMasqueGatewayAuthoritiesValid(v.gateways,r.clusterUUID)) return false;
  unsigned installs = 0;
  for (uint32_t i=0;i<3;++i) {
    const auto& m=v.members[i];
    if (m.machineUUID==0 || m.machineUUID!=r.executors[i].machineUUID || m.linuxMachineID.size()!=32 ||
        m.beforeBootID.size()!=36 ||
        m.runtimeRoot!="/root/prodigy"_ctv || m.gatewayInventory.empty() || m.gatewayInventory.size()>65536 ||
        m.installRequired!=(i!=0)) return false;
    for (char c:m.linuxMachineID) if (!((c>='a' && c<='f') || (c>='0' && c<='9'))) return false;
    installs += m.installRequired;
    uint32_t gateways=0;
    for (const auto& g:v.gateways) if (g.localMachineUUID==m.machineUUID) {
      if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(g) ||
          g.localClusterUUID!=r.clusterUUID || g.state!=CrossClusterMasqueGatewayState::active) return false;
      ++gateways;
    }
    if (gateways!=2) return false;
  }
  return installs==2;
}

static inline bool mothershipLocalInterruptedRecoveryRuntimeIntentValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& r)
{
  if (!mothershipLocalInterruptedRecoveryRuntimeIntentStructurallyValid(r)) return false;
  const auto& v = r.runtime;
  if (r.clusterUUID != mothershipLocalInterruptedUpgradeClusterUUID() ||
      v.upgradeOperationUUID != mothershipLocalInterruptedUpgradeOperationUUID() ||
      v.predecessorRecoveryUUID != mothershipLocalInterruptedUpgradePredecessorUUID() ||
      v.targetContractSHA256 != "9148f79b5ea66f6ff3d17831ddc487498181549bc77b547c427a9e35f8fa35ac"_ctv) return false;
  const uint128_t expected[] = {
    (uint128_t(0x0bf4487bf41a4eccULL)<<64)|0x9f3e5e316ff23a88ULL,
    (uint128_t(0x88e88d94e0de497dULL)<<64)|0x9ef43113fd04909bULL,
    (uint128_t(0xcbba7c68cf034a26ULL)<<64)|0xb1062449e8572b8aULL};
  const char *linuxIDs[] = {"081d00c431314065990ff533082074f7", "cc8defd48fde42c8b304c77971e19a29",
                           "0ef2a43f92fd48b8a04e3dd8e4eaf80d"};
  for (uint32_t i=0;i<3;++i) {
    const auto& member=v.members[i];
    if (member.machineUUID!=expected[i] || member.linuxMachineID!=String(linuxIDs[i])) return false;
    for (const auto& gateway:v.gateways) if (gateway.localMachineUUID==member.machineUUID &&
        (gateway.artifactSHA256!="a31d6be8fd338c5d9056822ca4eb42dc7f5cee9a2a60a08672847b016a92f631"_ctv ||
         gateway.artifactBytes!=4260945)) return false;
  }
  return true;
}

static inline bool mothershipLocalRecoveryWorkloadIdentityValid(
    const MothershipLocalRecoveryWorkloadIdentity& value)
{
  return value.applicationID != 0 && value.deploymentID != 0 &&
      uint16_t(value.deploymentID >> 48) == value.applicationID &&
      value.target == value.targetBase + value.targetSurge &&
      (value.stateful ? value.shardGroups != 0 : value.shardGroups == 0);
}

static inline bool mothershipLocalRecoveryWorkloadIdentityFromReport(
    uint16_t applicationID, const DeploymentStatusReport& deployment,
    MothershipLocalRecoveryWorkloadIdentity& identity)
{
  if (deployment.versionID == 0 || deployment.versionID >= (uint64_t(1) << 48)) return false;
  identity.applicationID = applicationID;
  identity.deploymentID = (uint64_t(applicationID) << 48) | deployment.versionID;
  identity.stateful = deployment.isStateful;
  identity.shardGroups = deployment.nShardGroups;
  identity.target = deployment.nTarget;
  identity.targetBase = deployment.nTargetBase;
  identity.targetSurge = deployment.nTargetSurge;
  return mothershipLocalRecoveryWorkloadIdentityValid(identity);
}

static inline bool mothershipLocalAdmittedRuntimeUpgradeIdentityValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& request)
{
  const auto& runtime = request.runtime;
  const auto& identity = request.admittedRuntime;
  const bool superseding = request.protocolVersion ==
      MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeSupersedingUpgradeVersion;
  if ((request.protocolVersion != MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeUpgradeVersion &&
       !superseding) ||
      request.clusterUUID == 0 || runtime.upgradeOperationUUID == 0 ||
      request.operationUUID == runtime.upgradeOperationUUID ||
      (superseding ?
        (runtime.predecessorRecoveryUUID == 0 || request.operationUUID == runtime.predecessorRecoveryUUID ||
         !mothershipPhysicalFaultDigestValid(runtime.predecessorRecoverySHA256)) :
        (runtime.predecessorRecoveryUUID != 0 || !runtime.predecessorRecoverySHA256.empty())) ||
      !mothershipPhysicalFaultDigestValid(runtime.admissionSHA256) ||
      !mothershipPhysicalFaultSafeAbsolutePath(runtime.bundlePath) ||
      !mothershipPhysicalFaultDigestValid(runtime.targetContractSHA256) ||
      runtime.members.size() != 3 || runtime.gateways.size() != 6 || request.executors.size() != 3 ||
      !prodigyCrossClusterMasqueGatewayAuthoritiesValid(runtime.gateways, request.clusterUUID) ||
      !mothershipPhysicalFaultDigestValid(identity.sourceBundleSHA256) ||
      !mothershipPhysicalFaultDigestValid(identity.sourceContractSHA256) ||
      identity.sourceReleaseID.empty() || identity.sourceReleaseID.size() > 256 ||
      !mothershipPhysicalFaultDigestValid(identity.sourceProdigySHA256) ||
      !mothershipPhysicalFaultDigestValid(identity.sourceMothershipSHA256) ||
      identity.sourceBinaryVersion.empty() || identity.sourceBinaryVersion.size() > 64 ||
      !mothershipPhysicalFaultDigestValid(identity.targetBundleSHA256) ||
      identity.targetReleaseID.empty() || identity.targetReleaseID.size() > 256 ||
      !mothershipPhysicalFaultDigestValid(identity.targetProdigySHA256) ||
      !mothershipPhysicalFaultDigestValid(identity.targetMothershipSHA256) ||
      identity.targetBinaryVersion.empty() || identity.targetBinaryVersion.size() > 64 ||
      identity.sourceBundleSHA256 == identity.targetBundleSHA256 || identity.authorityGeneration == 0 ||
      identity.masterUUID == 0 || identity.masterBootNs <= 0 ||
      !mothershipPhysicalFaultDigestValid(identity.semanticObservationSHA256) ||
      identity.activeDeploymentCount == 0 || identity.activeDeploymentCount != identity.workloads.size()) return false;
  for (uint32_t index = 0; index < identity.workloads.size(); ++index) {
    const auto& workload = identity.workloads[index];
    if (!mothershipLocalRecoveryWorkloadIdentityValid(workload) ||
        (index != 0 && (identity.workloads[index - 1].applicationID > workload.applicationID ||
          (identity.workloads[index - 1].applicationID == workload.applicationID &&
           identity.workloads[index - 1].deploymentID >= workload.deploymentID)))) return false;
  }
  for (uint32_t index = 0; index < runtime.members.size(); ++index) {
    const auto& member = runtime.members[index];
    if (member.machineUUID != request.executors[index].machineUUID || member.linuxMachineID.size() != 32 ||
        member.beforeBootID.size() != 36 || member.runtimeRoot != "/root/prodigy"_ctv ||
        member.gatewayInventory.empty() || member.gatewayInventory.size() > 65536 || !member.installRequired) return false;
    for (char byte : member.linuxMachineID)
      if (!((byte >= 'a' && byte <= 'f') || (byte >= '0' && byte <= '9'))) return false;
    uint32_t gateways = 0;
    for (const auto& authority : runtime.gateways)
      if (authority.localMachineUUID == member.machineUUID) {
        if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) ||
            authority.localClusterUUID != request.clusterUUID ||
            authority.state != CrossClusterMasqueGatewayState::active) return false;
        ++gateways;
      }
    if (gateways != 2) return false;
  }
  return true;
}

static inline bool mothershipLocalRecoveryRuntimeIntentValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& request)
{
  return request.protocolVersion == MothershipLocalAuthorityRecoveryCohortRequest::interruptedUpgradeVersion ?
      mothershipLocalInterruptedRecoveryRuntimeIntentValid(request) :
      mothershipLocalAdmittedRuntimeUpgradeIdentityValid(request);
}

// Version two admits only its frozen mixed source or completed uniform target.
static inline bool mothershipLocalInterruptedRecoveryRuntimeReportValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& request,
    const ClusterStatusReport& report, bool completed)
{
  if (!mothershipLocalRecoveryRuntimeIntentValid(request) || !report.hasTopology ||
      report.topology.machines.size()!=3 || report.machineReports.size()!=3 || report.nMachines!=3 ||
      report.nApplications!=0 || !report.applicationReports.empty()) return false;
  unsigned masters=0;
  for (const auto& member:request.runtime.members) {
    unsigned matches=0;
    String machine; machine.assignItoh(member.machineUUID);
    for (const auto& observed:report.machineReports) {
      if (observed.machineUUID!=machine) continue;
      ++matches;
      const bool target=completed || !member.installRequired;
      if (!observed.isBrain || !observed.controlPlaneReachable || !observed.runtimeReady ||
          observed.state!="healthy"_ctv || observed.decommissioning || observed.rebooting || observed.updatingOS ||
          observed.hardwareFailure || observed.activeContainers || observed.reservedContainers ||
          !observed.deploymentIDs.empty() || observed.updateStage!="idle"_ctv || !observed.stagedBundleSHA256.empty() ||
          observed.runningProdigyVersion!=(target ? String("54"_ctv) : String("53"_ctv)) ||
          observed.approvedBundleSHA256!=(target ? String(mothershipLocalInterruptedUpgradeTargetBundle) :
                                                  String(mothershipLocalInterruptedUpgradeSourceBundle)) ||
          (!completed && observed.currentMaster==member.installRequired)) return false;
      masters+=observed.currentMaster;
    }
    if (matches!=1) return false;
  }
  return masters==1;
}

static inline bool mothershipLocalRecoveryWorkloadsMatch(
    const MothershipLocalAuthorityRecoveryCohortRequest& request,
    const ClusterStatusReport& report)
{
  Vector<MothershipLocalRecoveryWorkloadIdentity> observed;
  if (report.nApplications != report.applicationReports.size()) return false;
  for (const auto& application : report.applicationReports)
    for (const auto& deployment : application.deploymentReports) {
      MothershipLocalRecoveryWorkloadIdentity identity;
      if (!mothershipLocalRecoveryWorkloadIdentityFromReport(
              application.applicationID, deployment, identity)) return false;
      observed.push_back(std::move(identity));
    }
  std::sort(observed.begin(), observed.end(), [](const auto& left, const auto& right) {
    return left.applicationID == right.applicationID ? left.deploymentID < right.deploymentID :
        left.applicationID < right.applicationID;
  });
  if (observed.size() != request.admittedRuntime.workloads.size()) return false;
  for (uint32_t index = 0; index < observed.size(); ++index) {
    const auto& left = observed[index];
    const auto& right = request.admittedRuntime.workloads[index];
    if (left.applicationID != right.applicationID || left.deploymentID != right.deploymentID ||
        left.stateful != right.stateful || left.shardGroups != right.shardGroups ||
        left.target != right.target || left.targetBase != right.targetBase ||
        left.targetSurge != right.targetSurge) return false;
  }
  return true;
}

static inline bool mothershipLocalAdmittedRuntimeUpgradeReportValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& request,
    const ClusterStatusReport& report, bool completed)
{
  const auto& identity = request.admittedRuntime;
  if (!mothershipLocalAdmittedRuntimeUpgradeIdentityValid(request) || !report.hasTopology ||
      report.topology.version < request.topologyVersion || report.topology.machines.size() != 3 ||
      report.machineReports.size() != 3 || report.nMachines != 3 ||
      !mothershipLocalRecoveryWorkloadsMatch(request, report)) return false;
  unsigned masters = 0;
  for (const auto& member : request.runtime.members) {
    unsigned topologyMatches = 0, reportMatches = 0;
    for (const auto& machine : report.topology.machines)
      topologyMatches += machine.uuid == member.machineUUID && machine.isBrain &&
          machine.kind == MachineConfig::MachineKind::vm && machine.backing == ClusterMachineBacking::owned &&
          machine.lifetime == MachineLifetime::owned;
    String machineUUID; machineUUID.assignItoh(member.machineUUID);
    for (const auto& observed : report.machineReports) {
      if (observed.machineUUID != machineUUID) continue;
      ++reportMatches;
      const bool target = completed || !member.installRequired;
      if (!observed.isBrain || !observed.controlPlaneReachable || !observed.runtimeReady ||
          observed.state != "healthy"_ctv || observed.decommissioning || observed.rebooting || observed.updatingOS ||
          observed.hardwareFailure || observed.updateStage != "idle"_ctv ||
          !observed.stagedBundleSHA256.empty() ||
          observed.runningProdigyVersion != (target ? identity.targetBinaryVersion : identity.sourceBinaryVersion) ||
          observed.approvedBundleSHA256 != (target ? identity.targetBundleSHA256 : identity.sourceBundleSHA256) ||
          (!completed && observed.currentMaster != (member.machineUUID == identity.masterUUID))) return false;
      masters += observed.currentMaster;
    }
    if (topologyMatches != 1 || reportMatches != 1) return false;
  }
  return masters == 1;
}

static inline bool mothershipLocalRecoveryRuntimeReportValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& request,
    const ClusterStatusReport& report, bool completed)
{
  return request.protocolVersion == MothershipLocalAuthorityRecoveryCohortRequest::interruptedUpgradeVersion ?
      mothershipLocalInterruptedRecoveryRuntimeReportValid(request, report, completed) :
      mothershipLocalAdmittedRuntimeUpgradeReportValid(request, report, completed);
}

static inline bool mothershipLocalAuthorityRecoveryPhaseValid(MothershipLocalAuthorityRecoveryPhase value)
{
  return value == MothershipLocalAuthorityRecoveryPhase::admitted ||
      value == MothershipLocalAuthorityRecoveryPhase::armed ||
      value == MothershipLocalAuthorityRecoveryPhase::released ||
      value == MothershipLocalAuthorityRecoveryPhase::recovered;
}

static inline bool mothershipLocalAuthorityRecoveryCohortEnvelopeValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& value, String *failure = nullptr)
{
  if (failure) failure->clear();
  if ((value.protocolVersion != MothershipLocalAuthorityRecoveryCohortRequest::version &&
       value.protocolVersion != MothershipLocalAuthorityRecoveryCohortRequest::interruptedUpgradeVersion &&
       value.protocolVersion != MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeUpgradeVersion &&
       value.protocolVersion != MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeSupersedingUpgradeVersion) ||
      value.operationUUID == 0 || value.clusterUUID == 0 || value.topologyVersion == 0 ||
      value.timeoutMilliseconds < mothershipLocalAuthorityRecoveryMinimumTimeoutMilliseconds ||
      value.timeoutMilliseconds > mothershipLocalVMFaultMaximumRecoveryMilliseconds || value.executors.size() != 3)
  {
    if (failure) failure->assign("local authority recovery requires one bounded exact three-machine cohort"_ctv);
    return false;
  }
  for (uint32_t index = 0; index < value.executors.size(); ++index)
  {
    const auto& executor = value.executors[index];
    if (executor.machineUUID == 0 || executor.boundaryUUID == 0 || executor.executorOperationUUID == 0 ||
        !mothershipPhysicalFaultDigestValid(executor.immutableBoundarySHA256) ||
        (index != 0 && value.executors[index - 1].machineUUID >= executor.machineUUID))
    {
      if (failure) failure->assign("local authority recovery executors must be canonically sorted and fully bound"_ctv);
      return false;
    }
    for (uint32_t other = 0; other < index; ++other)
      if (value.executors[other].boundaryUUID == executor.boundaryUUID ||
          value.executors[other].executorOperationUUID == executor.executorOperationUUID)
      {
        if (failure) failure->assign("local authority recovery requires distinct machine, boundary, and executor identities"_ctv);
        return false;
      }
  }
  return true;
}

static inline bool mothershipLocalAuthorityRecoveryCohortRequestValid(
    const MothershipLocalAuthorityRecoveryCohortRequest& value, String *failure = nullptr)
{
  if (!mothershipLocalAuthorityRecoveryCohortEnvelopeValid(value, failure)) return false;
  if (value.protocolVersion >= MothershipLocalAuthorityRecoveryCohortRequest::interruptedUpgradeVersion &&
      !mothershipLocalRecoveryRuntimeIntentValid(value)) {
    if (failure) failure->assign("local authority recovery runtime intent differs from its exact admitted rollout"_ctv);
    return false;
  }
  return true;
}

// A reboot may advance Brain's authoritative topology generation while
// preserving the exact three VM identities admitted by the recovery cohort.
// Reject an older generation or any identity/ownership substitution, but do
// not require the live generation to remain frozen across the reboot itself.
static inline bool mothershipLocalAuthorityRecoveryTopologyMatches(
    const MothershipLocalAuthorityRecoveryCohortRequest& request,
    const ClusterTopology& topology)
{
  if (topology.version < request.topologyVersion ||
      topology.machines.size() != request.executors.size()) return false;
  for (const auto& executor : request.executors)
  {
    uint32_t matches = 0;
    for (const auto& machine : topology.machines)
      if (machine.uuid == executor.machineUUID && machine.kind == MachineConfig::MachineKind::vm &&
          machine.backing == ClusterMachineBacking::owned && machine.lifetime == MachineLifetime::owned &&
          machine.isBrain) ++matches;
    if (matches != 1) return false;
  }
  return true;
}

class MothershipLocalAuthorityRecoveryBoundaryProgress {
public:
  uint128_t boundaryUUID = 0;
  MothershipLocalAuthorityRecoveryPhase phase = MothershipLocalAuthorityRecoveryPhase::admitted;
  String receiptSHA256;
};
template <typename S>
static void serialize(S&& serializer, MothershipLocalAuthorityRecoveryBoundaryProgress& value)
{
  serializer.value16b(value.boundaryUUID); serializer.value1b(value.phase); serializer.text1b(value.receiptSHA256, 64);
}

struct MothershipLocalRecoveryRuntimeProgress {
  uint128_t boundaryUUID = 0;
  bool installDispatched = false;
  String stateSHA256, secretsSHA256, activationBootID;
};
template<typename S> static void serialize(S&& s, MothershipLocalRecoveryRuntimeProgress& p) {
  s.value16b(p.boundaryUUID); s.value1b(p.installDispatched);
  s.text1b(p.stateSHA256,64); s.text1b(p.secretsSHA256,64); s.text1b(p.activationBootID,64);
}

class MothershipLocalAuthorityRecoveryCohortRecord {
public:
  static constexpr uint32_t version = 1;
  static constexpr uint32_t interruptedUpgradeVersion = 2;
  static constexpr uint32_t admittedRuntimeUpgradeVersion = 3;
  static constexpr uint32_t admittedRuntimeSupersedingUpgradeVersion = 4;
  uint32_t protocolVersion = version;
  MothershipLocalAuthorityRecoveryCohortRequest request;
  MothershipLocalAuthorityRecoveryPhase phase = MothershipLocalAuthorityRecoveryPhase::admitted;
  Vector<MothershipLocalAuthorityRecoveryBoundaryProgress> boundaries;
  Vector<MothershipLocalRecoveryRuntimeProgress> runtimeProgress;
};
template <typename S>
static void serialize(S&& serializer, MothershipLocalAuthorityRecoveryCohortRecord& value)
{
  serializer.value4b(value.protocolVersion); serializer.object(value.request); serializer.value1b(value.phase);
  serializer.object(value.boundaries);
  if (value.protocolVersion >= MothershipLocalAuthorityRecoveryCohortRecord::interruptedUpgradeVersion)
    serializer.object(value.runtimeProgress);
}

static inline bool mothershipLocalAuthorityRecoveryCohortRecordValid(
    const MothershipLocalAuthorityRecoveryCohortRecord& value, String *failure = nullptr)
{
  if (failure) failure->clear();
  if ((value.protocolVersion != MothershipLocalAuthorityRecoveryCohortRecord::version &&
       value.protocolVersion != MothershipLocalAuthorityRecoveryCohortRecord::interruptedUpgradeVersion &&
       value.protocolVersion != MothershipLocalAuthorityRecoveryCohortRecord::admittedRuntimeUpgradeVersion &&
       value.protocolVersion != MothershipLocalAuthorityRecoveryCohortRecord::admittedRuntimeSupersedingUpgradeVersion) ||
      value.protocolVersion != value.request.protocolVersion ||
      !mothershipLocalAuthorityRecoveryCohortEnvelopeValid(value.request, failure) ||
      !mothershipLocalAuthorityRecoveryPhaseValid(value.phase) || value.boundaries.size() != 3)
  {
    if (failure && failure->empty()) failure->assign("local authority recovery record is invalid"_ctv);
    return false;
  }
  if (value.protocolVersion >= MothershipLocalAuthorityRecoveryCohortRecord::interruptedUpgradeVersion) {
    const bool completedHistoricalV2 = value.protocolVersion ==
        MothershipLocalAuthorityRecoveryCohortRecord::interruptedUpgradeVersion &&
        value.phase == MothershipLocalAuthorityRecoveryPhase::recovered;
    const bool runtimeValid = completedHistoricalV2 ?
        mothershipLocalInterruptedRecoveryRuntimeIntentStructurallyValid(value.request) :
        mothershipLocalRecoveryRuntimeIntentValid(value.request);
    if (!runtimeValid) {
      if (failure) failure->assign("local authority recovery record runtime intent is invalid"_ctv);
      return false;
    }
  }
  MothershipLocalAuthorityRecoveryPhase minimum = MothershipLocalAuthorityRecoveryPhase::recovered;
  for (uint32_t index = 0; index < value.boundaries.size(); ++index)
  {
    const auto& progress = value.boundaries[index];
    if (progress.boundaryUUID != value.request.executors[index].boundaryUUID ||
        !mothershipLocalAuthorityRecoveryPhaseValid(progress.phase) ||
        (progress.phase == MothershipLocalAuthorityRecoveryPhase::admitted ? !progress.receiptSHA256.empty() :
         !mothershipPhysicalFaultDigestValid(progress.receiptSHA256)))
    {
      if (failure) failure->assign("local authority recovery progress is not bound to the immutable cohort"_ctv);
      return false;
    }
    if (uint8_t(progress.phase) < uint8_t(minimum)) minimum = progress.phase;
  }
  if (value.phase != minimum)
  {
    if (failure) failure->assign("local authority recovery cohort phase is not the durable common progress"_ctv);
    return false;
  }
  if (value.protocolVersion >= MothershipLocalAuthorityRecoveryCohortRecord::interruptedUpgradeVersion) {
    if (value.runtimeProgress.size()!=3) return false;
    for (uint32_t i=0;i<3;++i) {
      const auto& p=value.runtimeProgress[i]; const auto& member=value.request.runtime.members[i];
      if (p.boundaryUUID!=value.boundaries[i].boundaryUUID ||
          (!member.installRequired && (p.installDispatched || !p.stateSHA256.empty() || !p.secretsSHA256.empty())) ||
          (!p.installDispatched && (!p.stateSHA256.empty() || !p.secretsSHA256.empty())) ||
          (p.stateSHA256.empty()!=p.secretsSHA256.empty()) ||
          (!p.stateSHA256.empty() && (!mothershipPhysicalFaultDigestValid(p.stateSHA256) ||
                                    !mothershipPhysicalFaultDigestValid(p.secretsSHA256))) ||
          (!p.activationBootID.empty() && (p.activationBootID.size()!=36 || p.activationBootID==member.beforeBootID)) ||
          (member.installRequired && value.boundaries[i].phase>=MothershipLocalAuthorityRecoveryPhase::released &&
           (!p.installDispatched || p.stateSHA256.empty())) ||
          (value.boundaries[i].phase==MothershipLocalAuthorityRecoveryPhase::recovered && p.activationBootID.empty())) return false;
    }
  } else if (!value.runtimeProgress.empty()) return false;
  return true;
}

static inline bool mothershipLocalReleasedRuntimeRecoveryCanBeSuperseded(
    const MothershipLocalAuthorityRecoveryCohortRecord& predecessor,
    const String& predecessorSHA256,
    const MothershipLocalAuthorityRecoveryCohortRequest& successor,
    String *failure = nullptr)
{
  if (failure) failure->clear();
  const auto reject = [&](const char *reason) {
    if (failure) failure->assign(reason);
    return false;
  };
  if (successor.protocolVersion !=
          MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeSupersedingUpgradeVersion ||
      predecessor.protocolVersion <
          MothershipLocalAuthorityRecoveryCohortRecord::admittedRuntimeUpgradeVersion ||
      predecessor.phase != MothershipLocalAuthorityRecoveryPhase::released ||
      predecessor.request.operationUUID != successor.runtime.predecessorRecoveryUUID ||
      predecessorSHA256 != successor.runtime.predecessorRecoverySHA256 ||
      predecessor.request.clusterUUID != successor.clusterUUID ||
      predecessor.request.executors.size() != 3 || predecessor.boundaries.size() != 3 ||
      predecessor.runtimeProgress.size() != 3 || successor.executors.size() != 3 ||
      successor.runtime.members.size() != 3)
    return reject("superseding local runtime recovery is not bound to one released predecessor");

  const auto& before = predecessor.request.admittedRuntime;
  const auto& after = successor.admittedRuntime;
  if (before.targetBundleSHA256 != after.sourceBundleSHA256 ||
      predecessor.request.runtime.targetContractSHA256 != after.sourceContractSHA256 ||
      before.targetReleaseID != after.sourceReleaseID ||
      before.targetProdigySHA256 != after.sourceProdigySHA256 ||
      before.targetMothershipSHA256 != after.sourceMothershipSHA256 ||
      before.targetBinaryVersion != after.sourceBinaryVersion ||
      before.workloads.size() != after.workloads.size())
    return reject("superseding local runtime recovery source differs from the predecessor target");
  for (uint32_t index = 0; index < before.workloads.size(); ++index) {
    const auto& left = before.workloads[index];
    const auto& right = after.workloads[index];
    if (left.applicationID != right.applicationID || left.deploymentID != right.deploymentID ||
        left.stateful != right.stateful || left.shardGroups != right.shardGroups ||
        left.target != right.target || left.targetBase != right.targetBase ||
        left.targetSurge != right.targetSurge)
      return reject("superseding local runtime recovery changed the predecessor workload intent");
  }
  auto predecessorGateways = predecessor.request.runtime.gateways;
  auto successorGateways = successor.runtime.gateways;
  String predecessorGatewayBytes, successorGatewayBytes;
  if (!BitseryEngine::serialize(predecessorGatewayBytes, predecessorGateways) ||
      !BitseryEngine::serialize(successorGatewayBytes, successorGateways) ||
      predecessorGatewayBytes != successorGatewayBytes)
    return reject("superseding local runtime recovery changed gateway authority");
  for (uint32_t index = 0; index < 3; ++index) {
    const auto& oldExecutor = predecessor.request.executors[index];
    const auto& newExecutor = successor.executors[index];
    const auto& oldMember = predecessor.request.runtime.members[index];
    const auto& newMember = successor.runtime.members[index];
    if (predecessor.boundaries[index].phase < MothershipLocalAuthorityRecoveryPhase::released ||
        predecessor.runtimeProgress[index].activationBootID.empty() ||
        predecessor.runtimeProgress[index].activationBootID != newMember.beforeBootID ||
        oldExecutor.machineUUID != newExecutor.machineUUID ||
        oldExecutor.boundaryUUID != newExecutor.boundaryUUID ||
        oldExecutor.immutableBoundarySHA256 != newExecutor.immutableBoundarySHA256 ||
        oldMember.machineUUID != newMember.machineUUID ||
        oldMember.linuxMachineID != newMember.linuxMachineID)
      return reject("superseding local runtime recovery changed a recovered VM boundary or boot");
  }
  return true;
}

static inline bool mothershipLocalVMMachineFaultRecordValid(
    const MothershipLocalVMMachineFaultRecord& value, String *failure = nullptr)
{
  if (failure) failure->clear();
  if (value.protocolVersion != MothershipLocalVMMachineFaultRecord::version ||
      !mothershipLocalVMMachineFaultRequestValid(value.request, failure) ||
      !mothershipPhysicalFaultMachineObservationValid(value.admission) ||
      value.admission.clusterUUID != value.request.clusterUUID ||
      value.admission.machineUUID != value.request.machineUUID ||
      value.admission.stateSHA256 != value.request.expectedBootSHA256 ||
      (value.hasReceipt && !mothershipLocalVMMachineFaultReceiptValid(value.request, value.receipt, failure)))
  {
    if (failure && failure->empty()) failure->assign("local VM machine fault record is invalid"_ctv);
    return false;
  }
  if (!value.hasReceipt)
  {
    MothershipLocalVMMachineFaultReceipt empty = {};
    String observed = {}, expected = {};
    auto receipt = value.receipt;
    BitseryEngine::serialize(observed, receipt); BitseryEngine::serialize(expected, empty);
    if (observed != expected)
    {
      if (failure) failure->assign("local VM machine fault record has a premature receipt"_ctv);
      return false;
    }
  }
  return true;
}

template <typename T>
static inline bool mothershipPhysicalFaultExactSerializedEqual(const T& left, const T& right)
{
  String leftBytes = {}, rightBytes = {};
  T leftCopy = left, rightCopy = right;
  BitseryEngine::serialize(leftBytes, leftCopy); BitseryEngine::serialize(rightBytes, rightCopy);
  return leftBytes == rightBytes;
}

// Replaying an operation is legal only when every durable authorization input
// is byte-for-byte equivalent.  A caller may therefore retry after a lost
// response, but cannot reuse an operation identity to retarget a fault.
static inline bool mothershipPhysicalClusterNetworkFaultReplayAdmissible(
    const MothershipPhysicalClusterNetworkFaultRequest& original,
    const MothershipPhysicalClusterNetworkFaultRequest& replay)
{
  return mothershipPhysicalClusterNetworkFaultRequestValid(original) &&
      mothershipPhysicalClusterNetworkFaultRequestEqual(original, replay);
}

static inline bool mothershipLocalVMMachineFaultReplayAdmissible(
    const MothershipLocalVMMachineFaultRequest& original,
    const MothershipLocalVMMachineFaultRequest& replay)
{
  return mothershipLocalVMMachineFaultRequestValid(original) &&
      mothershipLocalVMMachineFaultRequestEqual(original, replay);
}
