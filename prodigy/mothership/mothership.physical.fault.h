#pragma once

// Typed contracts for bounded physical-boundary fault requests.  These are
// deliberately authorization and receipt contracts only: an executor must be
// separately sealed to these exact identities and may not accept shell, route,
// interface, namespace, or provider identifiers from a caller.

#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

#include <prodigy/mothership/mothership.cluster.types.h>

constexpr static uint32_t mothershipPhysicalFaultMaximumDurationMilliseconds = 60'000;
constexpr static uint32_t mothershipPhysicalFaultRestorationSlackMilliseconds = 5'000;
constexpr static uint32_t mothershipLocalVMFaultMaximumRecoveryMilliseconds = 300'000;
// This is a provider-owned task directory, not caller-controlled execution
// data. The sealed guest executor creates it only beneath /var/lib/prodigy
// after proving that parent is root-owned and not group/world writable.
constexpr static auto mothershipPhysicalFaultProviderStateRoot =
    "/var/lib/prodigy/mothership-physical-faults"_ctv;
constexpr static const char *mothershipVerifiedLocalVMMarkerPath = "/run/prodigy-disposable-linux";
constexpr static auto mothershipVerifiedLocalVMMarker = "prodigy-disposable-linux-v1"_ctv;

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

enum class MothershipPhysicalFaultDirection : uint8_t {
  both = 0,
  sourceToTarget = 1,
  targetToSource = 2,
};

enum class MothershipLocalVMMachineFaultAction : uint8_t {
  crash = 0,
  coldReboot = 1,
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

static inline bool mothershipPhysicalFaultDirectionValid(MothershipPhysicalFaultDirection value)
{
  return value == MothershipPhysicalFaultDirection::both ||
      value == MothershipPhysicalFaultDirection::sourceToTarget ||
      value == MothershipPhysicalFaultDirection::targetToSource;
}

static inline bool mothershipLocalVMMachineFaultActionValid(MothershipLocalVMMachineFaultAction value)
{
  return value == MothershipLocalVMMachineFaultAction::crash ||
      value == MothershipLocalVMMachineFaultAction::coldReboot;
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
  static constexpr uint32_t version = 2;
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
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0;
  uint128_t vmBoundaryUUID = 0; // explicit VM-isolation owner, never an ambient host
  uint128_t clusterUUID = 0;
  uint128_t machineUUID = 0;
  MothershipLocalVMMachineFaultAction action = MothershipLocalVMMachineFaultAction::crash;
  uint32_t durationMilliseconds = 0;
  String expectedBootSHA256;
};

template <typename S>
static void serialize(S&& serializer, MothershipLocalVMMachineFaultRequest& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.value16b(value.vmBoundaryUUID); serializer.value16b(value.clusterUUID);
  serializer.value16b(value.machineUUID); serializer.value1b(value.action);
  serializer.value4b(value.durationMilliseconds); serializer.text1b(value.expectedBootSHA256, 64);
}

static inline bool mothershipLocalVMMachineFaultRequestValid(const MothershipLocalVMMachineFaultRequest& value,
                                                              String *failure = nullptr)
{
  if (failure) failure->clear();
  if (value.protocolVersion != MothershipLocalVMMachineFaultRequest::version || value.operationUUID == 0 ||
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
      left.durationMilliseconds == right.durationMilliseconds && left.expectedBootSHA256 == right.expectedBootSHA256;
}

class MothershipLocalVMMachineFaultReceipt {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0;
  uint128_t vmBoundaryUUID = 0;
  MothershipPhysicalFaultMachineObservation before;
  MothershipPhysicalFaultMachineObservation after;
  String restoredBootSHA256;
  uint64_t faultedAtMonotonicMilliseconds = 0;
  uint64_t restoredAtMonotonicMilliseconds = 0;
  bool restored = false;
};

template <typename S>
static void serialize(S&& serializer, MothershipLocalVMMachineFaultReceipt& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.value16b(value.vmBoundaryUUID); serializer.object(value.before); serializer.object(value.after);
  serializer.text1b(value.restoredBootSHA256, 64); serializer.value8b(value.faultedAtMonotonicMilliseconds);
  serializer.value8b(value.restoredAtMonotonicMilliseconds); serializer.value1b(value.restored);
}

static inline bool mothershipLocalVMMachineFaultReceiptValid(const MothershipLocalVMMachineFaultRequest& request,
                                                              const MothershipLocalVMMachineFaultReceipt& receipt,
                                                              String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipLocalVMMachineFaultRequestValid(request, failure)) return false;
  const uint64_t elapsed = receipt.restoredAtMonotonicMilliseconds - receipt.faultedAtMonotonicMilliseconds;
  if (receipt.protocolVersion != MothershipLocalVMMachineFaultReceipt::version ||
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
