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
#include <prodigy/cluster.pair.enrollment.h>
#include <prodigy/cluster.pair.authority.h>
#include <prodigy/cousin.route.h>
#include <prodigy/cousin.service.permission.h>
#include <prodigy/transport.credentials.h>
#include <prodigy/biphasal.key.h>
#include <prodigy/server.state.h>
#include <prodigy/sha256.digest.h>
#include <macros/datacenter.h>
#include <switchboard/common/constants.h>

#ifndef PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
#define PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION PRODIGY_DEBUG
#endif

class MothershipResponse {
public:

  bool success;
  String failure; // string failure response
};

// A tagged updateProdigy frame cannot be mistaken for a bundle by older
// Brains, which reject this non-artifact tag before a follower transition.
constexpr inline auto ProdigyUpdateSelfConcurrencyRequestTag =
    "prodigy-update-concurrency-v1"_ctv;
constexpr inline uint8_t ProdigyUpdateSelfMinimumConcurrency = 1;
constexpr inline uint8_t ProdigyUpdateSelfMaximumConcurrency = 2;
// Version 24 is the first binary that understands the unambiguous v9
// master-authority persistence tail used by explicit follower concurrency.
constexpr inline uint64_t ProdigyUpdateSelfConcurrencyMinimumVersion = 24;

// This is deliberately not an application-wide destroy request.  The exact
// application/version/successor triple is the authority for a recovery action.
class CancelDeploymentRequest {
public:
  String applicationName;
  uint16_t applicationID = 0;
  uint64_t activeVersionID = 0;
  uint64_t successorVersionID = 0;
  String operationID;
  String reason;
};

template <typename S>
static void serialize(S&& serializer, CancelDeploymentRequest& request)
{
  serializer.text1b(request.applicationName, 128);
  serializer.value2b(request.applicationID);
  serializer.value8b(request.activeVersionID);
  serializer.value8b(request.successorVersionID);
  serializer.text1b(request.operationID, 36);
  serializer.text1b(request.reason, 512);
}
// Explicit qualification-only cancellation scope. The old wire request stays
// unchanged; this envelope is decoded separately on the same operation topic.
struct ProdigyQualificationCancellationMember {
  uint128_t containerUUID = 0, machineUUID = 0;
};
template <typename S> static void serialize(S&& s, ProdigyQualificationCancellationMember& v) {
  s.value16b(v.containerUUID); s.value16b(v.machineUUID);
}
struct ProdigyQualificationStatefulCancellation {
  static constexpr uint32_t version = 0x51435301; // QCS v1
  uint32_t protocolVersion = version;
  CancelDeploymentRequest request;
  uint128_t qualificationRunUUID = 0, successorOperationUUID = 0, sourceClusterUUID = 0;
  uint64_t executionGeneration = 0;
  int64_t deadlineAtMilliseconds = 0;
  String placementIntentSHA256, successorPlanSHA256, successorArtifactSHA256;
  Vector<ProdigyQualificationCancellationMember> members;
};
template <typename S> static void serialize(S&& s, ProdigyQualificationStatefulCancellation& v) {
  s.value4b(v.protocolVersion); s.object(v.request); s.value16b(v.qualificationRunUUID);
  s.value16b(v.successorOperationUUID); s.value16b(v.sourceClusterUUID); s.value8b(v.executionGeneration);
  s.value8b(v.deadlineAtMilliseconds); s.text1b(v.placementIntentSHA256, 64);
  s.text1b(v.successorPlanSHA256, 64); s.text1b(v.successorArtifactSHA256, 64); s.container(v.members, 24);
}
static inline bool prodigyQualificationStatefulCancellationValid(const ProdigyQualificationStatefulCancellation& v) {
  if (v.protocolVersion != v.version || !v.qualificationRunUUID || !v.successorOperationUUID || !v.sourceClusterUUID ||
      !v.executionGeneration || v.deadlineAtMilliseconds <= 0 || v.request.applicationName.empty() ||
      !v.request.applicationID || !v.request.activeVersionID || v.request.successorVersionID <= v.request.activeVersionID ||
      v.request.activeVersionID >= (uint64_t(1) << 48) || v.request.successorVersionID >= (uint64_t(1) << 48) ||
      v.request.operationID.size() != 36 || v.request.reason.empty() || v.members.empty() || v.members.size() > 24 ||
      !prodigyIsSHA256HexDigest(v.placementIntentSHA256) || !prodigyIsSHA256HexDigest(v.successorPlanSHA256) ||
      !prodigyIsSHA256HexDigest(v.successorArtifactSHA256)) return false;
  for (size_t i = 0; i < v.members.size(); ++i) {
    if (!v.members[i].containerUUID || !v.members[i].machineUUID) return false;
    for (size_t j = 0; j < i; ++j) if (v.members[i].containerUUID == v.members[j].containerUUID) return false;
  }
  return true;
}
class CancelDeploymentResponse : public MothershipResponse {
public:
  CancelDeploymentResult result = CancelDeploymentResult::rejected;
  CancelDeploymentPhase phase = CancelDeploymentPhase::none;
  String operationID;
  uint16_t applicationID = 0;
  uint64_t activeVersionID = 0;
  uint64_t successorVersionID = 0;
  uint64_t cancelledDeploymentID = 0;
  uint64_t successorDeploymentID = 0;
  uint64_t durableGeneration = 0;
};

template <typename S>
static void serialize(S&& serializer, CancelDeploymentResponse& response)
{
  serializer.value1b(response.success);
  serializer.text1b(response.failure, UINT32_MAX);
  uint8_t result = uint8_t(response.result);
  serializer.value1b(result);
  response.result = CancelDeploymentResult(result);
  uint8_t phase = uint8_t(response.phase);
  serializer.value1b(phase);
  response.phase = CancelDeploymentPhase(phase);
  serializer.text1b(response.operationID, 36);
  serializer.value2b(response.applicationID);
  serializer.value8b(response.activeVersionID);
  serializer.value8b(response.successorVersionID);
  serializer.value8b(response.cancelledDeploymentID);
  serializer.value8b(response.successorDeploymentID);
  serializer.value8b(response.durableGeneration);
}

class RecoverMaterializedStatefulDeployment {
public:
  String applicationName;
  uint16_t applicationID = 0;
  uint64_t activeVersionID = 0;
  uint64_t successorVersionID = 0;
  String operationID;
  String successorBlobSHA256;
  // A retry replaces an already accepted successor which failed before its
  // first health acknowledgement.  Storage identity is descriptive only;
  // the Neuron derives every filesystem path from the UUIDs.
  bool retryFailedSuccessor = false;
  uint64_t replacementSuccessorVersionID = 0;
  String replacementSuccessorBlobSHA256;
  uint128_t sourceContainerUUID = 0;
  uint128_t failedSuccessorContainerUUID = 0;
  uint128_t sourceMachineUUID = 0;
  uint64_t sourceDevice = 0;
  uint64_t sourceInode = 0;
  uint32_t sourceUID = 0;
  uint32_t sourceGID = 0;
  uint64_t sourcePID = 0;
  String captureSHA256;
  bool success = false;
  String failure;
  uint64_t activeDeploymentID = 0;
  uint64_t successorDeploymentID = 0;
  uint64_t durableGeneration = 0;
};
template <typename S>
static void serialize(S&& serializer, RecoverMaterializedStatefulDeployment& payload)
{
  serializer.text1b(payload.applicationName, 128);
  serializer.value2b(payload.applicationID);
  serializer.value8b(payload.activeVersionID);
  serializer.value8b(payload.successorVersionID);
  serializer.text1b(payload.operationID, 36);
  serializer.text1b(payload.successorBlobSHA256, 128);
  serializer.value1b(payload.retryFailedSuccessor);
  serializer.value8b(payload.replacementSuccessorVersionID);
  serializer.text1b(payload.replacementSuccessorBlobSHA256, 128);
  serializer.value16b(payload.sourceContainerUUID);
  serializer.value16b(payload.failedSuccessorContainerUUID);
  serializer.value16b(payload.sourceMachineUUID);
  serializer.value8b(payload.sourceDevice);
  serializer.value8b(payload.sourceInode);
  serializer.value4b(payload.sourceUID);
  serializer.value4b(payload.sourceGID);
  serializer.value8b(payload.sourcePID);
  serializer.text1b(payload.captureSHA256, 128);
  serializer.value1b(payload.success);
  serializer.text1b(payload.failure, UINT32_MAX);
  serializer.value8b(payload.activeDeploymentID);
  serializer.value8b(payload.successorDeploymentID);
  serializer.value8b(payload.durableGeneration);
}

// The trusted control plane identifies retained storage by immutable host
// identity.  Callers never supply a path: ContainerManager derives it from
// sourceContainerUUID and verifies the capture receipt before use.
class RetainedContainerStorageSource {
public:
  uint128_t sourceContainerUUID = 0;
  uint128_t failedSuccessorContainerUUID = 0;
  uint128_t machineUUID = 0;
  uint64_t sourceDevice = 0;
  uint64_t sourceInode = 0;
  uint32_t sourceUID = 0;
  uint32_t sourceGID = 0;
  uint64_t sourcePID = 0;
  String captureSHA256;
};
template <typename S>
static void serialize(S&& serializer, RetainedContainerStorageSource& source)
{
  serializer.value16b(source.sourceContainerUUID);
  serializer.value16b(source.failedSuccessorContainerUUID);
  serializer.value16b(source.machineUUID);
  serializer.value8b(source.sourceDevice);
  serializer.value8b(source.sourceInode);
  serializer.value4b(source.sourceUID);
  serializer.value4b(source.sourceGID);
  serializer.value8b(source.sourcePID);
  serializer.text1b(source.captureSHA256, 128);
}

static inline bool prodigyCanonicalOperationUUID(const String& value)
{
  if (value.size() != 36)
  {
    return false;
  }
  for (uint32_t index = 0; index < value.size(); ++index)
  {
    const char c = value[index];
    if (index == 8 || index == 13 || index == 18 || index == 23)
    {
      if (c != '-') return false;
      continue;
    }
    if ((c < '0' || c > '9') && (c < 'a' || c > 'f'))
    {
      return false;
    }
  }
  return true;
}

// A retained stateful deployment is re-armed only from an exact observation of
// its existing identity.  Container UUID is also the durable storage owner, so
// pairing it with the registered machine UUID binds the retained runtime and
// storage lineage without accepting an operator-selected filesystem path.
class ProdigyRetainedStatefulRearmMember {
public:
  uint128_t containerUUID = 0;
  uint128_t machineUUID = 0;
  uint32_t shardGroup = UINT32_MAX;
  ContainerState state = ContainerState::none;
  bool runtimeReady = false;
};

template <typename S>
static void serialize(S&& serializer, ProdigyRetainedStatefulRearmMember& member)
{
  serializer.value16b(member.containerUUID);
  serializer.value16b(member.machineUUID);
  serializer.value4b(member.shardGroup);
  serializer.value1b(member.state);
  serializer.value1b(member.runtimeReady);
}

// Immutable request scope.  The canonical digest below covers every field in
// this object; acceptedAtMs deliberately lives outside it so retries compare
// only operator-supplied and freshly observed authority.
class ProdigyRetainedStatefulRearmScope {
public:
  String operationID;
  uint128_t clusterUUID = 0;
  String applicationName;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  uint64_t versionID = 0;
  String canonicalPlanSHA256;
  String artifactSHA256;
  uint64_t artifactBytes = 0;
  Vector<uint128_t> machineUUIDs;
  Vector<ProdigyRetainedStatefulRearmMember> retainedMembers;
  DeploymentState expectedState = DeploymentState::none;
  uint32_t expectedTarget = 0;
  uint32_t expectedDeployed = 0;
  uint32_t expectedHealthy = 0;
  uint32_t expectedAcknowledgedPeers = 0;
  uint32_t expectedRuntimeMembers = 0;
  uint32_t expectedRuntimeStateRecords = 0;
  uint32_t desiredReplicas = 0;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  bool expectedIPv6Only = true;
};

template <typename S>
static void serialize(S&& serializer, ProdigyRetainedStatefulRearmScope& scope)
{
  serializer.text1b(scope.operationID, 36);
  serializer.value16b(scope.clusterUUID);
  serializer.text1b(scope.applicationName, 128);
  serializer.value2b(scope.applicationID);
  serializer.value8b(scope.deploymentID);
  serializer.value8b(scope.versionID);
  serializer.text1b(scope.canonicalPlanSHA256, 64);
  serializer.text1b(scope.artifactSHA256, 64);
  serializer.value8b(scope.artifactBytes);
  serializer.container(scope.machineUUIDs, 3, [](auto& nested, uint128_t& uuid) { nested.value16b(uuid); });
  serializer.container(scope.retainedMembers, 3,
      [](auto& nested, ProdigyRetainedStatefulRearmMember& member) { nested.object(member); });
  serializer.value1b(scope.expectedState);
  serializer.value4b(scope.expectedTarget);
  serializer.value4b(scope.expectedDeployed);
  serializer.value4b(scope.expectedHealthy);
  serializer.value4b(scope.expectedAcknowledgedPeers);
  serializer.value4b(scope.expectedRuntimeMembers);
  serializer.value4b(scope.expectedRuntimeStateRecords);
  serializer.value4b(scope.desiredReplicas);
  serializer.value8b(scope.expectedAuthorityGeneration);
  serializer.value16b(scope.expectedMasterUUID);
  serializer.value8b(scope.expectedMasterBootNs);
  serializer.value1b(scope.expectedIPv6Only);
}

class ProdigyRetainedStatefulRearmProof {
public:
  ProdigyRetainedStatefulRearmScope scope;
  String retainedStateSHA256;
  int64_t acceptedAtMs = 0;
};

template <typename S>
static void serialize(S&& serializer, ProdigyRetainedStatefulRearmProof& proof)
{
  serializer.object(proof.scope);
  serializer.text1b(proof.retainedStateSHA256, 64);
  serializer.value8b(proof.acceptedAtMs);
}

static inline bool prodigyRetainedStatefulRearmScopeValid(
    const ProdigyRetainedStatefulRearmScope& scope)
{
  if (!prodigyCanonicalOperationUUID(scope.operationID) || scope.clusterUUID == 0 ||
      scope.applicationName.empty() || scope.applicationName.size() > 128 || scope.applicationID == 0 ||
      scope.versionID == 0 || scope.versionID >= (uint64_t(1) << 48) ||
      scope.deploymentID != ((uint64_t(scope.applicationID) << 48) | scope.versionID) ||
      !prodigyIsSHA256HexDigest(scope.canonicalPlanSHA256) ||
      !prodigyIsSHA256HexDigest(scope.artifactSHA256) || scope.artifactBytes == 0 ||
      scope.machineUUIDs.size() != 3 || scope.retainedMembers.size() != 2 ||
      scope.expectedState != DeploymentState::none || scope.expectedTarget != 0 ||
      scope.expectedDeployed != 0 || scope.expectedHealthy != 2 || scope.desiredReplicas != 3 ||
      scope.expectedAcknowledgedPeers != 2 || scope.expectedRuntimeMembers != 2 ||
      // The retained predecessor predates a sealed serving-authority package.
      // Its three fresh runtime rows are a post-recovery identity observation,
      // not an authority record that may be inferred before the missing replica
      // is launched.
      scope.expectedRuntimeStateRecords != 0 || scope.expectedAuthorityGeneration == 0 ||
      scope.expectedMasterUUID == 0 || scope.expectedMasterBootNs <= 0 || !scope.expectedIPv6Only)
  {
    return false;
  }
  uint128_t previousMachine = 0;
  for (uint128_t machineUUID : scope.machineUUIDs)
  {
    if (machineUUID == 0 || (previousMachine != 0 && machineUUID <= previousMachine)) return false;
    previousMachine = machineUUID;
  }
  uint128_t previousContainer = 0;
  uint32_t runtimeReady = 0;
  for (const auto& member : scope.retainedMembers)
  {
    if (member.containerUUID == 0 || member.machineUUID == 0 || member.shardGroup != 0 ||
        member.state != ContainerState::healthy ||
        (previousContainer != 0 && member.containerUUID <= previousContainer) ||
        !std::binary_search(scope.machineUUIDs.begin(), scope.machineUUIDs.end(), member.machineUUID))
    {
      return false;
    }
    for (const auto& other : scope.retainedMembers)
      if (&other != &member && other.machineUUID == member.machineUUID) return false;
    previousContainer = member.containerUUID;
    runtimeReady += member.runtimeReady;
  }
  return runtimeReady == scope.expectedRuntimeMembers;
}

static inline bool prodigyRetainedStatefulRearmScopeSHA256(
    const ProdigyRetainedStatefulRearmScope& scope, String& digest)
{
  if (!prodigyRetainedStatefulRearmScopeValid(scope)) return false;
  String encoded = {};
  auto copy = scope;
  return BitseryEngine::serialize(encoded, copy) && prodigyComputeSHA256Hex(encoded, digest);
}

static inline bool prodigyRetainedStatefulRearmProofValid(
    const ProdigyRetainedStatefulRearmProof& proof, bool requireAccepted = true)
{
  String digest = {};
  return prodigyRetainedStatefulRearmScopeSHA256(proof.scope, digest) &&
      digest.equals(proof.retainedStateSHA256) && (!requireAccepted || proof.acceptedAtMs > 0);
}

static inline bool prodigyRetainedStatefulRearmProofEqual(
    const ProdigyRetainedStatefulRearmProof& left,
    const ProdigyRetainedStatefulRearmProof& right,
    bool includeAcceptanceTime = true)
{
  String a = {}, b = {};
  auto leftScope = left.scope, rightScope = right.scope;
  return BitseryEngine::serialize(a, leftScope) && BitseryEngine::serialize(b, rightScope) && a == b &&
      left.retainedStateSHA256.equals(right.retainedStateSHA256) &&
      (!includeAcceptanceTime || left.acceptedAtMs == right.acceptedAtMs);
}

// One shared payload is used for request and response on the bidirectional
// re-arm topic.  `response` prevents a shifted or reflected request from being
// interpreted as an acceptance receipt.
class RearmRetainedStatefulDeployment {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  bool response = false;
  ProdigyRetainedStatefulRearmProof proof;
  bool success = false;
  bool idempotent = false;
  bool completed = false;
  uint64_t durableGeneration = 0;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, RearmRetainedStatefulDeployment& payload)
{
  serializer.value4b(payload.protocolVersion);
  serializer.value1b(payload.response);
  serializer.object(payload.proof);
  serializer.value1b(payload.success);
  serializer.value1b(payload.idempotent);
  serializer.value1b(payload.completed);
  serializer.value8b(payload.durableGeneration);
  serializer.text1b(payload.failure, 4096);
}

enum class ProdigyLocalBundleRecoveryWitnessRepairAction : uint8_t {
  query = 1,
  retire = 2
};

class ProdigyLocalBundleRecoveryWitnessMachineScope {
public:
  uint128_t machineUUID = 0;
  bool bundleRegistered = false;
  uint32_t bootstrapCount = 0;
  String bootstrapInventorySHA256;
};

template <typename S>
static void serialize(S&& serializer, ProdigyLocalBundleRecoveryWitnessMachineScope& scope)
{
  serializer.value16b(scope.machineUUID);
  serializer.value1b(scope.bundleRegistered);
  serializer.value4b(scope.bootstrapCount);
  serializer.text1b(scope.bootstrapInventorySHA256, 64);
}

// This scope contains only non-secret identities and fingerprints. The raw
// captured bootstraps remain in the existing updateSelf authority owner.
class ProdigyLocalBundleRecoveryWitnessRepairScope {
public:
  uint128_t operationUUID = 0;
  uint128_t clusterUUID = 0;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  String installedBundleSHA256;
  String witnessExpectedBundleSHA256;
  Vector<ProdigyLocalBundleRecoveryWitnessMachineScope> machines;
};

template <typename S>
static void serialize(S&& serializer, ProdigyLocalBundleRecoveryWitnessRepairScope& scope)
{
  serializer.value16b(scope.operationUUID);
  serializer.value16b(scope.clusterUUID);
  serializer.value8b(scope.expectedAuthorityGeneration);
  serializer.value16b(scope.expectedMasterUUID);
  serializer.value8b(scope.expectedMasterBootNs);
  serializer.text1b(scope.installedBundleSHA256, 64);
  serializer.text1b(scope.witnessExpectedBundleSHA256, 64);
  serializer.container(scope.machines, 3, [](auto& nested, auto& machine) { nested.object(machine); });
}

static inline bool prodigyLocalBundleRecoveryWitnessRepairScopeValid(
    const ProdigyLocalBundleRecoveryWitnessRepairScope& scope)
{
  if (scope.operationUUID == 0 || scope.clusterUUID == 0 ||
      scope.expectedAuthorityGeneration == 0 || scope.expectedAuthorityGeneration == UINT64_MAX ||
      scope.expectedMasterUUID == 0 || scope.expectedMasterBootNs <= 0 ||
      !prodigyIsSHA256HexDigest(scope.installedBundleSHA256) ||
      !prodigyIsSHA256HexDigest(scope.witnessExpectedBundleSHA256) ||
      scope.machines.size() != 3)
  {
    return false;
  }
  const bool superseded = !scope.installedBundleSHA256.equals(
      scope.witnessExpectedBundleSHA256);
  uint128_t previousMachine = 0;
  for (const auto& machine : scope.machines)
  {
    if (machine.machineUUID == 0 || machine.machineUUID <= previousMachine ||
        machine.bundleRegistered == superseded ||
        !prodigyIsSHA256HexDigest(machine.bootstrapInventorySHA256))
    {
      return false;
    }
    previousMachine = machine.machineUUID;
  }
  return true;
}

static inline bool prodigyLocalBundleRecoveryWitnessRepairScopeSuperseded(
    const ProdigyLocalBundleRecoveryWitnessRepairScope& scope)
{
  return prodigyLocalBundleRecoveryWitnessRepairScopeValid(scope) &&
      !scope.installedBundleSHA256.equals(scope.witnessExpectedBundleSHA256);
}

static inline bool prodigyLocalBundleRecoveryWitnessRepairScopeSHA256(
    const ProdigyLocalBundleRecoveryWitnessRepairScope& scope, String& digest)
{
  if (!prodigyLocalBundleRecoveryWitnessRepairScopeValid(scope)) return false;
  String encoded = {};
  auto copy = scope;
  return BitseryEngine::serialize(encoded, copy) && prodigyComputeSHA256Hex(encoded, digest);
}

class ProdigyLocalBundleRecoveryWitnessRepairReceipt {
public:
  ProdigyLocalBundleRecoveryWitnessRepairScope scope;
  String scopeSHA256;
  int64_t acceptedAtMs = 0;
  uint64_t retiredAtAuthorityGeneration = 0;
};

template <typename S>
static void serialize(S&& serializer, ProdigyLocalBundleRecoveryWitnessRepairReceipt& receipt)
{
  serializer.object(receipt.scope);
  serializer.text1b(receipt.scopeSHA256, 64);
  serializer.value8b(receipt.acceptedAtMs);
  serializer.value8b(receipt.retiredAtAuthorityGeneration);
}

static inline bool prodigyLocalBundleRecoveryWitnessRepairReceiptValid(
    const ProdigyLocalBundleRecoveryWitnessRepairReceipt& receipt)
{
  String digest = {};
  return prodigyLocalBundleRecoveryWitnessRepairScopeSHA256(receipt.scope, digest) &&
      digest.equals(receipt.scopeSHA256) && receipt.acceptedAtMs > 0 &&
      receipt.retiredAtAuthorityGeneration == receipt.scope.expectedAuthorityGeneration + 1;
}

class ProdigyLocalBundleRecoveryWitnessRepairJournal {
public:
  static constexpr uint32_t legacyVersion = 1;
  static constexpr uint32_t version = 2;
  uint32_t protocolVersion = version;
  Vector<ProdigyLocalBundleRecoveryWitnessRepairReceipt> receipts;
};

template <typename S>
static void serialize(S&& serializer, ProdigyLocalBundleRecoveryWitnessRepairJournal& journal)
{
  serializer.value4b(journal.protocolVersion);
  serializer.container(journal.receipts, 64, [](auto& nested, auto& receipt) { nested.object(receipt); });
}

static inline bool prodigyLocalBundleRecoveryWitnessRepairJournalValid(
    const ProdigyLocalBundleRecoveryWitnessRepairJournal& journal)
{
  if ((journal.protocolVersion != ProdigyLocalBundleRecoveryWitnessRepairJournal::legacyVersion &&
       journal.protocolVersion != ProdigyLocalBundleRecoveryWitnessRepairJournal::version) ||
      journal.receipts.size() > 64)
  {
    return false;
  }
  for (uint32_t index = 0; index < journal.receipts.size(); ++index)
  {
    const auto& receipt = journal.receipts[index];
    if (!prodigyLocalBundleRecoveryWitnessRepairReceiptValid(receipt) ||
        (journal.protocolVersion == ProdigyLocalBundleRecoveryWitnessRepairJournal::legacyVersion &&
         prodigyLocalBundleRecoveryWitnessRepairScopeSuperseded(receipt.scope))) return false;
    for (uint32_t earlier = 0; earlier < index; ++earlier)
      if (journal.receipts[earlier].scope.operationUUID == receipt.scope.operationUUID ||
          journal.receipts[earlier].scopeSHA256 == receipt.scopeSHA256)
        return false;
  }
  return true;
}

// Reserved task-execution identities are the existing schema-neutral carrier
// for replicated maintenance journals. Deployment IDs always include a
// nonzero application ID in their high bits, so this identity cannot collide.
constexpr static uint64_t prodigyLocalBundleRecoveryWitnessRepairJournalExecutionID = 2;
constexpr static uint64_t prodigyLocalBundleRecoveryWitnessRepairJournalVersionID = 0x4c4257520001ULL;
constexpr static uint64_t prodigyLocalBundleRecoveryWitnessRepairJournalMaximumPayloadBytes =
    64 * 1024;

// One shared payload serves query and retire in both directions. `response`
// prevents a reflected request from being accepted as a durable receipt.
class RepairLocalBundleRecoveryWitness {
public:
  static constexpr uint32_t version = 2;
  uint32_t protocolVersion = version;
  bool response = false;
  ProdigyLocalBundleRecoveryWitnessRepairAction action =
      ProdigyLocalBundleRecoveryWitnessRepairAction::query;
  uint128_t operationUUID = 0;
  uint128_t clusterUUID = 0;
  ProdigyLocalBundleRecoveryWitnessRepairScope scope;
  String scopeSHA256;
  bool witnessPresent = false;
  bool eligible = false;
  bool success = false;
  bool idempotent = false;
  bool completed = false;
  uint64_t durableGeneration = 0;
  int64_t acceptedAtMs = 0;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, RepairLocalBundleRecoveryWitness& payload)
{
  serializer.value4b(payload.protocolVersion);
  serializer.value1b(payload.response);
  serializer.value1b(payload.action);
  serializer.value16b(payload.operationUUID);
  serializer.value16b(payload.clusterUUID);
  serializer.object(payload.scope);
  serializer.text1b(payload.scopeSHA256, 64);
  serializer.value1b(payload.witnessPresent);
  serializer.value1b(payload.eligible);
  serializer.value1b(payload.success);
  serializer.value1b(payload.idempotent);
  serializer.value1b(payload.completed);
  serializer.value8b(payload.durableGeneration);
  serializer.value8b(payload.acceptedAtMs);
  serializer.text1b(payload.failure, 4096);
}

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
  // Filled only by the selected Neuron immediately before a typed gateway
  // launch; these values never travel as a general system-container API.
  String gatewayReadinessSocket, gatewayLaunchToken, gatewayRecoverySocket, gatewayRecoveryToken, gatewayRole, gatewayRoutes;
  String gatewayEndpoint, gatewayLocalIdentity, gatewayPeerIdentity, gatewayPeerTrust;
  // Exact TUN owned by this gateway authority.  The child must use the same
  // interface that Neuron binds private BGP to; accepting a CLI-selected name
  // would let readiness describe one path while BGP used another.
  String gatewayTunnelInterface;
  // Typed references to the committed gateway authority. Keep UUIDs numeric
  // until launch so the child receives canonical hexadecimal, not CLI text.
  uint128_t gatewayPairUUID = 0, gatewayLocalClusterUUID = 0, gatewayLocalMachineUUID = 0;
  uint64_t gatewayKeyEpoch = 0, gatewayAuthorityGeneration = 0, gatewayGeneration = 0;

  bool configured(void) const
  {
    return kind != SystemContainerKind::none;
  }
};

// Neutral, credential-free identity for one private-BGP delivery.  It lives
// with the shared wire structs because Brain, Neuron, and lifecycle records
// all need the exact same scope without importing Vault behavior.
class ProdigyPairPrivateBGPSecretScope {
public:
  uint128_t pairUUID = 0;
  uint128_t operationUUID = 0;
  uint64_t keyEpoch = 0;
  uint8_t tunnelSlot = 0;
  uint128_t clusterUUID = 0;
  uint128_t machineUUID = 0;
  uint64_t authorityGeneration = 0;
  uint64_t gatewayGeneration = 0;
};
template <typename S> static void serialize(S&& s, ProdigyPairPrivateBGPSecretScope& scope)
{ s.value16b(scope.pairUUID); s.value16b(scope.operationUUID); s.value8b(scope.keyEpoch); s.value1b(scope.tunnelSlot);
  s.value16b(scope.clusterUUID); s.value16b(scope.machineUUID); s.value8b(scope.authorityGeneration); s.value8b(scope.gatewayGeneration); }


template <typename S>
static void serialize(S&& serializer, SystemContainerRuntimePlan& plan)
{
  serializer.value1b(plan.kind);
  serializer.object(plan.artifact);
  serializer.object(plan.egress);
  serializer.text1b(plan.gatewayReadinessSocket, 255);
  serializer.text1b(plan.gatewayLaunchToken, 128);
  serializer.text1b(plan.gatewayRole, 16);
  serializer.text1b(plan.gatewayRoutes, 512);
  serializer.text1b(plan.gatewayEndpoint, 128);
  serializer.text1b(plan.gatewayLocalIdentity, 64);
  serializer.text1b(plan.gatewayPeerIdentity, 64);
  serializer.text1b(plan.gatewayPeerTrust, 64);
  serializer.text1b(plan.gatewayTunnelInterface, 15);
  serializer.value16b(plan.gatewayPairUUID);
  serializer.value16b(plan.gatewayLocalClusterUUID);
  serializer.value16b(plan.gatewayLocalMachineUUID);
  serializer.value8b(plan.gatewayKeyEpoch);
  serializer.value8b(plan.gatewayAuthorityGeneration);
  serializer.value8b(plan.gatewayGeneration);
}

// The gateway ledger and the corresponding reconciliation inventory share one
// cardinality limit: every advertised artifact must be justified by an active
// authority record.
constexpr uint32_t ProdigyCrossClusterMasqueGatewayAuthorityMaximumRecords = 256;

class BrainReconcileStateRequest {
public:

  static constexpr uint32_t maximumCrossClusterMasqueGatewayArtifacts = 256;
  Vector<uint64_t> deploymentIDs;
  SystemContainerArtifactRef systemArtifact;
  // The tunnel-provider artifact predates the multi-gateway ledger and keeps
  // its dedicated field. MASQUE gateway artifacts are a deduplicated
  // inventory because one Brain can own multiple active authorities.
  Vector<SystemContainerArtifactRef> crossClusterMasqueGatewayArtifacts;
};

template <typename S>
static void serialize(S&& serializer, BrainReconcileStateRequest& request)
{
  serializer.object(request.deploymentIDs);
  serializer.object(request.systemArtifact);
  serializer.container(request.crossClusterMasqueGatewayArtifacts,
      BrainReconcileStateRequest::maximumCrossClusterMasqueGatewayArtifacts,
      [](auto& nested, SystemContainerArtifactRef& artifact) { nested.object(artifact); });
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

  // For overlay routes this is { datacenterFragment:8, machineFragment:24 }.
  // The field name is retained for the wire format and existing map layout.
  uint32_t machineFragment = 0;
  IPAddress nextHop = {};
  IPAddress sourceAddress = {};
  bool useGatewayMAC = false;
  String nextHopMAC;
  // A nonzero value selects host-local netkit delivery instead of NIC egress.
  // Only the two allocator-reserved MASQUE gateway fragments are valid for
  // cross-cluster private-site fallbacks.
  uint8_t localContainerRedirectFragment = 0;

  bool operator==(const SwitchboardOverlayMachineRoute& other) const
  {
    return machineFragment == other.machineFragment && nextHop.equals(other.nextHop) && sourceAddress.equals(other.sourceAddress) && useGatewayMAC == other.useGatewayMAC && nextHopMAC.equals(other.nextHopMAC) && localContainerRedirectFragment == other.localContainerRedirectFragment;
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
  serializer.value1b(route.localContainerRedirectFragment);
}

class SwitchboardOverlayHostedIngressRoute {
public:

  IPPrefix prefix;
  // Same full overlay identity as SwitchboardOverlayMachineRoute.
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
    if (uuid != 0 && other.uuid != 0)
    {
      return uuid == other.uuid;
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

  bool preservesIdentityAndConfigurationForRackUpdate(const ClusterMachine& other) const
  {
    if (uuid == 0 || uuid != other.uuid)
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

    return source == other.source && backing == other.backing && kind == other.kind &&
           lifetime == other.lifetime && isBrain == other.isBrain &&
           cloudPresent() == other.cloudPresent() &&
           (cloudPresent() == false || cloud == other.cloud) && ssh == other.ssh &&
           addresses == other.addresses && creationTimeMs == other.creationTimeMs &&
           vmImageURI == other.vmImageURI && ownership == other.ownership;
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
  bool hasTimingAttribution = false;
  ProdigyTimingAttribution timingAttribution;
  String reachabilityProbeAddress;
  Vector<BrainReachabilityProbeResult> reachabilityResults;
  bool success = false;
  bool hasTopology = false;
  ClusterTopology topology;
  String failure;

  bool operator==(const AddMachines& other) const
  {
    if (adoptedMachines.size() != other.adoptedMachines.size() || readyMachines.size() != other.readyMachines.size() || removedMachines.size() != other.removedMachines.size() || provisioningProgress.size() != other.provisioningProgress.size() || reachabilityResults.size() != other.reachabilityResults.size() || bootstrapSshUser.equals(other.bootstrapSshUser) == false || bootstrapSshKeyPackage != other.bootstrapSshKeyPackage || bootstrapSshHostKeyPackage != other.bootstrapSshHostKeyPackage || bootstrapSshPrivateKeyPath.equals(other.bootstrapSshPrivateKeyPath) == false || remoteProdigyPath.equals(other.remoteProdigyPath) == false || controlSocketPath.equals(other.controlSocketPath) == false || !(acme == other.acme) || clusterUUID != other.clusterUUID || architecture != other.architecture || isProgress != other.isProgress
        || hasTimingAttribution != other.hasTimingAttribution || timingAttribution != other.timingAttribution
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
  serializer.value1b(payload.hasTimingAttribution);
  serializer.object(payload.timingAttribution);
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
  bool hasTimingAttribution = false;
  ProdigyTimingAttribution timingAttribution;
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
  serializer.value1b(payload.hasTimingAttribution);
  serializer.object(payload.timingAttribution);
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
  bool rootFilesystemReadOnly = false;
  uint16_t runAsID = 0;

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
  serializer.value1b(config.rootFilesystemReadOnly);
  serializer.value2b(config.runAsID);
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
// Evidence tasks may retry after a transient worker failure, but their
// Mothership-owned execution record must reach a terminal state without
// repeatedly re-running a completed or permanently failing fixture.
constexpr static uint32_t prodigyTaskUntilSucceededMaximumAttempts = 3u;

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
  if (taskExecutionTerminal(from))
  {
    return false;
  }

  if (from == to)
  {
    return true;
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

static inline TaskExecutionState taskExecutionStateForAttemptTermination(TaskExecutionPolicy policy,
                                                                          const TaskTermination& termination,
                                                                          uint32_t attemptNumber)
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
  if (policy == TaskExecutionPolicy::untilSucceeded && attemptNumber < prodigyTaskUntilSucceededMaximumAttempts)
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

  TaskExecutionState next = taskExecutionStateForAttemptTermination(record.policy, attempt.termination, attempt.attemptNumber);
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

  bool hasDistinctServices() const
  {
    // Compare materialized service identities, not the caller's raw prefixes:
    // replacing their group bits can make different input values alias.
    const uint64_t services[] = {client, sibling, cousin, seeding, sharding, topologyBridge};
    for (uint32_t index = 0; index < 6; ++index)
      for (uint32_t other = index + 1; other < 6; ++other)
        if (services[index] != 0 && services[index] == services[other]) return false;
    return true;
  }

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
  drainOnly,
  // Explicit versioned tail. Existing topology encodings remain unchanged.
  applicationDataAuthority,
  allMastersSeedBootstrap
};

enum class StatefulDataAuthorityMode : uint8_t {
  retainedSource = 1,
  catchupOnly = 2,
  writeOwner = 3,
  fenced = 4,
  snapshotPreparing = 5
};

// Application data authority is separate from network reachability. Hashes
// bind the application's canonical sorted UUID->durable-head map; Prodigy
// neither reconstructs that map nor infers a write fence from healthy replicas.
class StatefulDataAuthority {
public:
  // Version one is the exact legacy authority wire. Version two appends the
  // immutable shard-group cardinality without changing any v1 byte offset.
  static constexpr uint32_t legacyContractVersion = 1;
  static constexpr uint32_t version = 2;
  uint32_t contractVersion = version;
  uint128_t operationUUID = 0;
  uint128_t previousOperationUUID = 0;
  uint64_t previousAuthorityEpoch = 0;
  uint128_t datasetUUID = 0;
  uint128_t snapshotUUID = 0;
  uint128_t sourceClusterUUID = 0;
  uint128_t targetClusterUUID = 0;
  uint128_t localClusterUUID = 0;
  uint128_t writeOwnerClusterUUID = 0;
  uint64_t authorityEpoch = 0;
  uint32_t shardGroup = 0;
  // The immutable global cardinality used by jump-hash ownership.  A paired
  // migration moves one group, but its target must retain this full topology.
  uint32_t nShardGroups = 0;
  StatefulDataAuthorityMode mode = StatefulDataAuthorityMode::catchupOnly;
  String contractSHA256;
  String shardManifestSHA256;
  String snapshotBoundarySHA256;
  String requiredAppliedWatermarkSHA256;
};

template <typename S>
static void serialize(S&& serializer, StatefulDataAuthority& authority)
{
  serializer.value4b(authority.contractVersion);
  serializer.value16b(authority.operationUUID);
  serializer.value16b(authority.previousOperationUUID);
  serializer.value8b(authority.previousAuthorityEpoch);
  serializer.value16b(authority.datasetUUID);
  serializer.value16b(authority.snapshotUUID);
  serializer.value16b(authority.sourceClusterUUID);
  serializer.value16b(authority.targetClusterUUID);
  serializer.value16b(authority.localClusterUUID);
  serializer.value16b(authority.writeOwnerClusterUUID);
  serializer.value8b(authority.authorityEpoch);
  serializer.value4b(authority.shardGroup);
  serializer.value1b(authority.mode);
  serializer.text1b(authority.contractSHA256, 64);
  serializer.text1b(authority.shardManifestSHA256, 64);
  serializer.text1b(authority.snapshotBoundarySHA256, 64);
  serializer.text1b(authority.requiredAppliedWatermarkSHA256, 64);
  if (authority.contractVersion >= StatefulDataAuthority::version)
    serializer.value4b(authority.nShardGroups);
}

static inline bool prodigyStatefulDataAuthorityValid(const StatefulDataAuthority& authority)
{
  if ((authority.contractVersion != StatefulDataAuthority::legacyContractVersion &&
       authority.contractVersion != StatefulDataAuthority::version) ||
      authority.operationUUID == 0 ||
      authority.datasetUUID == 0 || authority.snapshotUUID == 0 ||
      ((authority.previousOperationUUID == 0) != (authority.previousAuthorityEpoch == 0)) ||
      (authority.previousAuthorityEpoch != 0 && authority.authorityEpoch <= authority.previousAuthorityEpoch) ||
      authority.sourceClusterUUID == 0 || authority.targetClusterUUID == 0 ||
      authority.sourceClusterUUID == authority.targetClusterUUID || authority.authorityEpoch == 0 ||
      (authority.contractVersion == StatefulDataAuthority::legacyContractVersion
        ? authority.nShardGroups != 0
        : (authority.nShardGroups == 0 || authority.shardGroup >= authority.nShardGroups)) ||
      (authority.localClusterUUID != authority.sourceClusterUUID && authority.localClusterUUID != authority.targetClusterUUID) ||
      (authority.writeOwnerClusterUUID != authority.sourceClusterUUID && authority.writeOwnerClusterUUID != authority.targetClusterUUID) ||
      !prodigyIsSHA256HexDigest(authority.contractSHA256) ||
      !prodigyIsSHA256HexDigest(authority.shardManifestSHA256)) return false;
  if (authority.mode == StatefulDataAuthorityMode::snapshotPreparing)
    return authority.localClusterUUID == authority.sourceClusterUUID &&
        authority.writeOwnerClusterUUID == authority.sourceClusterUUID &&
        authority.snapshotBoundarySHA256.empty() && authority.requiredAppliedWatermarkSHA256.empty();
  if (authority.mode == StatefulDataAuthorityMode::retainedSource)
    return authority.localClusterUUID == authority.sourceClusterUUID &&
        (authority.snapshotBoundarySHA256.empty() || prodigyIsSHA256HexDigest(authority.snapshotBoundarySHA256)) &&
        (authority.writeOwnerClusterUUID == authority.sourceClusterUUID ? authority.requiredAppliedWatermarkSHA256.empty() :
         (prodigyIsSHA256HexDigest(authority.snapshotBoundarySHA256) && prodigyIsSHA256HexDigest(authority.requiredAppliedWatermarkSHA256)));
  if (!prodigyIsSHA256HexDigest(authority.snapshotBoundarySHA256) ||
      (authority.mode != StatefulDataAuthorityMode::fenced &&
       !prodigyIsSHA256HexDigest(authority.requiredAppliedWatermarkSHA256)) ||
      (authority.mode == StatefulDataAuthorityMode::fenced && !authority.requiredAppliedWatermarkSHA256.empty())) return false;
  switch (authority.mode) {
    case StatefulDataAuthorityMode::retainedSource:
      return authority.localClusterUUID == authority.sourceClusterUUID &&
             authority.writeOwnerClusterUUID == authority.sourceClusterUUID;
    case StatefulDataAuthorityMode::catchupOnly:
      return authority.localClusterUUID == authority.targetClusterUUID &&
             authority.writeOwnerClusterUUID == authority.sourceClusterUUID;
    case StatefulDataAuthorityMode::writeOwner:
      return authority.localClusterUUID == authority.writeOwnerClusterUUID;
    case StatefulDataAuthorityMode::fenced:
      return authority.localClusterUUID == authority.sourceClusterUUID;
    case StatefulDataAuthorityMode::snapshotPreparing: return false;
  }
  return false;
}

static inline bool prodigyStatefulDataAuthorityEqual(const StatefulDataAuthority& a,
                                                    const StatefulDataAuthority& b)
{
  String left, right;
  auto ac = a, bc = b;
  BitseryEngine::serialize(left, ac);
  BitseryEngine::serialize(right, bc);
  return left == right;
}

static inline bool prodigyStatefulDataAuthoritySourceNonwriter(const StatefulDataAuthority& value)
{
  return value.localClusterUUID == value.sourceClusterUUID &&
      (value.mode == StatefulDataAuthorityMode::fenced ||
       (value.mode == StatefulDataAuthorityMode::retainedSource && value.writeOwnerClusterUUID == value.targetClusterUUID));
}

static inline bool prodigyStatefulDataAuthorityCanAdvance(const StatefulDataAuthority& previous,
                                                         const StatefulDataAuthority& next)
{
  if (!prodigyStatefulDataAuthorityValid(previous) || !prodigyStatefulDataAuthorityValid(next)) return false;
  if (prodigyStatefulDataAuthorityEqual(previous, next)) return true;
  if (next.contractVersion != previous.contractVersion || next.authorityEpoch <= previous.authorityEpoch ||
      next.contractSHA256 != previous.contractSHA256 ||
      next.shardManifestSHA256 != previous.shardManifestSHA256 || next.shardGroup != previous.shardGroup ||
      next.nShardGroups != previous.nShardGroups ||
      next.datasetUUID != previous.datasetUUID || next.localClusterUUID != previous.localClusterUUID) return false;
  if (next.operationUUID != previous.operationUUID) {
    if (next.previousOperationUUID != previous.operationUUID ||
        (next.previousAuthorityEpoch < previous.authorityEpoch &&
         !(previous.mode == StatefulDataAuthorityMode::retainedSource &&
           previous.writeOwnerClusterUUID == previous.targetClusterUUID && next.previousAuthorityEpoch != 0))) return false;
    const bool reversed = next.sourceClusterUUID == previous.targetClusterUUID && next.targetClusterUUID == previous.sourceClusterUUID;
    if (prodigyStatefulDataAuthoritySourceNonwriter(previous) && next.mode == StatefulDataAuthorityMode::catchupOnly)
      return reversed && next.localClusterUUID == next.targetClusterUUID;
    if (previous.mode == StatefulDataAuthorityMode::catchupOnly && next.mode == StatefulDataAuthorityMode::catchupOnly)
      return next.sourceClusterUUID == previous.sourceClusterUUID && next.targetClusterUUID == previous.targetClusterUUID;
    if (previous.mode == StatefulDataAuthorityMode::retainedSource && previous.writeOwnerClusterUUID == previous.sourceClusterUUID &&
        next.mode == StatefulDataAuthorityMode::snapshotPreparing)
      return next.sourceClusterUUID == previous.sourceClusterUUID && next.targetClusterUUID == previous.targetClusterUUID;
    return previous.mode == StatefulDataAuthorityMode::writeOwner &&
        previous.localClusterUUID == previous.targetClusterUUID &&
        next.mode == StatefulDataAuthorityMode::snapshotPreparing &&
        next.previousOperationUUID == previous.operationUUID && next.previousAuthorityEpoch == previous.authorityEpoch &&
        reversed;
  }
  if (next.previousOperationUUID != previous.previousOperationUUID || next.previousAuthorityEpoch != previous.previousAuthorityEpoch ||
      next.sourceClusterUUID != previous.sourceClusterUUID || next.targetClusterUUID != previous.targetClusterUUID ||
      next.snapshotUUID != previous.snapshotUUID) return false;
  if (previous.mode == StatefulDataAuthorityMode::snapshotPreparing)
    return next.mode == StatefulDataAuthorityMode::fenced ||
        (next.mode == StatefulDataAuthorityMode::retainedSource && next.writeOwnerClusterUUID == next.sourceClusterUUID);
  if (previous.mode == StatefulDataAuthorityMode::fenced)
    return next.mode == StatefulDataAuthorityMode::retainedSource && next.writeOwnerClusterUUID == next.targetClusterUUID &&
        next.snapshotBoundarySHA256 == previous.snapshotBoundarySHA256;
  if (previous.mode == StatefulDataAuthorityMode::catchupOnly)
    return next.snapshotBoundarySHA256 == previous.snapshotBoundarySHA256 &&
        (next.mode == StatefulDataAuthorityMode::catchupOnly || next.mode == StatefulDataAuthorityMode::writeOwner);
  return false;
}

class StatefulDataAuthorityReceipt {
public:
  StatefulDataAuthority authority;
  bool ready = false;
  String snapshotReceiptSHA256;
  String appliedWatermarkSHA256;
  String fenceReceiptSHA256;
  String cleanupReceiptSHA256;
};

template <typename S>
static void serialize(S&& serializer, StatefulDataAuthorityReceipt& receipt)
{
  serializer.object(receipt.authority);
  serializer.value1b(receipt.ready);
  serializer.text1b(receipt.snapshotReceiptSHA256, 64);
  serializer.text1b(receipt.appliedWatermarkSHA256, 64);
  serializer.text1b(receipt.fenceReceiptSHA256, 64);
  serializer.text1b(receipt.cleanupReceiptSHA256, 64);
}

static inline bool prodigyStatefulDataAuthorityReceiptStaged(const StatefulDataAuthorityReceipt& receipt)
{
  return prodigyStatefulDataAuthorityValid(receipt.authority) && !receipt.ready &&
      receipt.authority.mode == StatefulDataAuthorityMode::catchupOnly &&
      prodigyIsSHA256HexDigest(receipt.snapshotReceiptSHA256) &&
      receipt.snapshotReceiptSHA256 == receipt.authority.snapshotBoundarySHA256 &&
      receipt.appliedWatermarkSHA256.empty() && receipt.fenceReceiptSHA256.empty() && receipt.cleanupReceiptSHA256.empty();
}

static inline bool prodigyStatefulDataAuthorityReceiptValid(const StatefulDataAuthorityReceipt& receipt)
{
  if (prodigyStatefulDataAuthorityReceiptStaged(receipt)) return true;
  if (!prodigyStatefulDataAuthorityValid(receipt.authority) || !receipt.ready) return false;
  if (receipt.authority.mode == StatefulDataAuthorityMode::retainedSource)
    return prodigyIsSHA256HexDigest(receipt.cleanupReceiptSHA256) && prodigyIsSHA256HexDigest(receipt.appliedWatermarkSHA256) &&
        (receipt.authority.writeOwnerClusterUUID == receipt.authority.sourceClusterUUID ? receipt.fenceReceiptSHA256.empty() :
         (prodigyIsSHA256HexDigest(receipt.fenceReceiptSHA256) && receipt.appliedWatermarkSHA256 == receipt.authority.requiredAppliedWatermarkSHA256)) &&
        receipt.snapshotReceiptSHA256 == receipt.authority.snapshotBoundarySHA256;
  if (!receipt.cleanupReceiptSHA256.empty() || !prodigyIsSHA256HexDigest(receipt.snapshotReceiptSHA256)) return false;
  if (receipt.authority.mode == StatefulDataAuthorityMode::snapshotPreparing)
    return receipt.appliedWatermarkSHA256.empty() && receipt.fenceReceiptSHA256.empty();
  if (receipt.authority.mode == StatefulDataAuthorityMode::fenced)
    return receipt.snapshotReceiptSHA256 == receipt.authority.snapshotBoundarySHA256 &&
        prodigyIsSHA256HexDigest(receipt.appliedWatermarkSHA256) && prodigyIsSHA256HexDigest(receipt.fenceReceiptSHA256);
  if (receipt.snapshotReceiptSHA256 != receipt.authority.snapshotBoundarySHA256) return false;
  if (receipt.appliedWatermarkSHA256 != receipt.authority.requiredAppliedWatermarkSHA256) return false;
  return receipt.fenceReceiptSHA256.empty();
}

enum class StatefulTopologyBridgeMode : uint8_t {
  none,
  sourceToTarget,
  targetToSource,
  bidirectional
};

enum class StatefulWorkerTopologyUpgradePhase : uint8_t {
  none,
  greenBootstrap,
  blueDraining,
  applicationDataAuthority,
  allMastersSeedBootstrap,
  initialAllMastersSeedBootstrap
};

class ProdigyAllMastersSeedBootstrap {
public:
  uint128_t sourceClusterUUID = 0;
  uint128_t targetClusterUUID = 0;
  uint64_t targetDeploymentID = 0;
  uint128_t qualificationRunUUID = 0;
  uint128_t successorOperationUUID = 0;
  uint32_t shardGroup = 0;
  uint64_t expectedSeedGeneration = 0;

  bool operator==(const ProdigyAllMastersSeedBootstrap& o) const {
    return sourceClusterUUID == o.sourceClusterUUID && targetClusterUUID == o.targetClusterUUID &&
        targetDeploymentID == o.targetDeploymentID && qualificationRunUUID == o.qualificationRunUUID &&
        successorOperationUUID == o.successorOperationUUID && shardGroup == o.shardGroup &&
        expectedSeedGeneration == o.expectedSeedGeneration;
  }
};

template <typename S>
static void serialize(S&& s, ProdigyAllMastersSeedBootstrap& v)
{
  s.value16b(v.sourceClusterUUID); s.value16b(v.targetClusterUUID);
  s.value8b(v.targetDeploymentID); s.value16b(v.qualificationRunUUID);
  s.value16b(v.successorOperationUUID); s.value4b(v.shardGroup);
  s.value8b(v.expectedSeedGeneration);
}

// Initial remote seeding has no predecessor or cancellation.  This is a
// distinct wire scope so legacy qualified-successor records remain unchanged.
static constexpr uint64_t ProdigyInitialAllMastersSeedBootstrapCapability = 524288;
class ProdigyInitialAllMastersSeedBootstrapScope {
public:
  ProdigyAllMastersSeedBootstrap bootstrap;
  uint128_t baselineOperationUUID = 0;
  uint32_t nShardGroups = 0;
  String planSHA256;
  String artifactSHA256;
  uint64_t artifactBytes = 0;
};
template <typename S>
static void serialize(S&& s, ProdigyInitialAllMastersSeedBootstrapScope& v) {
  s.object(v.bootstrap); s.value16b(v.baselineOperationUUID); s.value4b(v.nShardGroups);
  s.text1b(v.planSHA256, 64); s.text1b(v.artifactSHA256, 64); s.value8b(v.artifactBytes);
}

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
  StatefulDataAuthority dataAuthority;
  ProdigyAllMastersSeedBootstrap allMastersSeedBootstrap;

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
  if (topology.servingMode == StatefulTopologyServingMode::applicationDataAuthority)
    serializer.object(topology.dataAuthority);
  if (topology.servingMode == StatefulTopologyServingMode::allMastersSeedBootstrap)
    serializer.object(topology.allMastersSeedBootstrap);
}

static inline bool prodigyStatefulTopologyIsAllMastersSeedBootstrap(const StatefulTopology& topology)
{
  const auto& v = topology.allMastersSeedBootstrap;
  return topology.servingMode == StatefulTopologyServingMode::allMastersSeedBootstrap &&
      v.sourceClusterUUID != 0 && v.targetClusterUUID != 0 && v.sourceClusterUUID != v.targetClusterUUID &&
      v.targetDeploymentID != 0 && v.qualificationRunUUID != 0 && v.successorOperationUUID != 0 &&
      v.shardGroup == topology.shardGroup && v.expectedSeedGeneration != 0;
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
  if (topology.servingMode == StatefulTopologyServingMode::applicationDataAuthority)
    return prodigyStatefulDataAuthorityValid(topology.dataAuthority) &&
        (topology.dataAuthority.mode == StatefulDataAuthorityMode::writeOwner ||
         (topology.dataAuthority.mode == StatefulDataAuthorityMode::retainedSource &&
          topology.dataAuthority.writeOwnerClusterUUID == topology.dataAuthority.localClusterUUID) ||
         topology.dataAuthority.mode == StatefulDataAuthorityMode::snapshotPreparing);
  return topology.servingMode == StatefulTopologyServingMode::serve ||
      prodigyStatefulTopologyIsAllMastersSeedBootstrap(topology);
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

class ProdigyStatefulServingAuthorityMember {
public:
  uint128_t containerUUID = 0;
  uint128_t machineUUID = 0;
  uint32_t shardGroup = 0;
  bool isSource = false;
  bool advertiseClient = false;
  String planSHA256;

  bool operator==(const ProdigyStatefulServingAuthorityMember& other) const
  {
    return containerUUID == other.containerUUID && machineUUID == other.machineUUID && shardGroup == other.shardGroup &&
           isSource == other.isSource && advertiseClient == other.advertiseClient && planSHA256.equals(other.planSHA256);
  }
  bool operator!=(const ProdigyStatefulServingAuthorityMember& other) const { return !(*this == other); }
};

template <typename S>
static void serialize(S&& serializer, ProdigyStatefulServingAuthorityMember& member)
{
  serializer.value16b(member.containerUUID); serializer.value16b(member.machineUUID);
  serializer.value4b(member.shardGroup); serializer.value1b(member.isSource);
  serializer.value1b(member.advertiseClient); serializer.text1b(member.planSHA256, 64);
}

static inline bool prodigyStatefulServingApplicationConfigEqual(const ApplicationConfig& a, const ApplicationConfig& b)
{
  String as = {}, bs = {}; ApplicationConfig ac = a, bc = b;
  Vector<int> acaps = {}, bcaps = {};
  for (int value : ac.capabilities) acaps.push_back(value);
  for (int value : bc.capabilities) bcaps.push_back(value);
  std::sort(acaps.begin(), acaps.end()); std::sort(bcaps.begin(), bcaps.end());
  ac.capabilities.clear(); bc.capabilities.clear();
  BitseryEngine::serialize(as, ac); BitseryEngine::serialize(bs, bc);
  return acaps == bcaps && as.equals(bs);
}

class ProdigyStatefulServingAuthority {
public:
  uint64_t deploymentID = 0;
  uint16_t applicationID = 0;
  uint64_t operationID = 0;
  uint64_t revision = 0;
  StatefulWorkerTopologyUpgradePhase phase = StatefulWorkerTopologyUpgradePhase::none;
  uint32_t sourceEpoch = 0;
  uint32_t targetEpoch = 0;
  ApplicationConfig targetConfig;
  bool allMasters = false;
  // Canonical order: shardGroup, isSource, containerUUID.
  Vector<ProdigyStatefulServingAuthorityMember> members;
  StatefulDataAuthority dataAuthority;
  String pairIntentSHA256;
  String sourceFenceReceiptSHA256;
  String admittedPlanSHA256;
  String requestPlanSHA256;
  String ownershipReadyReceiptSHA256;
  bool sourceRetired = false;
  ProdigyAllMastersSeedBootstrap allMastersSeedBootstrap;
  ProdigyQualificationStatefulCancellation qualificationCancellation;
  ProdigyInitialAllMastersSeedBootstrapScope initialAllMastersSeedBootstrap;

  bool operator==(const ProdigyStatefulServingAuthority& other) const
  {
    if (deploymentID != other.deploymentID || applicationID != other.applicationID || operationID != other.operationID ||
        revision != other.revision || phase != other.phase || sourceEpoch != other.sourceEpoch || targetEpoch != other.targetEpoch ||
        allMasters != other.allMasters || !prodigyStatefulServingApplicationConfigEqual(targetConfig, other.targetConfig) ||
        (phase == StatefulWorkerTopologyUpgradePhase::applicationDataAuthority &&
         (!prodigyStatefulDataAuthorityEqual(dataAuthority, other.dataAuthority) ||
          pairIntentSHA256 != other.pairIntentSHA256 || sourceFenceReceiptSHA256 != other.sourceFenceReceiptSHA256 ||
          admittedPlanSHA256 != other.admittedPlanSHA256 || requestPlanSHA256 != other.requestPlanSHA256 ||
          ownershipReadyReceiptSHA256 != other.ownershipReadyReceiptSHA256 ||
          sourceRetired != other.sourceRetired)) ||
        (phase == StatefulWorkerTopologyUpgradePhase::allMastersSeedBootstrap &&
         (!(allMastersSeedBootstrap == other.allMastersSeedBootstrap) ||
          ![&]() { String a, b; auto x = qualificationCancellation, y = other.qualificationCancellation;
            BitseryEngine::serialize(a, x); BitseryEngine::serialize(b, y); return a == b; }())) ||
        (phase == StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap &&
         ![&]() { String a, b; auto x = initialAllMastersSeedBootstrap, y = other.initialAllMastersSeedBootstrap;
           return BitseryEngine::serialize(a, x) && BitseryEngine::serialize(b, y) && a == b; }()) ||
        members.size() != other.members.size()) return false;
    for (uint32_t i = 0; i < members.size(); ++i) if (members[i] != other.members[i]) return false;
    return true;
  }
  bool operator!=(const ProdigyStatefulServingAuthority& other) const { return !(*this == other); }
};

template <typename S>
static void serialize(S&& serializer, ProdigyStatefulServingAuthority& authority)
{
  serializer.value8b(authority.deploymentID); serializer.value2b(authority.applicationID);
  serializer.value8b(authority.operationID); serializer.value8b(authority.revision); serializer.value1b(authority.phase);
  serializer.value4b(authority.sourceEpoch); serializer.value4b(authority.targetEpoch); serializer.object(authority.targetConfig);
  serializer.value1b(authority.allMasters); serializer.container(authority.members, 4096);
  if (authority.phase == StatefulWorkerTopologyUpgradePhase::applicationDataAuthority) {
    serializer.object(authority.dataAuthority);
    serializer.text1b(authority.pairIntentSHA256, 64);
    serializer.text1b(authority.sourceFenceReceiptSHA256, 64);
    serializer.text1b(authority.admittedPlanSHA256, 64);
    serializer.text1b(authority.requestPlanSHA256, 64);
    serializer.text1b(authority.ownershipReadyReceiptSHA256, 64);
    serializer.value1b(authority.sourceRetired);
  }
  if (authority.phase == StatefulWorkerTopologyUpgradePhase::allMastersSeedBootstrap) {
    serializer.object(authority.allMastersSeedBootstrap);
    serializer.object(authority.qualificationCancellation);
  }
  if (authority.phase == StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap)
    serializer.object(authority.initialAllMastersSeedBootstrap);
}

// Legacy topology decisions cover the deployment's remaining shard groups;
// application data decisions have one explicit shard scope. Both use the same
// serving authority package and may coexist with disjoint member UUIDs.
static inline bool prodigyStatefulServingAuthoritySameScope(
    const ProdigyStatefulServingAuthority& a, const ProdigyStatefulServingAuthority& b)
{
  if (a.deploymentID != b.deploymentID) return false;
  const bool aa = a.phase == StatefulWorkerTopologyUpgradePhase::applicationDataAuthority;
  const bool ba = b.phase == StatefulWorkerTopologyUpgradePhase::applicationDataAuthority;
  const bool ab = a.phase == StatefulWorkerTopologyUpgradePhase::allMastersSeedBootstrap || a.phase == StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap;
  const bool bb = b.phase == StatefulWorkerTopologyUpgradePhase::allMastersSeedBootstrap || b.phase == StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap;
  if (aa != ba || ab != bb) return false;
  if (aa)
    return a.dataAuthority.shardGroup == b.dataAuthority.shardGroup;
  if (ab)
    return (a.phase == StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap ? a.initialAllMastersSeedBootstrap.bootstrap.shardGroup : a.allMastersSeedBootstrap.shardGroup) ==
           (b.phase == StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap ? b.initialAllMastersSeedBootstrap.bootstrap.shardGroup : b.allMastersSeedBootstrap.shardGroup);
  return true;
}

static inline bool prodigyStatefulServingAuthorityMatchesShard(
    const ProdigyStatefulServingAuthority& authority, uint64_t deploymentID, uint32_t shardGroup)
{
  return authority.deploymentID == deploymentID &&
      (authority.phase == StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap
       ? authority.initialAllMastersSeedBootstrap.bootstrap.shardGroup == shardGroup
       : authority.phase == StatefulWorkerTopologyUpgradePhase::allMastersSeedBootstrap
       ? authority.allMastersSeedBootstrap.shardGroup == shardGroup
       : authority.phase == StatefulWorkerTopologyUpgradePhase::applicationDataAuthority
       ? authority.dataAuthority.shardGroup == shardGroup
       : std::any_of(authority.members.begin(), authority.members.end(), [&](const auto& member) {
           return member.shardGroup == shardGroup;
         }));
}

class StatefulDataAuthorityMemberReceipt {
public:
  uint128_t containerUUID = 0;
  uint128_t machineUUID = 0;
  StatefulDataAuthorityReceipt receipt;
};

template <typename S>
static void serialize(S&& serializer, StatefulDataAuthorityMemberReceipt& value)
{
  serializer.value16b(value.containerUUID); serializer.value16b(value.machineUUID);
  serializer.object(value.receipt);
}

// Read-only application declaration on the existing stateful-authority topic.
// Version three is distinct from authority receipts' leading v1/v2.
// The authenticated container socket supplies container/machine identity; the
// application echoes only this challenge and the selected deployment scope.
class StatefulDataAuthorityPreparation {
public:
  static constexpr uint32_t currentVersion = 3;
  uint32_t version = currentVersion;
  bool response = false;
  uint128_t requestUUID = 0;
  uint128_t memberRequestUUID = 0; // Brain-minted anew for each process incarnation.
  uint128_t clusterUUID = 0;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  uint32_t shardGroup = 0;
  uint32_t nShardGroups = 0;
  uint32_t contractVersion = StatefulDataAuthority::version;
  String contractSHA256;
  String shardManifestSHA256;
  uint128_t datasetUUID = 0; // Unknown only before the first admitted authority.
  bool hasAuthority = false;
  StatefulDataAuthority currentAuthority;
  StatefulDataAuthorityMode mode = StatefulDataAuthorityMode::retainedSource;
  uint128_t writeOwnerClusterUUID = 0;
  bool hasDurableWatermark = false;
  uint64_t durableWatermark = 0;
  String durableWatermarkSHA256;
  bool supported = false;
  String failure;
};

template <typename S>
static void serialize(S&& serializer, StatefulDataAuthorityPreparation& value)
{
  serializer.value4b(value.version); serializer.value1b(value.response);
  serializer.value16b(value.requestUUID); serializer.value16b(value.memberRequestUUID); serializer.value16b(value.clusterUUID);
  serializer.value2b(value.applicationID); serializer.value8b(value.deploymentID);
  serializer.value4b(value.shardGroup); serializer.value4b(value.nShardGroups);
  serializer.value4b(value.contractVersion); serializer.text1b(value.contractSHA256, 64);
  serializer.text1b(value.shardManifestSHA256, 64); serializer.value16b(value.datasetUUID);
  serializer.value1b(value.hasAuthority); serializer.object(value.currentAuthority);
  serializer.value1b(value.mode); serializer.value16b(value.writeOwnerClusterUUID);
  serializer.value1b(value.hasDurableWatermark); serializer.value8b(value.durableWatermark);
  serializer.text1b(value.durableWatermarkSHA256, 64); serializer.value1b(value.supported);
  serializer.text1b(value.failure, 1024);
}

static inline bool prodigyStatefulDataAuthorityPreparationContextEqual(
    const StatefulDataAuthorityPreparation& a, const StatefulDataAuthorityPreparation& b)
{
  return a.version == b.version && a.requestUUID == b.requestUUID && a.memberRequestUUID == b.memberRequestUUID && a.clusterUUID == b.clusterUUID &&
      a.applicationID == b.applicationID && a.deploymentID == b.deploymentID &&
      a.shardGroup == b.shardGroup && a.nShardGroups == b.nShardGroups;
}

static inline bool prodigyStatefulDataAuthorityPreparationValid(const StatefulDataAuthorityPreparation& value)
{
  StatefulDataAuthority empty;
  if (value.version != StatefulDataAuthorityPreparation::currentVersion ||
      value.requestUUID == 0 || value.clusterUUID == 0 ||
      (value.applicationID != 3 && value.applicationID != 4) ||
      uint16_t(value.deploymentID >> 48) != value.applicationID || value.nShardGroups == 0 ||
      value.shardGroup >= value.nShardGroups || value.shardGroup > UINT16_MAX ||
      value.contractVersion != StatefulDataAuthority::version || value.failure.size() > 1024) return false;
  if (value.response && value.memberRequestUUID == 0) return false;
  if (!value.response || !value.supported)
    return !value.hasAuthority && prodigyStatefulDataAuthorityEqual(value.currentAuthority, empty) &&
        value.contractSHA256.empty() && value.shardManifestSHA256.empty() && value.datasetUUID == 0 &&
        value.mode == StatefulDataAuthorityMode::retainedSource && value.writeOwnerClusterUUID == 0 &&
        !value.hasDurableWatermark && value.durableWatermark == 0 && value.durableWatermarkSHA256.empty() &&
        (value.response ? !value.failure.empty() : (!value.supported && value.failure.empty()));
  if (!value.failure.empty() || !prodigyIsSHA256HexDigest(value.contractSHA256) ||
      !prodigyIsSHA256HexDigest(value.shardManifestSHA256) || value.writeOwnerClusterUUID == 0 ||
      (value.mode != StatefulDataAuthorityMode::writeOwner && value.mode != StatefulDataAuthorityMode::retainedSource &&
       value.mode != StatefulDataAuthorityMode::catchupOnly && value.mode != StatefulDataAuthorityMode::fenced &&
       value.mode != StatefulDataAuthorityMode::snapshotPreparing) ||
      (value.hasDurableWatermark ? !prodigyIsSHA256HexDigest(value.durableWatermarkSHA256) :
          (value.durableWatermark != 0 || !value.durableWatermarkSHA256.empty()))) return false;
  if (!value.hasAuthority)
    return value.datasetUUID == 0 && prodigyStatefulDataAuthorityEqual(value.currentAuthority, empty) &&
        value.mode == StatefulDataAuthorityMode::writeOwner && value.writeOwnerClusterUUID == value.clusterUUID;
  return prodigyStatefulDataAuthorityValid(value.currentAuthority) &&
      value.currentAuthority.contractVersion == value.contractVersion &&
      value.currentAuthority.localClusterUUID == value.clusterUUID &&
      value.currentAuthority.shardGroup == value.shardGroup &&
      value.currentAuthority.nShardGroups == value.nShardGroups &&
      value.currentAuthority.datasetUUID == value.datasetUUID &&
      value.currentAuthority.contractSHA256 == value.contractSHA256 &&
      value.currentAuthority.shardManifestSHA256 == value.shardManifestSHA256 &&
      value.currentAuthority.mode == value.mode && value.currentAuthority.writeOwnerClusterUUID == value.writeOwnerClusterUUID;
}

class StatefulDataAuthorityPreparationMember {
public:
  ProdigyStatefulServingAuthorityMember member;
  StatefulDataAuthorityPreparation preparation;
};

template <typename S>
static void serialize(S&& serializer, StatefulDataAuthorityPreparationMember& value)
{ serializer.object(value.member); serializer.object(value.preparation); }

// A preparation is evidence, not coordinator-owned data.  Each member has a
// distinct Brain challenge, but every application-owned fact must agree
// exactly before a later operation may bind the observed cohort.  Keeping this
// check next to the wire contract makes both Brain and a future Mothership
// preparer fail closed on a missing, reordered, replayed, or divergent proof.
static inline bool prodigyStatefulDataAuthorityPreparationMembersAgree(
    const StatefulDataAuthorityPreparation& request,
    const Vector<ProdigyStatefulServingAuthorityMember>& cohort,
    const Vector<StatefulDataAuthorityPreparationMember>& observations)
{
  if (!prodigyStatefulDataAuthorityPreparationValid(request) || request.response ||
      request.memberRequestUUID != 0 || cohort.size() != 3 || observations.size() != 3) return false;
  const StatefulDataAuthorityPreparation *first = nullptr;
  uint128_t previousContainerUUID = 0;
  for (uint32_t index = 0; index < observations.size(); ++index) {
    const auto& observed = observations[index];
    const auto& proof = observed.preparation;
    if (observed.member != cohort[index] || observed.member.containerUUID <= previousContainerUUID ||
        !proof.response || !proof.supported || !proof.hasDurableWatermark ||
        !prodigyStatefulDataAuthorityPreparationValid(proof) ||
        proof.requestUUID != request.requestUUID || proof.clusterUUID != request.clusterUUID ||
        proof.applicationID != request.applicationID || proof.deploymentID != request.deploymentID ||
        proof.shardGroup != request.shardGroup || proof.nShardGroups != request.nShardGroups)
      return false;
    previousContainerUUID = observed.member.containerUUID;
    if (!first) { first = &proof; continue; }
    if (proof.contractVersion != first->contractVersion || proof.contractSHA256 != first->contractSHA256 ||
        proof.shardManifestSHA256 != first->shardManifestSHA256 || proof.datasetUUID != first->datasetUUID ||
        proof.hasAuthority != first->hasAuthority || !prodigyStatefulDataAuthorityEqual(proof.currentAuthority, first->currentAuthority) ||
        proof.mode != first->mode || proof.writeOwnerClusterUUID != first->writeOwnerClusterUUID ||
        proof.hasDurableWatermark != first->hasDurableWatermark || proof.durableWatermark != first->durableWatermark ||
        proof.durableWatermarkSHA256 != first->durableWatermarkSHA256)
      return false;
  }
  return first != nullptr;
}

// One request/response payload on one authenticated Mothership topic. Direction
// supplies request versus receipt semantics; the runtime never accepts an app
// proof supplied by the coordinator as an observation of a local process.
class StatefulDataAuthorityOperation {
public:
  uint32_t version = 1;
  bool query = false;
  bool launchTarget = false;
  uint64_t deploymentID = 0;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  String pairIntentSHA256;
  StatefulDataAuthority authority;
  Vector<ProdigyStatefulServingAuthorityMember> cohort;
  String sourceFenceReceiptSHA256;
  String deploymentPlan;
  bool supported = true;
  bool accepted = false;
  bool ready = false;
  String failure;
  Vector<StatefulDataAuthorityMemberReceipt> receipts;
  bool preparationQuery = false;
  StatefulDataAuthorityPreparation preparation;
  Vector<StatefulDataAuthorityPreparationMember> preparationMembers;
};

class ProdigyInitialAllMastersSeedBootstrapOperation {
public:
  static constexpr uint32_t version = 0x51425302;
  uint32_t protocolVersion = version;
  bool query = false;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  ProdigyInitialAllMastersSeedBootstrapScope scope;
  String deploymentPlan;
  bool accepted = false;
  bool ready = false;
  String failure;
};
template <typename S>
static void serialize(S&& s, ProdigyInitialAllMastersSeedBootstrapOperation& v) {
  s.value4b(v.protocolVersion); s.value1b(v.query); s.value8b(v.expectedAuthorityGeneration);
  s.value16b(v.expectedMasterUUID); s.value8b(v.expectedMasterBootNs); s.object(v.scope);
  s.text1b(v.deploymentPlan, 1024 * 1024); s.value1b(v.accepted); s.value1b(v.ready); s.text1b(v.failure, 4096);
}

class ProdigyAllMastersSeedBootstrapOperation {
public:
  static constexpr uint32_t version = 0x51425301;
  uint32_t protocolVersion = version;
  bool query = false;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  ProdigyQualificationStatefulCancellation qualificationCancellation;
  ProdigyAllMastersSeedBootstrap bootstrap;
  String deploymentPlan;
  bool accepted = false;
  bool ready = false;
  String failure;
};

template <typename S>
static void serialize(S&& s, ProdigyAllMastersSeedBootstrapOperation& v) {
  s.value4b(v.protocolVersion); s.value1b(v.query); s.value8b(v.expectedAuthorityGeneration);
  s.value16b(v.expectedMasterUUID); s.value8b(v.expectedMasterBootNs);
  s.object(v.qualificationCancellation); s.object(v.bootstrap); s.text1b(v.deploymentPlan, 1024 * 1024);
  s.value1b(v.accepted); s.value1b(v.ready); s.text1b(v.failure, 4096);
}

template <typename S>
static void serialize(S&& serializer, StatefulDataAuthorityOperation& value)
{
  serializer.value4b(value.version); serializer.value1b(value.query); serializer.value1b(value.launchTarget);
  serializer.value8b(value.deploymentID); serializer.value8b(value.expectedAuthorityGeneration);
  serializer.value16b(value.expectedMasterUUID); serializer.value8b(value.expectedMasterBootNs);
  serializer.text1b(value.pairIntentSHA256, 64); serializer.object(value.authority);
  serializer.container(value.cohort, 4096); serializer.text1b(value.sourceFenceReceiptSHA256, 64);
  serializer.text1b(value.deploymentPlan, 1024 * 1024);
  serializer.value1b(value.supported); serializer.value1b(value.accepted); serializer.value1b(value.ready);
  serializer.text1b(value.failure, 4096); serializer.container(value.receipts, 4096);
  if (value.version >= 2) {
    serializer.value1b(value.preparationQuery); serializer.object(value.preparation);
    serializer.container(value.preparationMembers, 3);
  }
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

constexpr static uint32_t containerLogsDefaultMaximumBytes = 64U * 1024U;
constexpr static uint32_t containerLogsMaximumBytes = 1024U * 1024U;
constexpr static uint32_t containerLogsMaximumEntries = 64;
constexpr static uint32_t containerLogsMaximumWireBytes = containerLogsMaximumBytes + 16U * 1024U;

class ContainerLogEntry {
public:

  uint128_t machineUUID = 0;
  uint128_t containerUUID = 0;
  int64_t capturedAtMs = 0;
  bool running = false;
  bool truncated = false;
  String standardOutput;
  String standardError;
};

template <typename S>
static void serialize(S&& serializer, ContainerLogEntry& entry)
{
  serializer.value16b(entry.machineUUID);
  serializer.value16b(entry.containerUUID);
  serializer.value8b(entry.capturedAtMs);
  serializer.value1b(entry.running);
  serializer.value1b(entry.truncated);
  serializer.text1b(entry.standardOutput, containerLogsMaximumBytes);
  serializer.text1b(entry.standardError, containerLogsMaximumBytes);
}

class ContainerLogsOperation {
public:

  uint64_t requestID = 0;
  uint16_t applicationID = 0;
  uint128_t containerUUID = 0;
  uint32_t maximumBytes = containerLogsDefaultMaximumBytes;
  bool includeRunning = true;
  bool includeFailed = true;
  bool success = false;
  bool truncated = false;
  String failure;
  Vector<ContainerLogEntry> entries;
};

template <typename S>
static void serialize(S&& serializer, ContainerLogsOperation& operation)
{
  serializer.value8b(operation.requestID);
  serializer.value2b(operation.applicationID);
  serializer.value16b(operation.containerUUID);
  serializer.value4b(operation.maximumBytes);
  serializer.value1b(operation.includeRunning);
  serializer.value1b(operation.includeFailed);
  serializer.value1b(operation.success);
  serializer.value1b(operation.truncated);
  serializer.text1b(operation.failure, 4096);
  serializer.container(operation.entries, containerLogsMaximumEntries, [](S& serializer, ContainerLogEntry& entry) {
    serializer.object(entry);
  });
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
      string.snprintf_tab_add<"containerRuntime: cores={itoa} memMB={itoa} storMB={itoa} uuid={itoa}\n"_ctv>(nTabs, nLogicalCores, memoryMB, storageMB, uuid);
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

enum class DeploymentIdentityStoreKind : uint8_t {
  unknown = 0, kv = 1, graph = 2, truth = 3
};
enum class ProdigyStatefulStoreSourceCutAction : uint8_t { prepare = 1, query = 2, release = 3 };
enum class ProdigyStatefulStoreSourceCutScope : uint8_t { fullShardGroup = 1 };

class ProdigyStatefulStoreSourceCut {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyStatefulStoreSourceCutAction action = ProdigyStatefulStoreSourceCutAction::prepare;
  bool response = false;
  uint128_t operationUUID = 0, requestUUID = 0, memberRequestUUID = 0;
  uint128_t sourceClusterUUID = 0;
  uint64_t sourceDeploymentID = 0;
  uint128_t sourceContainerUUID = 0;
  uint16_t applicationID = 0;
  DeploymentIdentityStoreKind storeKind = DeploymentIdentityStoreKind::unknown;
  uint32_t shardGroup = UINT32_MAX, nShardGroups = 0;
  ProdigyStatefulStoreSourceCutScope scope = ProdigyStatefulStoreSourceCutScope::fullShardGroup;
  int64_t retainUntilMilliseconds = 0;
  uint128_t cutUUID = 0;
  uint64_t cutGeneration = 0;
  String contentSHA256, headsSHA256;
  bool ready = false, released = false;
  String failure;
  bool operator==(const ProdigyStatefulStoreSourceCut&) const = default;
};
template <typename S> static void serialize(S&& s, ProdigyStatefulStoreSourceCut& v) {
  s.value4b(v.protocolVersion); s.value1b(v.action); s.value1b(v.response);
  s.value16b(v.operationUUID); s.value16b(v.requestUUID); s.value16b(v.memberRequestUUID);
  s.value16b(v.sourceClusterUUID); s.value8b(v.sourceDeploymentID); s.value16b(v.sourceContainerUUID);
  s.value2b(v.applicationID); s.value1b(v.storeKind); s.value4b(v.shardGroup); s.value4b(v.nShardGroups);
  s.value1b(v.scope); s.value8b(v.retainUntilMilliseconds); s.value16b(v.cutUUID); s.value8b(v.cutGeneration);
  s.text1b(v.contentSHA256, 64); s.text1b(v.headsSHA256, 64); s.value1b(v.ready); s.value1b(v.released);
  s.text1b(v.failure, 1024);
}
static inline bool prodigyStatefulStoreSourceCutValid(const ProdigyStatefulStoreSourceCut& v) {
  const bool kind = ((v.applicationID == 2 || v.applicationID == 5) && v.storeKind == DeploymentIdentityStoreKind::graph) ||
      ((v.applicationID == 3 || v.applicationID == 4) && v.storeKind == DeploymentIdentityStoreKind::kv);
  if (v.protocolVersion != v.version || !kind || v.operationUUID == 0 || v.requestUUID == 0 ||
      v.sourceClusterUUID == 0 || v.sourceContainerUUID == 0 || v.sourceDeploymentID == 0 ||
      uint16_t(v.sourceDeploymentID >> 48) != v.applicationID || v.nShardGroups == 0 || v.shardGroup >= v.nShardGroups ||
      v.scope != ProdigyStatefulStoreSourceCutScope::fullShardGroup || v.retainUntilMilliseconds <= 0 ||
      v.failure.size() > 1024 || (v.cutUUID == 0) != (v.cutGeneration == 0)) return false;
  if (v.action != ProdigyStatefulStoreSourceCutAction::prepare && v.action != ProdigyStatefulStoreSourceCutAction::query &&
      v.action != ProdigyStatefulStoreSourceCutAction::release) return false;
  if (!v.response) return !v.ready && !v.released && v.failure.empty() && v.contentSHA256.empty() && v.headsSHA256.empty() &&
      (v.action == ProdigyStatefulStoreSourceCutAction::prepare ? v.cutUUID == 0 : v.cutUUID != 0);
  if (v.memberRequestUUID == 0 && (v.failure.empty() || v.action != ProdigyStatefulStoreSourceCutAction::prepare)) return false;
  if (!v.failure.empty()) return !v.ready && !v.released && v.contentSHA256.empty() && v.headsSHA256.empty() &&
      (v.action == ProdigyStatefulStoreSourceCutAction::prepare ? v.cutUUID == 0 : v.cutUUID != 0);
  if (v.action == ProdigyStatefulStoreSourceCutAction::release)
    return v.cutUUID != 0 && !v.ready && v.contentSHA256.empty() && v.headsSHA256.empty();
  if (v.released || (v.action == ProdigyStatefulStoreSourceCutAction::query && v.cutUUID == 0)) return false;
  if (v.ready) return v.cutUUID != 0 && prodigyIsSHA256HexDigest(v.contentSHA256) && prodigyIsSHA256HexDigest(v.headsSHA256);
  return v.contentSHA256.empty() && v.headsSHA256.empty() &&
      (v.action != ProdigyStatefulStoreSourceCutAction::prepare || v.cutUUID == 0);
}
static inline bool prodigyStatefulStoreSourceCutContextEqual(const ProdigyStatefulStoreSourceCut& a, const ProdigyStatefulStoreSourceCut& b) {
  return a.protocolVersion == b.protocolVersion && a.action == b.action && a.operationUUID == b.operationUUID &&
      a.requestUUID == b.requestUUID && a.memberRequestUUID == b.memberRequestUUID && a.sourceClusterUUID == b.sourceClusterUUID &&
      a.sourceDeploymentID == b.sourceDeploymentID && a.sourceContainerUUID == b.sourceContainerUUID && a.applicationID == b.applicationID &&
      a.storeKind == b.storeKind && a.shardGroup == b.shardGroup && a.nShardGroups == b.nShardGroups && a.scope == b.scope &&
      a.retainUntilMilliseconds == b.retainUntilMilliseconds;
}
static inline bool prodigyStatefulStoreSourceCutResponseMatches(const ProdigyStatefulStoreSourceCut& request, const ProdigyStatefulStoreSourceCut& response) {
  return !request.response && response.response && prodigyStatefulStoreSourceCutValid(request) &&
      prodigyStatefulStoreSourceCutValid(response) && prodigyStatefulStoreSourceCutContextEqual(request, response) &&
      (request.action == ProdigyStatefulStoreSourceCutAction::prepare ||
       (request.cutUUID == response.cutUUID && request.cutGeneration == response.cutGeneration));
}

enum class ProdigyStatefulStoreReceiptState : uint8_t { active = 1, withdrawn = 2 };

// The persisted all-masters placement is projected as this bounded desired
// authority.  It is neither a receipt nor an alternative placement record:
// Mothership copies it only from its durable registry row and every hop
// binds it to the target process before delivery.
class ProdigyStatefulStoreSeedAuthority {
public:
  static constexpr uint32_t version = 3;
  static constexpr uint32_t sourceCutVersion = 4;
  static constexpr uint32_t qualificationSeedFaultVersion = 5;
  uint32_t protocolVersion = version;
  uint64_t authorityGeneration = 0;
  uint128_t operationUUID = 0;
  uint16_t applicationID = 0;
  DeploymentIdentityStoreKind storeKind = DeploymentIdentityStoreKind::unknown;
  uint32_t shardGroup = UINT32_MAX;
  uint32_t nShardGroups = 0;
  uint128_t targetClusterUUID = 0;
  uint64_t targetDeploymentID = 0;
  uint128_t targetContainerUUID = 0;
  uint128_t sourceClusterUUID = 0;
  uint64_t sourceDeploymentID = 0;
  uint128_t sourceContainerUUID = 0;
  uint64_t seedGeneration = 0;
  String fixtureSHA256;
  String expectedCatchupWatermarkSHA256;
  // v3 appends the exact native EWR source boundary. These fields are not a
  // caller fixture and must be echoed by the target's native receipt.
  String sourceContentWatermarkSHA256;
  String sourceCatchupWatermarkSHA256;
  // v4 binds the immutable, retained native source cut and baseline provenance.
  uint128_t sourceBaselineOperationUUID = 0;
  uint128_t sourceRequestUUID = 0;
  uint128_t sourceMemberRequestUUID = 0;
  uint128_t seedRouteUUID = 0;
  uint128_t cutUUID = 0;
  uint64_t cutGeneration = 0;
  ProdigyStatefulStoreSourceCutScope sourceCutScope = ProdigyStatefulStoreSourceCutScope::fullShardGroup;
  uint64_t retainUntilMilliseconds = 0;
  // A qualification seed must be armed on the exact target before its
  // automatically driven protected session is permitted to activate.
  uint128_t qualificationRunUUID = 0, qualificationChallengeUUID = 0;
  uint64_t qualificationExecutionGeneration = 0;
  int64_t qualificationDeadlineAtMilliseconds = 0;
};
static inline bool prodigyStatefulStoreSeedAuthorityHasSourceCut(uint32_t version) {
  return version == ProdigyStatefulStoreSeedAuthority::sourceCutVersion ||
      version == ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion;
}
template <typename S> static void serialize(S&& s, ProdigyStatefulStoreSeedAuthority& value) {
  s.value4b(value.protocolVersion); s.value8b(value.authorityGeneration); s.value16b(value.operationUUID);
  s.value2b(value.applicationID); s.value1b(value.storeKind); s.value4b(value.shardGroup); s.value4b(value.nShardGroups);
  s.value16b(value.targetClusterUUID); s.value8b(value.targetDeploymentID); s.value16b(value.targetContainerUUID);
  s.value16b(value.sourceClusterUUID); s.value8b(value.sourceDeploymentID); s.value16b(value.sourceContainerUUID);
  s.value8b(value.seedGeneration); s.text1b(value.fixtureSHA256, 64); s.text1b(value.expectedCatchupWatermarkSHA256, 64);
  if (value.protocolVersion >= 3) { s.text1b(value.sourceContentWatermarkSHA256, 64); s.text1b(value.sourceCatchupWatermarkSHA256, 64); }
  if (value.protocolVersion >= 4) {
    s.value16b(value.sourceBaselineOperationUUID); s.value16b(value.sourceRequestUUID);
    s.value16b(value.sourceMemberRequestUUID); s.value16b(value.seedRouteUUID); s.value16b(value.cutUUID); s.value8b(value.cutGeneration);
    s.value1b(value.sourceCutScope); s.value8b(value.retainUntilMilliseconds);
  }
  if (value.protocolVersion >= ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion) {
    s.value16b(value.qualificationRunUUID); s.value16b(value.qualificationChallengeUUID);
    s.value8b(value.qualificationExecutionGeneration); s.value8b(value.qualificationDeadlineAtMilliseconds);
  }
}
static inline bool prodigyStatefulStoreSeedAuthorityValid(const ProdigyStatefulStoreSeedAuthority& value) {
  return (value.protocolVersion == ProdigyStatefulStoreSeedAuthority::version || prodigyStatefulStoreSeedAuthorityHasSourceCut(value.protocolVersion)) && value.authorityGeneration != 0 &&
      value.operationUUID != 0 && value.applicationID != 0 && value.storeKind != DeploymentIdentityStoreKind::unknown &&
      value.shardGroup < value.nShardGroups && value.targetClusterUUID != 0 && value.targetDeploymentID != 0 &&
      value.targetContainerUUID != 0 && value.sourceClusterUUID != 0 &&
      value.sourceClusterUUID != value.targetClusterUUID && value.sourceDeploymentID != 0 &&
      value.sourceContainerUUID != 0 && value.seedGeneration != 0 && prodigyIsSHA256HexDigest(value.fixtureSHA256) &&
      (prodigyStatefulStoreSeedAuthorityHasSourceCut(value.protocolVersion) ? value.expectedCatchupWatermarkSHA256.empty() :
       prodigyIsSHA256HexDigest(value.expectedCatchupWatermarkSHA256)) &&
      prodigyIsSHA256HexDigest(value.sourceContentWatermarkSHA256) && prodigyIsSHA256HexDigest(value.sourceCatchupWatermarkSHA256) &&
      (!prodigyStatefulStoreSeedAuthorityHasSourceCut(value.protocolVersion) ||
       (value.sourceBaselineOperationUUID != 0 && value.sourceRequestUUID != 0 && value.sourceMemberRequestUUID != 0 &&
        value.seedRouteUUID != 0 && value.cutUUID != 0 && value.cutGeneration != 0 && value.sourceCutScope == ProdigyStatefulStoreSourceCutScope::fullShardGroup &&
        value.retainUntilMilliseconds != 0)) &&
      (value.protocolVersion == ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion ?
       (value.storeKind == DeploymentIdentityStoreKind::kv && value.qualificationRunUUID != 0 && value.qualificationChallengeUUID != 0 && value.qualificationExecutionGeneration != 0 &&
        value.qualificationDeadlineAtMilliseconds > 0 && uint64_t(value.qualificationDeadlineAtMilliseconds) <= value.retainUntilMilliseconds) :
       (value.qualificationRunUUID == 0 && value.qualificationChallengeUUID == 0 && value.qualificationExecutionGeneration == 0 &&
        value.qualificationDeadlineAtMilliseconds == 0));
}

// Native store observation relayed through the existing container -> Neuron
// -> Brain receipt channel.  It is deliberately an observation, not launch
// authority: every field is emitted by the store after its own apply/session
// boundary has committed it.  Missing fields make the receipt invalid.
class ProdigyStatefulStoreReceipt {
public:
  static constexpr uint32_t version = 3;
  static constexpr uint32_t sourceCutVersion = 4;
  uint32_t protocolVersion = version;
  ProdigyStatefulStoreReceiptState state = ProdigyStatefulStoreReceiptState::active;
  uint128_t localContainerUUID = 0;
  uint128_t localClusterUUID = 0;
  uint64_t deploymentID = 0;
  DeploymentIdentityStoreKind storeKind = DeploymentIdentityStoreKind::unknown;
  uint32_t shardGroup = UINT32_MAX;
  uint32_t nShardGroups = 0;
  bool writable = false;
  uint128_t siblingSessionUUID = 0;
  uint64_t siblingSessionGeneration = 0;
  bool siblingSessionHealthy = false;
  uint128_t seededFromClusterUUID = 0;
  uint128_t seededFromContainerUUID = 0;
  uint64_t seedGeneration = 0;
  String seedFixtureSHA256;
  String appliedWatermarkSHA256;
  // v3 is the native source boundary accepted with a remote seed authority.
  // It must not be inferred from the seed fixture or identity.
  String sourceContentWatermarkSHA256;
  String sourceCatchupWatermarkSHA256;
  // The native target hashes the committed snapshot before queued replay. It
  // then proves its committed heads dominate the transferred cut vector after
  // replay; no hash equality establishes head dominance.
  uint128_t operationUUID = 0;
  uint128_t sourceBaselineOperationUUID = 0;
  uint128_t sourceRequestUUID = 0;
  uint128_t sourceMemberRequestUUID = 0;
  uint128_t seedRouteUUID = 0;
  uint64_t sourceDeploymentID = 0;
  uint128_t cutUUID = 0;
  uint64_t cutGeneration = 0;
  ProdigyStatefulStoreSourceCutScope sourceCutScope = ProdigyStatefulStoreSourceCutScope::fullShardGroup;
  uint64_t retainUntilMilliseconds = 0;
  String materializedContentSHA256;
  String materializedHeadsSHA256;
  bool cutMaterialized = false;
  bool committedHeadsDominateCut = false;
};

template <typename S>
static void serialize(S&& serializer, ProdigyStatefulStoreReceipt& value)
{
  serializer.value4b(value.protocolVersion); serializer.value1b(value.state);
  serializer.value16b(value.localContainerUUID); serializer.value16b(value.localClusterUUID);
  serializer.value8b(value.deploymentID); serializer.value1b(value.storeKind);
  serializer.value4b(value.shardGroup); serializer.value4b(value.nShardGroups); serializer.value1b(value.writable);
  serializer.value16b(value.siblingSessionUUID); serializer.value8b(value.siblingSessionGeneration);
  serializer.value1b(value.siblingSessionHealthy); serializer.value16b(value.seededFromClusterUUID);
  serializer.value16b(value.seededFromContainerUUID); serializer.value8b(value.seedGeneration);
  serializer.text1b(value.seedFixtureSHA256, 64); serializer.text1b(value.appliedWatermarkSHA256, 64);
  if (value.protocolVersion >= 3) {
    serializer.text1b(value.sourceContentWatermarkSHA256, 64);
    serializer.text1b(value.sourceCatchupWatermarkSHA256, 64);
  }
  if (value.protocolVersion >= 4) {
    serializer.value16b(value.operationUUID); serializer.value16b(value.sourceBaselineOperationUUID);
    serializer.value16b(value.sourceRequestUUID); serializer.value16b(value.sourceMemberRequestUUID);
    serializer.value16b(value.seedRouteUUID); serializer.value8b(value.sourceDeploymentID); serializer.value16b(value.cutUUID); serializer.value8b(value.cutGeneration);
    serializer.value1b(value.sourceCutScope); serializer.value8b(value.retainUntilMilliseconds);
    serializer.text1b(value.materializedContentSHA256, 64); serializer.text1b(value.materializedHeadsSHA256, 64);
    serializer.value1b(value.cutMaterialized); serializer.value1b(value.committedHeadsDominateCut);
  }
}

static inline bool prodigyStatefulStoreReceiptValid(const ProdigyStatefulStoreReceipt& value)
{
  return (value.protocolVersion == ProdigyStatefulStoreReceipt::version || value.protocolVersion == ProdigyStatefulStoreReceipt::sourceCutVersion) &&
      (value.state == ProdigyStatefulStoreReceiptState::active || value.state == ProdigyStatefulStoreReceiptState::withdrawn) &&
      value.localContainerUUID != 0 && value.localClusterUUID != 0 && value.deploymentID != 0 &&
      value.storeKind != DeploymentIdentityStoreKind::unknown && value.shardGroup < value.nShardGroups && value.writable &&
      value.siblingSessionUUID != 0 && value.siblingSessionGeneration != 0 &&
      (value.state == ProdigyStatefulStoreReceiptState::active ? value.siblingSessionHealthy : !value.siblingSessionHealthy) &&
      value.seededFromClusterUUID != 0 && value.seededFromContainerUUID != 0 && value.seedGeneration != 0 &&
      prodigyIsSHA256HexDigest(value.seedFixtureSHA256) && prodigyIsSHA256HexDigest(value.appliedWatermarkSHA256) &&
      prodigyIsSHA256HexDigest(value.sourceContentWatermarkSHA256) && prodigyIsSHA256HexDigest(value.sourceCatchupWatermarkSHA256) &&
      (value.protocolVersion != ProdigyStatefulStoreReceipt::sourceCutVersion ||
       (value.operationUUID != 0 && value.sourceBaselineOperationUUID != 0 && value.sourceRequestUUID != 0 &&
        value.sourceMemberRequestUUID != 0 && value.seedRouteUUID != 0 && value.sourceDeploymentID != 0 && value.cutUUID != 0 && value.cutGeneration != 0 &&
        value.sourceCutScope == ProdigyStatefulStoreSourceCutScope::fullShardGroup && value.retainUntilMilliseconds != 0 &&
        prodigyIsSHA256HexDigest(value.materializedContentSHA256) && prodigyIsSHA256HexDigest(value.materializedHeadsSHA256) &&
        value.cutMaterialized && value.committedHeadsDominateCut));
}

// A native proof is usable only for the exact durable authority that requested it.
static inline bool prodigyStatefulStoreReceiptMatchesSourceCutAuthority(
    const ProdigyStatefulStoreReceipt& receipt, const ProdigyStatefulStoreSeedAuthority& authority)
{
  return receipt.protocolVersion == ProdigyStatefulStoreReceipt::sourceCutVersion &&
      prodigyStatefulStoreSeedAuthorityHasSourceCut(authority.protocolVersion) &&
      prodigyStatefulStoreReceiptValid(receipt) && prodigyStatefulStoreSeedAuthorityValid(authority) &&
      receipt.operationUUID == authority.operationUUID && receipt.sourceBaselineOperationUUID == authority.sourceBaselineOperationUUID &&
      receipt.sourceRequestUUID == authority.sourceRequestUUID && receipt.sourceMemberRequestUUID == authority.sourceMemberRequestUUID &&
      receipt.seedRouteUUID == authority.seedRouteUUID &&
      receipt.localClusterUUID == authority.targetClusterUUID && receipt.deploymentID == authority.targetDeploymentID &&
      receipt.localContainerUUID == authority.targetContainerUUID && receipt.storeKind == authority.storeKind &&
      receipt.shardGroup == authority.shardGroup && receipt.nShardGroups == authority.nShardGroups &&
      receipt.seededFromClusterUUID == authority.sourceClusterUUID && receipt.sourceDeploymentID == authority.sourceDeploymentID &&
      receipt.seededFromContainerUUID == authority.sourceContainerUUID && receipt.seedGeneration == authority.seedGeneration &&
      receipt.cutUUID == authority.cutUUID && receipt.cutGeneration == authority.cutGeneration &&
      receipt.sourceCutScope == authority.sourceCutScope && receipt.retainUntilMilliseconds == authority.retainUntilMilliseconds &&
      receipt.seedFixtureSHA256 == authority.fixtureSHA256 &&
      receipt.sourceContentWatermarkSHA256 == authority.sourceContentWatermarkSHA256 &&
      receipt.sourceCatchupWatermarkSHA256 == authority.sourceCatchupWatermarkSHA256 &&
      receipt.materializedContentSHA256 == authority.sourceContentWatermarkSHA256 &&
      receipt.materializedHeadsSHA256 == authority.sourceCatchupWatermarkSHA256;
}

// Authenticated recovery context. The prior receipt is an expectation only;
// the target must independently re-emit its own still-live materialization.
class ProdigyStatefulStoreProofRecovery {
public:
  ProdigyStatefulStoreSeedAuthority authority = {};
  ProdigyStatefulStoreReceipt expected = {};
  uint128_t nonce = 0;
  bool response = false;
  bool accepted = false;
};
template <typename S> static void serialize(S&& serializer, ProdigyStatefulStoreProofRecovery& value) {
  serializer.object(value.authority); serializer.object(value.expected); serializer.value16b(value.nonce);
  serializer.value1b(value.response); serializer.value1b(value.accepted);
}
static inline bool prodigyStatefulStoreProofRecoveryValid(const ProdigyStatefulStoreProofRecovery& value) {
  return value.nonce != 0 && (value.response || !value.accepted) && value.expected.state == ProdigyStatefulStoreReceiptState::active &&
      prodigyStatefulStoreReceiptMatchesSourceCutAuthority(value.expected, value.authority);
}

// Qualification work is named by its exact fault/workload contract.  These
// enums deliberately do not contain an "any" value: an old generic payload is
// not a safe substitute for a row-specific experiment.
enum class ProdigyNametagQualificationWorkload : uint8_t {
  sequentialUserKeys = 1, handoffFence, multiWriterKVGraph, truthClaim,
  localWriter, siteLocalWrites, seedCatchup, brainCatchup, permissionRecovery,
  cousinRoute, masqueBGP, graphKVReplay, radarMutation, pulseMatrix,
  truthWriterFence, mothershipResume,
};
enum class ProdigyNametagQualificationFault : uint8_t {
  none = 1, secondStreamHandoff, concurrentWriter, truthPartition,
  localWriterIsolation, sitePartition, seedInterruption, brainHardReboot,
  permissionRevoke, cousinSessionLoss, masqueSessionLoss, ewrOrdPathLoss,
  replayReorder, directedMutation, fixedMatrixDuplicate, secondTruthWriter,
  mothershipRestart,
};
enum class ProdigyNametagQualificationTarget : uint8_t {
  allSites = 1, localSiteWriters, ewrTruthWriter, ewrOrdPath, ordSeedCohort,
  ordBrain, ewrPermission, ewrOrdCousinRoute, allApp11Probes, mothership,
  sitePaths, ewrOrdPaths,
};
enum class ProdigyNametagQualificationSite : uint8_t { ewr = 1, ord = 2, lan = 3, all = 4 };
enum class ProdigyNametagQualificationStore : uint8_t {
  none = 0, hot = 1, cold = 2, radar = 3, pulse = 4, truth = 5, graphKV = 6,
};
enum class ProdigyNametagQualificationWitness : uint8_t {
  orderedUserKeyDigest = 1, handoffFenceHeld, commutativeKVGraphDigest,
  uniqueEwrTruthWinner, perSiteWriterIsolation, siteLocalWritesRecovered,
  seedCatchupResumed, brainCatchupWatermark, permissionReinstallSession,
  cousinRouteReconnected, masqueBGPRestored, ewrOrdPathRestored,
  graphKVReplayOrdered, radarDirectedMutationDigest, pulseMatrixDeduplicated,
  secondTruthWriterFenced, mothershipDurableResume,
};

// Row sixteen has one mutating EWR participant and two read-only observers.
// Keep that distinction typed on the App11 receipt so the global join cannot
// mistake three local handoff attempts for one globally fenced session.
enum class ProdigyNametagQualificationParticipantRole : uint8_t {
  none = 0, ewrSessionFence = 1, truthObserver = 2,
};

enum class ProdigyNametagQualificationRow : uint8_t {
  sequentialUserKeyWrites = 1, secondStreamHandoffFence, sharedKeyCommutativeWrites,
  truthClaimPartition, localWriterIsolation, sitePartitionLocalWrites,
  seedInterruptionResume, brainHardRebootCatchup, permissionRevokeReinstall,
  cousinRouteSessionReconnect, masqueSessionLossBgpRecovery, ewrOrdPathLoss,
  graphKvReplayReorder, radarDirectedMutations, pulseFixedMatrixDedup,
  secondTruthWriterFencing, mothershipRestartResume,
};

class ProdigyNametagQualificationDescriptor {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyNametagQualificationWorkload workload = ProdigyNametagQualificationWorkload::sequentialUserKeys;
  ProdigyNametagQualificationFault fault = ProdigyNametagQualificationFault::none;
  ProdigyNametagQualificationTarget target = ProdigyNametagQualificationTarget::allSites;
  ProdigyNametagQualificationSite targetSite = ProdigyNametagQualificationSite::all;
  ProdigyNametagQualificationSite peerSite = ProdigyNametagQualificationSite::all;
  uint8_t pathSlot = UINT8_MAX;
  ProdigyNametagQualificationStore store = ProdigyNametagQualificationStore::none;
  ProdigyNametagQualificationWitness expectedWitness =
      ProdigyNametagQualificationWitness::orderedUserKeyDigest;
};
template <typename S>
static void serialize(S&& serializer, ProdigyNametagQualificationDescriptor& descriptor)
{
  serializer.value4b(descriptor.protocolVersion); serializer.value1b(descriptor.workload);
  serializer.value1b(descriptor.fault); serializer.value1b(descriptor.target);
  serializer.value1b(descriptor.targetSite); serializer.value1b(descriptor.peerSite);
  serializer.value1b(descriptor.pathSlot); serializer.value1b(descriptor.store);
  serializer.value1b(descriptor.expectedWitness);
}
static inline bool prodigyNametagQualificationDescriptorValid(
    const ProdigyNametagQualificationDescriptor& descriptor)
{
  return descriptor.protocolVersion == ProdigyNametagQualificationDescriptor::version &&
      uint8_t(descriptor.workload) >= 1 && uint8_t(descriptor.workload) <= 16 &&
      uint8_t(descriptor.fault) >= 1 && uint8_t(descriptor.fault) <= 17 &&
      uint8_t(descriptor.target) >= 1 && uint8_t(descriptor.target) <= 12 &&
      uint8_t(descriptor.targetSite) >= 1 && uint8_t(descriptor.targetSite) <= 4 &&
      uint8_t(descriptor.peerSite) >= 1 && uint8_t(descriptor.peerSite) <= 4 &&
      uint8_t(descriptor.store) <= 6 && uint8_t(descriptor.expectedWitness) >= 1 &&
      uint8_t(descriptor.expectedWitness) <= 17 &&
      ((descriptor.target == ProdigyNametagQualificationTarget::ewrOrdPath ||
        descriptor.target == ProdigyNametagQualificationTarget::ewrOrdCousinRoute) ?
          (descriptor.targetSite == ProdigyNametagQualificationSite::ewr &&
           descriptor.peerSite == ProdigyNametagQualificationSite::ord && descriptor.pathSlot < 3) :
          descriptor.pathSlot == UINT8_MAX) &&
      (descriptor.target != ProdigyNametagQualificationTarget::sitePaths ||
          (descriptor.targetSite != ProdigyNametagQualificationSite::all &&
           descriptor.peerSite == ProdigyNametagQualificationSite::all)) &&
      (descriptor.target != ProdigyNametagQualificationTarget::ewrOrdPaths ||
          (descriptor.targetSite == ProdigyNametagQualificationSite::ewr &&
           descriptor.peerSite == ProdigyNametagQualificationSite::ord)) &&
      (descriptor.target == ProdigyNametagQualificationTarget::ewrTruthWriter ?
          (descriptor.targetSite == ProdigyNametagQualificationSite::ewr &&
           descriptor.store == ProdigyNametagQualificationStore::truth) : true) &&
      (descriptor.target == ProdigyNametagQualificationTarget::ordSeedCohort ||
       descriptor.target == ProdigyNametagQualificationTarget::ordBrain ?
          descriptor.targetSite == ProdigyNametagQualificationSite::ord : true);
}
static inline bool prodigyNametagQualificationDescriptorEqual(
    const ProdigyNametagQualificationDescriptor& left,
    const ProdigyNametagQualificationDescriptor& right)
{
  return left.protocolVersion == right.protocolVersion && left.workload == right.workload &&
      left.fault == right.fault && left.target == right.target && left.targetSite == right.targetSite &&
      left.peerSite == right.peerSite && left.pathSlot == right.pathSlot && left.store == right.store &&
      left.expectedWitness == right.expectedWitness;
}

// This is the protocol-owned row mapping used by every participant.  Keeping
// it beside the wire types prevents Mothership and App11 from accepting two
// different experiments for the same row number.
static constexpr ProdigyNametagQualificationDescriptor prodigyNametagQualificationDescriptor(
    ProdigyNametagQualificationRow row)
{
  using Workload = ProdigyNametagQualificationWorkload;
  using Fault = ProdigyNametagQualificationFault;
  using Target = ProdigyNametagQualificationTarget;
  using Site = ProdigyNametagQualificationSite;
  using Store = ProdigyNametagQualificationStore;
  using Witness = ProdigyNametagQualificationWitness;
  switch (row) {
    case ProdigyNametagQualificationRow::sequentialUserKeyWrites:
      return {1, Workload::sequentialUserKeys, Fault::none, Target::allApp11Probes, Site::all, Site::all, UINT8_MAX, Store::hot, Witness::orderedUserKeyDigest};
    case ProdigyNametagQualificationRow::secondStreamHandoffFence:
      return {1, Workload::handoffFence, Fault::secondStreamHandoff, Target::allApp11Probes, Site::all, Site::all, UINT8_MAX, Store::none, Witness::handoffFenceHeld};
    case ProdigyNametagQualificationRow::sharedKeyCommutativeWrites:
      return {1, Workload::multiWriterKVGraph, Fault::concurrentWriter, Target::allApp11Probes, Site::all, Site::all, UINT8_MAX, Store::graphKV, Witness::commutativeKVGraphDigest};
    case ProdigyNametagQualificationRow::truthClaimPartition:
      return {1, Workload::truthClaim, Fault::truthPartition, Target::ewrTruthWriter, Site::ewr, Site::ord, UINT8_MAX, Store::truth, Witness::uniqueEwrTruthWinner};
    case ProdigyNametagQualificationRow::localWriterIsolation:
      return {1, Workload::localWriter, Fault::localWriterIsolation, Target::localSiteWriters, Site::all, Site::all, UINT8_MAX, Store::hot, Witness::perSiteWriterIsolation};
    case ProdigyNametagQualificationRow::sitePartitionLocalWrites:
      return {1, Workload::siteLocalWrites, Fault::sitePartition, Target::sitePaths, Site::ord, Site::all, UINT8_MAX, Store::none, Witness::siteLocalWritesRecovered};
    case ProdigyNametagQualificationRow::seedInterruptionResume:
      return {1, Workload::seedCatchup, Fault::seedInterruption, Target::ordSeedCohort, Site::ord, Site::ewr, UINT8_MAX, Store::cold, Witness::seedCatchupResumed};
    case ProdigyNametagQualificationRow::brainHardRebootCatchup:
      return {1, Workload::brainCatchup, Fault::brainHardReboot, Target::ordBrain, Site::ord, Site::all, UINT8_MAX, Store::none, Witness::brainCatchupWatermark};
    case ProdigyNametagQualificationRow::permissionRevokeReinstall:
      return {1, Workload::permissionRecovery, Fault::permissionRevoke, Target::ewrPermission, Site::ewr, Site::ord, UINT8_MAX, Store::none, Witness::permissionReinstallSession};
    case ProdigyNametagQualificationRow::cousinRouteSessionReconnect:
      return {1, Workload::cousinRoute, Fault::cousinSessionLoss, Target::ewrOrdCousinRoute, Site::ewr, Site::ord, 0, Store::none, Witness::cousinRouteReconnected};
    case ProdigyNametagQualificationRow::masqueSessionLossBgpRecovery:
      return {1, Workload::masqueBGP, Fault::masqueSessionLoss, Target::sitePaths, Site::ord, Site::all, UINT8_MAX, Store::none, Witness::masqueBGPRestored};
    case ProdigyNametagQualificationRow::ewrOrdPathLoss:
      return {1, Workload::masqueBGP, Fault::ewrOrdPathLoss, Target::ewrOrdPaths, Site::ewr, Site::ord, UINT8_MAX, Store::none, Witness::ewrOrdPathRestored};
    case ProdigyNametagQualificationRow::graphKvReplayReorder:
      return {1, Workload::graphKVReplay, Fault::replayReorder, Target::allApp11Probes, Site::all, Site::all, UINT8_MAX, Store::graphKV, Witness::graphKVReplayOrdered};
    case ProdigyNametagQualificationRow::radarDirectedMutations:
      return {1, Workload::radarMutation, Fault::directedMutation, Target::allApp11Probes, Site::all, Site::all, UINT8_MAX, Store::radar, Witness::radarDirectedMutationDigest};
    case ProdigyNametagQualificationRow::pulseFixedMatrixDedup:
      return {1, Workload::pulseMatrix, Fault::fixedMatrixDuplicate, Target::allApp11Probes, Site::all, Site::all, UINT8_MAX, Store::pulse, Witness::pulseMatrixDeduplicated};
    case ProdigyNametagQualificationRow::secondTruthWriterFencing:
      return {1, Workload::truthWriterFence, Fault::secondTruthWriter, Target::ewrTruthWriter, Site::ewr, Site::ord, UINT8_MAX, Store::truth, Witness::secondTruthWriterFenced};
    case ProdigyNametagQualificationRow::mothershipRestartResume:
      return {1, Workload::mothershipResume, Fault::mothershipRestart, Target::mothership, Site::all, Site::all, UINT8_MAX, Store::none, Witness::mothershipDurableResume};
  }
  return {};
}

static inline bool prodigyNametagQualificationRowDescriptorValid(
    uint8_t row, const ProdigyNametagQualificationDescriptor& descriptor)
{
  return row >= uint8_t(ProdigyNametagQualificationRow::sequentialUserKeyWrites) &&
      row <= uint8_t(ProdigyNametagQualificationRow::mothershipRestartResume) &&
      prodigyNametagQualificationDescriptorEqual(
          descriptor, prodigyNametagQualificationDescriptor(ProdigyNametagQualificationRow(row)));
}

// A bounded application-owned qualification observation.  This is not by
// itself a five-store or healthy-topology receipt: Brain must join it with the
// exact native store, Truth-carrier, and topology evidence for the same durable
// qualification intent.  Keeping that distinction in the type name prevents
// an application ACK from being promoted into database convergence proof.
// Rows nine and ten use one phased qualification operation.  Session and
// socket observations are supplied by the native session owner, never inferred
// from route authority or a command acknowledgement.
enum class ProdigyNametagQualificationCousinStage : uint8_t { none = 0, arm = 1, faultObserved = 2, final = 3 };
class ProdigyNametagQualificationCousinSession {
public:
  uint128_t pairUUID = 0, routeUUID = 0, sourcePermissionUUID = 0, destinationPermissionUUID = 0;
  uint128_t sourceClusterUUID = 0, destinationClusterUUID = 0;
  uint64_t sourceDeploymentID = 0, destinationDeploymentID = 0;
  uint128_t sourceContainerUUID = 0, destinationContainerUUID = 0;
  uint128_t sessionUUID = 0, successorRouteUUID = 0, successorSourcePermissionUUID = 0, successorSessionUUID = 0;
  uint64_t sessionGeneration = 0, successorSessionGeneration = 0;
  uint64_t routeGeneration = 0, sourcePermissionAuthorityGeneration = 0;
  uint64_t successorRouteGeneration = 0, successorPermissionAuthorityGeneration = 0;
  bool transportClosedOrUnsendable = false, healthy = false;
};
template <typename S>
static void serialize(S&& s, ProdigyNametagQualificationCousinSession& v) {
  s.value16b(v.pairUUID); s.value16b(v.routeUUID); s.value16b(v.sourcePermissionUUID); s.value16b(v.destinationPermissionUUID);
  s.value16b(v.sourceClusterUUID); s.value16b(v.destinationClusterUUID);
  s.value8b(v.sourceDeploymentID); s.value8b(v.destinationDeploymentID);
  s.value16b(v.sourceContainerUUID); s.value16b(v.destinationContainerUUID);
  s.value16b(v.sessionUUID); s.value8b(v.sessionGeneration);
  s.value16b(v.successorRouteUUID); s.value16b(v.successorSourcePermissionUUID);
  s.value16b(v.successorSessionUUID); s.value8b(v.successorSessionGeneration);
  s.value8b(v.routeGeneration); s.value8b(v.sourcePermissionAuthorityGeneration);
  s.value8b(v.successorRouteGeneration); s.value8b(v.successorPermissionAuthorityGeneration);
  s.value1b(v.transportClosedOrUnsendable); s.value1b(v.healthy);
}
static inline bool prodigyNametagQualificationCousinSessionIdentityValid(const ProdigyNametagQualificationCousinSession& v) {
  return v.pairUUID && v.routeUUID && v.sourcePermissionUUID && v.destinationPermissionUUID &&
      v.sourceClusterUUID && v.destinationClusterUUID && v.sourceClusterUUID != v.destinationClusterUUID &&
      v.sourceDeploymentID && v.destinationDeploymentID && v.sourceContainerUUID && v.destinationContainerUUID &&
      v.sessionUUID && v.sessionGeneration && v.successorRouteUUID && v.successorSourcePermissionUUID &&
      v.routeGeneration && v.sourcePermissionAuthorityGeneration && v.successorRouteGeneration;
}
// One native stateful container owns each transport observation.  In
// particular, an App11 process cannot attest to another process's socket.
// One envelope covers one route so routes with different owners remain distinct.
class ProdigyNametagQualificationCousinTransport {
public:
  // Version 4 distinguishes this shared envelope on the existing
  // Mothership qualification topic from the site request versions 2 and 3.
  static constexpr uint32_t version = 4;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0;
  uint128_t memberRequestUUID = 0;
  uint64_t executionGeneration = 0;
  int64_t deadlineAtMilliseconds = 0;
  ProdigyNametagQualificationCousinStage stage = ProdigyNametagQualificationCousinStage::none;
  ProdigyNametagQualificationCousinSession session = {};
  bool response = false, ready = false;
  String failure = {};
};
template <typename S>
static void serialize(S&& s, ProdigyNametagQualificationCousinTransport& value) {
  s.value4b(value.protocolVersion); s.value16b(value.runUUID); s.value16b(value.memberRequestUUID); s.value8b(value.executionGeneration);
  s.value8b(value.deadlineAtMilliseconds); s.value1b(value.stage); s.object(value.session);
  s.value1b(value.response); s.value1b(value.ready); s.text1b(value.failure, 1024);
}
static inline bool prodigyNametagQualificationCousinTransportValid(
    const ProdigyNametagQualificationCousinTransport& value) {
  const auto& s = value.session;
  if (value.protocolVersion != ProdigyNametagQualificationCousinTransport::version || !value.runUUID || !value.memberRequestUUID ||
      !value.executionGeneration || value.deadlineAtMilliseconds <= 0 ||
      value.stage < ProdigyNametagQualificationCousinStage::arm ||
      value.stage > ProdigyNametagQualificationCousinStage::final ||
      !prodigyNametagQualificationCousinSessionIdentityValid(s) ||
      (!value.response && (value.ready || !value.failure.empty())) ||
      (value.ready && (!value.response || !value.failure.empty()))) return false;
  if (!value.response || !value.ready)
    return !s.transportClosedOrUnsendable && !s.healthy && !s.successorSessionUUID &&
        !s.successorSessionGeneration;
  if (value.stage == ProdigyNametagQualificationCousinStage::arm)
    return s.healthy && !s.transportClosedOrUnsendable && !s.successorSessionUUID && !s.successorSessionGeneration;
  if (value.stage == ProdigyNametagQualificationCousinStage::faultObserved)
    return !s.healthy && s.transportClosedOrUnsendable && !s.successorSessionUUID && !s.successorSessionGeneration;
  return s.healthy && s.transportClosedOrUnsendable && s.successorSessionUUID && s.successorSessionGeneration &&
      s.successorPermissionAuthorityGeneration &&
      (s.successorSessionUUID != s.sessionUUID || s.successorSessionGeneration != s.sessionGeneration);
}
// Initial arm identifies a commissioned route; only the current Brain may
// resolve and challenge the native session.  Subsequent requests use the
// fully bound form above and never silently replace that challenge.
static inline bool prodigyNametagQualificationCousinTransportInitialArmValid(
    const ProdigyNametagQualificationCousinTransport& value) {
  const auto& s = value.session;
  return value.protocolVersion == ProdigyNametagQualificationCousinTransport::version && value.runUUID &&
      !value.memberRequestUUID && value.executionGeneration && value.deadlineAtMilliseconds > 0 &&
      value.stage == ProdigyNametagQualificationCousinStage::arm && !value.response && !value.ready &&
      value.failure.empty() && s.pairUUID && s.routeUUID && s.sourcePermissionUUID && s.destinationPermissionUUID &&
      s.sourceClusterUUID && s.destinationClusterUUID && s.sourceClusterUUID != s.destinationClusterUUID &&
      s.sourceDeploymentID && s.destinationDeploymentID && !s.sourceContainerUUID && !s.destinationContainerUUID &&
      !s.sessionUUID && !s.sessionGeneration && s.successorRouteUUID && s.successorSourcePermissionUUID &&
      s.routeGeneration && s.sourcePermissionAuthorityGeneration && s.successorRouteGeneration &&
      !s.successorPermissionAuthorityGeneration && !s.successorSessionUUID && !s.successorSessionGeneration &&
      !s.transportClosedOrUnsendable && !s.healthy;
}
static inline bool prodigyNametagQualificationCousinTransportResponseMatches(
    const ProdigyNametagQualificationCousinTransport& request,
    const ProdigyNametagQualificationCousinTransport& response) {
  if (request.response || !response.response || !prodigyNametagQualificationCousinTransportValid(request) ||
      !prodigyNametagQualificationCousinTransportValid(response)) return false;
  auto left = request, right = response;
  right.response = right.ready = false; right.failure.clear();
  right.session.transportClosedOrUnsendable = right.session.healthy = false;
  right.session.successorSessionUUID = 0; right.session.successorSessionGeneration = 0;
  String a = {}, b = {};
  return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
}

enum class ProdigyNametagQualificationReplayStage : uint8_t { none = 0, prearm = 1, arm = 2, replay = 3, query = 4, release = 5 };
enum class ProdigyNametagQualificationReplayStore : uint8_t { none = 0, kv = 1, graph = 2 };
static inline uint16_t prodigyNametagQualificationReplayApplicationID(ProdigyNametagQualificationReplayStore store) {
  return store == ProdigyNametagQualificationReplayStore::kv ? MeshRegistry::Hot::applicationID :
      store == ProdigyNametagQualificationReplayStore::graph ? MeshRegistry::Pulse::applicationID : 0;
}
// A single advertiser can serve several subscribers on the same route. Pick
// one exact session deterministically without treating those sessions as ambiguous.
static inline bool prodigyNametagQualificationReplaySessionLess(
    uint128_t source, uint128_t target, uint128_t session,
    uint128_t otherSource, uint128_t otherTarget, uint128_t otherSession) {
  return source != otherSource ? source < otherSource :
      target != otherTarget ? target < otherTarget : session < otherSession;
}
// KV advertiser-to-subscriber delivery reverses the route's local halves;
// graph sibling traffic is bidirectional and selects the source half.
static inline CousinRouteHalf prodigyNametagQualificationReplayLocalHalf(
    ProdigyNametagQualificationReplayStore store, bool targetSide) {
  const bool sourceHalf = (store == ProdigyNametagQualificationReplayStore::kv) ? targetSide : !targetSide;
  return sourceHalf ? CousinRouteHalf::source : CousinRouteHalf::destination;
}

// One workload name owner for Mothership and App11. KV routing uses exactly
// the normal first-16-byte slot hash; observation reuses the injection run.
static inline bool prodigyNametagQualificationReplayWorkloadName(uint128_t runUUID,
    ProdigyNametagQualificationReplayStore store, uint32_t group, String& name) {
  name.clear();
  if (!runUUID || (store != ProdigyNametagQualificationReplayStore::kv &&
      store != ProdigyNametagQualificationReplayStore::graph) ||
      group >= (store == ProdigyNametagQualificationReplayStore::kv ? 3u : 1u)) return false;
  for (uint32_t candidate = 0; candidate < 262144; ++candidate) {
    String identity("nametag.native-replay.v1", Copy::yes);
    const uint8_t storeID = uint8_t(store);
    identity.append(reinterpret_cast<const uint8_t*>(&runUUID), sizeof(runUUID));
    identity.append(storeID);
    identity.append(reinterpret_cast<const uint8_t*>(&group), sizeof(group));
    identity.append(reinterpret_cast<const uint8_t*>(&candidate), sizeof(candidate));
    if (!prodigyComputeSHA256Hex(identity, name)) return false;
    if (store == ProdigyNametagQualificationReplayStore::graph ||
        statefulServiceGroupOwnerForSlot(jump_consistent_hash(name.data(), 16), 3) == group) return true;
  }
  name.clear(); return false;
}

// One authenticated native source/target stream and one bounded row-13 run.
// Frame IDs and observations originate at the native replication owners.
class ProdigyNametagQualificationReplay {
public:
  static constexpr uint32_t version = 10;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0, challengeUUID = 0;
  uint64_t executionGeneration = 0;
  int64_t deadlineAtMilliseconds = 0;
  uint8_t direction = 0;
  ProdigyNametagQualificationReplayStage stage = ProdigyNametagQualificationReplayStage::none;
  ProdigyNametagQualificationReplayStore store = ProdigyNametagQualificationReplayStore::none;
  uint16_t applicationID = 0;
  uint32_t shardGroup = 0;
  uint128_t sourceAddress = 0;
  String workloadName = {};
  ProdigyNametagQualificationCousinSession session = {};
  bool targetSide = false;
  uint128_t originUUID = 0;
  uint64_t committedID = 0, olderCommittedID = 0, delayedID = 0, catchupID = 0;
  bool response = false, ready = false, duplicateRejected = false, staleRejected = false, delayedApplied = false, delayedRejected = false, catchupApplied = false;
  String failure = {};
};
template <typename S> static void serialize(S&& s, ProdigyNametagQualificationReplay& v) {
  s.value4b(v.protocolVersion); s.value16b(v.runUUID); s.value16b(v.challengeUUID); s.value8b(v.executionGeneration);
  s.value8b(v.deadlineAtMilliseconds); s.value1b(v.direction); s.value1b(v.stage); s.value1b(v.store); s.value2b(v.applicationID);
  s.value4b(v.shardGroup); s.value16b(v.sourceAddress); s.text1b(v.workloadName, 128); s.object(v.session); s.value1b(v.targetSide); s.value16b(v.originUUID); s.value8b(v.committedID);
  s.value8b(v.olderCommittedID); s.value8b(v.delayedID); s.value8b(v.catchupID); s.value1b(v.response); s.value1b(v.ready);
  s.value1b(v.duplicateRejected); s.value1b(v.staleRejected); s.value1b(v.delayedApplied); s.value1b(v.delayedRejected); s.value1b(v.catchupApplied); s.text1b(v.failure, 1024);
}
static inline bool prodigyNametagQualificationReplayValid(const ProdigyNametagQualificationReplay& v) {
  const auto& s = v.session;
  if (v.protocolVersion != v.version || !v.runUUID || !v.challengeUUID || !v.executionGeneration ||
      v.deadlineAtMilliseconds <= 0 || v.direction != 1 || v.stage < ProdigyNametagQualificationReplayStage::prearm ||
      v.stage > ProdigyNametagQualificationReplayStage::release ||
      v.store < ProdigyNametagQualificationReplayStore::kv || v.store > ProdigyNametagQualificationReplayStore::graph ||
      !v.applicationID || !v.sourceAddress || v.workloadName.empty() || v.workloadName.size() > 128 || !s.pairUUID || !s.routeUUID || !s.sourcePermissionUUID || !s.destinationPermissionUUID ||
      !s.sourceClusterUUID || !s.destinationClusterUUID || s.sourceClusterUUID == s.destinationClusterUUID ||
      !s.sourceDeploymentID || !s.destinationDeploymentID || !s.sourceContainerUUID || !s.destinationContainerUUID ||
      !s.sessionUUID || !s.sessionGeneration || !s.routeGeneration || !s.sourcePermissionAuthorityGeneration ||
      (!v.response && (v.ready || !v.failure.empty() || v.duplicateRejected || v.staleRejected || v.delayedApplied || v.delayedRejected || v.catchupApplied)) ||
      (v.ready && (!v.response || !v.failure.empty()))) return false;
  const bool hasIDs = v.originUUID && v.committedID && v.olderCommittedID && v.delayedID &&
        v.olderCommittedID < v.delayedID && v.delayedID < v.committedID &&
        (v.store == ProdigyNametagQualificationReplayStore::kv ? v.catchupID == 0 : v.catchupID > v.committedID);
  const bool noIDs = !v.originUUID && !v.committedID && !v.olderCommittedID && !v.delayedID && !v.catchupID;
  const bool noObservations = !v.duplicateRejected && !v.staleRejected && !v.delayedApplied && !v.delayedRejected && !v.catchupApplied;
  if (!v.targetSide && v.stage == ProdigyNametagQualificationReplayStage::prearm) return false;
  if (v.targetSide ? (v.stage == ProdigyNametagQualificationReplayStage::prearm ? !noIDs :
      v.stage == ProdigyNametagQualificationReplayStage::release ? (!noIDs && !hasIDs) : !hasIDs) : (!v.response ? !noIDs : ((v.ready && v.stage == ProdigyNametagQualificationReplayStage::query) ? !hasIDs : !noIDs))) return false;
  if (!v.targetSide || !v.ready || v.stage != ProdigyNametagQualificationReplayStage::query) return noObservations;
  return v.duplicateRejected && v.staleRejected &&
      (v.store == ProdigyNametagQualificationReplayStore::kv ? (v.delayedApplied && !v.delayedRejected && !v.catchupApplied) :
                                                                (!v.delayedApplied && v.delayedRejected && v.catchupApplied));
}
// Release may traverse the authenticated relay briefly after its deadline.
// Brain and the native owner still require the exact installed challenge.
static inline bool prodigyNametagQualificationReplayRelayTimely(
    const ProdigyNametagQualificationReplay& value, int64_t now) {
  return value.deadlineAtMilliseconds > now ||
      (value.stage == ProdigyNametagQualificationReplayStage::release &&
       value.deadlineAtMilliseconds > 0 && now - value.deadlineAtMilliseconds <= 60000);
}
static inline bool prodigyNametagQualificationReplayExpiredReleaseMatches(
    const ProdigyNametagQualificationReplay& request, const ProdigyNametagQualificationReplay& installedRequest,
    bool installed, uint64_t installedEpoch, uint64_t currentEpoch, int64_t now) {
  if (!installed || !currentEpoch || installedEpoch != currentEpoch || request.response ||
      request.stage != ProdigyNametagQualificationReplayStage::release || request.deadlineAtMilliseconds > now ||
      !prodigyNametagQualificationReplayRelayTimely(request, now) || !prodigyNametagQualificationReplayValid(request)) return false;
  auto expected = installedRequest; expected.stage = request.stage;
  auto actual = request; String a = {}, b = {};
  return BitseryEngine::serialize(a, expected) && BitseryEngine::serialize(b, actual) && a == b;
}
static inline bool prodigyNametagQualificationReplayResponseMatches(
    const ProdigyNametagQualificationReplay& request, const ProdigyNametagQualificationReplay& response) {
  if (request.response || !response.response || !prodigyNametagQualificationReplayValid(request) ||
      !prodigyNametagQualificationReplayValid(response)) return false;
  auto a = request, b = response;
  b.response = b.ready = false; b.failure.clear();
  if (!request.targetSide) { b.originUUID = 0; b.committedID = b.olderCommittedID = b.delayedID = b.catchupID = 0; }
  b.duplicateRejected = b.staleRejected = b.delayedApplied = b.delayedRejected = b.catchupApplied = false;
  String left = {}, right = {};
  return BitseryEngine::serialize(left, a) && BitseryEngine::serialize(right, b) && left == right;
}

// The source Brain resolves the live session and container before Mothership
// persists the resulting challenge; authority alone is not a transport proof.
static inline bool prodigyNametagQualificationReplayInitialValid(const ProdigyNametagQualificationReplay& request) {
  if (request.response || request.targetSide || request.stage != ProdigyNametagQualificationReplayStage::arm ||
      request.challengeUUID || request.sourceAddress || request.session.sourceContainerUUID ||
      request.session.destinationContainerUUID || request.session.sessionUUID || request.session.sessionGeneration) return false;
  auto populated = request;
  populated.challengeUUID = 1; populated.sourceAddress = 1;
  populated.session.sourceContainerUUID = 1; populated.session.destinationContainerUUID = 2;
  populated.session.sessionUUID = 3; populated.session.sessionGeneration = 1;
  return prodigyNametagQualificationReplayValid(populated);
}
static inline bool prodigyNametagQualificationReplayResolutionMatches(
    const ProdigyNametagQualificationReplay& request, const ProdigyNametagQualificationReplay& response) {
  if (!prodigyNametagQualificationReplayInitialValid(request) || !response.response || response.ready ||
      !response.failure.empty() || !prodigyNametagQualificationReplayValid(response)) return false;
  auto expected = request, observed = response;
  observed.response = false; observed.challengeUUID = 0; observed.sourceAddress = 0;
  observed.session.sourceContainerUUID = observed.session.destinationContainerUUID = 0;
  observed.session.sessionUUID = 0; observed.session.sessionGeneration = 0;
  String a = {}, b = {};
  return BitseryEngine::serialize(a, expected) && BitseryEngine::serialize(b, observed) && a == b;
}

// Seed interruption is bound to one accepted authority and one native stream.
// A held response is evidence only after the worker has applied snapshot data.
// Exact current machine OS boot identity; Neuron reads the kernel boot ID.
struct ProdigyNametagQualificationMachineBoot {
  static constexpr uint32_t version = 15;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0, challengeUUID = 0, clusterUUID = 0, machineUUID = 0;
  uint64_t executionGeneration = 0;
  int64_t deadlineAtMilliseconds = 0;
  bool response = false, ready = false;
  String bootID, failure;
};
template <typename S> static void serialize(S&& s, ProdigyNametagQualificationMachineBoot& v) {
  s.value4b(v.protocolVersion); s.value16b(v.runUUID); s.value16b(v.challengeUUID);
  s.value16b(v.clusterUUID); s.value16b(v.machineUUID); s.value8b(v.executionGeneration);
  s.value8b(v.deadlineAtMilliseconds); s.value1b(v.response); s.value1b(v.ready);
  s.text1b(v.bootID, 36); s.text1b(v.failure, 256);
}
static inline bool prodigyNametagQualificationMachineBootValid(const ProdigyNametagQualificationMachineBoot& v) {
  if (v.protocolVersion != v.version || !v.runUUID || !v.challengeUUID || !v.clusterUUID || !v.machineUUID ||
      !v.executionGeneration || v.deadlineAtMilliseconds <= 0 || v.failure.size() > 256 ||
      (!v.response && (v.ready || !v.bootID.empty() || !v.failure.empty())) ||
      (v.ready && (!v.response || !v.failure.empty() || v.bootID.size() != 36)) ||
      (!v.ready && !v.bootID.empty())) return false;
  if (v.ready) for (uint32_t i = 0; i < 36; ++i) {
    const char c = v.bootID[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != '-') return false; }
    else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}
static inline bool prodigyNametagQualificationMachineBootMatches(
    const ProdigyNametagQualificationMachineBoot& request, const ProdigyNametagQualificationMachineBoot& response) {
  if (request.response || !response.response || !prodigyNametagQualificationMachineBootValid(request) ||
      !prodigyNametagQualificationMachineBootValid(response)) return false;
  auto expected = request, actual = response; actual.response = actual.ready = false; actual.bootID.clear(); actual.failure.clear();
  String a, b; return BitseryEngine::serialize(a, expected) && BitseryEngine::serialize(b, actual) && a == b;
}

enum class ProdigyNametagQualificationSeedFaultStage : uint8_t { none = 0, arm = 1, query = 2, release = 3 };
class ProdigyNametagQualificationSeedFault {
public:
  static constexpr uint32_t version = 14;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0, challengeUUID = 0;
  uint64_t executionGeneration = 0;
  int64_t deadlineAtMilliseconds = 0;
  ProdigyNametagQualificationSeedFaultStage stage = ProdigyNametagQualificationSeedFaultStage::none;
  ProdigyStatefulStoreSeedAuthority authority = {};
  bool response = false, ready = false, held = false;
  uint128_t sessionUUID = 0;
  uint64_t sessionGeneration = 0, appliedFrames = 0;
  String failure;
};
template <typename S> static void serialize(S&& s, ProdigyNametagQualificationSeedFault& v) {
  s.value4b(v.protocolVersion); s.value16b(v.runUUID); s.value16b(v.challengeUUID);
  s.value8b(v.executionGeneration); s.value8b(v.deadlineAtMilliseconds); s.value1b(v.stage);
  s.object(v.authority); s.value1b(v.response); s.value1b(v.ready); s.value1b(v.held);
  s.value16b(v.sessionUUID); s.value8b(v.sessionGeneration); s.value8b(v.appliedFrames); s.text1b(v.failure, 1024);
}
static inline bool prodigyNametagQualificationSeedFaultValid(const ProdigyNametagQualificationSeedFault& v) {
  if (v.protocolVersion != v.version || !v.runUUID || !v.challengeUUID || !v.executionGeneration ||
      v.deadlineAtMilliseconds <= 0 || v.stage < ProdigyNametagQualificationSeedFaultStage::arm ||
      v.stage > ProdigyNametagQualificationSeedFaultStage::release ||
      !prodigyStatefulStoreSeedAuthorityValid(v.authority) ||
      v.authority.protocolVersion != ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion ||
      v.runUUID != v.authority.qualificationRunUUID || v.challengeUUID != v.authority.qualificationChallengeUUID ||
      v.executionGeneration != v.authority.qualificationExecutionGeneration ||
      v.deadlineAtMilliseconds != v.authority.qualificationDeadlineAtMilliseconds ||
      v.deadlineAtMilliseconds > v.authority.retainUntilMilliseconds ||
      (!v.response && (v.ready || v.held || v.sessionUUID || v.sessionGeneration || v.appliedFrames || !v.failure.empty())) ||
      (v.ready && (!v.response || !v.failure.empty())) ||
      (v.held && (!v.ready || v.stage != ProdigyNametagQualificationSeedFaultStage::query ||
                  !v.sessionUUID || !v.sessionGeneration || !v.appliedFrames))) return false;
  return v.held || (!v.sessionUUID && !v.sessionGeneration && !v.appliedFrames);
}
static inline bool prodigyNametagQualificationSeedFaultResponseMatches(
    const ProdigyNametagQualificationSeedFault& request, const ProdigyNametagQualificationSeedFault& response) {
  if (request.response || !response.response || !prodigyNametagQualificationSeedFaultValid(request) ||
      !prodigyNametagQualificationSeedFaultValid(response)) return false;
  auto expected = request, observed = response;
  observed.response = observed.ready = observed.held = false;
  observed.sessionUUID = 0; observed.sessionGeneration = observed.appliedFrames = 0; observed.failure.clear();
  String a, b;
  return BitseryEngine::serialize(a, expected) && BitseryEngine::serialize(b, observed) && a == b;
}

// Row 5 names one live container and the two other writers in the same
// shard group. The challenge is minted by Brain and pinned before a cut.
enum class ProdigyNametagQualificationWriterIsolationStage : uint8_t {
  none = 0, arm = 1, isolate = 2, query = 3, release = 4
};
class ProdigyNametagQualificationWriterIsolation {
public:
  static constexpr uint32_t version = 11;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0, challengeUUID = 0, clusterUUID = 0;
  uint64_t executionGeneration = 0, deploymentID = 0;
  int64_t deadlineAtMilliseconds = 0;
  ProdigyNametagQualificationWriterIsolationStage stage = ProdigyNametagQualificationWriterIsolationStage::none;
  uint16_t applicationID = 0;
  uint32_t shardGroup = 0, validForMilliseconds = 0;
  uint128_t targetContainerUUID = 0, targetMachineUUID = 0, targetAddress = 0;
  std::array<uint128_t, 2> survivorContainerUUIDs = {}, survivorAddresses = {};
  bool response = false, ready = false, isolated = false;
  String failure = {};
};
template <typename S> static void serialize(S&& s, ProdigyNametagQualificationWriterIsolation& v) {
  s.value4b(v.protocolVersion); s.value16b(v.runUUID); s.value16b(v.challengeUUID); s.value16b(v.clusterUUID);
  s.value8b(v.executionGeneration); s.value8b(v.deploymentID); s.value8b(v.deadlineAtMilliseconds);
  s.value1b(v.stage); s.value2b(v.applicationID); s.value4b(v.shardGroup); s.value4b(v.validForMilliseconds);
  s.value16b(v.targetContainerUUID); s.value16b(v.targetMachineUUID); s.value16b(v.targetAddress);
  for (auto& value : v.survivorContainerUUIDs) s.value16b(value);
  for (auto& value : v.survivorAddresses) s.value16b(value);
  s.value1b(v.response); s.value1b(v.ready); s.value1b(v.isolated); s.text1b(v.failure, 1024);
}
static inline bool prodigyNametagQualificationWriterIsolationValid(const ProdigyNametagQualificationWriterIsolation& v) {
  if (v.protocolVersion != v.version || !v.runUUID || !v.challengeUUID || !v.clusterUUID || !v.executionGeneration ||
      !v.deploymentID || v.deadlineAtMilliseconds <= 0 || v.stage < ProdigyNametagQualificationWriterIsolationStage::arm ||
      v.stage > ProdigyNametagQualificationWriterIsolationStage::release || (v.applicationID != 3 && v.applicationID != 4) ||
      !v.validForMilliseconds || v.validForMilliseconds > 60000 || !v.targetContainerUUID || !v.targetMachineUUID ||
      !v.targetAddress || !v.survivorContainerUUIDs[0] || !v.survivorContainerUUIDs[1] ||
      !v.survivorAddresses[0] || !v.survivorAddresses[1] ||
      v.targetContainerUUID == v.survivorContainerUUIDs[0] || v.targetContainerUUID == v.survivorContainerUUIDs[1] ||
      v.survivorContainerUUIDs[0] == v.survivorContainerUUIDs[1] || v.targetAddress == v.survivorAddresses[0] ||
      v.targetAddress == v.survivorAddresses[1] || v.survivorAddresses[0] == v.survivorAddresses[1] ||
      (!v.response && (v.ready || v.isolated || !v.failure.empty())) ||
      (v.ready && (!v.response || !v.failure.empty()))) return false;
  return !v.isolated || (v.response && v.ready && (v.stage == ProdigyNametagQualificationWriterIsolationStage::isolate ||
                                                   v.stage == ProdigyNametagQualificationWriterIsolationStage::query));
}
static inline bool prodigyNametagQualificationWriterIsolationResponseMatches(
    const ProdigyNametagQualificationWriterIsolation& request, const ProdigyNametagQualificationWriterIsolation& response) {
  if (request.response || !response.response || !prodigyNametagQualificationWriterIsolationValid(request) ||
      !prodigyNametagQualificationWriterIsolationValid(response)) return false;
  auto left = request, right = response; right.response = right.ready = right.isolated = false; right.failure.clear();
  String a = {}, b = {};
  return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
}

static inline bool prodigyNametagQualificationWriterIsolationInitialArmValid(
    const ProdigyNametagQualificationWriterIsolation& request) {
  if (request.response || request.stage != ProdigyNametagQualificationWriterIsolationStage::arm ||
      request.challengeUUID || request.targetContainerUUID || request.targetMachineUUID || request.targetAddress ||
      request.survivorContainerUUIDs[0] || request.survivorContainerUUIDs[1] ||
      request.survivorAddresses[0] || request.survivorAddresses[1]) return false;
  auto populated = request; populated.challengeUUID = 1; populated.targetContainerUUID = 2;
  populated.targetMachineUUID = 3; populated.targetAddress = 4;
  populated.survivorContainerUUIDs = {5, 6}; populated.survivorAddresses = {7, 8};
  return prodigyNametagQualificationWriterIsolationValid(populated);
}

enum class ProdigyNametagQualificationRestartStage : uint8_t { none = 0, beforeRestart = 1, afterRestart = 2 };
enum class ProdigyNametagQualificationWriterStage : uint8_t { none = 0, arm = 1, survivorWrites = 2, final = 3 };

enum class ProdigyNametagQualificationPathStage : uint8_t {
  none = 0, localWork = 1, partitionRead = 2, final = 3
};
static inline bool prodigyNametagQualificationPathRow(uint8_t row) {
  return row == uint8_t(ProdigyNametagQualificationRow::sitePartitionLocalWrites) ||
      row == uint8_t(ProdigyNametagQualificationRow::masqueSessionLossBgpRecovery) ||
      row == uint8_t(ProdigyNametagQualificationRow::ewrOrdPathLoss);
}
static inline bool prodigyNametagQualificationPathStageValid(
    uint8_t row, uint8_t direction, ProdigyNametagQualificationPathStage stage, uint8_t batch,
    int64_t expiresAt, int64_t startedAt, int64_t convergenceDeadline) {
  return prodigyNametagQualificationPathRow(row) &&
      batch <= (row == uint8_t(ProdigyNametagQualificationRow::masqueSessionLossBgpRecovery) ? 1 : 0) &&
      expiresAt > 0 && (direction == 1 ? expiresAt > startedAt && expiresAt <= convergenceDeadline : true) &&
      ((direction == 1 && (stage == ProdigyNametagQualificationPathStage::localWork ||
                           stage == ProdigyNametagQualificationPathStage::final ||
                           (stage == ProdigyNametagQualificationPathStage::partitionRead &&
                            row == uint8_t(ProdigyNametagQualificationRow::ewrOrdPathLoss)))) ||
       (direction == 2 && stage == ProdigyNametagQualificationPathStage::final));
}

// One bounded partition runs three normal identity-domain contests.  The
// controller joins explicit application responses with native path evidence.
enum class ProdigyNametagQualificationClaimStage : uint8_t {
  none = 0, prepare = 1, arm = 2, contend = 3, settle = 4, final = 5
};
struct ProdigyNametagQualificationClaimResult {
  bool observed = false, accepted = false;
};
template <typename S> static void serialize(S&& s, ProdigyNametagQualificationClaimResult& v) {
  s.value1b(v.observed); s.value1b(v.accepted);
}
static inline bool prodigyNametagQualificationClaimStageValid(
    uint8_t row, uint8_t direction, ProdigyNametagQualificationClaimStage stage,
    int64_t expiresAt, int64_t startedAt, int64_t convergenceDeadline) {
  if (row != uint8_t(ProdigyNametagQualificationRow::truthClaimPartition) ||
      stage < ProdigyNametagQualificationClaimStage::prepare ||
      stage > ProdigyNametagQualificationClaimStage::final ||
      (direction != 1 && direction != 2) ||
      (direction == 2 && stage != ProdigyNametagQualificationClaimStage::final)) return false;
  if (stage == ProdigyNametagQualificationClaimStage::prepare ||
      stage == ProdigyNametagQualificationClaimStage::arm) return expiresAt == 0;
  return expiresAt > 0 && (direction == 2 ||
      (expiresAt > startedAt && expiresAt <= convergenceDeadline));
}

enum class ProdigyNametagQualificationReplayWorkStage : uint8_t { none = 0, prepare = 1, workload = 2, final = 3 };

static constexpr bool prodigyNametagQualificationSeedReadbackRow(uint8_t row) {
  return row == uint8_t(ProdigyNametagQualificationRow::seedInterruptionResume) ||
      row == uint8_t(ProdigyNametagQualificationRow::brainHardRebootCatchup);
}

class ProdigyNametagQualificationApplicationReceipt {
public:
  // v5 replaces broad pass flags with a typed witness and participant role.
  static constexpr uint32_t version = 5;
  static constexpr uint32_t cousinStageVersion = 6;
  static constexpr uint32_t restartStageVersion = 7;
  static constexpr uint32_t replayStageVersion = 8;
  static constexpr uint32_t pathStageVersion = 9;
  static constexpr uint32_t writerStageVersion = 10;
  static constexpr uint32_t claimStageVersion = 12;
  static constexpr uint32_t seedReadbackVersion = 13;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0;
  uint8_t row = 0;
  uint8_t direction = 0;
  uint64_t executionGeneration = 0;
  String rowID;
  ProdigyNametagQualificationDescriptor descriptor;
  uint128_t localClusterUUID = 0;
  uint64_t deploymentID = 0;
  uint128_t localContainerUUID = 0;
  int64_t startedAtMilliseconds = 0;
  int64_t deadlineAtMilliseconds = 0;
  int64_t convergenceDeadlineAtMilliseconds = 0;
  int64_t observedAtMilliseconds = 0;
  ProdigyNametagQualificationWitness witnessedResult =
      ProdigyNametagQualificationWitness::orderedUserKeyDigest;
  ProdigyNametagQualificationParticipantRole participantRole =
      ProdigyNametagQualificationParticipantRole::none;
  // Optional for rows other than sixteen.  Row sixteen's global join requires
  // the EWR fence and both observers to report this exact post-state digest.
  String joinedWitnessDigest;
  String canonicalWitnessReceipt;
  String witnessDigest;
  ProdigyNametagQualificationCousinStage cousinStage = ProdigyNametagQualificationCousinStage::none;
  Vector<ProdigyNametagQualificationCousinSession> cousinSessions;
  ProdigyNametagQualificationRestartStage restartStage = ProdigyNametagQualificationRestartStage::none;
  ProdigyNametagQualificationReplayWorkStage replayStage = ProdigyNametagQualificationReplayWorkStage::none;
  ProdigyNametagQualificationPathStage pathStage = ProdigyNametagQualificationPathStage::none;
  uint8_t pathBatch = 0;
  int64_t pathFaultExpiresAtMilliseconds = 0;
  ProdigyNametagQualificationWriterStage writerStage = ProdigyNametagQualificationWriterStage::none;
  uint128_t writerChallengeUUID = 0;
  ProdigyNametagQualificationClaimStage claimStage = ProdigyNametagQualificationClaimStage::none;
  int64_t claimFaultExpiresAtMilliseconds = 0;
  std::array<ProdigyNametagQualificationClaimResult, 3> claimResults = {};
  std::array<uint128_t, 3> claimWinnerSites = {};
  String seedControlWitnessDigest, seedBaselineReadbackSHA256;
  // Compatibility-only in-memory fields for the not-yet-migrated execution
  // owner. They are deliberately outside v5 serialization and validation, so
  // an old broad-pass payload cannot become a qualification receipt.
  String canonicalApplicationReceipt, canonicalDataDigest, hotDigest, coldDigest, radarDigest, pulseDigest;
  String truthDigest, conflictWinnerDigest;
  uint128_t conflictWinnerClusterUUID = 0;
  bool perUserIsolation = false, sessionFence = false, truthClaimUniqueness = false;
  bool radarMutationAccepted = false, pulseMutationAccepted = false, pass = false;
};

template <typename S>
static void serialize(S&& serializer, ProdigyNametagQualificationApplicationReceipt& receipt)
{
  serializer.value4b(receipt.protocolVersion); serializer.value16b(receipt.runUUID);
  serializer.value1b(receipt.row); serializer.value1b(receipt.direction); serializer.value8b(receipt.executionGeneration);
  serializer.text1b(receipt.rowID, 128); serializer.object(receipt.descriptor);
  serializer.value16b(receipt.localClusterUUID); serializer.value8b(receipt.deploymentID);
  serializer.value16b(receipt.localContainerUUID); serializer.value8b(receipt.startedAtMilliseconds);
  serializer.value8b(receipt.deadlineAtMilliseconds); serializer.value8b(receipt.convergenceDeadlineAtMilliseconds);
  serializer.value8b(receipt.observedAtMilliseconds); serializer.value1b(receipt.witnessedResult);
  serializer.value1b(receipt.participantRole); serializer.text1b(receipt.joinedWitnessDigest, 64);
  serializer.text1b(receipt.canonicalWitnessReceipt, 8192); serializer.text1b(receipt.witnessDigest, 64);
  if (receipt.protocolVersion >= 6) { serializer.value1b(receipt.cousinStage); serializer.container(receipt.cousinSessions, 2); }
  if (receipt.protocolVersion >= 7) serializer.value1b(receipt.restartStage);
  if (receipt.protocolVersion >= 8) serializer.value1b(receipt.replayStage);
  if (receipt.protocolVersion >= 9) { serializer.value1b(receipt.pathStage); serializer.value1b(receipt.pathBatch);
    serializer.value8b(receipt.pathFaultExpiresAtMilliseconds); }
  if (receipt.protocolVersion >= 10) { serializer.value1b(receipt.writerStage); serializer.value16b(receipt.writerChallengeUUID); }
  if (receipt.protocolVersion >= 12) {
    serializer.value1b(receipt.claimStage); serializer.value8b(receipt.claimFaultExpiresAtMilliseconds);
    for (auto& site : receipt.claimWinnerSites) serializer.value16b(site);
    for (auto& result : receipt.claimResults) serializer.object(result);
  }
  if (receipt.protocolVersion >= 13) {
    serializer.text1b(receipt.seedControlWitnessDigest, 64); serializer.text1b(receipt.seedBaselineReadbackSHA256, 64);
  }
}

static inline bool prodigyNametagQualificationApplicationReceiptValid(
    const ProdigyNametagQualificationApplicationReceipt& receipt)
{
  const bool cousinRow = receipt.row == uint8_t(ProdigyNametagQualificationRow::permissionRevokeReinstall) ||
      receipt.row == uint8_t(ProdigyNametagQualificationRow::cousinRouteSessionReconnect);
  const bool cousinProof = receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::cousinStageVersion &&
      cousinRow && (receipt.cousinStage == ProdigyNametagQualificationCousinStage::faultObserved ||
                    receipt.cousinStage == ProdigyNametagQualificationCousinStage::final) &&
      receipt.cousinSessions.empty() && prodigyIsSHA256HexDigest(receipt.joinedWitnessDigest);
  const bool restartProof = receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::restartStageVersion &&
      receipt.row == uint8_t(ProdigyNametagQualificationRow::mothershipRestartResume) &&
      (receipt.restartStage == ProdigyNametagQualificationRestartStage::beforeRestart ||
       receipt.restartStage == ProdigyNametagQualificationRestartStage::afterRestart) &&
      receipt.cousinStage == ProdigyNametagQualificationCousinStage::none && receipt.cousinSessions.empty() &&
      prodigyIsSHA256HexDigest(receipt.joinedWitnessDigest) &&
      (receipt.direction == 1 || receipt.restartStage == ProdigyNametagQualificationRestartStage::afterRestart);
  const bool pathProof = receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::pathStageVersion &&
      receipt.cousinStage == ProdigyNametagQualificationCousinStage::none && receipt.cousinSessions.empty() &&
      receipt.restartStage == ProdigyNametagQualificationRestartStage::none &&
      prodigyIsSHA256HexDigest(receipt.joinedWitnessDigest) &&
      prodigyNametagQualificationPathStageValid(receipt.row, receipt.direction, receipt.pathStage, receipt.pathBatch,
          receipt.pathFaultExpiresAtMilliseconds, receipt.startedAtMilliseconds, receipt.convergenceDeadlineAtMilliseconds) &&
      (receipt.pathStage == ProdigyNametagQualificationPathStage::final ||
       receipt.observedAtMilliseconds < receipt.pathFaultExpiresAtMilliseconds);
  const bool writerProof = receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::writerStageVersion &&
      receipt.row == uint8_t(ProdigyNametagQualificationRow::localWriterIsolation) && receipt.writerChallengeUUID &&
      receipt.writerStage >= ProdigyNametagQualificationWriterStage::arm &&
      receipt.writerStage <= ProdigyNametagQualificationWriterStage::final &&
      (receipt.direction == 1 || receipt.writerStage == ProdigyNametagQualificationWriterStage::final) &&
      receipt.cousinStage == ProdigyNametagQualificationCousinStage::none && receipt.cousinSessions.empty() &&
      receipt.restartStage == ProdigyNametagQualificationRestartStage::none &&
      receipt.pathStage == ProdigyNametagQualificationPathStage::none && receipt.pathBatch == 0 &&
      !receipt.pathFaultExpiresAtMilliseconds && prodigyIsSHA256HexDigest(receipt.joinedWitnessDigest);
  const bool replayProof = receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::replayStageVersion &&
      receipt.row == uint8_t(ProdigyNametagQualificationRow::graphKvReplayReorder) &&
      (receipt.replayStage == ProdigyNametagQualificationReplayWorkStage::workload ||
       receipt.replayStage == ProdigyNametagQualificationReplayWorkStage::final) &&
      (receipt.direction == 1 || receipt.replayStage == ProdigyNametagQualificationReplayWorkStage::final) &&
      receipt.cousinStage == ProdigyNametagQualificationCousinStage::none && receipt.cousinSessions.empty() &&
      receipt.restartStage == ProdigyNametagQualificationRestartStage::none &&
      receipt.pathStage == ProdigyNametagQualificationPathStage::none && !receipt.pathBatch && !receipt.pathFaultExpiresAtMilliseconds &&
      receipt.writerStage == ProdigyNametagQualificationWriterStage::none && !receipt.writerChallengeUUID &&
      prodigyIsSHA256HexDigest(receipt.joinedWitnessDigest);
  const bool claimProof = receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::claimStageVersion &&
      prodigyNametagQualificationClaimStageValid(receipt.row, receipt.direction, receipt.claimStage,
          receipt.claimFaultExpiresAtMilliseconds, receipt.startedAtMilliseconds, receipt.convergenceDeadlineAtMilliseconds) &&
      std::all_of(receipt.claimWinnerSites.begin(), receipt.claimWinnerSites.end(), [&](uint128_t site) {
        return receipt.claimStage >= ProdigyNametagQualificationClaimStage::settle ? site != 0 : site == 0;
      }) && prodigyIsSHA256HexDigest(receipt.joinedWitnessDigest) &&
      (receipt.claimStage != ProdigyNametagQualificationClaimStage::contend ||
       receipt.observedAtMilliseconds < receipt.claimFaultExpiresAtMilliseconds) &&
      std::all_of(receipt.claimResults.begin(), receipt.claimResults.end(), [&](const auto& result) {
        return receipt.claimStage == ProdigyNametagQualificationClaimStage::contend ?
            (!result.accepted || result.observed) : (!result.accepted && !result.observed);
      });
  const bool seedReadbackProof = receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::seedReadbackVersion &&
      prodigyNametagQualificationSeedReadbackRow(receipt.row) &&
      prodigyIsSHA256HexDigest(receipt.seedControlWitnessDigest) &&
      prodigyIsSHA256HexDigest(receipt.seedBaselineReadbackSHA256) && prodigyIsSHA256HexDigest(receipt.joinedWitnessDigest);
  const bool knownVersion = receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::version || cousinProof || restartProof ||
      replayProof || pathProof || writerProof || claimProof || seedReadbackProof;
  // Each extension has one wire owner.  A valid version cannot smuggle fields
  // belonging to a different experiment through the common envelope.
  const bool extensionsValid =
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::seedReadbackVersion ||
       (receipt.seedControlWitnessDigest.empty() && receipt.seedBaselineReadbackSHA256.empty())) &&
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::cousinStageVersion ||
       (receipt.cousinStage == ProdigyNametagQualificationCousinStage::none && receipt.cousinSessions.empty())) &&
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::restartStageVersion ||
       receipt.restartStage == ProdigyNametagQualificationRestartStage::none) &&
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::replayStageVersion ||
       receipt.replayStage == ProdigyNametagQualificationReplayWorkStage::none) &&
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::pathStageVersion ||
       (receipt.pathStage == ProdigyNametagQualificationPathStage::none && !receipt.pathBatch && !receipt.pathFaultExpiresAtMilliseconds)) &&
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::writerStageVersion ||
       receipt.writerStage == ProdigyNametagQualificationWriterStage::none) &&
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::claimStageVersion ||
       (receipt.claimStage == ProdigyNametagQualificationClaimStage::none && !receipt.claimFaultExpiresAtMilliseconds &&
        std::all_of(receipt.claimWinnerSites.begin(), receipt.claimWinnerSites.end(), [](uint128_t site) { return site == 0; }))) &&
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::writerStageVersion || !receipt.writerChallengeUUID) &&
      (receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::claimStageVersion ||
       std::all_of(receipt.claimResults.begin(), receipt.claimResults.end(), [](const auto& result) {
         return !result.observed && !result.accepted;
       }));
  return knownVersion && extensionsValid &&
      (!prodigyNametagQualificationSeedReadbackRow(receipt.row) || seedReadbackProof) &&
      (receipt.row != uint8_t(ProdigyNametagQualificationRow::truthClaimPartition) ||
       receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::claimStageVersion) &&
      receipt.runUUID != 0 && receipt.row >= 1 && receipt.row <= 17 && receipt.executionGeneration != 0 &&
      (receipt.direction == 1 || receipt.direction == 2) && !receipt.rowID.empty() && receipt.rowID.size() <= 128 &&
      receipt.localClusterUUID != 0 && receipt.deploymentID != 0 && receipt.localContainerUUID != 0 &&
      receipt.startedAtMilliseconds > 0 && receipt.deadlineAtMilliseconds > receipt.startedAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds >= receipt.startedAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds <= receipt.deadlineAtMilliseconds &&
      receipt.observedAtMilliseconds >= receipt.startedAtMilliseconds &&
      receipt.observedAtMilliseconds <= receipt.convergenceDeadlineAtMilliseconds &&
      prodigyNametagQualificationDescriptorValid(receipt.descriptor) &&
      prodigyNametagQualificationRowDescriptorValid(receipt.row, receipt.descriptor) &&
      receipt.witnessedResult == receipt.descriptor.expectedWitness &&
      uint8_t(receipt.participantRole) <= uint8_t(ProdigyNametagQualificationParticipantRole::truthObserver) &&
      (receipt.joinedWitnessDigest.empty() || prodigyIsSHA256HexDigest(receipt.joinedWitnessDigest)) &&
      !receipt.canonicalWitnessReceipt.empty() && receipt.canonicalWitnessReceipt.size() <= 8192 &&
      prodigyIsSHA256HexDigest(receipt.witnessDigest);
}

class ProdigyNametagQualificationApp6Route {
public:
  uint128_t clusterUUID = 0, containerUUID = 0;
  uint64_t deploymentID = 0;
  uint8_t ipv6[16] = {};
  uint16_t port = 0;
  Vector<String> cids;
  String cidFixtureSHA256;
};
template <typename S>
static void serialize(S&& s, ProdigyNametagQualificationApp6Route& v) {
  s.value16b(v.clusterUUID); s.value8b(v.deploymentID); s.value16b(v.containerUUID);
  for (auto& byte : v.ipv6) s.value1b(byte);
  s.value2b(v.port); s.container(v.cids, 16, [](auto& nested, String& cid) { nested.text1b(cid, 20); });
  s.text1b(v.cidFixtureSHA256, 64);
}
static inline bool prodigyNametagQualificationApp6RoutesValid(const Vector<ProdigyNametagQualificationApp6Route>& routes) {
  if (routes.size() != 2 || routes[0].clusterUUID == routes[1].clusterUUID ||
      routes[0].containerUUID == routes[1].containerUUID ||
      (memcmp(routes[0].ipv6, routes[1].ipv6, 16) == 0 && routes[0].port == routes[1].port)) return false;
  for (size_t i = 0; i < routes.size(); ++i) {
    const auto& r = routes[i];
    if (!r.clusterUUID || !r.containerUUID || ApplicationConfig::extractApplicationID(r.deploymentID) != 6 ||
        !r.port || std::all_of(std::begin(r.ipv6), std::end(r.ipv6), [](uint8_t b) { return b == 0; }) ||
        r.cids.size() < 2 || r.cids.size() > 16 || !prodigyIsSHA256HexDigest(r.cidFixtureSHA256)) return false;
    for (size_t j = 0; j < r.cids.size(); ++j) {
      if (r.cids[j].empty() || r.cids[j].size() > 20) return false;
      for (size_t k = 0; k <= i; ++k)
        for (size_t n = 0; n < (k == i ? j : routes[k].cids.size()); ++n)
          if (r.cids[j] == routes[k].cids[n]) return false;
    }
  }
  return true;
}

// Brain sends this bounded command to the exact live App11 probe container.
// Runtime environment variables cannot represent 34 independently durable
// operations on one persistent deployment, so every execution is explicitly
// fenced by the immutable qualification tuple and its absolute time bounds.
class ProdigyNametagQualificationApplicationCommand {
public:
  // v4 binds row sixteen observation to one already-persisted injection
  // receipt. The binding is deliberately absent for every other command.
  // App11 must not infer
  // membership from its local environment or from a partial receipt set.
  static constexpr uint32_t version = 5;
  static constexpr uint32_t cousinStageVersion = 6;
  static constexpr uint32_t restartStageVersion = 7;
  static constexpr uint32_t replayStageVersion = 8;
  static constexpr uint32_t pathStageVersion = 9;
  static constexpr uint32_t writerStageVersion = 10;
  static constexpr uint32_t claimStageVersion = 12;
  static constexpr uint32_t seedReadbackVersion = 13;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0;
  uint8_t row = 0;
  uint8_t direction = 0;
  uint64_t executionGeneration = 0;
  String rowID;
  ProdigyNametagQualificationDescriptor descriptor;
  uint128_t localClusterUUID = 0;
  Vector<uint128_t> canonicalClusterUUIDs;
  uint64_t deploymentID = 0;
  int64_t startedAtMilliseconds = 0;
  int64_t deadlineAtMilliseconds = 0;
  int64_t convergenceDeadlineAtMilliseconds = 0;
  uint128_t priorInjectionRunUUID = 0;
  String priorInjectionReceiptDigest;
  Vector<ProdigyNametagQualificationApp6Route> app6Routes;
  ProdigyNametagQualificationCousinStage cousinStage = ProdigyNametagQualificationCousinStage::none;
  Vector<ProdigyNametagQualificationCousinSession> cousinSessions;
  ProdigyNametagQualificationRestartStage restartStage = ProdigyNametagQualificationRestartStage::none;
  ProdigyNametagQualificationReplayWorkStage replayStage = ProdigyNametagQualificationReplayWorkStage::none;
  Vector<ProdigyNametagQualificationReplay> replaySources;
  ProdigyNametagQualificationPathStage pathStage = ProdigyNametagQualificationPathStage::none;
  uint8_t pathBatch = 0;
  int64_t pathFaultExpiresAtMilliseconds = 0;
  ProdigyNametagQualificationWriterStage writerStage = ProdigyNametagQualificationWriterStage::none;
  ProdigyNametagQualificationWriterIsolation writerIsolation = {};
  ProdigyNametagQualificationClaimStage claimStage = ProdigyNametagQualificationClaimStage::none;
  int64_t claimFaultExpiresAtMilliseconds = 0;
  std::array<uint128_t, 3> claimWinnerSites = {};
  // Readback names the existing immutable baseline. The control digest is
  // supplied and verified by Mothership; App11 only verifies the data.
  uint128_t seedBaselineOperationUUID = 0;
  std::array<uint64_t, 5> seedStoreDeploymentIDs = {}; // Hot, Cold, Radar, Pulse, Truth.
  String seedControlWitnessDigest, seedBaselineFixtureSHA256, seedBaselineReadbackSHA256;
};

template <typename S>
static void serialize(S&& serializer, ProdigyNametagQualificationApplicationCommand& command)
{
  serializer.value4b(command.protocolVersion); serializer.value16b(command.runUUID);
  serializer.value1b(command.row); serializer.value1b(command.direction); serializer.value8b(command.executionGeneration);
  serializer.text1b(command.rowID, 128); serializer.object(command.descriptor);
  serializer.value16b(command.localClusterUUID); serializer.value8b(command.deploymentID);
  serializer.value8b(command.startedAtMilliseconds); serializer.value8b(command.deadlineAtMilliseconds);
  serializer.value8b(command.convergenceDeadlineAtMilliseconds);
  serializer.container(command.canonicalClusterUUIDs, 3,
      [](auto& nested, uint128_t& clusterUUID) { nested.value16b(clusterUUID); });
  if (command.protocolVersion >= 4) {
    serializer.value16b(command.priorInjectionRunUUID);
    serializer.text1b(command.priorInjectionReceiptDigest, 64);
  }
  if (command.protocolVersion >= 5) serializer.container(command.app6Routes, 2);
  if (command.protocolVersion >= 6) { serializer.value1b(command.cousinStage); serializer.container(command.cousinSessions, 2); }
  if (command.protocolVersion >= 7) serializer.value1b(command.restartStage);
  if (command.protocolVersion >= 8) { serializer.value1b(command.replayStage); serializer.container(command.replaySources, 2); }
  if (command.protocolVersion >= 9) { serializer.value1b(command.pathStage); serializer.value1b(command.pathBatch);
    serializer.value8b(command.pathFaultExpiresAtMilliseconds); }
  if (command.protocolVersion >= 10) { serializer.value1b(command.writerStage); serializer.object(command.writerIsolation); }
  if (command.protocolVersion >= 12) {
    serializer.value1b(command.claimStage); serializer.value8b(command.claimFaultExpiresAtMilliseconds);
    for (auto& site : command.claimWinnerSites) serializer.value16b(site);
  }
  if (command.protocolVersion >= 13) {
    serializer.value16b(command.seedBaselineOperationUUID);
    for (auto& deployment : command.seedStoreDeploymentIDs) serializer.value8b(deployment);
    serializer.text1b(command.seedControlWitnessDigest, 64);
    serializer.text1b(command.seedBaselineFixtureSHA256, 64); serializer.text1b(command.seedBaselineReadbackSHA256, 64);
  }
}

static inline bool prodigyNametagQualificationApplicationCommandValid(
    const ProdigyNametagQualificationApplicationCommand& command)
{
  const bool cousinRow = command.row == uint8_t(ProdigyNametagQualificationRow::permissionRevokeReinstall) ||
      command.row == uint8_t(ProdigyNametagQualificationRow::cousinRouteSessionReconnect);
  const bool cousinCommand = command.protocolVersion == ProdigyNametagQualificationApplicationCommand::cousinStageVersion &&
      cousinRow && command.canonicalClusterUUIDs.size() == 3 &&
      ((command.direction == 1 && (command.cousinStage == ProdigyNametagQualificationCousinStage::faultObserved ||
                                    command.cousinStage == ProdigyNametagQualificationCousinStage::final)) ||
       (command.direction == 2 && command.cousinStage == ProdigyNametagQualificationCousinStage::final)) && command.cousinSessions.empty();
  const bool restartCommand = command.protocolVersion == ProdigyNametagQualificationApplicationCommand::restartStageVersion &&
      command.row == uint8_t(ProdigyNametagQualificationRow::mothershipRestartResume) &&
      command.cousinStage == ProdigyNametagQualificationCousinStage::none && command.cousinSessions.empty() &&
      ((command.direction == 1 && (command.restartStage == ProdigyNametagQualificationRestartStage::beforeRestart ||
                                    command.restartStage == ProdigyNametagQualificationRestartStage::afterRestart)) ||
       (command.direction == 2 && command.restartStage == ProdigyNametagQualificationRestartStage::afterRestart));
  const bool pathCommand = command.protocolVersion == ProdigyNametagQualificationApplicationCommand::pathStageVersion &&
      command.cousinStage == ProdigyNametagQualificationCousinStage::none && command.cousinSessions.empty() &&
      command.restartStage == ProdigyNametagQualificationRestartStage::none &&
      prodigyNametagQualificationPathStageValid(command.row, command.direction, command.pathStage, command.pathBatch,
          command.pathFaultExpiresAtMilliseconds, command.startedAtMilliseconds, command.convergenceDeadlineAtMilliseconds);
  const bool writerCommand = command.protocolVersion == ProdigyNametagQualificationApplicationCommand::writerStageVersion &&
      command.row == uint8_t(ProdigyNametagQualificationRow::localWriterIsolation) &&
      command.writerStage >= ProdigyNametagQualificationWriterStage::arm &&
      command.writerStage <= ProdigyNametagQualificationWriterStage::final &&
      (command.direction == 1 || command.writerStage == ProdigyNametagQualificationWriterStage::final) &&
      command.cousinStage == ProdigyNametagQualificationCousinStage::none && command.cousinSessions.empty() &&
      command.restartStage == ProdigyNametagQualificationRestartStage::none &&
      command.pathStage == ProdigyNametagQualificationPathStage::none && command.pathBatch == 0 &&
      !command.pathFaultExpiresAtMilliseconds && prodigyNametagQualificationWriterIsolationValid(command.writerIsolation) &&
      !command.writerIsolation.response && command.writerIsolation.stage == ProdigyNametagQualificationWriterIsolationStage::arm &&
      command.writerIsolation.runUUID == command.runUUID &&
      (command.writerStage == ProdigyNametagQualificationWriterStage::final ||
       command.writerIsolation.clusterUUID == command.localClusterUUID) &&
      (command.direction == 2 || (command.writerIsolation.executionGeneration == command.executionGeneration &&
       command.writerIsolation.deadlineAtMilliseconds == command.deadlineAtMilliseconds));
  const bool replayCommand = command.protocolVersion == ProdigyNametagQualificationApplicationCommand::replayStageVersion &&
      command.row == uint8_t(ProdigyNametagQualificationRow::graphKvReplayReorder) &&
      (command.replayStage == ProdigyNametagQualificationReplayWorkStage::prepare ||
       command.replayStage == ProdigyNametagQualificationReplayWorkStage::workload ||
       command.replayStage == ProdigyNametagQualificationReplayWorkStage::final) &&
      (command.direction == 1 || command.replayStage == ProdigyNametagQualificationReplayWorkStage::final) &&
      command.cousinStage == ProdigyNametagQualificationCousinStage::none && command.cousinSessions.empty() &&
      command.restartStage == ProdigyNametagQualificationRestartStage::none &&
      command.pathStage == ProdigyNametagQualificationPathStage::none && !command.pathBatch && !command.pathFaultExpiresAtMilliseconds &&
      command.writerStage == ProdigyNametagQualificationWriterStage::none &&
      (command.replayStage != ProdigyNametagQualificationReplayWorkStage::workload ? command.replaySources.empty() :
       (command.replaySources.size() == 2 &&
        command.replaySources[0].store == ProdigyNametagQualificationReplayStore::kv &&
        command.replaySources[1].store == ProdigyNametagQualificationReplayStore::graph &&
        command.replaySources[0].challengeUUID != command.replaySources[1].challengeUUID &&
        std::all_of(command.replaySources.begin(), command.replaySources.end(), [&](const auto& source) {
          return prodigyNametagQualificationReplayValid(source) && !source.response && !source.targetSide &&
              source.stage == ProdigyNametagQualificationReplayStage::arm && source.runUUID == command.runUUID &&
              source.executionGeneration == command.executionGeneration && source.direction == command.direction &&
              source.deadlineAtMilliseconds > command.startedAtMilliseconds &&
              source.deadlineAtMilliseconds <= command.deadlineAtMilliseconds &&
              (prodigyNametagQualificationReplayLocalHalf(source.store, false) == CousinRouteHalf::source ?
               source.session.sourceClusterUUID : source.session.destinationClusterUUID) == command.localClusterUUID;
        })));
  const bool claimCommand = command.protocolVersion == ProdigyNametagQualificationApplicationCommand::claimStageVersion &&
      prodigyNametagQualificationClaimStageValid(command.row, command.direction, command.claimStage,
          command.claimFaultExpiresAtMilliseconds, command.startedAtMilliseconds, command.convergenceDeadlineAtMilliseconds) &&
      std::all_of(command.claimWinnerSites.begin(), command.claimWinnerSites.end(), [&](uint128_t site) {
        return command.claimStage >= ProdigyNametagQualificationClaimStage::settle ? site != 0 : site == 0;
      }) && (command.claimStage < ProdigyNametagQualificationClaimStage::settle ||
      std::all_of(command.claimWinnerSites.begin(), command.claimWinnerSites.end(), [&](uint128_t site) {
        return std::count(command.canonicalClusterUUIDs.begin(), command.canonicalClusterUUIDs.end(), site) == 1;
      }));
  const bool seedReadbackCommand = command.protocolVersion == ProdigyNametagQualificationApplicationCommand::seedReadbackVersion &&
      prodigyNametagQualificationSeedReadbackRow(command.row) && command.seedBaselineOperationUUID &&
      prodigyIsSHA256HexDigest(command.seedControlWitnessDigest) && prodigyIsSHA256HexDigest(command.seedBaselineFixtureSHA256) &&
      prodigyIsSHA256HexDigest(command.seedBaselineReadbackSHA256) &&
      ApplicationConfig::extractApplicationID(command.seedStoreDeploymentIDs[0]) == MeshRegistry::Hot::applicationID &&
      ApplicationConfig::extractApplicationID(command.seedStoreDeploymentIDs[1]) == MeshRegistry::Cold::applicationID &&
      ApplicationConfig::extractApplicationID(command.seedStoreDeploymentIDs[2]) == MeshRegistry::Radar::applicationID &&
      ApplicationConfig::extractApplicationID(command.seedStoreDeploymentIDs[3]) == MeshRegistry::Pulse::applicationID &&
      ApplicationConfig::extractApplicationID(command.seedStoreDeploymentIDs[4]) == MeshRegistry::Truth::applicationID;
  const bool knownVersion = (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::version || command.protocolVersion == 4) || cousinCommand || restartCommand ||
      replayCommand || pathCommand || writerCommand || claimCommand || seedReadbackCommand;
  // Each extension has one wire owner.  A valid version cannot smuggle fields
  // belonging to a different experiment through the common envelope.
  const bool extensionsValid =
      (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::seedReadbackVersion ||
       (!command.seedBaselineOperationUUID && command.seedControlWitnessDigest.empty() &&
        command.seedBaselineFixtureSHA256.empty() && command.seedBaselineReadbackSHA256.empty() &&
        std::all_of(command.seedStoreDeploymentIDs.begin(), command.seedStoreDeploymentIDs.end(), [](uint64_t id) { return id == 0; }))) &&
      (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::cousinStageVersion ||
       (command.cousinStage == ProdigyNametagQualificationCousinStage::none && command.cousinSessions.empty())) &&
      (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::restartStageVersion ||
       command.restartStage == ProdigyNametagQualificationRestartStage::none) &&
      (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::replayStageVersion ||
       command.replayStage == ProdigyNametagQualificationReplayWorkStage::none) &&
      (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::pathStageVersion ||
       (command.pathStage == ProdigyNametagQualificationPathStage::none && !command.pathBatch && !command.pathFaultExpiresAtMilliseconds)) &&
      (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::writerStageVersion ||
       command.writerStage == ProdigyNametagQualificationWriterStage::none) &&
      (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::claimStageVersion ||
       (command.claimStage == ProdigyNametagQualificationClaimStage::none && !command.claimFaultExpiresAtMilliseconds &&
        std::all_of(command.claimWinnerSites.begin(), command.claimWinnerSites.end(), [](uint128_t site) { return site == 0; })));
  return knownVersion && extensionsValid &&
      (!prodigyNametagQualificationSeedReadbackRow(command.row) || seedReadbackCommand) &&
      (command.row != uint8_t(ProdigyNametagQualificationRow::truthClaimPartition) ||
       command.protocolVersion == ProdigyNametagQualificationApplicationCommand::claimStageVersion) &&
      (command.protocolVersion == ProdigyNametagQualificationApplicationCommand::replayStageVersion || command.replaySources.empty()) &&
      command.runUUID != 0 && command.row >= 1 && command.row <= 17 && command.executionGeneration != 0 &&
      (command.direction == 1 || command.direction == 2) && !command.rowID.empty() && command.rowID.size() <= 128 &&
      prodigyNametagQualificationDescriptorValid(command.descriptor) &&
      prodigyNametagQualificationRowDescriptorValid(command.row, command.descriptor) &&
      command.localClusterUUID != 0 &&
      command.canonicalClusterUUIDs.size() == 3 && command.deploymentID != 0 &&
      ApplicationConfig::extractApplicationID(command.deploymentID) == 11 &&
      command.startedAtMilliseconds > 0 && command.deadlineAtMilliseconds > command.startedAtMilliseconds &&
      command.convergenceDeadlineAtMilliseconds >= command.startedAtMilliseconds &&
      command.convergenceDeadlineAtMilliseconds <= command.deadlineAtMilliseconds &&
      std::count(command.canonicalClusterUUIDs.begin(), command.canonicalClusterUUIDs.end(),
                 command.localClusterUUID) == 1 &&
      std::all_of(command.canonicalClusterUUIDs.begin(), command.canonicalClusterUUIDs.end(),
                  [](uint128_t clusterUUID) { return clusterUUID != 0; }) &&
      command.canonicalClusterUUIDs[0] != command.canonicalClusterUUIDs[1] &&
      command.canonicalClusterUUIDs[0] != command.canonicalClusterUUIDs[2] &&
      command.canonicalClusterUUIDs[1] != command.canonicalClusterUUIDs[2] &&
      ((command.row == uint8_t(ProdigyNametagQualificationRow::secondStreamHandoffFence) ||
        command.row == uint8_t(ProdigyNametagQualificationRow::truthClaimPartition)) ?
          (command.protocolVersion >= 5 && prodigyNametagQualificationApp6RoutesValid(command.app6Routes) &&
           command.app6Routes[0].clusterUUID == command.localClusterUUID &&
           (command.row != uint8_t(ProdigyNametagQualificationRow::truthClaimPartition) || command.app6Routes[0].cids.size() >= 6) &&
           std::count(command.canonicalClusterUUIDs.begin(), command.canonicalClusterUUIDs.end(), command.app6Routes[0].clusterUUID) == 1 &&
           std::count(command.canonicalClusterUUIDs.begin(), command.canonicalClusterUUIDs.end(), command.app6Routes[1].clusterUUID) == 1) :
          command.app6Routes.empty()) &&
      (((command.row == uint8_t(ProdigyNametagQualificationRow::secondTruthWriterFencing) ||
         command.row == uint8_t(ProdigyNametagQualificationRow::mothershipRestartResume) || cousinRow ||
         prodigyNametagQualificationPathRow(command.row) || prodigyNametagQualificationSeedReadbackRow(command.row) ||
         command.row == uint8_t(ProdigyNametagQualificationRow::truthClaimPartition) ||
         command.row == uint8_t(ProdigyNametagQualificationRow::localWriterIsolation)) &&
        command.direction == 2) ?
          (command.priorInjectionRunUUID == command.runUUID &&
           prodigyIsSHA256HexDigest(command.priorInjectionReceiptDigest)) :
          (command.priorInjectionRunUUID == 0 && command.priorInjectionReceiptDigest.empty()));
}

// This joins a fresh five-store read to an independently persisted native
// fault witness. It is never evidence of a reboot or seed fault by itself.
static inline bool prodigyNametagQualificationSeedReadbackReceiptMatchesCommand(
    const ProdigyNametagQualificationApplicationCommand& command,
    const ProdigyNametagQualificationApplicationReceipt& receipt)
{
  return prodigyNametagQualificationApplicationCommandValid(command) &&
      command.protocolVersion == ProdigyNametagQualificationApplicationCommand::seedReadbackVersion &&
      prodigyNametagQualificationApplicationReceiptValid(receipt) &&
      receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::seedReadbackVersion &&
      receipt.runUUID == command.runUUID && receipt.row == command.row && receipt.direction == command.direction &&
      receipt.executionGeneration == command.executionGeneration && receipt.rowID == command.rowID &&
      prodigyNametagQualificationDescriptorEqual(receipt.descriptor, command.descriptor) &&
      receipt.localClusterUUID == command.localClusterUUID && receipt.deploymentID == command.deploymentID &&
      receipt.startedAtMilliseconds == command.startedAtMilliseconds && receipt.deadlineAtMilliseconds == command.deadlineAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds == command.convergenceDeadlineAtMilliseconds &&
      receipt.seedControlWitnessDigest == command.seedControlWitnessDigest &&
      receipt.seedBaselineReadbackSHA256 == command.seedBaselineReadbackSHA256;
}

// App11 reports only its own local work or convergence observation. Native
// transport evidence is authenticated and joined independently.
static inline bool prodigyNametagQualificationReplayReceiptMatchesCommand(
    const ProdigyNametagQualificationApplicationCommand& command,
    const ProdigyNametagQualificationApplicationReceipt& receipt)
{
  return prodigyNametagQualificationApplicationCommandValid(command) &&
      command.protocolVersion == ProdigyNametagQualificationApplicationCommand::replayStageVersion &&
      prodigyNametagQualificationApplicationReceiptValid(receipt) &&
      receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::replayStageVersion &&
      receipt.runUUID == command.runUUID && receipt.row == command.row && receipt.direction == command.direction &&
      receipt.executionGeneration == command.executionGeneration && receipt.rowID == command.rowID &&
      prodigyNametagQualificationDescriptorEqual(receipt.descriptor, command.descriptor) &&
      receipt.localClusterUUID == command.localClusterUUID && receipt.deploymentID == command.deploymentID &&
      receipt.startedAtMilliseconds == command.startedAtMilliseconds && receipt.deadlineAtMilliseconds == command.deadlineAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds == command.convergenceDeadlineAtMilliseconds && receipt.replayStage == command.replayStage;
}

static inline bool prodigyNametagQualificationCousinReceiptMatchesCommand(
    const ProdigyNametagQualificationApplicationCommand& command,
    const ProdigyNametagQualificationApplicationReceipt& receipt)
{
  return prodigyNametagQualificationApplicationCommandValid(command) &&
      command.protocolVersion == ProdigyNametagQualificationApplicationCommand::cousinStageVersion &&
      prodigyNametagQualificationApplicationReceiptValid(receipt) &&
      receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::cousinStageVersion &&
      receipt.runUUID == command.runUUID && receipt.row == command.row && receipt.direction == command.direction &&
      receipt.executionGeneration == command.executionGeneration && receipt.rowID == command.rowID &&
      prodigyNametagQualificationDescriptorEqual(receipt.descriptor, command.descriptor) &&
      receipt.localClusterUUID == command.localClusterUUID && receipt.deploymentID == command.deploymentID &&
      receipt.startedAtMilliseconds == command.startedAtMilliseconds && receipt.deadlineAtMilliseconds == command.deadlineAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds == command.convergenceDeadlineAtMilliseconds &&
      receipt.cousinStage == command.cousinStage && receipt.cousinSessions.empty();
}

static inline bool prodigyNametagQualificationWriterReceiptMatchesCommand(
    const ProdigyNametagQualificationApplicationCommand& command,
    const ProdigyNametagQualificationApplicationReceipt& receipt)
{
  return prodigyNametagQualificationApplicationCommandValid(command) &&
      command.protocolVersion == ProdigyNametagQualificationApplicationCommand::writerStageVersion &&
      prodigyNametagQualificationApplicationReceiptValid(receipt) &&
      receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::writerStageVersion &&
      receipt.runUUID == command.runUUID && receipt.row == command.row && receipt.direction == command.direction &&
      receipt.executionGeneration == command.executionGeneration && receipt.rowID == command.rowID &&
      prodigyNametagQualificationDescriptorEqual(receipt.descriptor, command.descriptor) &&
      receipt.localClusterUUID == command.localClusterUUID && receipt.deploymentID == command.deploymentID &&
      receipt.startedAtMilliseconds == command.startedAtMilliseconds && receipt.deadlineAtMilliseconds == command.deadlineAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds == command.convergenceDeadlineAtMilliseconds &&
      receipt.writerStage == command.writerStage && receipt.writerChallengeUUID == command.writerIsolation.challengeUUID;
}

static inline bool prodigyNametagQualificationRestartReceiptMatchesCommand(
    const ProdigyNametagQualificationApplicationCommand& command,
    const ProdigyNametagQualificationApplicationReceipt& receipt)
{
  return prodigyNametagQualificationApplicationCommandValid(command) &&
      command.protocolVersion == ProdigyNametagQualificationApplicationCommand::restartStageVersion &&
      prodigyNametagQualificationApplicationReceiptValid(receipt) &&
      receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::restartStageVersion &&
      receipt.runUUID == command.runUUID && receipt.row == command.row && receipt.direction == command.direction &&
      receipt.executionGeneration == command.executionGeneration && receipt.rowID == command.rowID &&
      prodigyNametagQualificationDescriptorEqual(receipt.descriptor, command.descriptor) &&
      receipt.localClusterUUID == command.localClusterUUID && receipt.deploymentID == command.deploymentID &&
      receipt.startedAtMilliseconds == command.startedAtMilliseconds && receipt.deadlineAtMilliseconds == command.deadlineAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds == command.convergenceDeadlineAtMilliseconds &&
      receipt.restartStage == command.restartStage && receipt.cousinSessions.empty();
}

static inline bool prodigyNametagQualificationPathReceiptMatchesCommand(
    const ProdigyNametagQualificationApplicationCommand& command,
    const ProdigyNametagQualificationApplicationReceipt& receipt)
{
  return prodigyNametagQualificationApplicationCommandValid(command) &&
      command.protocolVersion == ProdigyNametagQualificationApplicationCommand::pathStageVersion &&
      prodigyNametagQualificationApplicationReceiptValid(receipt) &&
      receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::pathStageVersion &&
      receipt.runUUID == command.runUUID && receipt.row == command.row && receipt.direction == command.direction &&
      receipt.executionGeneration == command.executionGeneration && receipt.rowID == command.rowID &&
      prodigyNametagQualificationDescriptorEqual(receipt.descriptor, command.descriptor) &&
      receipt.localClusterUUID == command.localClusterUUID && receipt.deploymentID == command.deploymentID &&
      receipt.startedAtMilliseconds == command.startedAtMilliseconds && receipt.deadlineAtMilliseconds == command.deadlineAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds == command.convergenceDeadlineAtMilliseconds &&
      receipt.pathStage == command.pathStage && receipt.pathBatch == command.pathBatch &&
      receipt.pathFaultExpiresAtMilliseconds == command.pathFaultExpiresAtMilliseconds;
}

static inline bool prodigyNametagQualificationClaimReceiptMatchesCommand(
    const ProdigyNametagQualificationApplicationCommand& command,
    const ProdigyNametagQualificationApplicationReceipt& receipt)
{
  return prodigyNametagQualificationApplicationCommandValid(command) &&
      command.protocolVersion == ProdigyNametagQualificationApplicationCommand::claimStageVersion &&
      prodigyNametagQualificationApplicationReceiptValid(receipt) &&
      receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::claimStageVersion &&
      receipt.runUUID == command.runUUID && receipt.row == command.row && receipt.direction == command.direction &&
      receipt.executionGeneration == command.executionGeneration && receipt.rowID == command.rowID &&
      prodigyNametagQualificationDescriptorEqual(receipt.descriptor, command.descriptor) &&
      receipt.localClusterUUID == command.localClusterUUID && receipt.deploymentID == command.deploymentID &&
      receipt.startedAtMilliseconds == command.startedAtMilliseconds && receipt.deadlineAtMilliseconds == command.deadlineAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds == command.convergenceDeadlineAtMilliseconds &&
      receipt.claimStage == command.claimStage && receipt.claimFaultExpiresAtMilliseconds == command.claimFaultExpiresAtMilliseconds &&
      receipt.claimWinnerSites == command.claimWinnerSites;
}

// The qualification probe and App6 exchange this bounded barrier through
// their authenticated Neuron/Brain carriers. It never carries credentials.
enum class ProdigyNametagHandoffBarrierAction : uint8_t { arm = 1, query = 2, release = 3 };
class ProdigyNametagHandoffBarrier {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyNametagHandoffBarrierAction action = ProdigyNametagHandoffBarrierAction::arm;
  bool response = false, configured = false, paused = false, notificationHeld = false, released = false;
  uint128_t runUUID = 0, nonce = 0, clusterUUID = 0;
  uint8_t direction = 0;
  uint64_t executionGeneration = 0, probeDeploymentID = 0, appDeploymentID = 0;
  uint128_t probeContainerUUID = 0, appContainerUUID = 0;
  uint64_t accountToken = 0, applicationGeneration = 0, registrationContext = 0, operationID = 0;
  uint128_t applicationInstance = 0;
  int64_t deadlineMilliseconds = 0;
};
template <typename S>
static void serialize(S&& s, ProdigyNametagHandoffBarrier& v) {
  s.value4b(v.protocolVersion); s.value1b(v.action); s.value1b(v.response);
  s.value1b(v.configured); s.value1b(v.paused); s.value1b(v.notificationHeld); s.value1b(v.released);
  s.value16b(v.runUUID); s.value16b(v.nonce); s.value16b(v.clusterUUID); s.value1b(v.direction);
  s.value8b(v.executionGeneration); s.value8b(v.probeDeploymentID); s.value8b(v.appDeploymentID);
  s.value16b(v.probeContainerUUID); s.value16b(v.appContainerUUID); s.value8b(v.accountToken);
  s.value16b(v.applicationInstance); s.value8b(v.applicationGeneration); s.value8b(v.registrationContext);
  s.value8b(v.operationID); s.value8b(v.deadlineMilliseconds);
}
static inline bool prodigyNametagHandoffBarrierValid(const ProdigyNametagHandoffBarrier& v) {
  return v.protocolVersion == ProdigyNametagHandoffBarrier::version &&
      uint8_t(v.action) >= 1 && uint8_t(v.action) <= 3 && v.runUUID && v.nonce && v.clusterUUID &&
      (v.direction == 1 || v.direction == 2) && v.executionGeneration &&
      ApplicationConfig::extractApplicationID(v.probeDeploymentID) == 11 &&
      ((v.appDeploymentID == 0 && !v.response && v.action == ProdigyNametagHandoffBarrierAction::arm) ||
       ApplicationConfig::extractApplicationID(v.appDeploymentID) == 6) &&
      v.probeContainerUUID && v.appContainerUUID && v.accountToken && v.applicationInstance &&
      v.appContainerUUID == v.applicationInstance &&
      v.applicationGeneration && v.registrationContext && v.operationID && v.deadlineMilliseconds > 0 &&
      (v.response || (!v.configured && !v.paused && !v.notificationHeld && !v.released)) &&
      (!v.paused || v.configured) && (!v.notificationHeld || v.paused) && (!v.released || v.response);
}

// This is a single-site source-population control operation, not row eighteen
// of the qualification matrix.  The App11 namespace is derived from the
// operation and immutable manifest digest; the caller never supplies one.
enum class ProdigyNametagSourceBaselineAction : uint8_t { execute = 1, query = 2 };
class ProdigyNametagSourceBaselineCommand {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyNametagSourceBaselineAction action = ProdigyNametagSourceBaselineAction::execute;
  uint128_t operationUUID = 0, ewrClusterUUID = 0;
  // The entire EWR input tuple is carried through the App11 operation.  This
  // is deliberately independent of the later all-masters record: source
  // population is the prerequisite that creates its source data.
  uint64_t probeDeploymentID = 0, hotDeploymentID = 0, coldDeploymentID = 0;
  uint64_t radarDeploymentID = 0, pulseDeploymentID = 0, truthDeploymentID = 0;
  String fixtureManifestSHA256;
  int64_t deadlineAtMilliseconds = 0;
};
template <typename S>
static void serialize(S&& serializer, ProdigyNametagSourceBaselineCommand& value)
{ serializer.value4b(value.protocolVersion); serializer.value1b(value.action); serializer.value16b(value.operationUUID);
  serializer.value16b(value.ewrClusterUUID); serializer.value8b(value.probeDeploymentID);
  serializer.value8b(value.hotDeploymentID); serializer.value8b(value.coldDeploymentID); serializer.value8b(value.radarDeploymentID);
  serializer.value8b(value.pulseDeploymentID); serializer.value8b(value.truthDeploymentID);
  serializer.text1b(value.fixtureManifestSHA256, 64); serializer.value8b(value.deadlineAtMilliseconds); }
static inline bool prodigyNametagSourceBaselineCommandValid(const ProdigyNametagSourceBaselineCommand& value)
{ return value.protocolVersion == ProdigyNametagSourceBaselineCommand::version &&
      (value.action == ProdigyNametagSourceBaselineAction::execute || value.action == ProdigyNametagSourceBaselineAction::query) &&
      value.operationUUID != 0 && value.ewrClusterUUID != 0 && value.probeDeploymentID != 0 &&
      value.hotDeploymentID != 0 && value.coldDeploymentID != 0 && value.radarDeploymentID != 0 &&
      value.pulseDeploymentID != 0 && value.truthDeploymentID != 0 &&
      ApplicationConfig::extractApplicationID(value.probeDeploymentID) == 11 &&
      ApplicationConfig::extractApplicationID(value.hotDeploymentID) == MeshRegistry::Hot::applicationID &&
      ApplicationConfig::extractApplicationID(value.coldDeploymentID) == MeshRegistry::Cold::applicationID &&
      ApplicationConfig::extractApplicationID(value.radarDeploymentID) == MeshRegistry::Radar::applicationID &&
      ApplicationConfig::extractApplicationID(value.pulseDeploymentID) == MeshRegistry::Pulse::applicationID &&
      ApplicationConfig::extractApplicationID(value.truthDeploymentID) == MeshRegistry::Truth::applicationID &&
      prodigyIsSHA256HexDigest(value.fixtureManifestSHA256) && value.deadlineAtMilliseconds > 0; }

class ProdigyNametagSourceBaselineStoreDigest {
public:
  uint16_t applicationID = 0;
  uint32_t shardGroup = UINT32_MAX;
  String digest;
};
template <typename S>
static void serialize(S&& serializer, ProdigyNametagSourceBaselineStoreDigest& value)
{ serializer.value2b(value.applicationID); serializer.value4b(value.shardGroup); serializer.text1b(value.digest, 64); }
static inline bool prodigyNametagSourceBaselineStoreDigestsValid(
    const Vector<ProdigyNametagSourceBaselineStoreDigest>& values)
{
  if (values.size() != 9) return false;
  for (const auto& value : values) {
    const bool expected = (value.applicationID == MeshRegistry::Hot::applicationID && value.shardGroup < 3) ||
        (value.applicationID == MeshRegistry::Cold::applicationID && value.shardGroup < 3) ||
        ((value.applicationID == MeshRegistry::Pulse::applicationID || value.applicationID == MeshRegistry::Radar::applicationID ||
          value.applicationID == MeshRegistry::Truth::applicationID) && value.shardGroup == 0);
    if (!expected || !prodigyIsSHA256HexDigest(value.digest)) return false;
    for (const auto& prior : values)
      if (&prior != &value && prior.applicationID == value.applicationID && prior.shardGroup == value.shardGroup) return false;
  }
  return true;
}
class ProdigyNametagSourceBaselineReceipt {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0, ewrClusterUUID = 0, localContainerUUID = 0;
  uint64_t probeDeploymentID = 0;
  String fixtureManifestSHA256, canonicalReadbackDigest;
  int64_t deadlineAtMilliseconds = 0, observedAtMilliseconds = 0;
  Vector<ProdigyNametagSourceBaselineStoreDigest> storeDigests;
};
template <typename S>
static void serialize(S&& serializer, ProdigyNametagSourceBaselineReceipt& value)
{ serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID); serializer.value16b(value.ewrClusterUUID);
  serializer.value16b(value.localContainerUUID); serializer.value8b(value.probeDeploymentID);
  serializer.text1b(value.fixtureManifestSHA256, 64); serializer.text1b(value.canonicalReadbackDigest, 64);
  serializer.value8b(value.deadlineAtMilliseconds); serializer.value8b(value.observedAtMilliseconds);
  serializer.container(value.storeDigests, 9); }
static inline bool prodigyNametagSourceBaselineReceiptValid(const ProdigyNametagSourceBaselineReceipt& value)
{ return value.protocolVersion == ProdigyNametagSourceBaselineReceipt::version && value.operationUUID != 0 &&
      value.ewrClusterUUID != 0 && value.localContainerUUID != 0 && value.probeDeploymentID != 0 &&
      ApplicationConfig::extractApplicationID(value.probeDeploymentID) == 11 &&
      prodigyIsSHA256HexDigest(value.fixtureManifestSHA256) && prodigyIsSHA256HexDigest(value.canonicalReadbackDigest) &&
      value.deadlineAtMilliseconds > 0 && value.observedAtMilliseconds > 0 &&
      value.observedAtMilliseconds <= value.deadlineAtMilliseconds &&
      prodigyNametagSourceBaselineStoreDigestsValid(value.storeDigests); }

static inline bool prodigyNametagSourceBaselineReceiptEmpty(const ProdigyNametagSourceBaselineReceipt& value)
{
  return value.operationUUID == 0 && value.ewrClusterUUID == 0 && value.localContainerUUID == 0 &&
      value.probeDeploymentID == 0 && value.fixtureManifestSHA256.empty() && value.canonicalReadbackDigest.empty() &&
      value.deadlineAtMilliseconds == 0 && value.observedAtMilliseconds == 0 && value.storeDigests.empty();
}

// Execute and query differ only in the direction they travel.  The operation
// tuple itself must match exactly at every replay/cache boundary.
static inline bool prodigyNametagSourceBaselineCommandSameOperation(
    const ProdigyNametagSourceBaselineCommand& left, const ProdigyNametagSourceBaselineCommand& right)
{
  return left.protocolVersion == right.protocolVersion && left.operationUUID == right.operationUUID &&
      left.ewrClusterUUID == right.ewrClusterUUID && left.probeDeploymentID == right.probeDeploymentID &&
      left.hotDeploymentID == right.hotDeploymentID && left.coldDeploymentID == right.coldDeploymentID &&
      left.radarDeploymentID == right.radarDeploymentID && left.pulseDeploymentID == right.pulseDeploymentID &&
      left.truthDeploymentID == right.truthDeploymentID && left.fixtureManifestSHA256 == right.fixtureManifestSHA256 &&
      left.deadlineAtMilliseconds == right.deadlineAtMilliseconds;
}

// One topic and one payload serve both directions.  Direction is the role;
// splitting command and receipt topics would create a second control plane.
enum class ProdigyNametagSourceBaselineDirection : uint8_t { execute = 1, query = 2, receipt = 3 };
class ProdigyNametagSourceBaselineEnvelope {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyNametagSourceBaselineDirection direction = ProdigyNametagSourceBaselineDirection::execute;
  ProdigyNametagSourceBaselineCommand command;
  ProdigyNametagSourceBaselineReceipt receipt;
};
template <typename S>
static void serialize(S&& serializer, ProdigyNametagSourceBaselineEnvelope& value)
{ serializer.value4b(value.protocolVersion); serializer.value1b(value.direction); serializer.object(value.command); serializer.object(value.receipt); }
static inline bool prodigyNametagSourceBaselineEnvelopeValid(const ProdigyNametagSourceBaselineEnvelope& value)
{
  if (value.protocolVersion != ProdigyNametagSourceBaselineEnvelope::version) return false;
  if (value.direction == ProdigyNametagSourceBaselineDirection::execute)
    return prodigyNametagSourceBaselineCommandValid(value.command) &&
        value.command.action == ProdigyNametagSourceBaselineAction::execute &&
        prodigyNametagSourceBaselineReceiptEmpty(value.receipt);
  if (value.direction == ProdigyNametagSourceBaselineDirection::query)
    return prodigyNametagSourceBaselineCommandValid(value.command) &&
        value.command.action == ProdigyNametagSourceBaselineAction::query &&
        prodigyNametagSourceBaselineReceiptEmpty(value.receipt);
  return value.direction == ProdigyNametagSourceBaselineDirection::receipt &&
      prodigyNametagSourceBaselineCommandValid(value.command) &&
      prodigyNametagSourceBaselineReceiptValid(value.receipt) &&
      value.receipt.operationUUID == value.command.operationUUID &&
      value.receipt.ewrClusterUUID == value.command.ewrClusterUUID &&
      value.receipt.probeDeploymentID == value.command.probeDeploymentID &&
      value.receipt.fixtureManifestSHA256 == value.command.fixtureManifestSHA256 &&
      value.receipt.deadlineAtMilliseconds == value.command.deadlineAtMilliseconds;
}

// A bounded, live projection of one stateful member.  This deliberately
// references the existing COUSIN and data-authority evidence rather than
// creating an admission/claim record for an observation endpoint.
class DeploymentIdentityStatefulMember {
public:
  DeploymentIdentityStoreKind storeKind = DeploymentIdentityStoreKind::unknown;
  uint32_t shardGroup = UINT32_MAX;
  uint128_t replicaUUID = 0;
  uint128_t clusterUUID = 0;
  uint128_t machineUUID = 0;
  uint128_t containerUUID = 0;
  bool writable = false;
  bool clientServing = false;
  bool allMasters = false;
  uint128_t siblingSessionUUID = 0;
  uint64_t siblingSessionGeneration = 0;
  bool siblingSessionHealthy = false;
  uint128_t seededFromClusterUUID = 0;
  uint128_t seededFromContainerUUID = 0;
  String seedCatchupSHA256;
  uint64_t seedCatchupGeneration = 0;
  String replayWatermarkSHA256;
  String catchupWatermarkSHA256;
  // v4 DeploymentIdentityReport appends these direct native store values.
  // Unlike the historic seed/catch-up fields, neither may be reconstructed
  // from authority metadata by a coordinator.
  String sourceContentWatermarkSHA256;
  String sourceCatchupWatermarkSHA256;
  // v5 carries the authenticated native receipt, not an inferred projection.
  ProdigyStatefulStoreReceipt nativeSourceCutReceipt = {.protocolVersion = 0};
};

template <typename S>
static void serialize(S&& serializer, DeploymentIdentityStatefulMember& member)
{
  serializer.value1b(member.storeKind); serializer.value4b(member.shardGroup);
  serializer.value16b(member.replicaUUID); serializer.value16b(member.clusterUUID);
  serializer.value16b(member.machineUUID); serializer.value16b(member.containerUUID);
  serializer.value1b(member.writable); serializer.value1b(member.clientServing); serializer.value1b(member.allMasters);
  serializer.value16b(member.siblingSessionUUID); serializer.value8b(member.siblingSessionGeneration);
  serializer.value1b(member.siblingSessionHealthy); serializer.value16b(member.seededFromClusterUUID);
  serializer.value16b(member.seededFromContainerUUID); serializer.text1b(member.seedCatchupSHA256, 64);
  serializer.value8b(member.seedCatchupGeneration); serializer.text1b(member.replayWatermarkSHA256, 64);
  serializer.text1b(member.catchupWatermarkSHA256, 64);
}

template <typename S>
static void serializeDeploymentIdentityStatefulMemberV4(S&& serializer, DeploymentIdentityStatefulMember& member)
{
  serialize(serializer, member);
  serializer.text1b(member.sourceContentWatermarkSHA256, 64);
  serializer.text1b(member.sourceCatchupWatermarkSHA256, 64);
}

// app6's persistent Truth mesh observation.  Each entry is emitted by the
// existing Neuron/application report path after an authenticated reconnect;
// it is intentionally not a credential or session claim.
class DeploymentIdentityApp6TruthMeshReceipt {
public:
  uint128_t localClusterUUID = 0;
  uint128_t remoteClusterUUID = 0;
  uint128_t truthWriterContainerUUID = 0;
  uint128_t sessionUUID = 0;
  uint64_t commandGeneration = 0;
  uint64_t reconnectGeneration = 0;
  String lastSuccessfulRequestWatermarkSHA256;
  uint128_t reverseCarrierUUID = 0;
  bool healthy = false;
  uint128_t localApplicationContainerUUID = 0;
  uint128_t routeUUID = 0;
  uint64_t routeGeneration = 0;
  uint8_t observationVersion = 1;
};

template <typename S>
static void serialize(S&& serializer, DeploymentIdentityApp6TruthMeshReceipt& receipt)
{
  serializer.value16b(receipt.localClusterUUID); serializer.value16b(receipt.remoteClusterUUID);
  serializer.value16b(receipt.truthWriterContainerUUID); serializer.value16b(receipt.sessionUUID);
  serializer.value8b(receipt.commandGeneration); serializer.value8b(receipt.reconnectGeneration);
  serializer.text1b(receipt.lastSuccessfulRequestWatermarkSHA256, 64); serializer.value16b(receipt.reverseCarrierUUID);
  serializer.value1b(receipt.healthy);
}

// Read-only, versioned observed deployment identity.  It is not a durable
// admission receipt: it describes the current live or persisted authority
// view, and a coordinator must not infer a launch or retirement authorization
// from its absence or presence.
class DeploymentIdentityReport {
public:
  uint32_t version = 1;
  bool found = false;
  bool live = false;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  uint64_t versionID = 0;
  uint128_t clusterUUID = 0;
  String canonicalPlanSHA256 = {};
  String containerBlobSHA256 = {};
  uint64_t containerBlobBytes = 0;
  uint64_t authorityGeneration = 0;
  uint128_t masterUUID = 0;
  int64_t masterBootNs = 0;
  DeploymentState state = DeploymentState::none;
  uint32_t nTarget = 0;
  uint32_t nDeployed = 0;
  uint32_t nHealthy = 0;
  uint32_t acknowledgedPeerCount = 0;
  bool isStateful = false;
  bool useHostNetworkNamespace = false;
  uint128_t observedPrefixUUID = 0;
  String observedEndpointIPv4 = {};
  uint16_t observedEndpointPort = 0;
  uint128_t observedEndpointMachineUUID = 0;
  bool profileEligible = false;
  uint32_t selectedShardGroup = UINT32_MAX;
  uint32_t nShardGroups = 0;
  bool statefulCohortReady = false;
  String normalizedDeploymentPlan;
  Vector<ProdigyStatefulServingAuthorityMember> statefulCohort;
  // ContainerPlan is defined below; these are its existing private runtime
  // record bytes, not another plan codec. Only the authenticated observer sees
  // them, and the canonical serving owner computes each matching digest.
  Vector<String> statefulCohortRuntimeStates;
  String statefulCohortFailure;
  // v3: exact, per-replica stateful evidence. v4 appends authenticated native
  // source-boundary values. The cap covers the largest
  // supported deployment observation while keeping a hostile pull bounded.
  Vector<DeploymentIdentityStatefulMember> statefulRuntimeCohort;
  bool statefulRuntimeCohortConverged = false;
  Vector<DeploymentIdentityApp6TruthMeshReceipt> app6TruthMeshReceipts;
};

// Supported versions are additive; consumers still enforce the minimum
// version containing the fields on which their specific decision depends.
static inline bool prodigyDeploymentIdentityReportVersionSupported(uint32_t version, uint32_t minimum = 1)
{ return minimum >= 1 && minimum <= 6 && version >= minimum && version <= 6; }

template <typename S>
static void serialize(S&& serializer, DeploymentIdentityReport& report)
{
  serializer.value4b(report.version);
  serializer.value1b(report.found);
  serializer.value1b(report.live);
  serializer.value2b(report.applicationID);
  serializer.value8b(report.deploymentID);
  serializer.value8b(report.versionID);
  serializer.value16b(report.clusterUUID);
  serializer.text1b(report.canonicalPlanSHA256, 64);
  serializer.text1b(report.containerBlobSHA256, 64);
  serializer.value8b(report.containerBlobBytes);
  serializer.value8b(report.authorityGeneration);
  serializer.value16b(report.masterUUID);
  serializer.value8b(report.masterBootNs);
  serializer.value1b(report.state);
  serializer.value4b(report.nTarget);
  serializer.value4b(report.nDeployed);
  serializer.value4b(report.nHealthy);
  serializer.value4b(report.acknowledgedPeerCount);
  serializer.value1b(report.isStateful);
  serializer.value1b(report.useHostNetworkNamespace);
  serializer.value16b(report.observedPrefixUUID);
  serializer.text1b(report.observedEndpointIPv4, 64);
  serializer.value2b(report.observedEndpointPort);
  serializer.value16b(report.observedEndpointMachineUUID);
  serializer.value1b(report.profileEligible);
  if (report.version >= 2) {
    serializer.value4b(report.selectedShardGroup); serializer.value4b(report.nShardGroups);
    serializer.value1b(report.statefulCohortReady); serializer.text1b(report.normalizedDeploymentPlan, 1024 * 1024);
    serializer.container(report.statefulCohort, 3);
    serializer.container(report.statefulCohortRuntimeStates, 3, [](auto& nested, String& bytes) { nested.text1b(bytes, 1024 * 1024); });
    serializer.text1b(report.statefulCohortFailure, 1024);
  }
  if (report.version >= 3) {
    serializer.container(report.statefulRuntimeCohort, 64, [&](auto& nested, DeploymentIdentityStatefulMember& member) {
      if (report.version >= 4) serializeDeploymentIdentityStatefulMemberV4(nested, member);
      else serialize(nested, member);
      if (report.version >= 5) nested.object(member.nativeSourceCutReceipt);
    });
    serializer.value1b(report.statefulRuntimeCohortConverged);
    serializer.container(report.app6TruthMeshReceipts, 3, [&](auto& nested, DeploymentIdentityApp6TruthMeshReceipt& receipt) {
      serialize(nested, receipt);
      if (report.version >= 6) {
        nested.value1b(receipt.observationVersion);
        nested.value16b(receipt.localApplicationContainerUUID);
        nested.value16b(receipt.routeUUID); nested.value8b(receipt.routeGeneration);
      }
    });
  }
}

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
      string.snprintf_add<"subnet address={} network={}/{itoa} gateway={} internetReachable={itoa}\n"_ctv>(
          addressText,
          networkText,
          uint32_t(subnet.subnet.cidr),
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

// A separate versioned report for release admission.  It intentionally does
// not extend ClusterStatusReport, whose positional wire format is deployed.
// The outer request carries target-specific work; an old Brain cannot decode
// it and therefore cannot accidentally attest capacity for another target.
class ProdigyUpgradeAdmissionReportRequest {
public:
  uint32_t version = 1;
  String operationID = {};
  String targetBundleSHA256 = {};
  String targetContractSHA256 = {};
  uint64_t requiredStagingBytes = 0;
};

template <typename S>
static void serialize(S&& serializer, ProdigyUpgradeAdmissionReportRequest& request)
{
  serializer.value4b(request.version);
  serializer.text1b(request.operationID, 34);
  serializer.text1b(request.targetBundleSHA256, 64);
  serializer.text1b(request.targetContractSHA256, 64);
  serializer.value8b(request.requiredStagingBytes);
}

class ProdigyUpgradeAdmissionObservationRequest {
public:
  uint32_t version = 2;
  uint64_t receiptVersion = 0;
  uint64_t authorityGeneration = 0;
  uint64_t requesterTransportGeneration = 0;
  uint128_t masterUUID = 0;
  int64_t masterBootNs = 0;
  uint64_t nonce = 0;
  int64_t requestedAtMs = 0;
  String operationID = {};
  String targetBundleSHA256 = {};
  String targetContractSHA256 = {};
  uint64_t requiredStagingBytes = 0;
};

template <typename S>
static void serialize(S&& serializer, ProdigyUpgradeAdmissionObservationRequest& request)
{
  serializer.value4b(request.version); serializer.value8b(request.receiptVersion);
  serializer.value8b(request.authorityGeneration); serializer.value8b(request.requesterTransportGeneration);
  serializer.value16b(request.masterUUID); serializer.value8b(request.masterBootNs);
  serializer.value8b(request.nonce); serializer.value8b(request.requestedAtMs);
  serializer.text1b(request.operationID, 34);
  serializer.text1b(request.targetBundleSHA256, 64);
  serializer.text1b(request.targetContractSHA256, 64);
  serializer.value8b(request.requiredStagingBytes);
}

class ProdigyUpgradeAdmissionPeerObservation {
public:
  uint128_t brainUUID = 0;
  uint128_t machineUUID = 0;
  uint64_t receiptVersion = 0;
  uint64_t authorityGeneration = 0;
  uint64_t requesterTransportGeneration = 0;
  uint128_t masterUUID = 0;
  int64_t masterBootNs = 0;
  uint64_t nonce = 0;
  int64_t observedAtMs = 0;
  bool codeSupportsSerialFollowers = false;
  bool localInstalledBundleVerified = false;
  bool stateUploadFresh = false;
  bool authorityAcknowledged = false;
  bool recoveryWitnessAcknowledged = false;
  String operationID = {};
  String targetBundleSHA256 = {};
  String targetContractSHA256 = {};
  uint64_t requiredStagingBytes = 0;
  uint64_t stagingAvailableBytes = 0;
  bool stagingCapacityProbeComplete = false;
  bool stagingCapacityVerified = false;
  String installedBundleSHA256 = {};
};

template <typename S>
static void serialize(S&& serializer, ProdigyUpgradeAdmissionPeerObservation& observation)
{
  serializer.value16b(observation.brainUUID);
  serializer.value16b(observation.machineUUID);
  serializer.value8b(observation.receiptVersion);
  serializer.value8b(observation.authorityGeneration);
  serializer.value8b(observation.requesterTransportGeneration);
  serializer.value16b(observation.masterUUID); serializer.value8b(observation.masterBootNs);
  serializer.value8b(observation.nonce); serializer.value8b(observation.observedAtMs);
  serializer.value1b(observation.codeSupportsSerialFollowers);
  serializer.value1b(observation.localInstalledBundleVerified);
  serializer.value1b(observation.stateUploadFresh);
  serializer.value1b(observation.authorityAcknowledged);
  serializer.value1b(observation.recoveryWitnessAcknowledged);
  serializer.text1b(observation.operationID, 34);
  serializer.text1b(observation.targetBundleSHA256, 64);
  serializer.text1b(observation.targetContractSHA256, 64);
  serializer.value8b(observation.requiredStagingBytes);
  serializer.value8b(observation.stagingAvailableBytes);
  serializer.value1b(observation.stagingCapacityProbeComplete);
  serializer.value1b(observation.stagingCapacityVerified);
  serializer.text1b(observation.installedBundleSHA256, UINT32_MAX);
}

class ProdigyAdmittedUpdateRequest {
public:
  uint32_t version = 1;
  String operationID, sourceBundleSHA256, targetBundleSHA256, targetContractSHA256;
  uint64_t authorityGeneration = 0;
  uint64_t receiptVersion = 0;
  uint64_t nonce = 0;
  uint64_t requiredStagingBytes = 0;
  bool requiresEmptyWorkloadSet = false;
  uint128_t masterUUID = 0;
  int64_t masterBootNs = 0;
  // Version two binds the admitted rollout's durable Brain batch policy.
  // Zero preserves the v1 admitted request's default behavior.
  uint8_t brainConcurrency = 0;
};
template <typename S>
static void serialize(S&& serializer, ProdigyAdmittedUpdateRequest& request)
{
  serializer.value4b(request.version);
  serializer.text1b(request.operationID, 34);
  serializer.text1b(request.sourceBundleSHA256, 64);
  serializer.text1b(request.targetBundleSHA256, 64);
  serializer.text1b(request.targetContractSHA256, 64);
  serializer.value8b(request.authorityGeneration);
  serializer.value16b(request.masterUUID);
  serializer.value8b(request.masterBootNs);
  serializer.value8b(request.receiptVersion);
  serializer.value8b(request.nonce);
  serializer.value8b(request.requiredStagingBytes);
  serializer.value1b(request.requiresEmptyWorkloadSet);
  if (request.version >= 2) serializer.value1b(request.brainConcurrency);
}

class MothershipUpgradeAdmissionReport {
public:
  uint32_t version = 4;
  uint128_t clusterUUID = 0;
  uint64_t observationReceiptVersion = 0;
  uint64_t authorityGeneration = 0;
  uint128_t masterUUID = 0;
  int64_t masterBootNs = 0;
  uint64_t observationNonce = 0;
  int64_t observedAtMs = 0;
  bool master = false;
  bool authorityQuorumHealthy = false;
  bool authorityAcknowledged = false;
  bool recoveryWitnessAcknowledged = false;
  bool currentUpdaterSupportsSerialFollowers = false;
  bool fleetBundleDigestsFresh = false;
  bool fleetInventoriesFresh = false;
  bool observationComplete = false;
  uint32_t commissionedBrainCount = 0;
  uint32_t healthyCommissionedBrainCount = 0;
  uint32_t activeDeploymentCount = 0;
  uint64_t readySchedulableStorageBytes = 0;
  bool commissionedPeerTransportVerified = false;
  String operationID = {};
  String targetBundleSHA256 = {};
  String targetContractSHA256 = {};
  uint64_t requiredStagingBytes = 0;
  bool stagingCapacityResponsesComplete = false;
  bool stagingCapacityComplete = false;
  String masterApprovedBundleSHA256 = {};
  String masterRunningProdigyVersion = {};
  Vector<ProdigyUpgradeAdmissionPeerObservation> peers = {};
};

template <typename S>
static void serialize(S&& serializer, MothershipUpgradeAdmissionReport& report)
{
  serializer.value4b(report.version);
  serializer.value16b(report.clusterUUID);
  serializer.value8b(report.observationReceiptVersion);
  serializer.value8b(report.authorityGeneration); serializer.value16b(report.masterUUID);
  serializer.value8b(report.masterBootNs); serializer.value8b(report.observationNonce);
  serializer.value8b(report.observedAtMs); serializer.value1b(report.master);
  serializer.value1b(report.authorityQuorumHealthy);
  serializer.value1b(report.authorityAcknowledged);
  serializer.value1b(report.recoveryWitnessAcknowledged);
  serializer.value1b(report.currentUpdaterSupportsSerialFollowers);
  serializer.value1b(report.fleetBundleDigestsFresh);
  serializer.value1b(report.fleetInventoriesFresh);
  serializer.value1b(report.observationComplete);
  serializer.value4b(report.commissionedBrainCount); serializer.value4b(report.healthyCommissionedBrainCount);
  serializer.value4b(report.activeDeploymentCount);
  serializer.value8b(report.readySchedulableStorageBytes); serializer.value1b(report.commissionedPeerTransportVerified);
  serializer.text1b(report.operationID, 34);
  serializer.text1b(report.targetBundleSHA256, 64);
  serializer.text1b(report.targetContractSHA256, 64);
  serializer.value8b(report.requiredStagingBytes);
  serializer.value1b(report.stagingCapacityResponsesComplete);
  serializer.value1b(report.stagingCapacityComplete);
  serializer.text1b(report.masterApprovedBundleSHA256, UINT32_MAX);
  serializer.text1b(report.masterRunningProdigyVersion, UINT32_MAX);
  serializer.container(report.peers, 256);
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

static inline void prodigyStripMachineHardwareCapturesForBrainTransport(MachineHardwareProfile& hardware)
{
  Vector<MachineToolCapture> kernelIPv6Routes = {};
  for (const MachineToolCapture& capture : hardware.network.captures)
  {
    if (capture.tool.equal("ip"_ctv) && capture.phase.equal("route-show-ipv6"_ctv) && capture.succeeded)
    {
      kernelIPv6Routes.push_back(capture);
    }
  }

  prodigyStripMachineHardwareCapturesForClusterReport(hardware);
  hardware.network.captures = std::move(kernelIPv6Routes);
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

enum class SwitchboardWormholeOperationStatus : uint8_t {
  request = 0,
  applied,
  rejected,
  rollbackFailed,
};

struct SwitchboardWormholeOperation {
  constexpr static uint32_t maximumDesiredBytes = 1024u * 1024u;

  uint32_t containerID = 0;
  SwitchboardWormholeOperationStatus status = SwitchboardWormholeOperationStatus::request;
  String revision;
  String desired;
};

template <typename S>
static void serialize(S&& serializer, SwitchboardWormholeOperation& operation)
{
  serializer.value4b(operation.containerID);
  serializer.value1b(operation.status);
  serializer.text1b(operation.revision, 64);
  serializer.text1b(operation.desired, SwitchboardWormholeOperation::maximumDesiredBytes);
}

static inline bool wormholeTargetBindingsUnique(const Vector<Wormhole>& wormholes)
{
  for (uint32_t index = 0; index < wormholes.size(); ++index)
  {
    for (uint32_t other = index + 1; other < wormholes.size(); ++other)
    {
      if (wormholes[index].containerPort == wormholes[other].containerPort &&
          wormholes[index].layer4 == wormholes[other].layer4)
      {
        return false;
      }
    }
  }
  return true;
}

// Admission belongs to the revisioned runtime desired state, not the embedded,
// unversioned deployment/application Wormhole wire layout.
struct SwitchboardWormholeDesiredState {
  static constexpr uint32_t version = 1;
  static constexpr uint32_t maximumWormholes = 1024;
  uint32_t protocolVersion = version;
  Vector<Wormhole> wormholes = {};
  Vector<uint16_t> pairAdmissionTCPPorts = {};
};

template <typename S>
static void serialize(S&& serializer, SwitchboardWormholeDesiredState& state)
{
  serializer.value4b(state.protocolVersion);
  serializer.container(state.wormholes, SwitchboardWormholeDesiredState::maximumWormholes,
      [](auto& nested, Wormhole& wormhole) { nested.object(wormhole); });
  serializer.container(state.pairAdmissionTCPPorts, SwitchboardWormholeDesiredState::maximumWormholes,
      [](auto& nested, uint16_t& port) { nested.value2b(port); });
}

static inline bool prodigyWormholeRequiresPairAdmission(const SwitchboardWormholeDesiredState& state,
                                                       uint16_t port, uint8_t protocol)
{
  if (protocol != IPPROTO_TCP || port == 0) return false;
  for (uint16_t protectedPort : state.pairAdmissionTCPPorts)
    if (protectedPort == port) return true;
  return false;
}

static inline bool prodigyWormholeDesiredStateValid(const SwitchboardWormholeDesiredState& state,
                                                   bool requireResolvedAddresses = true)
{
  if (state.protocolVersion != SwitchboardWormholeDesiredState::version ||
      (!state.pairAdmissionTCPPorts.empty() &&
       state.wormholes.size() > SwitchboardWormholeDesiredState::maximumWormholes) ||
      state.pairAdmissionTCPPorts.size() > state.wormholes.size() ||
      !wormholeTargetBindingsUnique(state.wormholes)) return false;
  uint16_t previous = 0;
  for (uint16_t port : state.pairAdmissionTCPPorts)
  {
    if (port == 0 || port <= previous) return false;
    previous = port;
    uint32_t matches = 0;
    for (const Wormhole& wormhole : state.wormholes)
    {
      if (wormhole.containerPort != port) continue;
      if (wormhole.layer4 != IPPROTO_TCP || wormhole.isQuic ||
          (wormhole.externalAddress.isNull() ? requireResolvedAddresses : !wormhole.externalAddress.is6) ||
          wormhole.externalPort == 0 || (!wormhole.deliveryAddress.isNull() &&
          !wormhole.deliveryAddress.equals(wormhole.externalAddress))) return false;
      ++matches;
    }
    if (matches != 1) return false;
  }
  return true;
}

// A legacy vector begins with its element count. Zero followed by trailing
// bytes cannot be a valid legacy vector, so old readers reject this envelope
// without attempting a large allocation. Malformed envelopes never downgrade.
constexpr inline uint8_t prodigyWormholeDesiredMagic[] = {0, 'P', 'R', 'D', 'W', 'H', 1, 0};

static inline bool prodigyEncodeWormholeDesiredState(const SwitchboardWormholeDesiredState& state, String& encoded)
{
  encoded.clear();
  if (!prodigyWormholeDesiredStateValid(state)) return false;
  auto copy = state;
  String body = {};
  if (state.pairAdmissionTCPPorts.empty())
  {
    if (!BitseryEngine::serialize(body, copy.wormholes)) return false;
  }
  else
  {
    if (!BitseryEngine::serialize(body, copy) ||
        !encoded.reserve(sizeof(prodigyWormholeDesiredMagic) + body.size())) return false;
    encoded.append(prodigyWormholeDesiredMagic, sizeof(prodigyWormholeDesiredMagic));
  }
  if (state.pairAdmissionTCPPorts.empty()) encoded = std::move(body);
  else encoded.append(body);
  if (encoded.empty() || encoded.size() > SwitchboardWormholeOperation::maximumDesiredBytes)
  { encoded.clear(); return false; }
  return true;
}

static inline bool prodigyDecodeWormholeDesiredState(const String& encoded, SwitchboardWormholeDesiredState& state)
{
  state = {};
  if (encoded.empty() || encoded.size() > SwitchboardWormholeOperation::maximumDesiredBytes) return false;
  SwitchboardWormholeDesiredState decoded = {};
  if (encoded.size() > 1 && encoded[0] == 0)
  {
    if (encoded.size() <= sizeof(prodigyWormholeDesiredMagic) ||
        std::memcmp(encoded.data(), prodigyWormholeDesiredMagic, sizeof(prodigyWormholeDesiredMagic)) != 0) return false;
    String body = {};
    const uint64_t bytes = encoded.size() - sizeof(prodigyWormholeDesiredMagic);
    if (!body.reserve(bytes)) return false;
    body.append(encoded.data() + sizeof(prodigyWormholeDesiredMagic), bytes);
    if (!BitseryEngine::deserializeSafe(body, decoded) || decoded.pairAdmissionTCPPorts.empty()) return false;
  }
  else if (!BitseryEngine::deserializeSafe(encoded, decoded.wormholes)) return false;
  if (!prodigyWormholeDesiredStateValid(decoded)) return false;
  state = std::move(decoded);
  return true;
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

class ProdigyPersistentUpdateSelfMachineRecoveryWitness {
public:

  uint128_t machineUUID = 0;
  bool bundleRegistered = false;
  Vector<String> containerBootstraps;

  bool operator==(const ProdigyPersistentUpdateSelfMachineRecoveryWitness& other) const
  {
    return machineUUID == other.machineUUID && bundleRegistered == other.bundleRegistered &&
           containerBootstraps == other.containerBootstraps;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentUpdateSelfMachineRecoveryWitness& witness)
{
  serializer.value16b(witness.machineUUID);
  serializer.value1b(witness.bundleRegistered);
  serializer.object(witness.containerBootstraps);
}

class ProdigyPersistentUpdateSelfState {
public:

  enum class Phase : uint8_t {
    idle,
    waitingForBundleEchos,
    waitingForFollowerReboots,
    waitingForRelinquishEchos
  };

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
  // Worker transitions are serial and survive a master restart.  A worker is
  // complete only after its staged digest, new registration, and state upload.
  String workerExpectedBundleSHA256;
  String workerFailure;
  Vector<uint128_t> workerMachineUUIDs;
  Vector<uint128_t> workerStagedMachineUUIDs;
  Vector<uint128_t> workerTransitionIssuedMachineUUIDs;
  Vector<uint128_t> workerRebootedMachineUUIDs;
  Vector<uint128_t> workerStateUploadedMachineUUIDs;
  // The master Brain and its local Neuron exec in the same process. Preserve
  // the already-authoritative state-upload payload until the replacement
  // binary has proved its digest and the local Neuron has re-adopted every
  // live container. Serialized payloads keep this transaction owner
  // independent of the later ContainerPlan type declaration.
  uint128_t localMachineUUID = 0;
  bool localBundleRegistered = false;
  Vector<String> localContainerBootstraps;
  // Version-three master-authority records capture every commissioned machine under
  // one master-authority transaction. Payload bytes remain sidecar secrets.
  Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness> machineRecoveryWitnesses;

  bool active(void) const
  {
    return state != 0 || expectedEchos != 0 || bundleEchos != 0 || relinquishEchos != 0 || plannedMasterPeerKey != 0 || pendingDesignatedMasterPeerKey != 0 || useStagedBundleOnly || bundleBlob.size() > 0 || bundleEchoPeerKeys.empty() == false || relinquishEchoPeerKeys.empty() == false || followerBootNsByPeerKey.empty() == false || followerRebootedPeerKeys.empty() == false || workerExpectedBundleSHA256.size() > 0 || workerFailure.size() > 0 || workerMachineUUIDs.empty() == false || workerStagedMachineUUIDs.empty() == false || workerTransitionIssuedMachineUUIDs.empty() == false || workerRebootedMachineUUIDs.empty() == false || workerStateUploadedMachineUUIDs.empty() == false || localMachineUUID != 0 || localBundleRegistered || localContainerBootstraps.empty() == false || machineRecoveryWitnesses.empty() == false;
  }

  bool operator==(const ProdigyPersistentUpdateSelfState& other) const
  {
    return state == other.state && expectedEchos == other.expectedEchos && bundleEchos == other.bundleEchos && relinquishEchos == other.relinquishEchos && plannedMasterPeerKey == other.plannedMasterPeerKey && pendingDesignatedMasterPeerKey == other.pendingDesignatedMasterPeerKey && useStagedBundleOnly == other.useStagedBundleOnly && bundleBlob.equals(other.bundleBlob) && bundleEchoPeerKeys == other.bundleEchoPeerKeys && relinquishEchoPeerKeys == other.relinquishEchoPeerKeys && followerBootNsByPeerKey == other.followerBootNsByPeerKey && followerRebootedPeerKeys == other.followerRebootedPeerKeys && workerExpectedBundleSHA256.equals(other.workerExpectedBundleSHA256) && workerFailure.equals(other.workerFailure) && workerMachineUUIDs == other.workerMachineUUIDs && workerStagedMachineUUIDs == other.workerStagedMachineUUIDs && workerTransitionIssuedMachineUUIDs == other.workerTransitionIssuedMachineUUIDs && workerRebootedMachineUUIDs == other.workerRebootedMachineUUIDs && workerStateUploadedMachineUUIDs == other.workerStateUploadedMachineUUIDs && localMachineUUID == other.localMachineUUID && localBundleRegistered == other.localBundleRegistered && localContainerBootstraps == other.localContainerBootstraps && machineRecoveryWitnesses == other.machineRecoveryWitnesses;
  }

  bool operator!=(const ProdigyPersistentUpdateSelfState& other) const
  {
    return (*this == other) == false;
  }
};

static bool prodigyPersistentUpdateSelfStatesEquivalent(
    ProdigyPersistentUpdateSelfState lhs,
    ProdigyPersistentUpdateSelfState rhs)
{
  auto canonicalizeWorkerSets = [](ProdigyPersistentUpdateSelfState& state) {
    std::sort(state.workerMachineUUIDs.begin(), state.workerMachineUUIDs.end());
    std::sort(state.workerStagedMachineUUIDs.begin(), state.workerStagedMachineUUIDs.end());
    std::sort(state.workerTransitionIssuedMachineUUIDs.begin(),
              state.workerTransitionIssuedMachineUUIDs.end());
    std::sort(state.workerRebootedMachineUUIDs.begin(),
              state.workerRebootedMachineUUIDs.end());
    std::sort(state.workerStateUploadedMachineUUIDs.begin(),
              state.workerStateUploadedMachineUUIDs.end());
  };
  canonicalizeWorkerSets(lhs);
  canonicalizeWorkerSets(rhs);
  return lhs == rhs;
}

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
  serializer.text1b(state.workerExpectedBundleSHA256, UINT32_MAX);
  serializer.text1b(state.workerFailure, UINT32_MAX);
  serializer.object(state.workerMachineUUIDs);
  serializer.object(state.workerStagedMachineUUIDs);
  serializer.object(state.workerTransitionIssuedMachineUUIDs);
  serializer.object(state.workerRebootedMachineUUIDs);
  serializer.object(state.workerStateUploadedMachineUUIDs);
  serializer.value16b(state.localMachineUUID);
  serializer.value1b(state.localBundleRegistered);
  serializer.object(state.localContainerBootstraps);
  // All-machine recovery witnesses are framed by the enclosing master-authority
  // record version. They cannot be conditionally read here: updateSelf is a
  // nested object and old outer records contain subsequent fields.
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

// The add-machines journal is durable before a provider accepts a create.  The
// immutable create work must therefore live outside its legacy positional
// record: old snapshots cannot be taught an extra field in that record.
class ProdigyPendingAddMachinesProvisioningIntent {
public:

  uint64_t operationID = 0;
  uint32_t nextInstructionIndex = 0;
  Vector<CreateMachinesInstruction> instructions;

  bool operator==(const ProdigyPendingAddMachinesProvisioningIntent& other) const
  {
    return operationID == other.operationID &&
        nextInstructionIndex == other.nextInstructionIndex &&
        instructions == other.instructions;
  }

  bool operator!=(const ProdigyPendingAddMachinesProvisioningIntent& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPendingAddMachinesProvisioningIntent& intent)
{
  serializer.value8b(intent.operationID);
  serializer.value4b(intent.nextInstructionIndex);
  serializer.object(intent.instructions);
}

static inline bool prodigyPendingAddMachinesProvisioningIntentsValid(
    const Vector<ProdigyPendingAddMachinesOperation>& operations,
    const Vector<ProdigyPendingAddMachinesProvisioningIntent>& intents)
{
  for (uint32_t index = 0; index < intents.size(); ++index)
  {
    const auto& intent = intents[index];
    if (intent.operationID == 0 || intent.instructions.empty() ||
        uint64_t(intent.nextInstructionIndex) + intent.instructions.size() > UINT32_MAX)
    {
      return false;
    }
    if (std::any_of(intents.begin(), intents.begin() + index, [&](const auto& previous) {
          return previous.operationID == intent.operationID;
        }))
    {
      return false;
    }
    if (std::count_if(operations.begin(), operations.end(), [&](const auto& operation) {
          return operation.operationID == intent.operationID;
        }) != 1)
    {
      return false;
    }
    for (const auto& instruction : intent.instructions)
      if (instruction.backing != ClusterMachineBacking::cloud ||
          instruction.cloud.schema.empty() || instruction.count == 0 ||
          instruction.lifetime == MachineLifetime::owned)
      {
        return false;
      }
  }
  return true;
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

class ProdigyPendingMachineRetirement {
public:

  uint64_t retirementID = 0;
  uint64_t topologyVersion = 0;
  ClusterMachine machine;
  bool evacuationComplete = false;
  bool destroyRequired = false;
  bool destroySucceeded = false;

  bool operator==(const ProdigyPendingMachineRetirement& other) const
  {
    return retirementID == other.retirementID && topologyVersion == other.topologyVersion &&
           machine == other.machine &&
           evacuationComplete == other.evacuationComplete &&
           destroyRequired == other.destroyRequired &&
           destroySucceeded == other.destroySucceeded;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPendingMachineRetirement& retirement)
{
  serializer.value8b(retirement.retirementID);
  serializer.value8b(retirement.topologyVersion);
  serializer.object(retirement.machine);
  serializer.value1b(retirement.evacuationComplete);
  serializer.value1b(retirement.destroyRequired);
  serializer.value1b(retirement.destroySucceeded);
}

class ProdigyMachineRetirementJournal {
public:

  constexpr static uint8_t currentVersion = 1;

  uint8_t version = currentVersion;
  Vector<ProdigyPendingMachineRetirement> retirements;
};

template <typename S>
static void serialize(S&& serializer, ProdigyMachineRetirementJournal& journal)
{
  serializer.value1b(journal.version);
  serializer.object(journal.retirements);
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

class ProdigyMaterializedStatefulRecoveryOperation {
public:
  String operationID;
  uint64_t activeDeploymentID = 0;
  uint64_t successorDeploymentID = 0;
  String successorBlobSHA256;
  bool accepted = false;
  bool started = false;
  bool completed = false;
  int64_t updatedAtMs = 0;
};
template <typename S>
static void serialize(S&& serializer, ProdigyMaterializedStatefulRecoveryOperation& operation)
{
  serializer.text1b(operation.operationID, 36);
  serializer.value8b(operation.activeDeploymentID);
  serializer.value8b(operation.successorDeploymentID);
  serializer.text1b(operation.successorBlobSHA256, 128);
  serializer.value1b(operation.accepted);
  serializer.value1b(operation.started);
  serializer.value1b(operation.completed);
  serializer.value8b(operation.updatedAtMs);
}

enum class ProdigyMaterializedStatefulRecoveryRetryPhase : uint8_t {
  authorized,
  successorAdmitted,
  storageLaunchDispatched,
  storageLaunchHealthy,
  completed,
};

// Kept separate from the original operation so version-three durable state
// remains readable without interpreting a changed operation layout.
class ProdigyMaterializedStatefulRecoveryRetry {
public:
  String operationID;
  uint64_t activeDeploymentID = 0;
  uint64_t failedSuccessorDeploymentID = 0;
  String failedSuccessorBlobSHA256;
  uint64_t replacementSuccessorDeploymentID = 0;
  String replacementSuccessorBlobSHA256;
  RetainedContainerStorageSource source;
  uint128_t retryContainerUUID = 0;
  ProdigyMaterializedStatefulRecoveryRetryPhase phase = ProdigyMaterializedStatefulRecoveryRetryPhase::authorized;
  int64_t updatedAtMs = 0;
};
template <typename S>
static void serialize(S&& serializer, ProdigyMaterializedStatefulRecoveryRetry& retry)
{
  serializer.text1b(retry.operationID, 36);
  serializer.value8b(retry.activeDeploymentID);
  serializer.value8b(retry.failedSuccessorDeploymentID);
  serializer.text1b(retry.failedSuccessorBlobSHA256, 128);
  serializer.value8b(retry.replacementSuccessorDeploymentID);
  serializer.text1b(retry.replacementSuccessorBlobSHA256, 128);
  serializer.object(retry.source);
  serializer.value16b(retry.retryContainerUUID);
  uint8_t phase = uint8_t(retry.phase);
  serializer.value1b(phase);
  retry.phase = ProdigyMaterializedStatefulRecoveryRetryPhase(phase);
  serializer.value8b(retry.updatedAtMs);
}

enum class ApiCredentialExpirySeverity : uint8_t {
  warning,
  expired,
};

class ApiCredentialExpiryNotice {
public:
  uint64_t stableID = 0;
  uint16_t applicationID = 0;
  String name;
  String provider;
  uint64_t generation = 0;
  int64_t deadlineMs = 0;
  int64_t createdAtMs = 0;
  ApiCredentialExpirySeverity severity = ApiCredentialExpirySeverity::warning;
  bool acknowledged = false;
  bool resolved = false;
};

template <typename S>
static void serialize(S&& serializer, ApiCredentialExpiryNotice& notice)
{
  serializer.value8b(notice.stableID);
  serializer.value2b(notice.applicationID);
  serializer.text1b(notice.name, UINT32_MAX);
  serializer.text1b(notice.provider, UINT32_MAX);
  serializer.value8b(notice.generation);
  serializer.value8b(notice.deadlineMs);
  serializer.value8b(notice.createdAtMs);
  serializer.value1b(notice.severity);
  serializer.value1b(notice.acknowledged);
  serializer.value1b(notice.resolved);
}

// One shared payload is used for Brain delivery, Mothership acknowledgement,
// and Mothership snapshot requests. It deliberately has no credential material.
class ApiCredentialExpiryNoticePayload {
public:
  uint128_t clusterUUID = 0;
  ApiCredentialExpiryNotice notice;
  bool includeAcknowledged = false;
  bool requestSnapshot = false;
  bool acknowledge = false;
  bool snapshotComplete = false;
};

template <typename S>
static void serialize(S&& serializer, ApiCredentialExpiryNoticePayload& payload)
{
  serializer.value16b(payload.clusterUUID);
  serializer.object(payload.notice);
  serializer.value1b(payload.includeAcknowledged);
  serializer.value1b(payload.requestSnapshot);
  serializer.value1b(payload.acknowledge);
  serializer.value1b(payload.snapshotComplete);
}

class ProdigyDeploymentPlacementPolicy {
public:
  uint16_t applicationID = 0;
  uint64_t versionID = 0;
  String operationID;
  Vector<uint128_t> eligibleMachineUUIDs;
};

template <typename S>
static void serialize(S&& serializer, ProdigyDeploymentPlacementPolicy& policy)
{
  serializer.value2b(policy.applicationID);
  serializer.value8b(policy.versionID);
  serializer.text1b(policy.operationID, 36);
  serializer.container(policy.eligibleMachineUUIDs, 256, [](auto& nested, uint128_t& uuid) {
    nested.value16b(uuid);
  });
}

class CommitDeploymentPlacementPolicyResponse {
public:
  bool success = false;
  uint64_t durableGeneration = 0;
  String failure;
  ProdigyDeploymentPlacementPolicy policy;
};

template <typename S>
static void serialize(S&& serializer, CommitDeploymentPlacementPolicyResponse& response)
{
  serializer.value1b(response.success);
  serializer.value8b(response.durableGeneration);
  serializer.text1b(response.failure, 4096);
  serializer.object(response.policy);
}

static inline bool prodigyDeploymentPlacementPolicyValid(const ProdigyDeploymentPlacementPolicy& policy)
{
  if (policy.applicationID == 0 || policy.versionID == 0 ||
      prodigyCanonicalOperationUUID(policy.operationID) == false ||
      policy.eligibleMachineUUIDs.empty() || policy.eligibleMachineUUIDs.size() > 256)
  {
    return false;
  }
  uint128_t previous = 0;
  for (uint128_t machineUUID : policy.eligibleMachineUUIDs)
  {
    if (machineUUID == 0 || (previous != 0 && machineUUID <= previous)) return false;
    previous = machineUUID;
  }
  return true;
}

static inline bool prodigyDeploymentPlacementPoliciesEqual(
    const Vector<ProdigyDeploymentPlacementPolicy>& lhs,
    const Vector<ProdigyDeploymentPlacementPolicy>& rhs)
{
  if (lhs.size() != rhs.size()) return false;
  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    if (lhs[index].applicationID != rhs[index].applicationID ||
        lhs[index].versionID != rhs[index].versionID ||
        lhs[index].operationID.equals(rhs[index].operationID) == false ||
        lhs[index].eligibleMachineUUIDs != rhs[index].eligibleMachineUUIDs)
    {
      return false;
    }
  }
  return true;
}

// This is a durable receipt for the restricted, non-task target admission
// path.  It is deliberately outside positional DeploymentPlan bytes: old
// plans remain decodable and an operation cannot be inferred from a plan ID.
class ProdigyStatelessDeploymentAdmission {
public:
  uint128_t operationID = 0;
  uint128_t clusterUUID = 0;
  uint64_t deploymentID = 0;
  uint16_t applicationID = 0;
  uint64_t versionID = 0;
  String requestPlanSHA256;
  String normalizedPlanSHA256;
  String artifactSHA256;
  uint64_t artifactBytes = 0;
  uint64_t acceptedAuthorityGeneration = 0;
  uint128_t acceptedMasterUUID = 0;
  int64_t acceptedMasterBootNs = 0;
};

template <typename S>
static void serialize(S&& serializer, ProdigyStatelessDeploymentAdmission& admission)
{
  serializer.value16b(admission.operationID);
  serializer.value16b(admission.clusterUUID);
  serializer.value8b(admission.deploymentID);
  serializer.value2b(admission.applicationID);
  serializer.value8b(admission.versionID);
  serializer.text1b(admission.requestPlanSHA256, 64);
  serializer.text1b(admission.normalizedPlanSHA256, 64);
  serializer.text1b(admission.artifactSHA256, 64);
  serializer.value8b(admission.artifactBytes);
  serializer.value8b(admission.acceptedAuthorityGeneration);
  serializer.value16b(admission.acceptedMasterUUID);
  serializer.value8b(admission.acceptedMasterBootNs);
}

static inline bool prodigyStatelessDeploymentAdmissionValid(const ProdigyStatelessDeploymentAdmission& admission)
{
  return admission.operationID != 0 && admission.clusterUUID != 0 &&
         admission.deploymentID != 0 && admission.applicationID != 0 && admission.versionID != 0 &&
         ApplicationConfig::extractApplicationID(admission.deploymentID) == admission.applicationID &&
         admission.requestPlanSHA256.size() == 64 && admission.normalizedPlanSHA256.size() == 64 &&
         admission.artifactSHA256.size() == 64 && admission.artifactBytes != 0 &&
         admission.acceptedAuthorityGeneration != 0 && admission.acceptedMasterUUID != 0 &&
         admission.acceptedMasterBootNs != 0;
}

static inline bool prodigyStatelessDeploymentAdmissionEqual(
    const ProdigyStatelessDeploymentAdmission& a,
    const ProdigyStatelessDeploymentAdmission& b)
{
  return a.operationID == b.operationID && a.clusterUUID == b.clusterUUID &&
         a.deploymentID == b.deploymentID && a.applicationID == b.applicationID && a.versionID == b.versionID &&
         a.requestPlanSHA256.equals(b.requestPlanSHA256) &&
         a.normalizedPlanSHA256.equals(b.normalizedPlanSHA256) &&
         a.artifactSHA256.equals(b.artifactSHA256) && a.artifactBytes == b.artifactBytes &&
         a.acceptedAuthorityGeneration == b.acceptedAuthorityGeneration &&
         a.acceptedMasterUUID == b.acceptedMasterUUID && a.acceptedMasterBootNs == b.acceptedMasterBootNs;
}

static inline bool prodigyStatelessDeploymentAdmissionsEqual(
    const Vector<ProdigyStatelessDeploymentAdmission>& lhs,
    const Vector<ProdigyStatelessDeploymentAdmission>& rhs)
{
  if (lhs.size() != rhs.size()) return false;
  for (uint32_t index = 0; index < lhs.size(); ++index)
    if (!prodigyStatelessDeploymentAdmissionEqual(lhs[index], rhs[index])) return false;
  return true;
}

static inline bool prodigyStatelessDeploymentAdmissionsValid(
    const Vector<ProdigyStatelessDeploymentAdmission>& admissions, uint64_t generation)
{
  if (admissions.size() > 4096) return false;
  for (uint32_t index = 0; index < admissions.size(); ++index)
  {
    if (!prodigyStatelessDeploymentAdmissionValid(admissions[index]) ||
        admissions[index].acceptedAuthorityGeneration > generation) return false;
    for (uint32_t earlier = 0; earlier < index; ++earlier)
      if (admissions[earlier].operationID == admissions[index].operationID ||
          admissions[earlier].deploymentID == admissions[index].deploymentID) return false;
  }
  return true;
}

// Immutable proof that a completed stateless successor retired one exact
// admitted predecessor. Plans and admission receipts remain independently owned.
class ProdigyStatelessDeploymentRetirement {
public:
  uint64_t predecessorDeploymentID = 0;
  uint64_t successorDeploymentID = 0;
  String predecessorPlanSHA256;
  String successorPlanSHA256;
  uint64_t completedAuthorityGeneration = 0;
};

template <typename S>
static void serialize(S&& serializer, ProdigyStatelessDeploymentRetirement& retirement)
{
  serializer.value8b(retirement.predecessorDeploymentID);
  serializer.value8b(retirement.successorDeploymentID);
  serializer.text1b(retirement.predecessorPlanSHA256, 64);
  serializer.text1b(retirement.successorPlanSHA256, 64);
  serializer.value8b(retirement.completedAuthorityGeneration);
}

static inline bool prodigyStatelessDeploymentRetirementsEqual(
    const Vector<ProdigyStatelessDeploymentRetirement>& a,
    const Vector<ProdigyStatelessDeploymentRetirement>& b)
{
  if (a.size() != b.size()) return false;
  for (uint32_t i = 0; i < a.size(); ++i)
    if (a[i].predecessorDeploymentID != b[i].predecessorDeploymentID ||
        a[i].successorDeploymentID != b[i].successorDeploymentID ||
        !a[i].predecessorPlanSHA256.equals(b[i].predecessorPlanSHA256) ||
        !a[i].successorPlanSHA256.equals(b[i].successorPlanSHA256) ||
        a[i].completedAuthorityGeneration != b[i].completedAuthorityGeneration) return false;
  return true;
}

// The predecessor must be bound to its immutable admission. A successor
// without an admission is legal; its exact plan must be checked by the Brain
// against the authoritative plan store before accepting the transition.
static inline bool prodigyStatelessDeploymentRetirementsValid(
    const Vector<ProdigyStatelessDeploymentRetirement>& retirements,
    const Vector<ProdigyStatelessDeploymentAdmission>& admissions, uint64_t generation)
{
  if (retirements.size() > 4096) return false;
  for (uint32_t i = 0; i < retirements.size(); ++i)
  {
    const auto& r = retirements[i];
    const uint16_t app = ApplicationConfig::extractApplicationID(r.predecessorDeploymentID);
    if (!r.predecessorDeploymentID || !r.successorDeploymentID ||
        r.successorDeploymentID <= r.predecessorDeploymentID || !app ||
        app != ApplicationConfig::extractApplicationID(r.successorDeploymentID) ||
        !prodigyIsSHA256HexDigest(r.predecessorPlanSHA256) ||
        !prodigyIsSHA256HexDigest(r.successorPlanSHA256) ||
        !r.completedAuthorityGeneration || r.completedAuthorityGeneration > generation) return false;
    bool predecessorFound = false;
    for (const auto& admission : admissions)
    {
      if (admission.deploymentID == r.predecessorDeploymentID)
      {
        if (predecessorFound || !admission.normalizedPlanSHA256.equals(r.predecessorPlanSHA256) ||
            admission.acceptedAuthorityGeneration >= r.completedAuthorityGeneration) return false;
        predecessorFound = true;
      }
      if (admission.deploymentID == r.successorDeploymentID &&
          (!admission.normalizedPlanSHA256.equals(r.successorPlanSHA256) ||
           admission.acceptedAuthorityGeneration >= r.completedAuthorityGeneration)) return false;
    }
    if (!predecessorFound) return false;
    for (uint32_t earlier = 0; earlier < i; ++earlier)
      if (retirements[earlier].predecessorDeploymentID == r.predecessorDeploymentID) return false;
  }
  return true;
}

class ProdigyStatelessDeploymentAdmissionRequest {
public:
  uint8_t version = 1;
  uint128_t operationID = 0;
  uint128_t clusterUUID = 0;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  String requestPlanSHA256;
  String artifactSHA256;
  uint64_t artifactBytes = 0;
};

template <typename S>
static void serialize(S&& serializer, ProdigyStatelessDeploymentAdmissionRequest& request)
{
  serializer.value1b(request.version);
  serializer.value16b(request.operationID);
  serializer.value16b(request.clusterUUID);
  serializer.value8b(request.expectedAuthorityGeneration);
  serializer.value16b(request.expectedMasterUUID);
  serializer.value8b(request.expectedMasterBootNs);
  serializer.text1b(request.requestPlanSHA256, 64);
  serializer.text1b(request.artifactSHA256, 64);
  serializer.value8b(request.artifactBytes);
}


class StatelessDeploymentAdmissionReceipt {
public:
  uint8_t version = 2;
  bool supported = true;
  bool peersCapable = false;
  bool accepted = false;
  String failure;
  ProdigyStatelessDeploymentAdmission admission;
  uint64_t currentAuthorityGeneration = 0;
  uint128_t currentMasterUUID = 0;
  int64_t currentMasterBootNs = 0;
  uint32_t nTarget = 0;
  uint32_t nDeployed = 0;
  uint32_t nHealthy = 0;
  bool live = false;
  bool launchPending = false;
};

template <typename S>
static void serialize(S&& serializer, StatelessDeploymentAdmissionReceipt& receipt)
{
  serializer.value1b(receipt.version);
  serializer.value1b(receipt.supported);
  serializer.value1b(receipt.peersCapable);
  serializer.value1b(receipt.accepted);
  serializer.text1b(receipt.failure, 4096);
  serializer.object(receipt.admission);
  serializer.value8b(receipt.currentAuthorityGeneration);
  serializer.value16b(receipt.currentMasterUUID);
  serializer.value8b(receipt.currentMasterBootNs);
  serializer.value4b(receipt.nTarget);
  serializer.value4b(receipt.nDeployed);
  serializer.value4b(receipt.nHealthy);
  serializer.value1b(receipt.live);
  serializer.value1b(receipt.launchPending);
}


constexpr uint32_t ProdigyMachineFragmentAssignmentMaximumRecords = 65'535;

class ProdigyMachineFragmentAssignment {
public:

  uint128_t machineUUID = 0;
  uint32_t fragment = 0;

  bool operator==(const ProdigyMachineFragmentAssignment& other) const
  {
    return machineUUID == other.machineUUID && fragment == other.fragment;
  }

  bool operator!=(const ProdigyMachineFragmentAssignment& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyMachineFragmentAssignment& assignment)
{
  serializer.value16b(assignment.machineUUID);
  serializer.value4b(assignment.fragment);
}

static inline bool prodigyMachineFragmentAssignmentsValid(
    const Vector<ProdigyMachineFragmentAssignment>& assignments)
{
  if (assignments.size() > ProdigyMachineFragmentAssignmentMaximumRecords)
  {
    return false;
  }

  bytell_hash_set<uint32_t> fragments;
  fragments.reserve(assignments.size());
  uint128_t previousUUID = 0;
  for (uint32_t index = 0; index < assignments.size(); ++index)
  {
    const ProdigyMachineFragmentAssignment& assignment = assignments[index];
    if (assignment.machineUUID == 0 || assignment.fragment == 0 || assignment.fragment > 0x00ffffffu ||
        (index > 0 && assignment.machineUUID <= previousUUID) ||
        fragments.insert(assignment.fragment).second == false)
    {
      return false;
    }
    previousUUID = assignment.machineUUID;
  }
  return true;
}

constexpr uint32_t ProdigyCousinRouteMaximumRecords = 256;

// Route UUID is the durable collection identity.  Store records in that
// canonical order so a quorum never has two encodings for the same authority
// set.  CousinRouteRecord validates the complete immutable route scope and its
// operation-history invariants.
static inline bool prodigyCousinRoutesValid(const Vector<CousinRouteRecord>& routes)
{
  if (routes.size() > ProdigyCousinRouteMaximumRecords) return false;
  uint128_t previousRouteUUID = 0;
  for (uint32_t index = 0; index < routes.size(); ++index)
  {
    if (!cousinRouteStructurallyValid(routes[index]) ||
        !cousinRouteCurrentContract(routes[index]) ||
        (index != 0 && routes[index].routeUUID <= previousRouteUUID))
    {
      return false;
    }
    if (!cousinRouteTerminal(routes[index]))
      for (uint32_t other = 0; other < index; ++other)
        if (!cousinRouteTerminal(routes[other]) &&
            cousinRoutePeerRangeScopeMatches(routes[other], routes[index])) return false;
    previousRouteUUID = routes[index].routeUUID;
  }
  return true;
}

static inline bool prodigyCousinRoutesValid(const Vector<CousinRouteRecord>& routes,
                                            uint128_t localClusterUUID)
{
  if (prodigyCousinRoutesValid(routes) == false) return false;
  // Legacy and not-yet-configured Brains may restore an authority package
  // before they have a local cluster identity. An empty route set has no
  // cluster binding to validate; any materialized route still fails closed.
  if (routes.empty()) return true;
  if (localClusterUUID == 0) return false;
  for (const CousinRouteRecord& route : routes)
    if (route.sourceClusterUUID != localClusterUUID && route.destinationClusterUUID != localClusterUUID)
      return false;
  return true;
}

static inline bool prodigyCousinRoutesEqual(const Vector<CousinRouteRecord>& lhs,
                                            const Vector<CousinRouteRecord>& rhs)
{
  if (lhs.size() != rhs.size()) return false;
  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    String left = {}, right = {};
    CousinRouteRecord leftCopy = lhs[index], rightCopy = rhs[index];
    BitseryEngine::serialize(left, leftCopy);
    BitseryEngine::serialize(right, rightCopy);
    if (left != right) return false;
  }
  return true;
}

enum class CrossClusterMasqueGatewayState : uint8_t { active = 1, withdrawn = 2 };
enum class CrossClusterMasqueGatewayRole : uint8_t { listener = 1, connector = 2 };

static inline IPPrefix prodigyContainerDatacenterSitePrefix(uint8_t datacenterFragment)
{
  IPPrefix prefix = {};
  static constexpr uint8_t containerNetworkPrefix[11] = CONTAINER_NETWORK_SUBNET6;
  std::memcpy(prefix.network.v6, containerNetworkPrefix, sizeof(containerNetworkPrefix));
  prefix.network.v6[11] = datacenterFragment;
  prefix.network.is6 = true;
  prefix.cidr = 96;
  return prefix;
}

static inline bool prodigyContainerDatacenterSitePrefixValid(const IPPrefix& prefix, uint8_t datacenterFragment)
{
  return datacenterFragment != 0 && prefix.network.is6 && prefix.cidr == 96 &&
      prefix.equals(prefix.canonicalized()) && prefix.equals(prodigyContainerDatacenterSitePrefix(datacenterFragment));
}

class CrossClusterMasqueGatewayAuthority {
public:
  static constexpr uint32_t version = 3;
  uint32_t protocolVersion = version;
  uint128_t pairUUID = 0, pairOperationUUID = 0;
  uint128_t localClusterUUID = 0, peerClusterUUID = 0;
  uint128_t localMachineUUID = 0, peerMachineUUID = 0;
  uint8_t localDatacenterFragment = 0, peerDatacenterFragment = 0;
  IPPrefix localSitePrefix = {}, peerSitePrefix = {};
  String artifactSHA256, localIdentitySHA256, peerIdentitySHA256, peerTrustSHA256;
  uint64_t artifactBytes = 0, generation = 0, pairAuthorityGeneration = 0, keyGeneration = 0;
  IPAddress listenerPublicUDPEndpoint = {};
  uint16_t listenerPublicUDPPort = 0;
  // Mothership-derived private BGP tuple.  None of these are CLI-selected:
  // the /127 is deterministic for the enrolled pair/slot and the credential
  // reference is minted by the credential owner for this key generation.
  // gatewaySlot identifies the durable local host slot; tunnelSlot identifies
  // one path within a site pair.  A host can therefore carry one authority to
  // each remote site without sharing a BGP interface.
  uint8_t tunnelSlot = 0;
  String privateTunnelInterface;
  IPAddress privateTunnelLocalIPv6 = {}, privateTunnelPeerIPv6 = {};
  uint16_t privateLocalASN = 0, privatePeerASN = 0;
  uint32_t privateLocalBGPID = 0, privatePeerBGPID = 0;
  String privateSessionCredentialSHA256;
  CrossClusterMasqueGatewayRole localRole = CrossClusterMasqueGatewayRole::listener;
  CrossClusterMasqueGatewayState state = CrossClusterMasqueGatewayState::active;
  uint8_t gatewaySlot = 0;
};
template <typename S> static void serialize(S&& s, CrossClusterMasqueGatewayAuthority& r) {
  s.value4b(r.protocolVersion); s.value16b(r.pairUUID); s.value16b(r.pairOperationUUID); s.value16b(r.localClusterUUID); s.value16b(r.peerClusterUUID); s.value16b(r.localMachineUUID); s.value16b(r.peerMachineUUID);
  s.value1b(r.localDatacenterFragment); s.value1b(r.peerDatacenterFragment); s.object(r.localSitePrefix); s.object(r.peerSitePrefix); s.text1b(r.artifactSHA256, 64); s.value8b(r.artifactBytes); s.object(r.listenerPublicUDPEndpoint); s.value2b(r.listenerPublicUDPPort); s.value1b(r.tunnelSlot); s.text1b(r.privateTunnelInterface, 15); s.object(r.privateTunnelLocalIPv6); s.object(r.privateTunnelPeerIPv6); s.value2b(r.privateLocalASN); s.value2b(r.privatePeerASN); s.value4b(r.privateLocalBGPID); s.value4b(r.privatePeerBGPID); s.text1b(r.privateSessionCredentialSHA256, 64); s.text1b(r.localIdentitySHA256, 64); s.text1b(r.peerIdentitySHA256, 64); s.text1b(r.peerTrustSHA256, 64); s.value8b(r.generation); s.value8b(r.pairAuthorityGeneration); s.value8b(r.keyGeneration); s.value1b(r.localRole); s.value1b(r.state);
  // Version three append: old records cannot silently acquire a host slot.
  s.value1b(r.gatewaySlot);
}

enum class ProdigyCrossClusterPathFaultDirection : uint8_t { localToPeer = 1, peerToLocal = 2 };
enum class ProdigyCrossClusterPathFaultGatewayLifecyclePhase : uint8_t { prepared = 1, suspended = 2, restored = 3, restoreNeeded = 4 };
class ProdigyCrossClusterPathFaultRequest { public: static constexpr uint32_t version = 1; static constexpr uint32_t leaseVersion = 2; uint32_t protocolVersion = version; uint128_t operationUUID = 0; CrossClusterMasqueGatewayAuthority authority; ProdigyCrossClusterPathFaultDirection direction = ProdigyCrossClusterPathFaultDirection::localToPeer; ProdigyPairPrivateBGPSecretScope scope; String flowIdentity; uint64_t expiresAtMilliseconds = 0; };
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPathFaultRequest& value) { s.value4b(value.protocolVersion); s.value16b(value.operationUUID); s.object(value.authority); s.value1b(value.direction); s.object(value.scope); s.text1b(value.flowIdentity, 256); if (value.protocolVersion >= ProdigyCrossClusterPathFaultRequest::leaseVersion) s.value8b(value.expiresAtMilliseconds); }
class ProdigyCrossClusterPathFaultGatewayLifecycleRecord { public: static constexpr uint32_t version = 1; uint32_t protocolVersion = version; ProdigyCrossClusterPathFaultRequest request; SystemContainerRuntimePlan admittedPlan; uint128_t retiringContainerUUID = 0; uint128_t replacementContainerUUID = 0; uint64_t admittedLaunchGeneration = 0; ProdigyCrossClusterPathFaultGatewayLifecyclePhase phase = ProdigyCrossClusterPathFaultGatewayLifecyclePhase::prepared; };
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPathFaultGatewayLifecycleRecord& value) { s.value4b(value.protocolVersion); s.object(value.request); s.object(value.admittedPlan); s.value16b(value.retiringContainerUUID); s.value16b(value.replacementContainerUUID); s.value8b(value.admittedLaunchGeneration); s.value1b(value.phase); }

// Ephemeral readiness is carried independently of the durable gateway
// authority.  It lives with the authority schema because Brain and Neuron
// both retain the same receipt, while route helpers merely consume it.
class ProdigyCrossClusterMasqueGatewayReadiness {
public:
  uint128_t pairUUID = 0;
  uint128_t localClusterUUID = 0;
  uint128_t localMachineUUID = 0;
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  uint64_t gatewayGeneration = 0;
  bool authenticatedMasqueQUICReady = false;
};

template <typename S> static void serialize(S&& s, ProdigyCrossClusterMasqueGatewayReadiness& r) {
  s.value16b(r.pairUUID); s.value16b(r.localClusterUUID); s.value16b(r.localMachineUUID);
  s.value8b(r.keyEpoch); s.value8b(r.authorityGeneration); s.value8b(r.gatewayGeneration);
  s.value1b(r.authenticatedMasqueQUICReady);
}

static inline bool prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(const CrossClusterMasqueGatewayAuthority& a)
{
  return a.protocolVersion == CrossClusterMasqueGatewayAuthority::version && a.pairUUID != 0 && a.pairOperationUUID != 0 &&
      a.localClusterUUID != 0 && a.peerClusterUUID != 0 && a.localClusterUUID != a.peerClusterUUID &&
      a.localMachineUUID != 0 && a.peerMachineUUID != 0 && a.localMachineUUID != a.peerMachineUUID &&
      a.localDatacenterFragment != 0 && a.peerDatacenterFragment != 0 && a.localDatacenterFragment != a.peerDatacenterFragment &&
      prodigyContainerDatacenterSitePrefixValid(a.localSitePrefix, a.localDatacenterFragment) &&
      prodigyContainerDatacenterSitePrefixValid(a.peerSitePrefix, a.peerDatacenterFragment) && !a.localSitePrefix.equals(a.peerSitePrefix) &&
      prodigyIsSHA256HexDigest(a.artifactSHA256) && a.artifactBytes != 0 && !a.listenerPublicUDPEndpoint.isNull() && a.listenerPublicUDPPort != 0 &&
      a.tunnelSlot < 3 && a.gatewaySlot < 3 && a.privateTunnelInterface.size() != 0 && a.privateTunnelInterface.size() <= 15 &&
      a.privateTunnelLocalIPv6.is6 && a.privateTunnelPeerIPv6.is6 && !a.privateTunnelLocalIPv6.isNull() && !a.privateTunnelPeerIPv6.isNull() && !a.privateTunnelLocalIPv6.equals(a.privateTunnelPeerIPv6) &&
      a.privateLocalASN != 0 && a.privatePeerASN != 0 && a.privateLocalBGPID != 0 && a.privatePeerBGPID != 0 && prodigyIsSHA256HexDigest(a.privateSessionCredentialSHA256) &&
      prodigyIsSHA256HexDigest(a.localIdentitySHA256) && prodigyIsSHA256HexDigest(a.peerIdentitySHA256) &&
      prodigyIsSHA256HexDigest(a.peerTrustSHA256) && a.generation != 0 && a.pairAuthorityGeneration != 0 && a.keyGeneration != 0 &&
      (a.localRole == CrossClusterMasqueGatewayRole::listener || a.localRole == CrossClusterMasqueGatewayRole::connector) &&
      (a.state == CrossClusterMasqueGatewayState::active || a.state == CrossClusterMasqueGatewayState::withdrawn);
}

// Derive the non-secret private BGP tuple from the immutable pair and selected
// host identities. Registry owns credential minting; Brain and Neuron use this
// same derivation only to reject an authority that claims a peer replacement
// without the tuple that follows from that peer.
static inline bool prodigyDeriveCrossClusterMasquePrivateBGPTuple(
    CrossClusterMasqueGatewayAuthority& authority)
{
  if (authority.pairUUID == 0 || authority.localMachineUUID == 0 || authority.peerMachineUUID == 0 ||
      authority.localMachineUUID == authority.peerMachineUUID || authority.keyGeneration == 0 ||
      authority.gatewaySlot >= 3 || authority.tunnelSlot >= 3) return false;
  const uint128_t orderedLow = std::min(authority.localMachineUUID, authority.peerMachineUUID);
  const uint128_t orderedHigh = std::max(authority.localMachineUUID, authority.peerMachineUUID);
  String interfaceScope = {}, interfaceHash = {}, slot = {};
  interfaceScope.assignItoh(authority.pairUUID); interfaceScope.append("/"_ctv);
  slot.assignItoa(authority.tunnelSlot); interfaceScope.append(slot);
  if (!prodigyComputeSHA256Hex(interfaceScope, interfaceHash)) return false;
  // Pair-scoped and reciprocal. The full scope is hashed because a Linux
  // interface name has a 15-byte limit; topology validation rejects any
  // collision for a host which carries two pair-distinct paths.
  authority.privateTunnelInterface.assign("mtbgp"_ctv);
  authority.privateTunnelInterface.append(interfaceHash.substr(0, 10, Copy::no));
  // fd5a:4d53 is reserved for authenticated MASQUE site links; a /127 is
  // selected from the pair UUID and tunnelSlot. gatewaySlot identifies the
  // durable local host while tunnelSlot identifies its path.
  IPAddress first = {}, second = {};
  first.is6 = second.is6 = true;
  const uint64_t pair = uint64_t(authority.pairUUID);
  first.v6[0] = second.v6[0] = 0xfd; first.v6[1] = second.v6[1] = 0x5a;
  first.v6[2] = second.v6[2] = 0x4d; first.v6[3] = second.v6[3] = 0x53;
  for (uint32_t i = 0; i < 8; ++i) first.v6[4 + i] = second.v6[4 + i] = uint8_t(pair >> ((7 - i) * 8));
  first.v6[12] = second.v6[12] = authority.tunnelSlot;
  first.v6[15] = 0; second.v6[15] = 1;
  const bool localFirst = authority.localMachineUUID < authority.peerMachineUUID;
  authority.privateTunnelLocalIPv6 = localFirst ? first : second;
  authority.privateTunnelPeerIPv6 = localFirst ? second : first;
  const uint16_t lowASN = uint16_t(42000 + (uint64_t(orderedLow) % 20000));
  const uint16_t highASN = uint16_t(42000 + (uint64_t(orderedHigh) % 20000));
  authority.privateLocalASN = localFirst ? lowASN : highASN;
  authority.privatePeerASN = localFirst ? highASN : lowASN;
  authority.privateLocalBGPID = uint32_t(uint64_t(authority.localMachineUUID)) | 1u;
  authority.privatePeerBGPID = uint32_t(uint64_t(authority.peerMachineUUID)) | 1u;
  // Credential material is deliberately not derivable from public IDs.
  authority.privateSessionCredentialSHA256.clear();
  return true;
}

static inline bool prodigyCrossClusterMasqueGatewayPrivateBGPTupleMatches(
    const CrossClusterMasqueGatewayAuthority& authority)
{
  auto expected = authority;
  if (!prodigyDeriveCrossClusterMasquePrivateBGPTuple(expected)) return false;
  return authority.privateTunnelInterface == expected.privateTunnelInterface &&
      authority.privateTunnelLocalIPv6.equals(expected.privateTunnelLocalIPv6) &&
      authority.privateTunnelPeerIPv6.equals(expected.privateTunnelPeerIPv6) &&
      authority.privateLocalASN == expected.privateLocalASN &&
      authority.privatePeerASN == expected.privatePeerASN &&
      authority.privateLocalBGPID == expected.privateLocalBGPID &&
      authority.privatePeerBGPID == expected.privatePeerBGPID;
}

// The selected Neuron binds these launch-only fields directly from its current
// committed authority after admitting the typed system-container plan. They do
// not accept caller-rendered identity strings.
static inline bool prodigyBindCrossClusterMasqueGatewayRuntimePlanAuthority(
    SystemContainerRuntimePlan& plan, const CrossClusterMasqueGatewayAuthority& authority)
{
  if (plan.kind != SystemContainerKind::crossClusterMasqueGateway ||
      !prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) ||
      authority.state != CrossClusterMasqueGatewayState::active)
  {
    return false;
  }
  plan.gatewayPairUUID = authority.pairUUID;
  plan.gatewayLocalClusterUUID = authority.localClusterUUID;
  plan.gatewayLocalMachineUUID = authority.localMachineUUID;
  plan.gatewayKeyEpoch = authority.keyGeneration;
  plan.gatewayAuthorityGeneration = authority.pairAuthorityGeneration;
  plan.gatewayGeneration = authority.generation;
  plan.gatewayTunnelInterface.assign(authority.privateTunnelInterface);
  return true;
}

static inline bool prodigyCrossClusterMasqueGatewayRuntimePlanAuthorityConfigured(
    const SystemContainerRuntimePlan& plan)
{
  return plan.kind == SystemContainerKind::crossClusterMasqueGateway &&
      plan.gatewayPairUUID != 0 && plan.gatewayLocalClusterUUID != 0 &&
      plan.gatewayLocalMachineUUID != 0 && plan.gatewayKeyEpoch != 0 &&
      plan.gatewayAuthorityGeneration != 0 && plan.gatewayGeneration != 0 &&
      plan.gatewayTunnelInterface.size() != 0 && plan.gatewayTunnelInterface.size() <= 15;
}

// Render numeric plan references only at the exec boundary. This keeps the
// fields bounded. Rust's u128::from_str_radix(value, 16) consumes digits, not
// the 0x-prefixed spelling used by Mothership's public CLI.
static inline bool prodigyAppendCrossClusterMasqueGatewayAuthorityEnvironment(
    const SystemContainerRuntimePlan& plan, Vector<String>& environment)
{
  if (!prodigyCrossClusterMasqueGatewayRuntimePlanAuthorityConfigured(plan)) return false;
  auto append = [&environment](StringType auto&& key, const String& value) {
    String assignment = {};
    assignment.assign(key);
    assignment.append(value);
    environment.push_back(std::move(assignment));
  };
  String pairUUID = {}, localClusterUUID = {}, localMachineUUID = {};
  String keyEpoch = {}, authorityGeneration = {}, gatewayGeneration = {};
  pairUUID.assignItoh(plan.gatewayPairUUID);
  localClusterUUID.assignItoh(plan.gatewayLocalClusterUUID);
  localMachineUUID.assignItoh(plan.gatewayLocalMachineUUID);
  keyEpoch.assignItoa(plan.gatewayKeyEpoch);
  authorityGeneration.assignItoa(plan.gatewayAuthorityGeneration);
  gatewayGeneration.assignItoa(plan.gatewayGeneration);
  append("PRODIGY_MASQUE_PAIR_UUID="_ctv, pairUUID.substr(2, pairUUID.size() - 2, Copy::no));
  append("PRODIGY_MASQUE_LOCAL_CLUSTER_UUID="_ctv, localClusterUUID.substr(2, localClusterUUID.size() - 2, Copy::no));
  append("PRODIGY_MASQUE_LOCAL_MACHINE_UUID="_ctv, localMachineUUID.substr(2, localMachineUUID.size() - 2, Copy::no));
  append("PRODIGY_MASQUE_KEY_EPOCH="_ctv, keyEpoch);
  append("PRODIGY_MASQUE_AUTHORITY_GENERATION="_ctv, authorityGeneration);
  append("PRODIGY_MASQUE_GATEWAY_GENERATION="_ctv, gatewayGeneration);
  append("PRODIGY_MASQUE_TUN_INTERFACE="_ctv, plan.gatewayTunnelInterface);
  return true;
}
static inline bool prodigyCrossClusterMasqueGatewayAuthorityScopeMatches(
    const CrossClusterMasqueGatewayAuthority& a,
    const CrossClusterMasqueGatewayAuthority& b,
    bool allowCredentialRotation = false)
{
  return a.pairUUID == b.pairUUID && a.pairOperationUUID == b.pairOperationUUID &&
      a.localClusterUUID == b.localClusterUUID && a.peerClusterUUID == b.peerClusterUUID &&
      a.localMachineUUID == b.localMachineUUID && a.peerMachineUUID == b.peerMachineUUID &&
      a.localDatacenterFragment == b.localDatacenterFragment &&
      a.peerDatacenterFragment == b.peerDatacenterFragment &&
      a.localSitePrefix.equals(b.localSitePrefix) && a.peerSitePrefix.equals(b.peerSitePrefix) &&
      a.tunnelSlot == b.tunnelSlot && a.gatewaySlot == b.gatewaySlot && a.privateTunnelInterface == b.privateTunnelInterface &&
      a.privateTunnelLocalIPv6.equals(b.privateTunnelLocalIPv6) && a.privateTunnelPeerIPv6.equals(b.privateTunnelPeerIPv6) &&
      a.privateLocalASN == b.privateLocalASN && a.privatePeerASN == b.privatePeerASN &&
      a.privateLocalBGPID == b.privateLocalBGPID && a.privatePeerBGPID == b.privatePeerBGPID &&
      (allowCredentialRotation || a.privateSessionCredentialSHA256 == b.privateSessionCredentialSHA256) &&
      a.localRole == b.localRole;
}
static inline bool prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(
    const CrossClusterMasqueGatewayAuthority& previous,
    const CrossClusterMasqueGatewayAuthority& next)
{
  const bool reactivation = previous.state == CrossClusterMasqueGatewayState::withdrawn &&
      next.state == CrossClusterMasqueGatewayState::active;
  const bool peerReplacement = reactivation && previous.peerMachineUUID != next.peerMachineUUID &&
      previous.pairUUID == next.pairUUID && previous.pairOperationUUID == next.pairOperationUUID &&
      previous.localClusterUUID == next.localClusterUUID && previous.peerClusterUUID == next.peerClusterUUID &&
      previous.localMachineUUID == next.localMachineUUID &&
      previous.localDatacenterFragment == next.localDatacenterFragment &&
      previous.peerDatacenterFragment == next.peerDatacenterFragment &&
      previous.localSitePrefix.equals(next.localSitePrefix) && previous.peerSitePrefix.equals(next.peerSitePrefix) &&
      previous.tunnelSlot == next.tunnelSlot && previous.gatewaySlot == next.gatewaySlot &&
      previous.localRole == next.localRole &&
      previous.pairAuthorityGeneration == next.pairAuthorityGeneration &&
      previous.keyGeneration == next.keyGeneration &&
      previous.privateSessionCredentialSHA256 != next.privateSessionCredentialSHA256 &&
      prodigyCrossClusterMasqueGatewayPrivateBGPTupleMatches(next);
  if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(previous) ||
      !prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(next) ||
      (!prodigyCrossClusterMasqueGatewayAuthorityScopeMatches(previous, next, reactivation) && !peerReplacement) ||
      (previous.state != CrossClusterMasqueGatewayState::active && !reactivation) ||
      next.generation <= previous.generation ||
      next.pairAuthorityGeneration < previous.pairAuthorityGeneration ||
      next.keyGeneration < previous.keyGeneration)
  {
    return false;
  }
  return next.state == CrossClusterMasqueGatewayState::active ||
      next.state == CrossClusterMasqueGatewayState::withdrawn;
}
static inline bool prodigyCrossClusterMasqueGatewayAuthoritiesValid(const Vector<CrossClusterMasqueGatewayAuthority>& records, uint128_t localClusterUUID)
{
  if (records.size() > ProdigyCrossClusterMasqueGatewayAuthorityMaximumRecords) return false;
  uint128_t previousPair = 0, previousMachine = 0;
  for (uint32_t i = 0; i < records.size(); ++i) {
    const auto& r = records[i];
    if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(r) || (localClusterUUID != 0 && r.localClusterUUID != localClusterUUID) ||
        (i != 0 && (r.pairUUID < previousPair || (r.pairUUID == previousPair && r.localMachineUUID <= previousMachine)))) return false;
    previousPair = r.pairUUID; previousMachine = r.localMachineUUID;
    // Withdrawal tombstones retain their exact generation and pair history,
    // but no longer claim one of the two live gateway slots.  Brain keeps the
    // process slot fenced until authenticated inventory or the terminal kill
    // acknowledgement proves that the withdrawn runtime is absent.
    if (r.state != CrossClusterMasqueGatewayState::active) continue;
    uint32_t machineAuthorities = 0;
    for (uint32_t other = 0; other < records.size(); ++other) {
      if (other == i) continue;
      const auto& candidate = records[other];
      if (candidate.localMachineUUID != r.localMachineUUID ||
          candidate.state != CrossClusterMasqueGatewayState::active) continue;
      if (candidate.pairUUID == r.pairUUID || candidate.privateTunnelInterface == r.privateTunnelInterface) return false;
      ++machineAuthorities;
    }
    if (machineAuthorities >= 2) return false;
  }
  return true;
}
static inline bool prodigyCrossClusterMasqueGatewayAuthoritiesEqual(const Vector<CrossClusterMasqueGatewayAuthority>& lhs, const Vector<CrossClusterMasqueGatewayAuthority>& rhs)
{
  if (lhs.size() != rhs.size()) return false;
  for (uint32_t i = 0; i < lhs.size(); ++i) { String a, b; auto ac = lhs[i], bc = rhs[i]; BitseryEngine::serialize(a, ac); BitseryEngine::serialize(b, bc); if (a != b) return false; }
  return true;
}

// The durable ledger is sorted by pair UUID and retains withdrawal
// tombstones. Ranking the supplied set keeps an existing process on its
// reserved fragment while a withdrawn runtime is still terminally fenced.
// Brain supplies its machine-local effective set after that fence; the raw
// durable ledger deliberately does not reclaim or renumber a slot by itself.
static inline uint8_t prodigyCrossClusterMasqueGatewayRuntimeFragment(
    const Vector<CrossClusterMasqueGatewayAuthority>& records,
    uint128_t pairUUID,
    uint128_t localMachineUUID)
{
  if (pairUUID == 0 || localMachineUUID == 0) return 0;
  uint8_t rank = 0;
  bool found = false;
  for (const auto& record : records)
  {
    if (record.localMachineUUID != localMachineUUID) continue;
    if (record.pairUUID == pairUUID) found = true;
    else if (record.pairUUID < pairUUID) ++rank;
  }
  if (!found || rank > 1) return 0;
  return rank == 0 ? prodigyCrossClusterMasqueGatewayRuntimeFragmentFirst :
      prodigyCrossClusterMasqueGatewayRuntimeFragmentSecond;
}

static inline SystemContainerEgressPolicy prodigyCrossClusterMasqueGatewayEgressPolicy(
    const CrossClusterMasqueGatewayAuthority& authority)
{
  SystemContainerEgressPolicy policy = {};
  policy.port = authority.listenerPublicUDPPort;
  policy.protocol = IPPROTO_UDP;
  policy.peerIsIPv6 = authority.listenerPublicUDPEndpoint.is6;
  policy.allowIngressFromPeer =
      authority.localRole == CrossClusterMasqueGatewayRole::listener;
  if (policy.peerIsIPv6)
    std::memcpy(policy.address6, authority.listenerPublicUDPEndpoint.v6,
                sizeof(policy.address6));
  else
    policy.address4 = ntohl(authority.listenerPublicUDPEndpoint.v4);
  return policy;
}

// The public listener is an ordinary single-target UDP portal.  Its only
// authority is the current, registry-validated listener endpoint.
static inline bool prodigyCrossClusterMasqueGatewayWormholes(
    const CrossClusterMasqueGatewayAuthority& authority, Vector<Wormhole>& result)
{
  result.clear();
  if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) ||
      authority.state != CrossClusterMasqueGatewayState::active) return false;
  if (authority.localRole == CrossClusterMasqueGatewayRole::connector) return true;
  Wormhole endpoint = {};
  endpoint.externalAddress = authority.listenerPublicUDPEndpoint;
  endpoint.externalPort = authority.listenerPublicUDPPort;
  endpoint.containerPort = authority.listenerPublicUDPPort;
  endpoint.layer4 = IPPROTO_UDP;
  endpoint.isQuic = false; // Route by tuple, not by the application QUIC CID.
  result.push_back(std::move(endpoint));
  return true;
}

static inline bool prodigyCrossClusterMasqueGatewayWormholesMatch(
    const CrossClusterMasqueGatewayAuthority& authority, const Vector<Wormhole>& actual)
{
  Vector<Wormhole> expected = {};
  String expectedBytes = {}, actualBytes = {};
  auto copy = actual;
  return prodigyCrossClusterMasqueGatewayWormholes(authority, expected) &&
      BitseryEngine::serialize(expectedBytes, expected) &&
      BitseryEngine::serialize(actualBytes, copy) && expectedBytes == actualBytes;
}

static inline bool prodigyCrossClusterMasqueGatewayWhiteholesValid(
    const CrossClusterMasqueGatewayAuthority& authority, const Vector<Whitehole>& whiteholes)
{
  if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) ||
      authority.state != CrossClusterMasqueGatewayState::active) return false;
  if (authority.localRole == CrossClusterMasqueGatewayRole::listener) return whiteholes.empty();
  if (whiteholes.size() != 1 || !resolvedWhiteholesValid(whiteholes)) return false;
  const Whitehole& source = whiteholes[0];
  return source.transport == ExternalAddressTransport::quic &&
      source.source == ExternalAddressSource::hostPublicAddress &&
      source.address.is6 == authority.listenerPublicUDPEndpoint.is6;
}

// This is a Brain-to-selected-Neuron control projection, not another durable
// ledger.  The empty snapshot is deliberately valid so a removed/stale record
// withdraws the local /96 rather than surviving a control reconnect.
class ProdigyCrossClusterMasqueGatewayAuthorityProjection {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  Vector<CrossClusterMasqueGatewayAuthority> authorities;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterMasqueGatewayAuthorityProjection& p) {
  s.value4b(p.protocolVersion);
  s.container(p.authorities, ProdigyCrossClusterMasqueGatewayAuthorityMaximumRecords,
      [](auto& nested, CrossClusterMasqueGatewayAuthority& authority) { nested.object(authority); });
}
static inline bool prodigyCrossClusterMasqueGatewayAuthorityProjectionValid(
    const ProdigyCrossClusterMasqueGatewayAuthorityProjection& projection,
    uint128_t localClusterUUID)
{
  return projection.protocolVersion == ProdigyCrossClusterMasqueGatewayAuthorityProjection::version &&
      prodigyCrossClusterMasqueGatewayAuthoritiesValid(projection.authorities, localClusterUUID);
}

static inline bool prodigyCrossClusterMasqueGatewayAuthorityProjectionValidForMachine(
    const ProdigyCrossClusterMasqueGatewayAuthorityProjection& projection,
    uint128_t localClusterUUID, uint128_t localMachineUUID)
{
  if (localMachineUUID == 0 || projection.authorities.size() > 2 ||
      !prodigyCrossClusterMasqueGatewayAuthorityProjectionValid(projection, localClusterUUID)) return false;
  for (const auto& authority : projection.authorities)
    if (authority.localMachineUUID != localMachineUUID) return false;
  return true;
}

class ProdigyCrossClusterMasqueGatewayAuthorityRequest {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  CrossClusterMasqueGatewayAuthority authority;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterMasqueGatewayAuthorityRequest& r) { s.value4b(r.protocolVersion); s.object(r.authority); }
class ProdigyCrossClusterMasqueGatewayAuthorityQuery {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version; uint128_t pairUUID = 0, localMachineUUID = 0;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterMasqueGatewayAuthorityQuery& q) { s.value4b(q.protocolVersion); s.value16b(q.pairUUID); s.value16b(q.localMachineUUID); }
class ProdigyCrossClusterMasqueGatewayAuthorityResponse : public MothershipResponse {
public:
  uint128_t localClusterUUID = 0; uint64_t currentAuthorityGeneration = 0; bool found = false, qualified = false;
  CrossClusterMasqueGatewayAuthority authority;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterMasqueGatewayAuthorityResponse& r) { s.value1b(r.success); s.text1b(r.failure, 4096); s.value16b(r.localClusterUUID); s.value8b(r.currentAuthorityGeneration); s.value1b(r.found); s.value1b(r.qualified); s.object(r.authority); }

// An opt-in desired membership.  This is deliberately not a writer grant:
// only Truth's committed Raft configuration can elect and publish a leader.
#define PRODIGY_TRUTH_GLOBAL_MEMBERSHIP_VERSION 1
enum class TruthGlobalMemberRole : uint8_t { voter = 1, learner = 2 };
class TruthGlobalMember {
public:
  int32_t memberID = 0;
  uint128_t clusterUUID = 0, containerUUID = 0;
  IPAddress privateIPv6 = {};
  TruthGlobalMemberRole role = TruthGlobalMemberRole::voter;
};
template <typename S> static void serialize(S&& s, TruthGlobalMember& v) {
  s.value4b(v.memberID); s.value16b(v.clusterUUID); s.value16b(v.containerUUID); s.object(v.privateIPv6); s.value1b(v.role);
}
class TruthGlobalMembershipProjection {
public:
  static constexpr uint32_t version = PRODIGY_TRUTH_GLOBAL_MEMBERSHIP_VERSION;
  uint32_t protocolVersion = version;
  uint128_t membershipUUID = 0, operationUUID = 0, localClusterUUID = 0;
  uint64_t deploymentID = 0, generation = 0, expectedCommittedConfigIndex = 0;
  String expectedCommittedConfigSHA256;
  // Stable for the lifetime of this group, including after voter replacement.
  std::array<int32_t, 3> genesisMemberIDs{};
  int32_t highestAllocatedMemberID = 0;
  Vector<TruthGlobalMember> members;
  Vector<int32_t> retiredMemberIDs;
  bool replacementPending = false;
};
template <typename S> static void serialize(S&& s, TruthGlobalMembershipProjection& v) {
  s.value4b(v.protocolVersion); s.value16b(v.membershipUUID); s.value16b(v.operationUUID); s.value16b(v.localClusterUUID);
  s.value8b(v.deploymentID); s.value8b(v.generation); s.value8b(v.expectedCommittedConfigIndex);
  s.text1b(v.expectedCommittedConfigSHA256, 64);
  for (auto& id : v.genesisMemberIDs) s.value4b(id);
  s.value4b(v.highestAllocatedMemberID);
  s.container(v.members, 4); s.container4b(v.retiredMemberIDs, 256);
  s.value1b(v.replacementPending);
}
static inline bool prodigyTruthGlobalMembershipProjectionValid(const TruthGlobalMembershipProjection& v) {
  if (v.protocolVersion != TruthGlobalMembershipProjection::version || v.membershipUUID == 0 || v.localClusterUUID == 0 ||
      !v.operationUUID || uint16_t(v.deploymentID >> 48) != 10 || v.generation == 0 || v.expectedCommittedConfigIndex == 0 ||
      !prodigyIsSHA256HexDigest(v.expectedCommittedConfigSHA256) || v.members.empty() || v.members.size() > 4 || v.retiredMemberIDs.size() > 256) return false;
  if (v.genesisMemberIDs[0] <= 0 || v.genesisMemberIDs[0] >= v.genesisMemberIDs[1] ||
      v.genesisMemberIDs[1] >= v.genesisMemberIDs[2] || v.highestAllocatedMemberID < v.genesisMemberIDs[2]) return false;
  int32_t prior = 0; uint32_t voters = 0; bool local = false;
  for (const auto& member : v.members) {
    if (member.memberID <= 0 || member.memberID <= prior || member.memberID > v.highestAllocatedMemberID || member.clusterUUID == 0 ||
        member.containerUUID == 0 || !member.privateIPv6.is6 || member.privateIPv6.isNull() ||
        (member.role != TruthGlobalMemberRole::voter && member.role != TruthGlobalMemberRole::learner)) return false;
    if (member.role == TruthGlobalMemberRole::voter) ++voters;
    if (member.clusterUUID == v.localClusterUUID) local = true;
    for (const auto& earlier : v.members) {
      if (earlier.memberID >= member.memberID) break;
      if (earlier.containerUUID == member.containerUUID || earlier.privateIPv6.equals(member.privateIPv6)) return false;
    }
    prior = member.memberID;
  }
  prior = 0;
  for (int32_t retired : v.retiredMemberIDs) {
    if (retired <= 0 || retired <= prior || retired > v.highestAllocatedMemberID ||
        std::any_of(v.members.begin(), v.members.end(), [retired](const auto& m) { return m.memberID == retired; })) return false;
    prior = retired;
  }
  if (!local) return false;
  if (voters == 3) return v.members.size() == 3 || v.replacementPending;
  // The old voter has been removed and the caught-up learner is awaiting
  // promotion. Both remaining voters must participate in this transition.
  return v.replacementPending && voters == 2 && v.members.size() == 3;
}
// Member IDs are storage incarnations. An endpoint cannot acquire an old
// vote by changing the binding in a newer launch plan.
static inline bool prodigyTruthMembershipSuccessor(const TruthGlobalMembershipProjection& old,
                                                   const TruthGlobalMembershipProjection& next) {
  if (old.membershipUUID != next.membershipUUID || old.localClusterUUID != next.localClusterUUID ||
      old.deploymentID != next.deploymentID || old.genesisMemberIDs != next.genesisMemberIDs ||
      next.highestAllocatedMemberID < old.highestAllocatedMemberID ||
      next.generation < old.generation || next.expectedCommittedConfigIndex < old.expectedCommittedConfigIndex ||
      (next.expectedCommittedConfigIndex == old.expectedCommittedConfigIndex &&
       !next.expectedCommittedConfigSHA256.equals(old.expectedCommittedConfigSHA256))) return false;
  // The durable high-water mark keeps retired IDs fenced even after their
  // individual cleanup receipts have aged out of the bounded projection.
  for (const auto& member : next.members)
    if (member.memberID <= old.highestAllocatedMemberID &&
        std::none_of(old.members.begin(), old.members.end(), [&](const auto& m) { return m.memberID == member.memberID; }))
      return false;
  for (const auto& before : old.members) {
    auto after = std::find_if(next.members.begin(), next.members.end(),
                              [&](const auto& member) { return member.memberID == before.memberID; });
    if (after == next.members.end()) {
      if (!std::binary_search(next.retiredMemberIDs.begin(), next.retiredMemberIDs.end(), before.memberID)) return false;
    } else if (after->containerUUID != before.containerUUID || after->clusterUUID != before.clusterUUID ||
               !after->privateIPv6.equals(before.privateIPv6)) return false;
  }
  return true;
}
static inline bool prodigyTruthLocalMember(const TruthGlobalMembershipProjection& group, uint64_t deployment,
    uint128_t container) {
  if (group.deploymentID != deployment || !prodigyTruthGlobalMembershipProjectionValid(group)) return false;
  return std::any_of(group.members.begin(), group.members.end(), [&](const auto& m) {
    return m.clusterUUID == group.localClusterUUID && m.containerUUID == container;
  });
}
class CommitTruthGlobalMembershipResponse : public MothershipResponse {
public:
  uint64_t durableGeneration = 0;
  TruthGlobalMembershipProjection projection;
};
template <typename S> static void serialize(S&& s, CommitTruthGlobalMembershipResponse& v) {
  s.value1b(v.success); s.text1b(v.failure, 4096); s.value8b(v.durableGeneration); s.object(v.projection);
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
  ProdigyResumptionRegistry::SnapshotMap tlsResumptionSnapshotsByWormhole;
  Vector<ProdigyPendingAddMachinesOperation> pendingAddMachinesOperations;
  Vector<ProdigyPendingAddMachinesProvisioningIntent> pendingAddMachinesProvisioningIntents;
  Vector<ProdigyPendingAutonomousProvisioningOperation> pendingAutonomousProvisioningOperations;
  Vector<ProdigyPendingElasticAddressAssignment> pendingElasticAddressAssignments;
  Vector<ProdigyPendingElasticAddressRelease> pendingElasticAddressReleases;
  Vector<ProdigyStatefulWorkerTopologyUpgradeOperation> statefulWorkerTopologyUpgradeOperations;
  Vector<ProdigyStatefulServingAuthority> statefulServingAuthorities;
  Vector<ProdigyDeferredStatefulScaleIntent> deferredStatefulScaleIntents;
  Vector<ProdigyMaterializedStatefulRecoveryOperation> materializedStatefulRecoveryOperations;
  Vector<ProdigyMaterializedStatefulRecoveryRetry> materializedStatefulRecoveryRetries;
  // Immutable proof sidecars for the retained-deployment mode of the existing
  // materialized recovery operation ledger.  Lifecycle phase remains owned by
  // materializedStatefulRecoveryOperations; this vector is not another state
  // machine.
  Vector<ProdigyRetainedStatefulRearmProof> retainedStatefulRearmProofs;
  Vector<ApiCredentialExpiryNotice> apiCredentialExpiryNotices;
  Vector<ProdigyManagedMachineSchema> machineSchemas;
  Vector<RoutableResourceLease> routableResourceLeases;
  Vector<PublicTlsCertificateState> publicTlsCertificates;
  Vector<PrivateTlsVaultLifecycleState> privateTlsVaultLifecycles;
  bytell_hash_map<uint64_t, TaskExecutionRecord> taskExecutions;
  MothershipTunnelProviderDesiredState mothershipTunnelProviderDesiredState;
  ProdigyPersistentUpdateSelfState updateSelf;
  // Version-six master-authority tail.  This registry is deliberately separate
  // from positional DeploymentPlan bytes.
  Vector<ProdigyDeploymentPlacementPolicy> deploymentPlacementPolicies;
  // Version-twenty-five desired Truth membership projections.  Pending means
  // exactly that: Brain must not turn this admin input into a voting config.
  Vector<TruthGlobalMembershipProjection> truthGlobalMembershipProjections;
  Vector<ProdigyStatelessDeploymentAdmission> statelessDeploymentAdmissions;
  Vector<ProdigyStatelessDeploymentRetirement> statelessDeploymentRetirements;
  // Zero is the pre-v21 unlimited follower behavior. Explicit requests use
  // one or two and persist their durable transition/readiness checkpoints.
  uint8_t updateSelfFollowerConcurrency = 0;
  Vector<uint128_t> updateSelfFollowerTransitionIssuedPeerKeys;
  Vector<uint128_t> updateSelfFollowerReadyPeerKeys;
  // Durable enrollment metadata only; its root is private snapshot material.
  Vector<ProdigyClusterPairEnrollment> clusterPairEnrollments;
  Vector<ProdigyClusterPairEnrollmentOperation> clusterPairEnrollmentOperations;
  // Version-fifteen local deployment policy records.  They carry no pair
  // root, epoch, endpoint, or traffic key material.
  Vector<ProdigyLocalCousinServicePermission> localCousinServicePermissions;
  // Durable container-network identity. Entries are canonical by machine UUID
  // and retained after retirement so a 24-bit prefix is never reassigned.
  Vector<ProdigyMachineFragmentAssignment> machineFragmentAssignments;
  // Public enrollment ledger; its one authority root is in the snapshot sidecar.
  Vector<ProdigyTransportCredentialEnrollment> transportCredentialEnrollments;
  Vector<ProdigyTransportCredentialEnrollmentOperation> transportCredentialEnrollmentOperations;
  // Version-eighteen replicated route authority.  These are canonical public
  // authorization records, not route-application receipts or secret material.
  Vector<CousinRouteRecord> cousinRoutes;
  // Version-twenty append-only local gateway authority ledger. Tombstones are
  // newer records, never erasures, so replay cannot resurrect a gateway.
  Vector<CrossClusterMasqueGatewayAuthority> crossClusterMasqueGatewayAuthorities;
  // Never serialized in this public runtime record. Persistence extracts it to
  // ProdigyPersistentBrainSnapshotSecrets before writing the snapshot.
  ProdigyTransportCredentialAuthorityRoot transportCredentialAuthorityRoot;

  bool crossClusterMasqueGatewayAuthorityPairCurrent(const CrossClusterMasqueGatewayAuthority& authority) const
  {
    const auto enrollment = std::find_if(clusterPairEnrollments.begin(),
        clusterPairEnrollments.end(), [&](const auto& value) {
          return value.pairUUID == authority.pairUUID && value.operationUUID == authority.pairOperationUUID &&
              value.localClusterUUID == authority.localClusterUUID && value.peerClusterUUID == authority.peerClusterUUID;
        });
    if (enrollment == clusterPairEnrollments.end() ||
        enrollment->state != ProdigyClusterPairEnrollmentState::active ||
        enrollment->localAuthorityGeneration != authority.pairAuthorityGeneration ||
        enrollment->agreedKeyEpoch != authority.keyGeneration) return false;
    const auto operation = std::find_if(clusterPairEnrollmentOperations.begin(),
        clusterPairEnrollmentOperations.end(), [&](const auto& value) {
          return value.pairUUID == authority.pairUUID && value.operationUUID == authority.pairOperationUUID;
        });
    return operation != clusterPairEnrollmentOperations.end() &&
        operation->localAuthorityGeneration == authority.pairAuthorityGeneration &&
        operation->initialProjectionDelivered && !operation->revocationRequested && !operation->projectionsWithdrawn;
  }

  bool operator==(const ProdigyMasterAuthorityRuntimeState& other) const
  {
    if (generation != other.generation || hasCompletedInitialMasterElection != other.hasCompletedInitialMasterElection || transportTLSAuthority != other.transportTLSAuthority || nextMintedClientTlsGeneration != other.nextMintedClientTlsGeneration || nextTlsResumptionGeneration != other.nextTlsResumptionGeneration || nextPendingAddMachinesOperationID != other.nextPendingAddMachinesOperationID || nextPendingElasticAddressOperationID != other.nextPendingElasticAddressOperationID || nextDNSIntentRevision != other.nextDNSIntentRevision || tlsResumptionSnapshotsByWormhole.size() != other.tlsResumptionSnapshotsByWormhole.size() || pendingAddMachinesOperations.size() != other.pendingAddMachinesOperations.size() || pendingAddMachinesProvisioningIntents.size() != other.pendingAddMachinesProvisioningIntents.size() || pendingAutonomousProvisioningOperations.size() != other.pendingAutonomousProvisioningOperations.size() || pendingElasticAddressAssignments.size() != other.pendingElasticAddressAssignments.size() || pendingElasticAddressReleases.size() != other.pendingElasticAddressReleases.size() || statefulWorkerTopologyUpgradeOperations.size() != other.statefulWorkerTopologyUpgradeOperations.size() || statefulServingAuthorities.size() != other.statefulServingAuthorities.size() || deferredStatefulScaleIntents.size() != other.deferredStatefulScaleIntents.size() || materializedStatefulRecoveryOperations.size() != other.materializedStatefulRecoveryOperations.size() || materializedStatefulRecoveryRetries.size() != other.materializedStatefulRecoveryRetries.size() || retainedStatefulRearmProofs.size() != other.retainedStatefulRearmProofs.size() || apiCredentialExpiryNotices.size() != other.apiCredentialExpiryNotices.size() || machineSchemas.size() != other.machineSchemas.size() || routableResourceLeases.size() != other.routableResourceLeases.size() || publicTlsCertificates.size() != other.publicTlsCertificates.size() || privateTlsVaultLifecycles.size() != other.privateTlsVaultLifecycles.size() || taskExecutions.size() != other.taskExecutions.size() || mothershipTunnelProviderDesiredState != other.mothershipTunnelProviderDesiredState || updateSelf != other.updateSelf || updateSelfFollowerConcurrency != other.updateSelfFollowerConcurrency || updateSelfFollowerTransitionIssuedPeerKeys != other.updateSelfFollowerTransitionIssuedPeerKeys || updateSelfFollowerReadyPeerKeys != other.updateSelfFollowerReadyPeerKeys ||
        prodigyDeploymentPlacementPoliciesEqual(deploymentPlacementPolicies, other.deploymentPlacementPolicies) == false ||
        prodigyStatelessDeploymentAdmissionsEqual(statelessDeploymentAdmissions, other.statelessDeploymentAdmissions) == false ||
        prodigyStatelessDeploymentRetirementsEqual(statelessDeploymentRetirements, other.statelessDeploymentRetirements) == false ||
        prodigyClusterPairEnrollmentsEqual(clusterPairEnrollments, other.clusterPairEnrollments) == false ||
        clusterPairEnrollmentOperations.size() != other.clusterPairEnrollmentOperations.size() ||
        prodigyLocalCousinServicePermissionsEqual(localCousinServicePermissions, other.localCousinServicePermissions) == false ||
        machineFragmentAssignments != other.machineFragmentAssignments ||
        transportCredentialEnrollments != other.transportCredentialEnrollments ||
        transportCredentialEnrollmentOperations.size() != other.transportCredentialEnrollmentOperations.size() ||
        prodigyCousinRoutesEqual(cousinRoutes, other.cousinRoutes) == false ||
        prodigyCrossClusterMasqueGatewayAuthoritiesEqual(crossClusterMasqueGatewayAuthorities, other.crossClusterMasqueGatewayAuthorities) == false ||
        truthGlobalMembershipProjections.size() != other.truthGlobalMembershipProjections.size() ||
        transportCredentialAuthorityRoot.authorityEpoch != other.transportCredentialAuthorityRoot.authorityEpoch ||
        transportCredentialAuthorityRoot.keyEpoch != other.transportCredentialAuthorityRoot.keyEpoch ||
        transportCredentialAuthorityRoot.authorityGeneration != other.transportCredentialAuthorityRoot.authorityGeneration ||
        CRYPTO_memcmp(transportCredentialAuthorityRoot.root, other.transportCredentialAuthorityRoot.root,
                      ProdigyTransportCredentialAuthorityRootBytes) != 0)
    {
      return false;
    }
    for (uint32_t index = 0; index < clusterPairEnrollmentOperations.size(); ++index)
    {
      String left = {}, right = {};
      auto leftCopy = clusterPairEnrollmentOperations[index]; auto rightCopy = other.clusterPairEnrollmentOperations[index];
      BitseryEngine::serialize(left, leftCopy); BitseryEngine::serialize(right, rightCopy);
      if (left != right) return false;
    }

    for (uint32_t index = 0; index < transportCredentialEnrollmentOperations.size(); ++index)
    {
      const auto& left = transportCredentialEnrollmentOperations[index]; const auto& right = other.transportCredentialEnrollmentOperations[index];
      if (!(left == right)) return false;
    }
    for (uint32_t index = 0; index < truthGlobalMembershipProjections.size(); ++index)
    {
      String left = {}, right = {};
      auto a = truthGlobalMembershipProjections[index], b = other.truthGlobalMembershipProjections[index];
      BitseryEngine::serialize(left, a); BitseryEngine::serialize(right, b);
      if (left != right) return false;
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

    for (uint32_t index = 0; index < pendingAddMachinesProvisioningIntents.size(); ++index)
    {
      if (pendingAddMachinesProvisioningIntents[index] != other.pendingAddMachinesProvisioningIntents[index])
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

    for (uint32_t index = 0; index < statefulServingAuthorities.size(); ++index)
    {
      if (statefulServingAuthorities[index] != other.statefulServingAuthorities[index]) return false;
    }

    for (uint32_t index = 0; index < deferredStatefulScaleIntents.size(); ++index)
    {
      if (deferredStatefulScaleIntents[index] != other.deferredStatefulScaleIntents[index])
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < materializedStatefulRecoveryOperations.size(); ++index)
    {
      const auto& a = materializedStatefulRecoveryOperations[index];
      const auto& b = other.materializedStatefulRecoveryOperations[index];
      if (a.operationID.equals(b.operationID) == false ||
          a.activeDeploymentID != b.activeDeploymentID ||
          a.successorDeploymentID != b.successorDeploymentID ||
          a.successorBlobSHA256.equals(b.successorBlobSHA256) == false ||
          a.accepted != b.accepted ||
          a.started != b.started ||
          a.completed != b.completed ||
          a.updatedAtMs != b.updatedAtMs)
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < materializedStatefulRecoveryRetries.size(); ++index)
    {
      const auto& a = materializedStatefulRecoveryRetries[index];
      const auto& b = other.materializedStatefulRecoveryRetries[index];
      if (a.operationID.equals(b.operationID) == false ||
          a.activeDeploymentID != b.activeDeploymentID ||
          a.failedSuccessorDeploymentID != b.failedSuccessorDeploymentID ||
          a.failedSuccessorBlobSHA256.equals(b.failedSuccessorBlobSHA256) == false ||
          a.replacementSuccessorDeploymentID != b.replacementSuccessorDeploymentID ||
          a.replacementSuccessorBlobSHA256.equals(b.replacementSuccessorBlobSHA256) == false ||
          a.source.sourceContainerUUID != b.source.sourceContainerUUID ||
          a.source.failedSuccessorContainerUUID != b.source.failedSuccessorContainerUUID ||
          a.source.machineUUID != b.source.machineUUID ||
          a.source.sourceDevice != b.source.sourceDevice || a.source.sourceInode != b.source.sourceInode ||
          a.source.sourceUID != b.source.sourceUID || a.source.sourceGID != b.source.sourceGID ||
          a.source.sourcePID != b.source.sourcePID ||
          a.source.captureSHA256.equals(b.source.captureSHA256) == false ||
          a.retryContainerUUID != b.retryContainerUUID || a.phase != b.phase || a.updatedAtMs != b.updatedAtMs)
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < retainedStatefulRearmProofs.size(); ++index)
    {
      if (!prodigyRetainedStatefulRearmProofEqual(
              retainedStatefulRearmProofs[index], other.retainedStatefulRearmProofs[index]))
      {
        return false;
      }
    }

    for (uint32_t index = 0; index < apiCredentialExpiryNotices.size(); ++index)
    {
      const auto& a = apiCredentialExpiryNotices[index];
      const auto& b = other.apiCredentialExpiryNotices[index];
      if (a.stableID != b.stableID ||
          a.applicationID != b.applicationID ||
          a.name.equals(b.name) == false ||
          a.provider.equals(b.provider) == false ||
          a.generation != b.generation ||
          a.deadlineMs != b.deadlineMs ||
          a.createdAtMs != b.createdAtMs ||
          a.severity != b.severity ||
          a.acknowledged != b.acknowledged ||
          a.resolved != b.resolved)
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

class BrainReplicatedContainerRuntimeState;

static inline bool prodigyRetainedStatefulRearmProofsValid(
    const ProdigyMasterAuthorityRuntimeState& state)
{
  if (state.retainedStatefulRearmProofs.size() > 4096) return false;
  for (const auto& operation : state.materializedStatefulRecoveryOperations)
  {
    if (operation.activeDeploymentID != 0) continue;
    uint32_t matchingProofs = 0;
    for (const auto& proof : state.retainedStatefulRearmProofs)
      matchingProofs += proof.scope.operationID.equals(operation.operationID);
    if (matchingProofs != 1) return false;
  }
  for (uint32_t index = 0; index < state.retainedStatefulRearmProofs.size(); ++index)
  {
    const auto& proof = state.retainedStatefulRearmProofs[index];
    if (!prodigyRetainedStatefulRearmProofValid(proof) ||
        proof.scope.expectedAuthorityGeneration >= state.generation)
    {
      return false;
    }
    uint32_t matchingOperations = 0;
    for (const auto& operation : state.materializedStatefulRecoveryOperations)
    {
      if (!operation.operationID.equals(proof.scope.operationID)) continue;
      if (operation.activeDeploymentID != 0 ||
          operation.successorDeploymentID != proof.scope.deploymentID ||
          !operation.successorBlobSHA256.equals(proof.scope.artifactSHA256) ||
          !operation.accepted || !operation.started)
      {
        return false;
      }
      ++matchingOperations;
    }
    if (matchingOperations != 1) return false;
    for (uint32_t earlier = 0; earlier < index; ++earlier)
    {
      const auto& prior = state.retainedStatefulRearmProofs[earlier].scope;
      if (prior.operationID.equals(proof.scope.operationID) ||
          prior.deploymentID == proof.scope.deploymentID)
      {
        return false;
      }
    }
  }
  return true;
}

template <typename S>
static void prodigySerializeMasterAuthorityRuntimeState(
    S&& serializer,
    ProdigyMasterAuthorityRuntimeState& state,
    Vector<BrainReplicatedContainerRuntimeState> *containerRuntimeStates,
    Vector<BrainReplicatedContainerRuntimeState> *servingRuntimeStates);

template <typename S>
static void serialize(S&& serializer, ProdigyMasterAuthorityRuntimeState& state)
{
  prodigySerializeMasterAuthorityRuntimeState(serializer, state, nullptr, nullptr);
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

static inline bool prodigyBuildCousinWormholeDesiredState(
    const Vector<Wormhole>& wormholes, bool isStateful, uint64_t cousinService,
    const bytell_hash_map<uint64_t, Advertisement>& advertisements, SwitchboardWormholeDesiredState& state,
    bool requireResolvedAddresses = true)
{
  state = {};
  SwitchboardWormholeDesiredState desired = {};
  desired.wormholes = wormholes;
  if (isStateful)
  {
    for (const auto& [protectedService, definition] : advertisements)
    {
      const uint16_t app = cousinRouteServiceApplicationID(protectedService);
      // Retained database listeners and sharded database clients are private
      // authenticated services, not public application endpoints.
      const bool shardedClient = (app == 3 || app == 4) &&
          MeshServices::convertShardToPrefix(protectedService) == prodigyCousinClientAuthorityPrefix(app);
      if (protectedService != cousinService && app != 2 && app != 5 && app != 10 && !shardedClient) continue;
      // The definition controls first publication, even before the service's
      // active lifecycle state. Waiting for healthy would expose an open port.
      const uint16_t port = definition.port;
      if (port == 0 && !wormholes.empty()) return false;
      bool exposed = false;
      for (const Wormhole& wormhole : wormholes)
        if (wormhole.containerPort == port) exposed = true;
      if (exposed)
      {
        if (definition.service != protectedService) return false;
        for (const auto& [service, advertisement] : advertisements)
          if (service != protectedService && advertisement.port == port) return false;
        desired.pairAdmissionTCPPorts.push_back(port);
      }
    }
    std::sort(desired.pairAdmissionTCPPorts.begin(), desired.pairAdmissionTCPPorts.end());
  }
  if (!prodigyWormholeDesiredStateValid(desired, requireResolvedAddresses)) return false;
  state = std::move(desired);
  return true;
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

  // Append-only seed authority. A zero protocolVersion is the explicit
  // absence until a remote seed is scheduled, including initial all-master boot.
  ProdigyStatefulStoreSeedAuthority statefulStoreSeedAuthority = {.protocolVersion = 0};
  // Desired-only global Truth membership. Truth independently verifies its
  // committed Raft configuration before making this active.
  TruthGlobalMembershipProjection truthMembership = {.protocolVersion = 0};
  uint64_t declaredStatefulClientService = 0;
  uint16_t declaredStatefulClientPort = 0;

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
  if (plan.statefulTopology.servingMode == StatefulTopologyServingMode::applicationDataAuthority) {
    serializer.value8b(plan.declaredStatefulClientService);
    serializer.value2b(plan.declaredStatefulClientPort);
  }
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
  if constexpr (requires { serializer.adapter().isCompletedSuccessfully(); }) {
    bootstrap.plan.truthMembership = {.protocolVersion = 0};
    if (!serializer.adapter().isCompletedSuccessfully()) {
      serializer.object(bootstrap.plan.truthMembership);
      if (!prodigyTruthLocalMember(bootstrap.plan.truthMembership,bootstrap.plan.config.deploymentID(),bootstrap.plan.uuid) ||
          !serializer.adapter().isCompletedSuccessfully())
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
    }
  } else if (bootstrap.plan.truthMembership.protocolVersion) {
    serializer.object(bootstrap.plan.truthMembership);
  }
}

class BrainReplicatedContainerRuntimeState {
public:

  uint128_t machineUUID = 0;
  uint32_t machinePrivate4 = 0;
  ContainerPlan plan;
  uint16_t runtimeLogicalCores = 0;
  uint32_t runtimeMemoryMB = 0;
  uint32_t runtimeStorageMB = 0;
  String wormholeRuntimeRevision;
  String wormholeRuntimeDesired;
  Vector<uint32_t> wormholeRuntimePendingMachines;
  Vector<uint32_t> wormholeRuntimeFailedMachines;
  String wormholeRuntimeFailure;
  bool wormholeRuntimeFailureSuppressedReady = false;
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
  serializer.text1b(state.wormholeRuntimeRevision, 64);
  serializer.text1b(state.wormholeRuntimeDesired, SwitchboardWormholeOperation::maximumDesiredBytes);
  serializer.object(state.wormholeRuntimePendingMachines);
  serializer.object(state.wormholeRuntimeFailedMachines);
  serializer.text1b(state.wormholeRuntimeFailure, 4096);
  serializer.value1b(state.wormholeRuntimeFailureSuppressedReady);
}

// Package-only version-five framing keeps its optional container view inside the
// final runtime-state field, so legacy package records retain their exact outer
// boundary before metric samples.
template <typename S>
static void prodigySerializeMasterAuthorityRuntimeState(
    S&& serializer,
    ProdigyMasterAuthorityRuntimeState& state,
    Vector<BrainReplicatedContainerRuntimeState> *containerRuntimeStates,
    Vector<BrainReplicatedContainerRuntimeState> *servingRuntimeStates)
{
  constexpr uint64_t versionMarker = UINT64_MAX;
  // Versions 6-8 are the P6 placement/serving/admission layouts. The
  // divergent concurrency layout must never reuse version 6; version 9
  // appends its durable transition state after the cumulative P6 tails.
  // Version 10 appends cluster-pair enrollment descriptors; version 11
  // appends internal transport credential enrollment descriptors; version 12
  // appends durable pair-enrollment operations; version 13 permits their
  // revocation tail; version 14 adds explicitly agreed epoch rotation;
  // version 15 adds root-free, epoch-neutral local COUSIN deployment policy;
  // version 16 tags each transport operation row so lifecycle receipts cannot
  // be misread as the legacy enrollment layout; version 17 appends the
  // canonical machine-to-container-network-fragment registry; version 18
  // appends canonical replicated COUSIN route authority records; version 19
  // appends durable managed-machine create intent outside the legacy pending
  // add-machines record. Version 20 appends the Mothership-created local
  // MASQUE gateway authority ledger. Version 21 appends durable stateless
  // retirement receipts; version 22 appends immutable retained-deployment
  // re-arm proofs beside the existing recovery-operation ledger. Versions
  // 23/24 are decode-only: their retired database-repair tails must be empty.
  constexpr uint64_t explicitVersion = 25;
  using Serializer = std::remove_cv_t<std::remove_reference_t<S>>;
  if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
    state.transportCredentialAuthorityRoot = {};
  bool hasMaterializedStatefulRecoveryOperations = false;
  bool hasApiCredentialExpiryNotices = false;
  bool hasAllMachineRecoveryWitnesses = false;
  bool hasMaterializedStatefulRecoveryRetries = false;
  bool hasContainerRuntimeStates = false;
  bool hasDeploymentPlacementPolicies = false;
  bool hasStatefulServingAuthorities = false;
  bool hasStatelessDeploymentAdmissions = false;
  bool hasExplicitUpdateSelfFollowerConcurrency = false;
  bool hasClusterPairEnrollments = false;
  bool hasTransportCredentialEnrollments = false;
  bool hasClusterPairEnrollmentOperations = false;
  bool permitsClusterPairRevocationOperations = false;
  bool permitsClusterPairEpochOperations = false;
  bool hasLocalCousinServicePermissions = false;
  bool permitsTransportCredentialLifecycleOperations = false;
  bool hasMachineFragmentAssignments = false;
  bool hasCousinRoutes = false;
  bool hasPendingAddMachinesProvisioningIntents = false;
  bool hasCrossClusterMasqueGatewayAuthorities = false;
  bool hasStatelessDeploymentRetirements = false;
  bool hasRetainedStatefulRearmProofs = false;
  bool hasRetiredStoreSelections = false;
  bool hasRetiredMemberRepairs = false;
  bool hasTruthGlobalMembershipProjections = false;

  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    hasMaterializedStatefulRecoveryOperations = state.materializedStatefulRecoveryOperations.empty() == false;
    hasApiCredentialExpiryNotices = state.apiCredentialExpiryNotices.empty() == false;
    hasAllMachineRecoveryWitnesses = state.updateSelf.machineRecoveryWitnesses.empty() == false;
    hasMaterializedStatefulRecoveryRetries = state.materializedStatefulRecoveryRetries.empty() == false;
    hasDeploymentPlacementPolicies = state.deploymentPlacementPolicies.empty() == false;
    hasStatefulServingAuthorities = state.statefulServingAuthorities.empty() == false;
    hasStatelessDeploymentAdmissions = state.statelessDeploymentAdmissions.empty() == false;
    // The two merged histories used incompatible v6 layouts. Placement-only
    // state now uses the already cumulative v7 layout with empty serving tails.
    if (hasDeploymentPlacementPolicies) hasStatefulServingAuthorities = true;
    if (hasStatefulServingAuthorities) hasDeploymentPlacementPolicies = true;
    // Version eight is cumulative. Readers consume the v6 placement and v7
    // serving containers before the v8 admission tail, even when those older
    // collections are empty.
    if (hasStatelessDeploymentAdmissions)
    {
      hasDeploymentPlacementPolicies = true;
      hasStatefulServingAuthorities = true;
    }
    // Version six has a package-only container slot before the policy tail.
    // Emit that slot even when empty whenever the enclosing package supplies it.
    hasContainerRuntimeStates = containerRuntimeStates != nullptr &&
                                (containerRuntimeStates->empty() == false || hasDeploymentPlacementPolicies);
    // Version-four framing is cumulative: emit the earlier optional fields
    // (empty when unused) so a version-three reader has an unambiguous tail.
    hasClusterPairEnrollments = state.clusterPairEnrollments.empty() == false;
    hasClusterPairEnrollmentOperations = state.clusterPairEnrollmentOperations.empty() == false;
    const bool hasTransportCredentialLifecycleOperations = std::any_of(
        state.transportCredentialEnrollmentOperations.begin(), state.transportCredentialEnrollmentOperations.end(),
        [](const auto& operation) { return operation.protocolVersion >= 2; });
    hasMachineFragmentAssignments = state.machineFragmentAssignments.empty() == false;
    hasCousinRoutes = state.cousinRoutes.empty() == false;
    hasPendingAddMachinesProvisioningIntents = state.pendingAddMachinesProvisioningIntents.empty() == false;
    hasStatelessDeploymentRetirements = !state.statelessDeploymentRetirements.empty();
    hasTruthGlobalMembershipProjections = !state.truthGlobalMembershipProjections.empty();
    hasRetainedStatefulRearmProofs = !state.retainedStatefulRearmProofs.empty() || hasTruthGlobalMembershipProjections;
    hasCrossClusterMasqueGatewayAuthorities = !state.crossClusterMasqueGatewayAuthorities.empty() || hasStatelessDeploymentRetirements;
    // Version 22 is cumulative through the v21 retirement container. Emit
    // every earlier tail, even when empty, before the re-arm proof sidecar.
    if (hasRetainedStatefulRearmProofs)
    {
      hasStatelessDeploymentRetirements = true;
      hasCrossClusterMasqueGatewayAuthorities = true;
    }
    if (hasCrossClusterMasqueGatewayAuthorities) hasPendingAddMachinesProvisioningIntents = true;
    // Version nineteen is cumulative through the v18 route container.
    if (hasPendingAddMachinesProvisioningIntents) hasCousinRoutes = true;
    // Version eighteen is cumulative through the version-seventeen fragment
    // registry. Emit its bounded empty container when routes are present so
    // the reader cannot consume route bytes as fragment assignments.
    if (hasCousinRoutes) hasMachineFragmentAssignments = true;
    permitsTransportCredentialLifecycleOperations =
        hasTransportCredentialLifecycleOperations || hasMachineFragmentAssignments || hasCousinRoutes ||
        hasPendingAddMachinesProvisioningIntents;
    // Versions sixteen and seventeen include every earlier tail, even when empty.
    hasLocalCousinServicePermissions = !state.localCousinServicePermissions.empty() ||
                                       permitsTransportCredentialLifecycleOperations || hasCousinRoutes ||
                                       hasPendingAddMachinesProvisioningIntents;
    // Version fifteen is cumulative through the v12 operation container.
    // Emit that bounded empty container when the new policy tail is present.
    if (hasLocalCousinServicePermissions) hasClusterPairEnrollmentOperations = true;
    hasTransportCredentialEnrollments = state.transportCredentialEnrollments.empty() == false || state.transportCredentialEnrollmentOperations.empty() == false || hasClusterPairEnrollmentOperations || hasLocalCousinServicePermissions;
    // Version 11 retains the version-10 container even when there are no pairs.
    if (hasTransportCredentialEnrollments || hasClusterPairEnrollmentOperations || hasLocalCousinServicePermissions) hasClusterPairEnrollments = true;
    // Version 10 is cumulative and may use a zero concurrency placeholder
    // while retaining the pre-v21 unlimited behavior.
    hasExplicitUpdateSelfFollowerConcurrency = state.updateSelfFollowerConcurrency != 0 || hasClusterPairEnrollments || hasTransportCredentialEnrollments || hasClusterPairEnrollmentOperations;
    if (hasExplicitUpdateSelfFollowerConcurrency)
    {
      // Version nine is cumulative and retains P6's v6-v8 field order.
      hasDeploymentPlacementPolicies = true;
      hasStatefulServingAuthorities = true;
      hasStatelessDeploymentAdmissions = true;
      hasContainerRuntimeStates = containerRuntimeStates != nullptr;
    }
    // Version-four framing is cumulative: emit the earlier optional fields
    // (empty when unused) so a version-three reader has an unambiguous tail.
    if (hasAllMachineRecoveryWitnesses || hasMaterializedStatefulRecoveryRetries || hasContainerRuntimeStates || hasDeploymentPlacementPolicies || hasStatefulServingAuthorities || hasStatelessDeploymentAdmissions || hasExplicitUpdateSelfFollowerConcurrency)
    {
      hasMaterializedStatefulRecoveryOperations = true;
      hasApiCredentialExpiryNotices = true;
      hasAllMachineRecoveryWitnesses = true;
      hasMaterializedStatefulRecoveryRetries = true;
    }
    if (hasMaterializedStatefulRecoveryOperations || hasApiCredentialExpiryNotices || hasAllMachineRecoveryWitnesses || hasMaterializedStatefulRecoveryRetries || hasContainerRuntimeStates || hasDeploymentPlacementPolicies || hasStatefulServingAuthorities || hasStatelessDeploymentAdmissions || hasExplicitUpdateSelfFollowerConcurrency || hasPendingAddMachinesProvisioningIntents)
    {
      uint64_t marker = versionMarker;
      serializer.value8b(marker);

      const bool hasPairRevocationOperations = std::any_of(state.clusterPairEnrollmentOperations.begin(), state.clusterPairEnrollmentOperations.end(),
          [](const auto& operation) { return operation.protocolVersion >= 2; });
      const bool hasPairEpochOperations = std::any_of(state.clusterPairEnrollmentOperations.begin(), state.clusterPairEnrollmentOperations.end(),
          [](const auto& operation) { return operation.protocolVersion >= 3; });
      uint64_t version = 1;
      if (hasApiCredentialExpiryNotices) version = 2;
      if (hasAllMachineRecoveryWitnesses) version = 3;
      if (hasMaterializedStatefulRecoveryRetries) version = 4;
      if (hasContainerRuntimeStates) version = 5;
      if (hasDeploymentPlacementPolicies) version = 6;
      if (hasStatefulServingAuthorities) version = 7;
      if (hasStatelessDeploymentAdmissions) version = 8;
      if (hasExplicitUpdateSelfFollowerConcurrency) version = 9;
      if (hasClusterPairEnrollments) version = 10;
      if (hasTransportCredentialEnrollments) version = 11;
      if (hasClusterPairEnrollmentOperations) version = hasPairRevocationOperations ? 13 : 12;
      if (hasPairEpochOperations) version = 14;
      if (hasLocalCousinServicePermissions) version = 15;
      if (hasTransportCredentialLifecycleOperations) version = 16;
      if (hasMachineFragmentAssignments) version = 17;
      if (hasCousinRoutes) version = 18;
      if (hasPendingAddMachinesProvisioningIntents) version = 19;
      if (hasCrossClusterMasqueGatewayAuthorities) version = 20;
      if (hasStatelessDeploymentRetirements) version = 21;
      if (hasRetainedStatefulRearmProofs) version = 22;
      if (hasTruthGlobalMembershipProjections) version = 25;
      serializer.value8b(version);
    }
    serializer.value8b(state.generation);
  }
  else
  {
    serializer.value8b(state.generation);
    if (state.generation == versionMarker)
    {
      uint64_t version = 0;
      serializer.value8b(version);
      serializer.value8b(state.generation);
      if ((version < 1 || version > explicitVersion) ||
          (version == 5 && containerRuntimeStates == nullptr) ||
          state.generation == versionMarker)
      {
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
        return;
      }
      // P6 and the concurrent main line assigned different byte layouts to
      // version six. There is no producer discriminator in the record, so a
      // merged reader must not guess. P6's active admission records use v8;
      // a retained v6 record requires an explicit migration before upgrade.
      if (version == 6)
      {
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
        return;
      }
      hasMaterializedStatefulRecoveryOperations = true;
      hasApiCredentialExpiryNotices = version >= 2;
      hasAllMachineRecoveryWitnesses = version >= 3;
      hasMaterializedStatefulRecoveryRetries = version >= 4;
      hasContainerRuntimeStates = version == 5 || (version >= 6 && containerRuntimeStates != nullptr);
      hasDeploymentPlacementPolicies = version >= 6;
      hasStatefulServingAuthorities = version >= 7;
      hasStatelessDeploymentAdmissions = version >= 8;
      hasExplicitUpdateSelfFollowerConcurrency = version >= 9;
      hasClusterPairEnrollments = version >= 10;
      hasTransportCredentialEnrollments = version >= 11;
      hasClusterPairEnrollmentOperations = version >= 12;
      permitsClusterPairRevocationOperations = version >= 13;
      permitsClusterPairEpochOperations = version >= 14;
      hasLocalCousinServicePermissions = version >= 15;
      permitsTransportCredentialLifecycleOperations = version >= 16;
      hasMachineFragmentAssignments = version >= 17;
      hasCousinRoutes = version >= 18;
      hasPendingAddMachinesProvisioningIntents = version >= 19;
      hasCrossClusterMasqueGatewayAuthorities = version >= 20;
      hasStatelessDeploymentRetirements = version >= 21;
      hasRetainedStatefulRearmProofs = version >= 22;
      hasRetiredStoreSelections = version == 23 || version == 24;
      hasRetiredMemberRepairs = version == 24;
      hasTruthGlobalMembershipProjections = version >= 25;
    }
  }

  serializer.value1b(state.hasCompletedInitialMasterElection);
  serializer.object(state.transportTLSAuthority);
  serializer.value8b(state.nextMintedClientTlsGeneration);
  serializer.value8b(state.nextTlsResumptionGeneration);
  serializer.value8b(state.nextPendingAddMachinesOperationID);
  serializer.value8b(state.nextPendingElasticAddressOperationID);
  serializer.value8b(state.nextDNSIntentRevision);
  serializer.object(state.tlsResumptionSnapshotsByWormhole);
  serializer.object(state.pendingAddMachinesOperations);
  serializer.object(state.pendingAutonomousProvisioningOperations);
  serializer.object(state.pendingElasticAddressAssignments);
  serializer.object(state.pendingElasticAddressReleases);
  serializer.object(state.statefulWorkerTopologyUpgradeOperations);
  serializer.object(state.deferredStatefulScaleIntents);
  if (hasApiCredentialExpiryNotices)
  {
    serializer.object(state.materializedStatefulRecoveryOperations);
    serializer.object(state.apiCredentialExpiryNotices);
  }
  else if (hasMaterializedStatefulRecoveryOperations)
  {
    serializer.object(state.materializedStatefulRecoveryOperations);
    if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false) state.apiCredentialExpiryNotices.clear();
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.materializedStatefulRecoveryOperations.clear();
    state.apiCredentialExpiryNotices.clear();
  }
  if (hasMaterializedStatefulRecoveryRetries)
  {
    serializer.object(state.materializedStatefulRecoveryRetries);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.materializedStatefulRecoveryRetries.clear();
  }
  serializer.object(state.machineSchemas);
  serializer.object(state.routableResourceLeases);
  serializer.object(state.publicTlsCertificates);
  serializer.object(state.privateTlsVaultLifecycles);
  serializer.object(state.taskExecutions);
  serializer.object(state.mothershipTunnelProviderDesiredState);
  serializer.object(state.updateSelf);
  if (hasAllMachineRecoveryWitnesses)
  {
    serializer.object(state.updateSelf.machineRecoveryWitnesses);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.updateSelf.machineRecoveryWitnesses.clear();
  }
  if (hasContainerRuntimeStates)
  {
    serializer.container(*containerRuntimeStates, 4096);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    if (containerRuntimeStates != nullptr)
    {
      containerRuntimeStates->clear();
    }
  }
  if (hasDeploymentPlacementPolicies)
  {
    serializer.container(state.deploymentPlacementPolicies, 4096);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.deploymentPlacementPolicies.clear();
  }
  if (hasStatefulServingAuthorities)
  {
    serializer.container(state.statefulServingAuthorities, 4096);
    if (servingRuntimeStates != nullptr)
      serializer.container(*servingRuntimeStates, 4096);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.statefulServingAuthorities.clear();
    if (servingRuntimeStates != nullptr) servingRuntimeStates->clear();
  }
  if (hasStatelessDeploymentAdmissions)
  {
    serializer.container(state.statelessDeploymentAdmissions, 4096);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.statelessDeploymentAdmissions.clear();
  }
  if (hasExplicitUpdateSelfFollowerConcurrency)
  {
    serializer.value1b(state.updateSelfFollowerConcurrency);
    serializer.object(state.updateSelfFollowerTransitionIssuedPeerKeys);
    serializer.object(state.updateSelfFollowerReadyPeerKeys);
    if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
    {
      if ((state.updateSelfFollowerConcurrency < ProdigyUpdateSelfMinimumConcurrency && !hasClusterPairEnrollments) ||
          state.updateSelfFollowerConcurrency > ProdigyUpdateSelfMaximumConcurrency)
      {
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
      }
    }
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.updateSelfFollowerConcurrency = 0;
    state.updateSelfFollowerTransitionIssuedPeerKeys.clear();
    state.updateSelfFollowerReadyPeerKeys.clear();
  }
  if (hasClusterPairEnrollments)
  {
    // Versions 10 and 11 reserve this fixed-width root slot for compatibility,
    // but the public runtime record must never carry its private root.  The
    // authenticated transition and snapshot sidecar bind that material by the
    // immutable descriptor instead.
    if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
    {
      serializer.container(state.clusterPairEnrollments, ProdigyClusterPairEnrollmentMaximumRecords,
          [](auto& nested, ProdigyClusterPairEnrollment& enrollment) {
            ProdigyClusterPairEnrollment publicEnrollment = enrollment;
            OPENSSL_cleanse(publicEnrollment.root, sizeof(publicEnrollment.root));
            nested.object(publicEnrollment);
          });
    }
    else
    {
      serializer.container(state.clusterPairEnrollments, ProdigyClusterPairEnrollmentMaximumRecords,
          [](auto& nested, ProdigyClusterPairEnrollment& enrollment) { nested.object(enrollment); });
      for (const ProdigyClusterPairEnrollment& enrollment : state.clusterPairEnrollments)
      {
        if (!prodigyClusterPairEnrollmentRootIsZero(enrollment))
        {
          serializer.adapter().error(bitsery::ReaderError::InvalidData);
          return;
        }
      }
    }
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.clusterPairEnrollments.clear();
  }
  if (hasTransportCredentialEnrollments)
  {
    serializer.container(state.transportCredentialEnrollments, ProdigyTransportCredentialEnrollmentMaximumRecords,
        [](auto& nested, ProdigyTransportCredentialEnrollment& enrollment) { nested.object(enrollment); });
    serializer.container(state.transportCredentialEnrollmentOperations, ProdigyTransportCredentialEnrollmentMaximumRecords,
        [permitsTransportCredentialLifecycleOperations](auto& nested, ProdigyTransportCredentialEnrollmentOperation& operation) {
          prodigySerializeTransportCredentialEnrollmentOperation(nested, operation, permitsTransportCredentialLifecycleOperations);
        });
    if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
      if ((!permitsTransportCredentialLifecycleOperations && std::any_of(
              state.transportCredentialEnrollmentOperations.begin(), state.transportCredentialEnrollmentOperations.end(),
              [](const auto& operation) { return operation.protocolVersion != 1; })) ||
          (permitsTransportCredentialLifecycleOperations && std::any_of(
              state.transportCredentialEnrollmentOperations.begin(), state.transportCredentialEnrollmentOperations.end(),
              [](const auto& operation) { return operation.protocolVersion != 1 && operation.protocolVersion != 2; })))
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.transportCredentialEnrollments.clear();
    state.transportCredentialEnrollmentOperations.clear();
  }
  if (hasClusterPairEnrollmentOperations)
  {
    serializer.container(state.clusterPairEnrollmentOperations, ProdigyClusterPairEnrollmentMaximumRecords,
        [](auto& nested, ProdigyClusterPairEnrollmentOperation& operation) { nested.object(operation); });
    if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
      if ((!permitsClusterPairRevocationOperations &&
          std::any_of(state.clusterPairEnrollmentOperations.begin(), state.clusterPairEnrollmentOperations.end(),
              [](const auto& operation) { return operation.protocolVersion >= 2; })) ||
          (!permitsClusterPairEpochOperations &&
          std::any_of(state.clusterPairEnrollmentOperations.begin(), state.clusterPairEnrollmentOperations.end(),
              [](const auto& operation) { return operation.protocolVersion >= 3; })))
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.clusterPairEnrollmentOperations.clear();
  }
  if (hasLocalCousinServicePermissions)
  {
    serializer.container(state.localCousinServicePermissions,
        ProdigyLocalCousinServicePermissionMaximumRecords,
        [](auto& nested, ProdigyLocalCousinServicePermission& permission) { nested.object(permission); });
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.localCousinServicePermissions.clear();
  }
  if (hasMachineFragmentAssignments)
  {
    serializer.container(state.machineFragmentAssignments,
        ProdigyMachineFragmentAssignmentMaximumRecords,
        [](auto& nested, ProdigyMachineFragmentAssignment& assignment) { nested.object(assignment); });
    if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
    {
      if (prodigyMachineFragmentAssignmentsValid(state.machineFragmentAssignments) == false)
      {
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
      }
    }
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.machineFragmentAssignments.clear();
  }
  if (hasCousinRoutes)
  {
    serializer.container(state.cousinRoutes, ProdigyCousinRouteMaximumRecords,
        [](auto& nested, CousinRouteRecord& route) { nested.object(route); });
    if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
      if (prodigyCousinRoutesValid(state.cousinRoutes) == false)
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.cousinRoutes.clear();
  }
  if (hasPendingAddMachinesProvisioningIntents)
  {
    serializer.object(state.pendingAddMachinesProvisioningIntents);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.pendingAddMachinesProvisioningIntents.clear();
  }
  if (hasCrossClusterMasqueGatewayAuthorities)
  {
    serializer.container(state.crossClusterMasqueGatewayAuthorities,
        ProdigyCrossClusterMasqueGatewayAuthorityMaximumRecords,
        [](auto& nested, CrossClusterMasqueGatewayAuthority& authority) { nested.object(authority); });
    if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
      if (!prodigyCrossClusterMasqueGatewayAuthoritiesValid(state.crossClusterMasqueGatewayAuthorities, 0))
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    state.crossClusterMasqueGatewayAuthorities.clear();
  }
  if (hasStatelessDeploymentRetirements)
  {
    serializer.container(state.statelessDeploymentRetirements, 4096);
    if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
      if (!prodigyStatelessDeploymentRetirementsValid(state.statelessDeploymentRetirements,
                                                       state.statelessDeploymentAdmissions, state.generation))
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
  }
  else if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    state.statelessDeploymentRetirements.clear();
  }
  if (hasRetainedStatefulRearmProofs)
  {
    serializer.container(state.retainedStatefulRearmProofs, 4096,
        [](auto& nested, ProdigyRetainedStatefulRearmProof& proof) { nested.object(proof); });
    if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
      if (!prodigyRetainedStatefulRearmProofsValid(state))
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
  }
  else if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    state.retainedStatefulRearmProofs.clear();
  }
  if (hasTruthGlobalMembershipProjections)
  {
    serializer.container(state.truthGlobalMembershipProjections, 64);
    if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
      for (const auto& projection : state.truthGlobalMembershipProjections)
        if (!prodigyTruthGlobalMembershipProjectionValid(projection)) serializer.adapter().error(bitsery::ReaderError::InvalidData);
  }
  else if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    state.truthGlobalMembershipProjections.clear();
  }
  if constexpr (!ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    // v23/v24 appended application-database repair containers. Their writer
    // encodes an empty container as one zero byte. Accept only that canonical
    // empty form; reject active retired state before allocating or discarding
    // any payload. New writers never emit these tails.
    for (bool present : {hasRetiredStoreSelections, hasRetiredMemberRepairs})
    {
      if (!present) continue;
      uint8_t countPrefix = 0;
      serializer.value1b(countPrefix);
      if (countPrefix != 0)
      {
        serializer.adapter().error(bitsery::ReaderError::InvalidData);
        return;
      }
    }
  }
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    if (!prodigyPendingAddMachinesProvisioningIntentsValid(
            state.pendingAddMachinesOperations,
            state.pendingAddMachinesProvisioningIntents))
    {
      serializer.adapter().error(bitsery::ReaderError::InvalidData);
    }
  }
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

// Validate both exact declarations against the authority's retained plan map.
// The runtime-state decoder checks the predecessor admission; this check is
// required when the enclosing authority package supplies its plan map.
static inline bool prodigyStatelessDeploymentRetirementsMatchPlans(
    const Vector<ProdigyStatelessDeploymentRetirement>& retirements,
    const bytell_hash_map<uint64_t, DeploymentPlan>& plans)
{
  for (const auto& retirement : retirements)
  {
    auto predecessor = plans.find(retirement.predecessorDeploymentID);
    auto successor = plans.find(retirement.successorDeploymentID);
    if (predecessor == plans.end() || successor == plans.end()) return false;
    for (const auto& candidate : {std::pair<const DeploymentPlan *, const String *>
             {&predecessor->second, &retirement.predecessorPlanSHA256},
             {&successor->second, &retirement.successorPlanSHA256}})
    {
      if (candidate.first->isStateful || candidate.first->config.type != ApplicationType::stateless) return false;
      DeploymentPlan plan = *candidate.first;
      String bytes = {}, digest = {};
      if (!BitseryEngine::serialize(bytes, plan) || !prodigyComputeSHA256Hex(bytes, digest) ||
          !digest.equals(*candidate.second)) return false;
    }
    if (predecessor->second.config.deploymentID() != retirement.predecessorDeploymentID ||
        successor->second.config.deploymentID() != retirement.successorDeploymentID) return false;
  }
  return true;
}

static inline bool prodigyCousinAutomaticWhiteholePlanValid(const Vector<Whitehole>& whiteholes)
{
  return whiteholes.size() == 1 && whiteholeDeclarationValid(whiteholes[0]) &&
      whiteholes[0].family == ExternalAddressFamily::ipv6 && whiteholes[0].transport == ExternalAddressTransport::tcp;
}

static inline bool prodigyCousinProtectedWormholePlanValid(const DeploymentPlan& plan)
{
  if (!plan.isStateful || plan.useHostNetworkNamespace || plan.wormholes.size() != 1 ||
      !plan.whiteholes.empty()) return false;
  const Wormhole& wormhole = plan.wormholes.front();
  if (wormhole.layer4 != IPPROTO_TCP || wormhole.isQuic || wormhole.externalPort == 0 ||
      wormhole.externalPort != wormhole.containerPort) return false;
  bytell_hash_map<uint64_t, Advertisement> advertisements;
  for (const auto& advertisement : plan.advertisements)
    advertisements.emplace(advertisement.service, advertisement);
  SwitchboardWormholeDesiredState desired;
  const uint64_t cousin = StatefulMeshRoles::forShardGroup(
      plan.stateful, plan.config.applicationID, 0).cousin;
  return cousin != 0 && prodigyBuildCousinWormholeDesiredState(
      plan.wormholes, true, cousin, advertisements, desired, false) &&
      prodigyWormholeRequiresPairAdmission(desired, wormhole.containerPort, wormhole.layer4);
}

static inline bool prodigyCousinSourceContainerStateEligible(
    const ProdigyLocalCousinServicePermission& permission, ContainerState state,
    bool runtimeReady, const StatefulTopology& topology)
{
  if (!runtimeReady) return false;
  if (state == ContainerState::healthy) return true;
  if (permission.protocolVersion != ProdigyLocalCousinServicePermission::purposeVersion ||
      (state != ContainerState::scheduled && state != ContainerState::crashedRestarting)) return false;
  if (permission.purpose == ProdigyCousinServicePurpose::clientAuthority)
    return permission.localHalf == CousinRouteHalf::source;
  if (permission.purpose != ProdigyCousinServicePurpose::sibling &&
      permission.purpose != ProdigyCousinServicePurpose::seeding) return false;
  return topology.servingMode == StatefulTopologyServingMode::catchupOnly ||
      (topology.servingMode == StatefulTopologyServingMode::applicationDataAuthority &&
       prodigyStatefulDataAuthorityValid(topology.dataAuthority) && !prodigyStatefulTopologyServesClients(topology));
}

static inline uint64_t prodigyCousinPermissionServiceForRoles(
    const ProdigyLocalCousinServicePermission& permission, const StatefulMeshRoles& roles)
{
  switch (permission.purpose) {
    case ProdigyCousinServicePurpose::statefulCousin: return roles.cousin;
    case ProdigyCousinServicePurpose::clientAuthority:
      return permission.localHalf == CousinRouteHalf::source ?
          MeshServices::constrainPrefixToGroup(permission.localCousinServicePrefix, 0) : roles.client;
    case ProdigyCousinServicePurpose::sibling: return roles.sibling;
    case ProdigyCousinServicePurpose::seeding: return roles.seeding;
  }
  return 0;
}

static inline bool prodigyCousinSourceSubscriptionMatches(
    const ProdigyLocalCousinServicePermission& permission, uint64_t sourceService,
    const bytell_hash_map<uint64_t, Subscription>& subscriptions, ContainerState state)
{
  if (permission.purpose == ProdigyCousinServicePurpose::statefulCousin) return true;
  uint32_t matches = 0;
  for (const auto& [key, subscription] : subscriptions) {
    const bool selected = permission.purpose == ProdigyCousinServicePurpose::clientAuthority ?
        (key == permission.peerCousinServicePrefix || key == permission.authorizedService) : key == sourceService;
    if (selected && key == subscription.service && serviceBlueprintActiveAtContainerState(subscription, state)) ++matches;
  }
  return matches == 1;
}

static inline bool prodigyCousinPermissionPlanServiceMatches(
    const ProdigyLocalCousinServicePermission& permission, const DeploymentPlan& plan)
{
  if (plan.config.applicationID != permission.localApplicationID ||
      plan.config.deploymentID() != permission.localDeploymentID ||
      plan.config.containerBlobSHA256 != permission.artifactSHA256 || plan.config.containerBlobBytes != permission.artifactBytes) return false;
  // Legacy records predate purpose-bound route services.  They retain their
  // original deployment-identity and stateful cousin-prefix contract; only v3
  // permissions opt into the service and endpoint topology checks below.
  if (permission.protocolVersion < ProdigyLocalCousinServicePermission::purposeVersion)
    return plan.isStateful && plan.stateful.cousinPrefix == permission.localCousinServicePrefix;
  const bool automatic = permission.purpose != ProdigyCousinServicePurpose::statefulCousin;
  const bool source = permission.localHalf == CousinRouteHalf::source;
  if (!automatic) {
    if (!plan.isStateful || plan.stateful.cousinPrefix != permission.localCousinServicePrefix ||
        plan.useHostNetworkNamespace) return false;
    // A private route derives both endpoints from the current container
    // identity. Permission admission alone never authorizes a session: the
    // private route, gateway, discovery and exact service are checked later.
    if (plan.wormholes.empty() && plan.whiteholes.empty()) return true;
    return source ? (plan.wormholes.empty() && prodigyCousinAutomaticWhiteholePlanValid(plan.whiteholes))
                  : prodigyCousinProtectedWormholePlanValid(plan);
  }
  if (plan.useHostNetworkNamespace) return false;
  if (source && !plan.whiteholes.empty() && !prodigyCousinAutomaticWhiteholePlanValid(plan.whiteholes)) {
    if (permission.purpose != ProdigyCousinServicePurpose::clientAuthority ||
        !std::all_of(plan.whiteholes.begin(), plan.whiteholes.end(), [](const Whitehole& whitehole) {
          return whiteholeDeclarationValid(whitehole) && whitehole.transport == ExternalAddressTransport::quic;
        })) return false;
  }
  if (permission.purpose == ProdigyCousinServicePurpose::clientAuthority && source) {
    if (plan.isStateful || plan.config.type != ApplicationType::stateless ||
        (plan.config.applicationID != 6 && plan.config.applicationID != 11)) return false;
    uint32_t matches = 0;
    for (const auto& subscription : plan.subscriptions)
      if (subscription.service == permission.peerCousinServicePrefix &&
          serviceBlueprintActiveAtContainerState(subscription, ContainerState::healthy)) ++matches;
    return matches == 1;
  }
  const bool shardedClient = permission.purpose == ProdigyCousinServicePurpose::clientAuthority &&
      (plan.config.applicationID == 3 || plan.config.applicationID == 4);
  const bool shardedSeed = permission.purpose == ProdigyCousinServicePurpose::seeding &&
      (plan.config.applicationID == 3 || plan.config.applicationID == 4);
  if (!plan.isStateful || plan.config.type != ApplicationType::stateful ||
      (!shardedClient && !shardedSeed && !plan.stateful.neverShard) ||
      ((shardedClient || shardedSeed) && permission.destinationShardGroups > 1 && plan.stateful.neverShard)) return false;
  const uint16_t group = source && !shardedSeed ? 0 : permission.destinationShardGroup;
  const auto roles = StatefulMeshRoles::forShardGroup(plan.stateful, plan.config.applicationID, group);
  const uint64_t service = prodigyCousinPermissionServiceForRoles(permission, roles);
  if (service == 0 || !roles.hasDistinctServices() ||
      service != MeshServices::constrainPrefixToGroup(permission.localCousinServicePrefix, group)) return false;
  return !automatic || permission.purpose == ProdigyCousinServicePurpose::clientAuthority || service != roles.client;
}

// Neuron cannot reproduce a full DeploymentPlan digest from its materialized
// ContainerPlan. Brain owns that digest; Neuron independently checks every
// local identity/service it can prove before projecting an authenticated lease.
static inline bool prodigyCousinPermissionContainerPlanMatches(
    const ProdigyLocalCousinServicePermission& permission, const ContainerPlan& plan, uint64_t service,
    bool privateSession = false)
{
  if (plan.config.deploymentID() != permission.localDeploymentID || plan.config.applicationID != permission.localApplicationID ||
      plan.config.containerBlobSHA256 != permission.artifactSHA256 || plan.config.containerBlobBytes != permission.artifactBytes) return false;
  if (permission.purpose == ProdigyCousinServicePurpose::statefulCousin)
    return plan.isStateful && service == plan.statefulMeshRoles.cousin;
  const uint32_t groups = plan.isStateful ? plan.nShardGroups : 1;
  const uint32_t group = plan.isStateful ? plan.shardGroup : 0;
  if (!prodigyCousinServicePermissionGroupValid(permission, group, groups) ||
      service != prodigyCousinPermissionServiceForRoles(permission, plan.statefulMeshRoles)) return false;
  if (permission.localHalf == CousinRouteHalf::source ?
      !prodigyCousinSourceContainerStateEligible(permission, plan.state, plan.runtimeReady, plan.statefulTopology) :
      (plan.state != ContainerState::healthy || !plan.runtimeReady || !prodigyStatefulTopologyServesClients(plan.statefulTopology))) return false;
  if (permission.localHalf == CousinRouteHalf::source &&
      !prodigyCousinSourceSubscriptionMatches(permission, service, plan.subscriptions, plan.state)) return false;
  if (permission.purpose == ProdigyCousinServicePurpose::clientAuthority && permission.localHalf == CousinRouteHalf::source) {
    if (plan.isStateful || plan.config.type != ApplicationType::stateless ||
        (!privateSession && !plan.whiteholes.empty() && !prodigyCousinAutomaticWhiteholePlanValid(plan.whiteholes))) return false;
    return true; // The shared subscription check above admits only this exact peer prefix/shard.
  }
  return plan.isStateful && plan.config.type == ApplicationType::stateful && plan.statefulMeshRoles.hasDistinctServices() &&
      (permission.purpose == ProdigyCousinServicePurpose::clientAuthority || service != plan.statefulMeshRoles.client);
}

// Public, topology-free half of the P6 target profile.  Brain still resolves
// the registered prefix and its owning machine before accepting it.
static inline bool prodigyStatelessDeploymentAdmissionPlanEligible(const DeploymentPlan& plan)
{
  if (plan.config.type != ApplicationType::stateless || plan.isStateful ||
      plan.useHostNetworkNamespace || plan.stateless.nBase != 1 ||
      !plan.horizontalScalers.empty() || !plan.verticalScalers.empty() ||
      plan.canaryCount != 0 || plan.canariesMustLiveForMinutes != 0 ||
      plan.wormholes.size() != 1 || !plan.publicTLS.empty() || !plan.whiteholes.empty() ||
      !plan.subscriptions.empty() || !plan.advertisements.empty() ||
      plan.moveConstructively || plan.requiresDatacenterUniqueTag ||
      plan.hasTlsIssuancePolicy || !plan.hasApiCredentialPolicy ||
      plan.apiCredentialPolicy.applicationID != plan.config.applicationID ||
      !plan.apiCredentialPolicy.requiredCredentialNames.empty()) return false;
  const Wormhole& endpoint = plan.wormholes[0];
  return endpoint.source == ExternalAddressSource::registeredRoutablePrefix &&
         endpoint.routablePrefixUUID != 0 && endpoint.layer4 == IPPROTO_TCP &&
         !endpoint.isQuic && !endpoint.hasDNSConfig && !endpoint.externalAddress.is6 &&
         endpoint.externalPort != 0 && endpoint.containerPort != 0;
}

// The materialized recovery owner and the sealed retained-recovery preparer
// must admit the same in-place stateful lineage.  Keep the compatibility
// invariant with the durable plan type instead of duplicating it at either
// lifecycle boundary.
static inline bool prodigyMaterializedStatefulRecoveryPlansAreCompatible(
    const DeploymentPlan& active, const DeploymentPlan& successor)
{
  return active.isStateful && successor.isStateful &&
         active.config.type == ApplicationType::stateful && successor.config.type == ApplicationType::stateful &&
         active.config.applicationID == successor.config.applicationID &&
         successor.stateful.allowUpdateInPlace && successor.canaryCount == 0 &&
         successor.config.nLogicalCores == active.config.nLogicalCores &&
         successor.config.totalMemoryMB() == active.config.totalMemoryMB() &&
         successor.config.totalStorageMB() == active.config.totalStorageMB() &&
         successor.stateful.clientPrefix == active.stateful.clientPrefix &&
         successor.stateful.siblingPrefix == active.stateful.siblingPrefix &&
         successor.stateful.cousinPrefix == active.stateful.cousinPrefix &&
         successor.stateful.seedingPrefix == active.stateful.seedingPrefix &&
         successor.stateful.shardingPrefix == active.stateful.shardingPrefix &&
         successor.stateful.seedingAlways == active.stateful.seedingAlways &&
         successor.stateful.allMasters == active.stateful.allMasters;
}

class FailedDeploymentRecordPayload {
public:

  String reason;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  int64_t failedAtMs = 0;
  DeploymentStatusReport terminalReport;
};

template <typename S>
static void serialize(S&& serializer, FailedDeploymentRecordPayload& record)
{
  serializer.text1b(record.reason, UINT32_MAX);
  serializer.value2b(record.applicationID);
  serializer.value8b(record.deploymentID);
  serializer.value8b(record.failedAtMs);
  serializer.object(record.terminalReport);
}

class FailedDeploymentOperatorCancellationPayload {
public:
  FailedDeploymentRecordPayload failure;
  String operationID;
  uint64_t successorDeploymentID = 0;
  CancelDeploymentPhase phase = CancelDeploymentPhase::none;
  uint64_t durableGeneration = 0;
  int64_t completedAtMs = 0;
};

template <typename S>
static void serialize(S&& serializer, FailedDeploymentOperatorCancellationPayload& record)
{
  serializer.object(record.failure);
  serializer.text1b(record.operationID, 36);
  serializer.value8b(record.successorDeploymentID);
  uint8_t phase = uint8_t(record.phase);
  serializer.value1b(phase);
  record.phase = CancelDeploymentPhase(phase);
  serializer.value8b(record.durableGeneration);
  serializer.value8b(record.completedAtMs);
}

struct FailedDeploymentQualificationCancellationPayload {
  FailedDeploymentOperatorCancellationPayload base;
  ProdigyQualificationStatefulCancellation scope;
};
template <typename S> static void serialize(S&& s, FailedDeploymentQualificationCancellationPayload& v) {
  s.object(v.base); s.object(v.scope);
}

class FailedDeploymentRecord {
public:

  String reason;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  int64_t failedAtMs = 0;
  bool hasTerminalReport = false;
  DeploymentStatusReport terminalReport;
  bool hasOperatorCancellation = false;
  String operationID;
  uint64_t successorDeploymentID = 0;
  CancelDeploymentPhase cancellationPhase = CancelDeploymentPhase::none;
  uint64_t cancellationGeneration = 0;
  int64_t cancellationCompletedAtMs = 0;
  bool hasQualificationCancellation = false;
  ProdigyQualificationStatefulCancellation qualificationCancellation = {};
};

class DeploymentCancellationAcknowledgement {
public:
  String operationID;
  uint64_t durableGeneration = 0;
  uint128_t peerUUID = 0;
  int64_t peerBootNs = 0;
};

template <typename S>
static void serialize(S&& serializer, DeploymentCancellationAcknowledgement& acknowledgement)
{
  serializer.text1b(acknowledgement.operationID, 36);
  serializer.value8b(acknowledgement.durableGeneration);
  serializer.value16b(acknowledgement.peerUUID);
  serializer.value8b(acknowledgement.peerBootNs);
}

template <typename S>
static void serialize(S&& serializer, FailedDeploymentRecord& record)
{
  // Keep reason-only records byte-compatible with the former String map value.
  // Structured records remain one text1b value so existing snapshots can still
  // be decoded, while old binaries retain the opaque value instead of rejecting
  // the entire master-authority package.
  constexpr static char structuredPrefix[] = "PRODIGY_FAILED_DEPLOYMENT_REPORT_V1\0";
  constexpr static uint64_t structuredPrefixBytes = sizeof(structuredPrefix) - 1;
  constexpr static char qualificationPrefix[] = "PRODIGY_OPERATOR_CANCEL_QUALIFICATION_V1\0";
  constexpr static uint64_t qualificationPrefixBytes = sizeof(qualificationPrefix) - 1;
  constexpr static char cancellationPrefix[] = "PRODIGY_OPERATOR_CANCEL_V1\0";
  constexpr static uint64_t cancellationPrefixBytes = sizeof(cancellationPrefix) - 1;
  using Serializer = std::remove_cv_t<std::remove_reference_t<S>>;

  // The owning persistence visitors do not produce the legacy encoded record
  // below.  Detach the source fields directly before that temporary encoding
  // is discarded, including the structured terminal report payload.
  if constexpr (requires { serializer.detachPersistentValue(record.reason); })
  {
    serializer.detachPersistentValue(record.reason);
    if (record.hasTerminalReport || record.hasOperatorCancellation)
    {
      serializer.detachPersistentValue(record.terminalReport);
    }
    if (record.hasOperatorCancellation)
    {
      serializer.detachPersistentValue(record.operationID);
      if (record.hasQualificationCancellation) serializer.detachPersistentValue(record.qualificationCancellation);
    }
    return;
  }

  String encoded = {};
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    if (record.hasOperatorCancellation)
    {
      FailedDeploymentOperatorCancellationPayload payload = {};
      payload.failure.reason = record.reason;
      payload.failure.applicationID = record.applicationID;
      payload.failure.deploymentID = record.deploymentID;
      payload.failure.failedAtMs = record.failedAtMs;
      payload.failure.terminalReport = record.terminalReport;
      payload.operationID = record.operationID;
      payload.successorDeploymentID = record.successorDeploymentID;
      payload.phase = record.cancellationPhase;
      payload.durableGeneration = record.cancellationGeneration;
      payload.completedAtMs = record.cancellationCompletedAtMs;

      String serializedPayload = {};
      if (record.hasQualificationCancellation) {
        FailedDeploymentQualificationCancellationPayload qualified = {};
        qualified.base = std::move(payload); qualified.scope = record.qualificationCancellation;
        BitseryEngine::serialize(serializedPayload, qualified);
        encoded.append(qualificationPrefix, qualificationPrefixBytes);
      } else {
        BitseryEngine::serialize(serializedPayload, payload);
        encoded.append(cancellationPrefix, cancellationPrefixBytes);
      }
      encoded.append(serializedPayload);
    }
    else if (record.hasTerminalReport)
    {
      FailedDeploymentRecordPayload payload = {};
      payload.reason = record.reason;
      payload.applicationID = record.applicationID;
      payload.deploymentID = record.deploymentID;
      payload.failedAtMs = record.failedAtMs;
      payload.terminalReport = record.terminalReport;

      String serializedPayload = {};
      BitseryEngine::serialize(serializedPayload, payload);
      encoded.append(structuredPrefix, structuredPrefixBytes);
      encoded.append(serializedPayload);
    }
    else
    {
      encoded = record.reason;
    }
  }

  serializer.text1b(encoded, UINT32_MAX);

  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value == false)
  {
    record = {};
    const bool qualified = encoded.size() >= qualificationPrefixBytes && memcmp(encoded.data(), qualificationPrefix, qualificationPrefixBytes) == 0;
    if (qualified || (encoded.size() >= cancellationPrefixBytes && memcmp(encoded.data(), cancellationPrefix, cancellationPrefixBytes) == 0))
    {
      const uint64_t prefixBytes = qualified ? qualificationPrefixBytes : cancellationPrefixBytes;
      String serializedPayload = encoded.substr(prefixBytes, encoded.size() - prefixBytes, Copy::no);
      FailedDeploymentOperatorCancellationPayload payload = {};
      FailedDeploymentQualificationCancellationPayload qualification = {};
      const bool decoded = qualified ? BitseryEngine::deserializeSafe(serializedPayload, qualification) : BitseryEngine::deserializeSafe(serializedPayload, payload);
      if (qualified) payload = qualification.base;
      if (decoded && (!qualified || (prodigyQualificationStatefulCancellationValid(qualification.scope) &&
          qualification.scope.request.operationID == payload.operationID &&
          qualification.scope.request.applicationID == payload.failure.applicationID &&
          ((uint64_t(qualification.scope.request.applicationID) << 48) | qualification.scope.request.activeVersionID) == payload.failure.deploymentID &&
          ((uint64_t(qualification.scope.request.applicationID) << 48) | qualification.scope.request.successorVersionID) == payload.successorDeploymentID)) &&
          prodigyCanonicalOperationUUID(payload.operationID) &&
          payload.failure.applicationID != 0 && payload.failure.deploymentID != 0 &&
          payload.successorDeploymentID != 0 &&
          uint16_t(payload.failure.deploymentID >> 48) == payload.failure.applicationID &&
          uint16_t(payload.successorDeploymentID >> 48) == payload.failure.applicationID &&
          payload.failure.deploymentID != payload.successorDeploymentID &&
          payload.durableGeneration != 0 &&
          uint8_t(payload.phase) >= uint8_t(CancelDeploymentPhase::accepted) &&
          uint8_t(payload.phase) <= uint8_t(CancelDeploymentPhase::completed))
      {
        record.reason = std::move(payload.failure.reason);
        record.applicationID = payload.failure.applicationID;
        record.deploymentID = payload.failure.deploymentID;
        record.failedAtMs = payload.failure.failedAtMs;
        record.hasTerminalReport = true;
        record.terminalReport = std::move(payload.failure.terminalReport);
        record.hasOperatorCancellation = true;
        record.operationID = std::move(payload.operationID);
        record.successorDeploymentID = payload.successorDeploymentID;
        record.cancellationPhase = payload.phase;
        record.cancellationGeneration = payload.durableGeneration;
        record.cancellationCompletedAtMs = payload.completedAtMs;
        if (qualified) { record.hasQualificationCancellation = true; record.qualificationCancellation = std::move(qualification.scope); }
        return;
      }
    }
    if (encoded.size() >= structuredPrefixBytes && memcmp(encoded.data(), structuredPrefix, structuredPrefixBytes) == 0)
    {
      String serializedPayload = encoded.substr(structuredPrefixBytes, encoded.size() - structuredPrefixBytes, Copy::no);
      FailedDeploymentRecordPayload payload = {};
      if (BitseryEngine::deserializeSafe(serializedPayload, payload))
      {
        record.reason = std::move(payload.reason);
        record.applicationID = payload.applicationID;
        record.deploymentID = payload.deploymentID;
        record.failedAtMs = payload.failedAtMs;
        record.hasTerminalReport = true;
        record.terminalReport = std::move(payload.terminalReport);
        return;
      }
    }

    // A legacy or malformed tagged entry remains available as its original
    // reason text; one damaged terminal report cannot invalidate the snapshot.
    record.reason = std::move(encoded);
  }
}

class ProdigyPersistentMasterAuthorityPackage {
public:

  bytell_hash_map<uint16_t, ApplicationTlsVaultFactory> tlsVaultFactoriesByApp;
  bytell_hash_map<uint16_t, ApplicationApiCredentialSet> apiCredentialSetsByApp;
  bytell_hash_map<String, uint16_t> reservedApplicationIDsByName;
  bytell_hash_map<uint16_t, String> reservedApplicationNamesByID;
  Vector<ApplicationServiceIdentity> reservedApplicationServices;
  uint16_t nextReservableApplicationID = 1;
  // Full authoritative live container views are captured by Brain for crash recovery.
  // Snapshot persistence retains only their identities publicly; full records
  // live in the paired private sidecar.
  Vector<BrainReplicatedContainerRuntimeState> containerRuntimeStates;
  // Immutable desired serving plans are separate from observed live plans:
  // preparing a cutover must not change cold-start observations before ACK.
  // Their full content uses this package's existing private snapshot owner.
  Vector<BrainReplicatedContainerRuntimeState> servingRuntimeStates;
  bytell_hash_map<uint64_t, DeploymentPlan> deploymentPlans;
  bytell_hash_map<uint64_t, FailedDeploymentRecord> failedDeployments;
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
  if constexpr (requires { serializer.detachPersistentMap(map); })
  {
    // The ownership visitor must rebuild the map before it visits keys. Hash
    // table keys are const after insertion; assigning a detached String via
    // the normal writer's const_cast path would leave that invariant broken.
    serializer.detachPersistentMap(map);
    return;
  }

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
  serializer.object(package.tlsVaultFactoriesByApp);
  serializer.object(package.apiCredentialSetsByApp);
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
  serializer.object(package.reservedApplicationServices);

  serializer.value2b(package.nextReservableApplicationID);
  serializer.object(package.deploymentPlans);
  serializer.object(package.failedDeployments);
  prodigySerializeMasterAuthorityRuntimeState(
      serializer, package.runtimeState, &package.containerRuntimeStates, &package.servingRuntimeStates);
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

  // Appended after the legacy payload tail. A zero protocolVersion means no
  // startup authority was supplied, including initial all-master boot and
  // legacy producers without the appended tail.
  ProdigyStatefulStoreSeedAuthority statefulStoreSeedAuthority = {.protocolVersion = 0};
  TruthGlobalMembershipProjection truthMembership = {.protocolVersion = 0};
};

enum class StatefulInitialStoreDisposition : uint64_t {
  mustRecover = 0,
  initialEmptyAuthorized = 1
};

constexpr static uint32_t prodigyContainerStartupFlagShardGroupIndex = 0;
constexpr static uint32_t prodigyContainerStartupFlagShardGroupCountIndex = 1;
constexpr static uint32_t prodigyContainerStartupFlagInitialStoreDispositionIndex = 2;

static inline StatefulInitialStoreDisposition prodigyStatefulInitialStoreDispositionFromStartupFlags(
    const Vector<uint64_t>& flags)
{
  if (flags.size() <= prodigyContainerStartupFlagInitialStoreDispositionIndex ||
      flags[prodigyContainerStartupFlagInitialStoreDispositionIndex] !=
          uint64_t(StatefulInitialStoreDisposition::initialEmptyAuthorized))
  {
    return StatefulInitialStoreDisposition::mustRecover;
  }
  return StatefulInitialStoreDisposition::initialEmptyAuthorized;
}

static inline StatefulInitialStoreDisposition prodigyStatefulInitialStoreDispositionForPlan(
    const ContainerPlan& plan)
{
  if (!plan.isStateful || plan.config.type != ApplicationType::stateful || plan.nShardGroups == 0 ||
      plan.shardGroup >= plan.nShardGroups || plan.statefulTopology.shardGroup != plan.shardGroup ||
      plan.statefulMeshRoles.sibling == 0 || plan.statefulMeshRoles.seeding == 0 ||
      !prodigyStatefulMeshRolesConfigured(plan.statefulMeshRoles) ||
      !plan.statefulMeshRoles.hasDistinctServices() ||
      !prodigyStatefulTopologyServesClients(plan.statefulTopology) ||
      (plan.statefulTopology.servingMode != StatefulTopologyServingMode::serve &&
       !prodigyStatefulTopologyIsAllMastersSeedBootstrap(plan.statefulTopology)))
  {
    return StatefulInitialStoreDisposition::mustRecover;
  }

  bool siblingDeclared = false;
  for (const auto& [service, subscription] : plan.subscriptions)
  {
    const StatefulMeshRole role = plan.statefulMeshRoles.classify(service);
    if (role == StatefulMeshRole::sibling && service == plan.statefulMeshRoles.sibling &&
        subscription.startAt == ContainerState::scheduled &&
        subscription.stopAt == ContainerState::destroying && subscription.nature == SubscriptionNature::all)
    {
      siblingDeclared = true;
    }
    else if (role == StatefulMeshRole::seeding)
    {
      if (subscription.nature != SubscriptionNature::none ||
          !prodigyStatefulTopologyIsAllMastersSeedBootstrap(plan.statefulTopology))
      {
        return StatefulInitialStoreDisposition::mustRecover;
      }
    }
    else
    {
      return StatefulInitialStoreDisposition::mustRecover;
    }
  }

  return siblingDeclared ? StatefulInitialStoreDisposition::initialEmptyAuthorized :
      StatefulInitialStoreDisposition::mustRecover;
}

// A private listener declaration is carried to the process without publishing
// a mesh advertisement. The application still needs authenticated writeOwner
// authority before restoring its pruned client role and installing the socket.
static inline bool prodigyProjectStatefulDataClientPort(const ContainerPlan& plan, ContainerParameters& parameters)
{
  if (plan.statefulTopology.servingMode != StatefulTopologyServingMode::applicationDataAuthority) return true;
  if (!prodigyStatefulDataAuthorityValid(plan.statefulTopology.dataAuthority) ||
      !plan.declaredStatefulClientService || plan.declaredStatefulClientPort < 1024) return false;
  auto advertisement = plan.advertisements.find(plan.declaredStatefulClientService);
  if (advertisement != plan.advertisements.end() && advertisement->second.port != plan.declaredStatefulClientPort) return false;
  parameters.advertisesOnPorts.insert_or_assign(plan.declaredStatefulClientService, plan.declaredStatefulClientPort);
  return true;
}

template <typename S>
static void prodigySerializeContainerParameterFields(S&& serializer, ContainerParameters& params)
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

template <typename S>
static void serialize(S&& serializer, ContainerParameters& params)
{
  prodigySerializeContainerParameterFields(serializer, params);

  // Bitsery startup payloads predate this authority.  Only consume the
  // append-only tail when it is present so retained launches remain readable.
  if constexpr (requires { serializer.adapter().isCompletedSuccessfully(); })
  {
    if (!serializer.adapter().isCompletedSuccessfully())
    {
      serializer.object(params.statefulStoreSeedAuthority);
      // A retired selected-home extension requires explicit migration; it
      // must never be ignored while launching against the canonical app home.
      if (!serializer.adapter().isCompletedSuccessfully()) {
        serializer.object(params.truthMembership);
        if (!prodigyTruthLocalMember(params.truthMembership,params.deploymentID,params.uuid) || !serializer.adapter().isCompletedSuccessfully())
          serializer.adapter().error(bitsery::ReaderError::InvalidData);
      } else params.truthMembership = {.protocolVersion = 0};
    }
    else
    {
      params.statefulStoreSeedAuthority = {.protocolVersion = 0};
      params.truthMembership = {.protocolVersion = 0};
    }
  }
  else
  {
    serializer.object(params.statefulStoreSeedAuthority);
    if (params.truthMembership.protocolVersion) serializer.object(params.truthMembership);
  }
}
