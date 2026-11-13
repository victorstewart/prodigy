#pragma once

// The qualification manifest is a control-plane contract, not permission to
// invent workloads.  Each CLI spelling maps to exactly one row and direction;
// execution is admitted only when Brain exposes the matching authenticated
// application probe and convergence oracle.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string_view>

#include <networking/includes.h>
#include <prodigy/sha256.digest.h>
#include <prodigy/types.h>
#include <prodigy/cousin.route.h>
#include <prodigy/cousin.service.permission.h>
#include <prodigy/cross.cluster.path.fault.h>

enum class MothershipNametagQualificationDirection : uint8_t { injection = 1, observation = 2 };

using MothershipNametagQualificationRow = ProdigyNametagQualificationRow;

// Rows two, three, fourteen, and fifteen are App11-owned experiments: their descriptors carry
// fault names so the witnesses remain precise, but Mothership must neither
// apply nor restore infrastructure faults for them.  Every other non-none
// fault remains unavailable until an authenticated infrastructure owner is
// explicitly wired into the qualification executor.
static constexpr bool mothershipNametagQualificationRequiresExternalFaultOwnership(
    MothershipNametagQualificationRow row)
{
  return prodigyNametagQualificationDescriptor(row).fault != ProdigyNametagQualificationFault::none &&
      row != MothershipNametagQualificationRow::secondStreamHandoffFence &&
      row != MothershipNametagQualificationRow::sharedKeyCommutativeWrites &&
      row != MothershipNametagQualificationRow::radarDirectedMutations &&
      row != MothershipNametagQualificationRow::pulseFixedMatrixDedup;
}

// This reports code availability only. Native fault receipts and application
// witnesses still gate every actual execution and every completed result.
static constexpr bool mothershipNametagQualificationImplemented(MothershipNametagQualificationRow row)
{
  return !mothershipNametagQualificationRequiresExternalFaultOwnership(row) ||
      row == MothershipNametagQualificationRow::permissionRevokeReinstall ||
      row == MothershipNametagQualificationRow::cousinRouteSessionReconnect ||
      row == MothershipNametagQualificationRow::secondTruthWriterFencing ||
      row == MothershipNametagQualificationRow::mothershipRestartResume ||
      row == MothershipNametagQualificationRow::truthClaimPartition ||
      row == MothershipNametagQualificationRow::localWriterIsolation ||
      row == MothershipNametagQualificationRow::graphKvReplayReorder ||
      row == MothershipNametagQualificationRow::seedInterruptionResume ||
      row == MothershipNametagQualificationRow::brainHardRebootCatchup ||
      row == MothershipNametagQualificationRow::sitePartitionLocalWrites ||
      row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ||
      row == MothershipNametagQualificationRow::ewrOrdPathLoss;
}

// Qualification may not reinterpret a row descriptor as authority to select
// a route, permission, host, or provider action.  These reasons document the
// precise missing typed hand-off at the control-plane boundary.  They are
// intentionally stable strings because the argument-free operations have no
// other safe way to tell an operator which durable owner must be wired.
static constexpr const char *mothershipNametagQualificationFaultOwnerUnavailableReason(
    MothershipNametagQualificationRow row)
{
  switch (row) {
    case MothershipNametagQualificationRow::permissionRevokeReinstall:
      return "qualification all-masters record has no exact cousin permission identities";
    case MothershipNametagQualificationRow::cousinRouteSessionReconnect:
      return "qualification all-masters record has no exact cousin route generation identities";
    case MothershipNametagQualificationRow::masqueSessionLossBgpRecovery:
      return "MASQUE path-fault lifecycle has no Mothership-to-gateway session-control operation";
    case MothershipNametagQualificationRow::ewrOrdPathLoss:
      return "EWR-ORD path fault only exposes a sealed physical-provider operation";
    case MothershipNametagQualificationRow::sitePartitionLocalWrites:
      return "qualification has no typed site-partition lifecycle owner";
    case MothershipNametagQualificationRow::secondTruthWriterFencing:
      return "second Truth-writer admission is fenced, but row lacks the App11 stale-session witness";
    default:
      return "qualification disruptive row has no fault/restore phase owner";
  }
}

static constexpr ProdigyNametagQualificationDescriptor mothershipNametagQualificationDescriptor(
    MothershipNametagQualificationRow row)
{
  return prodigyNametagQualificationDescriptor(row);
}

class MothershipNametagQualificationAdapter {
public:
  MothershipNametagQualificationRow row = MothershipNametagQualificationRow::sequentialUserKeyWrites;
  MothershipNametagQualificationDirection direction = MothershipNametagQualificationDirection::injection;
  const char *operation = nullptr;
  const char *rowID = nullptr;
  uint32_t deadlineSeconds = 0;
  uint32_t convergenceSeconds = 0;
};

// This is intentionally the sole spelling table.  It keeps the manifest's
// 34 public operations as thin row adapters rather than 34 state machines.
constexpr static MothershipNametagQualificationAdapter mothershipNametagQualificationAdapters[] = {
  {MothershipNametagQualificationRow::brainHardRebootCatchup, MothershipNametagQualificationDirection::injection, "nametagChaosBrainHardRebootCatchup", "brain-hard-reboot-catchup", 180, 120},
  {MothershipNametagQualificationRow::cousinRouteSessionReconnect, MothershipNametagQualificationDirection::injection, "nametagChaosCousinRouteSessionReconnect", "cousin-route-session-reconnect", 180, 120},
  {MothershipNametagQualificationRow::ewrOrdPathLoss, MothershipNametagQualificationDirection::injection, "nametagChaosEwrOrdPathLoss", "ewr-ord-path-loss", 180, 120},
  {MothershipNametagQualificationRow::graphKvReplayReorder, MothershipNametagQualificationDirection::injection, "nametagChaosGraphKvReplayReorder", "graph-kv-replay-reorder", 120, 90},
  {MothershipNametagQualificationRow::localWriterIsolation, MothershipNametagQualificationDirection::injection, "nametagChaosLocalWriterIsolation", "local-writer-isolation", 120, 90},
  {MothershipNametagQualificationRow::masqueSessionLossBgpRecovery, MothershipNametagQualificationDirection::injection, "nametagChaosMasqueSessionLossBgpRecovery", "masque-session-loss-bgp-recovery", 180, 120},
  {MothershipNametagQualificationRow::mothershipRestartResume, MothershipNametagQualificationDirection::injection, "nametagChaosMothershipRestartResume", "mothership-restart-resume", 180, 120},
  {MothershipNametagQualificationRow::permissionRevokeReinstall, MothershipNametagQualificationDirection::injection, "nametagChaosPermissionRevokeReinstall", "permission-revoke-reinstall", 180, 120},
  {MothershipNametagQualificationRow::pulseFixedMatrixDedup, MothershipNametagQualificationDirection::injection, "nametagChaosPulseFixedMatrixDedup", "pulse-fixed-matrix-dedup", 120, 90},
  {MothershipNametagQualificationRow::radarDirectedMutations, MothershipNametagQualificationDirection::injection, "nametagChaosRadarDirectedMutations", "radar-directed-mutations", 120, 90},
  {MothershipNametagQualificationRow::secondStreamHandoffFence, MothershipNametagQualificationDirection::injection, "nametagChaosSecondStreamHandoffFence", "second-stream-handoff-fence", 120, 90},
  {MothershipNametagQualificationRow::secondTruthWriterFencing, MothershipNametagQualificationDirection::injection, "nametagChaosSecondTruthWriterFencing", "second-truth-writer-fencing", 120, 90},
  {MothershipNametagQualificationRow::seedInterruptionResume, MothershipNametagQualificationDirection::injection, "nametagChaosSeedInterruptionResume", "seed-interruption-resume", 180, 120},
  {MothershipNametagQualificationRow::sequentialUserKeyWrites, MothershipNametagQualificationDirection::injection, "nametagChaosSequentialUserKeyWrites", "sequential-user-key-writes", 120, 90},
  {MothershipNametagQualificationRow::sharedKeyCommutativeWrites, MothershipNametagQualificationDirection::injection, "nametagChaosSharedKeyCommutativeWrites", "shared-key-commutative-writes", 120, 90},
  {MothershipNametagQualificationRow::sitePartitionLocalWrites, MothershipNametagQualificationDirection::injection, "nametagChaosSitePartitionLocalWrites", "site-partition-local-writes", 180, 120},
  {MothershipNametagQualificationRow::truthClaimPartition, MothershipNametagQualificationDirection::injection, "nametagChaosTruthClaimPartition", "truth-claim-partition", 180, 120},
  {MothershipNametagQualificationRow::brainHardRebootCatchup, MothershipNametagQualificationDirection::observation, "nametagObserveBrainHardRebootCatchup", "brain-hard-reboot-catchup", 180, 120},
  {MothershipNametagQualificationRow::cousinRouteSessionReconnect, MothershipNametagQualificationDirection::observation, "nametagObserveCousinRouteSessionReconnect", "cousin-route-session-reconnect", 180, 120},
  {MothershipNametagQualificationRow::ewrOrdPathLoss, MothershipNametagQualificationDirection::observation, "nametagObserveEwrOrdPathLoss", "ewr-ord-path-loss", 180, 120},
  {MothershipNametagQualificationRow::graphKvReplayReorder, MothershipNametagQualificationDirection::observation, "nametagObserveGraphKvReplayReorder", "graph-kv-replay-reorder", 120, 90},
  {MothershipNametagQualificationRow::localWriterIsolation, MothershipNametagQualificationDirection::observation, "nametagObserveLocalWriterIsolation", "local-writer-isolation", 120, 90},
  {MothershipNametagQualificationRow::masqueSessionLossBgpRecovery, MothershipNametagQualificationDirection::observation, "nametagObserveMasqueSessionLossBgpRecovery", "masque-session-loss-bgp-recovery", 180, 120},
  {MothershipNametagQualificationRow::mothershipRestartResume, MothershipNametagQualificationDirection::observation, "nametagObserveMothershipRestartResume", "mothership-restart-resume", 180, 120},
  {MothershipNametagQualificationRow::permissionRevokeReinstall, MothershipNametagQualificationDirection::observation, "nametagObservePermissionRevokeReinstall", "permission-revoke-reinstall", 180, 120},
  {MothershipNametagQualificationRow::pulseFixedMatrixDedup, MothershipNametagQualificationDirection::observation, "nametagObservePulseFixedMatrixDedup", "pulse-fixed-matrix-dedup", 120, 90},
  {MothershipNametagQualificationRow::radarDirectedMutations, MothershipNametagQualificationDirection::observation, "nametagObserveRadarDirectedMutations", "radar-directed-mutations", 120, 90},
  {MothershipNametagQualificationRow::secondStreamHandoffFence, MothershipNametagQualificationDirection::observation, "nametagObserveSecondStreamHandoffFence", "second-stream-handoff-fence", 120, 90},
  {MothershipNametagQualificationRow::secondTruthWriterFencing, MothershipNametagQualificationDirection::observation, "nametagObserveSecondTruthWriterFencing", "second-truth-writer-fencing", 120, 90},
  {MothershipNametagQualificationRow::seedInterruptionResume, MothershipNametagQualificationDirection::observation, "nametagObserveSeedInterruptionResume", "seed-interruption-resume", 180, 120},
  {MothershipNametagQualificationRow::sequentialUserKeyWrites, MothershipNametagQualificationDirection::observation, "nametagObserveSequentialUserKeyWrites", "sequential-user-key-writes", 120, 90},
  {MothershipNametagQualificationRow::sharedKeyCommutativeWrites, MothershipNametagQualificationDirection::observation, "nametagObserveSharedKeyCommutativeWrites", "shared-key-commutative-writes", 120, 90},
  {MothershipNametagQualificationRow::sitePartitionLocalWrites, MothershipNametagQualificationDirection::observation, "nametagObserveSitePartitionLocalWrites", "site-partition-local-writes", 180, 120},
  {MothershipNametagQualificationRow::truthClaimPartition, MothershipNametagQualificationDirection::observation, "nametagObserveTruthClaimPartition", "truth-claim-partition", 180, 120},
};

static inline const MothershipNametagQualificationAdapter *mothershipNametagQualificationAdapter(std::string_view operation)
{
  for (const auto& adapter : mothershipNametagQualificationAdapters)
    if (operation == adapter.operation) return &adapter;
  return nullptr;
}

static inline const MothershipNametagQualificationAdapter *mothershipNametagQualificationAdapterForTuple(
    MothershipNametagQualificationRow row, MothershipNametagQualificationDirection direction,
    const String& rowID, uint32_t deadlineSeconds, uint32_t convergenceSeconds)
{
  for (const auto& adapter : mothershipNametagQualificationAdapters)
    if (adapter.row == row && adapter.direction == direction && rowID.equal(String(adapter.rowID)) &&
        adapter.deadlineSeconds == deadlineSeconds && adapter.convergenceSeconds == convergenceSeconds)
      return &adapter;
  return nullptr;
}

class MothershipNametagQualificationProbeTarget {
public:
  uint128_t clusterUUID = 0;
  uint64_t probeDeploymentID = 0;
};
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationProbeTarget& target)
{ serializer.value16b(target.clusterUUID); serializer.value8b(target.probeDeploymentID); }
static inline bool mothershipNametagQualificationProbeTargetValid(
    const MothershipNametagQualificationProbeTarget& target)
{ return target.clusterUUID != 0 && target.probeDeploymentID != 0; }

// The exact commissioned route and all successor identities are persisted
// before a disruptive command.  Old permission and route tombstones survive.
struct MothershipNametagQualificationCousinRecovery {
  uint128_t routeUUID = 0;
  uint128_t withdrawOperationUUID = 0;
  uint128_t successorRouteUUID = 0;
  uint128_t successorRouteOperationUUID = 0;
  uint128_t successorPermissionUUID = 0; // row 9 only; EWR source half
};
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationCousinRecovery& value)
{
  serializer.value16b(value.routeUUID); serializer.value16b(value.withdrawOperationUUID);
  serializer.value16b(value.successorRouteUUID); serializer.value16b(value.successorRouteOperationUUID);
  serializer.value16b(value.successorPermissionUUID);
}

// One durable intent binds all three sites to the already-persisted
// all-masters topology.  A single-cluster receipt can therefore never be
// promoted into a three-cluster qualification result.
class MothershipNametagQualificationIntent {
public:
  // v5 binds row sixteen's read-only observation to one completed injection.
  static constexpr uint32_t version = 6;
  static constexpr uint32_t cousinRecoveryVersion = 7;
  static constexpr uint32_t seedVersion = 8;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0;
  MothershipNametagQualificationRow row = MothershipNametagQualificationRow::sequentialUserKeyWrites;
  MothershipNametagQualificationDirection direction = MothershipNametagQualificationDirection::injection;
  uint64_t executionGeneration = 0;
  String rowID;
  ProdigyNametagQualificationDescriptor descriptor;
  uint128_t allMastersOperationUUID = 0;
  Vector<MothershipNametagQualificationProbeTarget> probeTargets;
  uint32_t deadlineSeconds = 0;
  uint32_t convergenceSeconds = 0;
  int64_t startedAtMilliseconds = 0;
  int64_t deadlineAtMilliseconds = 0;
  int64_t convergenceDeadlineAtMilliseconds = 0;
  uint128_t priorInjectionRunUUID = 0;
  String priorInjectionReceiptDigest;
  Vector<ProdigyNametagQualificationApp6Route> app6Routes;
  Vector<MothershipNametagQualificationCousinRecovery> cousinRecoveries;
  String seedInputSHA256;
  Vector<uint128_t> seedSuccessorOperationUUIDs, seedChallengeUUIDs;
};
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationIntent& intent)
{ serializer.value4b(intent.protocolVersion); serializer.value16b(intent.runUUID); serializer.value1b(intent.row); serializer.value1b(intent.direction);
  serializer.value8b(intent.executionGeneration); serializer.text1b(intent.rowID, 128); serializer.object(intent.descriptor); serializer.value16b(intent.allMastersOperationUUID);
  serializer.container(intent.probeTargets, 3);
  serializer.value4b(intent.deadlineSeconds); serializer.value4b(intent.convergenceSeconds); serializer.value8b(intent.startedAtMilliseconds);
  serializer.value8b(intent.deadlineAtMilliseconds); serializer.value8b(intent.convergenceDeadlineAtMilliseconds);
  if (intent.protocolVersion >= 5) {
    serializer.value16b(intent.priorInjectionRunUUID);
    serializer.text1b(intent.priorInjectionReceiptDigest, 64);
  }
  if (intent.protocolVersion >= 6) serializer.container(intent.app6Routes, 6);
  if (intent.protocolVersion >= 7) serializer.container(intent.cousinRecoveries, 2);
  if (intent.protocolVersion >= 8) { serializer.text1b(intent.seedInputSHA256, 64);
    serializer.container(intent.seedSuccessorOperationUUIDs, 2, [](auto& s, uint128_t& value) { s.value16b(value); });
    serializer.container(intent.seedChallengeUUIDs, 2, [](auto& s, uint128_t& value) { s.value16b(value); }); }
}

static inline bool mothershipNametagQualificationIntentValid(const MothershipNametagQualificationIntent& intent)
{
  if ((intent.protocolVersion != 5 && intent.protocolVersion != MothershipNametagQualificationIntent::version &&
       intent.protocolVersion != MothershipNametagQualificationIntent::cousinRecoveryVersion &&
       intent.protocolVersion != MothershipNametagQualificationIntent::seedVersion) || intent.runUUID == 0 ||
      intent.executionGeneration == 0 || !prodigyNametagQualificationDescriptorValid(intent.descriptor) ||
      !prodigyNametagQualificationDescriptorEqual(intent.descriptor, mothershipNametagQualificationDescriptor(intent.row)) ||
      intent.allMastersOperationUUID == 0 || intent.probeTargets.size() != 3 || intent.startedAtMilliseconds <= 0 ||
      intent.deadlineAtMilliseconds <= intent.startedAtMilliseconds ||
      intent.convergenceDeadlineAtMilliseconds < intent.startedAtMilliseconds ||
      intent.convergenceDeadlineAtMilliseconds > intent.deadlineAtMilliseconds) return false;
  if (intent.row == MothershipNametagQualificationRow::secondStreamHandoffFence ||
      intent.row == MothershipNametagQualificationRow::truthClaimPartition) {
    if (intent.protocolVersion < 6 || intent.app6Routes.size() != 6) return false;
    for (size_t site = 0; site < 3; ++site) {
      Vector<ProdigyNametagQualificationApp6Route> pair = {intent.app6Routes[site * 2], intent.app6Routes[site * 2 + 1]};
      if (!prodigyNametagQualificationApp6RoutesValid(pair) || pair[0].clusterUUID != intent.probeTargets[site].clusterUUID ||
          std::count_if(intent.probeTargets.begin(), intent.probeTargets.end(),
              [&](const auto& target) { return target.clusterUUID == pair[1].clusterUUID; }) != 1) return false;
    }
    for (size_t i = 0; i < intent.app6Routes.size(); ++i)
      for (const auto& cid : intent.app6Routes[i].cids)
        for (size_t previous = 0; previous < i; ++previous)
          for (const auto& prior : intent.app6Routes[previous].cids)
            if (cid == prior) return false;
  } else if (!intent.app6Routes.empty()) return false;
  const bool cousinRecoveryRow = intent.row == MothershipNametagQualificationRow::permissionRevokeReinstall ||
      intent.row == MothershipNametagQualificationRow::cousinRouteSessionReconnect;
  if (intent.protocolVersion == MothershipNametagQualificationIntent::cousinRecoveryVersion) {
    if (!cousinRecoveryRow || intent.cousinRecoveries.empty() || intent.cousinRecoveries.size() > 2) return false;
    for (uint32_t i = 0; i < intent.cousinRecoveries.size(); ++i) {
      const auto& recovery = intent.cousinRecoveries[i];
      if (!recovery.routeUUID || !recovery.withdrawOperationUUID || !recovery.successorRouteUUID ||
          !recovery.successorRouteOperationUUID || recovery.routeUUID == recovery.successorRouteUUID ||
          recovery.withdrawOperationUUID == recovery.successorRouteOperationUUID ||
          (intent.row == MothershipNametagQualificationRow::permissionRevokeReinstall ?
              recovery.successorPermissionUUID == 0 : recovery.successorPermissionUUID != 0)) return false;
      for (uint32_t j = 0; j < i; ++j) {
        const auto& previous = intent.cousinRecoveries[j];
        if (previous.routeUUID == recovery.routeUUID || previous.successorRouteUUID == recovery.successorRouteUUID ||
            previous.routeUUID == recovery.successorRouteUUID || previous.successorRouteUUID == recovery.routeUUID ||
            previous.withdrawOperationUUID == recovery.withdrawOperationUUID ||
            previous.withdrawOperationUUID == recovery.successorRouteOperationUUID ||
            previous.successorRouteOperationUUID == recovery.withdrawOperationUUID ||
            previous.successorRouteOperationUUID == recovery.successorRouteOperationUUID ||
            (recovery.successorPermissionUUID && previous.successorPermissionUUID == recovery.successorPermissionUUID)) return false;
      }
    }
  } else if (!intent.cousinRecoveries.empty()) return false;
  const bool seedRow = prodigyNametagQualificationSeedReadbackRow(uint8_t(intent.row));
  if (intent.protocolVersion == MothershipNametagQualificationIntent::seedVersion) {
    const size_t n = intent.row == MothershipNametagQualificationRow::seedInterruptionResume ? 2 : 1;
    if (!seedRow || !prodigyIsSHA256HexDigest(intent.seedInputSHA256) ||
        intent.seedSuccessorOperationUUIDs.size() != n || intent.seedChallengeUUIDs.size() != n) return false;
    for (size_t i = 0; i < n; ++i) {
      if (!intent.seedSuccessorOperationUUIDs[i] || !intent.seedChallengeUUIDs[i]) return false;
      for (size_t j = 0; j < n; ++j)
        if (intent.seedSuccessorOperationUUIDs[i] == intent.seedChallengeUUIDs[j]) return false;
      for (size_t j = 0; j < i; ++j)
        if (intent.seedSuccessorOperationUUIDs[i] == intent.seedSuccessorOperationUUIDs[j] ||
            intent.seedChallengeUUIDs[i] == intent.seedChallengeUUIDs[j]) return false;
    }
  } else if (!intent.seedInputSHA256.empty() || !intent.seedSuccessorOperationUUIDs.empty() || !intent.seedChallengeUUIDs.empty()) return false;
  for (uint32_t target = 0; target < intent.probeTargets.size(); ++target) {
    if (!mothershipNametagQualificationProbeTargetValid(intent.probeTargets[target])) return false;
    for (uint32_t prior = 0; prior < target; ++prior)
      if (intent.probeTargets[prior].clusterUUID == intent.probeTargets[target].clusterUUID ||
          intent.probeTargets[prior].probeDeploymentID == intent.probeTargets[target].probeDeploymentID) return false;
  }
  const uint64_t deadlineMs = uint64_t(intent.deadlineSeconds) * 1000;
  const uint64_t convergenceMs = uint64_t(intent.convergenceSeconds) * 1000;
  return deadlineMs != 0 && convergenceMs != 0 && convergenceMs <= deadlineMs &&
      uint64_t(intent.deadlineAtMilliseconds - intent.startedAtMilliseconds) == deadlineMs &&
      uint64_t(intent.convergenceDeadlineAtMilliseconds - intent.startedAtMilliseconds) == convergenceMs &&
      mothershipNametagQualificationAdapterForTuple(intent.row, intent.direction, intent.rowID,
                                                    intent.deadlineSeconds, intent.convergenceSeconds) != nullptr &&
      (((intent.row == MothershipNametagQualificationRow::secondTruthWriterFencing ||
        intent.row == MothershipNametagQualificationRow::mothershipRestartResume ||
        intent.row == MothershipNametagQualificationRow::localWriterIsolation ||
        intent.row == MothershipNametagQualificationRow::truthClaimPartition ||
        intent.row == MothershipNametagQualificationRow::graphKvReplayReorder ||
        (intent.protocolVersion == MothershipNametagQualificationIntent::seedVersion && seedRow) ||
        prodigyNametagQualificationPathRow(uint8_t(intent.row)) || cousinRecoveryRow) &&
        intent.direction == MothershipNametagQualificationDirection::observation) ?
          (intent.priorInjectionRunUUID == intent.runUUID &&
           prodigyIsSHA256HexDigest(intent.priorInjectionReceiptDigest)) :
          (intent.priorInjectionRunUUID == 0 && intent.priorInjectionReceiptDigest.empty()));
}

// This is deliberately a phase of the immutable qualification intent, not a
// second per-row runner.  In particular, a restart may only continue the
// already-bound v4 target set; it may never select a fresh generation after a
// disruptive command has been admitted.
enum class MothershipNametagQualificationExecutionPhase : uint8_t {
  prepared = 1, faultApplied, workloadIssued, converging, verified, faultRestored, failed,
};

static inline bool mothershipNametagQualificationExecutionPhaseValid(
    MothershipNametagQualificationExecutionPhase phase)
{
  return phase >= MothershipNametagQualificationExecutionPhase::prepared &&
      phase <= MothershipNametagQualificationExecutionPhase::failed;
}

static inline bool mothershipNametagQualificationExecutionPhaseTransitionValid(
    MothershipNametagQualificationExecutionPhase from,
    MothershipNametagQualificationExecutionPhase to,
    const MothershipNametagQualificationIntent& intent)
{
  if (!mothershipNametagQualificationIntentValid(intent) ||
      !mothershipNametagQualificationExecutionPhaseValid(from) ||
      !mothershipNametagQualificationExecutionPhaseValid(to) || from == to) return false;
  // A global qualification receipt proves all 18 direct routes are ready.
  // Consequently a reversible infrastructure fault must be restored before
  // convergence is observed; treating faultRestored as a post-verification
  // epilogue would make a successful global receipt impossible.
  if (to == MothershipNametagQualificationExecutionPhase::failed) {
    // Never strand a reversible cousin fault behind a terminal failure.  The
    // persisted phase remains resumable until restoration is acknowledged.
    const bool cousinRecovery = intent.row == MothershipNametagQualificationRow::permissionRevokeReinstall ||
        intent.row == MothershipNametagQualificationRow::cousinRouteSessionReconnect;
    if (intent.protocolVersion >= MothershipNametagQualificationIntent::cousinRecoveryVersion && cousinRecovery &&
        (from == MothershipNametagQualificationExecutionPhase::prepared ||
         from == MothershipNametagQualificationExecutionPhase::faultApplied ||
         from == MothershipNametagQualificationExecutionPhase::workloadIssued)) return false;
    return from != MothershipNametagQualificationExecutionPhase::verified;
  }
  const bool cousinObservation = intent.direction == MothershipNametagQualificationDirection::observation &&
      (intent.row == MothershipNametagQualificationRow::permissionRevokeReinstall ||
       intent.row == MothershipNametagQualificationRow::cousinRouteSessionReconnect ||
       intent.row == MothershipNametagQualificationRow::truthClaimPartition ||
       intent.row == MothershipNametagQualificationRow::graphKvReplayReorder ||
       prodigyNametagQualificationPathRow(uint8_t(intent.row)));
  const bool requiresExternalFaultOwnership = !cousinObservation &&
      intent.row != MothershipNametagQualificationRow::mothershipRestartResume &&
      mothershipNametagQualificationRequiresExternalFaultOwnership(intent.row);
  switch (from) {
    case MothershipNametagQualificationExecutionPhase::prepared:
      return (requiresExternalFaultOwnership &&
              to == MothershipNametagQualificationExecutionPhase::faultApplied) ||
          (!requiresExternalFaultOwnership &&
           to == MothershipNametagQualificationExecutionPhase::workloadIssued);
    case MothershipNametagQualificationExecutionPhase::faultApplied:
      return to == MothershipNametagQualificationExecutionPhase::workloadIssued;
    case MothershipNametagQualificationExecutionPhase::workloadIssued:
      return (requiresExternalFaultOwnership &&
              to == MothershipNametagQualificationExecutionPhase::faultRestored) ||
          (!requiresExternalFaultOwnership &&
           to == MothershipNametagQualificationExecutionPhase::converging);
    case MothershipNametagQualificationExecutionPhase::faultRestored:
      return requiresExternalFaultOwnership &&
          to == MothershipNametagQualificationExecutionPhase::converging;
    case MothershipNametagQualificationExecutionPhase::converging:
      return to == MothershipNametagQualificationExecutionPhase::verified;
    default: return false;
  }
}

static inline bool mothershipNametagQualificationExecutionPhaseTerminal(
    MothershipNametagQualificationExecutionPhase phase,
    const MothershipNametagQualificationIntent& intent)
{
  if (!mothershipNametagQualificationIntentValid(intent)) return false;
  return phase == MothershipNametagQualificationExecutionPhase::failed ||
      phase == MothershipNametagQualificationExecutionPhase::verified;
}

class MothershipNametagQualificationExecutionRecord {
public:
  static constexpr uint32_t version = 2;
  static constexpr uint32_t cousinRecoveryVersion = 3;
  static constexpr uint32_t cousinTransportVersion = 5;
  static constexpr uint32_t restartVersion = 6;
  static constexpr uint32_t pathVersion = 7;
  static constexpr uint32_t writerIsolationVersion = 8;
  static constexpr uint32_t replayVersion = 9;
  static constexpr uint32_t claimVersion = 10;
  static constexpr uint32_t seedVersion = 11;
  uint32_t protocolVersion = version;
  MothershipNametagQualificationIntent intent;
  MothershipNametagQualificationExecutionPhase phase = MothershipNametagQualificationExecutionPhase::prepared;
  // Row sixteen is a control-plane admission exercise.  This receipt records
  // the existing singleton policy's rejection before any deployment request
  // can reach a target Brain.
  class SecondTruthWriterAdmissionReceipt {
  public:
    uint128_t sourceClusterUUID = 0;
    uint128_t candidateClusterUUID = 0;
    uint128_t retainedOwnerClusterUUID = 0;
    uint64_t retainedPlacementGeneration = 0;
    String candidatePlanSHA256;
    bool fenced = false;
  } secondTruthWriterAdmission;
  struct CousinRecoveryBinding {
    CousinRouteRecord route = {};
    ProdigyLocalCousinServicePermission sourcePermission = {};
    ProdigyLocalCousinServicePermission destinationPermission = {};
    CousinRouteApplyReceipt sourceReceipt = {}, destinationReceipt = {};
    uint64_t sourceAuthorityGeneration = 0, destinationAuthorityGeneration = 0;
  };
  Vector<CousinRecoveryBinding> cousinRecoveryBindings;
  bool cousinRecoveryAborting = false;
  struct CousinNativeWitness {
    ProdigyNametagQualificationCousinTransport challenge = {}, arm = {}, fault = {}, final = {};
  };
  Vector<CousinNativeWitness> cousinNativeWitnesses;
  ProdigyNametagQualificationApplicationReceipt cousinLocalWorkReceipt = {};
  struct RestartProcess {
    uint64_t pid = 0, startTime = 0;
    String bootID, executableSHA256;
  } restartBefore, restartAfter;
  uint128_t restartNonce = 0;
  ProdigyNametagQualificationApplicationReceipt restartLocalWorkReceipt = {};
  struct PathFaultWitness {
    uint8_t batch = 0;
    ProdigyCrossClusterPathFaultControl request = {}, paused = {}, restored = {};
  };
  Vector<PathFaultWitness> pathFaults;
  Vector<ProdigyNametagQualificationApplicationReceipt> pathWorkReceipts;
  bool pathAborting = false;
  uint8_t pathRestoringBatches = 0;
  struct PathSurvivorStage {
    int64_t observedAtMilliseconds = 0;
    Vector<ProdigyCrossClusterPathFaultSurvivorReceipt> receipts;
  } pathSurvivorsBefore, pathSurvivorsDuring;
  struct WriterIsolationWitness {
    ProdigyNametagQualificationWriterIsolation challenge = {}, arm = {}, isolated = {}, queried = {}, released = {};
    ProdigyNametagQualificationApplicationReceipt localArm = {}, localWork = {};
    bool aborting = false;
  } writerIsolation;
  struct ReplayWitness {
    ProdigyNametagQualificationReplay sourceChallenge = {}, sourceArm = {}, sourceCapture = {}, sourceReplay = {}, sourceQuery = {}, sourceRelease = {};
    ProdigyNametagQualificationReplay targetPrearmChallenge = {}, targetPrearm = {};
    ProdigyNametagQualificationReplay targetChallenge = {}, targetArm = {}, targetReplay = {}, targetQuery = {}, targetRelease = {};
  };
  Vector<ReplayWitness> replayWitnesses;
  ProdigyNametagQualificationApplicationReceipt replayLocalWork = {};
  Vector<ProdigyNametagQualificationApplicationReceipt> replayFinalReadbacks;
  int64_t replayQueriesCompletedAtMilliseconds = 0;
  bool replayAborting = false;
  Vector<ProdigyNametagQualificationApplicationReceipt> claimReceipts;
  std::array<uint128_t, 3> claimWinnerSites = {};
  struct SeedSuccessorRef { uint128_t operationUUID = 0; String sha256; };
  Vector<SeedSuccessorRef> seedSuccessors;
  Vector<ProdigyNametagQualificationApplicationReceipt> seedFinalReadbacks;
  uint128_t seedBaselineOperationUUID = 0;
  String seedBaselineFixtureSHA256, seedBaselineReadbackSHA256, seedControlWitnessDigest;
  std::array<std::array<uint64_t, 5>, 3> seedStoreDeploymentIDs = {};
};
template <typename S>
static void serialize(S&& s, MothershipNametagQualificationExecutionRecord::PathFaultWitness& w)
{ s.value1b(w.batch); s.object(w.request); s.object(w.paused); s.object(w.restored); }
template <typename S>
static void serialize(S&& s, MothershipNametagQualificationExecutionRecord::PathSurvivorStage& w)
{ s.value8b(w.observedAtMilliseconds); s.container(w.receipts, 12); }
template <typename S>
static void serialize(S&& s, MothershipNametagQualificationExecutionRecord::ReplayWitness& w)
{ s.object(w.sourceChallenge); s.object(w.sourceArm); s.object(w.sourceCapture); s.object(w.sourceReplay); s.object(w.sourceQuery); s.object(w.sourceRelease);
  s.object(w.targetPrearmChallenge); s.object(w.targetPrearm);
  s.object(w.targetChallenge); s.object(w.targetArm); s.object(w.targetReplay); s.object(w.targetQuery); s.object(w.targetRelease); }
template <typename S>
static void serialize(S&& s, MothershipNametagQualificationExecutionRecord::WriterIsolationWitness& w)
{ s.object(w.challenge); s.object(w.arm); s.object(w.isolated); s.object(w.queried); s.object(w.released); s.object(w.localArm); s.object(w.localWork); s.value1b(w.aborting); }
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationExecutionRecord::RestartProcess& process)
{ serializer.value8b(process.pid); serializer.value8b(process.startTime); serializer.text1b(process.bootID, 64); serializer.text1b(process.executableSHA256, 64); }
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationExecutionRecord::CousinNativeWitness& witness)
{ serializer.object(witness.challenge); serializer.object(witness.arm); serializer.object(witness.fault); serializer.object(witness.final); }
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationExecutionRecord::CousinRecoveryBinding& binding)
{
  serializer.object(binding.route); serializer.object(binding.sourcePermission);
  serializer.object(binding.destinationPermission); serializer.object(binding.sourceReceipt);
  serializer.object(binding.destinationReceipt);
  serializer.value8b(binding.sourceAuthorityGeneration); serializer.value8b(binding.destinationAuthorityGeneration);
}
template <typename S>
static void serialize(S&& serializer,
    MothershipNametagQualificationExecutionRecord::SecondTruthWriterAdmissionReceipt& receipt)
{
  serializer.value16b(receipt.sourceClusterUUID);
  serializer.value16b(receipt.candidateClusterUUID);
  serializer.value16b(receipt.retainedOwnerClusterUUID);
  serializer.value8b(receipt.retainedPlacementGeneration);
  serializer.text1b(receipt.candidatePlanSHA256, 64);
  serializer.value1b(receipt.fenced);
}
template <typename S>
static void serialize(S&& s, MothershipNametagQualificationExecutionRecord::SeedSuccessorRef& ref)
{ s.value16b(ref.operationUUID); s.text1b(ref.sha256, 64); }
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationExecutionRecord& record)
{ serializer.value4b(record.protocolVersion); serializer.object(record.intent); serializer.value1b(record.phase);
  if (record.protocolVersion >= 2) {
    serializer.object(record.secondTruthWriterAdmission);
  }
  if (record.protocolVersion >= 3) {
    serializer.container(record.cousinRecoveryBindings, 2);
    serializer.value1b(record.cousinRecoveryAborting);
  }
  if (record.protocolVersion >= 5) { serializer.container(record.cousinNativeWitnesses, 2); serializer.object(record.cousinLocalWorkReceipt); }
  if (record.protocolVersion >= 6) { serializer.value16b(record.restartNonce); serializer.object(record.restartBefore);
    serializer.object(record.restartAfter); serializer.object(record.restartLocalWorkReceipt); }
  if (record.protocolVersion >= 7) { serializer.container(record.pathFaults, 12); serializer.container(record.pathWorkReceipts, 18); serializer.value1b(record.pathAborting); serializer.value1b(record.pathRestoringBatches); serializer.object(record.pathSurvivorsBefore); serializer.object(record.pathSurvivorsDuring); }
  if (record.protocolVersion >= 8) serializer.object(record.writerIsolation);
  if (record.protocolVersion >= 9) { serializer.container(record.replayWitnesses, 2); serializer.object(record.replayLocalWork);
    serializer.container(record.replayFinalReadbacks, 3); serializer.value8b(record.replayQueriesCompletedAtMilliseconds); serializer.value1b(record.replayAborting); }
  if (record.protocolVersion >= 10) { serializer.container(record.claimReceipts, 15);
    for (auto& site : record.claimWinnerSites) serializer.value16b(site); }
  if (record.protocolVersion >= 11) { serializer.container(record.seedSuccessors, 2); serializer.container(record.seedFinalReadbacks, 3);
    serializer.value16b(record.seedBaselineOperationUUID); serializer.text1b(record.seedBaselineFixtureSHA256, 64);
    serializer.text1b(record.seedBaselineReadbackSHA256, 64); serializer.text1b(record.seedControlWitnessDigest, 64);
    for (auto& site : record.seedStoreDeploymentIDs) for (auto& id : site) serializer.value8b(id); }
}
static inline bool mothershipNametagQualificationSecondTruthWriterAdmissionValid(
    const MothershipNametagQualificationExecutionRecord::SecondTruthWriterAdmissionReceipt& receipt)
{
  return receipt.sourceClusterUUID != 0 && receipt.candidateClusterUUID != 0 &&
      receipt.retainedOwnerClusterUUID == receipt.sourceClusterUUID &&
      receipt.candidateClusterUUID != receipt.retainedOwnerClusterUUID &&
      receipt.retainedPlacementGeneration != 0 && prodigyIsSHA256HexDigest(receipt.candidatePlanSHA256) && receipt.fenced;
}

static inline bool mothershipNametagQualificationSecondTruthWriterAdmissionMatchesIntent(
    const MothershipNametagQualificationIntent& intent,
    const MothershipNametagQualificationExecutionRecord::SecondTruthWriterAdmissionReceipt& receipt)
{
  return intent.row == MothershipNametagQualificationRow::secondTruthWriterFencing &&
      intent.direction == MothershipNametagQualificationDirection::injection &&
      intent.probeTargets.size() == 3 &&
      mothershipNametagQualificationSecondTruthWriterAdmissionValid(receipt) &&
      receipt.sourceClusterUUID == intent.probeTargets[0].clusterUUID &&
      receipt.candidateClusterUUID == intent.probeTargets[1].clusterUUID;
}

// PullDeploymentIdentity is the existing authenticated plan observer.  Row
// sixteen may replay only the exact retained EWR Truth plan it reports; a
// digest, deployment, or singleton-shape mismatch is not an admission attempt.
static inline bool mothershipNametagQualificationSecondTruthWriterCandidatePlan(
    const DeploymentIdentityReport& source, DeploymentPlan& candidate, String *failure = nullptr)
{
  candidate = {};
  String bytes = {}, digest = {};
  if (source.version < 4 || !source.found || !source.live ||
      source.applicationID != MeshRegistry::Truth::applicationID || !source.isStateful ||
      source.clusterUUID == 0 || source.deploymentID == 0 || source.normalizedDeploymentPlan.empty() ||
      !prodigyIsSHA256HexDigest(source.canonicalPlanSHA256) ||
      !BitseryEngine::deserializeSafe(source.normalizedDeploymentPlan, candidate) ||
      !BitseryEngine::serialize(bytes, candidate) || !prodigyComputeSHA256Hex(bytes, digest, failure) ||
      digest != source.canonicalPlanSHA256 || candidate.config.applicationID != MeshRegistry::Truth::applicationID ||
      candidate.config.deploymentID() != source.deploymentID || !candidate.isStateful || candidate.stateful.writerMode == StatefulWriterMode::allMasters) {
    candidate = {};
    if (failure && failure->empty()) failure->assign("second Truth-writer candidate does not match the retained EWR Truth plan"_ctv);
    return false;
  }
  return true;
}
static inline bool mothershipNametagQualificationCousinRecoveryBindingValid(
    const MothershipNametagQualificationIntent& intent, uint32_t index,
    const MothershipNametagQualificationExecutionRecord::CousinRecoveryBinding& binding)
{
  if (intent.protocolVersion != MothershipNametagQualificationIntent::cousinRecoveryVersion ||
      index >= intent.cousinRecoveries.size() || intent.probeTargets.size() != 3) return false;
  const auto& route = binding.route;
  const auto& source = binding.sourcePermission;
  const auto& destination = binding.destinationPermission;
  if (route.routeUUID != intent.cousinRecoveries[index].routeUUID ||
      !binding.sourceAuthorityGeneration || !binding.destinationAuthorityGeneration ||
      source.acceptedAuthorityGeneration > binding.sourceAuthorityGeneration ||
      destination.acceptedAuthorityGeneration > binding.destinationAuthorityGeneration ||
      !cousinRouteCurrentContract(route) || !cousinRouteStructurallyValid(route) ||
      route.state != CousinRouteState::active || route.issuedAtMs > intent.startedAtMilliseconds ||
      route.expiresAtMs <= intent.deadlineAtMilliseconds ||
      route.sourceClusterUUID != intent.probeTargets[0].clusterUUID ||
      route.destinationClusterUUID != intent.probeTargets[1].clusterUUID ||
      !cousinRouteApplyReceiptMatchesCurrentRoute(binding.sourceReceipt, route) ||
      !cousinRouteApplyReceiptMatchesCurrentRoute(binding.destinationReceipt, route) ||
      binding.sourceReceipt.localHalf != CousinRouteHalf::source ||
      binding.destinationReceipt.localHalf != CousinRouteHalf::destination ||
      !prodigyLocalCousinServicePermissionValid(source) ||
      !prodigyLocalCousinServicePermissionValid(destination) ||
      source.state != ProdigyLocalCousinServicePermissionState::active ||
      destination.state != ProdigyLocalCousinServicePermissionState::active ||
      source.localHalf != CousinRouteHalf::source || destination.localHalf != CousinRouteHalf::destination ||
      source.purpose == ProdigyCousinServicePurpose::seeding || destination.purpose == ProdigyCousinServicePurpose::seeding ||
      source.permissionUUID != route.sourcePermissionUUID || destination.permissionUUID != route.destinationPermissionUUID ||
      source.pairUUID != route.pairUUID || destination.pairUUID != route.pairUUID ||
      source.localClusterUUID != route.sourceClusterUUID || source.peerClusterUUID != route.destinationClusterUUID ||
      destination.localClusterUUID != route.destinationClusterUUID || destination.peerClusterUUID != route.sourceClusterUUID ||
      source.logicalWorkloadUUID != route.logicalWorkloadUUID || destination.logicalWorkloadUUID != route.logicalWorkloadUUID ||
      source.logicalServiceUUID != route.logicalServiceUUID || destination.logicalServiceUUID != route.logicalServiceUUID ||
      source.localApplicationID != route.sourceApplicationID || source.peerApplicationID != route.destinationApplicationID ||
      destination.localApplicationID != route.destinationApplicationID || destination.peerApplicationID != route.sourceApplicationID ||
      source.localCousinServicePrefix != route.sourceCousinServicePrefix || source.peerCousinServicePrefix != route.destinationCousinServicePrefix ||
      destination.localCousinServicePrefix != route.destinationCousinServicePrefix || destination.peerCousinServicePrefix != route.sourceCousinServicePrefix ||
      !prodigyCousinServicePermissionPeerScopeMatches(source, destination)) return false;
  for (uint16_t slot = 0; slot < CousinRouteSlotBitmap::slotCount; ++slot)
    if (route.slots.contains(slot) && (!source.slots.contains(slot) || !destination.slots.contains(slot))) return false;
  return intent.cousinRecoveries[index].successorPermissionUUID != source.permissionUUID &&
      intent.cousinRecoveries[index].successorPermissionUUID != destination.permissionUUID &&
      intent.cousinRecoveries[index].withdrawOperationUUID != route.operationUUID &&
      intent.cousinRecoveries[index].successorRouteOperationUUID != route.operationUUID &&
      !cousinRouteOperationUUIDWasUsed(route, intent.cousinRecoveries[index].withdrawOperationUUID) &&
      !cousinRouteOperationUUIDWasUsed(route, intent.cousinRecoveries[index].successorRouteOperationUUID);
}

static inline bool mothershipNametagQualificationPathExecutionComplete(
    const MothershipNametagQualificationExecutionRecord& record)
{
  if (record.pathAborting || record.protocolVersion != MothershipNametagQualificationExecutionRecord::pathVersion ||
      !prodigyNametagQualificationPathRow(uint8_t(record.intent.row))) return false;
  const bool row11 = record.intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery;
  const bool row12 = record.intent.row == MothershipNametagQualificationRow::ewrOrdPathLoss;
  if (record.pathFaults.size() != (row11 ? 7 : row12 ? 3 : 6) ||
      (row12 && (record.pathSurvivorsBefore.receipts.size() != 12 || record.pathSurvivorsDuring.receipts.size() != 12))) return false;
  for (uint8_t batch = 0; batch <= (row11 ? 1 : 0); ++batch) {
    size_t faults = 0, local = 0, partition = 0, final = 0;
    String finalDigest = {}, partitionDigest = {};
    for (const auto& fault : record.pathFaults) if (fault.batch == batch) {
      ++faults; if (!fault.paused.response || !fault.restored.response) return false;
    }
    for (const auto& receipt : record.pathWorkReceipts) if (receipt.pathBatch == batch) {
      if (receipt.pathStage == ProdigyNametagQualificationPathStage::localWork) ++local;
      else if (receipt.pathStage == ProdigyNametagQualificationPathStage::partitionRead) {
        ++partition; if (partitionDigest.empty()) partitionDigest = receipt.joinedWitnessDigest;
        else if (partitionDigest != receipt.joinedWitnessDigest) return false;
      } else if (receipt.pathStage == ProdigyNametagQualificationPathStage::final) {
        ++final; if (finalDigest.empty()) finalDigest = receipt.joinedWitnessDigest;
        else if (finalDigest != receipt.joinedWitnessDigest) return false;
      }
    }
    if (faults != (row11 ? (batch == 0 ? 1 : 6) : row12 ? 3 : 6) || local != 3 ||
        partition != (row12 ? 3 : 0) || final != 3) return false;
  }
  return true;
}

static inline bool mothershipNametagQualificationPathStageMayRecord(
    const MothershipNametagQualificationExecutionRecord& record,
    uint8_t batch, ProdigyNametagQualificationPathStage stage)
{
  if (record.pathAborting || batch > (record.intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ? 1 : 0)) return false;
  size_t work = 0, reads = 0;
  for (const auto& r : record.pathWorkReceipts) if (r.pathBatch == batch) {
    if (r.pathStage == ProdigyNametagQualificationPathStage::localWork) ++work;
    if (r.pathStage == ProdigyNametagQualificationPathStage::partitionRead) ++reads;
  }
  if (stage == ProdigyNametagQualificationPathStage::localWork) return !(record.pathRestoringBatches & (uint8_t(1) << batch));
  if (stage == ProdigyNametagQualificationPathStage::partitionRead)
    return record.intent.row == MothershipNametagQualificationRow::ewrOrdPathLoss && work == 3 &&
        !(record.pathRestoringBatches & (uint8_t(1) << batch));
  if (stage == ProdigyNametagQualificationPathStage::final)
    return (record.pathRestoringBatches & (uint8_t(1) << batch)) && work == 3 &&
        (record.intent.row != MothershipNametagQualificationRow::ewrOrdPathLoss || reads == 3);
  return false;
}

// A normal restore begins only after every selected path is paused and the
// required work during the cut has been durably recorded.
static inline bool mothershipNametagQualificationPathMayBeginRestore(
    const MothershipNametagQualificationExecutionRecord& record, uint8_t batch)
{
  if (record.pathAborting || batch > (record.intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ? 1 : 0)) return false;
  size_t faults = 0, work = 0, reads = 0;
  for (const auto& fault : record.pathFaults) if (fault.batch == batch) {
    ++faults; if (!fault.paused.response || fault.restored.response) return false;
  }
  for (const auto& receipt : record.pathWorkReceipts) if (receipt.pathBatch == batch) {
    if (receipt.pathStage == ProdigyNametagQualificationPathStage::localWork) ++work;
    if (receipt.pathStage == ProdigyNametagQualificationPathStage::partitionRead) ++reads;
  }
  const bool row11 = record.intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery;
  const bool row12 = record.intent.row == MothershipNametagQualificationRow::ewrOrdPathLoss;
  if (record.protocolVersion == MothershipNametagQualificationExecutionRecord::claimVersion) {
    work = 0; for (const auto& r : record.claimReceipts)
      if (r.claimStage == ProdigyNametagQualificationClaimStage::contend) ++work;
    if (std::any_of(record.claimWinnerSites.begin(), record.claimWinnerSites.end(), [](uint128_t v) { return !v; })) return false;
  }
  return faults == (row11 ? (batch ? 6 : 1) : row12 ? 3 : 6) && work == 3 &&
      reads == (row12 ? 3 : 0) && (!row12 || record.pathSurvivorsDuring.observedAtMilliseconds);
}

// Dispatch the complete participant set before waiting for any result.  This
// is required for competing operations that must overlap during one cut.
template <typename Dispatch, typename Collect>
static inline bool mothershipNametagQualificationDispatchSites(Dispatch&& dispatch, Collect&& collect)
{
  for (uint32_t site = 0; site < 3; ++site) if (!dispatch(site)) return false;
  for (uint32_t site = 0; site < 3; ++site) if (!collect(site)) return false;
  return true;
}

// The durable journal is the ordering authority on retries: all participants
// finish a stage before the next stage can be accepted, and restoration is
// acknowledged before settlement or final readback.
static inline bool mothershipNametagQualificationClaimStageMayRecord(
    const MothershipNametagQualificationExecutionRecord& record, ProdigyNametagQualificationClaimStage stage)
{
  if (stage < ProdigyNametagQualificationClaimStage::prepare || stage > ProdigyNametagQualificationClaimStage::final || record.pathAborting) return false;
  if (stage > ProdigyNametagQualificationClaimStage::prepare) {
    const auto prior = ProdigyNametagQualificationClaimStage(uint8_t(stage) - 1);
    size_t count = 0; for (const auto& r : record.claimReceipts) if (r.claimStage == prior) ++count;
    if (count != 3) return false;
  }
  if (stage == ProdigyNametagQualificationClaimStage::contend &&
      (record.pathFaults.size() != 6 || record.pathRestoringBatches ||
       std::any_of(record.pathFaults.begin(), record.pathFaults.end(), [](const auto& f) { return !f.paused.response || f.restored.response; }))) return false;
  if (stage >= ProdigyNametagQualificationClaimStage::settle &&
      (record.pathFaults.size() != 6 || !record.pathRestoringBatches ||
       std::any_of(record.pathFaults.begin(), record.pathFaults.end(), [](const auto& f) { return !f.restored.response; }))) return false;
  return true;
}

static inline bool mothershipNametagQualificationClaimExecutionComplete(const MothershipNametagQualificationExecutionRecord& record)
{
  if (record.protocolVersion != MothershipNametagQualificationExecutionRecord::claimVersion || record.pathAborting ||
      record.pathFaults.size() != 6 || !record.pathRestoringBatches || record.claimReceipts.size() != 15 ||
      std::any_of(record.claimWinnerSites.begin(), record.claimWinnerSites.end(), [](uint128_t site) { return !site; }) ||
      std::any_of(record.pathFaults.begin(), record.pathFaults.end(), [](const auto& f) { return !f.paused.response || !f.restored.response; })) return false;
  for (uint8_t stage = 1; stage <= 5; ++stage) {
    size_t count = 0; for (const auto& r : record.claimReceipts) if (uint8_t(r.claimStage) == stage) ++count;
    if (count != 3) return false;
  }
  if (record.intent.probeTargets.size() != 3) return false;
  for (size_t claim = 0; claim < 3; ++claim) {
    size_t accepted = 0; uint128_t winner = 0;
    for (const auto& r : record.claimReceipts) if (r.claimStage == ProdigyNametagQualificationClaimStage::contend && r.claimResults[claim].accepted) {
      if (!r.claimResults[claim].observed || r.localClusterUUID == record.intent.probeTargets[1].clusterUUID) return false;
      ++accepted; winner = r.localClusterUUID;
    }
    if (accepted != 1 || winner != record.claimWinnerSites[claim]) return false;
  }
  String joined = {};
  for (const auto& r : record.claimReceipts) if (r.claimStage == ProdigyNametagQualificationClaimStage::final) {
    if (joined.empty()) joined = r.joinedWitnessDigest;
    else if (joined != r.joinedWitnessDigest) return false;
  }
  return prodigyIsSHA256HexDigest(joined);
}

static inline bool mothershipNametagQualificationReplayExecutionComplete(
    const MothershipNametagQualificationExecutionRecord& record) {
  if (record.protocolVersion != MothershipNametagQualificationExecutionRecord::replayVersion ||
      record.replayAborting || record.replayWitnesses.size() != 2 || !record.replayLocalWork.runUUID ||
      !record.replayQueriesCompletedAtMilliseconds || record.replayFinalReadbacks.size() != 3) return false;
  for (const auto& w : record.replayWitnesses)
    if (!w.sourceArm.ready || !w.sourceCapture.ready || !w.targetPrearm.ready || !w.targetArm.ready ||
        !w.targetReplay.ready || !w.sourceReplay.ready || !w.sourceQuery.ready || !w.targetQuery.ready ||
        !w.sourceRelease.ready || !w.targetRelease.ready) return false;
  for (const auto& target : record.intent.probeTargets)
    if (std::none_of(record.replayFinalReadbacks.begin(), record.replayFinalReadbacks.end(), [&](const auto& receipt) {
      return receipt.localClusterUUID == target.clusterUUID && receipt.deploymentID == target.probeDeploymentID &&
          receipt.joinedWitnessDigest == record.replayLocalWork.joinedWitnessDigest;
    })) return false;
  return record.intent.probeTargets.size() == 3;
}

static inline bool mothershipNametagQualificationSeedControlWitnessDigest(
    const MothershipNametagQualificationExecutionRecord& record, String& digest)
{
  auto intent = record.intent; auto refs = record.seedSuccessors;
  String bytes; if (!BitseryEngine::serialize(bytes, intent)) return false;
  for (auto& ref : refs) { String part; if (!BitseryEngine::serialize(part, ref)) return false; bytes.append(part); }
  return prodigyComputeSHA256Hex(bytes, digest);
}

static inline bool mothershipNametagQualificationSeedExecutionComplete(
    const MothershipNametagQualificationExecutionRecord& record, bool requireAll = true)
{
  if (record.protocolVersion != record.seedVersion || record.intent.protocolVersion != record.intent.seedVersion ||
      !prodigyNametagQualificationSeedReadbackRow(uint8_t(record.intent.row)) ||
      record.seedSuccessors.size() != record.intent.seedSuccessorOperationUUIDs.size() ||
      record.seedFinalReadbacks.size() > 3 || (requireAll && record.seedFinalReadbacks.size() != 3) || !record.seedBaselineOperationUUID ||
      !prodigyIsSHA256HexDigest(record.seedBaselineFixtureSHA256) || !prodigyIsSHA256HexDigest(record.seedBaselineReadbackSHA256)) return false;
  for (size_t i = 0; i < record.seedSuccessors.size(); ++i)
    if (record.seedSuccessors[i].operationUUID != record.intent.seedSuccessorOperationUUIDs[i] ||
        !prodigyIsSHA256HexDigest(record.seedSuccessors[i].sha256)) return false;
  String digest; if (!mothershipNametagQualificationSeedControlWitnessDigest(record, digest) || digest != record.seedControlWitnessDigest) return false;
  const uint16_t apps[] = {MeshRegistry::Hot::applicationID, MeshRegistry::Cold::applicationID,
      MeshRegistry::Radar::applicationID, MeshRegistry::Pulse::applicationID, MeshRegistry::Truth::applicationID};
  for (size_t i = 0; i < record.seedFinalReadbacks.size(); ++i) {
    for (size_t j = 0; j < 5; ++j) if (ApplicationConfig::extractApplicationID(record.seedStoreDeploymentIDs[i][j]) != apps[j]) return false;
    const auto& r = record.seedFinalReadbacks[i]; const auto& t = record.intent.probeTargets[i];
    if (!prodigyNametagQualificationApplicationReceiptValid(r) || r.protocolVersion != r.seedReadbackVersion ||
        r.runUUID != record.intent.runUUID || r.row != uint8_t(record.intent.row) || r.direction != uint8_t(record.intent.direction) ||
        r.executionGeneration != record.intent.executionGeneration || r.rowID != record.intent.rowID ||
        !prodigyNametagQualificationDescriptorEqual(r.descriptor, record.intent.descriptor) ||
        r.localClusterUUID != t.clusterUUID || r.deploymentID != t.probeDeploymentID ||
        r.witnessedResult != record.intent.descriptor.expectedWitness ||
        r.startedAtMilliseconds != record.intent.startedAtMilliseconds || r.deadlineAtMilliseconds != record.intent.deadlineAtMilliseconds ||
        r.convergenceDeadlineAtMilliseconds != record.intent.convergenceDeadlineAtMilliseconds ||
        r.seedControlWitnessDigest != digest || r.seedBaselineReadbackSHA256 != record.seedBaselineReadbackSHA256) return false;
  }
  return true;
}

static inline bool mothershipNametagQualificationExecutionRecordValid(
    const MothershipNametagQualificationExecutionRecord& record)
{
  if ((record.protocolVersion != 1 && record.protocolVersion != MothershipNametagQualificationExecutionRecord::version &&
       record.protocolVersion != MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion &&
       record.protocolVersion != MothershipNametagQualificationExecutionRecord::cousinTransportVersion &&
       record.protocolVersion != MothershipNametagQualificationExecutionRecord::restartVersion &&
       record.protocolVersion != MothershipNametagQualificationExecutionRecord::pathVersion &&
       record.protocolVersion != MothershipNametagQualificationExecutionRecord::writerIsolationVersion &&
       record.protocolVersion != MothershipNametagQualificationExecutionRecord::replayVersion &&
       record.protocolVersion != MothershipNametagQualificationExecutionRecord::claimVersion &&
       record.protocolVersion != MothershipNametagQualificationExecutionRecord::seedVersion) ||
      !mothershipNametagQualificationIntentValid(record.intent) ||
      !mothershipNametagQualificationExecutionPhaseValid(record.phase)) return false;
  if (record.protocolVersion == record.seedVersion) {
    if (record.intent.protocolVersion != record.intent.seedVersion || !record.cousinRecoveryBindings.empty() || record.cousinRecoveryAborting ||
        !record.cousinNativeWitnesses.empty() || record.restartNonce || !record.pathFaults.empty() || !record.pathWorkReceipts.empty() ||
        record.pathAborting || record.pathRestoringBatches || !record.replayWitnesses.empty() || !record.replayFinalReadbacks.empty() ||
        record.replayQueriesCompletedAtMilliseconds || record.replayAborting || !record.claimReceipts.empty() ||
        record.seedSuccessors.size() > record.intent.seedSuccessorOperationUUIDs.size() || record.seedFinalReadbacks.size() > 3) return false;
    for (size_t i = 0; i < record.seedSuccessors.size(); ++i)
      if (record.seedSuccessors[i].operationUUID != record.intent.seedSuccessorOperationUUIDs[i] ||
          !prodigyIsSHA256HexDigest(record.seedSuccessors[i].sha256)) return false;
    // Compare the serialized legacy portion with its empty value, so the v11
    // seed journal cannot carry witnesses belonging to another qualification.
    auto actual = record; MothershipNametagQualificationExecutionRecord clean = {};
    clean.protocolVersion = record.protocolVersion; clean.intent = record.intent; clean.phase = record.phase;
    clean.seedSuccessors = record.seedSuccessors; clean.seedFinalReadbacks = record.seedFinalReadbacks;
    clean.seedBaselineOperationUUID = record.seedBaselineOperationUUID;
    clean.seedBaselineFixtureSHA256 = record.seedBaselineFixtureSHA256;
    clean.seedBaselineReadbackSHA256 = record.seedBaselineReadbackSHA256;
    clean.seedControlWitnessDigest = record.seedControlWitnessDigest; clean.seedStoreDeploymentIDs = record.seedStoreDeploymentIDs;
    String a, b; if (!BitseryEngine::serialize(a, actual) || !BitseryEngine::serialize(b, clean) || a != b) return false;
    if (record.phase == MothershipNametagQualificationExecutionPhase::verified)
      return mothershipNametagQualificationSeedExecutionComplete(record);
    if (!record.seedFinalReadbacks.empty()) return mothershipNametagQualificationSeedExecutionComplete(record, false);
    return true;
  }
  const bool rowSixteen = record.intent.row == MothershipNametagQualificationRow::secondTruthWriterFencing;
  const auto& receipt = record.secondTruthWriterAdmission;
  const bool empty = receipt.sourceClusterUUID == 0 && receipt.candidateClusterUUID == 0 &&
      receipt.retainedOwnerClusterUUID == 0 && receipt.retainedPlacementGeneration == 0 &&
      receipt.candidatePlanSHA256.empty() && !receipt.fenced;
  if (!(record.protocolVersion == 1 ? empty : (rowSixteen ? (empty ||
      mothershipNametagQualificationSecondTruthWriterAdmissionMatchesIntent(record.intent, receipt)) : empty))) return false;
  if (record.protocolVersion == MothershipNametagQualificationExecutionRecord::pathVersion) {
    if (record.intent.direction != MothershipNametagQualificationDirection::injection ||
        !prodigyNametagQualificationPathRow(uint8_t(record.intent.row)) ||
        !record.cousinRecoveryBindings.empty() || record.cousinRecoveryAborting ||
        !record.cousinNativeWitnesses.empty() || record.restartNonce ||
        (record.pathRestoringBatches & ~uint8_t(record.intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ? 3 : 1)) ||
        record.pathFaults.size() > 12 || record.pathWorkReceipts.size() > 18 ||
        (record.phase == MothershipNametagQualificationExecutionPhase::verified &&
         !mothershipNametagQualificationPathExecutionComplete(record))) return false;
    for (const auto *stage : {&record.pathSurvivorsBefore, &record.pathSurvivorsDuring}) {
      if ((stage->observedAtMilliseconds == 0) != stage->receipts.empty() || stage->receipts.size() > 12 ||
          (!stage->receipts.empty() && record.intent.row != MothershipNametagQualificationRow::ewrOrdPathLoss)) return false;
    }
    for (size_t i = 0; i < record.pathFaults.size(); ++i) {
      const auto& fault = record.pathFaults[i];
      if (fault.batch > (record.intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ? 1 : 0) ||
          !prodigyCrossClusterPathFaultControlValid(fault.request) || fault.request.response ||
          fault.request.action != ProdigyCrossClusterPathFaultGatewayAction::pause ||
          fault.request.request.expiresAtMilliseconds > uint64_t(record.intent.convergenceDeadlineAtMilliseconds)) return false;
      for (size_t j = 0; j < i; ++j) {
        const auto& previous = record.pathFaults[j];
        if (previous.request.request.operationUUID == fault.request.request.operationUUID ||
            (previous.batch == fault.batch &&
             prodigyCrossClusterPathFaultScopeEqual(previous.request.request.scope, fault.request.request.scope))) return false;
      }
      auto matches = [&](const auto& observation, ProdigyCrossClusterPathFaultGatewayAction action) {
        return !observation.response || (prodigyCrossClusterPathFaultControlValid(observation) && observation.accepted &&
            observation.action == action &&
            prodigyCrossClusterPathFaultRequestEqual(observation.request, fault.request.request) &&
            (action == ProdigyCrossClusterPathFaultGatewayAction::pause ?
                (!observation.sessionReady && !observation.bgpReady) :
                (observation.sessionReady && observation.bgpReady)));
      };
      if (!matches(fault.paused, ProdigyCrossClusterPathFaultGatewayAction::pause) ||
          !matches(fault.restored, ProdigyCrossClusterPathFaultGatewayAction::resume) ||
          (fault.restored.response && !record.pathAborting &&
           (!fault.paused.response || !(record.pathRestoringBatches & (uint8_t(1) << fault.batch))))) return false;
    }
    for (size_t i = 0; i < record.pathWorkReceipts.size(); ++i) {
      const auto& work = record.pathWorkReceipts[i];
      for (size_t j = 0; j < i; ++j) {
        const auto& previous = record.pathWorkReceipts[j];
        if (previous.pathBatch == work.pathBatch && previous.pathStage == work.pathStage &&
            previous.localClusterUUID == work.localClusterUUID) return false;
      }
      if (!prodigyNametagQualificationApplicationReceiptValid(work) ||
          work.protocolVersion != ProdigyNametagQualificationApplicationReceipt::pathStageVersion ||
          work.runUUID != record.intent.runUUID || work.row != uint8_t(record.intent.row) ||
          work.direction != uint8_t(record.intent.direction) || work.executionGeneration != record.intent.executionGeneration ||
          work.rowID != record.intent.rowID || !prodigyNametagQualificationDescriptorEqual(work.descriptor, record.intent.descriptor) ||
          work.startedAtMilliseconds != record.intent.startedAtMilliseconds ||
          work.deadlineAtMilliseconds != record.intent.deadlineAtMilliseconds ||
          work.convergenceDeadlineAtMilliseconds != record.intent.convergenceDeadlineAtMilliseconds ||
          std::none_of(record.intent.probeTargets.begin(), record.intent.probeTargets.end(), [&](const auto& target) {
            return target.clusterUUID == work.localClusterUUID && target.probeDeploymentID == work.deploymentID;
          }) || std::none_of(record.pathFaults.begin(), record.pathFaults.end(), [&](const auto& fault) {
            return fault.batch == work.pathBatch &&
                fault.request.request.expiresAtMilliseconds == uint64_t(work.pathFaultExpiresAtMilliseconds);
          })) return false;
    }
    return true;
  }
  if (record.protocolVersion == MothershipNametagQualificationExecutionRecord::claimVersion) {
    if (record.intent.row != MothershipNametagQualificationRow::truthClaimPartition ||
        record.intent.direction != MothershipNametagQualificationDirection::injection ||
        record.pathFaults.size() > 6 || record.claimReceipts.size() > 15 ||
        !record.cousinRecoveryBindings.empty() || record.cousinRecoveryAborting ||
        !record.cousinNativeWitnesses.empty() || record.restartNonce ||
        record.writerIsolation.challenge.runUUID || record.writerIsolation.localArm.runUUID ||
        record.writerIsolation.localWork.runUUID || record.writerIsolation.aborting ||
        !record.replayWitnesses.empty() || record.replayLocalWork.runUUID ||
        !record.replayFinalReadbacks.empty() || record.replayQueriesCompletedAtMilliseconds ||
        record.pathRestoringBatches > 1 ||
        (record.phase == MothershipNametagQualificationExecutionPhase::verified && !mothershipNametagQualificationClaimExecutionComplete(record)) ||
        !record.pathWorkReceipts.empty() ||
        !record.pathSurvivorsBefore.receipts.empty() || !record.pathSurvivorsDuring.receipts.empty()) return false;
    for (size_t i = 0; i < record.pathFaults.size(); ++i) {
      const auto& fault = record.pathFaults[i];
      if (fault.batch || !prodigyCrossClusterPathFaultControlValid(fault.request) || fault.request.response ||
          fault.request.action != ProdigyCrossClusterPathFaultGatewayAction::pause ||
          fault.request.request.expiresAtMilliseconds > uint64_t(record.intent.convergenceDeadlineAtMilliseconds)) return false;
      for (size_t j = 0; j < i; ++j)
        if (record.pathFaults[j].request.request.operationUUID == fault.request.request.operationUUID ||
            prodigyCrossClusterPathFaultScopeEqual(record.pathFaults[j].request.request.scope, fault.request.request.scope)) return false;
      auto matches = [&](const auto& result, ProdigyCrossClusterPathFaultGatewayAction action) {
        return !result.response || (prodigyCrossClusterPathFaultControlValid(result) && result.accepted &&
            result.action == action && prodigyCrossClusterPathFaultRequestEqual(result.request, fault.request.request) &&
            (action == ProdigyCrossClusterPathFaultGatewayAction::pause ?
                (!result.sessionReady && !result.bgpReady) : (result.sessionReady && result.bgpReady)));
      };
      if (!matches(fault.paused, ProdigyCrossClusterPathFaultGatewayAction::pause) ||
          !matches(fault.restored, ProdigyCrossClusterPathFaultGatewayAction::resume) ||
          (fault.restored.response && !record.pathAborting && (!fault.paused.response || !record.pathRestoringBatches))) return false;
    }
    for (size_t i = 0; i < record.claimReceipts.size(); ++i) {
      const auto& receipt = record.claimReceipts[i];
      if (!prodigyNametagQualificationApplicationReceiptValid(receipt) ||
          receipt.protocolVersion != ProdigyNametagQualificationApplicationReceipt::claimStageVersion ||
          receipt.runUUID != record.intent.runUUID || receipt.executionGeneration != record.intent.executionGeneration ||
          receipt.row != uint8_t(record.intent.row) || receipt.direction != uint8_t(record.intent.direction) ||
          receipt.rowID != record.intent.rowID || receipt.startedAtMilliseconds != record.intent.startedAtMilliseconds ||
          receipt.deadlineAtMilliseconds != record.intent.deadlineAtMilliseconds ||
          receipt.convergenceDeadlineAtMilliseconds != record.intent.convergenceDeadlineAtMilliseconds ||
          !prodigyNametagQualificationDescriptorEqual(receipt.descriptor, record.intent.descriptor) ||
          std::none_of(record.intent.probeTargets.begin(), record.intent.probeTargets.end(), [&](const auto& t) {
            return t.clusterUUID == receipt.localClusterUUID && t.probeDeploymentID == receipt.deploymentID;
          })) return false;
      for (size_t j = 0; j < i; ++j)
        if (record.claimReceipts[j].claimStage == receipt.claimStage &&
            record.claimReceipts[j].localClusterUUID == receipt.localClusterUUID) return false;
      if (receipt.claimStage >= ProdigyNametagQualificationClaimStage::contend &&
          std::none_of(record.pathFaults.begin(), record.pathFaults.end(), [&](const auto& f) {
            return f.request.request.expiresAtMilliseconds == uint64_t(receipt.claimFaultExpiresAtMilliseconds);
          })) return false;
      if (receipt.claimStage >= ProdigyNametagQualificationClaimStage::settle &&
          receipt.claimWinnerSites != record.claimWinnerSites) return false;
    }
    return true;
  }
  if (record.protocolVersion == MothershipNametagQualificationExecutionRecord::replayVersion) {
    if (record.intent.row != MothershipNametagQualificationRow::graphKvReplayReorder ||
        record.intent.direction != MothershipNametagQualificationDirection::injection ||
        !record.cousinRecoveryBindings.empty() || record.cousinRecoveryAborting || !record.cousinNativeWitnesses.empty() ||
        record.replayWitnesses.size() > 2 || record.replayFinalReadbacks.size() > 3) return false;
    const auto& local = record.replayLocalWork;
    if (local.runUUID && (!prodigyNametagQualificationApplicationReceiptValid(local) ||
        local.protocolVersion != ProdigyNametagQualificationApplicationReceipt::replayStageVersion ||
        local.replayStage != ProdigyNametagQualificationReplayWorkStage::workload ||
        local.runUUID != record.intent.runUUID || local.executionGeneration != record.intent.executionGeneration ||
        local.row != uint8_t(record.intent.row) || local.direction != uint8_t(record.intent.direction) ||
        local.rowID != record.intent.rowID || local.localClusterUUID != record.intent.probeTargets[0].clusterUUID ||
        local.deploymentID != record.intent.probeTargets[0].probeDeploymentID ||
        local.startedAtMilliseconds != record.intent.startedAtMilliseconds || local.deadlineAtMilliseconds != record.intent.deadlineAtMilliseconds ||
        local.convergenceDeadlineAtMilliseconds != record.intent.convergenceDeadlineAtMilliseconds ||
        !prodigyNametagQualificationDescriptorEqual(local.descriptor, record.intent.descriptor))) return false;
    if (record.replayQueriesCompletedAtMilliseconds &&
        (record.replayWitnesses.size() != 2 ||
         std::any_of(record.replayWitnesses.begin(), record.replayWitnesses.end(), [](const auto& w) {
           return !w.sourceQuery.ready || !w.targetQuery.ready;
         }) || record.replayQueriesCompletedAtMilliseconds < record.intent.startedAtMilliseconds ||
         record.replayQueriesCompletedAtMilliseconds > record.intent.convergenceDeadlineAtMilliseconds)) return false;
    for (size_t i = 0; i < record.replayFinalReadbacks.size(); ++i) {
      const auto& final = record.replayFinalReadbacks[i];
      if (!local.runUUID || !prodigyNametagQualificationApplicationReceiptValid(final) ||
          final.protocolVersion != ProdigyNametagQualificationApplicationReceipt::replayStageVersion ||
          final.replayStage != ProdigyNametagQualificationReplayWorkStage::final ||
          final.runUUID != local.runUUID || final.executionGeneration != local.executionGeneration ||
          final.row != local.row || final.direction != local.direction || final.rowID != local.rowID ||
          final.startedAtMilliseconds != local.startedAtMilliseconds || final.deadlineAtMilliseconds != local.deadlineAtMilliseconds ||
          final.convergenceDeadlineAtMilliseconds != local.convergenceDeadlineAtMilliseconds ||
          !record.replayQueriesCompletedAtMilliseconds || final.observedAtMilliseconds <= local.observedAtMilliseconds ||
          final.observedAtMilliseconds < record.replayQueriesCompletedAtMilliseconds ||
          final.joinedWitnessDigest != local.joinedWitnessDigest ||
          !prodigyNametagQualificationDescriptorEqual(final.descriptor, local.descriptor) ||
          std::none_of(record.intent.probeTargets.begin(), record.intent.probeTargets.end(), [&](const auto& target) {
            return target.clusterUUID == final.localClusterUUID && target.probeDeploymentID == final.deploymentID;
          })) return false;
      for (size_t j = 0; j < i; ++j)
        if (record.replayFinalReadbacks[j].localClusterUUID == final.localClusterUUID) return false;
    }
    for (const auto& w : record.replayWitnesses) {
      if (!prodigyNametagQualificationReplayValid(w.sourceChallenge) || w.sourceChallenge.response || w.sourceChallenge.targetSide ||
          w.sourceChallenge.stage != ProdigyNametagQualificationReplayStage::arm ||
          w.sourceChallenge.runUUID != record.intent.runUUID || w.sourceChallenge.executionGeneration != record.intent.executionGeneration) return false;
      if (w.sourceArm.response && !prodigyNametagQualificationReplayResponseMatches(w.sourceChallenge, w.sourceArm)) return false;
      if (w.sourceCapture.response) {
        if (!w.sourceArm.ready) return false;
        auto captureRequest = w.sourceChallenge; captureRequest.stage = ProdigyNametagQualificationReplayStage::query;
        if (!prodigyNametagQualificationReplayResponseMatches(captureRequest, w.sourceCapture)) return false;
      }
      if (w.targetPrearmChallenge.challengeUUID) {
        auto expected = w.sourceChallenge; expected.targetSide = true;
        expected.stage = ProdigyNametagQualificationReplayStage::prearm;
        String left, right;
        if (!BitseryEngine::serialize(left, expected) || !BitseryEngine::serialize(right, w.targetPrearmChallenge) || left != right) return false;
      }
      if (w.targetPrearm.response && !prodigyNametagQualificationReplayResponseMatches(w.targetPrearmChallenge, w.targetPrearm)) return false;
      if (w.targetChallenge.challengeUUID && (!prodigyNametagQualificationReplayValid(w.targetChallenge) ||
          !w.targetChallenge.targetSide || w.targetChallenge.response || w.targetChallenge.challengeUUID != w.sourceChallenge.challengeUUID ||
          !w.targetPrearm.ready || !w.sourceCapture.ready || w.targetChallenge.originUUID != w.sourceCapture.originUUID ||
          w.targetChallenge.committedID != w.sourceCapture.committedID || w.targetChallenge.olderCommittedID != w.sourceCapture.olderCommittedID ||
          w.targetChallenge.delayedID != w.sourceCapture.delayedID || w.targetChallenge.catchupID != w.sourceCapture.catchupID)) return false;
      if (w.targetChallenge.challengeUUID) {
        auto expected = w.sourceChallenge; expected.targetSide = true; expected.originUUID = w.sourceCapture.originUUID;
        expected.committedID = w.sourceCapture.committedID; expected.olderCommittedID = w.sourceCapture.olderCommittedID;
        expected.delayedID = w.sourceCapture.delayedID; expected.catchupID = w.sourceCapture.catchupID;
        String left, right;
        if (!BitseryEngine::serialize(left, expected) || !BitseryEngine::serialize(right, w.targetChallenge) || left != right) return false;
      }
      if (w.targetArm.response && !prodigyNametagQualificationReplayResponseMatches(w.targetChallenge, w.targetArm)) return false;
      auto matchesStage = [](const auto& challenge, const auto& response, ProdigyNametagQualificationReplayStage stage) {
        if (!response.response) return true;
        auto request = challenge; request.stage = stage;
        return prodigyNametagQualificationReplayResponseMatches(request, response);
      };
      if (!matchesStage(w.sourceChallenge, w.sourceReplay, ProdigyNametagQualificationReplayStage::replay) ||
          !matchesStage(w.sourceChallenge, w.sourceQuery, ProdigyNametagQualificationReplayStage::query) ||
          !matchesStage(w.sourceChallenge, w.sourceRelease, ProdigyNametagQualificationReplayStage::release) ||
          !matchesStage(w.targetChallenge, w.targetReplay, ProdigyNametagQualificationReplayStage::replay) ||
          !matchesStage(w.targetChallenge, w.targetQuery, ProdigyNametagQualificationReplayStage::query) ||
          !(matchesStage(w.targetChallenge, w.targetRelease, ProdigyNametagQualificationReplayStage::release) ||
            matchesStage(w.targetPrearmChallenge, w.targetRelease, ProdigyNametagQualificationReplayStage::release))) return false;
      if (w.sourceQuery.ready && (!w.sourceCapture.ready || w.sourceQuery.originUUID != w.sourceCapture.originUUID ||
          w.sourceQuery.committedID != w.sourceCapture.committedID || w.sourceQuery.olderCommittedID != w.sourceCapture.olderCommittedID ||
          w.sourceQuery.delayedID != w.sourceCapture.delayedID || w.sourceQuery.catchupID != w.sourceCapture.catchupID)) return false;
    }
    if (record.phase == MothershipNametagQualificationExecutionPhase::verified) {
      return mothershipNametagQualificationReplayExecutionComplete(record);
    }
    return true;
  }
  if (record.protocolVersion == MothershipNametagQualificationExecutionRecord::writerIsolationVersion) {
    const auto& w = record.writerIsolation;
    if (record.intent.row != MothershipNametagQualificationRow::localWriterIsolation ||
        record.intent.direction != MothershipNametagQualificationDirection::injection ||
        !record.cousinRecoveryBindings.empty() || record.cousinRecoveryAborting ||
        !record.cousinNativeWitnesses.empty() || record.restartNonce) return false;
    if (!w.challenge.challengeUUID)
      return record.phase == MothershipNametagQualificationExecutionPhase::prepared &&
          !w.arm.response && !w.isolated.response && !w.queried.response && !w.released.response &&
          !w.localArm.runUUID && !w.localWork.runUUID;
    if (!prodigyNametagQualificationWriterIsolationValid(w.challenge) || w.challenge.response ||
        w.challenge.stage != ProdigyNametagQualificationWriterIsolationStage::arm ||
        w.challenge.runUUID != record.intent.runUUID || w.challenge.executionGeneration != record.intent.executionGeneration ||
        w.challenge.deadlineAtMilliseconds != record.intent.deadlineAtMilliseconds ||
        w.challenge.clusterUUID != record.intent.probeTargets[0].clusterUUID) return false;
    auto localValid = [&](const auto& r, ProdigyNametagQualificationWriterStage stage) {
      return !r.runUUID || (prodigyNametagQualificationApplicationReceiptValid(r) &&
          r.protocolVersion == ProdigyNametagQualificationApplicationReceipt::writerStageVersion &&
          r.writerStage == stage && r.writerChallengeUUID == w.challenge.challengeUUID &&
          r.runUUID == record.intent.runUUID && r.executionGeneration == record.intent.executionGeneration &&
          r.row == uint8_t(record.intent.row) && r.direction == uint8_t(record.intent.direction) &&
          r.rowID == record.intent.rowID && r.localClusterUUID == w.challenge.clusterUUID &&
          r.deploymentID == record.intent.probeTargets[0].probeDeploymentID &&
          r.startedAtMilliseconds == record.intent.startedAtMilliseconds &&
          r.deadlineAtMilliseconds == record.intent.deadlineAtMilliseconds &&
          r.convergenceDeadlineAtMilliseconds == record.intent.convergenceDeadlineAtMilliseconds &&
          prodigyNametagQualificationDescriptorEqual(r.descriptor, record.intent.descriptor));
    };
    if (!localValid(w.localArm, ProdigyNametagQualificationWriterStage::arm) ||
        !localValid(w.localWork, ProdigyNametagQualificationWriterStage::survivorWrites) ||
        (w.localArm.runUUID && !w.arm.ready) || (w.localWork.runUUID && !w.isolated.ready)) return false;
    auto expected = w.challenge;
    if (w.arm.response && (!w.arm.ready || !prodigyNametagQualificationWriterIsolationResponseMatches(expected, w.arm))) return false;
    expected.stage = ProdigyNametagQualificationWriterIsolationStage::isolate;
    if (w.isolated.response && (!w.arm.ready || !w.isolated.ready || !w.isolated.isolated ||
        !prodigyNametagQualificationWriterIsolationResponseMatches(expected, w.isolated))) return false;
    expected.stage = ProdigyNametagQualificationWriterIsolationStage::query;
    if (w.queried.response && (!w.isolated.ready || !w.queried.ready ||
        !prodigyNametagQualificationWriterIsolationResponseMatches(expected, w.queried))) return false;
    expected.stage = ProdigyNametagQualificationWriterIsolationStage::release;
    if (w.released.response && (!w.arm.ready || !w.released.ready ||
        !prodigyNametagQualificationWriterIsolationResponseMatches(expected, w.released))) return false;
    if (w.aborting) return record.phase != MothershipNametagQualificationExecutionPhase::verified &&
        (record.phase != MothershipNametagQualificationExecutionPhase::failed || !w.arm.ready || w.released.ready);
    if (record.phase == MothershipNametagQualificationExecutionPhase::prepared) return true;
    if (!w.arm.ready || !w.localArm.runUUID || !w.isolated.ready || !w.isolated.isolated) return false;
    if (record.phase == MothershipNametagQualificationExecutionPhase::faultApplied) return true;
    if (!w.localWork.runUUID || !w.queried.ready || !w.queried.isolated) return false;
    if (record.phase == MothershipNametagQualificationExecutionPhase::workloadIssued) return true;
    return w.released.ready;
  }
  if (record.protocolVersion == MothershipNametagQualificationExecutionRecord::restartVersion) {
    const auto validProcess = [](const auto& p) { return p.pid && p.startTime && !p.bootID.empty() &&
        p.bootID.size() <= 64 && prodigyIsSHA256HexDigest(p.executableSHA256); };
    const auto emptyProcess = [](const auto& p) { return !p.pid && !p.startTime && p.bootID.empty() && p.executableSHA256.empty(); };
    const auto& before = record.restartBefore; const auto& after = record.restartAfter; const auto& local = record.restartLocalWorkReceipt;
    if (record.intent.row != MothershipNametagQualificationRow::mothershipRestartResume ||
        record.intent.direction != MothershipNametagQualificationDirection::injection || !record.restartNonce ||
        !validProcess(before) || !record.cousinRecoveryBindings.empty() || record.cousinRecoveryAborting ||
        !record.cousinNativeWitnesses.empty() || !prodigyNametagQualificationApplicationReceiptValid(local) ||
        local.protocolVersion != ProdigyNametagQualificationApplicationReceipt::restartStageVersion ||
        local.restartStage != ProdigyNametagQualificationRestartStage::beforeRestart ||
        local.runUUID != record.intent.runUUID || local.executionGeneration != record.intent.executionGeneration ||
        local.row != uint8_t(record.intent.row) || local.direction != uint8_t(record.intent.direction) ||
        local.rowID != record.intent.rowID || local.localClusterUUID != record.intent.probeTargets[0].clusterUUID ||
        local.deploymentID != record.intent.probeTargets[0].probeDeploymentID ||
        local.startedAtMilliseconds != record.intent.startedAtMilliseconds ||
        local.deadlineAtMilliseconds != record.intent.deadlineAtMilliseconds ||
        local.convergenceDeadlineAtMilliseconds != record.intent.convergenceDeadlineAtMilliseconds ||
        !prodigyNametagQualificationDescriptorEqual(local.descriptor, record.intent.descriptor)) return false;
    if (emptyProcess(after)) return record.phase == MothershipNametagQualificationExecutionPhase::prepared;
    return validProcess(after) && after.bootID == before.bootID && after.executableSHA256 == before.executableSHA256 &&
        (after.pid != before.pid || after.startTime != before.startTime);
  }
  if (record.protocolVersion < MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion)
    return record.cousinRecoveryBindings.empty() && !record.cousinRecoveryAborting && record.cousinNativeWitnesses.empty() &&
        (record.intent.protocolVersion != MothershipNametagQualificationIntent::cousinRecoveryVersion ||
         record.phase == MothershipNametagQualificationExecutionPhase::prepared);
  if (record.intent.protocolVersion != MothershipNametagQualificationIntent::cousinRecoveryVersion ||
      record.cousinRecoveryBindings.size() != record.intent.cousinRecoveries.size()) return false;
  for (uint32_t i = 0; i < record.cousinRecoveryBindings.size(); ++i)
    if (!mothershipNametagQualificationCousinRecoveryBindingValid(record.intent, i, record.cousinRecoveryBindings[i])) return false;
  if (record.protocolVersion == MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion)
    return record.cousinNativeWitnesses.empty();
  if (record.protocolVersion == MothershipNametagQualificationExecutionRecord::cousinTransportVersion) {
    if (record.cousinNativeWitnesses.size() > record.cousinRecoveryBindings.size()) return false;
    const auto& local = record.cousinLocalWorkReceipt;
    if (local.runUUID && (!prodigyNametagQualificationApplicationReceiptValid(local) ||
        local.protocolVersion != ProdigyNametagQualificationApplicationReceipt::cousinStageVersion ||
        local.cousinStage != ProdigyNametagQualificationCousinStage::faultObserved ||
        local.runUUID != record.intent.runUUID || local.executionGeneration != record.intent.executionGeneration ||
        local.row != uint8_t(record.intent.row) || local.direction != uint8_t(record.intent.direction) ||
        local.rowID != record.intent.rowID || local.localClusterUUID != record.intent.probeTargets[0].clusterUUID ||
        local.deploymentID != record.intent.probeTargets[0].probeDeploymentID ||
        local.startedAtMilliseconds != record.intent.startedAtMilliseconds ||
        local.deadlineAtMilliseconds != record.intent.deadlineAtMilliseconds ||
        local.convergenceDeadlineAtMilliseconds != record.intent.convergenceDeadlineAtMilliseconds ||
        !prodigyNametagQualificationDescriptorEqual(local.descriptor, record.intent.descriptor))) return false;
    if (!record.cousinRecoveryAborting && record.phase != MothershipNametagQualificationExecutionPhase::prepared &&
        (record.cousinNativeWitnesses.size() != record.cousinRecoveryBindings.size() ||
         !std::all_of(record.cousinNativeWitnesses.begin(), record.cousinNativeWitnesses.end(), [&](const auto& w) {
           if (!w.arm.ready) return false;
           if (record.phase == MothershipNametagQualificationExecutionPhase::faultApplied) return true;
           if (!w.fault.ready || !local.runUUID) return false;
           if (record.phase == MothershipNametagQualificationExecutionPhase::workloadIssued ||
               record.phase == MothershipNametagQualificationExecutionPhase::faultRestored) return true;
           return w.final.ready;
         }))) return false;
    for (size_t i = 0; i < record.cousinNativeWitnesses.size(); ++i) {
      const auto& w = record.cousinNativeWitnesses[i]; const auto& b = record.cousinRecoveryBindings[i];
      const auto& ref = record.intent.cousinRecoveries[i]; const auto& s = w.challenge.session;
      if (!prodigyNametagQualificationCousinTransportValid(w.challenge) || w.challenge.response ||
          w.challenge.stage != ProdigyNametagQualificationCousinStage::arm ||
          w.challenge.runUUID != record.intent.runUUID || w.challenge.executionGeneration != record.intent.executionGeneration ||
          w.challenge.deadlineAtMilliseconds != record.intent.deadlineAtMilliseconds ||
          s.pairUUID != b.route.pairUUID || s.routeUUID != b.route.routeUUID || s.routeGeneration != b.route.generation ||
          s.sourcePermissionUUID != b.sourcePermission.permissionUUID || s.destinationPermissionUUID != b.destinationPermission.permissionUUID ||
          s.sourcePermissionAuthorityGeneration != b.sourcePermission.acceptedAuthorityGeneration ||
          s.sourceClusterUUID != b.route.sourceClusterUUID || s.destinationClusterUUID != b.route.destinationClusterUUID ||
          s.sourceDeploymentID != b.sourcePermission.localDeploymentID || s.destinationDeploymentID != b.destinationPermission.localDeploymentID ||
          s.successorRouteUUID != ref.successorRouteUUID || s.successorRouteGeneration != 1 ||
          s.successorSourcePermissionUUID != (ref.successorPermissionUUID ? ref.successorPermissionUUID : b.sourcePermission.permissionUUID)) return false;
      auto expected = w.challenge;
      if (w.arm.response && (!w.arm.ready || !prodigyNametagQualificationCousinTransportResponseMatches(expected, w.arm))) return false;
      expected.stage = ProdigyNametagQualificationCousinStage::faultObserved;
      if (w.fault.response && (!w.arm.ready || !w.fault.ready || !prodigyNametagQualificationCousinTransportResponseMatches(expected, w.fault))) return false;
      expected.stage = ProdigyNametagQualificationCousinStage::final;
      expected.session.successorPermissionAuthorityGeneration = w.final.session.successorPermissionAuthorityGeneration;
      if (w.final.response && (!w.fault.ready || !w.final.ready || !prodigyNametagQualificationCousinTransportResponseMatches(expected, w.final) ||
          (ref.successorPermissionUUID ? expected.session.successorPermissionAuthorityGeneration <= b.sourcePermission.acceptedAuthorityGeneration :
           expected.session.successorPermissionAuthorityGeneration != b.sourcePermission.acceptedAuthorityGeneration))) return false;
    }
    return true;
  }
  return false;
}

// Resolve only the successor committed by this run's verified permission fault.
static inline bool mothershipNametagQualificationPermissionSuccessor(
    const MothershipNametagQualificationExecutionRecord& execution, uint128_t original, uint128_t& successor)
{
  successor = 0;
  if (!original || execution.intent.row != MothershipNametagQualificationRow::permissionRevokeReinstall ||
      execution.intent.direction != MothershipNametagQualificationDirection::injection ||
      execution.protocolVersion != MothershipNametagQualificationExecutionRecord::cousinTransportVersion ||
      execution.phase != MothershipNametagQualificationExecutionPhase::verified || execution.cousinRecoveryAborting ||
      !mothershipNametagQualificationExecutionRecordValid(execution)) return false;
  for (const auto& item : execution.intent.cousinRecoveries) {
    if (item.routeUUID != original) continue;
    if (successor || !item.successorRouteUUID) return false;
    successor = item.successorRouteUUID;
  }
  return successor != 0;
}

enum class MothershipNametagQualificationSiteAction : uint8_t { execute = 1, query = 2 };

// A source baseline is a prerequisite to, not a member of, the frozen 17-row
// qualification matrix.  It deliberately reuses the authenticated site RPC
// shape but contains no qualification descriptor or fault authority.
class MothershipNametagSourceBaselineExchange {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyNametagSourceBaselineCommand command;
  ProdigyNametagSourceBaselineReceipt receipt;
  bool success = false;
  bool completed = false;
  String failure;
};
template <typename S>
static void serialize(S&& serializer, MothershipNametagSourceBaselineExchange& value)
{ serializer.value4b(value.protocolVersion); serializer.object(value.command); serializer.object(value.receipt);
  serializer.value1b(value.success); serializer.value1b(value.completed); serializer.text1b(value.failure, 1024); }
static inline bool mothershipNametagSourceBaselineExchangeRequestValid(
    const MothershipNametagSourceBaselineExchange& value)
{ return value.protocolVersion == MothershipNametagSourceBaselineExchange::version &&
      prodigyNametagSourceBaselineCommandValid(value.command) &&
      prodigyNametagSourceBaselineReceiptEmpty(value.receipt) && !value.success && !value.completed && value.failure.empty(); }
static inline bool mothershipNametagSourceBaselineExchangeResponseValid(
    const MothershipNametagSourceBaselineExchange& request, const MothershipNametagSourceBaselineExchange& response)
{
  if (response.protocolVersion != MothershipNametagSourceBaselineExchange::version || !response.success ||
      !prodigyNametagSourceBaselineCommandSameOperation(request.command, response.command)) return false;
  if (request.command.action == ProdigyNametagSourceBaselineAction::execute)
    return !response.completed && prodigyNametagSourceBaselineReceiptEmpty(response.receipt);
  const auto& receipt = response.receipt;
  return response.completed && prodigyNametagSourceBaselineReceiptValid(receipt) &&
      receipt.operationUUID == request.command.operationUUID && receipt.ewrClusterUUID == request.command.ewrClusterUUID &&
      receipt.probeDeploymentID == request.command.probeDeploymentID &&
      receipt.fixtureManifestSHA256 == request.command.fixtureManifestSHA256 &&
      receipt.deadlineAtMilliseconds == request.command.deadlineAtMilliseconds;
}

class MothershipNametagSourceBaselineRecord {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyNametagSourceBaselineCommand command;
  ProdigyNametagSourceBaselineReceipt receipt;
};
class MothershipNametagSourceBaselineIntent {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  // The registered EWR name is an immutable caller input, while the UUID in
  // command is the resolved identity used on the wire.
  String ewrClusterName;
  uint32_t deadlineSeconds = 0;
  ProdigyNametagSourceBaselineCommand command;
};
template <typename S>
static void serialize(S&& serializer, MothershipNametagSourceBaselineIntent& value)
{ serializer.value4b(value.protocolVersion); serializer.text1b(value.ewrClusterName, 256); serializer.value4b(value.deadlineSeconds); serializer.object(value.command); }
static inline bool mothershipNametagSourceBaselineIntentValid(const MothershipNametagSourceBaselineIntent& value)
{ return value.protocolVersion == MothershipNametagSourceBaselineIntent::version && !value.ewrClusterName.empty() && value.deadlineSeconds != 0 && value.deadlineSeconds <= 3600 &&
      prodigyNametagSourceBaselineCommandValid(value.command) && value.command.action == ProdigyNametagSourceBaselineAction::execute; }
template <typename S>
static void serialize(S&& serializer, MothershipNametagSourceBaselineRecord& value)
{ serializer.value4b(value.protocolVersion); serializer.object(value.command); serializer.object(value.receipt); }
static inline bool mothershipNametagSourceBaselineRecordValid(const MothershipNametagSourceBaselineRecord& value)
{ return value.protocolVersion == MothershipNametagSourceBaselineRecord::version &&
      prodigyNametagSourceBaselineCommandValid(value.command) && prodigyNametagSourceBaselineReceiptValid(value.receipt) &&
      value.command.action == ProdigyNametagSourceBaselineAction::execute &&
      value.receipt.operationUUID == value.command.operationUUID && value.receipt.ewrClusterUUID == value.command.ewrClusterUUID &&
      value.receipt.probeDeploymentID == value.command.probeDeploymentID &&
      value.receipt.fixtureManifestSHA256 == value.command.fixtureManifestSHA256 &&
      value.receipt.deadlineAtMilliseconds == value.command.deadlineAtMilliseconds; }

class MothershipNametagQualificationSiteRequest {
public:
  static constexpr uint32_t version = 2;
  static constexpr uint32_t cousinStageVersion = 3;
  static constexpr uint32_t restartStageVersion = 5;
  static constexpr uint32_t writerStageVersion = 6;
  static constexpr uint32_t pathStageVersion = 7;
  static constexpr uint32_t replayStageVersion = 9;
  static constexpr uint32_t claimStageVersion = 12;
  static constexpr uint32_t seedReadbackVersion = 13;
  uint32_t protocolVersion = version;
  MothershipNametagQualificationIntent intent;
  uint128_t targetClusterUUID = 0;
  uint64_t targetApp6DeploymentID = 0;
  uint64_t targetProbeDeploymentID = 0;
  MothershipNametagQualificationSiteAction action = MothershipNametagQualificationSiteAction::execute;
  ProdigyNametagQualificationCousinStage cousinStage = ProdigyNametagQualificationCousinStage::none;
  Vector<ProdigyNametagQualificationCousinSession> cousinSessions;
  ProdigyNametagQualificationRestartStage restartStage = ProdigyNametagQualificationRestartStage::none;
  ProdigyNametagQualificationWriterStage writerStage = ProdigyNametagQualificationWriterStage::none;
  ProdigyNametagQualificationWriterIsolation writerIsolation = {};
  ProdigyNametagQualificationPathStage pathStage = ProdigyNametagQualificationPathStage::none;
  uint8_t pathBatch = 0;
  int64_t pathFaultExpiresAtMilliseconds = 0;
  ProdigyNametagQualificationReplayWorkStage replayStage = ProdigyNametagQualificationReplayWorkStage::none;
  Vector<ProdigyNametagQualificationReplay> replaySources;
  ProdigyNametagQualificationClaimStage claimStage = ProdigyNametagQualificationClaimStage::none;
  int64_t claimFaultExpiresAtMilliseconds = 0;
  std::array<uint128_t, 3> claimWinnerSites = {};
  uint128_t seedBaselineOperationUUID = 0;
  std::array<uint64_t, 5> seedStoreDeploymentIDs = {};
  String seedControlWitnessDigest, seedBaselineFixtureSHA256, seedBaselineReadbackSHA256;
};
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationSiteRequest& request)
{ serializer.value4b(request.protocolVersion); serializer.object(request.intent); serializer.value16b(request.targetClusterUUID);
  serializer.value8b(request.targetApp6DeploymentID); serializer.value8b(request.targetProbeDeploymentID);
  if (request.protocolVersion >= 2) serializer.value1b(request.action);
  if (request.protocolVersion >= 3) { serializer.value1b(request.cousinStage); serializer.container(request.cousinSessions, 2); }
  if (request.protocolVersion >= 5) serializer.value1b(request.restartStage);
  if (request.protocolVersion >= 6) { serializer.value1b(request.writerStage); serializer.object(request.writerIsolation); }
  if (request.protocolVersion >= 7) { serializer.value1b(request.pathStage); serializer.value1b(request.pathBatch); serializer.value8b(request.pathFaultExpiresAtMilliseconds); }
  if (request.protocolVersion >= 9) { serializer.value1b(request.replayStage); serializer.container(request.replaySources, 2); }
  if (request.protocolVersion >= 12) { serializer.value1b(request.claimStage); serializer.value8b(request.claimFaultExpiresAtMilliseconds);
    for (auto& site : request.claimWinnerSites) serializer.value16b(site); }
  if (request.protocolVersion >= 13) { serializer.value16b(request.seedBaselineOperationUUID);
    for (auto& deployment : request.seedStoreDeploymentIDs) serializer.value8b(deployment);
    serializer.text1b(request.seedControlWitnessDigest, 64); serializer.text1b(request.seedBaselineFixtureSHA256, 64);
    serializer.text1b(request.seedBaselineReadbackSHA256, 64); }
}
static inline bool mothershipNametagQualificationSiteRequestValid(const MothershipNametagQualificationSiteRequest& request)
{
  if ((request.protocolVersion != MothershipNametagQualificationSiteRequest::version &&
       request.protocolVersion != MothershipNametagQualificationSiteRequest::cousinStageVersion &&
       request.protocolVersion != MothershipNametagQualificationSiteRequest::restartStageVersion &&
       request.protocolVersion != MothershipNametagQualificationSiteRequest::writerStageVersion &&
       request.protocolVersion != MothershipNametagQualificationSiteRequest::pathStageVersion &&
       request.protocolVersion != MothershipNametagQualificationSiteRequest::replayStageVersion &&
       request.protocolVersion != MothershipNametagQualificationSiteRequest::claimStageVersion &&
       request.protocolVersion != MothershipNametagQualificationSiteRequest::seedReadbackVersion) ||
      !mothershipNametagQualificationIntentValid(request.intent) || request.targetClusterUUID == 0 ||
      request.targetApp6DeploymentID == 0 || request.targetProbeDeploymentID == 0 ||
      request.targetApp6DeploymentID == request.targetProbeDeploymentID ||
      (request.action != MothershipNametagQualificationSiteAction::execute &&
       request.action != MothershipNametagQualificationSiteAction::query)) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::cousinStageVersion) {
    if ((request.intent.row != MothershipNametagQualificationRow::permissionRevokeReinstall &&
         request.intent.row != MothershipNametagQualificationRow::cousinRouteSessionReconnect) ||
        (request.intent.direction == MothershipNametagQualificationDirection::injection ?
           (request.intent.protocolVersion != MothershipNametagQualificationIntent::cousinRecoveryVersion ||
            (request.cousinStage != ProdigyNametagQualificationCousinStage::faultObserved &&
             request.cousinStage != ProdigyNametagQualificationCousinStage::final)) :
           request.cousinStage != ProdigyNametagQualificationCousinStage::final) || !request.cousinSessions.empty()) return false;
  } else if (request.cousinStage != ProdigyNametagQualificationCousinStage::none || !request.cousinSessions.empty()) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::restartStageVersion) {
    if (request.intent.row != MothershipNametagQualificationRow::mothershipRestartResume ||
        (request.intent.direction == MothershipNametagQualificationDirection::injection ?
         (request.restartStage != ProdigyNametagQualificationRestartStage::beforeRestart &&
          request.restartStage != ProdigyNametagQualificationRestartStage::afterRestart) :
         request.restartStage != ProdigyNametagQualificationRestartStage::afterRestart)) return false;
  } else if (request.restartStage != ProdigyNametagQualificationRestartStage::none) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::writerStageVersion) {
    if (request.intent.row != MothershipNametagQualificationRow::localWriterIsolation ||
        request.writerStage < ProdigyNametagQualificationWriterStage::arm ||
        request.writerStage > ProdigyNametagQualificationWriterStage::final ||
        (request.intent.direction == MothershipNametagQualificationDirection::observation &&
         request.writerStage != ProdigyNametagQualificationWriterStage::final) ||
        !prodigyNametagQualificationWriterIsolationValid(request.writerIsolation) || request.writerIsolation.response ||
        request.writerIsolation.stage != ProdigyNametagQualificationWriterIsolationStage::arm ||
        request.writerIsolation.runUUID != request.intent.runUUID ||
        (request.writerStage != ProdigyNametagQualificationWriterStage::final &&
         request.writerIsolation.clusterUUID != request.targetClusterUUID))
      return false;
  } else if (request.writerStage != ProdigyNametagQualificationWriterStage::none) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::pathStageVersion) {
    if (!prodigyNametagQualificationPathStageValid(uint8_t(request.intent.row), uint8_t(request.intent.direction),
            request.pathStage, request.pathBatch, request.pathFaultExpiresAtMilliseconds,
            request.intent.startedAtMilliseconds, request.intent.convergenceDeadlineAtMilliseconds)) return false;
  } else if (request.pathStage != ProdigyNametagQualificationPathStage::none || request.pathBatch != 0 ||
             request.pathFaultExpiresAtMilliseconds != 0) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::replayStageVersion) {
    if (request.intent.row != MothershipNametagQualificationRow::graphKvReplayReorder ||
        (request.replayStage != ProdigyNametagQualificationReplayWorkStage::prepare &&
         request.replayStage != ProdigyNametagQualificationReplayWorkStage::workload &&
         request.replayStage != ProdigyNametagQualificationReplayWorkStage::final) ||
        (request.intent.direction == MothershipNametagQualificationDirection::observation &&
         request.replayStage != ProdigyNametagQualificationReplayWorkStage::final)) return false;
    if (request.replayStage == ProdigyNametagQualificationReplayWorkStage::workload) {
      if (request.replaySources.size() != 2 || request.targetClusterUUID != request.intent.probeTargets[0].clusterUUID ||
          request.replaySources[0].store != ProdigyNametagQualificationReplayStore::kv ||
          request.replaySources[1].store != ProdigyNametagQualificationReplayStore::graph ||
          request.replaySources[0].challengeUUID == request.replaySources[1].challengeUUID) return false;
      for (const auto& source : request.replaySources)
        if (!prodigyNametagQualificationReplayValid(source) || source.response || source.targetSide ||
            source.stage != ProdigyNametagQualificationReplayStage::arm || source.runUUID != request.intent.runUUID ||
            source.executionGeneration != request.intent.executionGeneration ||
            (prodigyNametagQualificationReplayLocalHalf(source.store, false) == CousinRouteHalf::source ?
             source.session.sourceClusterUUID : source.session.destinationClusterUUID) != request.targetClusterUUID ||
            source.deadlineAtMilliseconds <= request.intent.startedAtMilliseconds ||
            source.deadlineAtMilliseconds > request.intent.deadlineAtMilliseconds) return false;
    } else if (!request.replaySources.empty()) return false;
  } else if (request.replayStage != ProdigyNametagQualificationReplayWorkStage::none || !request.replaySources.empty()) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::claimStageVersion) {
    if (!prodigyNametagQualificationClaimStageValid(uint8_t(request.intent.row), uint8_t(request.intent.direction),
            request.claimStage, request.claimFaultExpiresAtMilliseconds,
            request.intent.startedAtMilliseconds, request.intent.convergenceDeadlineAtMilliseconds)) return false;
    for (uint128_t winner : request.claimWinnerSites) {
      if (request.claimStage >= ProdigyNametagQualificationClaimStage::settle) {
        if (std::count_if(request.intent.probeTargets.begin(), request.intent.probeTargets.end(),
              [&](const auto& site) { return site.clusterUUID == winner; }) != 1) return false;
      } else if (winner) return false;
    }
  } else if (request.claimStage != ProdigyNametagQualificationClaimStage::none || request.claimFaultExpiresAtMilliseconds ||
      std::any_of(request.claimWinnerSites.begin(), request.claimWinnerSites.end(), [](uint128_t site) { return site != 0; })) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::seedReadbackVersion) {
    if (!prodigyNametagQualificationSeedReadbackRow(uint8_t(request.intent.row)) || !request.seedBaselineOperationUUID ||
        !prodigyIsSHA256HexDigest(request.seedControlWitnessDigest) || !prodigyIsSHA256HexDigest(request.seedBaselineFixtureSHA256) ||
        !prodigyIsSHA256HexDigest(request.seedBaselineReadbackSHA256)) return false;
    const uint16_t apps[] = {MeshRegistry::Hot::applicationID, MeshRegistry::Cold::applicationID,
      MeshRegistry::Radar::applicationID, MeshRegistry::Pulse::applicationID, MeshRegistry::Truth::applicationID};
    for (size_t i = 0; i < 5; ++i)
      if (ApplicationConfig::extractApplicationID(request.seedStoreDeploymentIDs[i]) != apps[i]) return false;
  } else if (request.seedBaselineOperationUUID || !request.seedControlWitnessDigest.empty() ||
      !request.seedBaselineFixtureSHA256.empty() || !request.seedBaselineReadbackSHA256.empty() ||
      std::any_of(request.seedStoreDeploymentIDs.begin(), request.seedStoreDeploymentIDs.end(), [](uint64_t id) { return id != 0; })) return false;
  if (request.intent.row == MothershipNametagQualificationRow::secondStreamHandoffFence ||
      request.intent.row == MothershipNametagQualificationRow::truthClaimPartition) {
    bool exact = false;
    for (size_t site = 0; site < request.intent.probeTargets.size(); ++site)
      if (request.intent.probeTargets[site].clusterUUID == request.targetClusterUUID)
        exact = request.intent.app6Routes[site * 2].clusterUUID == request.targetClusterUUID &&
            request.intent.app6Routes[site * 2].deploymentID == request.targetApp6DeploymentID;
    if (!exact) return false;
  }
  return std::any_of(request.intent.probeTargets.begin(), request.intent.probeTargets.end(), [&](const auto& target) {
    return target.clusterUUID == request.targetClusterUUID && target.probeDeploymentID == request.targetProbeDeploymentID;
  });
}

static inline bool mothershipNametagQualificationApplicationCommand(
    const MothershipNametagQualificationSiteRequest& request,
    ProdigyNametagQualificationApplicationCommand& command)
{
  command = {};
  if (!mothershipNametagQualificationSiteRequestValid(request)) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::cousinStageVersion) {
    command.protocolVersion = ProdigyNametagQualificationApplicationCommand::cousinStageVersion;
    command.cousinStage = request.cousinStage; command.cousinSessions = request.cousinSessions;
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::restartStageVersion) {
    command.protocolVersion = ProdigyNametagQualificationApplicationCommand::restartStageVersion;
    command.restartStage = request.restartStage;
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::writerStageVersion) {
    command.protocolVersion = ProdigyNametagQualificationApplicationCommand::writerStageVersion;
    command.writerStage = request.writerStage; command.writerIsolation = request.writerIsolation;
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::pathStageVersion) {
    command.protocolVersion = ProdigyNametagQualificationApplicationCommand::pathStageVersion;
    command.pathStage = request.pathStage; command.pathBatch = request.pathBatch;
    command.pathFaultExpiresAtMilliseconds = request.pathFaultExpiresAtMilliseconds;
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::replayStageVersion) {
    command.protocolVersion = ProdigyNametagQualificationApplicationCommand::replayStageVersion;
    command.replayStage = request.replayStage;
    command.replaySources = request.replaySources;
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::claimStageVersion) {
    command.protocolVersion = ProdigyNametagQualificationApplicationCommand::claimStageVersion;
    command.claimStage = request.claimStage;
    command.claimFaultExpiresAtMilliseconds = request.claimFaultExpiresAtMilliseconds;
    command.claimWinnerSites = request.claimWinnerSites;
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::seedReadbackVersion) {
    command.protocolVersion = ProdigyNametagQualificationApplicationCommand::seedReadbackVersion;
    command.seedBaselineOperationUUID = request.seedBaselineOperationUUID;
    command.seedStoreDeploymentIDs = request.seedStoreDeploymentIDs;
    command.seedControlWitnessDigest = request.seedControlWitnessDigest;
    command.seedBaselineFixtureSHA256 = request.seedBaselineFixtureSHA256;
    command.seedBaselineReadbackSHA256 = request.seedBaselineReadbackSHA256;
  }
  command.runUUID = request.intent.runUUID;
  command.row = uint8_t(request.intent.row);
  command.direction = uint8_t(request.intent.direction);
  command.executionGeneration = request.intent.executionGeneration;
  if (request.intent.row == MothershipNametagQualificationRow::secondStreamHandoffFence ||
      request.intent.row == MothershipNametagQualificationRow::truthClaimPartition) {
    for (size_t site = 0; site < request.intent.probeTargets.size(); ++site)
      if (request.intent.probeTargets[site].clusterUUID == request.targetClusterUUID) {
        command.app6Routes.push_back(request.intent.app6Routes[site * 2]);
        command.app6Routes.push_back(request.intent.app6Routes[site * 2 + 1]);
        break;
      }
  }
  command.rowID = request.intent.rowID;
  command.descriptor = request.intent.descriptor;
  command.localClusterUUID = request.targetClusterUUID;
  for (const auto& target : request.intent.probeTargets)
    command.canonicalClusterUUIDs.push_back(target.clusterUUID);
  command.deploymentID = request.targetProbeDeploymentID;
  command.startedAtMilliseconds = request.intent.startedAtMilliseconds;
  command.deadlineAtMilliseconds = request.intent.deadlineAtMilliseconds;
  command.convergenceDeadlineAtMilliseconds = request.intent.convergenceDeadlineAtMilliseconds;
  command.priorInjectionRunUUID = request.intent.priorInjectionRunUUID;
  command.priorInjectionReceiptDigest = request.intent.priorInjectionReceiptDigest;
  return prodigyNametagQualificationApplicationCommandValid(command);
}

class MothershipNametagQualificationSiteResponse : public MothershipResponse {
public:
  static constexpr uint32_t version = 2;
  static constexpr uint32_t cousinStageVersion = 3;
  static constexpr uint32_t restartStageVersion = 5;
  static constexpr uint32_t writerStageVersion = 6;
  static constexpr uint32_t pathStageVersion = 7;
  static constexpr uint32_t replayStageVersion = 9;
  static constexpr uint32_t claimStageVersion = 12;
  static constexpr uint32_t seedReadbackVersion = 13;
  uint32_t protocolVersion = version;
  bool completed = false;
  ProdigyNametagQualificationApplicationReceipt applicationReceipt;
};
template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationSiteResponse& response)
{ serializer.value4b(response.protocolVersion); serializer.value1b(response.success); serializer.text1b(response.failure, 1024);
  serializer.value1b(response.completed); serializer.object(response.applicationReceipt); }

static inline bool mothershipNametagQualificationSiteResponseValid(
    const MothershipNametagQualificationSiteRequest& request,
    const MothershipNametagQualificationSiteResponse& response)
{
  if (!response.success || response.protocolVersion !=
      (request.protocolVersion == MothershipNametagQualificationSiteRequest::seedReadbackVersion ?
       MothershipNametagQualificationSiteResponse::seedReadbackVersion :
       request.protocolVersion == MothershipNametagQualificationSiteRequest::claimStageVersion ?
       MothershipNametagQualificationSiteResponse::claimStageVersion :
       request.protocolVersion == MothershipNametagQualificationSiteRequest::replayStageVersion ?
       MothershipNametagQualificationSiteResponse::replayStageVersion :
       request.protocolVersion == MothershipNametagQualificationSiteRequest::pathStageVersion ?
       MothershipNametagQualificationSiteResponse::pathStageVersion :
       request.protocolVersion == MothershipNametagQualificationSiteRequest::writerStageVersion ?
       MothershipNametagQualificationSiteResponse::writerStageVersion :
       request.protocolVersion == MothershipNametagQualificationSiteRequest::restartStageVersion ?
       MothershipNametagQualificationSiteResponse::restartStageVersion :
       request.protocolVersion == MothershipNametagQualificationSiteRequest::cousinStageVersion ?
       MothershipNametagQualificationSiteResponse::cousinStageVersion : MothershipNametagQualificationSiteResponse::version)) return false;
  if (request.action == MothershipNametagQualificationSiteAction::execute) return !response.completed;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::seedReadbackVersion) {
    ProdigyNametagQualificationApplicationCommand command = {};
    return response.completed && mothershipNametagQualificationApplicationCommand(request, command) &&
        prodigyNametagQualificationSeedReadbackReceiptMatchesCommand(command, response.applicationReceipt);
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::claimStageVersion) {
    ProdigyNametagQualificationApplicationCommand command = {};
    return response.completed && mothershipNametagQualificationApplicationCommand(request, command) &&
        prodigyNametagQualificationClaimReceiptMatchesCommand(command, response.applicationReceipt);
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::replayStageVersion) {
    ProdigyNametagQualificationApplicationCommand command = {};
    return response.completed && mothershipNametagQualificationApplicationCommand(request, command) &&
        prodigyNametagQualificationReplayReceiptMatchesCommand(command, response.applicationReceipt);
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::writerStageVersion) {
    ProdigyNametagQualificationApplicationCommand command = {};
    return response.completed && mothershipNametagQualificationApplicationCommand(request, command) &&
        prodigyNametagQualificationWriterReceiptMatchesCommand(command, response.applicationReceipt);
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::pathStageVersion) {
    ProdigyNametagQualificationApplicationCommand command = {};
    return response.completed && mothershipNametagQualificationApplicationCommand(request, command) &&
        prodigyNametagQualificationPathReceiptMatchesCommand(command, response.applicationReceipt);
  }
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::cousinStageVersion) {
    ProdigyNametagQualificationApplicationCommand command = {};
    return response.completed && mothershipNametagQualificationApplicationCommand(request, command) &&
        prodigyNametagQualificationCousinReceiptMatchesCommand(command, response.applicationReceipt);
  }
  if (!response.completed) return false;
  if (request.protocolVersion == MothershipNametagQualificationSiteRequest::restartStageVersion) {
    ProdigyNametagQualificationApplicationCommand command = {};
    return mothershipNametagQualificationApplicationCommand(request, command) &&
        prodigyNametagQualificationRestartReceiptMatchesCommand(command, response.applicationReceipt);
  }
  const auto& receipt = response.applicationReceipt;
  return receipt.protocolVersion == ProdigyNametagQualificationApplicationReceipt::version &&
      prodigyNametagQualificationApplicationReceiptValid(receipt) && receipt.runUUID == request.intent.runUUID &&
      receipt.row == uint8_t(request.intent.row) && receipt.direction == uint8_t(request.intent.direction) &&
      receipt.executionGeneration == request.intent.executionGeneration &&
      receipt.rowID.equal(request.intent.rowID) && receipt.localClusterUUID == request.targetClusterUUID &&
      prodigyNametagQualificationDescriptorEqual(receipt.descriptor, request.intent.descriptor) &&
      receipt.deploymentID == request.targetProbeDeploymentID &&
      receipt.startedAtMilliseconds == request.intent.startedAtMilliseconds &&
      receipt.deadlineAtMilliseconds == request.intent.deadlineAtMilliseconds &&
      receipt.convergenceDeadlineAtMilliseconds == request.intent.convergenceDeadlineAtMilliseconds;
}

class MothershipNametagQualificationReceipt {
public:
  static constexpr uint32_t version = 4;
  uint32_t protocolVersion = version;
  uint128_t runUUID = 0;
  MothershipNametagQualificationRow row = MothershipNametagQualificationRow::sequentialUserKeyWrites;
  MothershipNametagQualificationDirection direction = MothershipNametagQualificationDirection::injection;
  uint64_t executionGeneration = 0;
  String rowID;
  ProdigyNametagQualificationDescriptor descriptor;
  uint128_t allMastersOperationUUID = 0;
  Vector<ProdigyNametagQualificationApplicationReceipt> applicationReceipts;
  int64_t startedAtMilliseconds = 0;
  int64_t deadlineAtMilliseconds = 0;
  int64_t convergenceDeadlineAtMilliseconds = 0;
  ProdigyNametagQualificationWitness witnessedResult = ProdigyNametagQualificationWitness::orderedUserKeyDigest;
  String canonicalConvergenceWitness;
  String witnessDigest;
  // Compatibility-only execution scratch. v4 accepts only the typed witness
  // above; Mothership's fault executor must be migrated separately.
  String canonicalFiveStoreReceipt;
  bool healthyTopology = false;
  int64_t observedAtMilliseconds = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipNametagQualificationReceipt& receipt)
{
  serializer.value4b(receipt.protocolVersion); serializer.value16b(receipt.runUUID); serializer.value1b(receipt.row); serializer.value1b(receipt.direction);
  serializer.value8b(receipt.executionGeneration); serializer.text1b(receipt.rowID, 128); serializer.object(receipt.descriptor); serializer.value16b(receipt.allMastersOperationUUID);
  serializer.container(receipt.applicationReceipts, 3);
  serializer.value1b(receipt.witnessedResult); serializer.text1b(receipt.canonicalConvergenceWitness, 64 * 1024); serializer.text1b(receipt.witnessDigest, 64);
  serializer.value8b(receipt.startedAtMilliseconds); serializer.value8b(receipt.deadlineAtMilliseconds);
  serializer.value8b(receipt.convergenceDeadlineAtMilliseconds); serializer.value8b(receipt.observedAtMilliseconds);
}

static inline bool mothershipNametagQualificationReceiptValid(const MothershipNametagQualificationReceipt& receipt)
{
  if (receipt.protocolVersion != MothershipNametagQualificationReceipt::version || receipt.runUUID == 0 ||
      receipt.executionGeneration == 0 || !prodigyNametagQualificationDescriptorValid(receipt.descriptor) ||
      !prodigyNametagQualificationDescriptorEqual(receipt.descriptor, mothershipNametagQualificationDescriptor(receipt.row)) ||
      receipt.witnessedResult != receipt.descriptor.expectedWitness || receipt.canonicalConvergenceWitness.empty() ||
      !prodigyIsSHA256HexDigest(receipt.witnessDigest) || receipt.allMastersOperationUUID == 0 ||
      receipt.applicationReceipts.size() != 3 || receipt.startedAtMilliseconds <= 0 ||
      receipt.deadlineAtMilliseconds <= receipt.startedAtMilliseconds ||
      receipt.convergenceDeadlineAtMilliseconds < receipt.startedAtMilliseconds ||
      receipt.convergenceDeadlineAtMilliseconds > receipt.deadlineAtMilliseconds ||
      receipt.observedAtMilliseconds < receipt.startedAtMilliseconds ||
      receipt.observedAtMilliseconds > receipt.convergenceDeadlineAtMilliseconds) return false;
  String canonicalDigest = {};
  if (!prodigyComputeSHA256Hex(receipt.canonicalConvergenceWitness, canonicalDigest) ||
      !canonicalDigest.equal(receipt.witnessDigest)) return false;
  String canonicalPrefix = {};
  canonicalPrefix.assign("nametag-qualification-v4:"_ctv); canonicalPrefix.append(receipt.rowID); canonicalPrefix.append(":"_ctv);
  if (receipt.canonicalConvergenceWitness.size() <= canonicalPrefix.size() ||
      std::memcmp(receipt.canonicalConvergenceWitness.data(), canonicalPrefix.data(), canonicalPrefix.size()) != 0) return false;
  for (uint32_t index = 0; index < receipt.applicationReceipts.size(); ++index) {
    const auto& application = receipt.applicationReceipts[index];
    if (!prodigyNametagQualificationApplicationReceiptValid(application) || application.runUUID != receipt.runUUID ||
        application.row != uint8_t(receipt.row) || application.direction != uint8_t(receipt.direction) ||
        application.executionGeneration != receipt.executionGeneration ||
        !application.rowID.equal(receipt.rowID) || application.startedAtMilliseconds != receipt.startedAtMilliseconds ||
        !prodigyNametagQualificationDescriptorEqual(application.descriptor, receipt.descriptor) ||
        application.deadlineAtMilliseconds != receipt.deadlineAtMilliseconds ||
        application.convergenceDeadlineAtMilliseconds != receipt.convergenceDeadlineAtMilliseconds) return false;
    for (uint32_t prior = 0; prior < index; ++prior)
      if (receipt.applicationReceipts[prior].localClusterUUID == application.localClusterUUID ||
          receipt.applicationReceipts[prior].deploymentID == application.deploymentID ||
          receipt.applicationReceipts[prior].localContainerUUID == application.localContainerUUID) return false;
  }
  const uint64_t deadlineMs = uint64_t(receipt.deadlineAtMilliseconds - receipt.startedAtMilliseconds);
  const uint64_t convergenceMs = uint64_t(receipt.convergenceDeadlineAtMilliseconds - receipt.startedAtMilliseconds);
  if (deadlineMs == 0 || convergenceMs == 0 || deadlineMs % 1000 != 0 || convergenceMs % 1000 != 0 ||
      deadlineMs / 1000 > UINT32_MAX || convergenceMs / 1000 > UINT32_MAX) return false;
  return mothershipNametagQualificationAdapterForTuple(receipt.row, receipt.direction, receipt.rowID,
      uint32_t(deadlineMs / 1000), uint32_t(convergenceMs / 1000)) != nullptr;
}

static inline bool mothershipNametagQualificationReceiptDigest(
    const MothershipNametagQualificationReceipt& receipt, String& digest)
{
  digest.clear();
  auto copy = receipt;
  String encoded;
  return mothershipNametagQualificationReceiptValid(receipt) &&
      BitseryEngine::serialize(encoded, copy) && !encoded.empty() &&
      prodigyComputeSHA256Hex(encoded, digest) && prodigyIsSHA256HexDigest(digest);
}

// This is deliberately a join of the three authenticated, row-specific App11
// witnesses.  Topology/five-store observations are useful supporting evidence,
// but cannot substitute for a workload witness or select a generic pass.
static inline bool mothershipNametagQualificationRowSixteenWitnessesValid(
    const MothershipNametagQualificationIntent& intent,
    const Vector<ProdigyNametagQualificationApplicationReceipt>& applications,
    const MothershipNametagQualificationExecutionRecord *execution,
    const MothershipNametagQualificationReceipt *priorInjectionReceipt,
    String *canonicalAdmission = nullptr)
{
  if (intent.row != MothershipNametagQualificationRow::secondTruthWriterFencing) return true;
  if (intent.direction == MothershipNametagQualificationDirection::observation) {
    String priorDigest;
    if (priorInjectionReceipt == nullptr ||
        !mothershipNametagQualificationReceiptDigest(*priorInjectionReceipt, priorDigest) ||
        priorInjectionReceipt->runUUID != intent.priorInjectionRunUUID ||
        priorDigest != intent.priorInjectionReceiptDigest ||
        priorInjectionReceipt->row != MothershipNametagQualificationRow::secondTruthWriterFencing ||
        priorInjectionReceipt->direction != MothershipNametagQualificationDirection::injection ||
        priorInjectionReceipt->allMastersOperationUUID != intent.allMastersOperationUUID ||
        priorInjectionReceipt->observedAtMilliseconds > intent.startedAtMilliseconds ||
        priorInjectionReceipt->applicationReceipts.size() != intent.probeTargets.size()) return false;
    const String& joined = priorInjectionReceipt->applicationReceipts[0].joinedWitnessDigest;
    if (!prodigyIsSHA256HexDigest(joined) ||
        priorInjectionReceipt->applicationReceipts[0].participantRole !=
            ProdigyNametagQualificationParticipantRole::ewrSessionFence ||
        applications.size() != intent.probeTargets.size()) return false;
    for (uint32_t site = 0; site < applications.size(); ++site) {
      const auto& prior = priorInjectionReceipt->applicationReceipts[site];
      if (prior.localClusterUUID != intent.probeTargets[site].clusterUUID ||
          prior.deploymentID != intent.probeTargets[site].probeDeploymentID ||
          prior.observedAtMilliseconds > intent.startedAtMilliseconds ||
          prior.joinedWitnessDigest != joined ||
          (site == 0 ? prior.participantRole != ProdigyNametagQualificationParticipantRole::ewrSessionFence :
                       prior.participantRole != ProdigyNametagQualificationParticipantRole::truthObserver) ||
          applications[site].participantRole != ProdigyNametagQualificationParticipantRole::truthObserver ||
          applications[site].joinedWitnessDigest != joined) return false;
    }
    if (canonicalAdmission != nullptr) *canonicalAdmission = priorDigest;
    return true;
  }
  String expectedIntent = {}, encodedExecutionIntent = {};
  auto intentCopy = intent;
  auto executionIntentCopy = execution != nullptr ? execution->intent : MothershipNametagQualificationIntent{};
  // A crash may occur after the verified phase is durable but before the
  // final receipt is written; that exact intent must remain resumable.
  if (execution == nullptr ||
      (execution->phase != MothershipNametagQualificationExecutionPhase::converging &&
       execution->phase != MothershipNametagQualificationExecutionPhase::verified) ||
      !mothershipNametagQualificationExecutionRecordValid(*execution) ||
      !BitseryEngine::serialize(expectedIntent, intentCopy) ||
      !BitseryEngine::serialize(encodedExecutionIntent, executionIntentCopy) ||
      expectedIntent != encodedExecutionIntent ||
      !mothershipNametagQualificationSecondTruthWriterAdmissionMatchesIntent(
          intent, execution->secondTruthWriterAdmission) ||
      applications.size() != intent.probeTargets.size()) return false;
  const String& joined = applications[0].joinedWitnessDigest;
  if (!prodigyIsSHA256HexDigest(joined) ||
      applications[0].participantRole != ProdigyNametagQualificationParticipantRole::ewrSessionFence)
    return false;
  for (uint32_t site = 1; site < applications.size(); ++site)
    if (applications[site].participantRole != ProdigyNametagQualificationParticipantRole::truthObserver ||
        applications[site].joinedWitnessDigest != joined) return false;
  if (canonicalAdmission != nullptr) {
    auto admission = execution->secondTruthWriterAdmission;
    if (BitseryEngine::serialize(*canonicalAdmission, admission) == false || canonicalAdmission->empty()) return false;
  }
  return true;
}

static inline bool mothershipNametagQualificationBuildReceipt(
    const MothershipNametagQualificationIntent& intent,
    const Vector<ProdigyNametagQualificationApplicationReceipt>& applications,
    const String& canonicalTopologyEvidence, int64_t observedAtMilliseconds,
    MothershipNametagQualificationReceipt& receipt, String *failure = nullptr,
    const MothershipNametagQualificationExecutionRecord *execution = nullptr,
    const MothershipNametagQualificationReceipt *priorInjectionReceipt = nullptr,
    const MothershipNametagQualificationExecutionRecord *priorCousinExecution = nullptr)
{
  receipt = {};
  if (!mothershipNametagQualificationIntentValid(intent) || applications.size() != intent.probeTargets.size() ||
      canonicalTopologyEvidence.empty() || observedAtMilliseconds < intent.startedAtMilliseconds ||
      observedAtMilliseconds > intent.convergenceDeadlineAtMilliseconds)
  {
    if (failure) failure->assign("qualification receipt has no exact row-specific three-site witness"_ctv);
    return false;
  }

  String applicationBytes = {}, applicationDigest = {};
  for (uint32_t site = 0; site < applications.size(); ++site)
  {
    const auto& application = applications[site];
    const auto& target = intent.probeTargets[site];
    if (!prodigyNametagQualificationApplicationReceiptValid(application) ||
        application.runUUID != intent.runUUID || application.row != uint8_t(intent.row) ||
        application.direction != uint8_t(intent.direction) ||
        application.executionGeneration != intent.executionGeneration || !application.rowID.equal(intent.rowID) ||
        !prodigyNametagQualificationDescriptorEqual(application.descriptor, intent.descriptor) ||
        application.witnessedResult != intent.descriptor.expectedWitness ||
        application.localClusterUUID != target.clusterUUID || application.deploymentID != target.probeDeploymentID ||
        application.startedAtMilliseconds != intent.startedAtMilliseconds ||
        application.deadlineAtMilliseconds != intent.deadlineAtMilliseconds ||
        application.convergenceDeadlineAtMilliseconds != intent.convergenceDeadlineAtMilliseconds)
    {
      if (failure) failure->assign("qualification App11 receipt is absent, generic, or mismatched for its row"_ctv);
      receipt = {};
      return false;
    }
    String encoded = {};
    auto copy = application;
    if (!BitseryEngine::serialize(encoded, copy))
    {
      if (failure) failure->assign("qualification App11 witness cannot be canonically encoded"_ctv);
      receipt = {};
      return false;
    }
    applicationBytes.append(encoded);
  }
  if (prodigyNametagQualificationSeedReadbackRow(uint8_t(intent.row))) {
    if (!execution || !mothershipNametagQualificationExecutionRecordValid(*execution) ||
        !mothershipNametagQualificationSeedExecutionComplete(*execution) ||
        (execution->phase != MothershipNametagQualificationExecutionPhase::converging &&
         execution->phase != MothershipNametagQualificationExecutionPhase::verified)) return false;
    auto expected = execution->intent, actual = intent; String a, b;
    if (!BitseryEngine::serialize(a, expected) || !BitseryEngine::serialize(b, actual) || a != b) return false;
    for (size_t i = 0; i < applications.size(); ++i) {
      auto x = applications[i], y = execution->seedFinalReadbacks[i]; String u, v;
      if (!BitseryEngine::serialize(u, x) || !BitseryEngine::serialize(v, y) || u != v) return false;
    }
    auto saved = *execution; String evidence; if (!BitseryEngine::serialize(evidence, saved)) return false;
    applicationBytes.append(evidence);
  }
  String canonicalAdmission = {};
  if (!mothershipNametagQualificationRowSixteenWitnessesValid(
          intent, applications, execution, priorInjectionReceipt, &canonicalAdmission))
  {
    if (failure) failure->assign("row sixteen lacks its admission receipt, EWR fence, or matching observers"_ctv);
    receipt = {};
    return false;
  }
  // The final digest must commit to the durable singleton-policy rejection as
  // well as the three App11 witnesses.  This uses the existing receipt codec.
  if (!canonicalAdmission.empty()) applicationBytes.append(canonicalAdmission);
  if (prodigyNametagQualificationPathRow(uint8_t(intent.row)) &&
      intent.direction == MothershipNametagQualificationDirection::injection) {
    if (!execution || !mothershipNametagQualificationExecutionRecordValid(*execution) ||
        !mothershipNametagQualificationPathExecutionComplete(*execution) ||
        (execution->phase != MothershipNametagQualificationExecutionPhase::converging &&
         execution->phase != MothershipNametagQualificationExecutionPhase::verified) ||
        execution->intent.runUUID != intent.runUUID || execution->intent.executionGeneration != intent.executionGeneration ||
        execution->intent.allMastersOperationUUID != intent.allMastersOperationUUID) return false;
    const uint8_t finalBatch = intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ? 1 : 0;
    for (const auto& application : applications) {
      auto actual = application; String encoded = {};
      if (application.pathStage != ProdigyNametagQualificationPathStage::final || application.pathBatch != finalBatch ||
          !BitseryEngine::serialize(encoded, actual)) return false;
      bool matched = false;
      for (auto saved : execution->pathWorkReceipts) {
        if (saved.localClusterUUID != application.localClusterUUID || saved.pathStage != application.pathStage ||
            saved.pathBatch != finalBatch) continue;
        String bytes = {}; if (!BitseryEngine::serialize(bytes, saved) || bytes != encoded) return false;
        matched = true;
      }
      if (!matched) return false;
    }
    auto copy = *execution; String encoded = {};
    if (!BitseryEngine::serialize(encoded, copy)) return false;
    applicationBytes.append(encoded);
  }
  if (prodigyNametagQualificationPathRow(uint8_t(intent.row)) &&
      intent.direction == MothershipNametagQualificationDirection::observation) {
    const auto *proof = priorCousinExecution; String priorDigest = {};
    if (!proof || proof->phase != MothershipNametagQualificationExecutionPhase::verified ||
        !mothershipNametagQualificationExecutionRecordValid(*proof) ||
        !mothershipNametagQualificationPathExecutionComplete(*proof) ||
        proof->intent.runUUID != intent.runUUID || proof->intent.row != intent.row ||
        proof->intent.allMastersOperationUUID != intent.allMastersOperationUUID ||
        !priorInjectionReceipt || !mothershipNametagQualificationReceiptDigest(*priorInjectionReceipt, priorDigest) ||
        priorDigest != intent.priorInjectionReceiptDigest || priorInjectionReceipt->runUUID != intent.priorInjectionRunUUID ||
        priorInjectionReceipt->executionGeneration != proof->intent.executionGeneration ||
        priorInjectionReceipt->observedAtMilliseconds > intent.startedAtMilliseconds ||
        priorInjectionReceipt->applicationReceipts.size() != applications.size()) return false;
    const uint8_t batch = intent.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ? 1 : 0;
    for (size_t i = 0; i < applications.size(); ++i) {
      const auto& current = applications[i]; const auto& previous = priorInjectionReceipt->applicationReceipts[i];
      if (current.pathStage != ProdigyNametagQualificationPathStage::final || current.pathBatch != batch ||
          previous.localClusterUUID != current.localClusterUUID || previous.deploymentID != current.deploymentID ||
          previous.pathStage != current.pathStage || previous.pathBatch != batch ||
          previous.pathFaultExpiresAtMilliseconds != current.pathFaultExpiresAtMilliseconds ||
          previous.joinedWitnessDigest != current.joinedWitnessDigest) return false;
    }
    auto copy = *proof; String encoded = {};
    if (!BitseryEngine::serialize(encoded, copy)) return false;
    applicationBytes.append(priorDigest); applicationBytes.append(encoded);
  }
  if (intent.row == MothershipNametagQualificationRow::graphKvReplayReorder) {
    const bool injection = intent.direction == MothershipNametagQualificationDirection::injection;
    const auto *proof = injection ? execution : priorCousinExecution; String priorDigest = {};
    if (!proof || !mothershipNametagQualificationExecutionRecordValid(*proof) ||
        !mothershipNametagQualificationReplayExecutionComplete(*proof) ||
        (injection ? (proof->phase != MothershipNametagQualificationExecutionPhase::converging &&
                      proof->phase != MothershipNametagQualificationExecutionPhase::verified) :
                     proof->phase != MothershipNametagQualificationExecutionPhase::verified) ||
        proof->intent.runUUID != intent.runUUID || proof->intent.allMastersOperationUUID != intent.allMastersOperationUUID) return false;
    if (!injection && (!priorInjectionReceipt || !mothershipNametagQualificationReceiptDigest(*priorInjectionReceipt, priorDigest) ||
        priorDigest != intent.priorInjectionReceiptDigest || priorInjectionReceipt->runUUID != intent.priorInjectionRunUUID ||
        priorInjectionReceipt->executionGeneration != proof->intent.executionGeneration ||
        priorInjectionReceipt->observedAtMilliseconds > intent.startedAtMilliseconds)) return false;
    for (size_t i = 0; i < applications.size(); ++i) {
      const auto& application = applications[i];
      if (application.replayStage != ProdigyNametagQualificationReplayWorkStage::final ||
          application.joinedWitnessDigest != proof->replayLocalWork.joinedWitnessDigest ||
          proof->intent.probeTargets[i].clusterUUID != application.localClusterUUID ||
          proof->intent.probeTargets[i].probeDeploymentID != application.deploymentID) return false;
      if (injection) {
        auto actual = application; String bytes = {}; bool found = false;
        if (!BitseryEngine::serialize(bytes, actual)) return false;
        for (auto saved : proof->replayFinalReadbacks) if (saved.localClusterUUID == application.localClusterUUID) {
          String encoded = {}; if (!BitseryEngine::serialize(encoded, saved) || encoded != bytes) return false; found = true;
        }
        if (!found) return false;
      }
    }
    auto copy = *proof; String encoded = {}; if (!BitseryEngine::serialize(encoded, copy)) return false;
    if (!injection) applicationBytes.append(priorDigest);
    applicationBytes.append(encoded);
  }
  if (intent.row == MothershipNametagQualificationRow::truthClaimPartition) {
    const bool injection = intent.direction == MothershipNametagQualificationDirection::injection;
    const auto *proof = injection ? execution : priorCousinExecution; String priorDigest = {};
    if (!proof || !mothershipNametagQualificationExecutionRecordValid(*proof) ||
        !mothershipNametagQualificationClaimExecutionComplete(*proof) ||
        (injection ? (proof->phase != MothershipNametagQualificationExecutionPhase::converging &&
                      proof->phase != MothershipNametagQualificationExecutionPhase::verified) :
                     proof->phase != MothershipNametagQualificationExecutionPhase::verified) ||
        proof->intent.runUUID != intent.runUUID || proof->intent.allMastersOperationUUID != intent.allMastersOperationUUID) return false;
    if (!injection && (!priorInjectionReceipt ||
        !mothershipNametagQualificationReceiptDigest(*priorInjectionReceipt, priorDigest) ||
        priorDigest != intent.priorInjectionReceiptDigest || priorInjectionReceipt->runUUID != intent.priorInjectionRunUUID ||
        priorInjectionReceipt->executionGeneration != proof->intent.executionGeneration ||
        priorInjectionReceipt->observedAtMilliseconds > intent.startedAtMilliseconds ||
        priorInjectionReceipt->applicationReceipts.size() != applications.size())) return false;
    for (size_t i = 0; i < applications.size(); ++i) {
      const auto& application = applications[i];
      if (application.claimStage != ProdigyNametagQualificationClaimStage::final ||
          application.claimWinnerSites != proof->claimWinnerSites) return false;
      if (injection) {
        auto actual = application; String encoded = {}; bool found = false;
        if (!BitseryEngine::serialize(encoded, actual)) return false;
        for (auto saved : proof->claimReceipts) if (saved.localClusterUUID == application.localClusterUUID &&
            saved.claimStage == ProdigyNametagQualificationClaimStage::final) {
          String bytes = {}; if (!BitseryEngine::serialize(bytes, saved) || bytes != encoded) return false; found = true;
        }
        if (!found) return false;
      } else {
        const auto& previous = priorInjectionReceipt->applicationReceipts[i];
        if (previous.localClusterUUID != application.localClusterUUID || previous.deploymentID != application.deploymentID ||
            previous.claimWinnerSites != application.claimWinnerSites ||
            previous.claimFaultExpiresAtMilliseconds != application.claimFaultExpiresAtMilliseconds ||
            previous.joinedWitnessDigest != application.joinedWitnessDigest) return false;
      }
    }
    auto copy = *proof; String encoded = {}; if (!BitseryEngine::serialize(encoded, copy)) return false;
    if (!injection) applicationBytes.append(priorDigest); applicationBytes.append(encoded);
  }
  if (intent.row == MothershipNametagQualificationRow::localWriterIsolation) {
    const bool injection = intent.direction == MothershipNametagQualificationDirection::injection;
    const auto *proof = injection ? execution : priorCousinExecution;
    if (!proof || proof->protocolVersion != MothershipNametagQualificationExecutionRecord::writerIsolationVersion ||
        !mothershipNametagQualificationExecutionRecordValid(*proof) ||
        (injection ? (proof->phase != MothershipNametagQualificationExecutionPhase::converging &&
                      proof->phase != MothershipNametagQualificationExecutionPhase::verified) :
                     proof->phase != MothershipNametagQualificationExecutionPhase::verified) ||
        proof->intent.runUUID != intent.runUUID || proof->intent.row != intent.row ||
        proof->intent.allMastersOperationUUID != intent.allMastersOperationUUID ||
        proof->intent.probeTargets.size() != intent.probeTargets.size()) return false;
    for (size_t i = 0; i < applications.size(); ++i) {
      if (proof->intent.probeTargets[i].clusterUUID != intent.probeTargets[i].clusterUUID ||
          proof->intent.probeTargets[i].probeDeploymentID != intent.probeTargets[i].probeDeploymentID ||
          applications[i].protocolVersion != ProdigyNametagQualificationApplicationReceipt::writerStageVersion ||
          applications[i].writerStage != ProdigyNametagQualificationWriterStage::final ||
          applications[i].writerChallengeUUID != proof->writerIsolation.challenge.challengeUUID ||
          applications[i].joinedWitnessDigest != proof->writerIsolation.localWork.joinedWitnessDigest) return false;
    }
    if (!injection) {
      String priorDigest = {};
      if (!priorInjectionReceipt || !mothershipNametagQualificationReceiptDigest(*priorInjectionReceipt, priorDigest) ||
          priorDigest != intent.priorInjectionReceiptDigest || priorInjectionReceipt->runUUID != intent.priorInjectionRunUUID ||
          priorInjectionReceipt->executionGeneration != proof->intent.executionGeneration ||
          priorInjectionReceipt->observedAtMilliseconds > intent.startedAtMilliseconds) return false;
      String priorBytes = {}, priorApplicationDigest = {}, priorPrefix = {};
      for (const auto& application : priorInjectionReceipt->applicationReceipts) {
        auto item = application; String bytes = {};
        if (!BitseryEngine::serialize(bytes, item)) return false;
        priorBytes.append(bytes);
      }
      auto priorExecution = *proof; priorExecution.phase = MothershipNametagQualificationExecutionPhase::converging;
      String encoded = {};
      if (!BitseryEngine::serialize(encoded, priorExecution)) return false;
      priorBytes.append(encoded);
      if (!prodigyComputeSHA256Hex(priorBytes, priorApplicationDigest)) return false;
      priorPrefix.assign("nametag-qualification-v4:"_ctv); priorPrefix.append(intent.rowID);
      priorPrefix.append(":"_ctv); priorPrefix.append(priorApplicationDigest); priorPrefix.append(":"_ctv);
      if (priorInjectionReceipt->canonicalConvergenceWitness.size() <= priorPrefix.size() ||
          std::memcmp(priorInjectionReceipt->canonicalConvergenceWitness.data(), priorPrefix.data(), priorPrefix.size()) != 0) return false;
      applicationBytes.append(priorDigest);
    }
    auto copy = *proof; String encoded = {};
    if (!BitseryEngine::serialize(encoded, copy)) return false;
    applicationBytes.append(encoded);
  }
  if (intent.protocolVersion == MothershipNametagQualificationIntent::cousinRecoveryVersion &&
      intent.direction == MothershipNametagQualificationDirection::injection) {
    if (!execution || execution->protocolVersion != MothershipNametagQualificationExecutionRecord::cousinTransportVersion ||
        (execution->phase != MothershipNametagQualificationExecutionPhase::converging &&
         execution->phase != MothershipNametagQualificationExecutionPhase::verified) ||
        !mothershipNametagQualificationExecutionRecordValid(*execution)) {
      if (failure) failure->assign("qualification cousin recovery has no durable native transport and local-work proof"_ctv);
      return false;
    }
    for (const auto& application : applications)
      if (application.protocolVersion != ProdigyNametagQualificationApplicationReceipt::cousinStageVersion ||
          application.cousinStage != ProdigyNametagQualificationCousinStage::final ||
          application.joinedWitnessDigest != execution->cousinLocalWorkReceipt.joinedWitnessDigest) {
        if (failure) failure->assign("qualification post-restore observations do not match the pre-restore write"_ctv);
        return false;
      }
    auto requested = intent, stored = execution->intent; String a = {}, b = {};
    if (!BitseryEngine::serialize(a, requested) || !BitseryEngine::serialize(b, stored) || a != b) return false;
    auto copy = *execution; String encoded = {};
    if (!BitseryEngine::serialize(encoded, copy)) return false;
    applicationBytes.append(encoded);
  }
  if (intent.direction == MothershipNametagQualificationDirection::observation &&
      (intent.row == MothershipNametagQualificationRow::permissionRevokeReinstall ||
       intent.row == MothershipNametagQualificationRow::cousinRouteSessionReconnect)) {
    String priorDigest = {};
    if (!priorInjectionReceipt || !priorCousinExecution ||
        !mothershipNametagQualificationReceiptDigest(*priorInjectionReceipt, priorDigest) ||
        priorDigest != intent.priorInjectionReceiptDigest || priorInjectionReceipt->runUUID != intent.priorInjectionRunUUID ||
        priorInjectionReceipt->row != intent.row || priorInjectionReceipt->direction != MothershipNametagQualificationDirection::injection ||
        priorInjectionReceipt->allMastersOperationUUID != intent.allMastersOperationUUID ||
        priorInjectionReceipt->observedAtMilliseconds > intent.startedAtMilliseconds ||
        priorCousinExecution->protocolVersion != MothershipNametagQualificationExecutionRecord::cousinTransportVersion ||
        priorCousinExecution->phase != MothershipNametagQualificationExecutionPhase::verified ||
        !mothershipNametagQualificationExecutionRecordValid(*priorCousinExecution) ||
        priorCousinExecution->intent.runUUID != priorInjectionReceipt->runUUID ||
        priorCousinExecution->intent.executionGeneration != priorInjectionReceipt->executionGeneration ||
        priorCousinExecution->intent.row != intent.row || priorCousinExecution->intent.allMastersOperationUUID != intent.allMastersOperationUUID ||
        priorCousinExecution->intent.probeTargets.size() != intent.probeTargets.size()) return false;
    for (size_t site = 0; site < applications.size(); ++site) {
      const auto& priorTarget = priorCousinExecution->intent.probeTargets[site];
      if (priorTarget.clusterUUID != intent.probeTargets[site].clusterUUID ||
          priorTarget.probeDeploymentID != intent.probeTargets[site].probeDeploymentID ||
          applications[site].protocolVersion != ProdigyNametagQualificationApplicationReceipt::cousinStageVersion ||
          applications[site].cousinStage != ProdigyNametagQualificationCousinStage::final ||
          applications[site].joinedWitnessDigest != priorCousinExecution->cousinLocalWorkReceipt.joinedWitnessDigest) return false;
    }
    // The injection receipt was constructed immediately before the durable
    // converging -> verified transition. Reconstruct its committed digest so
    // a different native execution cannot be joined merely by matching IDs.
    String priorBytes = {}, priorApplicationDigest = {}, priorPrefix = {};
    for (const auto& application : priorInjectionReceipt->applicationReceipts) {
      auto item = application; String encoded = {};
      if (!BitseryEngine::serialize(encoded, item)) return false;
      priorBytes.append(encoded);
    }
    auto copy = *priorCousinExecution; copy.phase = MothershipNametagQualificationExecutionPhase::converging;
    String encoded = {};
    if (!BitseryEngine::serialize(encoded, copy)) return false;
    priorBytes.append(encoded);
    if (!prodigyComputeSHA256Hex(priorBytes, priorApplicationDigest)) return false;
    priorPrefix.assign("nametag-qualification-v4:"_ctv); priorPrefix.append(intent.rowID);
    priorPrefix.append(":"_ctv); priorPrefix.append(priorApplicationDigest); priorPrefix.append(":"_ctv);
    if (priorInjectionReceipt->canonicalConvergenceWitness.size() <= priorPrefix.size() ||
        std::memcmp(priorInjectionReceipt->canonicalConvergenceWitness.data(), priorPrefix.data(), priorPrefix.size()) != 0) return false;
    copy.phase = MothershipNametagQualificationExecutionPhase::verified; encoded.clear();
    if (!BitseryEngine::serialize(encoded, copy)) return false;
    applicationBytes.append(priorDigest); applicationBytes.append(encoded);
  }
  if (intent.row == MothershipNametagQualificationRow::mothershipRestartResume) {
    const bool injection = intent.direction == MothershipNametagQualificationDirection::injection;
    const auto *proof = injection ? execution : priorCousinExecution;
    if (!proof || proof->protocolVersion != MothershipNametagQualificationExecutionRecord::restartVersion ||
        !mothershipNametagQualificationExecutionRecordValid(*proof) || !proof->restartAfter.pid ||
        (injection ? (proof->phase != MothershipNametagQualificationExecutionPhase::converging &&
                      proof->phase != MothershipNametagQualificationExecutionPhase::verified) :
                     proof->phase != MothershipNametagQualificationExecutionPhase::verified) ||
        proof->intent.runUUID != intent.runUUID || proof->intent.row != intent.row ||
        proof->intent.allMastersOperationUUID != intent.allMastersOperationUUID ||
        proof->intent.probeTargets.size() != intent.probeTargets.size()) return false;
    for (size_t i = 0; i < applications.size(); ++i) {
      if (proof->intent.probeTargets[i].clusterUUID != intent.probeTargets[i].clusterUUID ||
          proof->intent.probeTargets[i].probeDeploymentID != intent.probeTargets[i].probeDeploymentID ||
          applications[i].protocolVersion != ProdigyNametagQualificationApplicationReceipt::restartStageVersion ||
          applications[i].restartStage != ProdigyNametagQualificationRestartStage::afterRestart ||
          applications[i].joinedWitnessDigest != proof->restartLocalWorkReceipt.joinedWitnessDigest) return false;
    }
    if (!injection) {
      String digest = {}, priorBytes = {}, priorDigest = {}, prefix = {};
      if (!priorInjectionReceipt || !mothershipNametagQualificationReceiptDigest(*priorInjectionReceipt, digest) ||
          digest != intent.priorInjectionReceiptDigest || priorInjectionReceipt->runUUID != intent.priorInjectionRunUUID ||
          priorInjectionReceipt->executionGeneration != proof->intent.executionGeneration ||
          priorInjectionReceipt->direction != MothershipNametagQualificationDirection::injection ||
          priorInjectionReceipt->row != intent.row || priorInjectionReceipt->allMastersOperationUUID != intent.allMastersOperationUUID ||
          priorInjectionReceipt->observedAtMilliseconds > intent.startedAtMilliseconds) return false;
      for (const auto& r : priorInjectionReceipt->applicationReceipts) { auto copy = r; String encoded = {};
        if (!BitseryEngine::serialize(encoded, copy)) return false; priorBytes.append(encoded); }
      auto prior = *proof; prior.phase = MothershipNametagQualificationExecutionPhase::converging; String encoded = {};
      if (!BitseryEngine::serialize(encoded, prior)) return false; priorBytes.append(encoded);
      if (!prodigyComputeSHA256Hex(priorBytes, priorDigest)) return false;
      prefix.assign("nametag-qualification-v4:"_ctv); prefix.append(intent.rowID); prefix.append(":"_ctv);
      prefix.append(priorDigest); prefix.append(":"_ctv);
      if (priorInjectionReceipt->canonicalConvergenceWitness.size() <= prefix.size() ||
          std::memcmp(priorInjectionReceipt->canonicalConvergenceWitness.data(), prefix.data(), prefix.size()) != 0) return false;
      applicationBytes.append(digest);
    }
    auto copy = *proof; String encoded = {};
    if (!BitseryEngine::serialize(encoded, copy)) return false;
    applicationBytes.append(encoded);
  }
  if (applicationBytes.empty() || !prodigyComputeSHA256Hex(applicationBytes, applicationDigest, failure)) return false;

  receipt.runUUID = intent.runUUID; receipt.row = intent.row; receipt.direction = intent.direction;
  receipt.executionGeneration = intent.executionGeneration; receipt.rowID = intent.rowID; receipt.descriptor = intent.descriptor;
  receipt.allMastersOperationUUID = intent.allMastersOperationUUID; receipt.applicationReceipts = applications;
  receipt.startedAtMilliseconds = intent.startedAtMilliseconds; receipt.deadlineAtMilliseconds = intent.deadlineAtMilliseconds;
  receipt.convergenceDeadlineAtMilliseconds = intent.convergenceDeadlineAtMilliseconds;
  receipt.observedAtMilliseconds = observedAtMilliseconds; receipt.witnessedResult = intent.descriptor.expectedWitness;
  receipt.canonicalConvergenceWitness.assign("nametag-qualification-v4:"_ctv);
  receipt.canonicalConvergenceWitness.append(intent.rowID); receipt.canonicalConvergenceWitness.append(":"_ctv);
  receipt.canonicalConvergenceWitness.append(applicationDigest); receipt.canonicalConvergenceWitness.append(":"_ctv);
  receipt.canonicalConvergenceWitness.append(canonicalTopologyEvidence);
  if (!prodigyComputeSHA256Hex(receipt.canonicalConvergenceWitness, receipt.witnessDigest, failure) ||
      !mothershipNametagQualificationReceiptValid(receipt))
  {
    if (failure && failure->empty()) failure->assign("qualification receipt is not a complete typed row witness"_ctv);
    receipt = {};
    return false;
  }
  if (failure) failure->clear();
  return true;
}
