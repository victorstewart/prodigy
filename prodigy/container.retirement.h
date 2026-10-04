#pragma once

#include <prodigy/bundle.artifact.h>

// Included after prodigy/types.h.  This is a durable authority-side intent
// record, not a container-runtime replication format: existing runtime upserts
// have no generation fence and cannot safely express deletion.
// Zero is reserved by the machine-retirement carrier.  One cannot be an
// ApplicationConfig::deploymentID because its high application-ID bits are
// zero and application ID zero is rejected by Brain reservation.
constexpr static uint64_t prodigyContainerRetirementJournalExecutionID = 1;
constexpr static uint64_t prodigyContainerRetirementJournalVersionID = 0x4352544a0001ULL; // "CRTJ" v1
constexpr static uint32_t prodigyContainerRetirementJournalMaximumEntries = 4096;
constexpr static uint64_t prodigyContainerRetirementJournalMaximumBootstrapBytes = 1024ULL * 1024ULL;
// Includes the serialized framing and identity fields, not merely bootstraps.
constexpr static uint64_t prodigyContainerRetirementJournalMaximumPayloadBytes = 16ULL * 1024ULL * 1024ULL;

// Version two extends the established authority journal rather than adding a
// second destruction-receipt owner.  Version one remains a byte-for-byte
// compatible stateful-topology record so a mixed fleet can continue reading
// its existing authority until the v2 capability gate has completed.
enum class ProdigyContainerRetirementKind : uint8_t {
  statefulTopology = 1,
  statelessPairedMigration = 2
};

class ProdigyContainerRetirementIntent {
public:
  uint128_t containerUUID = 0;
  uint64_t deploymentID = 0;
  uint16_t applicationID = 0;
  uint128_t machineUUID = 0;
  uint64_t topologyOperationID = 0;
  uint32_t sourceEpoch = 0;
  uint32_t targetEpoch = 0;
  uint64_t intentGeneration = 0;
  // Captured serialized NeuronContainerBootstrap while the source can still
  // survive a Brain restart.  A terminal ACK intentionally clears it.
  String bootstrap;
  bool killAcked = false;

  // V2 only.  These bind a source-cluster stateless cohort to the durable
  // independent-cluster operation and its already-admitted destination.
  ProdigyContainerRetirementKind kind = ProdigyContainerRetirementKind::statefulTopology;
  uint128_t pairedOperationID = 0;
  uint128_t pairedSourceClusterUUID = 0;
  uint128_t pairedTargetClusterUUID = 0;
  uint64_t pairedTargetDeploymentID = 0;

  bool sameIdentity(const ProdigyContainerRetirementIntent& other) const
  {
    return containerUUID == other.containerUUID && deploymentID == other.deploymentID &&
           applicationID == other.applicationID && machineUUID == other.machineUUID &&
           topologyOperationID == other.topologyOperationID &&
           sourceEpoch == other.sourceEpoch && targetEpoch == other.targetEpoch &&
           intentGeneration == other.intentGeneration && kind == other.kind &&
           pairedOperationID == other.pairedOperationID &&
           pairedSourceClusterUUID == other.pairedSourceClusterUUID &&
           pairedTargetClusterUUID == other.pairedTargetClusterUUID &&
           pairedTargetDeploymentID == other.pairedTargetDeploymentID;
  }
};

// A paired source fence is operation authority, not a second destruction
// receipt.  It binds the complete source deployment cohort without retaining
// plan bytes or bootstrap credentials in the journal's public descriptor.
class ProdigyPairedSourceRetirementCohortMember {
public:
  uint128_t containerUUID = 0;
  uint128_t machineUUID = 0;
  uint64_t intentGeneration = 0;

  bool sameIdentity(const ProdigyPairedSourceRetirementCohortMember& other) const
  {
    return containerUUID == other.containerUUID && machineUUID == other.machineUUID &&
           intentGeneration == other.intentGeneration;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPairedSourceRetirementCohortMember& member)
{
  serializer.value16b(member.containerUUID);
  serializer.value16b(member.machineUUID);
  serializer.value8b(member.intentGeneration);
}

class ProdigyPairedSourceRetirementFence {
public:
  uint128_t operationID = 0;
  uint128_t sourceClusterUUID = 0;
  uint128_t targetClusterUUID = 0;
  uint64_t sourceDeploymentID = 0;
  uint64_t targetDeploymentID = 0;
  String sourceNormalizedPlanSHA256;
  String sourceBlobSHA256;
  uint64_t sourceBlobBytes = 0;
  Vector<ProdigyPairedSourceRetirementCohortMember> cohort;

  bool sameIdentity(const ProdigyPairedSourceRetirementFence& other) const
  {
    if (operationID != other.operationID || sourceClusterUUID != other.sourceClusterUUID ||
        targetClusterUUID != other.targetClusterUUID || sourceDeploymentID != other.sourceDeploymentID ||
        targetDeploymentID != other.targetDeploymentID ||
        sourceNormalizedPlanSHA256.equals(other.sourceNormalizedPlanSHA256) == false ||
        sourceBlobSHA256.equals(other.sourceBlobSHA256) == false || sourceBlobBytes != other.sourceBlobBytes ||
        cohort.size() != other.cohort.size()) return false;
    for (uint32_t index = 0; index < cohort.size(); ++index)
      if (cohort[index].sameIdentity(other.cohort[index]) == false) return false;
    return true;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPairedSourceRetirementFence& fence)
{
  serializer.value16b(fence.operationID);
  serializer.value16b(fence.sourceClusterUUID);
  serializer.value16b(fence.targetClusterUUID);
  serializer.value8b(fence.sourceDeploymentID);
  serializer.value8b(fence.targetDeploymentID);
  serializer.text1b(fence.sourceNormalizedPlanSHA256, 64);
  serializer.text1b(fence.sourceBlobSHA256, 64);
  serializer.value8b(fence.sourceBlobBytes);
  serializer.container(fence.cohort, prodigyContainerRetirementJournalMaximumEntries,
                       [](S& serializer, ProdigyPairedSourceRetirementCohortMember& member) { serializer.object(member); });
}

// Cross-cluster source-retirement authority is intentionally separate from a
// target admission. The request carries only immutable source identity and a
// currently-observed source authority tuple; bootstrap material stays in the
// existing private retirement sidecar after the source seals its journal.
class ProdigyPairedSourceRetirementRequest {
public:
  uint8_t version = 1;
  uint128_t operationID = 0;
  uint128_t sourceClusterUUID = 0;
  uint128_t targetClusterUUID = 0;
  uint64_t sourceDeploymentID = 0;
  uint64_t targetDeploymentID = 0;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  String sourceNormalizedPlanSHA256;
  String sourceBlobSHA256;
  uint64_t sourceBlobBytes = 0;
};

template <typename S>
static void serialize(S&& serializer, ProdigyPairedSourceRetirementRequest& request)
{
  serializer.value1b(request.version);
  serializer.value16b(request.operationID);
  serializer.value16b(request.sourceClusterUUID);
  serializer.value16b(request.targetClusterUUID);
  serializer.value8b(request.sourceDeploymentID);
  serializer.value8b(request.targetDeploymentID);
  serializer.value8b(request.expectedAuthorityGeneration);
  serializer.value16b(request.expectedMasterUUID);
  serializer.value8b(request.expectedMasterBootNs);
  serializer.text1b(request.sourceNormalizedPlanSHA256, 64);
  serializer.text1b(request.sourceBlobSHA256, 64);
  serializer.value8b(request.sourceBlobBytes);
}

static inline bool prodigyPairedSourceRetirementRequestValid(
    const ProdigyPairedSourceRetirementRequest& request)
{
  return request.version == 1 && request.operationID != 0 && request.sourceClusterUUID != 0 &&
         request.targetClusterUUID != 0 && request.sourceClusterUUID != request.targetClusterUUID &&
         request.sourceDeploymentID != 0 && request.targetDeploymentID != 0 &&
         request.expectedAuthorityGeneration != 0 && request.expectedMasterUUID != 0 &&
         request.expectedMasterBootNs > 0 && request.sourceNormalizedPlanSHA256.size() == 64 &&
         request.sourceBlobSHA256.size() == 64 && request.sourceBlobBytes != 0 &&
         prodigyIsSHA256HexDigest(request.sourceNormalizedPlanSHA256) &&
         prodigyIsSHA256HexDigest(request.sourceBlobSHA256);
}

class PairedSourceRetirementReceipt {
public:
  uint8_t version = 1;
  bool supported = true;
  bool peersCapable = false;
  bool sealed = false;
  bool terminal = false;
  String failure;
  // A serialized v3 fence remains secret-free and lets Mothership compare an
  // exact retry without obtaining bootstrap material.
  String sealedFence;
  uint64_t currentAuthorityGeneration = 0;
  uint128_t currentMasterUUID = 0;
  int64_t currentMasterBootNs = 0;
};

template <typename S>
static void serialize(S&& serializer, PairedSourceRetirementReceipt& receipt)
{
  serializer.value1b(receipt.version);
  serializer.value1b(receipt.supported);
  serializer.value1b(receipt.peersCapable);
  serializer.value1b(receipt.sealed);
  serializer.value1b(receipt.terminal);
  serializer.text1b(receipt.failure, 4096);
  serializer.text1b(receipt.sealedFence, 1024 * 1024);
  serializer.value8b(receipt.currentAuthorityGeneration);
  serializer.value16b(receipt.currentMasterUUID);
  serializer.value8b(receipt.currentMasterBootNs);
}

template <typename S>
static void prodigySerializeContainerRetirementIntentV1(S&& serializer, ProdigyContainerRetirementIntent& intent)
{
  serializer.value16b(intent.containerUUID);
  serializer.value8b(intent.deploymentID);
  serializer.value2b(intent.applicationID);
  serializer.value16b(intent.machineUUID);
  serializer.value8b(intent.topologyOperationID);
  serializer.value4b(intent.sourceEpoch);
  serializer.value4b(intent.targetEpoch);
  serializer.value8b(intent.intentGeneration);
  serializer.text1b(intent.bootstrap, prodigyContainerRetirementJournalMaximumBootstrapBytes);
  serializer.value1b(intent.killAcked);
}

template <typename S>
static void prodigySerializeContainerRetirementIntentV2(S&& serializer, ProdigyContainerRetirementIntent& intent)
{
  prodigySerializeContainerRetirementIntentV1(serializer, intent);
  serializer.value1b(intent.kind);
  serializer.value16b(intent.pairedOperationID);
  serializer.value16b(intent.pairedSourceClusterUUID);
  serializer.value16b(intent.pairedTargetClusterUUID);
  serializer.value8b(intent.pairedTargetDeploymentID);
}

template <typename S>
static void serialize(S&& serializer, ProdigyContainerRetirementIntent& intent)
{
  // Direct intent serialization is retained only for source compatibility.
  // Journal framing selects the durable version explicitly.
  prodigySerializeContainerRetirementIntentV1(serializer, intent);
}

class ProdigyContainerRetirementJournal {
public:
  constexpr static uint8_t legacyVersion = 1;
  constexpr static uint8_t pairedIntentVersion = 2;
  constexpr static uint8_t currentVersion = 3;

  // Existing stateful callers value-initialize this journal.  They must keep
  // emitting the legacy framing until a dedicated v2 stateless admission has
  // established peer capability and deliberately promotes the record.
  uint8_t version = legacyVersion;
  Vector<ProdigyContainerRetirementIntent> intents;
  Vector<ProdigyPairedSourceRetirementFence> pairedSourceFences;
};

template <typename S>
static void serialize(S&& serializer, ProdigyContainerRetirementJournal& journal)
{
  serializer.value1b(journal.version);
  if (journal.version == ProdigyContainerRetirementJournal::legacyVersion)
  {
    serializer.container(journal.intents, prodigyContainerRetirementJournalMaximumEntries,
                         [](S& serializer, ProdigyContainerRetirementIntent& intent) {
                           prodigySerializeContainerRetirementIntentV1(serializer, intent);
                         });
  }
  else if (journal.version == ProdigyContainerRetirementJournal::pairedIntentVersion)
  {
    serializer.container(journal.intents, prodigyContainerRetirementJournalMaximumEntries,
                         [](S& serializer, ProdigyContainerRetirementIntent& intent) {
                           prodigySerializeContainerRetirementIntentV2(serializer, intent);
                         });
  }
  else if (journal.version == ProdigyContainerRetirementJournal::currentVersion)
  {
    serializer.container(journal.intents, prodigyContainerRetirementJournalMaximumEntries,
                         [](S& serializer, ProdigyContainerRetirementIntent& intent) {
                           prodigySerializeContainerRetirementIntentV2(serializer, intent);
                         });
    serializer.container(journal.pairedSourceFences, prodigyContainerRetirementJournalMaximumEntries,
                         [](S& serializer, ProdigyPairedSourceRetirementFence& fence) { serializer.object(fence); });
  }
}

static bool prodigyContainerRetirementJournalVersionSupported(uint8_t version, uint32_t readerVersion)
{
  return version >= ProdigyContainerRetirementJournal::legacyVersion &&
         version <= ProdigyContainerRetirementJournal::currentVersion &&
         readerVersion >= version;
}

static bool prodigyContainerRetirementIntentValid(const ProdigyContainerRetirementIntent& intent)
{
  if (intent.containerUUID == 0 || intent.deploymentID == 0 || intent.applicationID == 0 ||
      intent.machineUUID == 0 || intent.intentGeneration == 0 ||
      intent.intentGeneration == UINT64_MAX ||
      uint16_t(intent.deploymentID >> 48) != intent.applicationID ||
      intent.bootstrap.size() > prodigyContainerRetirementJournalMaximumBootstrapBytes)
  {
    return false;
  }
  const bool statefulTopology = intent.kind == ProdigyContainerRetirementKind::statefulTopology;
  const bool statelessPaired = intent.kind == ProdigyContainerRetirementKind::statelessPairedMigration;
  if (!statefulTopology && !statelessPaired) return false;
  if (statefulTopology &&
      (intent.topologyOperationID == 0 || intent.sourceEpoch == 0 || intent.targetEpoch == 0 ||
       intent.sourceEpoch == intent.targetEpoch || intent.pairedOperationID != 0 ||
       intent.pairedSourceClusterUUID != 0 || intent.pairedTargetClusterUUID != 0 ||
       intent.pairedTargetDeploymentID != 0)) return false;
  if (statelessPaired &&
      (intent.topologyOperationID != 0 || intent.sourceEpoch != 0 || intent.targetEpoch != 0 ||
       intent.pairedOperationID == 0 || intent.pairedSourceClusterUUID == 0 ||
       intent.pairedTargetClusterUUID == 0 || intent.pairedSourceClusterUUID == intent.pairedTargetClusterUUID ||
       intent.pairedTargetDeploymentID == 0)) return false;
  if (intent.killAcked) return intent.bootstrap.empty();

  NeuronContainerBootstrap bootstrap = {};
  if (intent.bootstrap.empty() ||
      BitseryEngine::deserializeSafe(intent.bootstrap, bootstrap) == false ||
      bootstrap.plan.uuid != intent.containerUUID ||
      bootstrap.plan.config.deploymentID() != intent.deploymentID ||
      bootstrap.plan.config.applicationID != intent.applicationID ||
      bootstrap.plan.isStateful != statefulTopology ||
      bootstrap.plan.config.type != (statefulTopology ? ApplicationType::stateful : ApplicationType::stateless) ||
      bootstrap.plan.restartOnFailure)
  {
    return false;
  }
  // deserializeSafe requires complete input consumption. ContainerPlan owns
  // unordered routing maps, so re-encoding a valid decoded plan can produce
  // a different iteration order. Keep the captured bytes immutable in the
  // journal merge; byte-for-byte re-encoding is not a validity requirement.
  return true;
}

static bool prodigyPairedSourceRetirementFenceValid(const ProdigyPairedSourceRetirementFence& fence)
{
  if (fence.operationID == 0 || fence.sourceClusterUUID == 0 || fence.targetClusterUUID == 0 ||
      fence.sourceClusterUUID == fence.targetClusterUUID || fence.sourceDeploymentID == 0 ||
      fence.targetDeploymentID == 0 || fence.sourceNormalizedPlanSHA256.size() != 64 ||
      fence.sourceBlobSHA256.size() != 64 || fence.sourceBlobBytes == 0 || fence.cohort.empty() ||
      fence.cohort.size() > prodigyContainerRetirementJournalMaximumEntries ||
      prodigyIsSHA256HexDigest(fence.sourceNormalizedPlanSHA256) == false ||
      prodigyIsSHA256HexDigest(fence.sourceBlobSHA256) == false)
  {
    return false;
  }
  uint128_t previousUUID = 0;
  for (const auto& member : fence.cohort)
  {
    if (member.containerUUID == 0 || member.machineUUID == 0 || member.intentGeneration == 0 ||
        member.intentGeneration == UINT64_MAX || (previousUUID != 0 && member.containerUUID <= previousUUID))
      return false;
    previousUUID = member.containerUUID;
  }
  return true;
}

static bool prodigyValidateContainerRetirementJournal(const ProdigyContainerRetirementJournal& journal);
static const ProdigyContainerRetirementIntent *prodigyFindContainerRetirementIntentInValidatedJournal(
    const ProdigyContainerRetirementJournal& journal, uint128_t containerUUID);

// Call only after journal validation.  Fences are sorted by operation ID;
// source-deployment lookup is a bounded linear scan because deployment IDs
// deliberately have no ordering relationship to random operation IDs.
static const ProdigyPairedSourceRetirementFence *prodigyFindPairedSourceRetirementFenceByOperationInValidatedJournal(
    const ProdigyContainerRetirementJournal& journal, uint128_t operationID)
{
  if (operationID == 0) return nullptr;
  uint32_t low = 0, high = uint32_t(journal.pairedSourceFences.size());
  while (low < high)
  {
    const uint32_t middle = low + (high - low) / 2;
    if (journal.pairedSourceFences[middle].operationID < operationID) low = middle + 1;
    else high = middle;
  }
  return low < journal.pairedSourceFences.size() && journal.pairedSourceFences[low].operationID == operationID
             ? &journal.pairedSourceFences[low] : nullptr;
}

static const ProdigyPairedSourceRetirementFence *prodigyFindPairedSourceRetirementFenceByDeploymentInValidatedJournal(
    const ProdigyContainerRetirementJournal& journal, uint64_t sourceDeploymentID)
{
  if (sourceDeploymentID == 0) return nullptr;
  for (const auto& fence : journal.pairedSourceFences)
    if (fence.sourceDeploymentID == sourceDeploymentID) return &fence;
  return nullptr;
}

static const ProdigyPairedSourceRetirementFence *prodigyFindPairedSourceRetirementFenceByOperation(
    const ProdigyContainerRetirementJournal& journal, uint128_t operationID)
{
  return prodigyValidateContainerRetirementJournal(journal)
             ? prodigyFindPairedSourceRetirementFenceByOperationInValidatedJournal(journal, operationID) : nullptr;
}

static const ProdigyPairedSourceRetirementFence *prodigyFindPairedSourceRetirementFenceByDeployment(
    const ProdigyContainerRetirementJournal& journal, uint64_t sourceDeploymentID)
{
  return prodigyValidateContainerRetirementJournal(journal)
             ? prodigyFindPairedSourceRetirementFenceByDeploymentInValidatedJournal(journal, sourceDeploymentID) : nullptr;
}

static bool prodigyValidateContainerRetirementJournal(const ProdigyContainerRetirementJournal& journal)
{
  if (!prodigyContainerRetirementJournalVersionSupported(
          journal.version, ProdigyContainerRetirementJournal::currentVersion) ||
      journal.intents.empty() ||
      journal.intents.size() > prodigyContainerRetirementJournalMaximumEntries)
  {
    return false;
  }

  uint128_t previousUUID = 0;
  uint64_t totalBootstrapBytes = 0;
  uint32_t pairedIntentCount = 0;
  for (const ProdigyContainerRetirementIntent& intent : journal.intents)
  {
    if ((journal.version == ProdigyContainerRetirementJournal::legacyVersion &&
         (intent.kind != ProdigyContainerRetirementKind::statefulTopology || intent.pairedOperationID != 0 ||
          intent.pairedSourceClusterUUID != 0 || intent.pairedTargetClusterUUID != 0 ||
          intent.pairedTargetDeploymentID != 0)) ||
        prodigyContainerRetirementIntentValid(intent) == false ||
        (previousUUID != 0 && intent.containerUUID <= previousUUID) ||
        intent.bootstrap.size() > prodigyContainerRetirementJournalMaximumPayloadBytes - totalBootstrapBytes)
    {
      return false;
    }
    totalBootstrapBytes += intent.bootstrap.size();
    previousUUID = intent.containerUUID;
    pairedIntentCount += intent.kind == ProdigyContainerRetirementKind::statelessPairedMigration;
  }
  if (journal.version != ProdigyContainerRetirementJournal::currentVersion)
    return journal.pairedSourceFences.empty();
  if (journal.pairedSourceFences.size() > prodigyContainerRetirementJournalMaximumEntries ||
      (pairedIntentCount == 0 && journal.pairedSourceFences.empty() == false) ||
      (pairedIntentCount != 0 && journal.pairedSourceFences.empty())) return false;
  uint128_t previousOperationID = 0;
  uint32_t cohortCount = 0;
  bytell_hash_set<uint64_t> sourceDeploymentIDs = {};
  for (const auto& fence : journal.pairedSourceFences)
  {
    if (!prodigyPairedSourceRetirementFenceValid(fence) ||
        (previousOperationID != 0 && fence.operationID <= previousOperationID) ||
        sourceDeploymentIDs.insert(fence.sourceDeploymentID).second == false ||
        fence.cohort.size() > prodigyContainerRetirementJournalMaximumEntries - cohortCount) return false;
    for (const auto& member : fence.cohort)
    {
      const auto *intent = prodigyFindContainerRetirementIntentInValidatedJournal(journal, member.containerUUID);
      if (intent == nullptr || intent->kind != ProdigyContainerRetirementKind::statelessPairedMigration ||
          intent->machineUUID != member.machineUUID || intent->intentGeneration != member.intentGeneration ||
          intent->deploymentID != fence.sourceDeploymentID || intent->pairedOperationID != fence.operationID ||
          intent->pairedSourceClusterUUID != fence.sourceClusterUUID ||
          intent->pairedTargetClusterUUID != fence.targetClusterUUID ||
          intent->pairedTargetDeploymentID != fence.targetDeploymentID) return false;
    }
    cohortCount += uint32_t(fence.cohort.size());
    previousOperationID = fence.operationID;
  }
  if (cohortCount != pairedIntentCount) return false;
  for (const auto& intent : journal.intents)
  {
    if (intent.kind != ProdigyContainerRetirementKind::statelessPairedMigration) continue;
    const auto *fence = prodigyFindPairedSourceRetirementFenceByOperationInValidatedJournal(journal, intent.pairedOperationID);
    if (fence == nullptr || fence->sourceDeploymentID != intent.deploymentID) return false;
  }
  return true;
}

// This performs no validation or bootstrap decoding. Call it only after the
// journal entered through prodigyParse..., prodigyMerge..., or an equivalent
// one-time validation boundary.
static const ProdigyContainerRetirementIntent *prodigyFindContainerRetirementIntentInValidatedJournal(
    const ProdigyContainerRetirementJournal& journal, uint128_t containerUUID)
{
  if (containerUUID == 0)
  {
    return nullptr;
  }
  uint32_t low = 0;
  uint32_t high = uint32_t(journal.intents.size());
  while (low < high)
  {
    const uint32_t middle = low + (high - low) / 2;
    const uint128_t candidate = journal.intents[middle].containerUUID;
    if (candidate < containerUUID)
    {
      low = middle + 1;
    }
    else
    {
      high = middle;
    }
  }
  return low < journal.intents.size() && journal.intents[low].containerUUID == containerUUID
             ? &journal.intents[low]
             : nullptr;
}

static const ProdigyContainerRetirementIntent *prodigyFindContainerRetirementIntent(
    const ProdigyContainerRetirementJournal& journal, uint128_t containerUUID)
{
  return prodigyValidateContainerRetirementJournal(journal)
             ? prodigyFindContainerRetirementIntentInValidatedJournal(journal, containerUUID)
             : nullptr;
}

static bool prodigyContainerRetirementJournalContainsExact(
    const ProdigyContainerRetirementJournal& journal,
    const ProdigyContainerRetirementIntent& expected)
{
  const ProdigyContainerRetirementIntent *actual =
      prodigyFindContainerRetirementIntent(journal, expected.containerUUID);
  return actual != nullptr && actual->sameIdentity(expected) &&
         (expected.killAcked ? actual->killAcked :
                              (actual->killAcked == false && actual->bootstrap.equals(expected.bootstrap)));
}

// Incoming records are a complete replacement only when they retain every
// durable intent.  Acknowledgment is monotonic; its bootstrap may be cleared
// only on that transition. There is deliberately no GC path until runtime
// replication gains a generation-bound tombstone fence.
static bool prodigyMergeContainerRetirementJournal(
    const ProdigyContainerRetirementJournal& current,
    const ProdigyContainerRetirementJournal& incoming,
    ProdigyContainerRetirementJournal& merged)
{
  if (prodigyValidateContainerRetirementJournal(current) == false ||
      prodigyValidateContainerRetirementJournal(incoming) == false)
  {
    return false;
  }

  for (const ProdigyContainerRetirementIntent& oldIntent : current.intents)
  {
    const ProdigyContainerRetirementIntent *newIntent =
        prodigyFindContainerRetirementIntentInValidatedJournal(incoming, oldIntent.containerUUID);
    if (newIntent == nullptr || oldIntent.sameIdentity(*newIntent) == false ||
        (oldIntent.killAcked && newIntent->killAcked == false) ||
        // Bootstrap is immutable while unacknowledged. The one legal
        // transition is a kill ACK, which clears it to shrink the terminal
        // fence without altering the source identity.
        (oldIntent.killAcked == false && newIntent->killAcked == false &&
         oldIntent.bootstrap.equals(newIntent->bootstrap) == false))
    {
      return false;
    }
  }

  for (const auto& oldFence : current.pairedSourceFences)
  {
    const auto *newFence = prodigyFindPairedSourceRetirementFenceByOperationInValidatedJournal(
        incoming, oldFence.operationID);
    if (newFence == nullptr || oldFence.sameIdentity(*newFence) == false) return false;
  }

  merged = incoming;
  return true;
}

static bool prodigyContainerRetirementJournalCarrier(const TaskExecutionRecord& carrier)
{
  return carrier.executionID == prodigyContainerRetirementJournalExecutionID &&
         carrier.applicationID == 0 &&
         carrier.versionID == prodigyContainerRetirementJournalVersionID &&
         carrier.policy == TaskExecutionPolicy::runOnce && carrier.terminal() &&
         carrier.expiresAtMs == 0;
}

static bool prodigyParseContainerRetirementJournalCarrier(
    const TaskExecutionRecord& carrier, ProdigyContainerRetirementJournal& journal)
{
  journal = {};
  return prodigyContainerRetirementJournalCarrier(carrier) &&
         carrier.fingerprint.size() <= prodigyContainerRetirementJournalMaximumPayloadBytes &&
         BitseryEngine::deserializeSafe(carrier.fingerprint, journal) &&
         prodigyValidateContainerRetirementJournal(journal);
}

static bool prodigyWriteContainerRetirementJournalCarrier(
    TaskExecutionRecord& carrier,
    const ProdigyContainerRetirementJournal& journal,
    int64_t nowMs)
{
  if (prodigyValidateContainerRetirementJournal(journal) == false || nowMs < 0)
  {
    return false;
  }

  ProdigyContainerRetirementJournal serializable = journal;
  String fingerprint = {};
  BitseryEngine::serialize(fingerprint, serializable);
  if (fingerprint.size() > prodigyContainerRetirementJournalMaximumPayloadBytes)
  {
    return false;
  }
  ProdigyContainerRetirementJournal checked = {};
  if (BitseryEngine::deserializeSafe(fingerprint, checked) == false ||
      prodigyValidateContainerRetirementJournal(checked) == false)
  {
    return false;
  }

  carrier = {};
  carrier.executionID = prodigyContainerRetirementJournalExecutionID;
  carrier.applicationID = 0;
  carrier.versionID = prodigyContainerRetirementJournalVersionID;
  carrier.policy = TaskExecutionPolicy::runOnce;
  carrier.state = TaskExecutionState::cancelled;
  carrier.fingerprint = std::move(fingerprint);
  carrier.acceptedAtMs = nowMs;
  carrier.updatedAtMs = nowMs;
  carrier.completedAtMs = nowMs;
  carrier.expiresAtMs = 0;
  return prodigyContainerRetirementJournalCarrier(carrier) &&
         prodigyParseContainerRetirementJournalCarrier(carrier, checked);
}

static bool prodigyStoreContainerRetirementJournalCarrier(
    bytell_hash_map<uint64_t, TaskExecutionRecord>& taskExecutions,
    const ProdigyContainerRetirementJournal& journal,
    int64_t nowMs)
{
  auto existing = taskExecutions.find(prodigyContainerRetirementJournalExecutionID);
  if (existing != taskExecutions.end() &&
      prodigyContainerRetirementJournalCarrier(existing->second) == false)
  {
    return false;
  }

  if (existing != taskExecutions.end())
  {
    ProdigyContainerRetirementJournal previous = {};
    if (prodigyParseContainerRetirementJournalCarrier(existing->second, previous) == false)
    {
      return false;
    }
    ProdigyContainerRetirementJournal merged = {};
    if (prodigyMergeContainerRetirementJournal(previous, journal, merged) == false)
    {
      return false;
    }
  }

  TaskExecutionRecord carrier = {};
  if (prodigyWriteContainerRetirementJournalCarrier(carrier, journal, nowMs) == false)
  {
    return false;
  }
  taskExecutions.insert_or_assign(prodigyContainerRetirementJournalExecutionID, std::move(carrier));
  return true;
}
