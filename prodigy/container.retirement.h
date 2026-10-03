#pragma once

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

  bool sameIdentity(const ProdigyContainerRetirementIntent& other) const
  {
    return containerUUID == other.containerUUID && deploymentID == other.deploymentID &&
           applicationID == other.applicationID && machineUUID == other.machineUUID &&
           topologyOperationID == other.topologyOperationID &&
           sourceEpoch == other.sourceEpoch && targetEpoch == other.targetEpoch &&
           intentGeneration == other.intentGeneration;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyContainerRetirementIntent& intent)
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

class ProdigyContainerRetirementJournal {
public:
  constexpr static uint8_t currentVersion = 1;

  uint8_t version = currentVersion;
  Vector<ProdigyContainerRetirementIntent> intents;
};

template <typename S>
static void serialize(S&& serializer, ProdigyContainerRetirementJournal& journal)
{
  serializer.value1b(journal.version);
  serializer.container(journal.intents, prodigyContainerRetirementJournalMaximumEntries,
                       [](S& serializer, ProdigyContainerRetirementIntent& intent) {
                         serializer.object(intent);
                       });
}

static bool prodigyContainerRetirementIntentValid(const ProdigyContainerRetirementIntent& intent)
{
  if (intent.containerUUID == 0 || intent.deploymentID == 0 || intent.applicationID == 0 ||
      intent.machineUUID == 0 || intent.topologyOperationID == 0 ||
      intent.sourceEpoch == 0 || intent.targetEpoch == 0 ||
      intent.sourceEpoch == intent.targetEpoch || intent.intentGeneration == 0 ||
      intent.intentGeneration == UINT64_MAX ||
      uint16_t(intent.deploymentID >> 48) != intent.applicationID ||
      intent.bootstrap.size() > prodigyContainerRetirementJournalMaximumBootstrapBytes)
  {
    return false;
  }
  if (intent.killAcked)
  {
    return intent.bootstrap.empty();
  }

  NeuronContainerBootstrap bootstrap = {};
  if (intent.bootstrap.empty() ||
      BitseryEngine::deserializeSafe(intent.bootstrap, bootstrap) == false ||
      bootstrap.plan.uuid != intent.containerUUID ||
      bootstrap.plan.config.deploymentID() != intent.deploymentID ||
      bootstrap.plan.config.applicationID != intent.applicationID ||
      bootstrap.plan.isStateful == false ||
      bootstrap.plan.config.type != ApplicationType::stateful ||
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

static bool prodigyValidateContainerRetirementJournal(const ProdigyContainerRetirementJournal& journal)
{
  if (journal.version != ProdigyContainerRetirementJournal::currentVersion ||
      journal.intents.empty() ||
      journal.intents.size() > prodigyContainerRetirementJournalMaximumEntries)
  {
    return false;
  }

  uint128_t previousUUID = 0;
  uint64_t totalBootstrapBytes = 0;
  for (const ProdigyContainerRetirementIntent& intent : journal.intents)
  {
    if (prodigyContainerRetirementIntentValid(intent) == false ||
        (previousUUID != 0 && intent.containerUUID <= previousUUID) ||
        intent.bootstrap.size() > prodigyContainerRetirementJournalMaximumPayloadBytes - totalBootstrapBytes)
    {
      return false;
    }
    totalBootstrapBytes += intent.bootstrap.size();
    previousUUID = intent.containerUUID;
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
