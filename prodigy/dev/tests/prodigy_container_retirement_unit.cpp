#include <prodigy/types.h>
#include <prodigy/container.retirement.h>

#include <cstdio>

class TestSuite {
public:
  uint32_t failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition == false)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      ++failed;
    }
  }
};

static ProdigyContainerRetirementIntent makeIntent(uint128_t uuid, bool killAcked = false)
{
  ProdigyContainerRetirementIntent intent = {};
  intent.containerUUID = uuid;
  intent.applicationID = 7;
  intent.deploymentID = (uint64_t(intent.applicationID) << 48) | 41;
  intent.machineUUID = uuid + 1000;
  intent.topologyOperationID = 91;
  intent.sourceEpoch = 3;
  intent.targetEpoch = 4;
  intent.intentGeneration = 17;
  intent.killAcked = killAcked;
  if (!killAcked)
  {
    NeuronContainerBootstrap bootstrap = {};
    bootstrap.plan.uuid = intent.containerUUID;
    bootstrap.plan.config.applicationID = intent.applicationID;
    bootstrap.plan.config.versionID = 41;
    bootstrap.plan.config.type = ApplicationType::stateful;
    bootstrap.plan.isStateful = true;
    bootstrap.plan.restartOnFailure = false;
    BitseryEngine::serialize(intent.bootstrap, bootstrap);
  }
  return intent;
}

static ProdigyContainerRetirementJournal makeJournal(uint32_t count = 1)
{
  ProdigyContainerRetirementJournal journal = {};
  for (uint32_t index = 0; index < count; ++index)
  {
    journal.intents.push_back(makeIntent(uint128_t(index) + 1));
  }
  return journal;
}

static bool findDeterministicCollidingServiceKeys(uint64_t& first, uint64_t& second)
{
  // A fixed Hasher seed and a shared low 16-bit bucket make the two insertions
  // collide for every practical small bytell table used by this fixture.  The
  // map serializer iterates table order, so inserting this pair in reverse
  // produces a legitimate alternate wire ordering without hand-editing bytes.
  noncrypto_hasher hasher = {};
  first = 0x10001;
  const size_t bucket = hasher(first) & 0xffff;
  for (second = first + 1; second < first + 200000; ++second)
  {
    if ((hasher(second) & 0xffff) == bucket)
    {
      return true;
    }
  }
  return false;
}

static NeuronContainerBootstrap makePopulatedBootstrap(
    uint128_t containerUUID, uint64_t firstService, uint64_t secondService, bool reverseInsertion)
{
  NeuronContainerBootstrap bootstrap = {};
  ContainerPlan& plan = bootstrap.plan;
  plan.uuid = containerUUID;
  plan.config.applicationID = 7;
  plan.config.versionID = 41;
  plan.config.type = ApplicationType::stateful;
  plan.isStateful = true;
  plan.restartOnFailure = false;
  plan.subscriptions.reserve(4);
  plan.advertisements.reserve(4);

  Subscription firstSubscription = {};
  firstSubscription.service = firstService;
  firstSubscription.startAt = ContainerState::scheduled;
  firstSubscription.stopAt = ContainerState::destroying;
  firstSubscription.nature = SubscriptionNature::all;
  Subscription secondSubscription = firstSubscription;
  secondSubscription.service = secondService;

  Advertisement firstAdvertisement = {};
  firstAdvertisement.service = firstService;
  firstAdvertisement.startAt = ContainerState::scheduled;
  firstAdvertisement.stopAt = ContainerState::destroying;
  firstAdvertisement.port = 4101;
  Advertisement secondAdvertisement = firstAdvertisement;
  secondAdvertisement.service = secondService;
  secondAdvertisement.port = 4102;

  if (reverseInsertion)
  {
    plan.subscriptions.insert_or_assign(secondService, secondSubscription);
    plan.subscriptions.insert_or_assign(firstService, firstSubscription);
    plan.advertisements.insert_or_assign(secondService, secondAdvertisement);
    plan.advertisements.insert_or_assign(firstService, firstAdvertisement);
  }
  else
  {
    plan.subscriptions.insert_or_assign(firstService, firstSubscription);
    plan.subscriptions.insert_or_assign(secondService, secondSubscription);
    plan.advertisements.insert_or_assign(firstService, firstAdvertisement);
    plan.advertisements.insert_or_assign(secondService, secondAdvertisement);
  }
  return bootstrap;
}

static void testCarrierRoundTripAndExactLookup(TestSuite& suite)
{
  ProdigyContainerRetirementJournal journal = makeJournal(2);
  TaskExecutionRecord carrier = {};
  suite.expect(prodigyWriteContainerRetirementJournalCarrier(carrier, journal, 100),
               "container_retirement_carrier_write");

  ProdigyContainerRetirementJournal decoded = {};
  suite.expect(prodigyParseContainerRetirementJournalCarrier(carrier, decoded) &&
                   decoded.intents.size() == 2 &&
                   prodigyContainerRetirementJournalContainsExact(decoded, journal.intents[1]),
               "container_retirement_carrier_roundtrip_exact_lookup");
}

static void testMalformedTrailingAndVersionRejected(TestSuite& suite)
{
  ProdigyContainerRetirementJournal journal = makeJournal();
  TaskExecutionRecord carrier = {};
  suite.expect(prodigyWriteContainerRetirementJournalCarrier(carrier, journal, 1),
               "container_retirement_malformed_setup");

  TaskExecutionRecord trailing = carrier;
  trailing.fingerprint.append(uint8_t(0));
  ProdigyContainerRetirementJournal decoded = {};
  suite.expect(prodigyParseContainerRetirementJournalCarrier(trailing, decoded) == false,
               "container_retirement_trailing_rejected");

  TaskExecutionRecord oversized = carrier;
  oversized.fingerprint.resize(prodigyContainerRetirementJournalMaximumPayloadBytes + 1);
  suite.expect(prodigyParseContainerRetirementJournalCarrier(oversized, decoded) == false,
               "container_retirement_oversized_carrier_rejected_before_decode");

  ProdigyContainerRetirementJournal wrongVersion = journal;
  wrongVersion.version = 2;
  suite.expect(prodigyWriteContainerRetirementJournalCarrier(carrier, wrongVersion, 1) == false,
               "container_retirement_version_rejected");
}

static void testIdentityAndMonotonicAckFences(TestSuite& suite)
{
  ProdigyContainerRetirementJournal current = makeJournal();
  ProdigyContainerRetirementJournal acknowledged = current;
  acknowledged.intents[0].killAcked = true;
  acknowledged.intents[0].bootstrap.clear();
  ProdigyContainerRetirementJournal merged = {};
  suite.expect(prodigyMergeContainerRetirementJournal(current, acknowledged, merged) &&
                   merged.intents[0].killAcked,
               "container_retirement_ack_advances");

  suite.expect(prodigyMergeContainerRetirementJournal(acknowledged, current, merged) == false,
               "container_retirement_ack_rollback_rejected");

  ProdigyContainerRetirementJournal changedIdentity = acknowledged;
  changedIdentity.intents[0].machineUUID += 1;
  suite.expect(prodigyMergeContainerRetirementJournal(acknowledged, changedIdentity, merged) == false,
               "container_retirement_identity_conflict_rejected");

  ProdigyContainerRetirementJournal removed = {};
  suite.expect(prodigyMergeContainerRetirementJournal(acknowledged, removed, merged) == false,
               "container_retirement_removal_rejected");

  ProdigyContainerRetirementJournal invalidTerminalIdentity = acknowledged;
  invalidTerminalIdentity.intents[0].applicationID += 1;
  suite.expect(prodigyValidateContainerRetirementJournal(invalidTerminalIdentity) == false,
               "container_retirement_terminal_identity_rejected");

  ProdigyContainerRetirementJournal invalidBootstrap = makeJournal();
  NeuronContainerBootstrap decoded = {};
  BitseryEngine::deserializeSafe(invalidBootstrap.intents[0].bootstrap, decoded);
  decoded.plan.restartOnFailure = true;
  BitseryEngine::serialize(invalidBootstrap.intents[0].bootstrap, decoded);
  suite.expect(prodigyValidateContainerRetirementJournal(invalidBootstrap) == false,
               "container_retirement_restartable_bootstrap_rejected");

  ProdigyContainerRetirementJournal wrongBootstrapIdentity = makeJournal();
  BitseryEngine::deserializeSafe(wrongBootstrapIdentity.intents[0].bootstrap, decoded);
  decoded.plan.uuid += 1;
  BitseryEngine::serialize(wrongBootstrapIdentity.intents[0].bootstrap, decoded);
  suite.expect(prodigyValidateContainerRetirementJournal(wrongBootstrapIdentity) == false,
               "container_retirement_bootstrap_identity_rejected");
}

static void testBootstrapSemanticOrderAndTrailingFences(TestSuite& suite)
{
  const int64_t priorHasherSeed = Hasher::threadSeed();
  Hasher::setThreadSeed(0x434f4e5441494e45LL);

  uint64_t firstService = 0, secondService = 0;
  const bool foundCollision = findDeterministicCollidingServiceKeys(firstService, secondService);
  suite.expect(foundCollision, "container_retirement_bootstrap_collision_fixture_found");
  if (foundCollision == false)
  {
    Hasher::setThreadSeed(priorHasherSeed);
    return;
  }

  NeuronContainerBootstrap first = makePopulatedBootstrap(1, firstService, secondService, false);
  NeuronContainerBootstrap reversed = makePopulatedBootstrap(1, firstService, secondService, true);
  String firstBytes = {}, reversedBytes = {};
  BitseryEngine::serialize(firstBytes, first);
  BitseryEngine::serialize(reversedBytes, reversed);

  NeuronContainerBootstrap decodedFirst = {}, decodedReversed = {};
  const bool decoded = BitseryEngine::deserializeSafe(firstBytes, decodedFirst) &&
      BitseryEngine::deserializeSafe(reversedBytes, decodedReversed);
  String reencoded = {};
  if (decoded) BitseryEngine::serialize(reencoded, decodedReversed);
  suite.expect(decoded && !reencoded.equals(reversedBytes),
               "container_retirement_valid_bootstrap_reencoding_is_not_canonical");
  suite.expect(decoded && firstBytes.equals(reversedBytes) == false &&
                   decodedFirst.plan.subscriptions.size() == 2 &&
                   decodedReversed.plan.subscriptions.size() == 2 &&
                   decodedFirst.plan.advertisements.size() == 2 &&
                   decodedReversed.plan.advertisements.size() == 2 &&
                   decodedFirst.plan.subscriptions.at(firstService).nature == SubscriptionNature::all &&
                   decodedReversed.plan.subscriptions.at(secondService).nature == SubscriptionNature::all &&
                   decodedFirst.plan.advertisements.at(firstService).port == 4101 &&
                   decodedReversed.plan.advertisements.at(secondService).port == 4102,
               "container_retirement_bootstrap_valid_semantics_survive_hash_order_reordering");

  ProdigyContainerRetirementIntent reorderedIntent = makeIntent(1);
  reorderedIntent.bootstrap = reversedBytes;
  suite.expect(prodigyContainerRetirementIntentValid(reorderedIntent),
               "container_retirement_semantically_valid_reordered_bootstrap_is_accepted");

  ProdigyContainerRetirementIntent nestedTrailingIntent = reorderedIntent;
  nestedTrailingIntent.bootstrap.append(uint8_t(0));
  suite.expect(prodigyContainerRetirementIntentValid(nestedTrailingIntent) == false,
               "container_retirement_nested_bootstrap_trailing_bytes_rejected");
  Hasher::setThreadSeed(priorHasherSeed);
}

static void testCarrierCollisionAndBound(TestSuite& suite)
{
  bytell_hash_map<uint64_t, TaskExecutionRecord> records = {};
  TaskExecutionRecord collision = {};
  collision.executionID = prodigyContainerRetirementJournalExecutionID;
  collision.applicationID = 1;
  records.insert_or_assign(collision.executionID, collision);
  suite.expect(prodigyStoreContainerRetirementJournalCarrier(records, makeJournal(), 1) == false,
               "container_retirement_carrier_collision_rejected");

  ProdigyContainerRetirementJournal empty = {};
  suite.expect(prodigyValidateContainerRetirementJournal(empty) == false,
               "container_retirement_empty_journal_rejected");

  ProdigyContainerRetirementJournal bound = makeJournal(prodigyContainerRetirementJournalMaximumEntries + 1);
  suite.expect(prodigyValidateContainerRetirementJournal(bound) == false,
               "container_retirement_bound_rejected");
}

int main(void)
{
  TestSuite suite = {};
  testCarrierRoundTripAndExactLookup(suite);
  testMalformedTrailingAndVersionRejected(suite);
  testIdentityAndMonotonicAckFences(suite);
  testBootstrapSemanticOrderAndTrailingFences(suite);
  testCarrierCollisionAndBound(suite);
  return suite.failed == 0 ? 0 : 1;
}
