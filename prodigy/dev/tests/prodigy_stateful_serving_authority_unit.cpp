#include <prodigy/stateful.serving.authority.h>
#include <cstdio>
#include <cstdlib>

static unsigned failures = 0;
static void check(bool value, const char *name)
{
  if (!value) { std::fprintf(stderr, "FAIL: %s\n", name); ++failures; }
}

static Vector<BrainReplicatedContainerRuntimeState> cohort(StatefulWorkerTopologyUpgradePhase phase, bool allMasters = false)
{
  Vector<BrainReplicatedContainerRuntimeState> states;
  const bool steady = phase == StatefulWorkerTopologyUpgradePhase::none;
  const bool blue = phase == StatefulWorkerTopologyUpgradePhase::blueDraining;
  for (unsigned index = 0; index < (steady ? 3u : 6u); ++index)
  {
    const bool source = index >= 3;
    BrainReplicatedContainerRuntimeState state = {};
    state.machineUUID = 100 + index;
    auto& plan = state.plan;
    plan.uuid = 10 + index;
    plan.config.applicationID = 7;
    plan.config.versionID = 9;
    plan.config.type = ApplicationType::stateful;
    plan.config.nLogicalCores = source ? 2 : 4;
    plan.isStateful = true;
    plan.statefulMeshRoles.client = 99;
    auto& topology = plan.statefulTopology;
    topology.operationID = steady ? 0 : 77;
    topology.topologyEpoch = source ? 11 : 22;
    topology.sourceEpoch = steady ? 22 : 11;
    topology.targetEpoch = 22;
    topology.workerCount = source ? 2 : 4;
    topology.servingMode = steady ? StatefulTopologyServingMode::serve :
        (source ? (blue ? StatefulTopologyServingMode::drainOnly : StatefulTopologyServingMode::serve) :
                  (blue ? StatefulTopologyServingMode::serve : StatefulTopologyServingMode::catchupOnly));
    topology.bridgeMode = steady ? StatefulTopologyBridgeMode::none :
        (blue ? StatefulTopologyBridgeMode::targetToSource : StatefulTopologyBridgeMode::sourceToTarget);
    const bool serving = topology.servingMode == StatefulTopologyServingMode::serve;
    if (serving && (allMasters || index % 3 == 0))
      plan.advertisements.emplace(99, Advertisement(99, ContainerState::healthy, ContainerState::destroying, 1234 + index));
    states.push_back(std::move(state));
  }
  return states;
}

static ProdigyStatefulServingAuthority authorityFor(const Vector<BrainReplicatedContainerRuntimeState>& states,
    StatefulWorkerTopologyUpgradePhase phase, bool allMasters = false)
{
  ProdigyStatefulServingAuthority authority = {};
  authority.deploymentID = states[0].plan.config.deploymentID();
  authority.applicationID = 7;
  authority.operationID = 77;
  authority.revision = 10;
  authority.phase = phase;
  authority.sourceEpoch = 11;
  authority.targetEpoch = 22;
  authority.targetConfig = states[0].plan.config;
  authority.allMasters = allMasters;
  for (const auto& state : states)
  {
    ProdigyStatefulServingAuthorityMember member = {};
    member.containerUUID = state.plan.uuid;
    member.machineUUID = state.machineUUID;
    member.shardGroup = state.plan.shardGroup;
    member.isSource = state.plan.statefulTopology.topologyEpoch == 11;
    member.advertiseClient = state.plan.advertisements.contains(99);
    check(prodigyStatefulServingRuntimeDigest(state, member.planSHA256), "construct member digest");
    authority.members.push_back(std::move(member));
  }
  return authority;
}

static String digest(char value)
{
  String result; for (uint32_t index = 0; index < 64; ++index) result.append(value); return result;
}

// Frozen v26/v1 wire model. Keep this independent from StatefulDataAuthority
// so the compatibility check fails if a new field is ever inserted into the
// legacy byte layout again.
class LegacyStatefulDataAuthorityV1Wire {
public:
  uint32_t contractVersion = StatefulDataAuthority::legacyContractVersion;
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
  StatefulDataAuthorityMode mode = StatefulDataAuthorityMode::catchupOnly;
  String contractSHA256;
  String shardManifestSHA256;
  String snapshotBoundarySHA256;
  String requiredAppliedWatermarkSHA256;
};

template <typename S>
static void serialize(S&& serializer, LegacyStatefulDataAuthorityV1Wire& authority)
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
}

static void testStatefulDataAuthorityWireCompatibility()
{
  LegacyStatefulDataAuthorityV1Wire legacy;
  legacy.operationUUID = 11; legacy.datasetUUID = 12; legacy.snapshotUUID = 13;
  legacy.sourceClusterUUID = 14; legacy.targetClusterUUID = 15;
  legacy.localClusterUUID = legacy.targetClusterUUID;
  legacy.writeOwnerClusterUUID = legacy.targetClusterUUID;
  legacy.authorityEpoch = 16; legacy.shardGroup = 2;
  legacy.mode = StatefulDataAuthorityMode::writeOwner;
  legacy.contractSHA256 = digest('a'); legacy.shardManifestSHA256 = digest('b');
  legacy.snapshotBoundarySHA256 = digest('c'); legacy.requiredAppliedWatermarkSHA256 = digest('d');

  StatefulDataAuthority authority;
  authority.contractVersion = StatefulDataAuthority::legacyContractVersion;
  authority.operationUUID = legacy.operationUUID; authority.datasetUUID = legacy.datasetUUID;
  authority.snapshotUUID = legacy.snapshotUUID; authority.sourceClusterUUID = legacy.sourceClusterUUID;
  authority.targetClusterUUID = legacy.targetClusterUUID; authority.localClusterUUID = legacy.localClusterUUID;
  authority.writeOwnerClusterUUID = legacy.writeOwnerClusterUUID; authority.authorityEpoch = legacy.authorityEpoch;
  authority.shardGroup = legacy.shardGroup; authority.mode = legacy.mode;
  authority.contractSHA256 = legacy.contractSHA256; authority.shardManifestSHA256 = legacy.shardManifestSHA256;
  authority.snapshotBoundarySHA256 = legacy.snapshotBoundarySHA256;
  authority.requiredAppliedWatermarkSHA256 = legacy.requiredAppliedWatermarkSHA256;

  String frozenBytes, legacyBytes;
  BitseryEngine::serialize(frozenBytes, legacy); BitseryEngine::serialize(legacyBytes, authority);
  check(frozenBytes == legacyBytes, "stateful authority v1 bytes preserve the exact v26 layout");
  StatefulDataAuthority decodedLegacy;
  check(BitseryEngine::deserializeSafe(frozenBytes, decodedLegacy) &&
      decodedLegacy.contractVersion == StatefulDataAuthority::legacyContractVersion &&
      decodedLegacy.nShardGroups == 0 && prodigyStatefulDataAuthorityValid(decodedLegacy),
      "stateful authority v1 persisted bytes remain readable");

  authority.contractVersion = StatefulDataAuthority::version; authority.nShardGroups = 3;
  auto currentBase = legacy; currentBase.contractVersion = StatefulDataAuthority::version;
  String currentBaseBytes, currentBytes;
  BitseryEngine::serialize(currentBaseBytes, currentBase); BitseryEngine::serialize(currentBytes, authority);
  String currentPrefix = currentBytes; currentPrefix.resize(currentBaseBytes.size());
  StatefulDataAuthority decodedCurrent;
  check(currentBytes.size() == currentBaseBytes.size() + sizeof(uint32_t) && currentPrefix == currentBaseBytes &&
      BitseryEngine::deserializeSafe(currentBytes, decodedCurrent) && decodedCurrent.nShardGroups == 3 &&
      prodigyStatefulDataAuthorityEqual(decodedCurrent, authority),
      "stateful authority v2 appends cardinality after the legacy wire");
  authority.contractVersion = StatefulDataAuthority::legacyContractVersion;
  check(!prodigyStatefulDataAuthorityValid(authority), "legacy authority cannot smuggle an unserialized cardinality");
}

static ProdigyStatefulServingAuthority applicationAuthority(uint32_t shard, StatefulDataAuthorityMode mode,
    Vector<BrainReplicatedContainerRuntimeState>& states)
{
  states = cohort(StatefulWorkerTopologyUpgradePhase::none);
  ProdigyStatefulServingAuthority result;
  result.applicationID = 3; result.operationID = 700 + shard; result.revision = 10;
  result.phase = StatefulWorkerTopologyUpgradePhase::applicationDataAuthority;
  result.sourceEpoch = result.targetEpoch = 1;
  result.pairIntentSHA256 = digest('a'); result.sourceFenceReceiptSHA256 = digest('b');
  result.admittedPlanSHA256 = result.requestPlanSHA256 = digest('c');
  auto& data = result.dataAuthority;
  data.operationUUID = result.operationID; data.datasetUUID = 20; data.snapshotUUID = 21;
  data.sourceClusterUUID = 30; data.targetClusterUUID = 40; data.authorityEpoch = 5;
  data.shardGroup = shard; data.nShardGroups = 3;
  data.mode = mode; data.contractSHA256 = digest('d'); data.shardManifestSHA256 = digest('e');
  const bool source = mode == StatefulDataAuthorityMode::fenced || mode == StatefulDataAuthorityMode::snapshotPreparing;
  const bool serving = mode == StatefulDataAuthorityMode::writeOwner || mode == StatefulDataAuthorityMode::snapshotPreparing;
  data.localClusterUUID = source ? data.sourceClusterUUID : data.targetClusterUUID;
  data.writeOwnerClusterUUID = mode == StatefulDataAuthorityMode::writeOwner ? data.targetClusterUUID : data.sourceClusterUUID;
  if (mode != StatefulDataAuthorityMode::snapshotPreparing) data.snapshotBoundarySHA256 = digest('f');
  if (!source) data.requiredAppliedWatermarkSHA256 = digest('f');
  for (uint32_t index = 0; index < states.size(); ++index) {
    auto& state = states[index]; auto& plan = state.plan;
    plan.config.applicationID = 3; plan.uuid += uint128_t(shard + 1) * 1000;
    plan.shardGroup = shard; plan.statefulTopology.shardGroup = shard;
    plan.statefulTopology.servingMode = StatefulTopologyServingMode::applicationDataAuthority;
    plan.statefulTopology.dataAuthority = data;
    plan.declaredStatefulClientService = 99; plan.declaredStatefulClientPort = 1234 + index;
    plan.statefulMeshRoles.client = serving && index == 0 ? 99 : 0;
    plan.advertisements.clear();
    if (serving && index == 0) plan.advertisements.emplace(99, Advertisement(99, ContainerState::healthy, ContainerState::destroying, 1234));
    ProdigyStatefulServingAuthorityMember member;
    member.containerUUID = plan.uuid; member.machineUUID = state.machineUUID; member.shardGroup = shard;
    member.isSource = source; member.advertiseClient = serving && index == 0;
    check(prodigyStatefulServingRuntimeDigest(state, member.planSHA256), "app scoped member digest");
    result.members.push_back(member);
  }
  result.deploymentID = states.front().plan.config.deploymentID(); result.targetConfig = states.front().plan.config;
  return result;
}

static void testApplicationShardAuthority()
{
  Vector<BrainReplicatedContainerRuntimeState> firstStates, secondStates;
  auto first = applicationAuthority(1, StatefulDataAuthorityMode::writeOwner, firstStates);
  auto second = applicationAuthority(2, StatefulDataAuthorityMode::catchupOnly, secondStates);
  check(prodigyValidateStatefulServingAuthority(first, firstStates, 10), "promoted shard owns one exact serving cohort");
  check(!prodigyStatefulServingClientPublicationReady(first), "desired writer is not an ownership-ready publication receipt");
  auto pendingWriter = firstStates.front().plan;
  prodigyProjectStatefulServingClientPublication(first, pendingWriter);
  check(pendingWriter.statefulMeshRoles.client == 0 && !pendingWriter.advertisements.contains(99) &&
      pendingWriter.declaredStatefulClientPort == 1234 &&
      pendingWriter.statefulTopology.dataAuthority.mode == StatefulDataAuthorityMode::writeOwner &&
      firstStates.front().plan.advertisements.contains(99),
      "pending writer dispatch preserves permission and private listener while withholding only discovery");
  Vector<StatefulDataAuthorityMemberReceipt> ownershipReceipts;
  for (const auto& member : first.members) {
    StatefulDataAuthorityMemberReceipt observed;
    observed.containerUUID = member.containerUUID; observed.machineUUID = member.machineUUID;
    observed.receipt.authority = first.dataAuthority; observed.receipt.ready = true;
    observed.receipt.snapshotReceiptSHA256 = first.dataAuthority.snapshotBoundarySHA256;
    observed.receipt.appliedWatermarkSHA256 = first.dataAuthority.requiredAppliedWatermarkSHA256;
    ownershipReceipts.push_back(observed);
  }
  check(prodigyStatefulServingOwnershipReadyReceiptsValid(first, ownershipReceipts), "exact three-member ownership ready proof admitted");
  auto wrongOwnership = ownershipReceipts; wrongOwnership.pop_back();
  check(!prodigyStatefulServingOwnershipReadyReceiptsValid(first, wrongOwnership), "partial ownership proof cannot publish");
  wrongOwnership = ownershipReceipts; wrongOwnership[1] = wrongOwnership[0];
  check(!prodigyStatefulServingOwnershipReadyReceiptsValid(first, wrongOwnership), "duplicate member proof cannot publish");
  wrongOwnership = ownershipReceipts; wrongOwnership[0].receipt.authority.authorityEpoch--;
  check(!prodigyStatefulServingOwnershipReadyReceiptsValid(first, wrongOwnership), "stale authority proof cannot publish");
  wrongOwnership = ownershipReceipts; wrongOwnership[0].machineUUID++;
  check(!prodigyStatefulServingOwnershipReadyReceiptsValid(first, wrongOwnership), "foreign incarnation cohort proof cannot publish");
  first.ownershipReadyReceiptSHA256 = digest('9');
  auto readyWriter = firstStates.front().plan;
  prodigyProjectStatefulServingClientPublication(first, readyWriter);
  check(prodigyStatefulServingClientPublicationReady(first) && readyWriter.advertisements.contains(99),
      "sealed ownership receipt permits the existing desired client projection");
  auto scopedFailover = first; auto scopedStates = firstStates;
  check(prodigyStatefulServingSelectClient(scopedFailover, scopedStates, 1, first.members[1].containerUUID) &&
      scopedStates[1].plan.advertisements.at(99).port == 1235 && scopedStates[1].plan.statefulMeshRoles.client == 99 &&
      scopedStates[0].plan.statefulMeshRoles.client == 0 && !scopedStates[0].plan.advertisements.contains(99) &&
      scopedFailover.ownershipReadyReceiptSHA256 == first.ownershipReadyReceiptSHA256,
      "shard follower promotion reuses the exact private listener and durable ownership seal");
  check(!prodigyStatefulServingSelectClient(scopedFailover, scopedStates, 2, first.members[1].containerUUID),
      "client failover cannot select another shard");
  auto wrongPayload = scopedStates; wrongPayload.push_back(secondStates.front());
  check(!prodigyStatefulServingSelectClient(scopedFailover, wrongPayload, 1, first.members[1].containerUUID),
      "client failover rejects sibling payload rather than replacing its authority");
  ProdigyStatefulServingAuthority restoredOwner; String ownerBytes; BitseryEngine::serialize(ownerBytes, scopedFailover);
  check(BitseryEngine::deserializeSafe(ownerBytes, restoredOwner) && restoredOwner == scopedFailover &&
      prodigyStatefulServingClientPublicationReady(restoredOwner), "cold restart preserves exact activation seal and scoped follower selection");
  check(prodigyValidateStatefulServingAuthority(second, secondStates, 10), "next shard starts as nonserving target");
  for (const auto& state : secondStates) {
    ContainerParameters parameters = {};
    parameters.statefulMeshRoles = state.plan.statefulMeshRoles;
    parameters.statefulMeshRoles.client = 0;
    parameters.statefulTopology = state.plan.statefulTopology;
    check(prodigyProjectStatefulDataClientPort(state.plan, parameters) && parameters.statefulMeshRoles.client == 0 &&
        parameters.advertisesOnPorts.at(99) == state.plan.declaredStatefulClientPort && !state.plan.advertisements.contains(99),
        "catchup startup retains exact private IPv6 client port without an advertiser or client role");
    String encoded; BitseryEngine::serialize(encoded, parameters); ContainerParameters decoded = {};
    check(BitseryEngine::deserializeSafe(encoded, decoded) && decoded.advertisesOnPorts.at(99) == state.plan.declaredStatefulClientPort &&
        decoded.statefulMeshRoles.client == 0 && prodigyStatefulDataAuthorityEqual(decoded.statefulTopology.dataAuthority, second.dataAuthority),
        "full startup codec preserves private port and catchup-only authority");
  }
  auto pending = second; pending.members.clear();
  check(prodigyValidateStatefulServingAuthority(pending, {}, 10), "empty desired target authority precedes construction");
  for (uint32_t count = 1; count <= 3; ++count) {
    auto partial = second; partial.members.resize(count); auto plans = secondStates; plans.resize(count);
    check(prodigyValidateStatefulServingAuthority(partial, plans, 10), "each exact target member persists before serial launch");
  }
  Vector<BrainReplicatedContainerRuntimeState> all = firstStates;
  all.insert(all.end(), secondStates.begin(), secondStates.end());
  check(prodigyValidateStatefulServingAuthorities({first, second}, all, 10), "serial shard B cannot overwrite promoted shard A");
  check(!prodigyValidateStatefulServingAuthorities({first, first, second}, all, 10), "duplicate shard scope rejects");
  auto premature = secondStates;
  premature.front().plan.advertisements.emplace(99, Advertisement(99, ContainerState::healthy, ContainerState::destroying, 1234));
  check(!prodigyValidateStatefulServingAuthority(second, premature, 10), "catchup target cannot advertise clients before owner receipt");
  Vector<BrainReplicatedContainerRuntimeState> oldSource;
  auto retired = applicationAuthority(1, StatefulDataAuthorityMode::fenced, oldSource);
  retired.sourceRetired = true; retired.members.clear();
  check(prodigyValidateStatefulServingAuthority(retired, {}, 10), "terminal source tombstone needs no restartable cohort");
  check(prodigyValidateStatefulServingAuthorities({retired, second}, secondStates, 10), "retired shard A coexists with admitted shard B");
  all = secondStates; all.push_back(oldSource.front());
  check(!prodigyValidateStatefulServingAuthorities({retired, second}, all, 10), "stale retired source UUID cannot reappear in cold payload");
  ProdigyPersistentMasterAuthorityPackage saved, restored;
  saved.runtimeState.generation = 10; saved.runtimeState.statefulServingAuthorities = {retired, second};
  saved.servingRuntimeStates = secondStates;
  String encoded; BitseryEngine::serialize(encoded, saved);
  check(BitseryEngine::deserializeSafe(encoded, restored) &&
      prodigyValidateStatefulServingAuthorities(restored.runtimeState.statefulServingAuthorities, restored.servingRuntimeStates, 10) &&
      restored.runtimeState.statefulServingAuthorities[0].sourceRetired,
      "cold/master recovery preserves independent shard scopes and terminal source fence");
}

int main()
{
  testStatefulDataAuthorityWireCompatibility();
  testApplicationShardAuthority();
  const auto steadyPhase = StatefulWorkerTopologyUpgradePhase::none;
  const auto bluePhase = StatefulWorkerTopologyUpgradePhase::blueDraining;
  const auto greenPhase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
  for (auto phase : {steadyPhase, bluePhase, greenPhase})
  {
    for (bool allMasters : {false, true})
    {
      auto states = cohort(phase, allMasters);
      auto authority = authorityFor(states, phase, allMasters);
      check(prodigyValidateStatefulServingAuthority(authority, states, 10), "valid phase and client cohort");
      auto missing = states; missing.pop_back();
      check(!prodigyValidateStatefulServingAuthority(authority, missing, 10), "missing payload rejects");
      auto duplicate = states; duplicate[1] = duplicate[0];
      check(!prodigyValidateStatefulServingAuthority(authority, duplicate, 10), "duplicate payload rejects");
      auto future = authority; future.revision = 11;
      check(!prodigyValidateStatefulServingAuthority(future, states, 10), "uncommitted revision rejects");
      auto reordered = authority; std::swap(reordered.members[0], reordered.members[1]);
      check(!prodigyValidateStatefulServingAuthority(reordered, states, 10), "noncanonical members reject");
      auto wrongMachine = states; wrongMachine[0].machineUUID += 1;
      check(!prodigyValidateStatefulServingAuthority(authority, wrongMachine, 10), "machine identity change rejects");
      auto wrongConfig = states; wrongConfig[0].plan.config.memoryMB += 1;
      auto wrongConfigAuthority = authorityFor(wrongConfig, phase, allMasters);
      wrongConfigAuthority.targetConfig = authority.targetConfig;
      check(!prodigyValidateStatefulServingAuthority(wrongConfigAuthority, wrongConfig, 10), "rehashing cannot rebind target config");
      auto wrongMode = states;
      wrongMode[0].plan.statefulTopology.servingMode = phase == greenPhase
          ? StatefulTopologyServingMode::serve : StatefulTopologyServingMode::catchupOnly;
      check(!prodigyValidateStatefulServingAuthority(authorityFor(wrongMode, phase, allMasters), wrongMode, 10),
            "rehashing cannot authorize contradictory serving mode");
      auto wrongBridge = states;
      wrongBridge[0].plan.statefulTopology.bridgeMode = phase == bluePhase
          ? StatefulTopologyBridgeMode::sourceToTarget : StatefulTopologyBridgeMode::targetToSource;
      check(!prodigyValidateStatefulServingAuthority(authorityFor(wrongBridge, phase, allMasters), wrongBridge, 10),
            "rehashing cannot authorize contradictory bridge mode");
    }
  }

  auto sourceOnly = cohort(greenPhase);
  sourceOnly.erase(sourceOnly.begin(), sourceOnly.begin() + 3);
  auto initialGreen = authorityFor(sourceOnly, greenPhase);
  initialGreen.targetConfig = cohort(greenPhase)[0].plan.config;
  check(prodigyValidateStatefulServingAuthority(initialGreen, sourceOnly, 10),
        "initial green binds all source plans before target creation");
  for (unsigned targetCount = 1; targetCount <= 3; ++targetCount)
  {
    auto admittedGreen = cohort(greenPhase);
    admittedGreen.erase(admittedGreen.begin() + targetCount, admittedGreen.begin() + 3);
    auto admittedAuthority = authorityFor(admittedGreen, greenPhase);
    check(prodigyValidateStatefulServingAuthority(admittedAuthority, admittedGreen, 10),
          "green admits each exact nonserving target before serial launch");
    auto earlyClient = admittedGreen;
    earlyClient[0].plan.advertisements.emplace(99,
        Advertisement(99, ContainerState::healthy, ContainerState::destroying, 1234));
    check(!prodigyValidateStatefulServingAuthority(authorityFor(earlyClient, greenPhase), earlyClient, 10),
          "partial green admission never grants target client authority");
    if (targetCount < 3)
    {
      auto incompleteBlue = cohort(bluePhase);
      incompleteBlue.erase(incompleteBlue.begin() + targetCount, incompleteBlue.begin() + 3);
      check(!prodigyValidateStatefulServingAuthority(authorityFor(incompleteBlue, bluePhase), incompleteBlue, 10),
            "blue cutover still requires the complete target cohort");
    }
  }

  auto states = cohort(steadyPhase);
  auto first = states[0];
  first.plan.config.capabilities.insert(3); first.plan.config.capabilities.insert(1);
  first.plan.subscriptions.emplace(2, Subscription(2, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));
  first.plan.subscriptions.emplace(1, Subscription(1, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));
  first.plan.hasCredentialBundle = true;
  first.plan.credentialBundle.apiCredentials.push_back({});
  first.plan.credentialBundle.apiCredentials[0].metadata.emplace("b"_ctv, "2"_ctv);
  first.plan.credentialBundle.apiCredentials[0].metadata.emplace("a"_ctv, "1"_ctv);
  first.plan.subscriptionPairings.emplace(2, uint128_t(200), uint128_t(300), uint64_t(2), uint16_t(400));
  first.plan.subscriptionPairings.emplace(1, uint128_t(201), uint128_t(301), uint64_t(1), uint16_t(401));
  auto second = first;
  second.plan.config.capabilities.clear(); second.plan.config.capabilities.insert(1); second.plan.config.capabilities.insert(3);
  second.plan.subscriptions.clear();
  second.plan.subscriptions.emplace(1, first.plan.subscriptions.at(1)); second.plan.subscriptions.emplace(2, first.plan.subscriptions.at(2));
  second.plan.credentialBundle.apiCredentials[0].metadata.clear();
  second.plan.credentialBundle.apiCredentials[0].metadata.emplace("a"_ctv, "1"_ctv);
  second.plan.credentialBundle.apiCredentials[0].metadata.emplace("b"_ctv, "2"_ctv);
  second.plan.subscriptionPairings.clear();
  second.plan.subscriptionPairings.emplace(1, uint128_t(201), uint128_t(301), uint64_t(1), uint16_t(401));
  second.plan.subscriptionPairings.emplace(2, uint128_t(200), uint128_t(300), uint64_t(2), uint16_t(400));
  String firstDigest, secondDigest;
  check(prodigyStatefulServingRuntimeDigest(first, firstDigest) && prodigyStatefulServingRuntimeDigest(second, secondDigest) &&
        firstDigest.equals(secondDigest), "hash insertion order cannot change plan identity");
  second.plan.subscriptionPairings.clear();
  check(prodigyStatefulServingRuntimeDigest(second, secondDigest) && !firstDigest.equals(secondDigest), "pairing secrets are bound");
  String wire; BrainReplicatedContainerRuntimeState recovered = {};
  BitseryEngine::serialize(wire, first);
  check(BitseryEngine::deserializeSafe(wire, recovered) && prodigyStatefulServingRuntimeDigest(recovered, secondDigest) &&
        firstDigest.equals(secondDigest), "production codec roundtrip retains canonical digest");

  auto authority = authorityFor(states, steadyPhase);
  ProdigyMasterAuthorityRuntimeState runtime = {}, runtimeRoundtrip = {};
  runtime.generation = 10; runtime.statefulServingAuthorities.push_back(authority);
  BitseryEngine::serialize(wire, runtime);
  check(BitseryEngine::deserializeSafe(wire, runtimeRoundtrip) && runtimeRoundtrip == runtime, "v7 descriptor framing without placement policies");
  ProdigyPersistentMasterAuthorityPackage package = {}, packageRoundtrip = {};
  package.runtimeState = runtime; package.servingRuntimeStates = states;
  BitseryEngine::serialize(wire, package);
  check(BitseryEngine::deserializeSafe(wire, packageRoundtrip) &&
        prodigyValidateStatefulServingAuthorities(packageRoundtrip.runtimeState.statefulServingAuthorities,
            packageRoundtrip.servingRuntimeStates, 10), "v7 package retains complete private plans");
  ProdigyMasterAuthorityRuntimeState legacy = {}, legacyRoundtrip = {};
  BitseryEngine::serialize(wire, legacy);
  check(BitseryEngine::deserializeSafe(wire, legacyRoundtrip) && legacyRoundtrip == legacy, "empty legacy framing unchanged");
  std::fprintf(stderr, "%s: %u failures\n", failures ? "FAIL" : "PASS", failures);
  return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
