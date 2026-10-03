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

int main()
{
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
