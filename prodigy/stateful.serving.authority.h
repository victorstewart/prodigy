#pragma once

#include <prodigy/bundle.artifact.h>
#include <prodigy/types.h>

// Reuse the production codec for every ordinary field. Detach only unordered
// collections and frame their sorted entries separately, so a private payload
// retains the same identity after deserialization into different hash tables.
class ProdigyStatefulServingRuntimeDigestInput {
public:
  BrainReplicatedContainerRuntimeState state;
};

template <typename S>
static void serialize(S&& serializer, ProdigyStatefulServingRuntimeDigestInput& input)
{
  ContainerPlan& plan = input.state.plan;
  auto capabilities = std::move(plan.config.capabilities);
  auto subscriptions = std::move(plan.subscriptions);
  auto advertisements = std::move(plan.advertisements);
  auto subscriptionPairings = std::move(plan.subscriptionPairings.map);
  auto advertisementPairings = std::move(plan.advertisementPairings.map);
  plan.config.capabilities.clear();
  plan.subscriptions.clear();
  plan.advertisements.clear();
  plan.subscriptionPairings.clear();
  plan.advertisementPairings.clear();
  using Metadata = std::remove_cvref_t<decltype(plan.credentialBundle.apiCredentials[0].metadata)>;
  Vector<Metadata> metadata;
  for (auto& credential : plan.credentialBundle.apiCredentials)
  {
    metadata.push_back(std::move(credential.metadata));
    credential.metadata.clear();
  }
  serializer.object(input.state);
  Vector<int> orderedCapabilities;
  for (int capability : capabilities) orderedCapabilities.push_back(capability);
  std::sort(orderedCapabilities.begin(), orderedCapabilities.end());
  serializer.container(orderedCapabilities, UINT32_MAX, [](auto& nested, int& capability) {
    nested.value4b(capability);
  });
  auto serviceMap = [&](auto& map) {
    prodigySerializePersistentMapAsEntries(
        serializer, map,
        [](auto& nested, uint64_t& service) { nested.value8b(service); },
        [](auto& nested, auto& value) { nested.object(value); },
        [](uint64_t lhs, uint64_t rhs) { return lhs < rhs; });
  };
  serviceMap(subscriptions);
  serviceMap(advertisements);
  serviceMap(subscriptionPairings);
  serviceMap(advertisementPairings);
  uint32_t metadataCount = uint32_t(metadata.size());
  serializer.value4b(metadataCount);
  for (auto& entries : metadata)
  {
    prodigySerializePersistentMapAsEntries(
        serializer, entries,
        [](auto& nested, String& key) { nested.text1b(key, UINT32_MAX); },
        [](auto& nested, String& value) { nested.text1b(value, UINT32_MAX); },
        [](const String& lhs, const String& rhs) { return prodigyPersistentStringComesBefore(lhs, rhs); });
  }
}

static inline bool prodigyStatefulServingRuntimeDigest(
    const BrainReplicatedContainerRuntimeState& state, String& digest)
{
  ProdigyStatefulServingRuntimeDigestInput input = {};
  input.state = state;
  String serialized;
  BitseryEngine::serialize(serialized, input);
  const bool valid = prodigyComputeSHA256Hex(serialized, digest);
  Vault::secureClearString(serialized);
  return valid;
}

static inline bool prodigyStatefulStoreGenerationImmutablePlanIdentityMatches(
    const ProdigyStatefulStoreGenerationSelection& selection,
    const BrainReplicatedContainerRuntimeState& sealed,
    const ContainerPlan& proposedPlan);

// Returns true with a zero protocolVersion only when this target has no desired
// generation record.  A record for the target which is stale, malformed, or
// no longer matches the sealed serving runtime is an error, never legacy
// fallback.  `servingRevision` is an admission lower bound: later unrelated
// authority revisions remain valid while the exact sealed member digest does.
static inline bool prodigyProjectStatefulStoreGeneration(
    const ProdigyMasterAuthorityRuntimeState& runtime,
    const Vector<BrainReplicatedContainerRuntimeState>& sealedRuntimeStates,
    const ContainerPlan& launch,
    ProdigyStatefulStoreGenerationSelection& outSelection)
{
  outSelection = {.protocolVersion = 0};
  const ProdigyStatefulStoreGenerationSelection *selected = nullptr;
  for (const auto& candidate : runtime.statefulStoreGenerationSelections)
  {
    if (candidate.authority.targetContainerUUID != launch.uuid) continue;
    if (selected != nullptr || !prodigyStatefulStoreGenerationSelectionValid(candidate)) return false;
    selected = &candidate;
  }
  if (selected == nullptr) return true;
  const auto& authority = selected->authority;
  if (!prodigyStatefulStoreGenerationSelectionMatchesPlan(*selected, launch)) return false;

  const BrainReplicatedContainerRuntimeState *sealed = nullptr;
  for (const auto& candidate : sealedRuntimeStates)
  {
    if (candidate.plan.uuid != launch.uuid) continue;
    if (sealed != nullptr) return false;
    sealed = &candidate;
  }
  if (sealed == nullptr || sealed->plan.config.deploymentID() != authority.targetDeploymentID ||
      sealed->plan.shardGroup != authority.shardGroup || sealed->plan.nShardGroups != authority.nShardGroups) return false;
  if (!prodigyStatefulStoreGenerationImmutablePlanIdentityMatches(*selected, *sealed, launch)) return false;

  String currentDigest = {};
  if (!prodigyStatefulServingRuntimeDigest(*sealed, currentDigest) ||
      !currentDigest.equals(selected->admittedPlanSHA256)) return false;
  const ProdigyStatefulServingAuthority *currentAuthority = nullptr;
  const ProdigyStatefulServingAuthorityMember *currentMember = nullptr;
  for (const auto& serving : runtime.statefulServingAuthorities)
  {
    if (!prodigyStatefulServingAuthorityMatchesShard(serving, authority.targetDeploymentID, authority.shardGroup)) continue;
    auto member = std::find_if(serving.members.begin(), serving.members.end(), [&](const auto& value) {
      return value.containerUUID == authority.targetContainerUUID;
    });
    if (member == serving.members.end()) continue;
    if (currentAuthority != nullptr || serving.revision < selected->servingRevision ||
        serving.revision > runtime.generation || member->machineUUID != sealed->machineUUID ||
        member->shardGroup != launch.shardGroup ||
        !member->planSHA256.equals(selected->admittedPlanSHA256)) return false;
    currentAuthority = &serving;
    currentMember = &*member;
  }
  if (currentAuthority == nullptr || currentMember == nullptr) return false;
  outSelection = *selected;
  return true;
}

// State upload refreshes liveness and mesh observations independently of the
// sealed serving member.  A selected native home may follow that refresh only
// when every immutable launch field remains identical.  Keep this
// normalization beside the sealed-runtime projection so Neuron cannot grow a
// second, subtly weaker identity rule for same-UUID recovery.
static inline bool prodigyStatefulStoreGenerationImmutablePlanIdentityMatches(
    const ProdigyStatefulStoreGenerationSelection& selection,
    const BrainReplicatedContainerRuntimeState& sealed,
    const ContainerPlan& proposedPlan)
{
  if (!prodigyStatefulStoreGenerationSelectionMatchesPlan(selection, sealed.plan) ||
      !prodigyStatefulStoreGenerationSelectionMatchesPlan(selection, proposedPlan)) return false;
  BrainReplicatedContainerRuntimeState normalized = sealed;
  normalized.plan = proposedPlan;
  normalized.plan.state = sealed.plan.state;
  normalized.plan.runtimeReady = sealed.plan.runtimeReady;
  normalized.plan.subscriptionPairings = sealed.plan.subscriptionPairings;
  normalized.plan.advertisementPairings = sealed.plan.advertisementPairings;
  normalized.plan.hasCredentialBundle = sealed.plan.hasCredentialBundle;
  normalized.plan.credentialBundle = sealed.plan.credentialBundle;
  String sealedDigest = {}, proposedDigest = {};
  return prodigyStatefulServingRuntimeDigest(sealed, sealedDigest) &&
      prodigyStatefulServingRuntimeDigest(normalized, proposedDigest) && sealedDigest == proposedDigest;
}

static inline bool prodigyStatefulStoreGenerationImmutablePlanIdentityMatches(
    const ProdigyStatefulStoreGenerationSelection& selection,
    const ContainerPlan& sealedPlan, const ContainerPlan& proposedPlan,
    uint128_t machineUUID)
{
  if (machineUUID == 0) return false;
  BrainReplicatedContainerRuntimeState sealed = {};
  sealed.machineUUID = machineUUID;
  sealed.plan = sealedPlan;
  return prodigyStatefulStoreGenerationImmutablePlanIdentityMatches(selection, sealed, proposedPlan);
}

// A desired home can advance only with a fresh durable authority decision.
// UUID novelty alone is not ordering: an old state upload could otherwise
// rebind a crashed container to a historical or forked generation.
static inline bool prodigyStatefulStoreGenerationSelectionStrictlyAdvances(
    const ProdigyStatefulStoreGenerationSelection& previous,
    const ProdigyStatefulStoreGenerationSelection& next)
{
  if (!prodigyStatefulStoreGenerationSelectionValid(next)) return false;
  if (previous.protocolVersion == 0) return true;
  return prodigyStatefulStoreGenerationSelectionValid(previous) &&
      previous.generationUUID != next.generationUUID &&
      previous.admittedPlanSHA256.equals(next.admittedPlanSHA256) &&
      next.authority.authorityGeneration > previous.authority.authorityGeneration &&
      next.authority.seedGeneration > previous.authority.seedGeneration;
}

// Desired writer permission is not an application activation acknowledgement.
// The existing serving package seals that observation before discovery may
// expose its desired client advertisement. Legacy/source serving is unchanged.
static inline bool prodigyStatefulServingClientPublicationReady(const ProdigyStatefulServingAuthority& authority)
{
  return authority.phase != StatefulWorkerTopologyUpgradePhase::applicationDataAuthority ||
      authority.dataAuthority.mode != StatefulDataAuthorityMode::writeOwner ||
      prodigyIsSHA256HexDigest(authority.ownershipReadyReceiptSHA256);
}

static inline void prodigyProjectStatefulServingClientPublication(const ProdigyStatefulServingAuthority& authority,
    ContainerPlan& plan)
{
  if (prodigyStatefulServingClientPublicationReady(authority)) return;
  plan.advertisements.erase(plan.declaredStatefulClientService);
  plan.advertisementPairings.map.erase(plan.declaredStatefulClientService);
  plan.statefulMeshRoles.client = 0;
}

static inline bool prodigyStatefulServingOwnershipReadyReceiptsValid(const ProdigyStatefulServingAuthority& authority,
    const Vector<StatefulDataAuthorityMemberReceipt>& receipts)
{
  if (authority.phase != StatefulWorkerTopologyUpgradePhase::applicationDataAuthority ||
      authority.dataAuthority.mode != StatefulDataAuthorityMode::writeOwner || authority.sourceRetired ||
      authority.members.size() != 3 || receipts.size() != 3) return false;
  for (uint32_t index = 0; index < 3; ++index) {
    const auto& member = authority.members[index]; const auto& observed = receipts[index];
    if (observed.containerUUID != member.containerUUID || observed.machineUUID != member.machineUUID ||
        !observed.receipt.ready || !prodigyStatefulDataAuthorityReceiptValid(observed.receipt) ||
        !prodigyStatefulDataAuthorityEqual(observed.receipt.authority, authority.dataAuthority)) return false;
  }
  return true;
}

static inline bool prodigyValidateStatefulServingAuthority(
    const ProdigyStatefulServingAuthority& authority,
    const Vector<BrainReplicatedContainerRuntimeState>& payload,
    uint64_t generation)
{
  if (authority.deploymentID == 0 || authority.applicationID == 0 || authority.revision == 0 ||
      authority.revision > generation || authority.targetConfig.deploymentID() != authority.deploymentID ||
      authority.targetConfig.applicationID != authority.applicationID ||
      uint8_t(authority.phase) > uint8_t(StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap)) return false;
  const bool application = authority.phase == StatefulWorkerTopologyUpgradePhase::applicationDataAuthority;
  const bool initial = authority.phase == StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap;
  const bool bootstrap = authority.phase == StatefulWorkerTopologyUpgradePhase::allMastersSeedBootstrap || initial;
  if (initial) {
    const auto& scope = authority.initialAllMastersSeedBootstrap;
    StatefulTopology topology; topology.servingMode = StatefulTopologyServingMode::allMastersSeedBootstrap;
    topology.shardGroup = scope.bootstrap.shardGroup; topology.allMastersSeedBootstrap = scope.bootstrap;
    if (!authority.allMasters || authority.applicationID < 2 || authority.applicationID > 5 ||
        !prodigyStatefulTopologyIsAllMastersSeedBootstrap(topology) || scope.baselineOperationUUID == 0 ||
        scope.bootstrap.targetDeploymentID != authority.deploymentID || scope.nShardGroups == 0 || scope.nShardGroups > UINT16_MAX ||
        ((authority.applicationID == 2 || authority.applicationID == 5) && scope.nShardGroups != 1) ||
        scope.bootstrap.shardGroup >= scope.nShardGroups || !prodigyIsSHA256HexDigest(scope.planSHA256) ||
        !prodigyIsSHA256HexDigest(scope.artifactSHA256) || scope.artifactSHA256 != authority.targetConfig.containerBlobSHA256 ||
        scope.artifactBytes == 0 || scope.artifactBytes != authority.targetConfig.containerBlobBytes || authority.members.size() > 3) return false;
  }
  if (bootstrap && !initial) {
    StatefulTopology topology; topology.servingMode = StatefulTopologyServingMode::allMastersSeedBootstrap;
    topology.shardGroup = authority.allMastersSeedBootstrap.shardGroup;
    topology.allMastersSeedBootstrap = authority.allMastersSeedBootstrap;
    const auto& scope = authority.qualificationCancellation;
    if (!authority.allMasters || authority.applicationID < 2 || authority.applicationID > 5 ||
        !prodigyStatefulTopologyIsAllMastersSeedBootstrap(topology) ||
        !prodigyQualificationStatefulCancellationValid(scope) ||
        scope.sourceClusterUUID != authority.allMastersSeedBootstrap.sourceClusterUUID ||
        scope.qualificationRunUUID != authority.allMastersSeedBootstrap.qualificationRunUUID ||
        scope.successorOperationUUID != authority.allMastersSeedBootstrap.successorOperationUUID ||
        authority.allMastersSeedBootstrap.targetDeploymentID != authority.deploymentID ||
        scope.request.applicationID != authority.applicationID ||
        scope.request.successorVersionID != (authority.deploymentID & ((uint64_t(1) << 48) - 1)) ||
        scope.members.size() % 3 != 0 || authority.allMastersSeedBootstrap.shardGroup >= scope.members.size() / 3 ||
        authority.members.size() > 3) return false;
  }
  if (application &&
      ((authority.applicationID != 3 && authority.applicationID != 4) || authority.allMasters ||
       !prodigyStatefulDataAuthorityValid(authority.dataAuthority) || !prodigyIsSHA256HexDigest(authority.pairIntentSHA256) ||
       !prodigyIsSHA256HexDigest(authority.admittedPlanSHA256) ||
       !prodigyIsSHA256HexDigest(authority.requestPlanSHA256) ||
       (!authority.ownershipReadyReceiptSHA256.empty() &&
        (authority.dataAuthority.mode != StatefulDataAuthorityMode::writeOwner ||
         !prodigyIsSHA256HexDigest(authority.ownershipReadyReceiptSHA256))) ||
       (authority.dataAuthority.mode == StatefulDataAuthorityMode::writeOwner &&
        authority.dataAuthority.localClusterUUID == authority.dataAuthority.targetClusterUUID &&
        !prodigyIsSHA256HexDigest(authority.sourceFenceReceiptSHA256)))) return false;

  if ((authority.phase == StatefulWorkerTopologyUpgradePhase::none &&
       (authority.operationID == 0 || authority.sourceEpoch == 0 || authority.targetEpoch == 0)) ||
      (!application && !bootstrap && authority.phase != StatefulWorkerTopologyUpgradePhase::none &&
       (authority.operationID == 0 || authority.sourceEpoch == 0 || authority.targetEpoch == 0 ||
        authority.sourceEpoch == authority.targetEpoch))) return false;
  if (payload.size() != authority.members.size()) return false;
  if (authority.sourceRetired && (!application ||
      (!prodigyStatefulDataAuthoritySourceNonwriter(authority.dataAuthority) && authority.dataAuthority.mode != StatefulDataAuthorityMode::catchupOnly) ||
      !authority.members.empty())) return false;
  if (authority.members.empty()) return bootstrap || (application &&
      (authority.dataAuthority.mode == StatefulDataAuthorityMode::catchupOnly || authority.sourceRetired));

  const ProdigyStatefulServingAuthorityMember *previous = nullptr;
  bytell_hash_set<uint128_t> memberUUIDs = {};
  bytell_hash_set<uint128_t> payloadUUIDs = {};
  bytell_hash_map<uint32_t, uint32_t> sourceCounts = {};
  bytell_hash_map<uint32_t, uint32_t> targetCounts = {};
  bytell_hash_map<uint32_t, uint32_t> sourceClients = {};
  bytell_hash_map<uint32_t, uint32_t> targetClients = {};
  for (const ProdigyStatefulServingAuthorityMember& member : authority.members)
  {
    if (member.containerUUID == 0 || member.machineUUID == 0 ||
        prodigyIsSHA256HexDigest(member.planSHA256) == false ||
        memberUUIDs.insert(member.containerUUID).second == false ||
        (previous != nullptr &&
         (member.shardGroup < previous->shardGroup ||
          (member.shardGroup == previous->shardGroup &&
           (member.isSource < previous->isSource ||
            (member.isSource == previous->isSource && member.containerUUID <= previous->containerUUID)))))) return false;
    previous = &member;
    auto& count = member.isSource ? sourceCounts[member.shardGroup] : targetCounts[member.shardGroup];
    ++count;
    if (member.advertiseClient) ++(member.isSource ? sourceClients[member.shardGroup] : targetClients[member.shardGroup]);
  }

  for (const BrainReplicatedContainerRuntimeState& state : payload)
  {
    const ContainerPlan& plan = state.plan;
    if (plan.uuid == 0 || payloadUUIDs.insert(plan.uuid).second == false || state.machineUUID == 0 ||
        plan.config.deploymentID() != authority.deploymentID || plan.config.applicationID != authority.applicationID ||
        plan.isStateful == false) return false;
    auto member = std::find_if(authority.members.begin(), authority.members.end(), [&](const auto& candidate) {
      return candidate.containerUUID == plan.uuid;
    });
    if (member == authority.members.end() || member->machineUUID != state.machineUUID ||
        member->shardGroup != plan.shardGroup) return false;
    String digest = {};
    if (!prodigyStatefulServingRuntimeDigest(state, digest) || digest.equals(member->planSHA256) == false) return false;
    const bool advertised = plan.statefulMeshRoles.client != 0 &&
                            plan.advertisements.find(plan.statefulMeshRoles.client) != plan.advertisements.end();
    if (advertised != member->advertiseClient) return false;
    if (member->isSource == false &&
        prodigyStatefulServingApplicationConfigEqual(plan.config, authority.targetConfig) == false) return false;
    const StatefulTopology& topology = plan.statefulTopology;
    if (topology.shardGroup != member->shardGroup) return false;
    if (bootstrap) {
      const auto& binding = initial ? authority.initialAllMastersSeedBootstrap.bootstrap : authority.allMastersSeedBootstrap;
      // Bootstrap listeners use their serialized client advertisement. Private
      // listener declarations belong to applicationDataAuthority plans only.
      if (member->isSource || member->shardGroup != binding.shardGroup ||
          !prodigyStatefulTopologyIsAllMastersSeedBootstrap(topology) ||
          !(topology.allMastersSeedBootstrap == binding) ||
          !advertised || plan.advertisements.at(plan.statefulMeshRoles.client).port < 1024) return false;
      continue;
    }
    if (application) {
      const bool source = authority.dataAuthority.localClusterUUID == authority.dataAuthority.sourceClusterUUID;
      if (member->isSource != source || member->shardGroup != authority.dataAuthority.shardGroup ||
          !plan.declaredStatefulClientService || plan.declaredStatefulClientPort < 1024 ||
          topology.servingMode != StatefulTopologyServingMode::applicationDataAuthority ||
          !prodigyStatefulDataAuthorityEqual(topology.dataAuthority, authority.dataAuthority) ||
          !prodigyStatefulServingApplicationConfigEqual(plan.config, authority.targetConfig)) return false;
      auto clientAdvertisement = plan.advertisements.find(plan.declaredStatefulClientService);
      if ((clientAdvertisement != plan.advertisements.end()) != member->advertiseClient ||
          plan.statefulMeshRoles.client != (member->advertiseClient ? plan.declaredStatefulClientService : 0)) return false;
      if (clientAdvertisement != plan.advertisements.end() && clientAdvertisement->second.port != plan.declaredStatefulClientPort) return false;
      continue;
    }
    if (authority.phase == StatefulWorkerTopologyUpgradePhase::none)
    {
      if (member->isSource || topology.operationID != 0 || topology.topologyEpoch != authority.targetEpoch ||
          topology.sourceEpoch != authority.targetEpoch || topology.targetEpoch != authority.targetEpoch ||
          topology.servingMode != StatefulTopologyServingMode::serve ||
          topology.bridgeMode != StatefulTopologyBridgeMode::none) return false;
    }
    else if (topology.operationID != authority.operationID || topology.sourceEpoch != authority.sourceEpoch ||
             topology.targetEpoch != authority.targetEpoch ||
             topology.topologyEpoch != (member->isSource ? authority.sourceEpoch : authority.targetEpoch)) return false;
    if (authority.phase != StatefulWorkerTopologyUpgradePhase::none)
    {
      const bool blue = authority.phase == StatefulWorkerTopologyUpgradePhase::blueDraining;
      const auto mode = member->isSource
          ? (blue ? StatefulTopologyServingMode::drainOnly : StatefulTopologyServingMode::serve)
          : (blue ? StatefulTopologyServingMode::serve : StatefulTopologyServingMode::catchupOnly);
      const auto bridge = blue ? StatefulTopologyBridgeMode::targetToSource : StatefulTopologyBridgeMode::sourceToTarget;
      if (topology.servingMode != mode || topology.bridgeMode != bridge) return false;
    }
  }

  bytell_hash_set<uint32_t> groups;
  for (const auto& [shard, count] : sourceCounts) groups.insert(shard);
  for (const auto& [shard, count] : targetCounts) groups.insert(shard);
  for (uint32_t shard : groups)
  {
    const uint32_t sources = sourceCounts[shard], targets = targetCounts[shard];
    const uint32_t clients = authority.allMasters ? 3u : 1u;
    if (bootstrap) {
      if (sources != 0 || targets > 3) return false;
    }
    else if (application) {
      const bool source = authority.dataAuthority.localClusterUUID == authority.dataAuthority.sourceClusterUUID;
      const bool serving = authority.dataAuthority.mode == StatefulDataAuthorityMode::writeOwner ||
          (authority.dataAuthority.mode == StatefulDataAuthorityMode::retainedSource &&
           authority.dataAuthority.writeOwnerClusterUUID == authority.dataAuthority.localClusterUUID) ||
          authority.dataAuthority.mode == StatefulDataAuthorityMode::snapshotPreparing;
      if ((serving || source ? (source ? sources : targets) != 3 : targets > 3) || (source ? targets : sources) != 0 ||
          sourceClients[shard] + targetClients[shard] != (serving ? 1u : 0u)) return false;
    }
    else if (authority.phase == StatefulWorkerTopologyUpgradePhase::none)
    {
      if (sources != 0 || targets != 3 || targetClients[shard] != clients) return false;
    }
    else if (authority.phase == StatefulWorkerTopologyUpgradePhase::greenBootstrap)
    {
      // Initial bootstrap commits the existing serving cohort before creating
      // any target. A rollback binds both complete cohorts.
      if (sources != 3 || targets > 3 || sourceClients[shard] != clients || targetClients[shard] != 0)
        return false;
    }
    else if (sources != 3 || targets != 3 || sourceClients[shard] != 0 || targetClients[shard] != clients) return false;
  }
  return !groups.empty() && payloadUUIDs.size() == memberUUIDs.size();
}

// The caller has selected a healthy member in this exact authority scope.
// Change only its serving projection; data authority and sibling scopes stay
// immutable. Application targets reuse the listener installed before readiness.
static inline bool prodigyStatefulServingSelectClient(ProdigyStatefulServingAuthority& authority,
    Vector<BrainReplicatedContainerRuntimeState>& states, uint32_t shardGroup, uint128_t selectedUUID,
    uint64_t legacyClientService = 0, uint16_t legacyClientPort = 0)
{
  auto selected = std::find_if(authority.members.begin(), authority.members.end(), [&](const auto& member) {
    return member.shardGroup == shardGroup && member.containerUUID == selectedUUID;
  });
  if (selected == authority.members.end()) return false;
  const bool application = authority.phase == StatefulWorkerTopologyUpgradePhase::applicationDataAuthority;
  for (auto& state : states) {
    if (!prodigyStatefulServingAuthorityMatchesShard(authority, state.plan.config.deploymentID(), state.plan.shardGroup)) return false;
    if (state.plan.shardGroup != shardGroup) continue;
    const uint64_t client = application ? state.plan.declaredStatefulClientService : legacyClientService;
    const uint16_t port = application ? state.plan.declaredStatefulClientPort : legacyClientPort;
    if (!client || port < 1024) return false;
    if (state.plan.uuid == selectedUUID) {
      state.plan.statefulMeshRoles.client = client;
      state.plan.advertisements.insert_or_assign(client, Advertisement(client, ContainerState::healthy, ContainerState::destroying, port));
    } else {
      state.plan.advertisements.erase(client); state.plan.advertisementPairings.map.erase(client);
      if (application) state.plan.statefulMeshRoles.client = 0;
    }
    for (auto& member : authority.members)
      if (member.containerUUID == state.plan.uuid) {
        member.advertiseClient = state.plan.uuid == selectedUUID;
        if (!prodigyStatefulServingRuntimeDigest(state, member.planSHA256)) return false;
      }
  }
  return prodigyValidateStatefulServingAuthority(authority, states, authority.revision);
}

static inline bool prodigyValidateStatefulServingAuthorities(
    const Vector<ProdigyStatefulServingAuthority>& authorities,
    const Vector<BrainReplicatedContainerRuntimeState>& payload,
    uint64_t generation)
{
  bytell_hash_set<uint128_t> payloadUUIDs = {};
  for (const BrainReplicatedContainerRuntimeState& state : payload)
  {
    if (state.plan.uuid == 0 || payloadUUIDs.insert(state.plan.uuid).second == false) return false;
  }
  bytell_hash_set<uint128_t> covered;
  for (uint32_t index = 0; index < authorities.size(); ++index)
  {
    const auto& authority = authorities[index];
    for (uint32_t prior = 0; prior < index; ++prior)
      if (prodigyStatefulServingAuthoritySameScope(authorities[prior], authority)) return false;
    Vector<BrainReplicatedContainerRuntimeState> states;
    for (const auto& state : payload) {
      if (!prodigyStatefulServingAuthorityMatchesShard(authority, state.plan.config.deploymentID(), state.plan.shardGroup)) continue;
      if (!covered.insert(state.plan.uuid).second) return false;
      states.push_back(state);
    }
    if (!prodigyValidateStatefulServingAuthority(authority, states, generation)) return false;
  }
  return covered.size() == payloadUUIDs.size();
}
