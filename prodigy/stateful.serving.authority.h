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
      uint8_t(authority.phase) > uint8_t(StatefulWorkerTopologyUpgradePhase::applicationDataAuthority)) return false;
  const bool application = authority.phase == StatefulWorkerTopologyUpgradePhase::applicationDataAuthority;
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
      (!application && authority.phase != StatefulWorkerTopologyUpgradePhase::none &&
       (authority.operationID == 0 || authority.sourceEpoch == 0 || authority.targetEpoch == 0 ||
        authority.sourceEpoch == authority.targetEpoch))) return false;
  if (payload.size() != authority.members.size()) return false;
  if (authority.sourceRetired && (!application ||
      (!prodigyStatefulDataAuthoritySourceNonwriter(authority.dataAuthority) && authority.dataAuthority.mode != StatefulDataAuthorityMode::catchupOnly) ||
      !authority.members.empty())) return false;
  if (authority.members.empty()) return application &&
      (authority.dataAuthority.mode == StatefulDataAuthorityMode::catchupOnly || authority.sourceRetired);

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
    if (application) {
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
