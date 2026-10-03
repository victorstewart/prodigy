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

static inline bool prodigyValidateStatefulServingAuthority(
    const ProdigyStatefulServingAuthority& authority,
    const Vector<BrainReplicatedContainerRuntimeState>& payload,
    uint64_t generation)
{
  if (authority.deploymentID == 0 || authority.applicationID == 0 || authority.revision == 0 ||
      authority.revision > generation || authority.targetConfig.deploymentID() != authority.deploymentID ||
      authority.targetConfig.applicationID != authority.applicationID || authority.members.empty() ||
      uint8_t(authority.phase) > uint8_t(StatefulWorkerTopologyUpgradePhase::blueDraining)) return false;

  if ((authority.phase == StatefulWorkerTopologyUpgradePhase::none &&
       (authority.operationID == 0 || authority.sourceEpoch == 0 || authority.targetEpoch == 0)) ||
      (authority.phase != StatefulWorkerTopologyUpgradePhase::none &&
       (authority.operationID == 0 || authority.sourceEpoch == 0 || authority.targetEpoch == 0 ||
        authority.sourceEpoch == authority.targetEpoch))) return false;
  if (payload.size() != authority.members.size()) return false;

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
    if (authority.phase == StatefulWorkerTopologyUpgradePhase::none)
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

static inline bool prodigyValidateStatefulServingAuthorities(
    const Vector<ProdigyStatefulServingAuthority>& authorities,
    const Vector<BrainReplicatedContainerRuntimeState>& payload,
    uint64_t generation)
{
  bytell_hash_set<uint64_t> deployments = {};
  bytell_hash_set<uint128_t> payloadUUIDs = {};
  bytell_hash_map<uint64_t, Vector<BrainReplicatedContainerRuntimeState>> byDeployment = {};
  for (const BrainReplicatedContainerRuntimeState& state : payload)
  {
    if (state.plan.uuid == 0 || payloadUUIDs.insert(state.plan.uuid).second == false) return false;
    byDeployment[state.plan.config.deploymentID()].push_back(state);
  }
  for (const ProdigyStatefulServingAuthority& authority : authorities)
  {
    auto states = byDeployment.find(authority.deploymentID);
    if (deployments.insert(authority.deploymentID).second == false ||
        states == byDeployment.end() ||
        prodigyValidateStatefulServingAuthority(authority, states->second, generation) == false) return false;
  }
  return byDeployment.size() == authorities.size();
}
