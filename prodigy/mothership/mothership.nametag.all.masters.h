#pragma once

// Durable desired state for Nametag's three-site multi-writer stores.  This is
// deliberately not a ProductionPair: no member is selected, drained, fenced,
// or retired by this record.

#include <prodigy/types.h>
#include <prodigy/cousin.discovery.h>
#include <prodigy/cousin.route.h>
#include <prodigy/cousin.service.permission.h>
#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/persistent.state.h>
#include <simdjson.h>
#include <string_view>

class MothershipNametagAllMastersSite {
public:
  uint128_t clusterUUID = 0;
  uint64_t pulseDeploymentID = 0;
  uint64_t hotDeploymentID = 0;
  uint64_t coldDeploymentID = 0;
  uint64_t radarDeploymentID = 0;
  uint64_t truthDeploymentID = 0;
  uint64_t app6DeploymentID = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipNametagAllMastersSite& value)
{
  serializer.value16b(value.clusterUUID); serializer.value8b(value.pulseDeploymentID);
  serializer.value8b(value.hotDeploymentID); serializer.value8b(value.coldDeploymentID);
  serializer.value8b(value.radarDeploymentID); serializer.value8b(value.truthDeploymentID); serializer.value8b(value.app6DeploymentID);
}

struct MothershipNametagSeedRouteReference {
  uint8_t site = 0;
  uint16_t applicationID = 0;
  uint32_t shardGroup = 0;
  uint128_t routeUUID = 0;
};
template <typename S> static void serialize(S&& serializer, MothershipNametagSeedRouteReference& value) {
  serializer.value1b(value.site); serializer.value2b(value.applicationID);
  serializer.value4b(value.shardGroup); serializer.value16b(value.routeUUID);
}

struct MothershipNametagSourceRepairPlan {
  uint16_t applicationID = 0;
  uint64_t previousDeploymentID = 0, successorDeploymentID = 0;
  String normalizedPlan, planSHA256, artifactSHA256;
  uint64_t artifactBytes = 0;
  DeploymentIdentityReport predecessor;
};
template <typename S> static void serialize(S&& s, MothershipNametagSourceRepairPlan& v) {
  s.value2b(v.applicationID); s.value8b(v.previousDeploymentID); s.value8b(v.successorDeploymentID);
  s.text1b(v.normalizedPlan, 1024 * 1024); s.text1b(v.planSHA256, 64); s.text1b(v.artifactSHA256, 64);
  s.value8b(v.artifactBytes); s.object(v.predecessor);
}
static inline bool mothershipNametagSourceRepairPlanValid(const MothershipNametagSourceRepairPlan& value);

class MothershipNametagAllMastersIntent {
public:
  static constexpr uint32_t version = 4;
  static constexpr uint32_t sourceCutVersion = 5;
  static constexpr uint32_t seedRouteVersion = 6;
  static constexpr uint32_t expiredCutRecoveryVersion = 7;
  static constexpr uint32_t radarExpiredCutRecoveryVersion = 8;
  uint32_t protocolVersion = version;
  constexpr bool isExpiredCutRecovery() const {
    return protocolVersion == expiredCutRecoveryVersion || protocolVersion == radarExpiredCutRecoveryVersion;
  }
  uint128_t operationUUID = 0;
  uint128_t sourceBaselineOperationUUID = 0;
  // Canonical site order is EWR, ORD, LAN.  Truth is populated only at EWR.
  Vector<MothershipNametagAllMastersSite> sites;
  // Three durable paths for each direct site pair name both local ends: 18
  // authorities total.  Mothership re-loads each exact record and obtains a
  // fresh authenticated readiness receipt before it delivers any seed.
  Vector<CrossClusterMasqueGatewayAuthority> directGatewayAuthorities;
  Vector<MothershipNametagSeedRouteReference> seedRoutes;
  // A new management run retains the original remote bootstrap seed identity.
  // Native preparation fills these witnesses before normal source deployment.
  uint128_t predecessorOperationUUID = 0;
  String predecessorRecordSHA256, initialSeedRecordSHA256, predecessorBaselineSHA256;
  Vector<MothershipNametagSourceRepairPlan> sourceRepairPlans;
};

// Initial remote launches are journaled before installing any bootstrap fence
// or sending a deployment request. The normalized plan bytes remain the owner
// of the plan identity on every retry.
struct MothershipNametagInitialSeedPlan {
  uint8_t site = 0;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  String normalizedPlan, planSHA256, artifactPath, artifactSHA256;
  uint64_t artifactBytes = 0;
  uint32_t nShardGroups = 0;
};
template <typename S> static void serialize(S&& s, MothershipNametagInitialSeedPlan& v) {
  s.value1b(v.site); s.value2b(v.applicationID); s.value8b(v.deploymentID);
  s.text1b(v.normalizedPlan, 1024 * 1024); s.text1b(v.planSHA256, 64);
  s.text1b(v.artifactPath, 4096); s.text1b(v.artifactSHA256, 64);
  s.value8b(v.artifactBytes); s.value4b(v.nShardGroups);
}
struct MothershipNametagInitialSeedRecord {
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0, baselineOperationUUID = 0;
  String intentBytes, intentSHA256, baselineReceiptSHA256;
  Vector<MothershipNametagInitialSeedPlan> plans;
  uint8_t dispatchMask = 0, completedMask = 0;
};
template <typename S> static void serialize(S&& s, MothershipNametagInitialSeedRecord& v) {
  s.value4b(v.protocolVersion); s.value16b(v.operationUUID); s.value16b(v.baselineOperationUUID);
  s.text1b(v.intentBytes, 1024 * 1024); s.text1b(v.intentSHA256, 64); s.text1b(v.baselineReceiptSHA256, 64);
  s.container(v.plans, 8); s.value1b(v.dispatchMask); s.value1b(v.completedMask);
}

// Preparation starts from stable caller-owned names and enrollment operation
// identities. Cluster and pair UUIDs are allocated by Mothership, so callers
// must never predict them in a pre-provisioning JSON file.
struct MothershipNametagAllMastersPreparation {
  MothershipNametagAllMastersIntent intent;
  Vector<String> siteNames;
  Vector<uint128_t> pairOperationUUIDs;
  Vector<uint16_t> sourceRepairApplications;
  Vector<String> sourceRepairPlanPaths, sourceRepairArtifactPaths;
};

static inline bool mothershipParseNametagAllMastersPreparationJSON(
    simdjson::dom::element document, MothershipNametagAllMastersPreparation& output,
    String& failure)
{
  output = {};
  failure.clear();
  const auto reject = [&]() {
    output = {};
    failure.assign("invalid all-masters preparation: require exact canonical fields, EWR/ORD/LAN site names and three distinct pair operations"_ctv);
    return false;
  };
  const auto uuid = [](simdjson::dom::element value, uint128_t& result) {
    std::string_view text;
    if (value.get(text) != simdjson::SUCCESS) return false;
    String input; input.setInvariant(text.data(), text.size());
    return prodigyParseCanonicalHex128(input, result);
  };
  if (document.type() != simdjson::dom::element_type::OBJECT) return reject();
  constexpr std::string_view names[] = {"schema", "operationUUID", "sites", "pairOperationUUIDs", "sourceBaselineOperationUUID", "seedRoutes",
    "predecessorOperationUUID", "predecessorRecordSHA256", "sourceRepairPlans"};
  uint32_t seen = 0;
  for (auto field : document.get_object()) {
    uint32_t index = 0;
    while (index < std::size(names) && names[index] != field.key) ++index;
    if (index == std::size(names) || (seen & (1u << index))) return reject();
    seen |= 1u << index;
    if (index == 0) {
      std::string_view schema;
      if (field.value.get(schema) != simdjson::SUCCESS) return reject();
      if (schema == "mothership.nametag-all-masters.prepare.v6") output.intent.protocolVersion = MothershipNametagAllMastersIntent::radarExpiredCutRecoveryVersion;
      else if (schema == "mothership.nametag-all-masters.prepare.v5") output.intent.protocolVersion = MothershipNametagAllMastersIntent::expiredCutRecoveryVersion;
      else if (schema == "mothership.nametag-all-masters.prepare.v4") output.intent.protocolVersion = MothershipNametagAllMastersIntent::seedRouteVersion;
      else if (schema == "mothership.nametag-all-masters.prepare.v3") output.intent.protocolVersion = MothershipNametagAllMastersIntent::sourceCutVersion;
      else if (schema != "mothership.nametag-all-masters.prepare.v2") return reject();
    } else if (index == 1) {
      if (!uuid(field.value, output.intent.operationUUID)) return reject();
    } else if (index == 2) {
      if (field.value.type() != simdjson::dom::element_type::ARRAY) return reject();
      for (auto entry : field.value.get_array()) {
        if (output.intent.sites.size() >= 3 || entry.type() != simdjson::dom::element_type::OBJECT) return reject();
        auto& site = output.intent.sites.emplace_back();
        auto& siteName = output.siteNames.emplace_back();
        constexpr std::string_view siteNames[] = {"clusterName", "pulseDeploymentID", "hotDeploymentID",
          "coldDeploymentID", "radarDeploymentID", "truthDeploymentID", "app6DeploymentID"};
        uint64_t *deployments[] = {&site.pulseDeploymentID, &site.hotDeploymentID, &site.coldDeploymentID,
          &site.radarDeploymentID, &site.truthDeploymentID, &site.app6DeploymentID};
        uint32_t siteSeen = 0;
        for (auto item : entry.get_object()) {
          uint32_t key = 0;
          while (key < std::size(siteNames) && siteNames[key] != item.key) ++key;
          if (key == std::size(siteNames) || (siteSeen & (1u << key))) return reject();
          siteSeen |= 1u << key;
          if (key == 0) {
            std::string_view name;
            if (item.value.get(name) != simdjson::SUCCESS || name.empty()) return reject();
            siteName.assign(name.data(), name.size());
          }
          else if (item.value.get(*deployments[key - 1]) != simdjson::SUCCESS) return reject();
        }
        if (siteSeen != 127 || site.pulseDeploymentID == 0 || site.hotDeploymentID == 0 ||
            site.coldDeploymentID == 0 || site.radarDeploymentID == 0 || site.app6DeploymentID == 0 ||
            ((output.intent.sites.size() == 1) != (site.truthDeploymentID != 0))) return reject();
        for (uint32_t prior = 0; prior + 1 < output.siteNames.size(); ++prior)
          if (output.siteNames[prior].equal(siteName)) return reject();
      }
    } else if (index == 3) {
      if (field.value.type() != simdjson::dom::element_type::ARRAY) return reject();
      for (auto entry : field.value.get_array()) {
        if (output.pairOperationUUIDs.size() >= 3) return reject();
        uint128_t operationUUID = 0;
        if (!uuid(entry, operationUUID) || operationUUID == 0) return reject();
        for (const auto prior : output.pairOperationUUIDs)
          if (prior == operationUUID) return reject();
        output.pairOperationUUIDs.push_back(operationUUID);
      }
    } else if (index == 4) {
      if (!uuid(field.value, output.intent.sourceBaselineOperationUUID)) return reject();
    } else if (index == 5) {
      if (field.value.type() != simdjson::dom::element_type::ARRAY) return reject();
      for (auto entry : field.value.get_array()) {
        if (output.intent.seedRoutes.size() >= 16 || entry.type() != simdjson::dom::element_type::OBJECT) return reject();
        MothershipNametagSeedRouteReference reference = {}; uint32_t fields = 0;
        for (auto item : entry.get_object()) {
          uint32_t bit = item.key == "site" ? 1 : item.key == "applicationID" ? 2 :
              item.key == "shardGroup" ? 4 : item.key == "routeUUID" ? 8 : 0;
          if (!bit || (fields & bit)) return reject(); fields |= bit;
          if (bit == 8) { if (!uuid(item.value, reference.routeUUID) || !reference.routeUUID) return reject(); }
          else { uint64_t n = 0; if (item.value.get(n) != simdjson::SUCCESS || n > UINT32_MAX) return reject();
            if (bit == 1) { if (n > UINT8_MAX) return reject(); reference.site = uint8_t(n); }
            else if (bit == 2) { if (n > UINT16_MAX) return reject(); reference.applicationID = uint16_t(n); }
            else reference.shardGroup = uint32_t(n);
          }
        }
        if (fields != 15) return reject(); output.intent.seedRoutes.push_back(reference);
      }
    } else if (index == 6) {
      if (!uuid(field.value, output.intent.predecessorOperationUUID) || !output.intent.predecessorOperationUUID) return reject();
    } else if (index == 7) {
      std::string_view digest;
      if (field.value.get(digest) != simdjson::SUCCESS) return reject();
      output.intent.predecessorRecordSHA256.assign(digest.data(), digest.size());
      if (!prodigyIsSHA256HexDigest(output.intent.predecessorRecordSHA256)) return reject();
    } else {
      simdjson::dom::array plans;
      if (field.value.get(plans) != simdjson::SUCCESS || (plans.size() != 1 && plans.size() != 2)) return reject();
      for (auto entry : plans) {
        simdjson::dom::object object; uint64_t app = 0; std::string_view plan, artifact;
        if (entry.get(object) || object.size() != 3 || object["applicationID"].get(app) || (app != 3 && app != 4 && app != MeshRegistry::Radar::applicationID) ||
            object["plan"].get(plan) || plan.size() < 3 || plan.size() > 4096 || plan[0] != '@' || plan[1] != '/' ||
            object["artifact"].get(artifact) || artifact.empty() || artifact.size() > 4096 || artifact[0] != '/' ||
            std::find(output.sourceRepairApplications.begin(), output.sourceRepairApplications.end(), uint16_t(app)) != output.sourceRepairApplications.end()) return reject();
        output.sourceRepairApplications.push_back(uint16_t(app));
        output.sourceRepairPlanPaths.emplace_back().assign(plan.data(), plan.size());
        output.sourceRepairArtifactPaths.emplace_back().assign(artifact.data(), artifact.size());
      }
    }
  }
  if (output.intent.isExpiredCutRecovery()) {
    const auto& apps = output.sourceRepairApplications;
    if (output.intent.protocolVersion == MothershipNametagAllMastersIntent::radarExpiredCutRecoveryVersion) {
      if (apps.size() != 1 || apps[0] != MeshRegistry::Radar::applicationID) return reject();
    } else if (apps.size() != 2 || std::count(apps.begin(), apps.end(), uint16_t(3)) != 1 ||
               std::count(apps.begin(), apps.end(), uint16_t(4)) != 1) return reject();
  }
  return ((seen == 15 && output.intent.protocolVersion == MothershipNametagAllMastersIntent::version) ||
          ((seen == 31 && output.intent.protocolVersion == MothershipNametagAllMastersIntent::sourceCutVersion ||
            seen == 63 && output.intent.protocolVersion == MothershipNametagAllMastersIntent::seedRouteVersion ||
            seen == 511 && output.intent.isExpiredCutRecovery()) &&
           output.intent.sourceBaselineOperationUUID != 0)) && output.intent.operationUUID != 0 && output.intent.sites.size() == 3 &&
      output.siteNames.size() == 3 && output.pairOperationUUIDs.size() == 3 ? true : reject();
}

// Mothership, rather than a caller, selects every seed edge after it has
// authenticated the live deployment reports.  There are four logical stores
// (Pulse, Hot, Cold, Radar), with 1 + 3 + 3 + 1 shard groups respectively,
// across the later ORD/LAN sites and three replicas: exactly 48 rows.  EWR is
// the populated baseline and is never instructed to seed itself. Keeping the target
// identity in the row prevents a later reschedule from silently inheriting a
// seed receipt for a different process.
class MothershipNametagAllMastersSeedPlacement {
public:
  uint8_t site = UINT8_MAX;
  // Store kind is intentionally coarse for native lifecycle routing.  The
  // exact application identity prevents Hot/Cold and Pulse/Radar swaps.
  uint16_t applicationID = 0;
  DeploymentIdentityStoreKind storeKind = DeploymentIdentityStoreKind::unknown;
  uint32_t shardGroup = UINT32_MAX;
  uint128_t targetClusterUUID = 0;
  uint64_t targetDeploymentID = 0;
  uint128_t targetContainerUUID = 0;
  uint128_t sourceClusterUUID = 0;
  uint64_t sourceDeploymentID = 0;
  uint128_t sourceContainerUUID = 0;
  uint64_t seedGeneration = 0;
  // Historic authority fields remain for old store compatibility. They are
  // never interpreted as the EWR source-content proof.
  String fixtureSHA256;
  String expectedCatchupWatermarkSHA256;
  // v6 carries the native source boundary separately from legacy fixture
  // fields. Only these values authorize an EWR-to-remote seed.
  String sourceContentWatermarkSHA256;
  String sourceCatchupWatermarkSHA256;
  bool deliveryApplied = false;
  bool catchupObserved = false;
  ProdigyStatefulStoreReceipt nativeSourceCutReceipt = {.protocolVersion = 0};
  uint128_t qualificationRunUUID = 0, qualificationChallengeUUID = 0;
  uint64_t qualificationExecutionGeneration = 0;
  int64_t qualificationDeadlineAtMilliseconds = 0;
  bool deliveryDispatched = false;
};

template <typename S>
static void serializeMothershipNametagAllMastersSeedPlacement(S&& serializer,
    MothershipNametagAllMastersSeedPlacement& value, uint32_t recordVersion)
{
  serializer.value1b(value.site);
  if (recordVersion >= 3) serializer.value2b(value.applicationID);
  serializer.value1b(value.storeKind); serializer.value4b(value.shardGroup);
  serializer.value16b(value.targetClusterUUID); serializer.value8b(value.targetDeploymentID); serializer.value16b(value.targetContainerUUID);
  serializer.value16b(value.sourceClusterUUID); serializer.value8b(value.sourceDeploymentID); serializer.value16b(value.sourceContainerUUID);
  serializer.value8b(value.seedGeneration); serializer.text1b(value.fixtureSHA256, 64);
  serializer.text1b(value.expectedCatchupWatermarkSHA256, 64);
  if (recordVersion >= 5) { serializer.value1b(value.deliveryApplied); serializer.value1b(value.catchupObserved); }
  if (recordVersion >= 6) {
    serializer.text1b(value.sourceContentWatermarkSHA256, 64);
    serializer.text1b(value.sourceCatchupWatermarkSHA256, 64);
  }
  if (recordVersion >= 7) serializer.object(value.nativeSourceCutReceipt);
  if (recordVersion >= 8) {
    serializer.value16b(value.qualificationRunUUID); serializer.value16b(value.qualificationChallengeUUID);
    serializer.value8b(value.qualificationExecutionGeneration); serializer.value8b(value.qualificationDeadlineAtMilliseconds);
    serializer.value1b(value.deliveryDispatched);
  }
}

template <typename S>
static void serialize(S&& serializer, MothershipNametagAllMastersIntent& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.container(value.sites, 3);
  serializer.container(value.directGatewayAuthorities, 18,
      [](auto& nested, CrossClusterMasqueGatewayAuthority& authority) { nested.object(authority); });
  if (value.protocolVersion >= MothershipNametagAllMastersIntent::sourceCutVersion)
    serializer.value16b(value.sourceBaselineOperationUUID);
  if (value.protocolVersion >= MothershipNametagAllMastersIntent::seedRouteVersion)
    serializer.container(value.seedRoutes, 16, [](auto& nested, MothershipNametagSeedRouteReference& reference) { nested.object(reference); });
  if (value.protocolVersion >= MothershipNametagAllMastersIntent::expiredCutRecoveryVersion) {
    serializer.value16b(value.predecessorOperationUUID); serializer.text1b(value.predecessorRecordSHA256, 64);
    serializer.text1b(value.initialSeedRecordSHA256, 64); serializer.text1b(value.predecessorBaselineSHA256, 64);
    serializer.container(value.sourceRepairPlans, 2);
  }
}

static inline bool mothershipNametagAllMastersSiteIdentityMatches(uint32_t site,
    uint128_t expectedClusterUUID, const MothershipProdigyCluster& cluster)
{
  // Names are operator labels, not geographic authority.  In particular, the
  // retained LAN and each newly created cloud cluster have unique run names.
  if (expectedClusterUUID == 0 || cluster.clusterUUID != expectedClusterUUID) return false;
  if (site < 2)
    return cluster.deploymentMode == MothershipClusterDeploymentMode::remote &&
        cluster.provider == MothershipClusterProvider::vultr &&
        (site == 0 ? cluster.providerScope == "ewr"_ctv : cluster.providerScope == "ord"_ctv);
  return site == 2 && cluster.deploymentMode == MothershipClusterDeploymentMode::local &&
      cluster.provider == MothershipClusterProvider::unknown && cluster.providerScope.empty();
}

static inline bool mothershipNametagAllMastersPreparedSiteMatches(uint32_t site,
    const String& expectedName, const MothershipProdigyCluster& cluster)
{
  return !expectedName.empty() && cluster.name.equal(expectedName) &&
      mothershipNametagAllMastersSiteIdentityMatches(site, cluster.clusterUUID, cluster) &&
      cluster.nBrains == 3 && cluster.topology.machines.size() == 3;
}

static inline bool mothershipNametagAllMastersDirectGatewayTopologyValid(
    const MothershipNametagAllMastersIntent& intent)
{
  if (intent.directGatewayAuthorities.size() != 18) return false;
  const CrossClusterMasqueGatewayAuthority *directions[3][3][3] = {};
  uint128_t siteMachines[3][3] = {};
  uint32_t machineAuthorityCounts[3][3] = {};
  for (const auto& authority : intent.directGatewayAuthorities) {
    if (authority.state != CrossClusterMasqueGatewayState::active || authority.pairUUID == 0 ||
        authority.pairOperationUUID == 0 || authority.localMachineUUID == 0 || authority.peerMachineUUID == 0 ||
        authority.localMachineUUID == authority.peerMachineUUID || authority.localClusterUUID == authority.peerClusterUUID ||
        authority.tunnelSlot >= 3 || authority.gatewaySlot != authority.tunnelSlot) return false;
    uint32_t pairAuthorities = 0;
    for (const auto& other : intent.directGatewayAuthorities) {
      if (other.pairUUID == authority.pairUUID) {
        if (other.pairOperationUUID != authority.pairOperationUUID ||
            !((other.localClusterUUID == authority.localClusterUUID && other.peerClusterUUID == authority.peerClusterUUID) ||
              (other.localClusterUUID == authority.peerClusterUUID && other.peerClusterUUID == authority.localClusterUUID))) return false;
        ++pairAuthorities;
      }
      if (&other != &authority && other.pairOperationUUID == authority.pairOperationUUID &&
          other.pairUUID != authority.pairUUID) return false;
    }
    // One enrolled site pair owns three reciprocal tunnel slots: three local
    // authorities at each end, all bound to the enrollment's one pair UUID.
    if (pairAuthorities != 6) return false;
    uint32_t local = UINT32_MAX, peer = UINT32_MAX;
    for (uint32_t site = 0; site < 3; ++site) {
      if (intent.sites[site].clusterUUID == authority.localClusterUUID) local = site;
      if (intent.sites[site].clusterUUID == authority.peerClusterUUID) peer = site;
    }
    if (local == UINT32_MAX || peer == UINT32_MAX || local == peer || directions[local][peer][authority.tunnelSlot] != nullptr) return false;
    directions[local][peer][authority.tunnelSlot] = &authority;
    uint128_t& machine = siteMachines[local][authority.gatewaySlot];
    if (machine != 0 && machine != authority.localMachineUUID) return false;
    for (uint32_t site = 0; site < 3; ++site) for (uint32_t slot = 0; slot < 3; ++slot)
      if ((site != local || slot != authority.gatewaySlot) && siteMachines[site][slot] == authority.localMachineUUID) return false;
    machine = authority.localMachineUUID;
    if (++machineAuthorityCounts[local][authority.gatewaySlot] > 2) return false;
  }
  for (uint32_t left = 0; left < 3; ++left) for (uint32_t right = left + 1; right < 3; ++right) {
    for (uint32_t path = 0; path < 3; ++path) {
      const auto *forward = directions[left][right][path];
      const auto *reverse = directions[right][left][path];
      if (forward == nullptr || reverse == nullptr || forward->pairUUID != reverse->pairUUID ||
          forward->pairOperationUUID != reverse->pairOperationUUID ||
          forward->localMachineUUID != reverse->peerMachineUUID || forward->peerMachineUUID != reverse->localMachineUUID ||
          forward->tunnelSlot != reverse->tunnelSlot) return false;
    }
  }
  for (uint32_t site = 0; site < 3; ++site) for (uint32_t slot = 0; slot < 3; ++slot)
    if (siteMachines[site][slot] == 0 || machineAuthorityCounts[site][slot] != 2) return false;
  return true;
}

static inline bool mothershipNametagAllMastersIntentValid(const MothershipNametagAllMastersIntent& intent)
{
  if ((intent.protocolVersion != MothershipNametagAllMastersIntent::version &&
       intent.protocolVersion != MothershipNametagAllMastersIntent::sourceCutVersion &&
       intent.protocolVersion != MothershipNametagAllMastersIntent::seedRouteVersion &&
       !intent.isExpiredCutRecovery()) ||
      (intent.protocolVersion >= MothershipNametagAllMastersIntent::sourceCutVersion && intent.sourceBaselineOperationUUID == 0) ||
      (intent.protocolVersion == MothershipNametagAllMastersIntent::version && intent.sourceBaselineOperationUUID != 0) ||
      intent.operationUUID == 0 ||
      intent.sites.size() != 3) return false;
  for (uint32_t site = 0; site < intent.sites.size(); ++site) {
    const auto& value = intent.sites[site];
    if (value.clusterUUID == 0 || value.pulseDeploymentID == 0 || value.hotDeploymentID == 0 ||
        value.coldDeploymentID == 0 || value.radarDeploymentID == 0 || value.app6DeploymentID == 0 ||
        ((site == 0) != (value.truthDeploymentID != 0))) return false;
    const uint64_t deploymentIDs[] = {value.pulseDeploymentID, value.hotDeploymentID, value.coldDeploymentID,
                                      value.radarDeploymentID, value.app6DeploymentID, value.truthDeploymentID};
    for (uint32_t left = 0; left < (site == 0 ? 6u : 5u); ++left)
      for (uint32_t right = 0; right < left; ++right)
        if (deploymentIDs[left] == deploymentIDs[right]) return false;
    for (uint32_t other = 0; other < site; ++other)
      if (intent.sites[other].clusterUUID == value.clusterUUID) return false;
  }
  if (intent.protocolVersion >= MothershipNametagAllMastersIntent::seedRouteVersion) {
    if (intent.seedRoutes.size() != 16) return false;
    for (uint32_t i = 0; i < intent.seedRoutes.size(); ++i) {
      const auto& route = intent.seedRoutes[i];
      if (route.site < 1 || route.site > 2 || route.routeUUID == 0 ||
          ((route.applicationID == 3 || route.applicationID == 4) ? route.shardGroup >= 3 :
           (route.applicationID != 2 && route.applicationID != 5) || route.shardGroup != 0)) return false;
      for (uint32_t j = 0; j < i; ++j)
        if (intent.seedRoutes[j].routeUUID == route.routeUUID ||
            (intent.seedRoutes[j].site == route.site && intent.seedRoutes[j].applicationID == route.applicationID &&
             intent.seedRoutes[j].shardGroup == route.shardGroup)) return false;
    }
  } else if (!intent.seedRoutes.empty()) return false;
  if (intent.protocolVersion == MothershipNametagAllMastersIntent::expiredCutRecoveryVersion ||
      intent.protocolVersion == MothershipNametagAllMastersIntent::radarExpiredCutRecoveryVersion) {
    const bool radarOnly = intent.protocolVersion == MothershipNametagAllMastersIntent::radarExpiredCutRecoveryVersion;
    if (!intent.predecessorOperationUUID || intent.predecessorOperationUUID == intent.operationUUID ||
        !prodigyIsSHA256HexDigest(intent.predecessorRecordSHA256) || !prodigyIsSHA256HexDigest(intent.initialSeedRecordSHA256) ||
        !prodigyIsSHA256HexDigest(intent.predecessorBaselineSHA256) || intent.sourceRepairPlans.size() != (radarOnly ? 1 : 2)) return false;
    for (size_t i = 0; i < intent.sourceRepairPlans.size(); ++i) {
      const auto& plan = intent.sourceRepairPlans[i];
      const uint16_t app = radarOnly ? MeshRegistry::Radar::applicationID : uint16_t(i + 3);
      const uint64_t deployment = radarOnly ? intent.sites[0].radarDeploymentID : (i ? intent.sites[0].coldDeploymentID : intent.sites[0].hotDeploymentID);
      if (plan.applicationID != app || !mothershipNametagSourceRepairPlanValid(plan) ||
          plan.predecessor.clusterUUID != intent.sites[0].clusterUUID || plan.successorDeploymentID != deployment) return false;
    }
  } else if (intent.predecessorOperationUUID || !intent.predecessorRecordSHA256.empty() || !intent.initialSeedRecordSHA256.empty() ||
             !intent.predecessorBaselineSHA256.empty() || !intent.sourceRepairPlans.empty()) return false;
  return mothershipNametagAllMastersDirectGatewayTopologyValid(intent);
}

static inline bool mothershipNametagInitialSeedRecordValid(const MothershipNametagInitialSeedRecord& record) {
  MothershipNametagAllMastersIntent intent = {}; String digest;
  if (record.protocolVersion != record.version || !record.operationUUID || !record.baselineOperationUUID ||
      record.intentBytes.empty() || !prodigyIsSHA256HexDigest(record.intentSHA256) ||
      !prodigyIsSHA256HexDigest(record.baselineReceiptSHA256) || record.plans.size() != 8 ||
      (record.completedMask & ~record.dispatchMask) || !BitseryEngine::deserializeSafe(record.intentBytes, intent) ||
      !mothershipNametagAllMastersIntentValid(intent) || intent.protocolVersion != intent.seedRouteVersion ||
      intent.operationUUID != record.operationUUID || intent.sourceBaselineOperationUUID != record.baselineOperationUUID ||
      !prodigyComputeSHA256Hex(record.intentBytes, digest) || digest != record.intentSHA256) return false;
  for (size_t i = 0; i < record.plans.size(); ++i) {
    const auto& item = record.plans[i]; DeploymentPlan plan = {}; String planDigest;
    if (item.site < 1 || item.site > 2 || (item.applicationID != 2 && item.applicationID != 3 && item.applicationID != 4 && item.applicationID != 5) ||
        item.nShardGroups != (item.applicationID == 3 || item.applicationID == 4 ? 3u : 1u) || item.artifactPath.empty() || item.artifactPath[0] != '/' ||
        !prodigyIsSHA256HexDigest(item.planSHA256) || !prodigyIsSHA256HexDigest(item.artifactSHA256) || !item.artifactBytes ||
        !BitseryEngine::deserializeSafe(item.normalizedPlan, plan) || !prodigyComputeSHA256Hex(item.normalizedPlan, planDigest) || planDigest != item.planSHA256 ||
        !plan.isStateful || plan.config.type != ApplicationType::stateful || !plan.stateful.allMasters || plan.useHostNetworkNamespace ||
        !plan.horizontalScalers.empty() || !plan.verticalScalers.empty() || plan.canaryCount || plan.canariesMustLiveForMinutes ||
        !plan.wormholes.empty() || !plan.whiteholes.empty() || plan.config.applicationID != item.applicationID ||
        plan.config.deploymentID() != item.deploymentID || plan.config.containerBlobSHA256 != item.artifactSHA256 || plan.config.containerBlobBytes != item.artifactBytes) return false;
    const auto& site = intent.sites[item.site];
    const uint64_t expected = item.applicationID == 2 ? site.pulseDeploymentID : item.applicationID == 3 ? site.hotDeploymentID :
        item.applicationID == 4 ? site.coldDeploymentID : site.radarDeploymentID;
    if (item.deploymentID != expected) return false;
    for (size_t j = 0; j < i; ++j) if (record.plans[j].site == item.site && record.plans[j].applicationID == item.applicationID) return false;
  }
  return true;
}

static inline bool mothershipNametagAllMastersTruthDeploymentCardinalityObserved(const ClusterStatusReport& report,
    bool expectOne)
{
  uint32_t count = 0;
  for (const auto& application : report.applicationReports)
    if (application.applicationID == MeshRegistry::Truth::applicationID) count += application.deploymentReports.size();
  return count == (expectOne ? 1u : 0u);
}

// Stable index into the eight logical EWR baseline groups.  It deliberately
// distinguishes the otherwise same-kind Hot/Cold and Pulse/Radar deployments.
static inline uint32_t mothershipNametagAllMastersStoreIndex(uint16_t applicationID)
{
  switch (applicationID) {
    case MeshRegistry::Pulse::applicationID: return 0;
    case MeshRegistry::Hot::applicationID: return 1;
    case MeshRegistry::Cold::applicationID: return 4;
    case MeshRegistry::Radar::applicationID: return 7;
    default: return UINT32_MAX;
  }
}

static inline bool mothershipNametagAllMastersDeploymentReadyForSeedSelection(const DeploymentIdentityReport& report,
    uint128_t clusterUUID, uint64_t deploymentID, uint16_t applicationID, uint32_t groups,
    DeploymentIdentityStoreKind kind)
{
  if (!prodigyDeploymentIdentityReportVersionSupported(report.version, 4) || !report.found || !report.live || !report.isStateful ||
      report.clusterUUID != clusterUUID || report.deploymentID != deploymentID || report.applicationID != applicationID ||
      report.nShardGroups != groups || report.nTarget != groups * 3 || report.nDeployed != groups * 3 ||
      report.nHealthy != groups * 3 || report.statefulRuntimeCohort.size() != groups * 3) return false;
  for (uint32_t group = 0; group < groups; ++group) {
    uint32_t replicas = 0;
    for (const auto& member : report.statefulRuntimeCohort) {
      if (member.shardGroup != group) continue;
      if (member.storeKind != kind || member.clusterUUID != clusterUUID || member.machineUUID == 0 ||
          member.containerUUID == 0 || member.replicaUUID != member.containerUUID || !member.allMasters) return false;
      ++replicas;
    }
    if (replicas != 3) return false;
  }
  return true;
}

static inline bool mothershipNametagSourceRepairPlanValid(const MothershipNametagSourceRepairPlan& value)
{
  DeploymentPlan previous, next; String previousBytes, nextBytes, digest;
  const auto& observed = value.predecessor;
  if ((value.applicationID != 3 && value.applicationID != 4 && value.applicationID != MeshRegistry::Radar::applicationID) || !value.previousDeploymentID ||
      value.successorDeploymentID <= value.previousDeploymentID || !value.artifactBytes ||
      !prodigyIsSHA256HexDigest(value.artifactSHA256) || !prodigyIsSHA256HexDigest(value.planSHA256) ||
      !mothershipNametagAllMastersDeploymentReadyForSeedSelection(observed, observed.clusterUUID,
          value.previousDeploymentID, value.applicationID, value.applicationID == MeshRegistry::Radar::applicationID ? 1 : 3,
          value.applicationID == MeshRegistry::Radar::applicationID ? DeploymentIdentityStoreKind::graph : DeploymentIdentityStoreKind::kv) ||
      !BitseryEngine::deserializeSafe(observed.normalizedDeploymentPlan, previous) ||
      !BitseryEngine::deserializeSafe(value.normalizedPlan, next) ||
      !prodigyComputeSHA256Hex(observed.normalizedDeploymentPlan, digest) || digest != observed.canonicalPlanSHA256 ||
      !prodigyComputeSHA256Hex(value.normalizedPlan, digest) || digest != value.planSHA256 ||
      previous.config.deploymentID() != value.previousDeploymentID || next.config.deploymentID() != value.successorDeploymentID ||
      previous.config.applicationID != value.applicationID || next.config.applicationID != value.applicationID ||
      !previous.isStateful || !next.isStateful || !previous.stateful.allMasters || !next.stateful.allMasters ||
      !previous.stateful.allowUpdateInPlace || !next.stateful.allowUpdateInPlace ||
      previous.useHostNetworkNamespace || next.useHostNetworkNamespace ||
      previous.config.containerBlobSHA256 != observed.containerBlobSHA256 ||
      previous.config.containerBlobBytes != observed.containerBlobBytes ||
      next.config.containerBlobSHA256 != value.artifactSHA256 || next.config.containerBlobBytes != value.artifactBytes) return false;
  // This repair admits only a new image/version. Storage, resources, topology,
  // environment, services and every other normalized plan field remain fixed.
  next.config.versionID = previous.config.versionID;
  next.config.containerBlobSHA256 = previous.config.containerBlobSHA256;
  next.config.containerBlobBytes = previous.config.containerBlobBytes;
  return BitseryEngine::serialize(previousBytes, previous) && BitseryEngine::serialize(nextBytes, next) && previousBytes == nextBytes;
}

// Bind the private route to the retained source incarnation and its current
// authenticated discovery address; a route receipt alone does not name a container.
static inline bool mothershipNametagPrivateSeedCounterpartMatches(
    const MothershipNametagAllMastersSeedPlacement& row, const ProdigyStatefulStoreSeedAuthority& authority,
    const CousinRouteRecord& route, const ProdigyLocalCousinServicePermission& subscriber,
    const ProdigyLocalCousinServicePermission& advertiser, uint16_t slot,
    const DeploymentIdentityReport& report, const ProdigyCousinCounterpart& counterpart)
{
  if (route.version != 3 || route.endpointKind != CousinRouteEndpointKind::privateContainer ||
      route.destinationRoutablePrefixUUID != 0 || route.destinationCIDR != 128 ||
      authority.sourceClusterUUID != row.sourceClusterUUID || authority.sourceDeploymentID != row.sourceDeploymentID ||
      authority.sourceContainerUUID != row.sourceContainerUUID || authority.applicationID != row.applicationID ||
      authority.storeKind != row.storeKind || authority.shardGroup != row.shardGroup ||
      !mothershipNametagAllMastersDeploymentReadyForSeedSelection(report, row.sourceClusterUUID,
          row.sourceDeploymentID, row.applicationID, authority.nShardGroups, row.storeKind) ||
      counterpart.containerUUID != row.sourceContainerUUID || counterpart.shardGroup != row.shardGroup ||
      counterpart.shardGroups != authority.nShardGroups || counterpart.routablePrefixUUID != 0 ||
      !counterpart.publicAddress.equals(route.destinationPublicAddress) || counterpart.publicTCPPort != route.destinationTCPPort ||
      !prodigyLocalCousinServicePermissionEqual(counterpart.permission, advertiser) ||
      !prodigyCousinCounterpartMatchesPermission(counterpart, subscriber, slot, true)) return false;
  return std::count_if(report.statefulRuntimeCohort.begin(), report.statefulRuntimeCohort.end(), [&](const auto& member) {
    return member.containerUUID == row.sourceContainerUUID && member.replicaUUID == row.sourceContainerUUID &&
        member.machineUUID == counterpart.nodeUUID && member.clusterUUID == row.sourceClusterUUID &&
        member.shardGroup == row.shardGroup && member.storeKind == row.storeKind && member.allMasters;
  }) == 1;
}

static inline bool mothershipNametagAllMastersSeedPlacementsSynthesize(
    const MothershipNametagAllMastersIntent& intent,
    const Vector<DeploymentIdentityReport>& pulse, const Vector<DeploymentIdentityReport>& hot,
    const Vector<DeploymentIdentityReport>& cold, const Vector<DeploymentIdentityReport>& radar,
    Vector<MothershipNametagAllMastersSeedPlacement>& placements)
{
  if (!mothershipNametagAllMastersIntentValid(intent) || pulse.size() != 3 || hot.size() != 3 ||
      cold.size() != 3 || radar.size() != 3) return false;
  placements.clear();
  struct Store { uint16_t applicationID; DeploymentIdentityStoreKind kind; uint32_t groups; const Vector<DeploymentIdentityReport> *reports; };
  const Store stores[] = {
      {MeshRegistry::Pulse::applicationID, DeploymentIdentityStoreKind::graph, 1, &pulse},
      {MeshRegistry::Hot::applicationID, DeploymentIdentityStoreKind::kv, 3, &hot},
      {MeshRegistry::Cold::applicationID, DeploymentIdentityStoreKind::kv, 3, &cold},
      {MeshRegistry::Radar::applicationID, DeploymentIdentityStoreKind::graph, 1, &radar}};
  for (const auto& store : stores) for (uint32_t group = 0; group < store.groups; ++group) {
    const auto& ewr = store.reports->front();
    auto source = std::find_if(ewr.statefulRuntimeCohort.begin(), ewr.statefulRuntimeCohort.end(),
        [&](const auto& member) { return member.shardGroup == group && member.storeKind == store.kind &&
            member.clusterUUID == ewr.clusterUUID && member.containerUUID != 0 &&
            prodigyIsSHA256HexDigest(member.sourceContentWatermarkSHA256) &&
            prodigyIsSHA256HexDigest(member.sourceCatchupWatermarkSHA256); });
    // Do not replace this native receipt gate with an identity-derived digest.
    if (source == ewr.statefulRuntimeCohort.end()) return false;
    for (uint32_t site = 1; site < 3; ++site) {
      const auto& report = (*store.reports)[site];
      uint32_t replicas = 0;
      for (const auto& target : report.statefulRuntimeCohort) {
        if (target.shardGroup != group) continue;
        if (++replicas > 3 || target.containerUUID == 0) return false;
        MothershipNametagAllMastersSeedPlacement placement = {};
        placement.site = uint8_t(site); placement.applicationID = store.applicationID; placement.storeKind = store.kind; placement.shardGroup = group;
        placement.targetClusterUUID = report.clusterUUID; placement.targetDeploymentID = report.deploymentID;
        placement.targetContainerUUID = target.containerUUID;
        placement.sourceClusterUUID = ewr.clusterUUID; placement.sourceDeploymentID = ewr.deploymentID;
        placement.sourceContainerUUID = source->containerUUID; placement.seedGeneration = 1;
        placement.fixtureSHA256 = source->seedCatchupSHA256;
        placement.expectedCatchupWatermarkSHA256 = source->catchupWatermarkSHA256;
        placement.sourceContentWatermarkSHA256 = source->sourceContentWatermarkSHA256;
        placement.sourceCatchupWatermarkSHA256 = source->sourceCatchupWatermarkSHA256;
        placements.push_back(std::move(placement));
      }
      if (replicas != 3) return false;
    }
  }
  return placements.size() == 48;
}

// DeploymentIdentityReport is the existing Mothership pull payload.  It has
// enough membership evidence to reject wrong groups, passive replicas, and an
// extra graph; it does not invent a second runtime topic.
static inline bool mothershipNametagAllMastersRuntimeMemberObserved(
    const DeploymentIdentityStatefulMember& member, DeploymentIdentityStoreKind kind,
    uint128_t clusterUUID, uint32_t groups, bool allMasters)
{
  return member.storeKind == kind && member.shardGroup < groups && member.replicaUUID != 0 &&
      member.clusterUUID == clusterUUID && member.machineUUID != 0 && member.containerUUID != 0 &&
      member.replicaUUID == member.containerUUID && member.writable && member.clientServing &&
      member.allMasters == allMasters && member.siblingSessionUUID != 0 &&
      member.siblingSessionGeneration != 0 && member.siblingSessionHealthy &&
      member.seededFromClusterUUID != 0 && member.seededFromContainerUUID != 0 &&
      prodigyIsSHA256HexDigest(member.seedCatchupSHA256) && member.seedCatchupGeneration != 0 &&
      prodigyIsSHA256HexDigest(member.replayWatermarkSHA256) &&
      prodigyIsSHA256HexDigest(member.catchupWatermarkSHA256) &&
      prodigyIsSHA256HexDigest(member.sourceContentWatermarkSHA256) &&
      prodigyIsSHA256HexDigest(member.sourceCatchupWatermarkSHA256);
}

static inline bool mothershipNametagAllMastersDeploymentObserved(const DeploymentIdentityReport& report,
    uint128_t clusterUUID, uint64_t deploymentID, uint16_t applicationID, uint32_t groups,
    DeploymentIdentityStoreKind kind)
{
  if (!prodigyDeploymentIdentityReportVersionSupported(report.version, 4) || !report.found || !report.live || !report.isStateful ||
      report.clusterUUID != clusterUUID || report.deploymentID != deploymentID || report.applicationID != applicationID ||
      report.nShardGroups != groups || report.nTarget != groups * 3 ||
      report.nDeployed != groups * 3 || report.nHealthy != groups * 3 ||
      !report.statefulRuntimeCohortConverged || report.statefulRuntimeCohort.size() != groups * 3)
    return false;
  for (uint32_t group = 0; group < groups; ++group) {
    uint32_t count = 0;
    for (const auto& member : report.statefulRuntimeCohort) {
      if (member.shardGroup == group) {
        if (!mothershipNametagAllMastersRuntimeMemberObserved(member, kind, clusterUUID, groups, true)) return false;
        ++count;
      } else if (member.shardGroup >= groups) return false;
    }
    if (count != 3) return false;
  }
  return true;
}

static inline uint128_t mothershipNametagTruthWriterContainerObserved(const DeploymentIdentityReport& report,
    const MothershipNametagAllMastersSite& site)
{
  // Truth's normal single-master group has three physical replicas, not
  // three client-serving writers. Brain observes the selected master from
  // its current runtime advertisement. Truth does not use remote cousin seed
  // receipts, so those receipts cannot establish this placement invariant.
  if (!prodigyDeploymentIdentityReportVersionSupported(report.version, 4) || !report.found || !report.live || !report.isStateful ||
      report.clusterUUID != site.clusterUUID || report.deploymentID != site.truthDeploymentID ||
      report.applicationID != MeshRegistry::Truth::applicationID || report.nShardGroups != 1 ||
      report.nTarget != 3 || report.nDeployed != 3 || report.nHealthy != 3 ||
      report.statefulRuntimeCohort.size() != 3) return 0;
  uint128_t writer = 0;
  for (size_t index = 0; index < report.statefulRuntimeCohort.size(); ++index) {
    const auto& member = report.statefulRuntimeCohort[index];
    if (member.storeKind != DeploymentIdentityStoreKind::truth || member.shardGroup != 0 ||
        member.allMasters || member.clusterUUID != site.clusterUUID || member.machineUUID == 0 ||
        member.containerUUID == 0 || member.replicaUUID != member.containerUUID) return 0;
    for (size_t previous = 0; previous < index; ++previous)
      if (report.statefulRuntimeCohort[previous].containerUUID == member.containerUUID ||
          report.statefulRuntimeCohort[previous].machineUUID == member.machineUUID) return 0;
    if (member.clientServing) {
      if (writer != 0) return 0;
      writer = member.containerUUID;
    }
  }
  return writer;
}

static inline bool mothershipNametagTruthWriterObserved(const DeploymentIdentityReport& report,
    const MothershipNametagAllMastersSite& site)
{
  return mothershipNametagTruthWriterContainerObserved(report, site) != 0;
}

// Pre-seed admission binds each App6 to its intended site and deployment.
// A remote Truth receipt is only possible once native seed authority has made
// the remote stores available to ordinary application traffic.
static inline bool mothershipNametagApp6IdentitySetObserved(const Vector<DeploymentIdentityReport>& app6,
    const Vector<MothershipNametagAllMastersSite>& sites)
{
  if (app6.size() != 3 || sites.size() != 3) return false;
  for (uint32_t site = 0; site < sites.size(); ++site) {
    const auto& report = app6[site];
    if (!prodigyDeploymentIdentityReportVersionSupported(report.version, 3) || !report.found || !report.live ||
        report.isStateful || report.clusterUUID != sites[site].clusterUUID ||
        report.deploymentID != sites[site].app6DeploymentID ||
        report.applicationID != MeshRegistry::Nametag::applicationID) return false;
  }
  return true;
}

static inline bool mothershipNametagApp6TruthMeshObserved(const DeploymentIdentityReport& report,
    const MothershipNametagAllMastersSite& site, uint128_t ewrClusterUUID, uint128_t truthWriter)
{
  if (!prodigyDeploymentIdentityReportVersionSupported(report.version, 3) || !report.found || !report.live || report.isStateful ||
      report.clusterUUID != site.clusterUUID || report.deploymentID != site.app6DeploymentID ||
      report.applicationID != MeshRegistry::Nametag::applicationID || report.app6TruthMeshReceipts.size() != 1) return false;
  const auto& receipt = report.app6TruthMeshReceipts.front();
  return receipt.localClusterUUID == site.clusterUUID && receipt.remoteClusterUUID == ewrClusterUUID &&
      receipt.truthWriterContainerUUID == truthWriter && receipt.sessionUUID != 0 &&
      receipt.commandGeneration != 0 && receipt.reconnectGeneration != 0 &&
      prodigyIsSHA256HexDigest(receipt.lastSuccessfulRequestWatermarkSHA256) && receipt.healthy &&
      (receipt.observationVersion == 1 ? receipt.reverseCarrierUUID != 0 :
       (report.version >= 6 && receipt.observationVersion == 2 && receipt.reverseCarrierUUID == 0 &&
        report.nTarget == 1 && report.nDeployed == 1 && report.nHealthy == 1 &&
        receipt.localApplicationContainerUUID != 0 && receipt.routeUUID != 0 && receipt.routeGeneration != 0));
}

static inline bool mothershipNametagApp6TruthMeshSetObserved(const Vector<DeploymentIdentityReport>& app6,
    const Vector<MothershipNametagAllMastersSite>& sites, const DeploymentIdentityReport& truth)
{
  if (app6.size() != 3 || sites.size() != 3) return false;
  const uint128_t writer = mothershipNametagTruthWriterContainerObserved(truth, sites.front());
  if (writer == 0) return false;
  // EWR reaches its Truth writer through the ordinary local mesh.  The
  // cross-cluster reverse-carrier receipt applies to the remote sites only.
  const auto& local = app6.front();
  if (!prodigyDeploymentIdentityReportVersionSupported(local.version, 3) || !local.found || !local.live || local.isStateful ||
      local.clusterUUID != sites.front().clusterUUID || local.deploymentID != sites.front().app6DeploymentID ||
      local.applicationID != MeshRegistry::Nametag::applicationID || local.nTarget != 1 ||
      local.nDeployed != 1 || local.nHealthy != 1) return false;
  for (uint32_t site = 1; site < 3; ++site)
    if (!mothershipNametagApp6TruthMeshObserved(app6[site], sites[site], sites[0].clusterUUID, writer)) return false;
  return true;
}

static inline bool mothershipNametagAllMastersSiteObserved(const MothershipNametagAllMastersSite& site,
    const DeploymentIdentityReport& pulse, const DeploymentIdentityReport& hot,
    const DeploymentIdentityReport& cold, const DeploymentIdentityReport& radar,
    const DeploymentIdentityReport *truth)
{
  return mothershipNametagAllMastersDeploymentObserved(pulse, site.clusterUUID, site.pulseDeploymentID, MeshRegistry::Pulse::applicationID, 1, DeploymentIdentityStoreKind::graph) &&
      mothershipNametagAllMastersDeploymentObserved(hot, site.clusterUUID, site.hotDeploymentID, MeshRegistry::Hot::applicationID, 3, DeploymentIdentityStoreKind::kv) &&
      mothershipNametagAllMastersDeploymentObserved(cold, site.clusterUUID, site.coldDeploymentID, MeshRegistry::Cold::applicationID, 3, DeploymentIdentityStoreKind::kv) &&
      mothershipNametagAllMastersDeploymentObserved(radar, site.clusterUUID, site.radarDeploymentID, MeshRegistry::Radar::applicationID, 1, DeploymentIdentityStoreKind::graph) &&
      ((site.truthDeploymentID == 0 && truth == nullptr) || (site.truthDeploymentID != 0 && truth != nullptr &&
       mothershipNametagTruthWriterObserved(*truth, site)));
}

// The native receipt must bind each target to the persisted EWR source
// baseline.  A syntactically valid receipt from another source (or carrying a
// caller-provided digest) is not convergence for this operation.
static inline bool mothershipNametagAllMastersSeedPlacementsObserved(
    const Vector<MothershipNametagAllMastersSeedPlacement>& placements,
    const Vector<DeploymentIdentityReport>& pulse, const Vector<DeploymentIdentityReport>& hot,
    const Vector<DeploymentIdentityReport>& cold, const Vector<DeploymentIdentityReport>& radar)
{
  if (placements.size() != 48 || pulse.size() != 3 || hot.size() != 3 || cold.size() != 3 || radar.size() != 3) return false;
  for (const auto& row : placements) {
    const Vector<DeploymentIdentityReport> *reports = nullptr;
    if (row.applicationID == MeshRegistry::Pulse::applicationID) reports = &pulse;
    else if (row.applicationID == MeshRegistry::Hot::applicationID) reports = &hot;
    else if (row.applicationID == MeshRegistry::Cold::applicationID) reports = &cold;
    else if (row.applicationID == MeshRegistry::Radar::applicationID) reports = &radar;
    else return false;
    if (row.site == 0 || row.site >= reports->size() || row.sourceClusterUUID == row.targetClusterUUID ||
        row.sourceContainerUUID == row.targetContainerUUID) return false;
    const auto& report = (*reports)[row.site];
    if (report.clusterUUID != row.targetClusterUUID || report.deploymentID != row.targetDeploymentID ||
        report.applicationID != row.applicationID) return false;
    bool observed = false;
    for (const auto& member : report.statefulRuntimeCohort) {
      if (member.containerUUID != row.targetContainerUUID || member.shardGroup != row.shardGroup) continue;
      observed = member.seededFromClusterUUID == row.sourceClusterUUID &&
          member.seededFromContainerUUID == row.sourceContainerUUID &&
          member.seedCatchupSHA256 == row.fixtureSHA256 &&
          member.catchupWatermarkSHA256 == row.expectedCatchupWatermarkSHA256 &&
          member.sourceContentWatermarkSHA256 == row.sourceContentWatermarkSHA256 &&
          member.sourceCatchupWatermarkSHA256 == row.sourceCatchupWatermarkSHA256;
      break;
    }
    if (!observed) return false;
    const auto& sourceReport = reports->front();
    if (sourceReport.clusterUUID != row.sourceClusterUUID || sourceReport.deploymentID != row.sourceDeploymentID) return false;
    const auto source = std::find_if(sourceReport.statefulRuntimeCohort.begin(), sourceReport.statefulRuntimeCohort.end(),
        [&](const auto& member) { return member.containerUUID == row.sourceContainerUUID && member.shardGroup == row.shardGroup; });
    if (source == sourceReport.statefulRuntimeCohort.end() ||
        source->sourceContentWatermarkSHA256 != row.sourceContentWatermarkSHA256 ||
        source->sourceCatchupWatermarkSHA256 != row.sourceCatchupWatermarkSHA256) return false;
  }
  return true;
}

// The registry persists each independently observed remote receipt. Keep this
// single-row predicate identical to the aggregate completion proof without
// allowing a partial vector to masquerade as a complete campaign.
static inline bool mothershipNametagAllMastersSeedPlacementObserved(
    const MothershipNametagAllMastersSeedPlacement& row,
    const Vector<DeploymentIdentityReport>& pulse, const Vector<DeploymentIdentityReport>& hot,
    const Vector<DeploymentIdentityReport>& cold, const Vector<DeploymentIdentityReport>& radar)
{
  const Vector<DeploymentIdentityReport> *reports = row.applicationID == MeshRegistry::Pulse::applicationID ? &pulse :
      (row.applicationID == MeshRegistry::Hot::applicationID ? &hot :
       (row.applicationID == MeshRegistry::Cold::applicationID ? &cold :
        (row.applicationID == MeshRegistry::Radar::applicationID ? &radar : nullptr)));
  if (reports == nullptr || row.site == 0 || row.site >= reports->size() || row.sourceClusterUUID == row.targetClusterUUID ||
      row.sourceContainerUUID == row.targetContainerUUID) return false;
  const auto& report = (*reports)[row.site];
  const auto& sourceReport = reports->front();
  if (report.clusterUUID != row.targetClusterUUID || report.deploymentID != row.targetDeploymentID ||
      report.applicationID != row.applicationID || sourceReport.clusterUUID != row.sourceClusterUUID ||
      sourceReport.deploymentID != row.sourceDeploymentID) return false;
  const auto source = std::find_if(sourceReport.statefulRuntimeCohort.begin(), sourceReport.statefulRuntimeCohort.end(),
      [&](const auto& member) { return member.containerUUID == row.sourceContainerUUID && member.shardGroup == row.shardGroup; });
  const auto target = std::find_if(report.statefulRuntimeCohort.begin(), report.statefulRuntimeCohort.end(),
      [&](const auto& member) { return member.containerUUID == row.targetContainerUUID && member.shardGroup == row.shardGroup; });
  return source != sourceReport.statefulRuntimeCohort.end() && target != report.statefulRuntimeCohort.end() &&
      source->sourceContentWatermarkSHA256 == row.sourceContentWatermarkSHA256 &&
      source->sourceCatchupWatermarkSHA256 == row.sourceCatchupWatermarkSHA256 &&
      target->seededFromClusterUUID == row.sourceClusterUUID && target->seededFromContainerUUID == row.sourceContainerUUID &&
      target->sourceContentWatermarkSHA256 == row.sourceContentWatermarkSHA256 &&
      target->sourceCatchupWatermarkSHA256 == row.sourceCatchupWatermarkSHA256;
}

static inline bool mothershipNametagAllMastersSiteReadyForSeedSelection(const MothershipNametagAllMastersSite& site,
    const DeploymentIdentityReport& pulse, const DeploymentIdentityReport& hot,
    const DeploymentIdentityReport& cold, const DeploymentIdentityReport& radar,
    const DeploymentIdentityReport *truth)
{
  return mothershipNametagAllMastersDeploymentReadyForSeedSelection(pulse, site.clusterUUID, site.pulseDeploymentID,
             MeshRegistry::Pulse::applicationID, 1, DeploymentIdentityStoreKind::graph) &&
      mothershipNametagAllMastersDeploymentReadyForSeedSelection(hot, site.clusterUUID, site.hotDeploymentID,
             MeshRegistry::Hot::applicationID, 3, DeploymentIdentityStoreKind::kv) &&
      mothershipNametagAllMastersDeploymentReadyForSeedSelection(cold, site.clusterUUID, site.coldDeploymentID,
             MeshRegistry::Cold::applicationID, 3, DeploymentIdentityStoreKind::kv) &&
      mothershipNametagAllMastersDeploymentReadyForSeedSelection(radar, site.clusterUUID, site.radarDeploymentID,
             MeshRegistry::Radar::applicationID, 1, DeploymentIdentityStoreKind::graph) &&
      ((site.truthDeploymentID == 0 && truth == nullptr) || (site.truthDeploymentID != 0 && truth != nullptr &&
       mothershipNametagTruthWriterObserved(*truth, site)));
}

class MothershipNametagSourceCutProgress {
public:
  // The original request is persisted before dispatch. A dispatched request
  // without its returned challenge is intentionally not replayable.
  ProdigyStatefulStoreSourceCut request;
  ProdigyStatefulStoreSourceCut proof;
  bool dispatched = false;
  bool released = false;
};
template <typename S>
static void serialize(S&& serializer, MothershipNametagSourceCutProgress& value)
{
  serializer.object(value.request); serializer.object(value.proof);
  serializer.value1b(value.dispatched); serializer.value1b(value.released);
}

class MothershipNametagAllMastersRecord {
public:
  static constexpr uint32_t version = 6;
  static constexpr uint32_t sourceCutVersion = 7;
  static constexpr uint32_t qualificationSeedFaultVersion = 8;
  uint32_t protocolVersion = version;
  String requestSHA256;
  MothershipNametagAllMastersIntent intent;
  // Produced only by Mothership after pulling authenticated deployment
  // identity reports; callers never supply container identities here.
  Vector<MothershipNametagAllMastersSeedPlacement> seedPlacements;
  // Persist the EWR baseline before delivery; a restart replays only rows
  // without a target acknowledgement and retains per-target catch-up proof.
  enum class Phase : uint8_t { ewrBaselineObserved = 1, remoteSeeding = 2, remoteSeeded = 3, sourceCutsPreparing = 4 };
  Phase phase = Phase::ewrBaselineObserved;
  Vector<MothershipNametagSourceCutProgress> sourceCuts;
};

static inline uint128_t mothershipNametagSeedOperationUUID(const MothershipNametagAllMastersRecord& record)
{
  return record.intent.isExpiredCutRecovery() ?
      record.intent.predecessorOperationUUID : record.intent.operationUUID;
}

template <typename S>
static void serialize(S&& serializer, MothershipNametagAllMastersRecord& value)
{
  serializer.value4b(value.protocolVersion); serializer.text1b(value.requestSHA256, 64); serializer.object(value.intent);
  serializer.container(value.seedPlacements, value.protocolVersion >= 5 ? 48 : 72, [&](auto& nested, MothershipNametagAllMastersSeedPlacement& placement) {
    serializeMothershipNametagAllMastersSeedPlacement(nested, placement, value.protocolVersion);
  });
  if (value.protocolVersion >= 5) serializer.value1b(value.phase);
  if (value.protocolVersion >= MothershipNametagAllMastersRecord::sourceCutVersion)
    serializer.container(value.sourceCuts, 8);
}

// Derive a command only from the immutable registry row and source cut.
static inline bool mothershipNametagSourceCutAuthority(const MothershipNametagAllMastersRecord& record,
    const MothershipNametagAllMastersSeedPlacement& row, ProdigyStatefulStoreSeedAuthority& authority)
{
  auto cut = std::find_if(record.sourceCuts.begin(), record.sourceCuts.end(), [&](const auto& value) {
    return value.request.applicationID == row.applicationID && value.request.shardGroup == row.shardGroup;
  });
  if (record.protocolVersion < MothershipNametagAllMastersRecord::sourceCutVersion || cut == record.sourceCuts.end() ||
      !cut->proof.ready || cut->request.sourceClusterUUID != row.sourceClusterUUID ||
      cut->request.sourceDeploymentID != row.sourceDeploymentID || cut->request.sourceContainerUUID != row.sourceContainerUUID ||
      cut->proof.contentSHA256 != row.sourceContentWatermarkSHA256 || cut->proof.headsSHA256 != row.sourceCatchupWatermarkSHA256) return false;
  auto route = std::find_if(record.intent.seedRoutes.begin(), record.intent.seedRoutes.end(), [&](const auto& value) {
    return value.site == row.site && value.applicationID == row.applicationID && value.shardGroup == row.shardGroup;
  });
  if (route == record.intent.seedRoutes.end() || route->routeUUID == 0) return false;
  authority = {}; authority.protocolVersion = ProdigyStatefulStoreSeedAuthority::sourceCutVersion;
  authority.authorityGeneration = authority.seedGeneration = row.seedGeneration; authority.operationUUID = mothershipNametagSeedOperationUUID(record);
  authority.applicationID = row.applicationID; authority.storeKind = row.storeKind; authority.shardGroup = row.shardGroup;
  authority.nShardGroups = cut->request.nShardGroups; authority.targetClusterUUID = row.targetClusterUUID;
  authority.targetDeploymentID = row.targetDeploymentID; authority.targetContainerUUID = row.targetContainerUUID;
  authority.sourceClusterUUID = row.sourceClusterUUID; authority.sourceDeploymentID = row.sourceDeploymentID;
  authority.sourceContainerUUID = row.sourceContainerUUID; authority.fixtureSHA256 = row.fixtureSHA256;
  authority.sourceContentWatermarkSHA256 = cut->proof.contentSHA256; authority.sourceCatchupWatermarkSHA256 = cut->proof.headsSHA256;
  authority.sourceBaselineOperationUUID = record.intent.sourceBaselineOperationUUID;
  authority.sourceRequestUUID = cut->request.requestUUID; authority.sourceMemberRequestUUID = cut->request.memberRequestUUID;
  authority.cutUUID = cut->proof.cutUUID; authority.cutGeneration = cut->proof.cutGeneration;
  authority.seedRouteUUID = route->routeUUID;
  authority.sourceCutScope = cut->request.scope; authority.retainUntilMilliseconds = cut->request.retainUntilMilliseconds;
  if (row.qualificationChallengeUUID) {
    if (record.protocolVersion != MothershipNametagAllMastersRecord::qualificationSeedFaultVersion) return false;
    authority.protocolVersion = ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion;
    authority.qualificationRunUUID = row.qualificationRunUUID;
    authority.qualificationChallengeUUID = row.qualificationChallengeUUID;
    authority.qualificationExecutionGeneration = row.qualificationExecutionGeneration;
    authority.qualificationDeadlineAtMilliseconds = row.qualificationDeadlineAtMilliseconds;
  }
  return prodigyStatefulStoreSeedAuthorityValid(authority);
}

static inline bool mothershipNametagSourceCutPlacementsSynthesize(MothershipNametagAllMastersRecord& record,
    const Vector<DeploymentIdentityReport>& pulse, const Vector<DeploymentIdentityReport>& hot,
    const Vector<DeploymentIdentityReport>& cold, const Vector<DeploymentIdentityReport>& radar, const String& fixture)
{
  if (record.protocolVersion < MothershipNametagAllMastersRecord::sourceCutVersion || !prodigyIsSHA256HexDigest(fixture)) return false;
  const Vector<DeploymentIdentityReport> *reports[] = {&pulse, &hot, &cold, &radar};
  for (const auto *report : reports) if (report->size() != 3) return false;
  Vector<MothershipNametagAllMastersSeedPlacement> placements;
  for (const auto& cut : record.sourceCuts) {
    const uint32_t base = mothershipNametagAllMastersStoreIndex(cut.request.applicationID);
    const uint32_t index = base == 0 ? 0 : (base == 1 ? 1 : (base == 4 ? 2 : (base == 7 ? 3 : UINT32_MAX)));
    if (index == UINT32_MAX || !cut.proof.ready || cut.released) return false;
    for (uint32_t site = 1; site < 3; ++site) {
      const auto& report = (*reports[index])[site]; uint32_t count = 0;
      for (const auto& target : report.statefulRuntimeCohort) {
        if (target.shardGroup != cut.request.shardGroup) continue;
        if (++count > 3 || target.containerUUID == 0 || target.storeKind != cut.request.storeKind) return false;
        MothershipNametagAllMastersSeedPlacement row = {};
        row.site = site; row.applicationID = cut.request.applicationID; row.storeKind = cut.request.storeKind;
        row.shardGroup = cut.request.shardGroup; row.targetClusterUUID = report.clusterUUID; row.targetDeploymentID = report.deploymentID;
        row.targetContainerUUID = target.containerUUID; row.sourceClusterUUID = cut.request.sourceClusterUUID;
        row.sourceDeploymentID = cut.request.sourceDeploymentID; row.sourceContainerUUID = cut.request.sourceContainerUUID;
        row.seedGeneration = 1; row.fixtureSHA256 = fixture; row.sourceContentWatermarkSHA256 = cut.proof.contentSHA256;
        row.sourceCatchupWatermarkSHA256 = cut.proof.headsSHA256; placements.push_back(std::move(row));
      }
      if (count != 3) return false;
    }
  }
  if (placements.size() != 48) return false;
  record.seedPlacements = std::move(placements); record.phase = MothershipNametagAllMastersRecord::Phase::ewrBaselineObserved;
  return true;
}

static inline bool mothershipNametagAllMastersRecordValid(const MothershipNametagAllMastersRecord& record)
{
  if ((record.protocolVersion != MothershipNametagAllMastersRecord::version &&
       record.protocolVersion != MothershipNametagAllMastersRecord::sourceCutVersion &&
       record.protocolVersion != MothershipNametagAllMastersRecord::qualificationSeedFaultVersion) ||
      !prodigyIsSHA256HexDigest(record.requestSHA256) || !mothershipNametagAllMastersIntentValid(record.intent) ||
      (record.phase != MothershipNametagAllMastersRecord::Phase::ewrBaselineObserved &&
       record.phase != MothershipNametagAllMastersRecord::Phase::remoteSeeding &&
       record.phase != MothershipNametagAllMastersRecord::Phase::remoteSeeded &&
       record.phase != MothershipNametagAllMastersRecord::Phase::sourceCutsPreparing)) return false;
  if (record.protocolVersion >= MothershipNametagAllMastersRecord::sourceCutVersion) {
    if ((record.intent.protocolVersion != MothershipNametagAllMastersIntent::sourceCutVersion &&
         record.intent.protocolVersion != MothershipNametagAllMastersIntent::seedRouteVersion &&
         record.intent.protocolVersion != MothershipNametagAllMastersIntent::expiredCutRecoveryVersion &&
         record.intent.protocolVersion != MothershipNametagAllMastersIntent::radarExpiredCutRecoveryVersion) || record.sourceCuts.size() != 8) return false;
    bool seen[8] = {};
    for (const auto& cut : record.sourceCuts) {
      const auto& request = cut.request;
      const uint32_t base = mothershipNametagAllMastersStoreIndex(request.applicationID);
      const auto& site = record.intent.sites[0];
      const uint64_t sourceDeployment = base == 0 ? site.pulseDeploymentID :
          (base == 1 ? site.hotDeploymentID : (base == 4 ? site.coldDeploymentID : site.radarDeploymentID));
      if (base == UINT32_MAX || request.shardGroup >= ((base == 1 || base == 4) ? 3u : 1u) ||
          request.nShardGroups != ((base == 1 || base == 4) ? 3u : 1u) || seen[base + request.shardGroup] ||
          !prodigyStatefulStoreSourceCutValid(request) || request.response ||
          request.action != ProdigyStatefulStoreSourceCutAction::prepare ||
          request.operationUUID != mothershipNametagSeedOperationUUID(record) ||
          request.sourceClusterUUID != record.intent.sites[0].clusterUUID ||
          request.sourceDeploymentID != sourceDeployment ||
          (request.memberRequestUUID != 0 && !cut.dispatched)) return false;
      seen[base + request.shardGroup] = true;
      if (cut.proof.response) {
        if (!cut.dispatched || request.memberRequestUUID == 0 ||
            !prodigyStatefulStoreSourceCutResponseMatches(request, cut.proof) || !cut.proof.ready) return false;
      } else if (cut.released || cut.proof.ready || cut.proof.released || cut.proof.cutUUID != 0 ||
                 cut.proof.cutGeneration != 0 || !cut.proof.contentSHA256.empty() ||
                 !cut.proof.headsSHA256.empty() || !cut.proof.failure.empty()) return false;
      if (cut.released && record.phase != MothershipNametagAllMastersRecord::Phase::remoteSeeded) return false;
    }
    if (record.phase == MothershipNametagAllMastersRecord::Phase::sourceCutsPreparing)
      return record.seedPlacements.empty();
    for (const auto& cut : record.sourceCuts) if (!cut.proof.ready) return false;
  } else if (record.phase == MothershipNametagAllMastersRecord::Phase::sourceCutsPreparing || !record.sourceCuts.empty()) return false;
  if (record.seedPlacements.size() != 48) return false;
  uint32_t targetCounts[3][4][3] = {};
  uint128_t sourceContainers[4][3] = {};
  String sourceContents[4][3] = {}, sourceWatermarks[4][3] = {};
  bool anyDelivered = false, allObserved = true;
  for (uint32_t index = 0; index < record.seedPlacements.size(); ++index) {
    const auto& row = record.seedPlacements[index];
    const bool marked = row.qualificationRunUUID || row.qualificationChallengeUUID ||
        row.qualificationExecutionGeneration || row.qualificationDeadlineAtMilliseconds;
    if (marked && (record.protocolVersion != MothershipNametagAllMastersRecord::qualificationSeedFaultVersion ||
        !row.qualificationRunUUID || !row.qualificationChallengeUUID || !row.qualificationExecutionGeneration ||
        row.qualificationDeadlineAtMilliseconds <= 0 || row.storeKind != DeploymentIdentityStoreKind::kv)) return false;
    if (record.protocolVersion >= MothershipNametagAllMastersRecord::qualificationSeedFaultVersion &&
        row.deliveryApplied && !row.deliveryDispatched) return false;
    if (row.site == 0 || row.site >= 3 || row.storeKind == DeploymentIdentityStoreKind::unknown || row.shardGroup >= 3 ||
        row.targetClusterUUID == 0 || row.targetDeploymentID == 0 || row.targetContainerUUID == 0 ||
        row.sourceClusterUUID != record.intent.sites[0].clusterUUID || row.sourceDeploymentID == 0 ||
        row.sourceContainerUUID == 0 || row.seedGeneration == 0 || !prodigyIsSHA256HexDigest(row.fixtureSHA256) ||
        (record.protocolVersion >= MothershipNametagAllMastersRecord::sourceCutVersion ? !row.expectedCatchupWatermarkSHA256.empty() :
         !prodigyIsSHA256HexDigest(row.expectedCatchupWatermarkSHA256)) ||
        !prodigyIsSHA256HexDigest(row.sourceContentWatermarkSHA256) ||
        !prodigyIsSHA256HexDigest(row.sourceCatchupWatermarkSHA256) || (row.catchupObserved && !row.deliveryApplied)) return false;
    const auto& targetSite = record.intent.sites[row.site];
    uint64_t targetDeploymentID = 0;
    uint32_t maxGroups = 0;
    DeploymentIdentityStoreKind expectedKind = DeploymentIdentityStoreKind::unknown;
    const uint32_t storeIndex = mothershipNametagAllMastersStoreIndex(row.applicationID);
    if (record.protocolVersion >= MothershipNametagAllMastersRecord::sourceCutVersion) {
      auto cut = std::find_if(record.sourceCuts.begin(), record.sourceCuts.end(), [&](const auto& value) {
        return value.request.applicationID == row.applicationID && value.request.shardGroup == row.shardGroup;
      });
      if (cut == record.sourceCuts.end() || cut->request.sourceContainerUUID != row.sourceContainerUUID ||
          cut->proof.contentSHA256 != row.sourceContentWatermarkSHA256 ||
          cut->proof.headsSHA256 != row.sourceCatchupWatermarkSHA256) return false;
      ProdigyStatefulStoreSeedAuthority authority = {};
      if (!mothershipNametagSourceCutAuthority(record, row, authority) ||
          (row.catchupObserved && !prodigyStatefulStoreReceiptMatchesSourceCutAuthority(row.nativeSourceCutReceipt, authority)) ||
          (!row.catchupObserved && row.nativeSourceCutReceipt.protocolVersion != 0)) return false;
    }
    switch (storeIndex) {
      case 0: targetDeploymentID = targetSite.pulseDeploymentID; maxGroups = 1; expectedKind = DeploymentIdentityStoreKind::graph; break;
      case 1: targetDeploymentID = targetSite.hotDeploymentID; maxGroups = 3; expectedKind = DeploymentIdentityStoreKind::kv; break;
      case 4: targetDeploymentID = targetSite.coldDeploymentID; maxGroups = 3; expectedKind = DeploymentIdentityStoreKind::kv; break;
      case 7: targetDeploymentID = targetSite.radarDeploymentID; maxGroups = 1; expectedKind = DeploymentIdentityStoreKind::graph; break;
      default: return false;
    }
    const auto& sourceSite = record.intent.sites[0];
    uint64_t sourceDeploymentID = row.applicationID == MeshRegistry::Pulse::applicationID ? sourceSite.pulseDeploymentID :
        (row.applicationID == MeshRegistry::Hot::applicationID ? sourceSite.hotDeploymentID :
         (row.applicationID == MeshRegistry::Cold::applicationID ? sourceSite.coldDeploymentID : sourceSite.radarDeploymentID));
    if (row.storeKind != expectedKind || row.shardGroup >= maxGroups ||
        row.targetClusterUUID != targetSite.clusterUUID || row.targetDeploymentID != targetDeploymentID ||
        row.sourceDeploymentID != sourceDeploymentID || row.sourceClusterUUID == row.targetClusterUUID ||
        row.sourceContainerUUID == row.targetContainerUUID) return false;
    const uint32_t storeSlot = storeIndex == 0 ? 0 : (storeIndex == 1 ? 1 : (storeIndex == 4 ? 2 : 3));
    if (++targetCounts[row.site][storeSlot][row.shardGroup] > 3) return false;
    uint128_t& sourceContainer = sourceContainers[storeSlot][row.shardGroup];
    if (sourceContainer == 0) sourceContainer = row.sourceContainerUUID;
    else if (sourceContainer != row.sourceContainerUUID) return false;
    String& sourceContent = sourceContents[storeSlot][row.shardGroup];
    String& sourceWatermark = sourceWatermarks[storeSlot][row.shardGroup];
    if (sourceContent.empty()) { sourceContent = row.sourceContentWatermarkSHA256; sourceWatermark = row.sourceCatchupWatermarkSHA256; }
    else if (sourceContent != row.sourceContentWatermarkSHA256 || sourceWatermark != row.sourceCatchupWatermarkSHA256) return false;
    anyDelivered = anyDelivered || row.deliveryApplied;
    allObserved = allObserved && row.catchupObserved;
    for (uint32_t prior = 0; prior < index; ++prior) {
      const auto& before = record.seedPlacements[prior];
      if (before.targetClusterUUID == row.targetClusterUUID && before.targetDeploymentID == row.targetDeploymentID &&
          before.targetContainerUUID == row.targetContainerUUID) return false;
    }
  }
  constexpr uint32_t groupsByStore[] = {1, 3, 3, 1};
  for (uint32_t site = 1; site < 3; ++site)
    for (uint32_t store = 0; store < 4; ++store)
      for (uint32_t group = 0; group < groupsByStore[store]; ++group)
        if (targetCounts[site][store][group] != 3 || sourceContainers[store][group] == 0) return false;
  if ((record.phase == MothershipNametagAllMastersRecord::Phase::ewrBaselineObserved && anyDelivered) ||
      (record.phase == MothershipNametagAllMastersRecord::Phase::remoteSeeding && (!anyDelivered || allObserved)) ||
      (record.phase == MothershipNametagAllMastersRecord::Phase::remoteSeeded && !allObserved)) return false;
  return true;
}

// Recovery is restricted to an expired, unseeded first admission. Its remote
// bootstrap and site identities remain the authority. Version 7 replaces only
// Hot/Cold; version 8 replaces only Radar through its explicit repair plan.
static inline bool mothershipNametagExpiredCutRecoveryMatches(const MothershipNametagAllMastersIntent& next,
    const MothershipNametagAllMastersRecord& prior, const MothershipNametagInitialSeedRecord& bootstrap, int64_t now)
{
  if (!mothershipNametagAllMastersIntentValid(next) || !mothershipNametagAllMastersRecordValid(prior) ||
      !next.isExpiredCutRecovery() || prior.intent.protocolVersion != prior.intent.seedRouteVersion ||
      next.predecessorOperationUUID != prior.intent.operationUUID || next.sourceBaselineOperationUUID == prior.intent.sourceBaselineOperationUUID ||
      prior.phase != MothershipNametagAllMastersRecord::Phase::sourceCutsPreparing || !prior.seedPlacements.empty() ||
      prior.sourceCuts.size() != 8 || now <= 0 || !mothershipNametagInitialSeedRecordValid(bootstrap) ||
      bootstrap.operationUUID != prior.intent.operationUUID || bootstrap.baselineOperationUUID != prior.intent.sourceBaselineOperationUUID ||
      bootstrap.dispatchMask != 0xff || bootstrap.completedMask != 0xff) return false;
  for (const auto& cut : prior.sourceCuts)
    if (cut.request.retainUntilMilliseconds > now || (cut.dispatched && !cut.request.memberRequestUUID)) return false;
  for (const auto& plan : next.sourceRepairPlans) for (const auto& cut : prior.sourceCuts) {
    if (cut.request.applicationID != plan.applicationID) continue;
    if (std::count_if(plan.predecessor.statefulRuntimeCohort.begin(), plan.predecessor.statefulRuntimeCohort.end(),
        [&](const auto& member) { return member.containerUUID == cut.request.sourceContainerUUID &&
            member.shardGroup == cut.request.shardGroup && member.clusterUUID == cut.request.sourceClusterUUID; }) != 1) return false;
  }
  MothershipNametagAllMastersIntent initial;
  if (!BitseryEngine::deserializeSafe(bootstrap.intentBytes, initial)) return false;
  for (uint32_t i = 0; i < 3; ++i) {
    auto old = prior.intent.sites[i], proposed = next.sites[i], first = initial.sites[i]; String a, b, c;
    if (i == 0) {
      if (next.protocolVersion == next.radarExpiredCutRecoveryVersion) {
        if (next.sourceRepairPlans.size() != 1 || next.sourceRepairPlans[0].previousDeploymentID != old.radarDeploymentID) return false;
        proposed.radarDeploymentID = old.radarDeploymentID;
      } else {
        if (next.sourceRepairPlans[0].previousDeploymentID != old.hotDeploymentID ||
            next.sourceRepairPlans[1].previousDeploymentID != old.coldDeploymentID) return false;
        proposed.hotDeploymentID = old.hotDeploymentID; proposed.coldDeploymentID = old.coldDeploymentID;
      }
    }
    if (!BitseryEngine::serialize(a, old) || !BitseryEngine::serialize(b, proposed) || !BitseryEngine::serialize(c, first) || a != b || a != c) return false;
  }
  if (next.directGatewayAuthorities.size() != prior.intent.directGatewayAuthorities.size()) return false;
  for (size_t i = 0; i < next.directGatewayAuthorities.size(); ++i) {
    auto a = next.directGatewayAuthorities[i], b = prior.intent.directGatewayAuthorities[i]; String left, right;
    if (!BitseryEngine::serialize(left, a) || !BitseryEngine::serialize(right, b) || left != right) return false;
  }
  return true;
}

static inline bool mothershipNametagExpiredCutRecoveryReportsMatch(const MothershipNametagAllMastersIntent& intent,
    const MothershipNametagInitialSeedRecord& bootstrap, const Vector<DeploymentIdentityReport>& pulse,
    const Vector<DeploymentIdentityReport>& hot, const Vector<DeploymentIdentityReport>& cold,
    const Vector<DeploymentIdentityReport>& radar)
{
  if (!mothershipNametagAllMastersIntentValid(intent) || !intent.isExpiredCutRecovery() ||
      !mothershipNametagInitialSeedRecordValid(bootstrap)) return false;
  const Vector<DeploymentIdentityReport>* reports[] = {&pulse, &hot, &cold, &radar};
  for (const auto* reportsForStore : reports) if (reportsForStore->size() != 3) return false;
  for (const auto& plan : bootstrap.plans) {
    const auto& observed = (*reports[plan.applicationID - 2])[plan.site];
    if (observed.deploymentID != plan.deploymentID || observed.canonicalPlanSHA256 != plan.planSHA256 ||
        observed.normalizedDeploymentPlan != plan.normalizedPlan || observed.containerBlobSHA256 != plan.artifactSHA256 ||
        observed.containerBlobBytes != plan.artifactBytes) return false;
  }
  for (const auto& plan : intent.sourceRepairPlans) {
    const auto& observed = (*reports[plan.applicationID - 2])[0];
    if (observed.deploymentID != plan.successorDeploymentID || observed.canonicalPlanSHA256 != plan.planSHA256 ||
        observed.normalizedDeploymentPlan != plan.normalizedPlan || observed.containerBlobSHA256 != plan.artifactSHA256 ||
        observed.containerBlobBytes != plan.artifactBytes) return false;
  }
  return true;
}

// A successor is retained alongside, never in place of, the completed
// all-masters operation. The caller must provide current authenticated reports
// and route observations before the registry admits this immutable request.
enum class MothershipNametagSeedSuccessorKind : uint8_t { replica = 1, site = 2 };
enum class MothershipNametagSeedSuccessorStage : uint8_t { prepared = 1, held = 2, rebootDispatched = 3, rebootObserved = 4, resumed = 5, complete = 6 };

// Frozen before a disposable site is cancelled. This is an intent, not
// evidence that cancellation, placement, or seeding has occurred.
struct MothershipNametagSeedSuccessorPlan {
  uint16_t applicationID = 0;
  uint64_t previousDeploymentID = 0, successorDeploymentID = 0;
  uint128_t cancellationOperationUUID = 0;
  String planSHA256, artifactSHA256;
  Vector<ProdigyQualificationCancellationMember> previousMembers;
};
template <typename S> static void serialize(S&& s, MothershipNametagSeedSuccessorPlan& v) {
  s.value2b(v.applicationID); s.value8b(v.previousDeploymentID); s.value8b(v.successorDeploymentID);
  s.value16b(v.cancellationOperationUUID); s.text1b(v.planSHA256, 64); s.text1b(v.artifactSHA256, 64); s.container(v.previousMembers, 9);
}
// The old authenticated permission bodies and the complete intended new
// contracts are stored together before either Brain is asked to commit them.
struct MothershipNametagSeedSuccessorRoutePlan {
  bool seeding = false, routeReady = false;
  uint128_t sourceContainerUUID = 0, sourceMachineUUID = 0;
  CousinRouteRecord previousRoute = {}, desiredRoute = {};
  ProdigyLocalCousinServicePermission previousSource = {}, previousDestination = {};
  ProdigyLocalCousinServicePermission desiredSource = {}, desiredDestination = {};
  CousinRouteApplyReceipt previousSourceReceipt = {}, previousDestinationReceipt = {};
};
template <typename S> static void serialize(S&& s, MothershipNametagSeedSuccessorRoutePlan& v) {
  s.value1b(v.seeding); s.value1b(v.routeReady); s.value16b(v.sourceContainerUUID); s.value16b(v.sourceMachineUUID);
  s.object(v.previousRoute); s.object(v.desiredRoute);
  s.object(v.previousSource); s.object(v.previousDestination);
  s.object(v.desiredSource); s.object(v.desiredDestination);
  s.object(v.previousSourceReceipt); s.object(v.previousDestinationReceipt);
}
struct MothershipNametagSeedSuccessorPlacementIntent {
  static constexpr uint32_t legacyVersion = 3, version = 4;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0, predecessorOperationUUID = 0, qualificationRunUUID = 0;
  uint64_t executionGeneration = 0;
  uint8_t qualificationRow = 0, site = 0;
  String predecessorSHA256;
  uint128_t predecessorSuccessorUUID = 0;
  String predecessorSuccessorSHA256;
  Vector<uint32_t> predecessorIndices;
  Vector<MothershipNametagSeedSuccessorPlan> plans;
  uint8_t cancellationDispatchedMask = 0, cancellationCompletedMask = 0;
  Vector<CancelDeploymentResponse> cancellationReceipts;
  Vector<MothershipNametagSeedSuccessorRoutePlan> routePlan;
};
template <typename S> static void serialize(S&& s, MothershipNametagSeedSuccessorPlacementIntent& v) {
  s.value4b(v.protocolVersion); s.value16b(v.operationUUID); s.value16b(v.predecessorOperationUUID);
  s.value16b(v.qualificationRunUUID); s.value8b(v.executionGeneration); s.value1b(v.qualificationRow); s.value1b(v.site);
  s.text1b(v.predecessorSHA256, 64); s.value16b(v.predecessorSuccessorUUID); s.text1b(v.predecessorSuccessorSHA256, 64);
  s.container(v.predecessorIndices, 24, [](S& a, uint32_t& i) { a.value4b(i); });
  s.container(v.plans, 4); s.value1b(v.cancellationDispatchedMask); s.value1b(v.cancellationCompletedMask);
  s.container(v.cancellationReceipts, 4);
  if (v.protocolVersion >= v.version) s.container(v.routePlan, 128);
}
static inline bool mothershipSeedSuccessorRoutePermissionPairValid(const CousinRouteRecord& r,
    const ProdigyLocalCousinServicePermission& a, const ProdigyLocalCousinServicePermission& b, bool accepted) {
  if (!cousinRouteCurrentContract(r) || !cousinRouteStructurallyValid(r) || r.state != CousinRouteState::active ||
      !prodigyLocalCousinServicePermissionValid(a, accepted) || !prodigyLocalCousinServicePermissionValid(b, accepted) ||
      a.protocolVersion != 3 || b.protocolVersion != 3 || a.state != ProdigyLocalCousinServicePermissionState::active ||
      b.state != ProdigyLocalCousinServicePermissionState::active || a.localHalf != CousinRouteHalf::source ||
      b.localHalf != CousinRouteHalf::destination || a.permissionUUID != r.sourcePermissionUUID ||
      b.permissionUUID != r.destinationPermissionUUID || a.pairUUID != r.pairUUID || b.pairUUID != r.pairUUID ||
      a.logicalWorkloadUUID != r.logicalWorkloadUUID || b.logicalWorkloadUUID != r.logicalWorkloadUUID ||
      a.logicalServiceUUID != r.logicalServiceUUID || b.logicalServiceUUID != r.logicalServiceUUID ||
      a.localClusterUUID != r.sourceClusterUUID || a.peerClusterUUID != r.destinationClusterUUID ||
      b.localClusterUUID != r.destinationClusterUUID || b.peerClusterUUID != r.sourceClusterUUID ||
      a.localApplicationID != r.sourceApplicationID || a.peerApplicationID != r.destinationApplicationID ||
      b.localApplicationID != r.destinationApplicationID || b.peerApplicationID != r.sourceApplicationID ||
      a.localCousinServicePrefix != r.sourceCousinServicePrefix || a.peerCousinServicePrefix != r.destinationCousinServicePrefix ||
      b.localCousinServicePrefix != r.destinationCousinServicePrefix || b.peerCousinServicePrefix != r.sourceCousinServicePrefix ||
      !prodigyCousinServicePermissionPeerScopeMatches(a, b)) return false;
  for (uint16_t slot = 0; slot < CousinRouteSlotBitmap::slotCount; ++slot)
    if (r.slots.contains(slot) && (!a.slots.contains(slot) || !b.slots.contains(slot))) return false;
  return true;
}
static inline bool mothershipNametagSeedSuccessorPlacementIntentValid(
    const MothershipNametagSeedSuccessorPlacementIntent& v, const MothershipNametagAllMastersRecord& prior) {
  if ((v.protocolVersion != v.version && v.protocolVersion != v.legacyVersion) ||
      (v.protocolVersion == v.legacyVersion && !v.routePlan.empty()) ||
      !v.operationUUID || !v.qualificationRunUUID || !v.executionGeneration ||
      v.operationUUID == v.predecessorOperationUUID || v.predecessorOperationUUID != prior.intent.operationUUID ||
      (v.qualificationRow != uint8_t(ProdigyNametagQualificationRow::seedInterruptionResume) &&
       v.qualificationRow != uint8_t(ProdigyNametagQualificationRow::brainHardRebootCatchup)) ||
      v.site < 1 || v.site > 2 || !prodigyIsSHA256HexDigest(v.predecessorSHA256) ||
      (v.predecessorSuccessorUUID ? (v.predecessorSuccessorUUID == v.operationUUID || !prodigyIsSHA256HexDigest(v.predecessorSuccessorSHA256)) : !v.predecessorSuccessorSHA256.empty()) ||
      v.predecessorIndices.size() != 24 || v.plans.size() != 4 || prior.seedPlacements.size() != 48 || prior.intent.sites.size() != 3 ||
      (v.cancellationDispatchedMask & 0xf0) || (v.cancellationCompletedMask & ~v.cancellationDispatchedMask)) return false;
  for (uint32_t i = 0; i < v.predecessorIndices.size(); ++i) {
    const auto index = v.predecessorIndices[i];
    if (index >= prior.seedPlacements.size() || prior.seedPlacements[index].site != v.site) return false;
    for (uint32_t j = 0; j < i; ++j) if (v.predecessorIndices[j] == index) return false;
    const auto& old = prior.seedPlacements[index];
    if (std::count_if(v.plans.begin(), v.plans.end(), [&](const auto& plan) {
          return plan.applicationID == old.applicationID && plan.previousDeploymentID == old.targetDeploymentID;
        }) != 1) return false;
  }
  for (uint32_t i = 0; i < v.plans.size(); ++i) {
    const auto& plan = v.plans[i];
    if (!plan.applicationID || !plan.previousDeploymentID || !plan.successorDeploymentID ||
        (plan.previousDeploymentID >> 48) != plan.applicationID || (plan.successorDeploymentID >> 48) != plan.applicationID ||
        plan.successorDeploymentID <= plan.previousDeploymentID || !plan.cancellationOperationUUID ||
        !prodigyIsSHA256HexDigest(plan.planSHA256) || !prodigyIsSHA256HexDigest(plan.artifactSHA256)) return false;
    for (uint32_t j = 0; j < i; ++j)
      if (v.plans[j].applicationID == plan.applicationID || v.plans[j].cancellationOperationUUID == plan.cancellationOperationUUID) return false;
    const auto expectedMembers = std::count_if(prior.seedPlacements.begin(), prior.seedPlacements.end(), [&](const auto& row) {
      return row.site == v.site && row.applicationID == plan.applicationID && row.targetDeploymentID == plan.previousDeploymentID;
    });
    if (plan.previousMembers.size() != size_t(expectedMembers) || !expectedMembers) return false;
    for (const auto& member : plan.previousMembers) {
      if (!member.machineUUID || !member.containerUUID ||
          std::count_if(plan.previousMembers.begin(), plan.previousMembers.end(), [&](const auto& other) {
            return other.containerUUID == member.containerUUID;
          }) != 1 ||
          std::count_if(prior.seedPlacements.begin(), prior.seedPlacements.end(), [&](const auto& row) {
            return row.site == v.site && row.applicationID == plan.applicationID && row.targetDeploymentID == plan.previousDeploymentID &&
                row.targetContainerUUID == member.containerUUID;
          }) != 1) return false;
    }

  }
  if (v.cancellationReceipts.size() != unsigned((v.cancellationCompletedMask & 1) + ((v.cancellationCompletedMask >> 1) & 1) + ((v.cancellationCompletedMask >> 2) & 1) + ((v.cancellationCompletedMask >> 3) & 1))) return false;
  for (const auto& receipt : v.cancellationReceipts) {
    if (!receipt.success || receipt.result != CancelDeploymentResult::completed ||
        receipt.phase != CancelDeploymentPhase::completed || !receipt.durableGeneration ||
        !prodigyCanonicalOperationUUID(receipt.operationID)) return false;
    uint128_t operation = 0;
    for (uint32_t i = 0; i < receipt.operationID.size(); ++i) {
      const char c = receipt.operationID[i]; if (c == '-') continue;
      operation = (operation << 4) | uint128_t(c <= '9' ? c - '0' : c - 'a' + 10);
    }
    uint32_t matches = 0;
    for (uint32_t i = 0; i < v.plans.size(); ++i) {
      const auto& plan = v.plans[i];
      if ((v.cancellationCompletedMask & (1u << i)) && plan.cancellationOperationUUID == operation &&
          plan.applicationID == receipt.applicationID && plan.previousDeploymentID == receipt.cancelledDeploymentID &&
          plan.successorDeploymentID == receipt.successorDeploymentID &&
          receipt.activeVersionID == (plan.previousDeploymentID & ((uint64_t(1) << 48) - 1)) &&
          receipt.successorVersionID == (plan.successorDeploymentID & ((uint64_t(1) << 48) - 1))) ++matches;
    }
    if (matches != 1 || std::count_if(v.cancellationReceipts.begin(), v.cancellationReceipts.end(), [&](const auto& other) {
          return other.operationID == receipt.operationID;
        }) != 1) return false;
  }
  if (!v.routePlan.empty()) {
    uint32_t seedCount = 0;
    for (size_t i = 0; i < v.routePlan.size(); ++i) {
      const auto& x = v.routePlan[i];
      if (!mothershipSeedSuccessorRoutePermissionPairValid(x.previousRoute, x.previousSource, x.previousDestination, true) ||
          !mothershipSeedSuccessorRoutePermissionPairValid(x.desiredRoute, x.desiredSource, x.desiredDestination, false) ||
          !cousinRouteApplyReceiptMatchesCurrentRoute(x.previousSourceReceipt, x.previousRoute) ||
          !cousinRouteApplyReceiptMatchesCurrentRoute(x.previousDestinationReceipt, x.previousRoute) ||
          x.previousSourceReceipt.localHalf != CousinRouteHalf::source || x.previousDestinationReceipt.localHalf != CousinRouteHalf::destination ||
          x.desiredRoute.routeUUID == x.previousRoute.routeUUID || x.desiredRoute.operationUUID == x.previousRoute.operationUUID ||
          x.desiredSource.permissionUUID == x.previousSource.permissionUUID || x.desiredDestination.permissionUUID == x.previousDestination.permissionUUID ||
          x.desiredSource.permissionUUID == x.previousDestination.permissionUUID || x.desiredDestination.permissionUUID == x.previousSource.permissionUUID ||
          x.desiredSource.permissionUUID == x.desiredDestination.permissionUUID ||
          x.desiredRoute.pairUUID != x.previousRoute.pairUUID || x.desiredRoute.logicalWorkloadUUID != x.previousRoute.logicalWorkloadUUID ||
          x.desiredRoute.logicalServiceUUID != x.previousRoute.logicalServiceUUID ||
          x.desiredRoute.sourceClusterUUID != x.previousRoute.sourceClusterUUID || x.desiredRoute.destinationClusterUUID != x.previousRoute.destinationClusterUUID ||
          x.desiredRoute.sourceApplicationID != x.previousRoute.sourceApplicationID || x.desiredRoute.destinationApplicationID != x.previousRoute.destinationApplicationID ||
          x.desiredRoute.sourceCousinServicePrefix != x.previousRoute.sourceCousinServicePrefix || x.desiredRoute.destinationCousinServicePrefix != x.previousRoute.destinationCousinServicePrefix ||
          x.desiredRoute.slots != x.previousRoute.slots || x.desiredSource.purpose != x.previousSource.purpose ||
          x.desiredSource.slots != x.previousSource.slots || x.desiredDestination.slots != x.previousDestination.slots ||
          x.desiredSource.authorizedService != x.previousSource.authorizedService ||
          x.desiredSource.destinationShardGroup != x.previousSource.destinationShardGroup || x.desiredSource.destinationShardGroups != x.previousSource.destinationShardGroups ||
          x.seeding != (x.desiredSource.purpose == ProdigyCousinServicePurpose::seeding)) return false;
      const auto matches = std::count_if(v.plans.begin(), v.plans.end(), [&](const auto& p) {
        return (x.previousSource.localClusterUUID == prior.intent.sites[v.site].clusterUUID && x.previousSource.localDeploymentID == p.previousDeploymentID && x.desiredSource.localDeploymentID == p.successorDeploymentID && x.desiredSource.canonicalPlanSHA256 == p.planSHA256 && x.desiredSource.artifactSHA256 == p.artifactSHA256) ||
               (x.previousDestination.localClusterUUID == prior.intent.sites[v.site].clusterUUID && x.previousDestination.localDeploymentID == p.previousDeploymentID && x.desiredDestination.localDeploymentID == p.successorDeploymentID && x.desiredDestination.canonicalPlanSHA256 == p.planSHA256 && x.desiredDestination.artifactSHA256 == p.artifactSHA256);
      });
      if (matches != 1) return false;
      const auto& oldPeer = x.previousSource.localClusterUUID == prior.intent.sites[v.site].clusterUUID ? x.previousDestination : x.previousSource;
      const auto& newPeer = x.previousSource.localClusterUUID == prior.intent.sites[v.site].clusterUUID ? x.desiredDestination : x.desiredSource;
      if (oldPeer.localDeploymentID != newPeer.localDeploymentID || oldPeer.canonicalPlanSHA256 != newPeer.canonicalPlanSHA256 ||
          oldPeer.artifactSHA256 != newPeer.artifactSHA256 || oldPeer.artifactBytes != newPeer.artifactBytes ||
          !((newPeer.baselineLogicalCores == 0 && newPeer.baselineMemoryMB == 0 && newPeer.baselineStorageMB == 0) ||
            (oldPeer.baselineLogicalCores == newPeer.baselineLogicalCores && oldPeer.baselineMemoryMB == newPeer.baselineMemoryMB &&
             oldPeer.baselineStorageMB == newPeer.baselineStorageMB))) return false;
      if (x.seeding) {
        if (x.routeReady ? (!x.sourceContainerUUID || !x.sourceMachineUUID) : (x.sourceContainerUUID || x.sourceMachineUUID)) return false;
        if (x.previousRoute.version != 3 || x.desiredRoute.version != 3 ||
            x.desiredRoute.endpointKind != CousinRouteEndpointKind::privateContainer ||
            x.desiredRoute.destinationRoutablePrefixUUID || x.desiredRoute.destinationCIDR != 128) return false;
        ++seedCount;
        if (std::count_if(prior.intent.seedRoutes.begin(), prior.intent.seedRoutes.end(), [&](const auto& ref) {
          return ref.site == v.site && ref.routeUUID == x.previousRoute.routeUUID &&
                 ref.applicationID == x.previousSource.localApplicationID && ref.shardGroup == x.previousSource.destinationShardGroup;
        }) != 1) return false;
      } else if (x.sourceContainerUUID || x.sourceMachineUUID) return false;
      for (size_t j = 0; j < i; ++j)
        if (v.routePlan[j].previousRoute.routeUUID == x.previousRoute.routeUUID || v.routePlan[j].desiredRoute.routeUUID == x.desiredRoute.routeUUID ||
            v.routePlan[j].desiredRoute.operationUUID == x.desiredRoute.operationUUID ||
            v.routePlan[j].desiredSource.permissionUUID == x.desiredSource.permissionUUID ||
            v.routePlan[j].desiredDestination.permissionUUID == x.desiredDestination.permissionUUID ||
            v.routePlan[j].desiredDestination.permissionUUID == x.desiredSource.permissionUUID ||
            v.routePlan[j].desiredSource.permissionUUID == x.desiredDestination.permissionUUID) return false;
    }
    if (seedCount != 8) return false;
  }
  return true;
}

struct MothershipNametagSeedSuccessorTarget {
  uint32_t predecessorIndex = UINT32_MAX;
  uint64_t targetDeploymentID = 0;
  uint128_t containerUUID = 0;
  uint128_t machineUUID = 0;
  uint128_t routeUUID = 0;
  ProdigyStatefulStoreSeedAuthority authority = {.protocolVersion = 0};
  bool deliveryDispatched = false, deliveryApplied = false;
  ProdigyStatefulStoreReceipt nativeReceipt = {.protocolVersion = 0};
};
template <typename S> static void serialize(S&& s, MothershipNametagSeedSuccessorTarget& v) {
  s.value4b(v.predecessorIndex); s.value8b(v.targetDeploymentID); s.value16b(v.containerUUID); s.value16b(v.machineUUID); s.value16b(v.routeUUID);
  s.object(v.authority); s.value1b(v.deliveryDispatched); s.value1b(v.deliveryApplied); s.object(v.nativeReceipt);
}
struct MothershipNametagSeedRebootFence {
  uint128_t clusterUUID = 0, machineUUID = 0, dispatchUUID = 0;
  String beforeBootID, afterBootID;
  bool dispatched = false, providerAccepted = false, observed = false;
};
template <typename S> static void serialize(S&& s, MothershipNametagSeedRebootFence& v) {
  s.value16b(v.clusterUUID); s.value16b(v.machineUUID); s.value16b(v.dispatchUUID);
  s.text1b(v.beforeBootID, 64); s.text1b(v.afterBootID, 64); s.value1b(v.dispatched); s.value1b(v.providerAccepted); s.value1b(v.observed);
}
struct MothershipNametagSeedSuccessor {
  // Version 4 additionally retains the acknowledged provider reboot submission.
  static constexpr uint32_t version = 4;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0, predecessorOperationUUID = 0, qualificationRunUUID = 0;
  uint8_t qualificationRow = 0; uint64_t executionGeneration = 0;
  String predecessorSHA256;
  uint128_t predecessorSuccessorUUID = 0;
  String predecessorSuccessorSHA256;
  MothershipNametagSeedSuccessorKind kind = MothershipNametagSeedSuccessorKind::replica;
  uint8_t site = 0;
  uint32_t heldTargetIndex = UINT32_MAX;
  Vector<MothershipNametagSeedSuccessorTarget> targets;
  Vector<MothershipNametagSourceCutProgress> sourceCuts;
  MothershipNametagSeedSuccessorStage stage = MothershipNametagSeedSuccessorStage::prepared;
  MothershipNametagSeedRebootFence sourceReboot, destinationReboot;
  ProdigyNametagQualificationSeedFault heldReceipt = {}, releaseReceipt = {};
  bool releaseDispatched = false;
  uint8_t sourceCutReleaseDispatchedMask = 0;
  Vector<ProdigyStatefulStoreSourceCut> sourceCutReleaseReceipts;
};
template <typename S> static void serialize(S&& s, MothershipNametagSeedSuccessor& v) {
  s.value4b(v.protocolVersion); s.value16b(v.operationUUID); s.value16b(v.predecessorOperationUUID);
  s.value16b(v.qualificationRunUUID); s.value1b(v.qualificationRow); s.value8b(v.executionGeneration); s.text1b(v.predecessorSHA256, 64);
  s.value16b(v.predecessorSuccessorUUID); s.text1b(v.predecessorSuccessorSHA256, 64); s.value1b(v.kind);
  s.value1b(v.site); s.value4b(v.heldTargetIndex); s.container(v.targets, 24); s.container(v.sourceCuts, 8);
  s.value1b(v.stage); s.object(v.sourceReboot); s.object(v.destinationReboot); s.object(v.heldReceipt);
  s.object(v.releaseReceipt); s.value1b(v.releaseDispatched); s.value1b(v.sourceCutReleaseDispatchedMask);
  s.container(v.sourceCutReleaseReceipts, 8);
}

// Derive the authority from the retained cut and observed replacement. Only the
// selected KV target carries the qualification hold; the other 23 seed normally.
static inline bool mothershipNametagSeedSuccessorAuthority(const MothershipNametagSeedSuccessor& v,
    const MothershipNametagAllMastersRecord& prior, uint32_t index, uint128_t challenge,
    int64_t deadline, ProdigyStatefulStoreSeedAuthority& a) {
  a = {};
  if (index >= v.targets.size() || v.targets[index].predecessorIndex >= prior.seedPlacements.size()) return false;
  const auto& t = v.targets[index]; const auto& old = prior.seedPlacements[t.predecessorIndex];
  const auto cut = std::find_if(v.sourceCuts.begin(), v.sourceCuts.end(), [&](const auto& c) {
    return c.request.applicationID == old.applicationID && c.request.shardGroup == old.shardGroup;
  });
  if (cut == v.sourceCuts.end() || !cut->proof.ready || old.seedGeneration == UINT64_MAX) return false;
  a.protocolVersion = ProdigyStatefulStoreSeedAuthority::sourceCutVersion;
  a.authorityGeneration = a.seedGeneration = old.seedGeneration + 1; a.operationUUID = v.operationUUID;
  a.applicationID = old.applicationID; a.storeKind = old.storeKind; a.shardGroup = old.shardGroup;
  a.nShardGroups = cut->request.nShardGroups; a.targetClusterUUID = old.targetClusterUUID;
  a.targetDeploymentID = t.targetDeploymentID; a.targetContainerUUID = t.containerUUID;
  a.sourceClusterUUID = cut->request.sourceClusterUUID; a.sourceDeploymentID = cut->request.sourceDeploymentID;
  a.sourceContainerUUID = cut->request.sourceContainerUUID; a.fixtureSHA256 = old.fixtureSHA256;
  a.sourceContentWatermarkSHA256 = cut->proof.contentSHA256; a.sourceCatchupWatermarkSHA256 = cut->proof.headsSHA256;
  a.sourceBaselineOperationUUID = prior.intent.sourceBaselineOperationUUID;
  a.sourceRequestUUID = cut->request.requestUUID; a.sourceMemberRequestUUID = cut->request.memberRequestUUID;
  a.cutUUID = cut->proof.cutUUID; a.cutGeneration = cut->proof.cutGeneration;
  a.seedRouteUUID = t.routeUUID; a.sourceCutScope = cut->request.scope; a.retainUntilMilliseconds = cut->request.retainUntilMilliseconds;
  if (index == v.heldTargetIndex) {
    a.protocolVersion = ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion;
    a.qualificationRunUUID = v.qualificationRunUUID; a.qualificationChallengeUUID = challenge;
    a.qualificationExecutionGeneration = v.executionGeneration; a.qualificationDeadlineAtMilliseconds = deadline;
  } else if (challenge || deadline) return false;
  return prodigyStatefulStoreSeedAuthorityValid(a);
}
static inline bool mothershipNametagSeedSuccessorNativeComplete(const MothershipNametagSeedSuccessor& v) {
  return v.targets.size() == 24 && std::all_of(v.targets.begin(), v.targets.end(), [](const auto& t) {
    return t.deliveryDispatched && t.deliveryApplied &&
        t.nativeReceipt.state == ProdigyStatefulStoreReceiptState::active &&
        prodigyStatefulStoreReceiptMatchesSourceCutAuthority(t.nativeReceipt, t.authority);
  });
}

static inline bool mothershipNametagSeedSuccessorValid(const MothershipNametagSeedSuccessor& v,
    const MothershipNametagAllMastersRecord& prior, const Vector<DeploymentIdentityReport>& reports,
    bool requireLiveReports = true)
{
  if (v.protocolVersion != v.version || !v.operationUUID || !v.qualificationRunUUID || !v.qualificationRow || !v.executionGeneration ||
      v.operationUUID == v.predecessorOperationUUID || v.predecessorOperationUUID != prior.intent.operationUUID ||
      !prodigyIsSHA256HexDigest(v.predecessorSHA256) || v.site < 1 || v.site > 2 ||
      (v.kind != MothershipNametagSeedSuccessorKind::replica && v.kind != MothershipNametagSeedSuccessorKind::site) ||
      v.targets.size() != 24 ||
      v.heldTargetIndex >= v.targets.size() || v.sourceCuts.size() != 8 ||
      v.stage < MothershipNametagSeedSuccessorStage::prepared || v.stage > MothershipNametagSeedSuccessorStage::complete ||
      (!requireLiveReports && v.stage != MothershipNametagSeedSuccessorStage::complete) ||
      (v.qualificationRow != uint8_t(ProdigyNametagQualificationRow::seedInterruptionResume) &&
       v.qualificationRow != uint8_t(ProdigyNametagQualificationRow::brainHardRebootCatchup)) ||
      (v.predecessorSuccessorUUID ? (v.predecessorSuccessorUUID == v.operationUUID || !prodigyIsSHA256HexDigest(v.predecessorSuccessorSHA256)) : !v.predecessorSuccessorSHA256.empty())) return false;
  for (uint32_t i = 0; i < v.targets.size(); ++i) {
    const auto& t = v.targets[i];
    if (t.predecessorIndex >= prior.seedPlacements.size() || !t.containerUUID || !t.machineUUID || !t.routeUUID) return false;
    const auto& old = prior.seedPlacements[t.predecessorIndex];
    if (old.site != v.site || !t.targetDeploymentID || t.targetDeploymentID <= old.targetDeploymentID ||
        (t.targetDeploymentID >> 48) != old.applicationID || t.containerUUID == old.targetContainerUUID) return false;
    for (const auto& historical : prior.seedPlacements)
      if (historical.targetClusterUUID == old.targetClusterUUID && historical.targetContainerUUID == t.containerUUID) return false;
    for (uint32_t j = 0; j < i; ++j)
      if (v.targets[j].predecessorIndex == t.predecessorIndex || v.targets[j].containerUUID == t.containerUUID) return false;
    const auto report = std::find_if(reports.begin(), reports.end(), [&](const auto& r) {
      return r.found && r.live && r.clusterUUID == old.targetClusterUUID && r.deploymentID == t.targetDeploymentID && r.applicationID == old.applicationID;
    });
    if (requireLiveReports && (report == reports.end() || std::count_if(report->statefulRuntimeCohort.begin(), report->statefulRuntimeCohort.end(), [&](const auto& member) {
          return member.clusterUUID == old.targetClusterUUID && member.containerUUID == t.containerUUID && member.machineUUID == t.machineUUID &&
              member.storeKind == old.storeKind && member.shardGroup == old.shardGroup;
        }) != 1)) return false;
    const auto cut = std::find_if(v.sourceCuts.begin(), v.sourceCuts.end(), [&](const auto& c) {
      return c.request.applicationID == old.applicationID && c.request.shardGroup == old.shardGroup;
    });
    if (cut == v.sourceCuts.end() || cut->request.operationUUID != v.operationUUID ||
        cut->request.action != ProdigyStatefulStoreSourceCutAction::prepare ||
        cut->request.sourceClusterUUID != old.sourceClusterUUID || cut->request.sourceDeploymentID != old.sourceDeploymentID ||
        cut->request.storeKind != old.storeKind ||
        cut->request.nShardGroups != (old.storeKind == DeploymentIdentityStoreKind::kv ? 3u : 1u) ||
        !prodigyStatefulStoreSourceCutValid(cut->request) || cut->request.response ||
        (cut->request.memberRequestUUID && !cut->dispatched) ||
        (cut->released && (v.stage < MothershipNametagSeedSuccessorStage::resumed || !mothershipNametagSeedSuccessorNativeComplete(v))) ||
        (cut->proof.response && (!cut->dispatched || !cut->proof.ready ||
          !prodigyStatefulStoreSourceCutResponseMatches(cut->request, cut->proof))) ||
        (!cut->proof.response && (cut->proof.ready || cut->proof.cutUUID || cut->proof.cutGeneration ||
          !cut->proof.contentSHA256.empty() || !cut->proof.headsSHA256.empty() || !cut->proof.failure.empty())) ||
        (v.stage != MothershipNametagSeedSuccessorStage::prepared && !cut->proof.ready)) return false;
    for (uint32_t j = 0; j < i; ++j) {
      const auto& before = v.targets[j]; const auto& row = prior.seedPlacements[before.predecessorIndex];
      if (row.applicationID == old.applicationID && (before.targetDeploymentID != t.targetDeploymentID ||
          (row.shardGroup == old.shardGroup && before.routeUUID != t.routeUUID))) return false;
    }
    if (!t.authority.protocolVersion) {
      auto empty = ProdigyStatefulStoreSeedAuthority{.protocolVersion = 0}, copy = t.authority; String a, b;
      if (t.deliveryDispatched || t.deliveryApplied || t.nativeReceipt.protocolVersion ||
          !BitseryEngine::serialize(a, empty) || !BitseryEngine::serialize(b, copy) || a != b) return false;
    } else {
      ProdigyStatefulStoreSeedAuthority expected = {};
      if (!mothershipNametagSeedSuccessorAuthority(v, prior, i, t.authority.qualificationChallengeUUID,
          t.authority.qualificationDeadlineAtMilliseconds, expected)) return false;
      String a, b; auto actual = t.authority;
      if (!BitseryEngine::serialize(a, expected) || !BitseryEngine::serialize(b, actual) || a != b ||
          (t.deliveryApplied && !t.deliveryDispatched)) return false;
      if (t.nativeReceipt.protocolVersion && (!t.deliveryApplied ||
          t.nativeReceipt.state != ProdigyStatefulStoreReceiptState::active ||
          !prodigyStatefulStoreReceiptMatchesSourceCutAuthority(t.nativeReceipt, t.authority) ||
          (i == v.heldTargetIndex && v.stage < MothershipNametagSeedSuccessorStage::resumed))) return false;
    }
  }
  const auto& heldTarget = v.targets[v.heldTargetIndex];
  const auto& heldOld = prior.seedPlacements[heldTarget.predecessorIndex];
  if (heldOld.storeKind != DeploymentIdentityStoreKind::kv) return false;
  if (v.stage == MothershipNametagSeedSuccessorStage::prepared) {
    auto empty = ProdigyNametagQualificationSeedFault{}, observed = v.heldReceipt; String a, b;
    if (!BitseryEngine::serialize(a, empty) || !BitseryEngine::serialize(b, observed) || a != b) return false;
  } else {
    const auto cut = std::find_if(v.sourceCuts.begin(), v.sourceCuts.end(), [&](const auto& c) {
      return c.request.applicationID == heldOld.applicationID && c.request.shardGroup == heldOld.shardGroup;
    });
    const auto& receipt = v.heldReceipt; const auto& a = receipt.authority;
    String heldBytes, deliveredBytes; auto heldAuthority = a, deliveredAuthority = heldTarget.authority;
    if (!heldTarget.deliveryApplied || !BitseryEngine::serialize(heldBytes, heldAuthority) ||
        !BitseryEngine::serialize(deliveredBytes, deliveredAuthority) || heldBytes != deliveredBytes) return false;
    if (cut == v.sourceCuts.end() || !prodigyNametagQualificationSeedFaultValid(receipt) || !receipt.response ||
        !receipt.ready || !receipt.held || receipt.stage != ProdigyNametagQualificationSeedFaultStage::query ||
        receipt.runUUID != v.qualificationRunUUID || receipt.executionGeneration != v.executionGeneration ||
        a.operationUUID != v.operationUUID || a.sourceBaselineOperationUUID != prior.intent.sourceBaselineOperationUUID ||
        a.applicationID != heldOld.applicationID || a.storeKind != heldOld.storeKind || a.shardGroup != heldOld.shardGroup ||
        a.nShardGroups != cut->request.nShardGroups || a.seedGeneration <= heldOld.seedGeneration || a.fixtureSHA256 != heldOld.fixtureSHA256 ||
        a.targetClusterUUID != heldOld.targetClusterUUID || a.targetDeploymentID != heldTarget.targetDeploymentID ||
        a.targetContainerUUID != heldTarget.containerUUID || a.seedRouteUUID != heldTarget.routeUUID ||
        a.sourceClusterUUID != cut->request.sourceClusterUUID || a.sourceDeploymentID != cut->request.sourceDeploymentID ||
        a.sourceContainerUUID != cut->request.sourceContainerUUID || a.sourceRequestUUID != cut->request.requestUUID ||
        a.sourceMemberRequestUUID != cut->request.memberRequestUUID || a.cutUUID != cut->proof.cutUUID ||
        a.cutGeneration != cut->proof.cutGeneration || a.sourceCutScope != cut->request.scope ||
        a.retainUntilMilliseconds != cut->request.retainUntilMilliseconds ||
        a.sourceContentWatermarkSHA256 != cut->proof.contentSHA256 || a.sourceCatchupWatermarkSHA256 != cut->proof.headsSHA256) return false;
  }
  if (v.releaseDispatched && v.stage < MothershipNametagSeedSuccessorStage::held) return false;
  if (v.releaseDispatched && v.kind == MothershipNametagSeedSuccessorKind::replica)
    for (uint32_t i = 0; i < v.targets.size(); ++i) {
      if (i == v.heldTargetIndex) continue;
      const auto& target = v.targets[i];
      if (target.nativeReceipt.state != ProdigyStatefulStoreReceiptState::active ||
          !prodigyStatefulStoreReceiptMatchesSourceCutAuthority(target.nativeReceipt, target.authority)) return false;
    }
  if (v.stage < MothershipNametagSeedSuccessorStage::resumed) {
    auto empty = ProdigyNametagQualificationSeedFault{}, actual = v.releaseReceipt; String a, b;
    if (!BitseryEngine::serialize(a, empty) || !BitseryEngine::serialize(b, actual) || a != b ||
        v.sourceCutReleaseDispatchedMask || !v.sourceCutReleaseReceipts.empty()) return false;
  } else {
    auto request = v.heldReceipt; request.stage = ProdigyNametagQualificationSeedFaultStage::release;
    request.response = request.ready = request.held = false; request.sessionUUID = 0;
    request.sessionGeneration = request.appliedFrames = 0; request.failure.clear();
    if (!v.releaseDispatched || !v.releaseReceipt.ready ||
        !prodigyNametagQualificationSeedFaultResponseMatches(request, v.releaseReceipt)) return false;
  }
  for (uint32_t i = 0; i < v.sourceCuts.size(); ++i) {
    const auto& cut = v.sourceCuts[i]; const auto bit = uint8_t(1u << i);
    const auto receipt = std::find_if(v.sourceCutReleaseReceipts.begin(), v.sourceCutReleaseReceipts.end(),
        [&](const auto& r) { return r.requestUUID == cut.request.requestUUID; });
    if (cut.released != (receipt != v.sourceCutReleaseReceipts.end())) return false;
    if (receipt != v.sourceCutReleaseReceipts.end()) {
      auto request = cut.request; request.action = ProdigyStatefulStoreSourceCutAction::release;
      request.cutUUID = cut.proof.cutUUID; request.cutGeneration = cut.proof.cutGeneration;
      if (!(v.sourceCutReleaseDispatchedMask & bit) || !receipt->released ||
          !prodigyStatefulStoreSourceCutResponseMatches(request, *receipt) ||
          std::count_if(v.sourceCutReleaseReceipts.begin(), v.sourceCutReleaseReceipts.end(),
            [&](const auto& r) { return r.requestUUID == receipt->requestUUID; }) != 1) return false;
    }
  }
  if (std::any_of(v.sourceCutReleaseReceipts.begin(), v.sourceCutReleaseReceipts.end(), [&](const auto& r) {
        return std::none_of(v.sourceCuts.begin(), v.sourceCuts.end(), [&](const auto& c) { return c.request.requestUUID == r.requestUUID; });
      }) || (v.sourceCutReleaseDispatchedMask && !mothershipNametagSeedSuccessorNativeComplete(v)) ||
      (v.stage == MothershipNametagSeedSuccessorStage::complete &&
       (!mothershipNametagSeedSuccessorNativeComplete(v) || v.sourceCutReleaseReceipts.size() != 8))) return false;
  for (const auto& cut : v.sourceCuts) {
    if (std::none_of(v.targets.begin(), v.targets.end(), [&](const auto& target) {
          const auto& old = prior.seedPlacements[target.predecessorIndex];
          return old.applicationID == cut.request.applicationID && old.shardGroup == cut.request.shardGroup;
        })) return false;
    for (const auto& historical : prior.sourceCuts)
      if (historical.request.requestUUID == cut.request.requestUUID ||
          (historical.proof.cutUUID && historical.proof.cutUUID == cut.proof.cutUUID)) return false;
  }
  for (uint32_t i = 0; i < v.sourceCuts.size(); ++i) for (uint32_t j = 0; j < i; ++j)
    if (v.sourceCuts[i].request.applicationID == v.sourceCuts[j].request.applicationID &&
        v.sourceCuts[i].request.shardGroup == v.sourceCuts[j].request.shardGroup) return false;
  auto fenceValid = [](const MothershipNametagSeedRebootFence& f) {
    if (!f.clusterUUID && !f.machineUUID && !f.dispatchUUID && f.beforeBootID.empty() && f.afterBootID.empty()) return !f.dispatched && !f.providerAccepted && !f.observed;
    return f.clusterUUID && f.machineUUID && f.dispatchUUID && prodigyCanonicalOperationUUID(f.beforeBootID) &&
        (!f.providerAccepted || f.dispatched) &&
        (!f.observed ? f.afterBootID.empty() : f.providerAccepted && prodigyCanonicalOperationUUID(f.afterBootID) && f.afterBootID != f.beforeBootID);
  };
  const bool rebootRow = v.qualificationRow == uint8_t(ProdigyNametagQualificationRow::brainHardRebootCatchup);
  if (!rebootRow && (v.sourceReboot.clusterUUID || v.destinationReboot.clusterUUID ||
      v.stage == MothershipNametagSeedSuccessorStage::rebootDispatched || v.stage == MothershipNametagSeedSuccessorStage::rebootObserved)) return false;
  return fenceValid(v.sourceReboot) && fenceValid(v.destinationReboot) &&
      (!rebootRow || v.stage < MothershipNametagSeedSuccessorStage::rebootDispatched ||
          (v.sourceReboot.dispatched && v.destinationReboot.dispatched)) &&
      (!rebootRow || v.stage < MothershipNametagSeedSuccessorStage::rebootObserved ||
          (v.sourceReboot.observed && v.destinationReboot.observed)) &&
      (!v.sourceReboot.clusterUUID || v.sourceReboot.clusterUUID == prior.intent.sites[0].clusterUUID) &&
      (!v.destinationReboot.clusterUUID || v.destinationReboot.clusterUUID == prior.intent.sites[v.site].clusterUUID);
}

// This is a derived current-cohort view, not another all-masters operation or a
// rewritten historical record. Its receipts retain their actual successor IDs.
// Validate each completed link before projecting it; persist only the links.
static inline bool mothershipNametagSeedSuccessorProject(const MothershipNametagSeedSuccessor& completed,
    MothershipNametagAllMastersRecord& current) {
  if (!mothershipNametagSeedSuccessorValid(completed, current, {}, false)) return false;
  for (const auto& target : completed.targets) {
    auto& row = current.seedPlacements[target.predecessorIndex]; const auto& a = target.authority;
    row.targetDeploymentID = target.targetDeploymentID; row.targetContainerUUID = target.containerUUID;
    row.sourceContainerUUID = a.sourceContainerUUID; row.sourceDeploymentID = a.sourceDeploymentID;
    row.seedGeneration = a.seedGeneration; row.sourceContentWatermarkSHA256 = a.sourceContentWatermarkSHA256;
    row.sourceCatchupWatermarkSHA256 = a.sourceCatchupWatermarkSHA256;
    row.deliveryDispatched = row.deliveryApplied = row.catchupObserved = true; row.nativeSourceCutReceipt = target.nativeReceipt;
    row.qualificationRunUUID = a.qualificationRunUUID; row.qualificationChallengeUUID = a.qualificationChallengeUUID;
    row.qualificationExecutionGeneration = a.qualificationExecutionGeneration;
    row.qualificationDeadlineAtMilliseconds = a.qualificationDeadlineAtMilliseconds;
    auto& site = current.intent.sites[row.site];
    if (row.applicationID == MeshRegistry::Hot::applicationID) site.hotDeploymentID = target.targetDeploymentID;
    else if (row.applicationID == MeshRegistry::Cold::applicationID) site.coldDeploymentID = target.targetDeploymentID;
    else if (row.applicationID == MeshRegistry::Pulse::applicationID) site.pulseDeploymentID = target.targetDeploymentID;
    else if (row.applicationID == MeshRegistry::Radar::applicationID) site.radarDeploymentID = target.targetDeploymentID;
    else return false;
    const auto route = std::find_if(current.intent.seedRoutes.begin(), current.intent.seedRoutes.end(), [&](const auto& r) {
      return r.site == row.site && r.applicationID == row.applicationID && r.shardGroup == row.shardGroup;
    });
    if (route == current.intent.seedRoutes.end()) return false;
    route->routeUUID = target.routeUUID;
  }
  // Keep every cut identity so a later link cannot reuse a prior request/cut.
  for (const auto& cut : completed.sourceCuts) current.sourceCuts.push_back(cut);
  return true;
}
