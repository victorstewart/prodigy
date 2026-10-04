#pragma once

// Pure admission logic. It owns no lifecycle state and has no cluster/provider
// side effects. The existing bundle/release approval owner supplies the envelope.
#include <networking/includes.h>
#include <simdjson.h>

static inline bool prodigyIsSHA256HexDigest(const String& digest);
static inline bool prodigyComputeSHA256Hex(const String& payload, String& digest, String *failure);

enum class MothershipUpgradeDisposition : uint8_t {
  sameClusterRollout,
  newClusterRequired,
  unsupported,
};

enum class MothershipUpgradePath : uint8_t {
  reject,
  sameLogicalRollout,
  logicalClusterRelocation,
  separateClusterMigration,
};

enum class MothershipUpgradeCompatibilityState : uint8_t {
  unknown,
  compatible,
  incompatible,
};

struct MothershipUpgradeIdentity {
  String releaseID = {};
  String contractSHA256 = {};
  String prodigySHA256 = {};
  String mothershipSHA256 = {};
};

// `contractSHA256` is the SHA256 of the exact embedded contract bytes. It is
// supplied by the existing local bundle-approval owner; the contract never
// hashes itself or asserts trust through a JSON signature field.
struct MothershipUpgradeEnvelope {
  bool approvedByBundleOwner = false;
  String approvedBundleSHA256 = {};
  String contractSHA256 = {};
  String prodigySHA256 = {};
  String mothershipSHA256 = {};
};

struct MothershipUpgradeCompatibility {
  MothershipUpgradeCompatibilityState wire = MothershipUpgradeCompatibilityState::unknown;
  MothershipUpgradeCompatibilityState persistentState = MothershipUpgradeCompatibilityState::unknown;
  MothershipUpgradeCompatibilityState authorityState = MothershipUpgradeCompatibilityState::unknown;
  MothershipUpgradeCompatibilityState transportTrust = MothershipUpgradeCompatibilityState::unknown;
  MothershipUpgradeCompatibilityState containerProtocol = MothershipUpgradeCompatibilityState::unknown;
  MothershipUpgradeCompatibilityState dataPlane = MothershipUpgradeCompatibilityState::unknown;
  MothershipUpgradeCompatibilityState appState = MothershipUpgradeCompatibilityState::unknown;

  bool allCompatible(void) const
  {
    return wire == MothershipUpgradeCompatibilityState::compatible &&
           persistentState == MothershipUpgradeCompatibilityState::compatible &&
           authorityState == MothershipUpgradeCompatibilityState::compatible &&
           transportTrust == MothershipUpgradeCompatibilityState::compatible &&
           containerProtocol == MothershipUpgradeCompatibilityState::compatible &&
           dataPlane == MothershipUpgradeCompatibilityState::compatible &&
           appState == MothershipUpgradeCompatibilityState::compatible;
  }
};

struct MothershipUpgradeContract {
  uint32_t manifestVersion = 0;
  uint32_t minimumHealthyBrains = 0;
  uint32_t containerRetirementJournalVersion = 0;
  uint64_t requiredFreeBytes = 0;
  String releaseID = {};
  String contractSHA256 = {};
  String prodigySHA256 = {};
  String mothershipSHA256 = {};
  String architecture = {};
  String binaryVersion = {};
  String rollbackMode = {};
  // A qualified exact-source claim about unchanged cluster CA, role, UUID and
  // enrollment semantics. Current peer TLS evidence is still required.
  String transportIdentityMode = {};
  String migrationProtocolVersion = {};
  MothershipUpgradeDisposition disposition = MothershipUpgradeDisposition::unsupported;
  MothershipUpgradeCompatibility compatibility = {};
  Vector<MothershipUpgradeIdentity> sources = {};
};

struct MothershipUpgradeWorkloadInput {
  String applicationID = {};
  bool stateful = false;
  bool migrationEligible = false;
  bool bridgeProtocolAvailable = false;
  bool endpointStrategyAvailable = false;
  bool fencingAvailable = false;
  bool observedPublicContinuity = false;
};

// Observed topology and workload evidence remain outside the generic release
// contract, so a release contract cannot become a self-referential plan hash.
struct MothershipUpgradePlannerInput {
  MothershipUpgradeEnvelope envelope = {};
  MothershipUpgradeIdentity observedSource = {};
  String observedTargetArchitecture = {};
  uint128_t sourceClusterUUID = 0;
  uint128_t targetClusterUUID = 0;
  bool requestProviderRelocation = false;
  bool requestSeparateCluster = false;
  bool currentUpdaterSupportsSerialFollowers = false;
  bool sourceQuorumHealthy = false;
  bool targetQuorumHealthy = false;
  bool overlapCapacityAvailable = false;
  bool trustRootsAndUUIDBindingsMatch = false;
  bool providerGatewayScopedL3L4 = false;
  bool providerGatewayAvoidsHostNetworkMutation = false;
  bool publicBaselineHealthy = false;
  bool emptyIsolatedTestCluster = false;
  uint32_t healthyBrains = 0;
  uint64_t freeBytes = 0;
  Vector<MothershipUpgradeWorkloadInput> workloads = {};
};

struct MothershipUpgradePlan {
  MothershipUpgradePath path = MothershipUpgradePath::reject;
  bool eligible = false;
  String inputSHA256 = {};
  String sourceReleaseID = {};
  String targetReleaseID = {};
  String sourceContractSHA256 = {};
  String targetContractSHA256 = {};
  String firstStopGate = {};
  Vector<String> reasons = {};
  Vector<String> requiredPreconditions = {};
  Vector<String> orderedIntentReceipts = {};
};

static inline void mothershipUpgradeReject(MothershipUpgradePlan& plan, const String& reason)
{
  plan.path = MothershipUpgradePath::reject;
  plan.eligible = false;
  plan.reasons.push_back(reason);
  if (plan.firstStopGate.empty()) plan.firstStopGate = reason;
}

static inline bool mothershipUpgradeGetString(const simdjson::dom::element& object, const char *key, String& value)
{
  std::string_view raw;
  if (object[key].get_string().get(raw) != simdjson::SUCCESS || raw.empty()) return false;
  value.assign(raw.data(), uint64_t(raw.size()));
  return true;
}

static inline bool mothershipUpgradeGetUInt(const simdjson::dom::element& object, const char *key, uint64_t& value)
{
  return object[key].get_uint64().get(value) == simdjson::SUCCESS;
}

static inline bool mothershipUpgradeParseCompatibility(const simdjson::dom::element& object,
                                                       const char *key,
                                                       MothershipUpgradeCompatibilityState& state)
{
  String declared;
  if (!mothershipUpgradeGetString(object, key, declared)) return false;
  if (declared == "compatible"_ctv) state = MothershipUpgradeCompatibilityState::compatible;
  else if (declared == "incompatible"_ctv) state = MothershipUpgradeCompatibilityState::incompatible;
  else if (declared == "unknown"_ctv) state = MothershipUpgradeCompatibilityState::unknown;
  else return false;
  return true;
}

static inline bool mothershipUpgradeValidEnvelope(const MothershipUpgradeEnvelope& envelope)
{
  return envelope.approvedByBundleOwner &&
         prodigyIsSHA256HexDigest(envelope.approvedBundleSHA256) &&
         prodigyIsSHA256HexDigest(envelope.contractSHA256) &&
         prodigyIsSHA256HexDigest(envelope.prodigySHA256) &&
         prodigyIsSHA256HexDigest(envelope.mothershipSHA256);
}

static inline bool mothershipUpgradeCanonicalArchitecture(const String& architecture)
{
  return architecture == "x86_64"_ctv || architecture == "aarch64"_ctv;
}

static inline bool mothershipParseUpgradeContract(const String& json,
                                                  const MothershipUpgradeEnvelope& envelope,
                                                  MothershipUpgradeContract& contract,
                                                  String *failure = nullptr)
{
  contract = {};
  if (failure) failure->clear();
  if (!mothershipUpgradeValidEnvelope(envelope))
  {
    if (failure) failure->assign("upgrade envelope is absent or unauthenticated"_ctv);
    return false;
  }

  String actualContractSHA256;
  if (!prodigyComputeSHA256Hex(json, actualContractSHA256, failure) || actualContractSHA256 != envelope.contractSHA256)
  {
    if (failure && failure->empty()) failure->assign("contract bytes differ from authenticated envelope"_ctv);
    return false;
  }

  simdjson::dom::parser parser;
  simdjson::dom::element document;
  String paddedJSON = json;
  paddedJSON.need(simdjson::SIMDJSON_PADDING);
  if (parser.parse(paddedJSON.data(), json.size()).get(document) != simdjson::SUCCESS ||
      document.type() != simdjson::dom::element_type::OBJECT)
  {
    if (failure) failure->assign("upgrade contract is not a JSON object"_ctv);
    return false;
  }

  uint64_t version = 0, minimumHealthyBrains = 0, requiredFreeBytes = 0;
  if (!mothershipUpgradeGetUInt(document, "manifestVersion", version) || version != 1 ||
      !mothershipUpgradeGetString(document, "releaseID", contract.releaseID) ||
      !mothershipUpgradeGetString(document, "prodigySHA256", contract.prodigySHA256) ||
      !mothershipUpgradeGetString(document, "mothershipSHA256", contract.mothershipSHA256) ||
      !mothershipUpgradeGetString(document, "architecture", contract.architecture) ||
      !mothershipUpgradeGetString(document, "binaryVersion", contract.binaryVersion) ||
      !mothershipUpgradeGetUInt(document, "minimumHealthyBrains", minimumHealthyBrains) ||
      minimumHealthyBrains == 0 || minimumHealthyBrains > UINT32_MAX ||
      !mothershipUpgradeGetUInt(document, "requiredFreeBytes", requiredFreeBytes) ||
      !mothershipUpgradeGetString(document, "rollbackMode", contract.rollbackMode) ||
      !mothershipUpgradeGetString(document, "transportIdentityMode", contract.transportIdentityMode) ||
      !mothershipUpgradeGetString(document, "migrationProtocolVersion", contract.migrationProtocolVersion) ||
      !mothershipUpgradeCanonicalArchitecture(contract.architecture) ||
      !prodigyIsSHA256HexDigest(contract.prodigySHA256) ||
      !prodigyIsSHA256HexDigest(contract.mothershipSHA256) ||
      contract.prodigySHA256 != envelope.prodigySHA256 ||
      contract.mothershipSHA256 != envelope.mothershipSHA256)
  {
    if (failure) failure->assign("upgrade contract identity is missing or differs from approved envelope"_ctv);
    return false;
  }
  contract.manifestVersion = uint32_t(version);
  contract.minimumHealthyBrains = uint32_t(minimumHealthyBrains);
  contract.requiredFreeBytes = requiredFreeBytes;
  contract.contractSHA256 = envelope.contractSHA256;
  const auto retirementVersion = document["containerRetirementJournalVersion"];
  if (retirementVersion.error() != simdjson::NO_SUCH_FIELD)
  {
    uint64_t value = 0;
    if (retirementVersion.get_uint64().get(value) != simdjson::SUCCESS || value > 3)
    {
      if (failure) failure->assign("unsupported container retirement journal reader"_ctv);
      return false;
    }
    contract.containerRetirementJournalVersion = uint32_t(value);
  }

  String disposition;
  if (!mothershipUpgradeGetString(document, "disposition", disposition))
  {
    if (failure) failure->assign("upgrade disposition is missing"_ctv);
    return false;
  }
  if (disposition == "same-cluster-rollout"_ctv) contract.disposition = MothershipUpgradeDisposition::sameClusterRollout;
  else if (disposition == "new-cluster-required"_ctv) contract.disposition = MothershipUpgradeDisposition::newClusterRequired;
  else if (disposition == "unsupported"_ctv) contract.disposition = MothershipUpgradeDisposition::unsupported;
  else { if (failure) failure->assign("upgrade disposition is unknown"_ctv); return false; }

  if ((contract.transportIdentityMode != "preserveClusterIdentity"_ctv &&
       contract.transportIdentityMode != "unsupported"_ctv) ||
      (contract.disposition == MothershipUpgradeDisposition::sameClusterRollout &&
       contract.transportIdentityMode != "preserveClusterIdentity"_ctv))
  {
    if (failure) failure->assign("same-cluster transport identity preservation is unqualified"_ctv);
    return false;
  }

  simdjson::dom::element compatibility;
  if (document["compatibility"].get(compatibility) != simdjson::SUCCESS ||
      compatibility.type() != simdjson::dom::element_type::OBJECT ||
      !mothershipUpgradeParseCompatibility(compatibility, "wire", contract.compatibility.wire) ||
      !mothershipUpgradeParseCompatibility(compatibility, "persistentState", contract.compatibility.persistentState) ||
      !mothershipUpgradeParseCompatibility(compatibility, "authorityState", contract.compatibility.authorityState) ||
      !mothershipUpgradeParseCompatibility(compatibility, "transportTrust", contract.compatibility.transportTrust) ||
      !mothershipUpgradeParseCompatibility(compatibility, "containerProtocol", contract.compatibility.containerProtocol) ||
      !mothershipUpgradeParseCompatibility(compatibility, "dataPlane", contract.compatibility.dataPlane) ||
      !mothershipUpgradeParseCompatibility(compatibility, "appState", contract.compatibility.appState))
  {
    if (failure) failure->assign("upgrade compatibility is missing or unknown"_ctv);
    return false;
  }
  if (contract.disposition != MothershipUpgradeDisposition::unsupported &&
      (contract.compatibility.wire == MothershipUpgradeCompatibilityState::unknown ||
       contract.compatibility.persistentState == MothershipUpgradeCompatibilityState::unknown ||
       contract.compatibility.authorityState == MothershipUpgradeCompatibilityState::unknown ||
       contract.compatibility.transportTrust == MothershipUpgradeCompatibilityState::unknown ||
       contract.compatibility.containerProtocol == MothershipUpgradeCompatibilityState::unknown ||
       contract.compatibility.dataPlane == MothershipUpgradeCompatibilityState::unknown ||
       contract.compatibility.appState == MothershipUpgradeCompatibilityState::unknown))
  {
    if (failure) failure->assign("qualified upgrade compatibility may not contain unknown axes"_ctv);
    return false;
  }

  Vector<String> sourceIDs;
  simdjson::dom::array supported;
  if (document["supportedSourceReleaseIDs"].get_array().get(supported) != simdjson::SUCCESS ||
      (supported.size() == 0 && contract.disposition != MothershipUpgradeDisposition::unsupported))
  {
    if (failure) failure->assign("supported source release IDs are missing"_ctv);
    return false;
  }
  for (const simdjson::dom::element& value : supported)
  {
    std::string_view raw;
    if (value.get_string().get(raw) != simdjson::SUCCESS || raw.empty())
    {
      if (failure) failure->assign("supported source release ID is invalid"_ctv);
      return false;
    }
    String id;
    id.assign(raw.data(), uint64_t(raw.size()));
    for (const String& prior : sourceIDs)
      if (prior == id) { if (failure) failure->assign("supported source release ID is duplicated"_ctv); return false; }
    sourceIDs.push_back(std::move(id));
  }

  simdjson::dom::array sources;
  if (document["sourceContracts"].get_array().get(sources) != simdjson::SUCCESS ||
      (sources.size() == 0 && contract.disposition != MothershipUpgradeDisposition::unsupported))
  {
    if (failure) failure->assign("upgrade source identities are missing"_ctv);
    return false;
  }
  for (const simdjson::dom::element& source : sources)
  {
    MothershipUpgradeIdentity identity;
    if (source.type() != simdjson::dom::element_type::OBJECT ||
        !mothershipUpgradeGetString(source, "releaseID", identity.releaseID) ||
        !mothershipUpgradeGetString(source, "contractSHA256", identity.contractSHA256) ||
        !mothershipUpgradeGetString(source, "prodigySHA256", identity.prodigySHA256) ||
        !mothershipUpgradeGetString(source, "mothershipSHA256", identity.mothershipSHA256) ||
        !prodigyIsSHA256HexDigest(identity.contractSHA256) ||
        !prodigyIsSHA256HexDigest(identity.prodigySHA256) ||
        !prodigyIsSHA256HexDigest(identity.mothershipSHA256))
    {
      if (failure) failure->assign("upgrade source identity is invalid"_ctv);
      return false;
    }
    for (const MothershipUpgradeIdentity& prior : contract.sources)
      if (prior.releaseID == identity.releaseID || prior.contractSHA256 == identity.contractSHA256)
      { if (failure) failure->assign("upgrade source identity is duplicated"_ctv); return false; }
    contract.sources.push_back(std::move(identity));
  }
  if (contract.sources.size() != sourceIDs.size())
  {
    if (failure) failure->assign("source identity table does not match supported release IDs"_ctv);
    return false;
  }
  for (const MothershipUpgradeIdentity& source : contract.sources)
  {
    bool found = false;
    for (const String& id : sourceIDs) if (id == source.releaseID) { found = true; break; }
    if (!found) { if (failure) failure->assign("source identity release ID is not declared"_ctv); return false; }
  }
  return true;
}

static inline bool mothershipUpgradeDeclaredSource(const MothershipUpgradeContract& contract,
                                                   const MothershipUpgradeIdentity& observed)
{
  for (const MothershipUpgradeIdentity& source : contract.sources)
    if (source.releaseID == observed.releaseID && source.contractSHA256 == observed.contractSHA256 &&
        source.prodigySHA256 == observed.prodigySHA256 && source.mothershipSHA256 == observed.mothershipSHA256) return true;
  return false;
}

static inline bool mothershipUpgradeWorkloadsValid(const MothershipUpgradePlannerInput& input, bool requireBridge)
{
  for (const MothershipUpgradeWorkloadInput& workload : input.workloads)
    if (workload.applicationID.empty() || !workload.migrationEligible || !workload.endpointStrategyAvailable ||
        !workload.observedPublicContinuity || (workload.stateful && !workload.fencingAvailable) ||
        (requireBridge && !workload.bridgeProtocolAvailable)) return false;
  return true;
}

static inline void mothershipUpgradeAppendField(String& encoded, const String& value)
{
  String length;
  length.snprintf<"{itoa}:"_ctv>(value.size());
  encoded.append(length);
  encoded.append(value);
  encoded.append('|');
}

static inline void mothershipUpgradeAppendBool(String& encoded, bool value)
{
  encoded.append(value ? '1' : '0');
  encoded.append('|');
}

static inline void mothershipUpgradeAppendUInt(String& encoded, uint64_t value)
{
  String text;
  text.snprintf<"{itoa}|"_ctv>(value);
  encoded.append(text);
}

static inline void mothershipUpgradeAppendUUID(String& encoded, uint128_t value)
{
  String text;
  text.assignItoh(value);
  mothershipUpgradeAppendField(encoded, text);
}

static inline void mothershipUpgradeAppendCompatibility(String& encoded, const MothershipUpgradeCompatibility& c)
{
  mothershipUpgradeAppendUInt(encoded, uint64_t(c.wire));
  mothershipUpgradeAppendUInt(encoded, uint64_t(c.persistentState));
  mothershipUpgradeAppendUInt(encoded, uint64_t(c.authorityState));
  mothershipUpgradeAppendUInt(encoded, uint64_t(c.transportTrust));
  mothershipUpgradeAppendUInt(encoded, uint64_t(c.containerProtocol));
  mothershipUpgradeAppendUInt(encoded, uint64_t(c.dataPlane));
  mothershipUpgradeAppendUInt(encoded, uint64_t(c.appState));
}

static inline bool mothershipUpgradePlanInputDigest(const MothershipUpgradeContract& contract,
                                                    const MothershipUpgradePlannerInput& input,
                                                    String& digest)
{
  String encoded;
  mothershipUpgradeAppendField(encoded, input.envelope.approvedBundleSHA256);
  mothershipUpgradeAppendField(encoded, input.envelope.contractSHA256);
  mothershipUpgradeAppendField(encoded, input.envelope.prodigySHA256);
  mothershipUpgradeAppendField(encoded, input.envelope.mothershipSHA256);
  mothershipUpgradeAppendBool(encoded, input.envelope.approvedByBundleOwner);
  mothershipUpgradeAppendField(encoded, input.observedSource.releaseID);
  mothershipUpgradeAppendField(encoded, input.observedSource.contractSHA256);
  mothershipUpgradeAppendField(encoded, input.observedSource.prodigySHA256);
  mothershipUpgradeAppendField(encoded, input.observedSource.mothershipSHA256);
  mothershipUpgradeAppendField(encoded, input.observedTargetArchitecture);
  mothershipUpgradeAppendUUID(encoded, input.sourceClusterUUID);
  mothershipUpgradeAppendUUID(encoded, input.targetClusterUUID);
  mothershipUpgradeAppendField(encoded, contract.releaseID);
  mothershipUpgradeAppendField(encoded, contract.contractSHA256);
  mothershipUpgradeAppendField(encoded, contract.prodigySHA256);
  mothershipUpgradeAppendField(encoded, contract.mothershipSHA256);
  mothershipUpgradeAppendField(encoded, contract.architecture);
  mothershipUpgradeAppendField(encoded, contract.binaryVersion);
  mothershipUpgradeAppendField(encoded, contract.rollbackMode);
  mothershipUpgradeAppendField(encoded, contract.transportIdentityMode);
  mothershipUpgradeAppendUInt(encoded, contract.containerRetirementJournalVersion);
  mothershipUpgradeAppendField(encoded, contract.migrationProtocolVersion);
  mothershipUpgradeAppendUInt(encoded, uint64_t(contract.disposition));
  mothershipUpgradeAppendCompatibility(encoded, contract.compatibility);
  mothershipUpgradeAppendUInt(encoded, contract.minimumHealthyBrains);
  mothershipUpgradeAppendUInt(encoded, contract.requiredFreeBytes);
  mothershipUpgradeAppendBool(encoded, input.requestProviderRelocation);
  mothershipUpgradeAppendBool(encoded, input.requestSeparateCluster);
  mothershipUpgradeAppendBool(encoded, input.currentUpdaterSupportsSerialFollowers);
  mothershipUpgradeAppendBool(encoded, input.sourceQuorumHealthy);
  mothershipUpgradeAppendBool(encoded, input.targetQuorumHealthy);
  mothershipUpgradeAppendBool(encoded, input.overlapCapacityAvailable);
  mothershipUpgradeAppendBool(encoded, input.trustRootsAndUUIDBindingsMatch);
  mothershipUpgradeAppendBool(encoded, input.providerGatewayScopedL3L4);
  mothershipUpgradeAppendBool(encoded, input.providerGatewayAvoidsHostNetworkMutation);
  mothershipUpgradeAppendBool(encoded, input.publicBaselineHealthy);
  mothershipUpgradeAppendBool(encoded, input.emptyIsolatedTestCluster);
  mothershipUpgradeAppendUInt(encoded, input.healthyBrains);
  mothershipUpgradeAppendUInt(encoded, input.freeBytes);
  mothershipUpgradeAppendUInt(encoded, input.workloads.size());
  for (const MothershipUpgradeWorkloadInput& workload : input.workloads)
  {
    mothershipUpgradeAppendField(encoded, workload.applicationID);
    mothershipUpgradeAppendBool(encoded, workload.stateful);
    mothershipUpgradeAppendBool(encoded, workload.migrationEligible);
    mothershipUpgradeAppendBool(encoded, workload.bridgeProtocolAvailable);
    mothershipUpgradeAppendBool(encoded, workload.endpointStrategyAvailable);
    mothershipUpgradeAppendBool(encoded, workload.fencingAvailable);
    mothershipUpgradeAppendBool(encoded, workload.observedPublicContinuity);
  }
  return prodigyComputeSHA256Hex(encoded, digest, nullptr);
}

static inline void mothershipUpgradeReceipt(MothershipUpgradePlan& plan, const String& receipt)
{
  plan.orderedIntentReceipts.push_back(receipt);
}

static inline MothershipUpgradePlan mothershipPlanUpgrade(const MothershipUpgradeContract& contract,
                                                          const MothershipUpgradePlannerInput& input)
{
  MothershipUpgradePlan plan;
  plan.sourceReleaseID = input.observedSource.releaseID;
  plan.targetReleaseID = contract.releaseID;
  plan.sourceContractSHA256 = input.observedSource.contractSHA256;
  plan.targetContractSHA256 = contract.contractSHA256;
  if (!mothershipUpgradePlanInputDigest(contract, input, plan.inputSHA256))
  {
    mothershipUpgradeReject(plan, "planner input hash failed"_ctv);
    return plan;
  }
  if (!mothershipUpgradeValidEnvelope(input.envelope) || input.envelope.contractSHA256 != contract.contractSHA256 ||
      input.envelope.prodigySHA256 != contract.prodigySHA256 || input.envelope.mothershipSHA256 != contract.mothershipSHA256 ||
      !prodigyIsSHA256HexDigest(input.observedSource.contractSHA256) || !prodigyIsSHA256HexDigest(input.observedSource.prodigySHA256) ||
      !prodigyIsSHA256HexDigest(input.observedSource.mothershipSHA256))
  {
    mothershipUpgradeReject(plan, "release identity is absent or unauthenticated"_ctv);
    return plan;
  }
  if (!mothershipUpgradeCanonicalArchitecture(input.observedTargetArchitecture) ||
      input.observedTargetArchitecture != contract.architecture)
  {
    mothershipUpgradeReject(plan, "observed target architecture does not match release contract"_ctv);
    return plan;
  }
  if (input.sourceClusterUUID == 0 || input.targetClusterUUID == 0)
  {
    mothershipUpgradeReject(plan, "source and target cluster UUIDs are required"_ctv);
    return plan;
  }
  if (!mothershipUpgradeDeclaredSource(contract, input.observedSource))
  {
    mothershipUpgradeReject(plan, "exact observed source identity is not declared"_ctv);
    return plan;
  }
  if (contract.disposition == MothershipUpgradeDisposition::unsupported)
  {
    mothershipUpgradeReject(plan, "target release declares upgrades unsupported"_ctv);
    return plan;
  }
  if (!input.sourceQuorumHealthy || !input.targetQuorumHealthy || input.healthyBrains < contract.minimumHealthyBrains)
  {
    mothershipUpgradeReject(plan, "healthy controller quorum is insufficient"_ctv);
    return plan;
  }
  if (!input.overlapCapacityAvailable || input.freeBytes < contract.requiredFreeBytes)
  {
    mothershipUpgradeReject(plan, "overlap capacity is insufficient"_ctv);
    return plan;
  }
  if (input.emptyIsolatedTestCluster && !input.workloads.empty())
  {
    mothershipUpgradeReject(plan, "empty test cluster profile contains workloads"_ctv);
    return plan;
  }
  if (!input.publicBaselineHealthy && !input.emptyIsolatedTestCluster)
  {
    mothershipUpgradeReject(plan, "public baseline is unqualified"_ctv);
    return plan;
  }
  if (input.requestSeparateCluster)
  {
    if (contract.disposition != MothershipUpgradeDisposition::newClusterRequired || input.sourceClusterUUID == input.targetClusterUUID)
    {
      mothershipUpgradeReject(plan, "separate cluster request conflicts with declared identity mode"_ctv);
      return plan;
    }
    if (!mothershipUpgradeWorkloadsValid(input, true))
    {
      mothershipUpgradeReject(plan, "workload bridge or fencing evidence is incomplete"_ctv);
      return plan;
    }
    plan.path = MothershipUpgradePath::separateClusterMigration;
    plan.eligible = true;
    plan.requiredPreconditions.push_back("authenticated application bridge and fencing receipts"_ctv);
    mothershipUpgradeReceipt(plan, "targetReserved"_ctv);
    mothershipUpgradeReceipt(plan, "bridgeReady"_ctv);
    mothershipUpgradeReceipt(plan, "trafficShifted"_ctv);
    plan.firstStopGate = "bridge readiness and workload fencing"_ctv;
    return plan;
  }
  if (contract.disposition != MothershipUpgradeDisposition::sameClusterRollout || input.sourceClusterUUID != input.targetClusterUUID)
  {
    mothershipUpgradeReject(plan, "same logical cluster identity is required"_ctv);
    return plan;
  }
  if (!contract.compatibility.allCompatible())
  {
    mothershipUpgradeReject(plan, "same-cluster compatibility is incomplete or incompatible"_ctv);
    return plan;
  }
  if (contract.transportIdentityMode != "preserveClusterIdentity"_ctv ||
      !input.trustRootsAndUUIDBindingsMatch || !input.currentUpdaterSupportsSerialFollowers)
  {
    mothershipUpgradeReject(plan, "same-cluster trust or serial updater evidence is unqualified"_ctv);
    return plan;
  }
  if (!mothershipUpgradeWorkloadsValid(input, false))
  {
    mothershipUpgradeReject(plan, "workload endpoint or fencing evidence is incomplete"_ctv);
    return plan;
  }
  if (input.requestProviderRelocation)
  {
    if (!input.providerGatewayScopedL3L4 || !input.providerGatewayAvoidsHostNetworkMutation)
    {
      mothershipUpgradeReject(plan, "provider gateway is not narrowly scoped"_ctv);
      return plan;
    }
    plan.path = MothershipUpgradePath::logicalClusterRelocation;
    plan.requiredPreconditions.push_back("destination quorum and scoped gateway verified"_ctv);
    mothershipUpgradeReceipt(plan, "destinationMemberReady"_ctv);
    mothershipUpgradeReceipt(plan, "workloadReady"_ctv);
    mothershipUpgradeReceipt(plan, "trafficShifted"_ctv);
    mothershipUpgradeReceipt(plan, "sourceDrained"_ctv);
    plan.firstStopGate = "destination member readiness"_ctv;
  }
  else
  {
    plan.path = MothershipUpgradePath::sameLogicalRollout;
    plan.requiredPreconditions.push_back("serial follower update capability verified"_ctv);
    mothershipUpgradeReceipt(plan, "bundleStaged"_ctv);
    mothershipUpgradeReceipt(plan, "follower1Ready"_ctv);
    mothershipUpgradeReceipt(plan, "follower2Ready"_ctv);
    mothershipUpgradeReceipt(plan, "masterTransferred"_ctv);
    plan.firstStopGate = "first follower readiness"_ctv;
  }
  plan.eligible = true;
  return plan;
}
