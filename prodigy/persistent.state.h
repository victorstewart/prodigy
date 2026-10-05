#pragma once

#include <algorithm>
#include <limits.h>
#include <cstring>
#include <memory>

#include <networking/includes.h>
#include <types/types.containers.h>
#include <databases/embedded/tidesdb.h>
#include <prodigy/bootstrap.config.h>
#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/mothership/mothership.tunnel.auth.h>
#include <prodigy/mothership/mothership.tunnel.policy.h>
#include <prodigy/runtime.environment.h>
#include <prodigy/transport.tls.h>
#include <prodigy/types.h>
#include <prodigy/container.retirement.h>
#include <prodigy/stateful.serving.authority.h>
#include <prodigy/brain/metrics.h>
#include <services/base64.h>
#include <services/random.h>

// Exact live Neuron state captured by Mothership before an interrupted
// sole-Brain replacement. ContainerPlan remains the wire/domain owner.
class ProdigyLocalContainerCheckpoint {
public:
  uint128_t machineUUID = 0;
  uint8_t datacenterFragment = 0;
  uint32_t machineFragment = 0;
  Vector<ContainerPlan> plans;
};

template <typename S>
static void serialize(S&& serializer, ProdigyLocalContainerCheckpoint& checkpoint)
{
  serializer.value16b(checkpoint.machineUUID);
  serializer.value1b(checkpoint.datacenterFragment);
  serializer.value4b(checkpoint.machineFragment);
  serializer.container(checkpoint.plans, 4096);
}

class ProdigyBootstrapBundleSupersessionReceipt {
public:

  // Input-only boot receipt. Mothership supplies it on replacement startup;
  // accepted state is committed through the existing brain snapshot.
  uint128_t operationID = 0;
  uint128_t clusterUUID = 0;
  String expectedIncompleteWorkerBundleSHA256;
  String successorBundleSHA256;
  String targetControlSocketPath;
  String localContainerCheckpoint;
  String localContainerCheckpointSHA256;

  bool present(void) const { return operationID != 0; }
};

static inline bool prodigyParseCanonicalHex128(const String& text, uint128_t& result)
{
  if (text.size() < 3 || text[0] != '0' || text[1] != 'x' || text.size() > 34) return false;
  uint128_t value = 0;
  for (uint64_t i = 2; i < text.size(); i += 1)
  {
    const char c = text[i];
    uint8_t digit = 0;
    if (c >= '0' && c <= '9') digit = uint8_t(c - '0');
    else if (c >= 'a' && c <= 'f') digit = uint8_t(c - 'a' + 10);
    else return false;
    value = (value << 4) | digit;
  }
  if (value == 0) return false;
  String canonical = {};
  canonical.assignItoh(value);
  if (canonical.equals(text) == false) return false;
  result = value;
  return true;
}

static inline bool prodigySHA256HexIsCanonical(const String& value)
{
  if (value.size() != 64) return false;
  for (uint64_t i = 0; i < value.size(); i += 1)
  {
    const char c = value[i];
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) continue;
    return false;
  }
  return true;
}

class ProdigyPersistentBootState {
public:

  ProdigyBootstrapConfig bootstrapConfig;
  String bootstrapSshUser;
  Vault::SSHKeyPackage bootstrapSshKeyPackage;
  Vault::SSHKeyPackage bootstrapSshHostKeyPackage;
  String bootstrapSshPrivateKeyPath;
  ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
  ClusterTopology initialTopology; // boot-only authoritative topology for first start before any brain snapshot exists
  ProdigyBootstrapBundleSupersessionReceipt bootstrapBundleSupersession; // input-only; excluded from binary boot persistence

  bool operator==(const ProdigyPersistentBootState& other) const
  {
    return bootstrapConfig == other.bootstrapConfig && bootstrapSshUser.equals(other.bootstrapSshUser) && bootstrapSshKeyPackage == other.bootstrapSshKeyPackage && bootstrapSshHostKeyPackage == other.bootstrapSshHostKeyPackage && bootstrapSshPrivateKeyPath.equals(other.bootstrapSshPrivateKeyPath) && runtimeEnvironment == other.runtimeEnvironment && initialTopology == other.initialTopology;
  }

  bool operator!=(const ProdigyPersistentBootState& other) const
  {
    return (*this == other) == false;
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentBootState& state)
{
  serializer.object(state.bootstrapConfig);
  serializer.text1b(state.bootstrapSshUser, UINT32_MAX);
  serializer.object(state.bootstrapSshKeyPackage);
  serializer.object(state.bootstrapSshHostKeyPackage);
  serializer.text1b(state.bootstrapSshPrivateKeyPath, UINT32_MAX);
  serializer.object(state.runtimeEnvironment);
  serializer.object(state.initialTopology);
}

static inline bool prodigyPersistentBootStateSSHKeyPackageConfigured(const Vault::SSHKeyPackage& package)
{
  return package.privateKeyOpenSSH.size() > 0 || package.publicKeyOpenSSH.size() > 0;
}

static inline bool parseProdigyPersistentSSHKeyPackageJSONElement(
    simdjson::dom::element value,
    const char *fieldName,
    Vault::SSHKeyPackage& package,
    String *failure = nullptr)
{
  if (value.type() != simdjson::dom::element_type::OBJECT)
  {
    if (failure)
    {
      failure->snprintf<"{} requires object"_ctv>(String(fieldName));
    }
    return false;
  }

  Vault::SSHKeyPackage parsed = {};
  for (auto field : value.get_object())
  {
    String key = {};
    key.setInvariant(field.key.data(), field.key.size());

    if (key.equal("privateKeyOpenSSH"_ctv))
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->snprintf<"{}.privateKeyOpenSSH requires string"_ctv>(String(fieldName));
        }
        return false;
      }

      parsed.privateKeyOpenSSH.assign(field.value.get_c_str());
    }
    else if (key.equal("publicKeyOpenSSH"_ctv))
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->snprintf<"{}.publicKeyOpenSSH requires string"_ctv>(String(fieldName));
        }
        return false;
      }

      parsed.publicKeyOpenSSH.assign(field.value.get_c_str());
    }
    else
    {
      if (failure)
      {
        failure->snprintf<"invalid {} field"_ctv>(String(fieldName));
      }
      return false;
    }
  }

  if (prodigyPersistentBootStateSSHKeyPackageConfigured(parsed) && Vault::validateSSHKeyPackageEd25519(parsed, failure) == false)
  {
    return false;
  }

  package = std::move(parsed);
  return true;
}

static inline void renderProdigyPersistentSSHKeyPackageJSON(const Vault::SSHKeyPackage& package, String& json, bool redactPrivateKeyMaterial = false)
{
  json.append("{\"privateKeyOpenSSH\":"_ctv);
  if (redactPrivateKeyMaterial && package.privateKeyOpenSSH.size() > 0)
  {
    String redacted = {};
    redacted.assign("[redacted]"_ctv);
    appendEscapedJSONString(json, redacted);
  }
  else
  {
    appendEscapedJSONString(json, package.privateKeyOpenSSH);
  }
  json.append(",\"publicKeyOpenSSH\":"_ctv);
  appendEscapedJSONString(json, package.publicKeyOpenSSH);
  json.append("}"_ctv);
}

static inline void prodigyBackfillBrainConfigSSHFromBootState(const ProdigyPersistentBootState& state, BrainConfig& config)
{
  if (config.bootstrapSshUser.size() == 0 && state.bootstrapSshUser.size() > 0)
  {
    config.bootstrapSshUser = state.bootstrapSshUser;
  }

  if (prodigyPersistentBootStateSSHKeyPackageConfigured(config.bootstrapSshKeyPackage) == false && prodigyPersistentBootStateSSHKeyPackageConfigured(state.bootstrapSshKeyPackage))
  {
    config.bootstrapSshKeyPackage = state.bootstrapSshKeyPackage;
  }

  if (prodigyPersistentBootStateSSHKeyPackageConfigured(config.bootstrapSshHostKeyPackage) == false && prodigyPersistentBootStateSSHKeyPackageConfigured(state.bootstrapSshHostKeyPackage))
  {
    config.bootstrapSshHostKeyPackage = state.bootstrapSshHostKeyPackage;
  }

  if (config.bootstrapSshPrivateKeyPath.size() == 0 && state.bootstrapSshPrivateKeyPath.size() > 0)
  {
    config.bootstrapSshPrivateKeyPath = state.bootstrapSshPrivateKeyPath;
  }
}

static inline bool prodigyResolveInitialTopologyFromBootState(const ProdigyPersistentBootState& state, ClusterTopology& topology)
{
  topology = {};
  if (state.initialTopology.machines.empty())
  {
    return false;
  }

  topology = state.initialTopology;
  return true;
}

static inline uint32_t prodigyResolveStartupClusterNodeCount(
    const ProdigyPersistentBootState& state,
    const ProdigyBootstrapConfig& effectiveBootstrapConfig)
{
  if (state.initialTopology.machines.empty() == false)
  {
    return uint32_t(state.initialTopology.machines.size());
  }

  if (effectiveBootstrapConfig.bootstrapPeers.empty() == false)
  {
    return uint32_t(effectiveBootstrapConfig.bootstrapPeers.size()) + 1;
  }

  return 1;
}

static inline bool prodigyStartupRequiresTransportTLS(
    const ProdigyPersistentBootState& state,
    const ProdigyBootstrapConfig& effectiveBootstrapConfig)
{
  return prodigyResolveStartupClusterNodeCount(state, effectiveBootstrapConfig) > 1;
}

class ProdigyPersistentBrainSnapshot {
public:

  Vector<ProdigyBootstrapConfig::BootstrapPeer> brainPeers;
  ClusterTopology topology;
  BrainConfig brainConfig;
  ProdigyPersistentMasterAuthorityPackage masterAuthority;
  Vector<ProdigyMetricSample> metricSamples;
  // Live snapshots retain an immutable generation without flattening history
  // on the Ring. The existing persistence worker serializes this view using
  // the same flat metric vector schema as snapshots loaded from disk.
  std::shared_ptr<const MetricsStore::Snapshot> metricCapture;
};

static inline void prodigyReplaceCachedBrainSnapshot(
    ProdigyPersistentBrainSnapshot& target,
    ProdigyPersistentBrainSnapshot&& replacement)
{
  // Cached runtime snapshots should take ownership of the freshly built
  // snapshot without routing large deployment/state maps back through
  // assignment on an already-populated cache object.
  std::destroy_at(std::addressof(target));
  std::construct_at(std::addressof(target), std::move(replacement));
}

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentBrainSnapshot& snapshot)
{
  serializer.container(snapshot.brainPeers, UINT32_MAX);
  serializer.object(snapshot.topology);
  serializer.object(snapshot.brainConfig);
  serializer.object(snapshot.masterAuthority);
  if constexpr (requires { serializer.frozenMetricSamples(snapshot.metricSamples, snapshot.metricCapture); })
  {
    serializer.frozenMetricSamples(snapshot.metricSamples, snapshot.metricCapture);
  }
  else if constexpr (ProdigyPersistentSerializerIsWriter<std::remove_cvref_t<S>>::value)
  {
    if (snapshot.metricCapture)
    {
      Vector<ProdigyMetricSample> samples;
      snapshot.metricCapture->exportSamples(samples);
      serializer.container(samples, UINT32_MAX);
    }
    else serializer.container(snapshot.metricSamples, UINT32_MAX);
  }
  else
  {
    snapshot.metricCapture.reset();
    serializer.container(snapshot.metricSamples, UINT32_MAX);
  }
}

static inline const char *defaultProdigyPersistentStateDBPath(void)
{
  return "/var/lib/prodigy/state";
}

class ProdigyPersistentLocalBrainState {
public:

  uint128_t uuid = 0;
  uint128_t ownerClusterUUID = 0;
  ProdigyTransportTLSMaterial transportTLS;
  ProdigyTransportCredentialBootstrap transportCredentials;
  // Authenticated provisioning seeds this only on Brain machines. Subsequent
  // authority changes are owned by the replicated master-authority package.
  ProdigyTransportCredentialAuthorityRoot transportCredentialAuthorityRoot;

  bool transportTLSConfigured(void) const
  {
    return uuid != 0 && transportTLS.configured();
  }

  bool canMintTransportTLS(void) const
  {
    return uuid != 0 && transportTLS.canMintForCluster();
  }
};

static inline bool prodigyLocalTransportCredentialStateValid(
    const ProdigyPersistentLocalBrainState& state, bool requireSecret = true)
{
  const auto& bootstrap = state.transportCredentials;
  const auto& root = state.transportCredentialAuthorityRoot;
  uint8_t rootBytes = 0;
  for (uint8_t byte : root.root) rootBytes |= byte;
  const bool rootEmpty = root.authorityEpoch == 0 && root.keyEpoch == 0 && root.authorityGeneration == 0 && rootBytes == 0;
  if (!prodigyTransportCredentialBootstrapValid(bootstrap, requireSecret)) return false;
  if (!bootstrap.enabled) return rootEmpty;
  if (bootstrap.self.nodeUUID != state.uuid || bootstrap.self.clusterUUID != state.ownerClusterUUID) return false;
  if (bootstrap.self.role == ProdigyTransportCredentialNodeRole::neuron) return rootEmpty;
  if (root.authorityEpoch != bootstrap.self.authorityEpoch || root.keyEpoch != bootstrap.self.keyEpoch ||
      root.authorityGeneration != bootstrap.self.rootAuthorityGeneration) return false;
  if (!requireSecret) return rootBytes == 0;
  if (!root.valid()) return false;
  ProdigyTransportCredentialEnrollment local = {};
  local.operationUUID = bootstrap.self.operationUUID;
  local.nodeUUID = state.uuid; local.clusterUUID = state.ownerClusterUUID;
  local.authorityEpoch = bootstrap.self.authorityEpoch; local.keyEpoch = bootstrap.self.keyEpoch;
  local.authorityGeneration = bootstrap.self.authorityGeneration;
  local.role = bootstrap.self.role; local.state = ProdigyTransportCredentialEnrollmentState::active;
  ProdigyTransportNodeCredential derived = {};
  return prodigyDeriveTransportNodeCredential(root, local, derived) &&
      CRYPTO_memcmp(derived.secret, bootstrap.self.secret, sizeof(derived.secret)) == 0;
}

static inline bool prodigyBuildLocalTransportCredentialState(
    const ProdigyTransportCredentialAuthorityRoot& authority,
    const Vector<ProdigyTransportCredentialEnrollment>& ledger,
    uint128_t nodeUUID, ProdigyTransportCredentialNodeRole role,
    ProdigyPersistentLocalBrainState& state,
    uint64_t committedAuthorityGeneration = 0)
{
  const ProdigyTransportCredentialEnrollment *local = nullptr;
  for (const auto& enrollment : ledger)
  {
    if (enrollment.nodeUUID == nodeUUID && enrollment.role == role &&
        enrollment.state == ProdigyTransportCredentialEnrollmentState::active)
    {
      if (local != nullptr) return false;
      local = &enrollment;
    }
  }
  if (local == nullptr || (state.uuid != 0 && state.uuid != nodeUUID) ||
      (state.ownerClusterUUID != 0 && state.ownerClusterUUID != local->clusterUUID)) return false;
  ProdigyPersistentLocalBrainState candidate = state;
  candidate.uuid = nodeUUID; candidate.ownerClusterUUID = local->clusterUUID;
  if (!prodigyBuildTransportCredentialBootstrap(authority, *local, ledger, true, candidate.transportCredentials,
      committedAuthorityGeneration)) return false;
  candidate.transportCredentialAuthorityRoot = role == ProdigyTransportCredentialNodeRole::brain ?
      authority : ProdigyTransportCredentialAuthorityRoot{};
  if (!prodigyLocalTransportCredentialStateValid(candidate)) return false;
  state = std::move(candidate);
  return true;
}

static inline void prodigyTransportCredentialBootstrapLedger(
    const ProdigyTransportCredentialBootstrap& bootstrap,
    Vector<ProdigyTransportCredentialEnrollment>& ledger)
{
  ledger = bootstrap.authorizedPeers;
  ProdigyTransportCredentialEnrollment self = {};
  self.operationUUID = bootstrap.self.operationUUID; self.nodeUUID = bootstrap.self.nodeUUID;
  self.clusterUUID = bootstrap.self.clusterUUID; self.authorityEpoch = bootstrap.self.authorityEpoch;
  self.keyEpoch = bootstrap.self.keyEpoch; self.authorityGeneration = bootstrap.self.authorityGeneration;
  self.role = bootstrap.self.role; self.state = ProdigyTransportCredentialEnrollmentState::active;
  ledger.push_back(self);
  std::sort(ledger.begin(), ledger.end(), [](const auto& lhs, const auto& rhs) {
    if (lhs.nodeUUID != rhs.nodeUUID) return lhs.nodeUUID < rhs.nodeUUID;
    if (lhs.role != rhs.role) return uint8_t(lhs.role) < uint8_t(rhs.role);
    return lhs.operationUUID < rhs.operationUUID;
  });
}

// The control projection always describes the Neuron role. A Brain host's
// durable local record instead owns its separate Brain credential and root.
// Preserve that owner while updating the approved public Brain peer list.
static inline bool prodigyApplyLocalTransportCredentialPeerProjection(
    ProdigyPersistentLocalBrainState& state,
    const ProdigyTransportCredentialBootstrap& projection,
    ProdigyTransportCredentialBootstrap& resultingNeuron)
{
  if (!prodigyLocalTransportCredentialStateValid(state) || !state.transportCredentials.enabled ||
      projection.self.role != ProdigyTransportCredentialNodeRole::neuron) return false;
  auto candidate = state;
  ProdigyTransportCredentialBootstrap currentNeuron, updatedNeuron;
  const bool brainRole = state.transportCredentials.self.role == ProdigyTransportCredentialNodeRole::brain;
  Vector<ProdigyTransportCredentialEnrollment> ledger;
  if (brainRole)
  {
    prodigyTransportCredentialBootstrapLedger(state.transportCredentials, ledger);
    ProdigyPersistentLocalBrainState localNeuron;
    if (!prodigyBuildLocalTransportCredentialState(state.transportCredentialAuthorityRoot, ledger, state.uuid,
          ProdigyTransportCredentialNodeRole::neuron, localNeuron, state.transportCredentials.committedAuthorityGeneration)) return false;
    currentNeuron = std::move(localNeuron.transportCredentials);
  }
  else currentNeuron = state.transportCredentials;
  if (!prodigyApplyTransportCredentialPeerProjection(currentNeuron, projection, updatedNeuron)) return false;
  if (!brainRole) candidate.transportCredentials = updatedNeuron;
  else
  {
    const ProdigyTransportCredentialEnrollment *ownBrain = nullptr;
    for (const auto& entry : ledger)
      if (entry.nodeUUID == state.uuid && entry.role == ProdigyTransportCredentialNodeRole::brain) ownBrain = &entry;
    if (!ownBrain || std::none_of(projection.authorizedPeers.begin(), projection.authorizedPeers.end(),
        [&](const auto& entry) { return entry == *ownBrain; })) return false;
    auto& peers = candidate.transportCredentials.authorizedPeers;
    peers.erase(std::remove_if(peers.begin(), peers.end(), [](const auto& entry) {
      return entry.role == ProdigyTransportCredentialNodeRole::brain;
    }), peers.end());
    for (const auto& entry : projection.authorizedPeers)
      if (entry.nodeUUID != state.uuid) peers.push_back(entry);
    std::sort(peers.begin(), peers.end(), [](const auto& lhs, const auto& rhs) {
      if (lhs.nodeUUID != rhs.nodeUUID) return lhs.nodeUUID < rhs.nodeUUID;
      if (lhs.role != rhs.role) return uint8_t(lhs.role) < uint8_t(rhs.role);
      return lhs.operationUUID < rhs.operationUUID;
    });
    candidate.transportCredentials.committedAuthorityGeneration = projection.committedAuthorityGeneration;
    prodigyTransportCredentialBootstrapLedger(candidate.transportCredentials, ledger);
    ProdigyPersistentLocalBrainState rebuiltNeuron;
    if (!prodigyBuildLocalTransportCredentialState(candidate.transportCredentialAuthorityRoot, ledger, candidate.uuid,
          ProdigyTransportCredentialNodeRole::neuron, rebuiltNeuron, projection.committedAuthorityGeneration) ||
        !prodigyTransportCredentialBootstrapSameProjection(rebuiltNeuron.transportCredentials, updatedNeuron) ||
        CRYPTO_memcmp(rebuiltNeuron.transportCredentials.self.secret, updatedNeuron.self.secret, sizeof(updatedNeuron.self.secret)) != 0) return false;
  }
  if (!prodigyLocalTransportCredentialStateValid(candidate)) return false;
  state = std::move(candidate);
  resultingNeuron = std::move(updatedNeuron);
  return true;
}

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentLocalBrainState& state)
{
  serializer.value16b(state.uuid);
  serializer.value16b(state.ownerClusterUUID);
  serializer.object(state.transportTLS);
  using Serializer = std::remove_cvref_t<S>;
  constexpr uint64_t markerValue = 0x41454749534c3031ULL;
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    if (state.transportCredentials.enabled)
    {
      uint64_t marker = markerValue;
      serializer.value8b(marker);
      serializer.object(state.transportCredentials);
      serializer.object(state.transportCredentialAuthorityRoot);
    }
  }
  else if (!serializer.adapter().isCompletedSuccessfully())
  {
    uint64_t marker = 0;
    serializer.value8b(marker);
    if (marker != markerValue)
    {
      serializer.adapter().error(bitsery::ReaderError::InvalidData);
      return;
    }
    serializer.object(state.transportCredentials);
    serializer.object(state.transportCredentialAuthorityRoot);
  }
}

// This is a durable, input-independent witness that a specific bootstrap
// supersession receipt was fully consumed. It intentionally stores only the
// checkpoint digest: the checkpoint itself remains one-shot startup input.
class ProdigyPersistentConsumedBootstrapBundleSupersessionReceipt {
public:

  uint128_t operationID = 0;
  uint128_t clusterUUID = 0;
  uint128_t localMachineUUID = 0;
  String targetControlSocketPath;
  String expectedIncompleteWorkerBundleSHA256;
  String successorBundleSHA256;
  String localContainerCheckpointSHA256;
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentConsumedBootstrapBundleSupersessionReceipt& receipt)
{
  serializer.value16b(receipt.operationID);
  serializer.value16b(receipt.clusterUUID);
  serializer.value16b(receipt.localMachineUUID);
  serializer.text1b(receipt.targetControlSocketPath, UINT32_MAX);
  serializer.text1b(receipt.expectedIncompleteWorkerBundleSHA256, UINT32_MAX);
  serializer.text1b(receipt.successorBundleSHA256, UINT32_MAX);
  serializer.text1b(receipt.localContainerCheckpointSHA256, UINT32_MAX);
}

static inline void resolveProdigyPersistentStateDBPath(String& path)
{
  if (const char *overridePath = getenv("PRODIGY_STATE_DB"); overridePath && overridePath[0] != '\0')
  {
    path.assign(overridePath);
    return;
  }

  path.assign(defaultProdigyPersistentStateDBPath());
}

static inline void resolveProdigyPersistentSecretsDBPath(const String& statePath, String& path)
{
  if (const char *overridePath = getenv("PRODIGY_STATE_SECRETS_DB"); overridePath && overridePath[0] != '\0')
  {
    path.assign(overridePath);
    return;
  }

  path = statePath;
  path.append(".secrets"_ctv);
}

static inline void prodigyBuildTransportTLSBootstrap(const ProdigyPersistentLocalBrainState& localState, ProdigyTransportTLSBootstrap& bootstrap)
{
  bootstrap = {};
  bootstrap.uuid = localState.uuid;
  bootstrap.transport = localState.transportTLS;
}

static inline void prodigyBuildTransportTLSAuthority(const ProdigyPersistentLocalBrainState& localState, ProdigyTransportTLSAuthority& authority)
{
  authority = {};
  authority.generation = localState.transportTLS.generation;
  authority.clusterRootCertPem = localState.transportTLS.clusterRootCertPem;
  authority.clusterRootKeyPem = localState.transportTLS.clusterRootKeyPem;
}

static inline bool prodigyApplyTransportTLSAuthorityToLocalState(
    ProdigyPersistentLocalBrainState& localState,
    const ProdigyTransportTLSAuthority& authority,
    String *failure = nullptr)
{
  if (failure)
  {
    failure->clear();
  }

  if (localState.uuid == 0)
  {
    if (failure)
    {
      failure->assign("local brain uuid required for transport tls authority"_ctv);
    }
    return false;
  }

  if (authority.canMintForCluster() == false)
  {
    if (failure)
    {
      failure->assign("transport tls authority incomplete"_ctv);
    }
    return false;
  }

  String localCertPem = {};
  String localKeyPem = {};
  Vector<String> addresses;
  if (prodigyGenerateTransportNodeCertificateEd25519(
          authority.clusterRootCertPem,
          authority.clusterRootKeyPem,
          localState.uuid,
          addresses,
          localCertPem,
          localKeyPem,
          failure) == false)
  {
    return false;
  }

  localState.transportTLS.generation = authority.generation;
  localState.transportTLS.clusterRootCertPem = authority.clusterRootCertPem;
  localState.transportTLS.clusterRootKeyPem = authority.clusterRootKeyPem;
  localState.transportTLS.localCertPem = localCertPem;
  localState.transportTLS.localKeyPem = localKeyPem;
  return true;
}

static inline bool parseProdigyPersistentLocalBrainStateJSON(const String& json, ProdigyPersistentLocalBrainState& state, String *failure = nullptr)
{
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  if (parser.parse(json.data(), json.size()).get(doc))
  {
    if (failure)
    {
      failure->assign("invalid local brain state json");
    }
    return false;
  }

  if (doc.type() != simdjson::dom::element_type::OBJECT)
  {
    if (failure)
    {
      failure->assign("local brain state must be an object");
    }
    return false;
  }

  ProdigyPersistentLocalBrainState parsed = {};
  bool sawUUID = false;
  bool sawRootCert = false;
  bool sawLocalCert = false;
  bool sawLocalKey = false;
  bool sawTransportCredentials = false;
  bool sawTransportAuthority = false;

  for (auto field : doc.get_object())
  {
    String key;
    key.setInvariant(field.key.data(), field.key.size());

    if (key == "uuid"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("local brain state uuid requires string");
        }
        return false;
      }

      String encoded(field.value.get_c_str());
      if (Vault::parseNodeCommonName(encoded, parsed.uuid) == false)
      {
        if (failure)
        {
          failure->assign("local brain state uuid must be 32 hex characters");
        }
        return false;
      }

      sawUUID = true;
    }
    else if (key == "ownerClusterUUID"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("local brain state ownerClusterUUID requires string");
        }
        return false;
      }

      String encoded(field.value.get_c_str());
      if (Vault::parseNodeCommonName(encoded, parsed.ownerClusterUUID) == false)
      {
        if (failure)
        {
          failure->assign("local brain state ownerClusterUUID must be 32 hex characters");
        }
        return false;
      }
    }
    else if (key == "transportAEGISBootstrap"_ctv)
    {
      if (sawTransportCredentials || field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure) failure->assign("transportAEGISBootstrap requires one bounded string"_ctv);
        return false;
      }
      sawTransportCredentials = true;
      String encoded = {};
      encoded.assign(field.value.get_c_str());
      String decoded = {};
      const bool ok = encoded.size() <= 1024 * 1024 && Base64::decode(encoded, decoded) &&
          BitseryEngine::deserializeSafe(decoded, parsed.transportCredentials) &&
          parsed.transportCredentials.enabled && prodigyTransportCredentialBootstrapValid(parsed.transportCredentials);
      Vault::secureClearString(encoded);
      Vault::secureClearString(decoded);
      if (!ok)
      {
        if (failure) failure->assign("invalid transportAEGISBootstrap"_ctv);
        return false;
      }
    }
    else if (key == "transportAEGISAuthority"_ctv)
    {
      if (sawTransportAuthority || field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure) failure->assign("transportAEGISAuthority requires one bounded string"_ctv);
        return false;
      }
      sawTransportAuthority = true;
      String encoded = {}, decoded = {};
      encoded.assign(field.value.get_c_str());
      const bool ok = encoded.size() <= 512 && Base64::decode(encoded, decoded) &&
          BitseryEngine::deserializeSafe(decoded, parsed.transportCredentialAuthorityRoot) &&
          parsed.transportCredentialAuthorityRoot.valid();
      Vault::secureClearString(encoded); Vault::secureClearString(decoded);
      if (!ok)
      {
        if (failure) failure->assign("invalid transportAEGISAuthority"_ctv);
        return false;
      }
    }
    else if (key == "generation"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64)
      {
        if (failure)
        {
          failure->assign("local brain state generation requires integer");
        }
        return false;
      }

      parsed.transportTLS.generation = uint64_t(field.value.get_uint64().value_unsafe());
    }
    else if (key == "clusterRootCertPem"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("local brain state clusterRootCertPem requires string");
        }
        return false;
      }

      parsed.transportTLS.clusterRootCertPem.assign(field.value.get_c_str());
      sawRootCert = (parsed.transportTLS.clusterRootCertPem.size() > 0);
    }
    else if (key == "clusterRootKeyPem"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("local brain state clusterRootKeyPem requires string");
        }
        return false;
      }

      parsed.transportTLS.clusterRootKeyPem.assign(field.value.get_c_str());
    }
    else if (key == "localCertPem"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("local brain state localCertPem requires string");
        }
        return false;
      }

      parsed.transportTLS.localCertPem.assign(field.value.get_c_str());
      sawLocalCert = (parsed.transportTLS.localCertPem.size() > 0);
    }
    else if (key == "localKeyPem"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("local brain state localKeyPem requires string");
        }
        return false;
      }

      parsed.transportTLS.localKeyPem.assign(field.value.get_c_str());
      sawLocalKey = (parsed.transportTLS.localKeyPem.size() > 0);
    }
    else
    {
      if (failure)
      {
        failure->assign("invalid local brain state field");
      }
      return false;
    }
  }

  if (sawUUID == false)
  {
    if (failure)
    {
      failure->assign("local brain state uuid required");
    }
    return false;
  }

  if (sawRootCert == false)
  {
    if (sawLocalCert || sawLocalKey)
    {
      if (failure)
      {
        failure->assign("local brain state clusterRootCertPem required when tls material is present");
      }
      return false;
    }
  }
  else if (sawLocalCert == false || sawLocalKey == false)
  {
    if (failure)
    {
      failure->assign("local brain state localCertPem and localKeyPem required when tls material is present");
    }
    return false;
  }

  if (!prodigyLocalTransportCredentialStateValid(parsed))
  {
    if (failure) failure->assign("transport credential identity disagrees with local state"_ctv);
    return false;
  }
  state = parsed;
  return true;
}

static inline void renderProdigyPersistentLocalBrainStateJSON(const ProdigyPersistentLocalBrainState& state, String& json)
{
  json.clear();
  json.append("{\"uuid\":\""_ctv);
  String encodedUUID = {};
  if (Vault::buildNodeCommonName(state.uuid, encodedUUID))
  {
    json.append(encodedUUID);
  }
  else
  {
    json.append(String::toHex(state.uuid));
  }
  json.append("\""_ctv);

  if (state.ownerClusterUUID != 0)
  {
    String ownerClusterUUID = {};
    if (Vault::buildNodeCommonName(state.ownerClusterUUID, ownerClusterUUID) == false)
    {
      ownerClusterUUID.assignItoh(state.ownerClusterUUID);
    }
    json.append(",\"ownerClusterUUID\":"_ctv);
    appendEscapedJSONString(json, ownerClusterUUID);
  }

  if (state.transportTLS.clusterRootCertPem.size() > 0 || state.transportTLS.clusterRootKeyPem.size() > 0 || state.transportTLS.localCertPem.size() > 0 || state.transportTLS.localKeyPem.size() > 0 || state.transportTLS.generation > 0)
  {
    json.append(",\"generation\":"_ctv);
    json.snprintf_add<"{itoa}"_ctv>(state.transportTLS.generation);

    json.append(",\"clusterRootCertPem\":"_ctv);
    appendEscapedJSONString(json, state.transportTLS.clusterRootCertPem);

    if (state.transportTLS.clusterRootKeyPem.size() > 0)
    {
      json.append(",\"clusterRootKeyPem\":"_ctv);
      appendEscapedJSONString(json, state.transportTLS.clusterRootKeyPem);
    }

    json.append(",\"localCertPem\":"_ctv);
    appendEscapedJSONString(json, state.transportTLS.localCertPem);

    json.append(",\"localKeyPem\":"_ctv);
    appendEscapedJSONString(json, state.transportTLS.localKeyPem);
  }
  if (state.transportCredentials.enabled)
  {
    String serialized = {}, encoded = {};
    auto bootstrap = state.transportCredentials;
    BitseryEngine::serialize(serialized, bootstrap);
    Base64::encode(serialized, encoded);
    json.append(",\"transportAEGISBootstrap\":"_ctv);
    appendEscapedJSONString(json, encoded);
    Vault::secureClearString(serialized);
    Vault::secureClearString(encoded);
    if (state.transportCredentialAuthorityRoot.valid())
    {
      auto authority = state.transportCredentialAuthorityRoot;
      BitseryEngine::serialize(serialized, authority);
      Base64::encode(serialized, encoded);
      json.append(",\"transportAEGISAuthority\":"_ctv);
      appendEscapedJSONString(json, encoded);
      Vault::secureClearString(serialized); Vault::secureClearString(encoded);
    }
  }
  json.append("}"_ctv);
}

static inline void prodigyBackfillLocalBrainOwnerClusterUUID(
    ProdigyPersistentLocalBrainState& state,
    const ProdigyPersistentBrainSnapshot& snapshot,
    bool *changed = nullptr)
{
  if (changed)
  {
    *changed = false;
  }

  if (state.ownerClusterUUID != 0 || snapshot.brainConfig.clusterUUID == 0)
  {
    return;
  }

  state.ownerClusterUUID = snapshot.brainConfig.clusterUUID;
  if (changed)
  {
    *changed = true;
  }
}

static inline bool prodigyEnsureLocalBrainOwnedByCluster(
    ProdigyPersistentLocalBrainState& state,
    uint128_t clusterUUID,
    bool *changed = nullptr,
    String *failure = nullptr)
{
  if (changed)
  {
    *changed = false;
  }
  if (failure)
  {
    failure->clear();
  }

  if (clusterUUID == 0)
  {
    return true;
  }

  if (state.ownerClusterUUID == 0)
  {
    state.ownerClusterUUID = clusterUUID;
    if (changed)
    {
      *changed = true;
    }
    return true;
  }

  if (state.ownerClusterUUID == clusterUUID)
  {
    return true;
  }

  String existingClusterUUID = {};
  existingClusterUUID.assignItoh(state.ownerClusterUUID);
  String requestedClusterUUID = {};
  requestedClusterUUID.assignItoh(clusterUUID);
  if (failure)
  {
    failure->snprintf<"local machine already belongs to cluster {} and refuses takeover by cluster {}"_ctv>(
        existingClusterUUID,
        requestedClusterUUID);
  }

  return false;
}

static inline bool parseProdigyEnvironmentBGPJSONElement(simdjson::dom::element element, ProdigyEnvironmentBGPConfig& bgp, String *failure = nullptr)
{
  if (element.type() != simdjson::dom::element_type::OBJECT)
  {
    if (failure)
    {
      failure->assign("runtimeEnvironment.bgp requires object");
    }
    return false;
  }

  ProdigyEnvironmentBGPConfig parsed = {};
  parsed.specified = true;

  for (auto field : element.get_object())
  {
    String key;
    key.setInvariant(field.key.data(), field.key.size());

    if (key == "enabled"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::BOOL || field.value.get(parsed.config.enabled) != simdjson::SUCCESS)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.bgp.enabled requires bool");
        }
        return false;
      }
    }
    else if (key == "bgpID"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.bgp.bgpID requires string");
        }
        return false;
      }

      String value(field.value.get_c_str());
      if (prodigyParseBGPIDText(value, parsed.config.ourBGPID) == false)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.bgp.bgpID requires ipv4 string");
        }
        return false;
      }
    }
    else if (key == "community"_ctv)
    {
      uint64_t value = 0;
      if ((field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64) || field.value.get(value) != simdjson::SUCCESS || value > UINT32_MAX)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.bgp.community requires uint32");
        }
        return false;
      }

      parsed.config.community = uint32_t(value);
    }
    else if (key == "nextHop4"_ctv || key == "nextHop6"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->snprintf<"runtimeEnvironment.bgp.{} requires string"_ctv>(key);
        }
        return false;
      }

      IPAddress parsedAddress = {};
      String value(field.value.get_c_str());
      if (prodigyParseIPAddressText(value, parsedAddress) == false)
      {
        if (failure)
        {
          failure->snprintf<"runtimeEnvironment.bgp.{} invalid address"_ctv>(key);
        }
        return false;
      }

      if (key == "nextHop4"_ctv)
      {
        if (parsedAddress.is6)
        {
          if (failure)
          {
            failure->assign("runtimeEnvironment.bgp.nextHop4 requires ipv4");
          }
          return false;
        }

        parsed.config.nextHop4 = parsedAddress;
      }
      else
      {
        if (parsedAddress.is6 == false)
        {
          if (failure)
          {
            failure->assign("runtimeEnvironment.bgp.nextHop6 requires ipv6");
          }
          return false;
        }

        parsed.config.nextHop6 = parsedAddress;
      }
    }
    else if (key == "peers"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::ARRAY)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.bgp.peers requires array");
        }
        return false;
      }

      for (auto peerValue : field.value.get_array())
      {
        if (peerValue.type() != simdjson::dom::element_type::OBJECT)
        {
          if (failure)
          {
            failure->assign("runtimeEnvironment.bgp.peers requires object members");
          }
          return false;
        }

        NeuronBGPPeerConfig peer = {};
        for (auto peerField : peerValue.get_object())
        {
          String peerKey;
          peerKey.setInvariant(peerField.key.data(), peerField.key.size());

          if (peerKey == "peerASN"_ctv)
          {
            uint64_t value = 0;
            if ((peerField.value.type() != simdjson::dom::element_type::INT64 && peerField.value.type() != simdjson::dom::element_type::UINT64) || peerField.value.get(value) != simdjson::SUCCESS || value > UINT16_MAX)
            {
              if (failure)
              {
                failure->assign("runtimeEnvironment.bgp.peers[].peerASN requires uint16");
              }
              return false;
            }

            peer.peerASN = uint16_t(value);
          }
          else if (peerKey == "peerAddress"_ctv || peerKey == "sourceAddress"_ctv)
          {
            if (peerField.value.type() != simdjson::dom::element_type::STRING)
            {
              if (failure)
              {
                failure->snprintf<"runtimeEnvironment.bgp.peers[].{} requires string"_ctv>(peerKey);
              }
              return false;
            }

            IPAddress parsedAddress = {};
            String value(peerField.value.get_c_str());
            if (prodigyParseIPAddressText(value, parsedAddress) == false)
            {
              if (failure)
              {
                failure->snprintf<"runtimeEnvironment.bgp.peers[].{} invalid address"_ctv>(peerKey);
              }
              return false;
            }

            if (peerKey == "peerAddress"_ctv)
            {
              peer.peerAddress = parsedAddress;
            }
            else
            {
              peer.sourceAddress = parsedAddress;
            }
          }
          else if (peerKey == "md5Password"_ctv)
          {
            if (peerField.value.type() != simdjson::dom::element_type::STRING)
            {
              if (failure)
              {
                failure->assign("runtimeEnvironment.bgp.peers[].md5Password requires string");
              }
              return false;
            }

            peer.md5Password.assign(peerField.value.get_c_str());
          }
          else if (peerKey == "hopLimit"_ctv)
          {
            uint64_t value = 0;
            if ((peerField.value.type() != simdjson::dom::element_type::INT64 && peerField.value.type() != simdjson::dom::element_type::UINT64) || peerField.value.get(value) != simdjson::SUCCESS || value > UINT8_MAX)
            {
              if (failure)
              {
                failure->assign("runtimeEnvironment.bgp.peers[].hopLimit requires uint8");
              }
              return false;
            }

            peer.hopLimit = uint8_t(value);
          }
          else
          {
            if (failure)
            {
              failure->assign("invalid runtimeEnvironment.bgp.peers[] field");
            }
            return false;
          }
        }

        parsed.config.peers.push_back(peer);
      }
    }
    else
    {
      if (failure)
      {
        failure->assign("invalid runtimeEnvironment.bgp field");
      }
      return false;
    }
  }

  bgp = parsed;
  return true;
}

static inline bool parseProdigyRuntimeEnvironmentConfigJSONElement(simdjson::dom::element element, ProdigyRuntimeEnvironmentConfig& config, String *failure = nullptr)
{
  if (element.type() != simdjson::dom::element_type::OBJECT)
  {
    if (failure)
    {
      failure->assign("runtimeEnvironment must be an object");
    }
    return false;
  }

  ProdigyRuntimeEnvironmentConfig parsed = {};

  for (auto field : element.get_object())
  {
    String key;
    key.setInvariant(field.key.data(), field.key.size());

    if (key == "kind"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.kind requires string");
        }
        return false;
      }

      String value(field.value.get_c_str());
      if (parseProdigyEnvironmentKind(value, parsed.kind) == false)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.kind invalid");
        }
        return false;
      }
    }
    else if (key == "providerScope"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.providerScope requires string");
        }
        return false;
      }

      parsed.providerScope.assign(field.value.get_c_str());
    }
    else if (key == "providerCredentialMaterial"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.providerCredentialMaterial requires string");
        }
        return false;
      }

      parsed.providerCredentialMaterial.assign(field.value.get_c_str());
    }
    else if (key == "aws"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::OBJECT)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.aws requires object");
        }
        return false;
      }

      for (auto nestedField : field.value.get_object())
      {
        String nestedKey;
        nestedKey.setInvariant(nestedField.key.data(), nestedField.key.size());

        if (nestedKey == "bootstrapLaunchTemplateName"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.aws.bootstrapLaunchTemplateName requires string");
            }
            return false;
          }

          parsed.aws.bootstrapLaunchTemplateName.assign(nestedField.value.get_c_str());
        }
        else if (nestedKey == "bootstrapLaunchTemplateVersion"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.aws.bootstrapLaunchTemplateVersion requires string");
            }
            return false;
          }

          parsed.aws.bootstrapLaunchTemplateVersion.assign(nestedField.value.get_c_str());
        }
        else if (nestedKey == "bootstrapCredentialRefreshCommand"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.aws.bootstrapCredentialRefreshCommand requires string");
            }
            return false;
          }

          parsed.aws.bootstrapCredentialRefreshCommand.assign(nestedField.value.get_c_str());
        }
        else if (nestedKey == "bootstrapCredentialRefreshFailureHint"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint requires string");
            }
            return false;
          }

          parsed.aws.bootstrapCredentialRefreshFailureHint.assign(nestedField.value.get_c_str());
        }
        else if (nestedKey == "instanceProfileName"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.aws.instanceProfileName requires string");
            }
            return false;
          }

          parsed.aws.instanceProfileName.assign(nestedField.value.get_c_str());
        }
        else if (nestedKey == "instanceProfileArn"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.aws.instanceProfileArn requires string");
            }
            return false;
          }

          parsed.aws.instanceProfileArn.assign(nestedField.value.get_c_str());
        }
        else
        {
          if (failure)
          {
            failure->assign("invalid runtimeEnvironment.aws field");
          }
          return false;
        }
      }
    }
    else if (key == "gcp"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::OBJECT)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.gcp requires object");
        }
        return false;
      }

      for (auto nestedField : field.value.get_object())
      {
        String nestedKey;
        nestedKey.setInvariant(nestedField.key.data(), nestedField.key.size());

        if (nestedKey == "bootstrapAccessTokenRefreshCommand"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand requires string");
            }
            return false;
          }

          parsed.gcp.bootstrapAccessTokenRefreshCommand.assign(nestedField.value.get_c_str());
        }
        else if (nestedKey == "bootstrapAccessTokenRefreshFailureHint"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint requires string");
            }
            return false;
          }

          parsed.gcp.bootstrapAccessTokenRefreshFailureHint.assign(nestedField.value.get_c_str());
        }
        else
        {
          if (failure)
          {
            failure->assign("invalid runtimeEnvironment.gcp field");
          }
          return false;
        }
      }
    }
    else if (key == "azure"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::OBJECT)
      {
        if (failure)
        {
          failure->assign("runtimeEnvironment.azure requires object");
        }
        return false;
      }

      for (auto nestedField : field.value.get_object())
      {
        String nestedKey;
        nestedKey.setInvariant(nestedField.key.data(), nestedField.key.size());

        if (nestedKey == "bootstrapAccessTokenRefreshCommand"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand requires string");
            }
            return false;
          }

          parsed.azure.bootstrapAccessTokenRefreshCommand.assign(nestedField.value.get_c_str());
        }
        else if (nestedKey == "bootstrapAccessTokenRefreshFailureHint"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint requires string");
            }
            return false;
          }

          parsed.azure.bootstrapAccessTokenRefreshFailureHint.assign(nestedField.value.get_c_str());
        }
        else if (nestedKey == "managedIdentityResourceID"_ctv)
        {
          if (nestedField.value.type() != simdjson::dom::element_type::STRING)
          {
            if (failure)
            {
              failure->assign("runtimeEnvironment.azure.managedIdentityResourceID requires string");
            }
            return false;
          }

          parsed.azure.managedIdentityResourceID.assign(nestedField.value.get_c_str());
        }
        else
        {
          if (failure)
          {
            failure->assign("invalid runtimeEnvironment.azure field");
          }
          return false;
        }
      }
    }
    else if (key == "bgp"_ctv)
    {
      if (parseProdigyEnvironmentBGPJSONElement(field.value, parsed.bgp, failure) == false)
      {
        return false;
      }
    }
    else
    {
      if (failure)
      {
        failure->assign("invalid runtimeEnvironment field");
      }
      return false;
    }
  }

  prodigyApplyInternalRuntimeEnvironmentDefaults(parsed);
  config = parsed;
  return true;
}

static inline bool parseProdigyBootstrapBundleSupersessionReceiptJSONElement(
    simdjson::dom::element value,
    ProdigyBootstrapBundleSupersessionReceipt& receipt,
    String *failure = nullptr)
{
  if (value.type() != simdjson::dom::element_type::OBJECT)
  {
    if (failure) failure->assign("bootstrapBundleSupersession requires object"_ctv);
    return false;
  }
  String operationID = {}, clusterUUID = {};
  bool sawOperationID = false, sawClusterUUID = false, sawExpected = false, sawSuccessor = false, sawSocket = false;
  ProdigyBootstrapBundleSupersessionReceipt parsed = {};
  for (auto field : value.get_object())
  {
    String key = {}; key.setInvariant(field.key.data(), field.key.size());
    if (field.value.type() != simdjson::dom::element_type::STRING)
    {
      if (failure) failure->assign("bootstrapBundleSupersession fields require strings"_ctv);
      return false;
    }
    String text = {}; text.assign(field.value.get_c_str());
    if (key == "operationID"_ctv) { operationID = std::move(text); sawOperationID = true; }
    else if (key == "clusterUUID"_ctv) { clusterUUID = std::move(text); sawClusterUUID = true; }
    else if (key == "expectedIncompleteWorkerBundleSHA256"_ctv) { parsed.expectedIncompleteWorkerBundleSHA256 = std::move(text); sawExpected = true; }
    else if (key == "successorBundleSHA256"_ctv) { parsed.successorBundleSHA256 = std::move(text); sawSuccessor = true; }
    else if (key == "targetControlSocketPath"_ctv) { parsed.targetControlSocketPath = std::move(text); sawSocket = true; }
    else if (key == "localContainerCheckpoint"_ctv)
    {
      if (text.size() > 32 * 1024 * 1024) { if (failure) failure->assign("local container checkpoint exceeds size limit"_ctv); return false; }
      Base64::decode(text, parsed.localContainerCheckpoint);
    }
    else if (key == "localContainerCheckpointSHA256"_ctv) { parsed.localContainerCheckpointSHA256 = std::move(text); }
    else { if (failure) failure->assign("invalid bootstrapBundleSupersession field"_ctv); return false; }
  }
  if (!(sawOperationID && sawClusterUUID && sawExpected && sawSuccessor && sawSocket) ||
      prodigyParseCanonicalHex128(operationID, parsed.operationID) == false ||
      prodigyParseCanonicalHex128(clusterUUID, parsed.clusterUUID) == false ||
      prodigySHA256HexIsCanonical(parsed.expectedIncompleteWorkerBundleSHA256) == false ||
      prodigySHA256HexIsCanonical(parsed.successorBundleSHA256) == false ||
      parsed.targetControlSocketPath.empty() ||
      (parsed.localContainerCheckpoint.empty() != parsed.localContainerCheckpointSHA256.empty()) ||
      (parsed.localContainerCheckpoint.empty() == false && prodigySHA256HexIsCanonical(parsed.localContainerCheckpointSHA256) == false))
  {
    if (failure) failure->assign("invalid bootstrapBundleSupersession receipt"_ctv);
    return false;
  }
  receipt = std::move(parsed);
  return true;
}

static inline bool parseProdigyPersistentBootStateJSON(const String& json, ProdigyPersistentBootState& state, String *failure = nullptr)
{
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  if (parser.parse(json.data(), json.size()).get(doc))
  {
    if (failure)
    {
      failure->assign("invalid boot json");
    }
    return false;
  }

  if (doc.type() != simdjson::dom::element_type::OBJECT)
  {
    if (failure)
    {
      failure->assign("boot state must be an object");
    }
    return false;
  }

  ProdigyPersistentBootState parsed = {};
  bool sawBootstrapPeers = false;
  bool sawNodeRole = false;
  bool sawControlSocketPath = false;

  for (auto field : doc.get_object())
  {
    String key;
    key.setInvariant(field.key.data(), field.key.size());

    if (key == "bootstrapPeers"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::ARRAY)
      {
        if (failure)
        {
          failure->assign("bootstrapPeers requires array");
        }
        return false;
      }

      sawBootstrapPeers = true;
      for (auto peer : field.value.get_array())
      {
        ProdigyBootstrapConfig::BootstrapPeer parsedPeer = {};
        if (parseProdigyBootstrapPeerJSONElement(peer, parsedPeer, failure) == false)
        {
          return false;
        }

        parsed.bootstrapConfig.bootstrapPeers.push_back(parsedPeer);
      }
    }
    else if (key == "nodeRole"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("nodeRole requires string");
        }
        return false;
      }

      String value(field.value.get_c_str());
      if (parseProdigyBootstrapNodeRole(value, parsed.bootstrapConfig.nodeRole) == false)
      {
        if (failure)
        {
          failure->assign("nodeRole invalid");
        }
        return false;
      }

      sawNodeRole = true;
    }
    else if (key == "controlSocketPath"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("controlSocketPath requires string");
        }
        return false;
      }

      parsed.bootstrapConfig.controlSocketPath.assign(field.value.get_c_str());
      sawControlSocketPath = true;
    }
    else if (key == "bootstrapSshUser"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("bootstrapSshUser requires string");
        }
        return false;
      }

      parsed.bootstrapSshUser.assign(field.value.get_c_str());
    }
    else if (key == "bootstrapSshKeyPackage"_ctv)
    {
      if (parseProdigyPersistentSSHKeyPackageJSONElement(field.value, "bootstrapSshKeyPackage", parsed.bootstrapSshKeyPackage, failure) == false)
      {
        return false;
      }
    }
    else if (key == "bootstrapSshHostKeyPackage"_ctv)
    {
      if (parseProdigyPersistentSSHKeyPackageJSONElement(field.value, "bootstrapSshHostKeyPackage", parsed.bootstrapSshHostKeyPackage, failure) == false)
      {
        return false;
      }
    }
    else if (key == "bootstrapSshPrivateKeyPath"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("bootstrapSshPrivateKeyPath requires string");
        }
        return false;
      }

      parsed.bootstrapSshPrivateKeyPath.assign(field.value.get_c_str());
    }
    else if (key == "runtimeEnvironment"_ctv)
    {
      if (parseProdigyRuntimeEnvironmentConfigJSONElement(field.value, parsed.runtimeEnvironment, failure) == false)
      {
        return false;
      }
    }
    else if (key == "bootstrapBundleSupersession"_ctv)
    {
      if (parseProdigyBootstrapBundleSupersessionReceiptJSONElement(field.value, parsed.bootstrapBundleSupersession, failure) == false)
      {
        return false;
      }
    }
    else if (key == "initialTopology"_ctv)
    {
      if (field.value.type() != simdjson::dom::element_type::STRING)
      {
        if (failure)
        {
          failure->assign("initialTopology requires string");
        }
        return false;
      }

      String encodedTopology = {};
      encodedTopology.assign(field.value.get_c_str());
      String decodedTopology = {};
      if (Base64::decode(encodedTopology, decodedTopology) == false)
      {
        if (failure)
        {
          failure->assign("initialTopology base64 decode failed");
        }
        return false;
      }

      ClusterTopology initialTopology = {};
      if (BitseryEngine::deserializeSafe(decodedTopology, initialTopology) == false)
      {
        if (failure)
        {
          failure->assign("initialTopology decode failed");
        }
        return false;
      }

      parsed.initialTopology = std::move(initialTopology);
    }
    else
    {
      if (failure)
      {
        failure->assign("invalid boot state field");
      }
      return false;
    }
  }

  if (sawBootstrapPeers == false)
  {
    if (failure)
    {
      failure->assign("bootstrapPeers required");
    }
    return false;
  }

  if (sawNodeRole == false)
  {
    if (failure)
    {
      failure->assign("nodeRole required");
    }
    return false;
  }

  if (sawControlSocketPath == false || parsed.bootstrapConfig.controlSocketPath.size() == 0)
  {
    if (failure)
    {
      failure->assign("controlSocketPath required");
    }
    return false;
  }

  prodigyStripManagedCloudBootstrapCredentials(parsed.runtimeEnvironment);
  state = parsed;
  return true;
}

static inline void renderProdigyPersistentBootStateJSON(const ProdigyPersistentBootState& state, String& json, bool redactPrivateKeyMaterial = false)
{
  ProdigyRuntimeEnvironmentConfig renderedRuntimeEnvironment = state.runtimeEnvironment;
  prodigyStripManagedCloudBootstrapCredentials(renderedRuntimeEnvironment);
  const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment = renderedRuntimeEnvironment;

  json.clear();
  json.append("{\"bootstrapPeers\":["_ctv);

  for (uint64_t index = 0; index < state.bootstrapConfig.bootstrapPeers.size(); ++index)
  {
    if (index > 0)
    {
      json.append(","_ctv);
    }

    renderProdigyBootstrapPeerJSON(state.bootstrapConfig.bootstrapPeers[index], json);
  }

  json.append("],\"nodeRole\":"_ctv);
  String nodeRole;
  nodeRole.assign(prodigyBootstrapNodeRoleName(state.bootstrapConfig.nodeRole));
  appendEscapedJSONString(json, nodeRole);

  json.append(",\"controlSocketPath\":"_ctv);
  appendEscapedJSONString(json, state.bootstrapConfig.controlSocketPath);

  if (state.bootstrapSshUser.size() > 0)
  {
    json.append(",\"bootstrapSshUser\":"_ctv);
    appendEscapedJSONString(json, state.bootstrapSshUser);
  }

  if (prodigyPersistentBootStateSSHKeyPackageConfigured(state.bootstrapSshKeyPackage))
  {
    json.append(",\"bootstrapSshKeyPackage\":"_ctv);
    renderProdigyPersistentSSHKeyPackageJSON(state.bootstrapSshKeyPackage, json, redactPrivateKeyMaterial);
  }

  if (prodigyPersistentBootStateSSHKeyPackageConfigured(state.bootstrapSshHostKeyPackage))
  {
    json.append(",\"bootstrapSshHostKeyPackage\":"_ctv);
    renderProdigyPersistentSSHKeyPackageJSON(state.bootstrapSshHostKeyPackage, json, redactPrivateKeyMaterial);
  }

  if (state.bootstrapSshPrivateKeyPath.size() > 0)
  {
    json.append(",\"bootstrapSshPrivateKeyPath\":"_ctv);
    appendEscapedJSONString(json, state.bootstrapSshPrivateKeyPath);
  }

  if (runtimeEnvironment.configured())
  {
    json.append(",\"runtimeEnvironment\":{"_ctv);
    json.append("\"kind\":"_ctv);
    String environmentKind;
    environmentKind.assign(prodigyEnvironmentKindName(runtimeEnvironment.kind));
    appendEscapedJSONString(json, environmentKind);

    if (runtimeEnvironment.providerScope.size() > 0)
    {
      json.append(",\"providerScope\":"_ctv);
      appendEscapedJSONString(json, runtimeEnvironment.providerScope);
    }

    if (runtimeEnvironment.providerCredentialMaterial.size() > 0)
    {
      json.append(",\"providerCredentialMaterial\":"_ctv);
      appendEscapedJSONString(json, runtimeEnvironment.providerCredentialMaterial);
    }

    if (runtimeEnvironment.aws.configured())
    {
      json.append(",\"aws\":{"_ctv);
      bool firstAws = true;

      if (runtimeEnvironment.aws.bootstrapLaunchTemplateName.size() > 0)
      {
        appendEscapedJSONString(json, "bootstrapLaunchTemplateName"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.aws.bootstrapLaunchTemplateName);
        firstAws = false;
      }

      if (runtimeEnvironment.aws.bootstrapLaunchTemplateVersion.size() > 0)
      {
        if (firstAws == false)
        {
          json.append(","_ctv);
        }

        appendEscapedJSONString(json, "bootstrapLaunchTemplateVersion"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.aws.bootstrapLaunchTemplateVersion);
        firstAws = false;
      }

      if (runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() > 0)
      {
        if (firstAws == false)
        {
          json.append(","_ctv);
        }

        appendEscapedJSONString(json, "bootstrapCredentialRefreshCommand"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.aws.bootstrapCredentialRefreshCommand);
        firstAws = false;
      }

      if (runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() > 0)
      {
        if (firstAws == false)
        {
          json.append(","_ctv);
        }

        appendEscapedJSONString(json, "bootstrapCredentialRefreshFailureHint"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint);
        firstAws = false;
      }

      if (runtimeEnvironment.aws.instanceProfileName.size() > 0)
      {
        if (firstAws == false)
        {
          json.append(","_ctv);
        }

        appendEscapedJSONString(json, "instanceProfileName"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.aws.instanceProfileName);
        firstAws = false;
      }

      if (runtimeEnvironment.aws.instanceProfileArn.size() > 0)
      {
        if (firstAws == false)
        {
          json.append(","_ctv);
        }

        appendEscapedJSONString(json, "instanceProfileArn"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.aws.instanceProfileArn);
      }

      json.append("}"_ctv);
    }

    if (runtimeEnvironment.gcp.configured())
    {
      json.append(",\"gcp\":{"_ctv);
      bool firstGcp = true;

      if (runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.size() > 0)
      {
        appendEscapedJSONString(json, "bootstrapAccessTokenRefreshCommand"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand);
        firstGcp = false;
      }

      if (runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint.size() > 0)
      {
        if (firstGcp == false)
        {
          json.append(","_ctv);
        }

        appendEscapedJSONString(json, "bootstrapAccessTokenRefreshFailureHint"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint);
      }

      json.append("}"_ctv);
    }

    if (runtimeEnvironment.azure.configured())
    {
      json.append(",\"azure\":{"_ctv);
      bool firstAzure = true;

      if (runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.size() > 0)
      {
        appendEscapedJSONString(json, "bootstrapAccessTokenRefreshCommand"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand);
        firstAzure = false;
      }

      if (runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint.size() > 0)
      {
        if (firstAzure == false)
        {
          json.append(","_ctv);
        }

        appendEscapedJSONString(json, "bootstrapAccessTokenRefreshFailureHint"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint);
        firstAzure = false;
      }

      if (runtimeEnvironment.azure.managedIdentityResourceID.size() > 0)
      {
        if (firstAzure == false)
        {
          json.append(","_ctv);
        }

        appendEscapedJSONString(json, "managedIdentityResourceID"_ctv);
        json.append(":"_ctv);
        appendEscapedJSONString(json, runtimeEnvironment.azure.managedIdentityResourceID);
      }

      json.append("}"_ctv);
    }

    if (runtimeEnvironment.bgp.configured())
    {
      json.append(",\"bgp\":{"_ctv);
      json.append("\"enabled\":"_ctv);
      if (runtimeEnvironment.bgp.config.enabled)
      {
        json.append("true"_ctv);
      }
      else
      {
        json.append("false"_ctv);
      }

      if (runtimeEnvironment.bgp.config.ourBGPID != 0)
      {
        String bgpID = {};
        if (prodigyRenderBGPIDText(runtimeEnvironment.bgp.config.ourBGPID, bgpID))
        {
          json.append(",\"bgpID\":"_ctv);
          appendEscapedJSONString(json, bgpID);
        }
      }

      if (runtimeEnvironment.bgp.config.community != 0)
      {
        json.append(",\"community\":"_ctv);
        json.snprintf_add<"{itoa}"_ctv>(runtimeEnvironment.bgp.config.community);
      }

      if (runtimeEnvironment.bgp.config.nextHop4.isNull() == false)
      {
        String nextHop4 = {};
        if (prodigyRenderIPAddressText(runtimeEnvironment.bgp.config.nextHop4, nextHop4))
        {
          json.append(",\"nextHop4\":"_ctv);
          appendEscapedJSONString(json, nextHop4);
        }
      }

      if (runtimeEnvironment.bgp.config.nextHop6.isNull() == false)
      {
        String nextHop6 = {};
        if (prodigyRenderIPAddressText(runtimeEnvironment.bgp.config.nextHop6, nextHop6))
        {
          json.append(",\"nextHop6\":"_ctv);
          appendEscapedJSONString(json, nextHop6);
        }
      }

      if (runtimeEnvironment.bgp.config.peers.empty() == false)
      {
        json.append(",\"peers\":["_ctv);
        for (uint32_t index = 0; index < runtimeEnvironment.bgp.config.peers.size(); ++index)
        {
          if (index > 0)
          {
            json.append(","_ctv);
          }

          const NeuronBGPPeerConfig& peer = runtimeEnvironment.bgp.config.peers[index];
          json.append("{\"peerASN\":"_ctv);
          json.snprintf_add<"{itoa}"_ctv>(uint32_t(peer.peerASN));

          String peerAddress = {};
          if (prodigyRenderIPAddressText(peer.peerAddress, peerAddress))
          {
            json.append(",\"peerAddress\":"_ctv);
            appendEscapedJSONString(json, peerAddress);
          }

          String sourceAddress = {};
          if (prodigyRenderIPAddressText(peer.sourceAddress, sourceAddress))
          {
            json.append(",\"sourceAddress\":"_ctv);
            appendEscapedJSONString(json, sourceAddress);
          }

          if (peer.md5Password.size() > 0)
          {
            json.append(",\"md5Password\":"_ctv);
            appendEscapedJSONString(json, peer.md5Password);
          }

          if (peer.hopLimit > 0)
          {
            json.append(",\"hopLimit\":"_ctv);
            json.snprintf_add<"{itoa}"_ctv>(uint32_t(peer.hopLimit));
          }

          json.append("}"_ctv);
        }
        json.append("]"_ctv);
      }

      json.append("}"_ctv);
    }

    json.append("}"_ctv);
  }

  if (state.bootstrapBundleSupersession.present())
  {
    const ProdigyBootstrapBundleSupersessionReceipt& receipt = state.bootstrapBundleSupersession;
    String operationID = {}, clusterUUID = {};
    operationID.assignItoh(receipt.operationID);
    clusterUUID.assignItoh(receipt.clusterUUID);
    json.append(",\"bootstrapBundleSupersession\":{\"operationID\":"_ctv); appendEscapedJSONString(json, operationID);
    json.append(",\"clusterUUID\":"_ctv); appendEscapedJSONString(json, clusterUUID);
    json.append(",\"expectedIncompleteWorkerBundleSHA256\":"_ctv); appendEscapedJSONString(json, receipt.expectedIncompleteWorkerBundleSHA256);
    json.append(",\"successorBundleSHA256\":"_ctv); appendEscapedJSONString(json, receipt.successorBundleSHA256);
    json.append(",\"targetControlSocketPath\":"_ctv); appendEscapedJSONString(json, receipt.targetControlSocketPath);
    if (receipt.localContainerCheckpoint.empty() == false)
    {
      String encodedCheckpoint = {};
      Base64::encode(receipt.localContainerCheckpoint.data(), receipt.localContainerCheckpoint.size(), encodedCheckpoint);
      json.append(",\"localContainerCheckpoint\":"_ctv); appendEscapedJSONString(json, encodedCheckpoint);
      json.append(",\"localContainerCheckpointSHA256\":"_ctv); appendEscapedJSONString(json, receipt.localContainerCheckpointSHA256);
    }
    json.append("}"_ctv);
  }

  if (state.initialTopology.machines.empty() == false)
  {
    ClusterTopology topology = state.initialTopology;
    String serializedTopology = {};
    BitseryEngine::serialize(serializedTopology, topology);

    String encodedTopology = {};
    Base64::encode(serializedTopology, encodedTopology);

    json.append(",\"initialTopology\":"_ctv);
    appendEscapedJSONString(json, encodedTopology);
  }

  json.append("}"_ctv);
}

static inline uint64_t prodigyGeneratePersistentSecretVersion(void)
{
  uint64_t version = 0;
  while (version == 0)
  {
    version = Random::generateNumberWithNBits<64, uint64_t>();
  }

  return version;
}

static inline void prodigyBuildPersistentSecretRecordKey(const char *baseKey, uint64_t version, String& key)
{
  key.assign(baseKey);
  key.append("#"_ctv);
  key.snprintf_add<"{itoa}"_ctv>(version);
}

static inline void prodigyClearPersistentSecretString(String& value)
{
  if (value.isInvariant())
  {
    value.reset();
    return;
  }

  Vault::secureClearString(value);
}

static inline void prodigyClearPersistentSecretBytes(uint8_t *bytes, size_t size)
{
  if (bytes == nullptr || size == 0)
  {
    return;
  }

  uint8_t volatile *cursor = bytes;
  while (size > 0)
  {
    *cursor++ = 0;
    size -= 1;
  }
}

static inline bool prodigyPersistentSecretBytesAreZero(const uint8_t *bytes, size_t size)
{
  for (size_t index = 0; index < size; index += 1)
  {
    if (bytes[index] != 0)
    {
      return false;
    }
  }

  return true;
}

static inline void prodigyClearPersistentSSHPrivateKey(Vault::SSHKeyPackage& package)
{
  prodigyClearPersistentSecretString(package.privateKeyOpenSSH);
}

class ProdigyPersistentStoredBootState {
public:

  uint64_t secretVersion = 0;
  ProdigyPersistentBootState state;
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentStoredBootState& record)
{
  serializer.value8b(record.secretVersion);
  serializer.object(record.state);
}

class ProdigyPersistentStoredBrainSnapshot {
public:

  uint64_t secretVersion = 0;
  ProdigyPersistentBrainSnapshot state;
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentStoredBrainSnapshot& record)
{
  serializer.value8b(record.secretVersion);
  serializer.object(record.state);
}

class ProdigyPersistentStoredLocalBrainState {
public:

  uint64_t secretVersion = 0;
  ProdigyPersistentLocalBrainState state;
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentStoredLocalBrainState& record)
{
  serializer.value8b(record.secretVersion);
  serializer.object(record.state);
}

class ProdigyPersistentBootStateSecrets {
public:

  String bootstrapSshPrivateKeyOpenSSH;
  String bootstrapSshHostPrivateKeyOpenSSH;

  bool empty(void) const
  {
    return bootstrapSshPrivateKeyOpenSSH.size() == 0 && bootstrapSshHostPrivateKeyOpenSSH.size() == 0;
  }

  void clear(void)
  {
    prodigyClearPersistentSecretString(bootstrapSshPrivateKeyOpenSSH);
    prodigyClearPersistentSecretString(bootstrapSshHostPrivateKeyOpenSSH);
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentBootStateSecrets& secrets)
{
  serializer.text1b(secrets.bootstrapSshPrivateKeyOpenSSH, UINT32_MAX);
  serializer.text1b(secrets.bootstrapSshHostPrivateKeyOpenSSH, UINT32_MAX);
}

class ProdigyPersistentApplicationTlsVaultFactorySecrets {
public:

  String rootKeyPem;
  String intermediateKeyPem;

  bool empty(void) const
  {
    return rootKeyPem.size() == 0 && intermediateKeyPem.size() == 0;
  }

  void clear(void)
  {
    prodigyClearPersistentSecretString(rootKeyPem);
    prodigyClearPersistentSecretString(intermediateKeyPem);
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentApplicationTlsVaultFactorySecrets& secrets)
{
  serializer.text1b(secrets.rootKeyPem, UINT32_MAX);
  serializer.text1b(secrets.intermediateKeyPem, UINT32_MAX);
}

class ProdigyPersistentApiCredentialSecret {
public:

  String name;
  String provider;
  uint64_t generation = 0;
  String material;

  void clear(void)
  {
    prodigyClearPersistentSecretString(material);
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentApiCredentialSecret& secret)
{
  serializer.text1b(secret.name, UINT32_MAX);
  serializer.text1b(secret.provider, UINT32_MAX);
  serializer.value8b(secret.generation);
  serializer.text1b(secret.material, UINT32_MAX);
}

class ProdigyPersistentApplicationApiCredentialSetSecrets {
public:

  Vector<ProdigyPersistentApiCredentialSecret> credentials;

  bool empty(void) const
  {
    return credentials.empty();
  }

  void clear(void)
  {
    for (auto& credential : credentials)
    {
      credential.clear();
    }

    credentials.clear();
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentApplicationApiCredentialSetSecrets& secrets)
{
  serializer.object(secrets.credentials);
}

class ProdigyPersistentTlsResumptionEpochSecret {
public:

  String registryKey;
  uint64_t generation = 0;
  uint8_t keyID[16] = {};
  uint8_t masterSecret[32] = {};

  void clear(void)
  {
    prodigyClearPersistentSecretBytes(masterSecret, sizeof(masterSecret));
  }
};

// The public descriptor supplies all identity fields.  This sidecar carries
// only the corresponding root, never an independent enrollment authority.
// It remains copyable for snapshot ownership; every copy wipes its root when
// destroyed, including temporary and vector-reallocated copies.
class ProdigyPersistentClusterPairEnrollmentRootSecret {
public:
  uint128_t pairUUID = 0;
  uint128_t localClusterUUID = 0;
  uint128_t peerClusterUUID = 0;
  uint128_t operationUUID = 0;
  uint64_t rootGeneration = 0;
  uint64_t agreedKeyEpoch = 0;
  uint64_t localAuthorityGeneration = 0;
  uint8_t root[ProdigyClusterPairEnrollmentRootBytes] = {};

  ~ProdigyPersistentClusterPairEnrollmentRootSecret()
  {
    OPENSSL_cleanse(root, sizeof(root));
  }

  bool matches(const ProdigyClusterPairEnrollment& enrollment) const
  {
    return pairUUID == enrollment.pairUUID &&
           localClusterUUID == enrollment.localClusterUUID &&
           peerClusterUUID == enrollment.peerClusterUUID &&
           operationUUID == enrollment.operationUUID &&
           rootGeneration == enrollment.rootGeneration &&
           agreedKeyEpoch == enrollment.agreedKeyEpoch &&
           localAuthorityGeneration == enrollment.localAuthorityGeneration;
  }

  bool rootIsZero(void) const
  {
    uint8_t aggregate = 0;
    for (uint8_t byte : root) aggregate |= byte;
    return aggregate == 0;
  }

  void clear(void)
  {
    prodigyClearPersistentSecretBytes(root, sizeof(root));
  }
};

// The transport authority root is private snapshot material.  The public
// ledger binds it through epoch, key epoch and the exact master-authority
// generation; it is never reconstructed from bootstrap defaults.
class ProdigyPersistentTransportCredentialAuthorityRootSecret {
public:
  ProdigyTransportCredentialAuthorityRoot root = {};

  void clear(void) { OPENSSL_cleanse(root.root, sizeof(root.root)); root = {}; }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentClusterPairEnrollmentRootSecret& secret)
{
  serializer.value16b(secret.pairUUID);
  serializer.value16b(secret.localClusterUUID);
  serializer.value16b(secret.peerClusterUUID);
  serializer.value16b(secret.operationUUID);
  serializer.value8b(secret.rootGeneration);
  serializer.value8b(secret.agreedKeyEpoch);
  serializer.value8b(secret.localAuthorityGeneration);
  for (uint8_t& byte : secret.root) serializer.value1b(byte);
}

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentTransportCredentialAuthorityRootSecret& secret)
{
  serializer.value8b(secret.root.authorityEpoch);
  serializer.value8b(secret.root.keyEpoch);
  serializer.value8b(secret.root.authorityGeneration);
  for (uint8_t& byte : secret.root.root) serializer.value1b(byte);
}

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentTlsResumptionEpochSecret& secret)
{
  serializer.text1b(secret.registryKey, UINT32_MAX);
  serializer.value8b(secret.generation);
  for (uint8_t& byte : secret.keyID)
  {
    serializer.value1b(byte);
  }
  for (uint8_t& byte : secret.masterSecret)
  {
    serializer.value1b(byte);
  }
}

class ProdigyPersistentPublicTlsCertificateSecret {
public:

  String identityName;
  uint64_t generation = 0;
  String keyPem;

  void clear(void)
  {
    prodigyClearPersistentSecretString(keyPem);
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentPublicTlsCertificateSecret& secret)
{
  serializer.text1b(secret.identityName, UINT32_MAX);
  serializer.value8b(secret.generation);
  serializer.text1b(secret.keyPem, UINT32_MAX);
}

class ProdigyPersistentPendingAddMachinesOperationSecrets {
public:

  uint64_t operationID = 0;
  String bootstrapSshPrivateKeyOpenSSH;
  String bootstrapSshHostPrivateKeyOpenSSH;

  bool empty(void) const
  {
    return bootstrapSshPrivateKeyOpenSSH.size() == 0 && bootstrapSshHostPrivateKeyOpenSSH.size() == 0;
  }

  void clear(void)
  {
    prodigyClearPersistentSecretString(bootstrapSshPrivateKeyOpenSSH);
    prodigyClearPersistentSecretString(bootstrapSshHostPrivateKeyOpenSSH);
  }
};

// Runtime plans include transport pairings and CID keys as well as credentials.
// Keep each complete runtime record private; the public placeholder retains
// only the stable machine/container identity used for one-to-one restoration.
class ProdigyPersistentContainerRuntimeStateSecrets {
public:

  uint128_t machineUUID = 0;
  uint128_t containerUUID = 0;
  BrainReplicatedContainerRuntimeState runtimeState;

  void clear(void)
  {
    runtimeState = {};
  }
};

// The retirement carrier is durable public authority state, but a pending
// intent's captured Neuron bootstrap includes its credential bundle.  Keep the
// immutable identity visible to bind the public descriptor to this existing
// snapshot-secret sidecar; keep only the replay payload private.
class ProdigyPersistentContainerRetirementBootstrapSecrets {
public:
  uint128_t containerUUID = 0;
  uint64_t deploymentID = 0;
  uint16_t applicationID = 0;
  uint128_t machineUUID = 0;
  uint64_t topologyOperationID = 0;
  uint32_t sourceEpoch = 0;
  uint32_t targetEpoch = 0;
  uint64_t intentGeneration = 0;
  String bootstrap;

  bool matches(const ProdigyContainerRetirementIntent& intent) const
  {
    ProdigyContainerRetirementIntent identity = {};
    identity.containerUUID = containerUUID;
    identity.deploymentID = deploymentID;
    identity.applicationID = applicationID;
    identity.machineUUID = machineUUID;
    identity.topologyOperationID = topologyOperationID;
    identity.sourceEpoch = sourceEpoch;
    identity.targetEpoch = targetEpoch;
    identity.intentGeneration = intentGeneration;
    return identity.sameIdentity(intent);
  }

  void clear(void)
  {
    prodigyClearPersistentSecretString(bootstrap);
  }
};

// Kept separate from the v1 sidecar so existing pending stateful snapshots
// retain their exact secret framing.  A v2 descriptor's operation binding is
// part of the bootstrap identity; omitting it would let a private replay blob
// be rebound to another paired migration.
class ProdigyPersistentContainerRetirementBootstrapSecretsV2 {
public:
  uint128_t containerUUID = 0;
  uint64_t deploymentID = 0;
  uint16_t applicationID = 0;
  uint128_t machineUUID = 0;
  uint64_t topologyOperationID = 0;
  uint32_t sourceEpoch = 0;
  uint32_t targetEpoch = 0;
  uint64_t intentGeneration = 0;
  ProdigyContainerRetirementKind kind = ProdigyContainerRetirementKind::statefulTopology;
  uint128_t pairedOperationID = 0;
  uint128_t pairedSourceClusterUUID = 0;
  uint128_t pairedTargetClusterUUID = 0;
  uint64_t pairedTargetDeploymentID = 0;
  String bootstrap;

  bool matches(const ProdigyContainerRetirementIntent& intent) const
  {
    return containerUUID == intent.containerUUID && deploymentID == intent.deploymentID &&
           applicationID == intent.applicationID && machineUUID == intent.machineUUID &&
           topologyOperationID == intent.topologyOperationID && sourceEpoch == intent.sourceEpoch &&
           targetEpoch == intent.targetEpoch && intentGeneration == intent.intentGeneration &&
           kind == intent.kind && pairedOperationID == intent.pairedOperationID &&
           pairedSourceClusterUUID == intent.pairedSourceClusterUUID &&
           pairedTargetClusterUUID == intent.pairedTargetClusterUUID &&
           pairedTargetDeploymentID == intent.pairedTargetDeploymentID;
  }

  void clear(void)
  {
    prodigyClearPersistentSecretString(bootstrap);
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentContainerRetirementBootstrapSecrets& secrets)
{
  serializer.value16b(secrets.containerUUID);
  serializer.value8b(secrets.deploymentID);
  serializer.value2b(secrets.applicationID);
  serializer.value16b(secrets.machineUUID);
  serializer.value8b(secrets.topologyOperationID);
  serializer.value4b(secrets.sourceEpoch);
  serializer.value4b(secrets.targetEpoch);
  serializer.value8b(secrets.intentGeneration);
  serializer.text1b(secrets.bootstrap, prodigyContainerRetirementJournalMaximumBootstrapBytes);
}

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentContainerRetirementBootstrapSecretsV2& secrets)
{
  serializer.value16b(secrets.containerUUID);
  serializer.value8b(secrets.deploymentID);
  serializer.value2b(secrets.applicationID);
  serializer.value16b(secrets.machineUUID);
  serializer.value8b(secrets.topologyOperationID);
  serializer.value4b(secrets.sourceEpoch);
  serializer.value4b(secrets.targetEpoch);
  serializer.value8b(secrets.intentGeneration);
  serializer.value1b(secrets.kind);
  serializer.value16b(secrets.pairedOperationID);
  serializer.value16b(secrets.pairedSourceClusterUUID);
  serializer.value16b(secrets.pairedTargetClusterUUID);
  serializer.value8b(secrets.pairedTargetDeploymentID);
  serializer.text1b(secrets.bootstrap, prodigyContainerRetirementJournalMaximumBootstrapBytes);
}

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentContainerRuntimeStateSecrets& secrets)
{
  serializer.value16b(secrets.machineUUID);
  serializer.value16b(secrets.containerUUID);
  serializer.object(secrets.runtimeState);
}

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentPendingAddMachinesOperationSecrets& secrets)
{
  serializer.value8b(secrets.operationID);
  serializer.text1b(secrets.bootstrapSshPrivateKeyOpenSSH, UINT32_MAX);
  serializer.text1b(secrets.bootstrapSshHostPrivateKeyOpenSSH, UINT32_MAX);
}

class ProdigyPersistentBrainSnapshotSecrets {
public:

  String bootstrapSshPrivateKeyOpenSSH;
  String bootstrapSshHostPrivateKeyOpenSSH;
  String dnsCredentialMaterial;
  bytell_hash_map<uint16_t, ProdigyPersistentApplicationTlsVaultFactorySecrets> tlsVaultFactorySecretsByApp;
  bytell_hash_map<uint16_t, ProdigyPersistentApplicationApiCredentialSetSecrets> apiCredentialSecretsByApp;
  Vector<ProdigyPersistentTlsResumptionEpochSecret> tlsResumptionEpochSecrets;
  Vector<ProdigyPersistentPublicTlsCertificateSecret> publicTlsCertificateSecrets;
  String transportTLSAuthorityClusterRootKeyPem;
  String mothershipTunnelGatewayServerKeyPem;
  Vector<ProdigyPersistentPendingAddMachinesOperationSecrets> pendingAddMachinesOperationSecrets;
  // Container bootstraps contain credential bundles and transport identities.
  // Keep the exact replay payload in the existing private snapshot sidecar.
  Vector<String> localContainerBootstraps;
  Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness> machineRecoveryWitnesses;
  Vector<ProdigyPersistentContainerRuntimeStateSecrets> containerRuntimeStateSecrets;
  // Desired serving plans use the same private record shape as observed
  // runtime plans, but carry a distinct public descriptor vector.
  Vector<ProdigyPersistentContainerRuntimeStateSecrets> servingRuntimeStateSecrets;
  Vector<ProdigyPersistentContainerRetirementBootstrapSecrets> containerRetirementBootstrapSecrets;
  Vector<ProdigyPersistentContainerRetirementBootstrapSecretsV2> containerRetirementBootstrapSecretsV2;
  Vector<ProdigyPersistentClusterPairEnrollmentRootSecret> clusterPairEnrollmentRootSecrets;
  Vector<ProdigyPersistentTransportCredentialAuthorityRootSecret> transportCredentialAuthorityRootSecrets;

  bool empty(void) const
  {
    return bootstrapSshPrivateKeyOpenSSH.size() == 0 && bootstrapSshHostPrivateKeyOpenSSH.size() == 0 && dnsCredentialMaterial.size() == 0 && tlsVaultFactorySecretsByApp.empty() && apiCredentialSecretsByApp.empty() && tlsResumptionEpochSecrets.empty() && publicTlsCertificateSecrets.empty() && transportTLSAuthorityClusterRootKeyPem.size() == 0 && mothershipTunnelGatewayServerKeyPem.size() == 0 && pendingAddMachinesOperationSecrets.empty() && localContainerBootstraps.empty() && machineRecoveryWitnesses.empty() && containerRuntimeStateSecrets.empty() && servingRuntimeStateSecrets.empty() && containerRetirementBootstrapSecrets.empty() && containerRetirementBootstrapSecretsV2.empty() && clusterPairEnrollmentRootSecrets.empty() && transportCredentialAuthorityRootSecrets.empty();
  }

  void clear(void)
  {
    prodigyClearPersistentSecretString(bootstrapSshPrivateKeyOpenSSH);
    prodigyClearPersistentSecretString(bootstrapSshHostPrivateKeyOpenSSH);
    prodigyClearPersistentSecretString(dnsCredentialMaterial);
    prodigyClearPersistentSecretString(transportTLSAuthorityClusterRootKeyPem);
    prodigyClearPersistentSecretString(mothershipTunnelGatewayServerKeyPem);

    for (auto& [applicationID, factorySecrets] : tlsVaultFactorySecretsByApp)
    {
      (void)applicationID;
      factorySecrets.clear();
    }

    for (auto& [applicationID, credentialSecrets] : apiCredentialSecretsByApp)
    {
      (void)applicationID;
      credentialSecrets.clear();
    }

    for (auto& epochSecret : tlsResumptionEpochSecrets)
    {
      epochSecret.clear();
    }

    for (auto& certificateSecret : publicTlsCertificateSecrets)
    {
      certificateSecret.clear();
    }

    for (auto& operationSecrets : pendingAddMachinesOperationSecrets)
    {
      operationSecrets.clear();
    }
    tlsVaultFactorySecretsByApp.clear();
    apiCredentialSecretsByApp.clear();
    tlsResumptionEpochSecrets.clear();
    publicTlsCertificateSecrets.clear();
    pendingAddMachinesOperationSecrets.clear();
    for (String& bootstrap : localContainerBootstraps)
    {
      prodigyClearPersistentSecretString(bootstrap);
    }
    localContainerBootstraps.clear();
    for (auto& witness : machineRecoveryWitnesses)
    {
      for (String& bootstrap : witness.containerBootstraps)
      {
        prodigyClearPersistentSecretString(bootstrap);
      }
      witness.containerBootstraps.clear();
    }
    machineRecoveryWitnesses.clear();
    for (auto& runtimeStateSecrets : containerRuntimeStateSecrets)
    {
      runtimeStateSecrets.clear();
    }
    containerRuntimeStateSecrets.clear();
    for (auto& runtimeStateSecrets : servingRuntimeStateSecrets)
    {
      runtimeStateSecrets.clear();
    }
    servingRuntimeStateSecrets.clear();
    for (auto& retirementSecrets : containerRetirementBootstrapSecrets)
    {
      retirementSecrets.clear();
    }
    containerRetirementBootstrapSecrets.clear();
    for (auto& retirementSecrets : containerRetirementBootstrapSecretsV2)
    {
      retirementSecrets.clear();
    }
    containerRetirementBootstrapSecretsV2.clear();
    for (auto& enrollmentSecret : clusterPairEnrollmentRootSecrets)
    {
      enrollmentSecret.clear();
    }
    clusterPairEnrollmentRootSecrets.clear();
    for (auto& authorityRoot : transportCredentialAuthorityRootSecrets) authorityRoot.clear();
    transportCredentialAuthorityRootSecrets.clear();
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentBrainSnapshotSecrets& secrets)
{
  serializer.text1b(secrets.bootstrapSshPrivateKeyOpenSSH, UINT32_MAX);
  serializer.text1b(secrets.bootstrapSshHostPrivateKeyOpenSSH, UINT32_MAX);
  serializer.text1b(secrets.dnsCredentialMaterial, UINT32_MAX);
  serializer.object(secrets.tlsVaultFactorySecretsByApp);
  serializer.object(secrets.apiCredentialSecretsByApp);
  serializer.object(secrets.tlsResumptionEpochSecrets);
  serializer.object(secrets.publicTlsCertificateSecrets);
  serializer.text1b(secrets.transportTLSAuthorityClusterRootKeyPem, UINT32_MAX);
  serializer.text1b(secrets.mothershipTunnelGatewayServerKeyPem, UINT32_MAX);
  serializer.object(secrets.pendingAddMachinesOperationSecrets);
  // This sidecar is a top-level record. Older records end at the preceding
  // field; their bootstraps remain in the public snapshot until the next save.
  using Serializer = std::remove_cv_t<std::remove_reference_t<S>>;
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    serializer.object(secrets.localContainerBootstraps);
  }
  else if (serializer.adapter().isCompletedSuccessfully() == false)
  {
    serializer.object(secrets.localContainerBootstraps);
  }
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    serializer.object(secrets.machineRecoveryWitnesses);
  }
  else if (serializer.adapter().isCompletedSuccessfully() == false)
  {
    serializer.object(secrets.machineRecoveryWitnesses);
  }
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    serializer.object(secrets.containerRuntimeStateSecrets);
  }
  else if (serializer.adapter().isCompletedSuccessfully() == false)
  {
    serializer.object(secrets.containerRuntimeStateSecrets);
  }
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    // Preserve the established sidecar bytes until a new feature is active.
    if (!secrets.servingRuntimeStateSecrets.empty() || !secrets.containerRetirementBootstrapSecrets.empty() ||
        !secrets.containerRetirementBootstrapSecretsV2.empty() || !secrets.clusterPairEnrollmentRootSecrets.empty() || !secrets.transportCredentialAuthorityRootSecrets.empty())
      serializer.object(secrets.servingRuntimeStateSecrets);
  }
  else if (serializer.adapter().isCompletedSuccessfully() == false)
  {
    serializer.object(secrets.servingRuntimeStateSecrets);
  }
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    if (!secrets.servingRuntimeStateSecrets.empty() || !secrets.containerRetirementBootstrapSecrets.empty() ||
        !secrets.containerRetirementBootstrapSecretsV2.empty() || !secrets.clusterPairEnrollmentRootSecrets.empty() || !secrets.transportCredentialAuthorityRootSecrets.empty())
      serializer.object(secrets.containerRetirementBootstrapSecrets);
  }
  else if (serializer.adapter().isCompletedSuccessfully() == false)
  {
    serializer.object(secrets.containerRetirementBootstrapSecrets);
  }
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    if (!secrets.containerRetirementBootstrapSecretsV2.empty() || !secrets.clusterPairEnrollmentRootSecrets.empty() || !secrets.transportCredentialAuthorityRootSecrets.empty())
      serializer.object(secrets.containerRetirementBootstrapSecretsV2);
  }
  else if (serializer.adapter().isCompletedSuccessfully() == false)
  {
    serializer.object(secrets.containerRetirementBootstrapSecretsV2);
  }
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    if (!secrets.clusterPairEnrollmentRootSecrets.empty() || !secrets.transportCredentialAuthorityRootSecrets.empty())
      serializer.container(secrets.clusterPairEnrollmentRootSecrets, ProdigyClusterPairEnrollmentMaximumRecords,
        [](auto& nested, ProdigyPersistentClusterPairEnrollmentRootSecret& secret) { nested.object(secret); });
  }
  else if (serializer.adapter().isCompletedSuccessfully() == false)
  {
    serializer.container(secrets.clusterPairEnrollmentRootSecrets, ProdigyClusterPairEnrollmentMaximumRecords,
        [](auto& nested, ProdigyPersistentClusterPairEnrollmentRootSecret& secret) { nested.object(secret); });
  }
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    if (!secrets.transportCredentialAuthorityRootSecrets.empty())
      serializer.container(secrets.transportCredentialAuthorityRootSecrets, 1,
        [](auto& nested, ProdigyPersistentTransportCredentialAuthorityRootSecret& secret) { nested.object(secret); });
  }
  else if (serializer.adapter().isCompletedSuccessfully() == false)
  {
    serializer.container(secrets.transportCredentialAuthorityRootSecrets, 1,
      [](auto& nested, ProdigyPersistentTransportCredentialAuthorityRootSecret& secret) { nested.object(secret); });
  }
}

class ProdigyPersistentLocalBrainStateSecrets {
public:

  String clusterRootKeyPem;
  String localKeyPem;
  ProdigyTransportNodeCredential transportNodeCredential;
  ProdigyTransportCredentialAuthorityRoot transportAuthorityRoot;

  bool empty(void) const
  {
    return clusterRootKeyPem.size() == 0 && localKeyPem.size() == 0 && transportNodeCredential.nodeUUID == 0 && transportAuthorityRoot.authorityEpoch == 0;
  }

  void clear(void)
  {
    prodigyClearPersistentSecretString(clusterRootKeyPem);
    prodigyClearPersistentSecretString(localKeyPem);
    OPENSSL_cleanse(transportNodeCredential.secret, sizeof(transportNodeCredential.secret));
    transportNodeCredential = {};
    transportAuthorityRoot = {};
  }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentLocalBrainStateSecrets& secrets)
{
  serializer.text1b(secrets.clusterRootKeyPem, UINT32_MAX);
  serializer.text1b(secrets.localKeyPem, UINT32_MAX);
  using Serializer = std::remove_cvref_t<S>;
  if constexpr (ProdigyPersistentSerializerIsWriter<Serializer>::value)
  {
    if (secrets.transportNodeCredential.nodeUUID != 0)
    {
      serializer.object(secrets.transportNodeCredential);
      serializer.object(secrets.transportAuthorityRoot);
    }
  }
  else if (!serializer.adapter().isCompletedSuccessfully())
  {
    serializer.object(secrets.transportNodeCredential);
    serializer.object(secrets.transportAuthorityRoot);
  }
}

static inline void prodigyExtractPersistentBootStateSecrets(
    const ProdigyPersistentBootState& state,
    ProdigyPersistentBootState& publicState,
    ProdigyPersistentBootStateSecrets& secrets)
{
  publicState = state;
  secrets.clear();

  secrets.bootstrapSshPrivateKeyOpenSSH = state.bootstrapSshKeyPackage.privateKeyOpenSSH;
  secrets.bootstrapSshHostPrivateKeyOpenSSH = state.bootstrapSshHostKeyPackage.privateKeyOpenSSH;
  prodigyClearPersistentSSHPrivateKey(publicState.bootstrapSshKeyPackage);
  prodigyClearPersistentSSHPrivateKey(publicState.bootstrapSshHostKeyPackage);
}

static inline void prodigyApplyPersistentBootStateSecrets(
    ProdigyPersistentBootState& state,
    const ProdigyPersistentBootStateSecrets& secrets)
{
  state.bootstrapSshKeyPackage.privateKeyOpenSSH = secrets.bootstrapSshPrivateKeyOpenSSH;
  state.bootstrapSshHostKeyPackage.privateKeyOpenSSH = secrets.bootstrapSshHostPrivateKeyOpenSSH;
}

static bool prodigyParsePersistentContainerRetirementDescriptor(
    const TaskExecutionRecord& carrier, ProdigyContainerRetirementJournal& journal)
{
  journal = {};
  if (!prodigyContainerRetirementJournalCarrier(carrier) ||
      carrier.fingerprint.size() > prodigyContainerRetirementJournalMaximumPayloadBytes ||
      BitseryEngine::deserializeSafe(carrier.fingerprint, journal) == false ||
      !prodigyContainerRetirementJournalVersionSupported(
          journal.version, ProdigyContainerRetirementJournal::currentVersion) || journal.intents.empty() ||
      journal.intents.size() > prodigyContainerRetirementJournalMaximumEntries)
  {
    return false;
  }
  // Public descriptors deliberately omit every bootstrap.  Validate the
  // complete journal (including v3 paired fences/cohorts) through the single
  // authoritative validator after converting that omission to terminal form.
  // This preserves identity checks without accepting a malformed public fence.
  ProdigyContainerRetirementJournal bootstrapOmittedJournal = journal;
  for (auto& intent : bootstrapOmittedJournal.intents)
  {
    if (!intent.bootstrap.empty()) return false;
    intent.killAcked = true;
  }
  return prodigyValidateContainerRetirementJournal(bootstrapOmittedJournal);
}

static bool prodigyPersistentWriteContainerRetirementDescriptor(
    TaskExecutionRecord& carrier, ProdigyContainerRetirementJournal& journal)
{
  String encoded = {};
  BitseryEngine::serialize(encoded, journal);
  if (encoded.size() > prodigyContainerRetirementJournalMaximumPayloadBytes)
  {
    return false;
  }
  carrier.fingerprint = std::move(encoded);
  return true;
}

// This persistence owner validates only descriptor/sidecar integrity. It does
// not make an enrollment authoritative or usable for credential issuance.
static bool prodigyValidatePersistentClusterPairEnrollmentDescriptors(
    const Vector<ProdigyClusterPairEnrollment>& enrollments,
    uint128_t localClusterUUID,
    uint64_t runtimeAuthorityGeneration,
    bool requireHydratedRoots,
    bool requireRevokedOnly,
    String *failure = nullptr)
{
  if (enrollments.size() > ProdigyClusterPairEnrollmentMaximumRecords)
  {
    if (failure) failure->assign("persistent brain snapshot has too many cluster pair enrollments"_ctv);
    return false;
  }
  for (uint32_t left = 0; left < enrollments.size(); ++left)
  {
    const ProdigyClusterPairEnrollment& enrollment = enrollments[left];
    if (!prodigyClusterPairEnrollmentDescriptorValid(enrollment) ||
        enrollment.localClusterUUID != localClusterUUID ||
        enrollment.localAuthorityGeneration > runtimeAuthorityGeneration ||
        (requireRevokedOnly && enrollment.state != ProdigyClusterPairEnrollmentState::revoked) ||
        (requireHydratedRoots
             ? (enrollment.state == ProdigyClusterPairEnrollmentState::revoked
                    ? !prodigyClusterPairEnrollmentRootIsZero(enrollment)
                    : prodigyClusterPairEnrollmentRootIsZero(enrollment))
             : !prodigyClusterPairEnrollmentRootIsZero(enrollment)))
    {
      if (failure) failure->assign("persistent brain snapshot cluster pair enrollment is malformed"_ctv);
      return false;
    }
    for (uint32_t right = 0; right < left; ++right)
    {
      if (enrollment.pairUUID == enrollments[right].pairUUID ||
          enrollment.operationUUID == enrollments[right].operationUUID)
      {
        if (failure) failure->assign("persistent brain snapshot duplicate cluster pair enrollment identity"_ctv);
        return false;
      }
    }
  }
  // Pending operations are the failover fence. Their immutable electorate is
  // validated before any leader can re-drive delivery.
  return true;
}

static bool prodigyValidatePersistentTransportCredentialEnrollmentOperations(
    const Vector<ProdigyTransportCredentialEnrollmentOperation>& operations,
    const Vector<ProdigyTransportCredentialEnrollment>& enrollments,
    uint64_t runtimeAuthorityGeneration,
    String *failure = nullptr)
{
  if (operations.size() > ProdigyTransportCredentialEnrollmentMaximumRecords) return false;
  const ProdigyTransportCredentialEnrollmentOperation *unfinishedCohort = nullptr;
  for (uint32_t index = 0; index < operations.size(); ++index)
  {
    const auto& operation = operations[index];
    if (!operation.valid() || operation.transitionGeneration > runtimeAuthorityGeneration)
    { if (failure) failure->assign("persistent transport credential operation is malformed"_ctv); return false; }
    bool found = false;
    for (const auto& enrollment : enrollments) found |= enrollment == operation.enrollment;
    if (!found) { if (failure) failure->assign("persistent transport credential operation has no ledger enrollment"_ctv); return false; }
    if (operation.phase == ProdigyTransportCredentialEnrollmentOperationPhase::pending ||
        operation.phase == ProdigyTransportCredentialEnrollmentOperationPhase::active)
    {
      if ((unfinishedCohort != nullptr &&
           (!prodigyTransportCredentialSameCohort(unfinishedCohort->enrollment, operation.enrollment) ||
            unfinishedCohort->pinnedMasterAuthorityEpoch != operation.pinnedMasterAuthorityEpoch)) ||
          !prodigyTransportCredentialElectorateMatches(operation.enrollment, operation.electorate, enrollments))
      { if (failure) failure->assign("persistent transport credential operation electorate is inconsistent"_ctv); return false; }
      unfinishedCohort = &operation;
    }
    const ProdigyTransportCredentialEnrollmentOperation *cohort = nullptr;
    for (uint32_t prior = 0; prior < index; ++prior)
    {
      if (operations[prior].enrollment.operationUUID == operation.enrollment.operationUUID)
      { if (failure) failure->assign("persistent duplicate transport credential operation"_ctv); return false; }
      if (cohort == nullptr && prodigyTransportCredentialSameCohort(operations[prior].enrollment, operation.enrollment))
        cohort = &operations[prior];
    }
    if (cohort != nullptr)
    {
      auto voters = operation.electorate;
      auto cohortVoters = cohort->electorate;
      std::sort(voters.begin(), voters.end());
      std::sort(cohortVoters.begin(), cohortVoters.end());
      const bool pending = operation.phase == ProdigyTransportCredentialEnrollmentOperationPhase::pending;
      const bool cohortPending = cohort->phase == ProdigyTransportCredentialEnrollmentOperationPhase::pending;
      if (voters != cohortVoters || pending != cohortPending)
      { if (failure) failure->assign("persistent transport credential cohort is partially activated or has different voters"_ctv); return false; }
    }
    else
    {
      // Terminal history cannot reconstruct the old active set after a voter
      // is revoked, and never authorizes another release. Its recorded voters
      // must nevertheless be real, older Brain enrollments. Unfinished
      // operations above require the exact current pre-cohort electorate.
      Vector<uint128_t> knownVoters;
      for (const auto& enrollment : enrollments)
        if (enrollment.clusterUUID == operation.enrollment.clusterUUID &&
            enrollment.authorityEpoch == operation.enrollment.authorityEpoch &&
            enrollment.keyEpoch == operation.enrollment.keyEpoch &&
            enrollment.authorityGeneration < operation.enrollment.authorityGeneration &&
            enrollment.role == ProdigyTransportCredentialNodeRole::brain &&
            (enrollment.state == ProdigyTransportCredentialEnrollmentState::active ||
             enrollment.state == ProdigyTransportCredentialEnrollmentState::revoked))
          knownVoters.push_back(enrollment.nodeUUID);
      std::sort(knownVoters.begin(), knownVoters.end());
      for (uint128_t voter : operation.electorate)
        if (!std::binary_search(knownVoters.begin(), knownVoters.end(), voter))
        { if (failure) failure->assign("persistent transport credential cohort has an unknown voter"_ctv); return false; }
    }
  }
  // Initial provisioning has no enrollment operations. Once a later cohort
  // has an operation, however, every ledger member of that cohort must have
  // its matching operation. The addMachines owner additionally checks the
  // journal's exact role set, including targets missing from both vectors.
  for (const auto& enrollment : enrollments)
  {
    bool hasCohort = false, hasOperation = false;
    for (const auto& operation : operations)
    {
      hasCohort |= prodigyTransportCredentialSameCohort(enrollment, operation.enrollment);
      hasOperation |= enrollment == operation.enrollment;
    }
    if (hasCohort && !hasOperation)
    { if (failure) failure->assign("persistent transport credential cohort has an unjournaled enrollment"_ctv); return false; }
  }
  return true;
}

static bool prodigyValidatePersistentTransportCredentialEnrollments(
    const Vector<ProdigyTransportCredentialEnrollment>& enrollments,
    const ProdigyTransportCredentialAuthorityRoot *root,
    uint128_t localClusterUUID,
    uint64_t runtimeAuthorityGeneration,
    String *failure = nullptr)
{
  if (enrollments.size() > ProdigyTransportCredentialEnrollmentMaximumRecords)
  {
    if (failure) failure->assign("persistent brain snapshot has too many transport credential enrollments"_ctv);
    return false;
  }
  if (enrollments.empty())
  {
    if (root != nullptr && (root->authorityEpoch != 0 || root->keyEpoch != 0 || root->authorityGeneration != 0 ||
        std::any_of(std::begin(root->root), std::end(root->root), [](uint8_t value) { return value != 0; })))
    {
      if (failure) failure->assign("persistent brain snapshot transport authority root is orphaned"_ctv);
      return false;
    }
    return true;
  }
  if (root == nullptr || !root->valid() || root->authorityGeneration > runtimeAuthorityGeneration)
  {
    if (failure) failure->assign("persistent brain snapshot transport credential ledger has no current private authority root"_ctv);
    return false;
  }
  for (uint32_t left = 0; left < enrollments.size(); ++left)
  {
    const auto& enrollment = enrollments[left];
    if (!enrollment.valid() || enrollment.clusterUUID != localClusterUUID ||
        enrollment.authorityGeneration > runtimeAuthorityGeneration ||
        enrollment.authorityEpoch != root->authorityEpoch || enrollment.keyEpoch != root->keyEpoch ||
        enrollment.authorityGeneration < root->authorityGeneration)
    {
      if (failure) failure->assign("persistent brain snapshot transport credential enrollment is malformed or stale"_ctv);
      return false;
    }
    for (uint32_t right = 0; right < left; ++right)
    {
      if (enrollment.operationUUID == enrollments[right].operationUUID ||
          (enrollment.nodeUUID == enrollments[right].nodeUUID && enrollment.role == enrollments[right].role &&
           enrollment.state != ProdigyTransportCredentialEnrollmentState::revoked &&
           enrollments[right].state != ProdigyTransportCredentialEnrollmentState::revoked))
      {
        if (failure) failure->assign("persistent brain snapshot duplicate transport credential enrollment identity"_ctv);
        return false;
      }
    }
  }
  return true;
}

static inline bool prodigyExtractPersistentBrainSnapshotSecrets(
    ProdigyPersistentBrainSnapshot snapshot,
    ProdigyPersistentBrainSnapshot& publicSnapshot,
    ProdigyPersistentBrainSnapshotSecrets& secrets,
    String *failure = nullptr)
{
  publicSnapshot = {};
  secrets.clear();
  if (failure) failure->clear();
  if (!prodigyValidatePersistentClusterPairEnrollmentDescriptors(
          snapshot.masterAuthority.runtimeState.clusterPairEnrollments,
          snapshot.brainConfig.clusterUUID,
          snapshot.masterAuthority.runtimeState.generation,
          true,
          false,
          failure))
  {
    return false;
  }
  if (!prodigyValidatePersistentTransportCredentialEnrollments(
          snapshot.masterAuthority.runtimeState.transportCredentialEnrollments,
          &snapshot.masterAuthority.runtimeState.transportCredentialAuthorityRoot,
          snapshot.brainConfig.clusterUUID,
          snapshot.masterAuthority.runtimeState.generation,
          failure)) return false;
  if (!prodigyValidatePersistentTransportCredentialEnrollmentOperations(
          snapshot.masterAuthority.runtimeState.transportCredentialEnrollmentOperations,
          snapshot.masterAuthority.runtimeState.transportCredentialEnrollments,
          snapshot.masterAuthority.runtimeState.generation, failure)) return false;
  if (!prodigyValidateStatefulServingAuthorities(snapshot.masterAuthority.runtimeState.statefulServingAuthorities,
        snapshot.masterAuthority.servingRuntimeStates, snapshot.masterAuthority.runtimeState.generation))
  {
    if (failure) failure->assign("persistent brain snapshot serving authority is incomplete or invalid"_ctv);
    return false;
  }
  publicSnapshot = std::move(snapshot);

  if (publicSnapshot.masterAuthority.runtimeState.transportCredentialAuthorityRoot.valid())
  {
    ProdigyPersistentTransportCredentialAuthorityRootSecret authoritySecret = {};
    authoritySecret.root = publicSnapshot.masterAuthority.runtimeState.transportCredentialAuthorityRoot;
    secrets.transportCredentialAuthorityRootSecrets.push_back(authoritySecret);
    authoritySecret.clear();
  }
  publicSnapshot.masterAuthority.runtimeState.transportCredentialAuthorityRoot = {};

  auto& enrollments = publicSnapshot.masterAuthority.runtimeState.clusterPairEnrollments;
  for (ProdigyClusterPairEnrollment& enrollment : enrollments)
  {
    if (enrollment.state != ProdigyClusterPairEnrollmentState::revoked)
    {
      ProdigyPersistentClusterPairEnrollmentRootSecret rootSecret = {};
      rootSecret.pairUUID = enrollment.pairUUID;
      rootSecret.localClusterUUID = enrollment.localClusterUUID;
      rootSecret.peerClusterUUID = enrollment.peerClusterUUID;
      rootSecret.operationUUID = enrollment.operationUUID;
      rootSecret.rootGeneration = enrollment.rootGeneration;
      rootSecret.agreedKeyEpoch = enrollment.agreedKeyEpoch;
      rootSecret.localAuthorityGeneration = enrollment.localAuthorityGeneration;
      std::memcpy(rootSecret.root, enrollment.root, sizeof(rootSecret.root));
      secrets.clusterPairEnrollmentRootSecrets.push_back(rootSecret);
      rootSecret.clear();
    }
    prodigyClearPersistentSecretBytes(enrollment.root, sizeof(enrollment.root));
  }

  secrets.localContainerBootstraps =
      std::move(publicSnapshot.masterAuthority.runtimeState.updateSelf.localContainerBootstraps);
  publicSnapshot.masterAuthority.runtimeState.updateSelf.localContainerBootstraps.clear();
  secrets.machineRecoveryWitnesses =
      std::move(publicSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses);
  publicSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.clear();

  for (BrainReplicatedContainerRuntimeState& runtimeState : publicSnapshot.masterAuthority.containerRuntimeStates)
  {
    ProdigyPersistentContainerRuntimeStateSecrets runtimeStateSecrets = {};
    runtimeStateSecrets.machineUUID = runtimeState.machineUUID;
    runtimeStateSecrets.containerUUID = runtimeState.plan.uuid;
    runtimeStateSecrets.runtimeState = std::move(runtimeState);
    runtimeState = {};
    runtimeState.machineUUID = runtimeStateSecrets.machineUUID;
    runtimeState.plan.uuid = runtimeStateSecrets.containerUUID;
    secrets.containerRuntimeStateSecrets.push_back(std::move(runtimeStateSecrets));
  }

  for (BrainReplicatedContainerRuntimeState& runtimeState : publicSnapshot.masterAuthority.servingRuntimeStates)
  {
    if (runtimeState.machineUUID == 0 || runtimeState.plan.uuid == 0 ||
        runtimeState.plan.config.applicationID == 0 || runtimeState.plan.config.deploymentID() == 0)
    {
      if (failure) failure->assign("persistent brain snapshot serving runtime descriptor is invalid"_ctv);
      return false;
    }

    ProdigyPersistentContainerRuntimeStateSecrets runtimeStateSecrets = {};
    runtimeStateSecrets.machineUUID = runtimeState.machineUUID;
    runtimeStateSecrets.containerUUID = runtimeState.plan.uuid;
    runtimeStateSecrets.runtimeState = std::move(runtimeState);
    runtimeState = {};
    runtimeState.machineUUID = runtimeStateSecrets.machineUUID;
    runtimeState.plan.uuid = runtimeStateSecrets.containerUUID;
    runtimeState.plan.config.applicationID = runtimeStateSecrets.runtimeState.plan.config.applicationID;
    runtimeState.plan.config.versionID = runtimeStateSecrets.runtimeState.plan.config.versionID;
    runtimeState.plan.shardGroup = runtimeStateSecrets.runtimeState.plan.shardGroup;
    secrets.servingRuntimeStateSecrets.push_back(std::move(runtimeStateSecrets));
  }

  secrets.bootstrapSshPrivateKeyOpenSSH = publicSnapshot.brainConfig.bootstrapSshKeyPackage.privateKeyOpenSSH;
  secrets.bootstrapSshHostPrivateKeyOpenSSH = publicSnapshot.brainConfig.bootstrapSshHostKeyPackage.privateKeyOpenSSH;
  secrets.dnsCredentialMaterial = publicSnapshot.brainConfig.dnsCredential.material;
  prodigyClearPersistentSSHPrivateKey(publicSnapshot.brainConfig.bootstrapSshKeyPackage);
  prodigyClearPersistentSSHPrivateKey(publicSnapshot.brainConfig.bootstrapSshHostKeyPackage);
  prodigyClearPersistentSecretString(publicSnapshot.brainConfig.dnsCredential.material);

  for (auto& [applicationID, factory] : publicSnapshot.masterAuthority.tlsVaultFactoriesByApp)
  {
    ProdigyPersistentApplicationTlsVaultFactorySecrets factorySecrets = {};
    factorySecrets.rootKeyPem = factory.rootKeyPem;
    factorySecrets.intermediateKeyPem = factory.intermediateKeyPem;

    if (factorySecrets.empty() == false)
    {
      secrets.tlsVaultFactorySecretsByApp.insert_or_assign(applicationID, factorySecrets);
    }

    prodigyClearPersistentSecretString(factory.rootKeyPem);
    prodigyClearPersistentSecretString(factory.intermediateKeyPem);
  }

  for (auto& [applicationID, set] : publicSnapshot.masterAuthority.apiCredentialSetsByApp)
  {
    ProdigyPersistentApplicationApiCredentialSetSecrets setSecrets = {};

    for (auto& credential : set.credentials)
    {
      if (credential.material.size() > 0)
      {
        ProdigyPersistentApiCredentialSecret credentialSecret = {};
        credentialSecret.name = credential.name;
        credentialSecret.provider = credential.provider;
        credentialSecret.generation = credential.generation;
        credentialSecret.material = credential.material;
        setSecrets.credentials.push_back(credentialSecret);
      }

      prodigyClearPersistentSecretString(credential.material);
    }

    if (setSecrets.empty() == false)
    {
      secrets.apiCredentialSecretsByApp.insert_or_assign(applicationID, setSecrets);
    }
  }

  for (auto& [registryKey, snapshot] : publicSnapshot.masterAuthority.runtimeState.tlsResumptionSnapshotsByWormhole)
  {
    for (TlsResumptionKeyEpoch& epoch : snapshot.keyRing)
    {
      if (prodigyPersistentSecretBytesAreZero(epoch.masterSecret, sizeof(epoch.masterSecret)) == false)
      {
        ProdigyPersistentTlsResumptionEpochSecret epochSecret = {};
        epochSecret.registryKey = registryKey;
        epochSecret.generation = epoch.generation;
        std::memcpy(epochSecret.keyID, epoch.keyID, sizeof(epochSecret.keyID));
        std::memcpy(epochSecret.masterSecret, epoch.masterSecret, sizeof(epochSecret.masterSecret));
        secrets.tlsResumptionEpochSecrets.push_back(epochSecret);
      }

      prodigyClearPersistentSecretBytes(epoch.masterSecret, sizeof(epoch.masterSecret));
    }
  }

  for (PublicTlsCertificateState& certificate : publicSnapshot.masterAuthority.runtimeState.publicTlsCertificates)
  {
    if (certificate.identity.keyPem.size() > 0)
    {
      ProdigyPersistentPublicTlsCertificateSecret certificateSecret = {};
      certificateSecret.identityName = certificate.identity.name;
      certificateSecret.generation = certificate.identity.generation;
      certificateSecret.keyPem = certificate.identity.keyPem;
      secrets.publicTlsCertificateSecrets.push_back(certificateSecret);
    }

    prodigyClearPersistentSecretString(certificate.identity.keyPem);
  }

  secrets.transportTLSAuthorityClusterRootKeyPem = publicSnapshot.masterAuthority.runtimeState.transportTLSAuthority.clusterRootKeyPem;
  prodigyClearPersistentSecretString(publicSnapshot.masterAuthority.runtimeState.transportTLSAuthority.clusterRootKeyPem);

  secrets.mothershipTunnelGatewayServerKeyPem = publicSnapshot.masterAuthority.runtimeState.mothershipTunnelProviderDesiredState.gatewayAuth.serverKeyPem;
  prodigyClearPersistentSecretString(publicSnapshot.masterAuthority.runtimeState.mothershipTunnelProviderDesiredState.gatewayAuth.serverKeyPem);

  for (auto& operation : publicSnapshot.masterAuthority.runtimeState.pendingAddMachinesOperations)
  {
    ProdigyPersistentPendingAddMachinesOperationSecrets operationSecrets = {};
    operationSecrets.operationID = operation.operationID;
    operationSecrets.bootstrapSshPrivateKeyOpenSSH = operation.request.bootstrapSshKeyPackage.privateKeyOpenSSH;
    operationSecrets.bootstrapSshHostPrivateKeyOpenSSH = operation.request.bootstrapSshHostKeyPackage.privateKeyOpenSSH;

    if (operationSecrets.empty() == false)
    {
      secrets.pendingAddMachinesOperationSecrets.push_back(operationSecrets);
    }

    prodigyClearPersistentSSHPrivateKey(operation.request.bootstrapSshKeyPackage);
    prodigyClearPersistentSSHPrivateKey(operation.request.bootstrapSshHostKeyPackage);
  }

  for (auto& [executionID, carrier] : publicSnapshot.masterAuthority.runtimeState.taskExecutions)
  {
    (void)executionID;
    if (!prodigyContainerRetirementJournalCarrier(carrier))
    {
      continue;
    }

    ProdigyContainerRetirementJournal journal = {};
    if (!prodigyParseContainerRetirementJournalCarrier(carrier, journal))
    {
      if (failure) failure->assign("persistent brain snapshot retirement carrier is invalid"_ctv);
      return false;
    }

    for (ProdigyContainerRetirementIntent& intent : journal.intents)
    {
      if (intent.killAcked)
      {
        continue;
      }
      if (journal.version == ProdigyContainerRetirementJournal::legacyVersion)
      {
        ProdigyPersistentContainerRetirementBootstrapSecrets retirementSecrets = {};
        retirementSecrets.containerUUID = intent.containerUUID;
        retirementSecrets.deploymentID = intent.deploymentID;
        retirementSecrets.applicationID = intent.applicationID;
        retirementSecrets.machineUUID = intent.machineUUID;
        retirementSecrets.topologyOperationID = intent.topologyOperationID;
        retirementSecrets.sourceEpoch = intent.sourceEpoch;
        retirementSecrets.targetEpoch = intent.targetEpoch;
        retirementSecrets.intentGeneration = intent.intentGeneration;
        retirementSecrets.bootstrap = std::move(intent.bootstrap);
        secrets.containerRetirementBootstrapSecrets.push_back(std::move(retirementSecrets));
      }
      else
      {
        ProdigyPersistentContainerRetirementBootstrapSecretsV2 retirementSecrets = {};
        retirementSecrets.containerUUID = intent.containerUUID;
        retirementSecrets.deploymentID = intent.deploymentID;
        retirementSecrets.applicationID = intent.applicationID;
        retirementSecrets.machineUUID = intent.machineUUID;
        retirementSecrets.topologyOperationID = intent.topologyOperationID;
        retirementSecrets.sourceEpoch = intent.sourceEpoch;
        retirementSecrets.targetEpoch = intent.targetEpoch;
        retirementSecrets.intentGeneration = intent.intentGeneration;
        retirementSecrets.kind = intent.kind;
        retirementSecrets.pairedOperationID = intent.pairedOperationID;
        retirementSecrets.pairedSourceClusterUUID = intent.pairedSourceClusterUUID;
        retirementSecrets.pairedTargetClusterUUID = intent.pairedTargetClusterUUID;
        retirementSecrets.pairedTargetDeploymentID = intent.pairedTargetDeploymentID;
        retirementSecrets.bootstrap = std::move(intent.bootstrap);
        secrets.containerRetirementBootstrapSecretsV2.push_back(std::move(retirementSecrets));
      }
      intent.bootstrap.clear();
    }

    if (!prodigyPersistentWriteContainerRetirementDescriptor(carrier, journal) ||
        !prodigyParsePersistentContainerRetirementDescriptor(carrier, journal))
    {
      if (failure) failure->assign("persistent brain snapshot retirement descriptor could not be written"_ctv);
      return false;
    }
  }

  return true;
}

static inline bool prodigyApplyPersistentBrainSnapshotSecrets(
    ProdigyPersistentBrainSnapshot& snapshot,
    const ProdigyPersistentBrainSnapshotSecrets& secrets,
    String *failure = nullptr)
{
  if (failure)
  {
    failure->clear();
  }

  if (secrets.transportCredentialAuthorityRootSecrets.size() > 1)
  {
    if (failure) failure->assign("persistent brain snapshot has duplicate private transport authority roots"_ctv);
    return false;
  }
  const ProdigyTransportCredentialAuthorityRoot *transportAuthorityRoot =
      secrets.transportCredentialAuthorityRootSecrets.empty() ? nullptr :
      &secrets.transportCredentialAuthorityRootSecrets[0].root;
  if (!prodigyValidatePersistentTransportCredentialEnrollments(
          snapshot.masterAuthority.runtimeState.transportCredentialEnrollments,
          transportAuthorityRoot,
          snapshot.brainConfig.clusterUUID,
          snapshot.masterAuthority.runtimeState.generation,
          failure)) return false;
  if (!prodigyValidatePersistentTransportCredentialEnrollmentOperations(
          snapshot.masterAuthority.runtimeState.transportCredentialEnrollmentOperations,
          snapshot.masterAuthority.runtimeState.transportCredentialEnrollments,
          snapshot.masterAuthority.runtimeState.generation, failure)) return false;

  auto& enrollments = snapshot.masterAuthority.runtimeState.clusterPairEnrollments;
  if (enrollments.size() > ProdigyClusterPairEnrollmentMaximumRecords ||
      secrets.clusterPairEnrollmentRootSecrets.size() > ProdigyClusterPairEnrollmentMaximumRecords)
  {
    if (failure) failure->assign("persistent brain snapshot has too many cluster pair enrollment records"_ctv);
    return false;
  }
  if (!prodigyValidatePersistentClusterPairEnrollmentDescriptors(
          enrollments,
          snapshot.brainConfig.clusterUUID,
          snapshot.masterAuthority.runtimeState.generation,
          false,
          false,
          failure))
  {
    return false;
  }
  for (uint32_t left = 0; left < enrollments.size(); ++left)
  {
    const ProdigyClusterPairEnrollment& enrollment = enrollments[left];
    uint32_t matches = 0;
    const ProdigyPersistentClusterPairEnrollmentRootSecret *matched = nullptr;
    for (const auto& rootSecret : secrets.clusterPairEnrollmentRootSecrets)
    {
      if (rootSecret.matches(enrollment))
      {
        ++matches;
        matched = &rootSecret;
      }
    }
    if (enrollment.state == ProdigyClusterPairEnrollmentState::revoked)
    {
      if (matches != 0)
      {
        if (failure) failure->assign("persistent brain snapshot revoked cluster pair enrollment has a root"_ctv);
        return false;
      }
      continue;
    }
    if (matches != 1 || matched == nullptr || matched->rootIsZero())
    {
      if (failure) failure->assign("persistent brain snapshot cluster pair enrollment has no unique private root"_ctv);
      return false;
    }
  }
  for (const auto& rootSecret : secrets.clusterPairEnrollmentRootSecrets)
  {
    uint32_t matches = 0;
    for (const auto& enrollment : enrollments)
      matches += enrollment.state != ProdigyClusterPairEnrollmentState::revoked && rootSecret.matches(enrollment);
    if (matches != 1 || rootSecret.rootIsZero())
    {
      if (failure) failure->assign("persistent brain snapshot cluster pair root is orphaned or stale"_ctv);
      return false;
    }
  }
  // All descriptors and every private root now agree. Hydrate only after
  // completing this pass so a later bad record cannot expose earlier roots.
  for (ProdigyClusterPairEnrollment& enrollment : enrollments)
  {
    if (enrollment.state == ProdigyClusterPairEnrollmentState::revoked) continue;
    for (const auto& rootSecret : secrets.clusterPairEnrollmentRootSecrets)
    {
      if (rootSecret.matches(enrollment))
      {
        std::memcpy(enrollment.root, rootSecret.root, sizeof(enrollment.root));
        break;
      }
    }
  }

  if (transportAuthorityRoot != nullptr)
    snapshot.masterAuthority.runtimeState.transportCredentialAuthorityRoot = *transportAuthorityRoot;
  else
    snapshot.masterAuthority.runtimeState.transportCredentialAuthorityRoot = {};

  snapshot.brainConfig.bootstrapSshKeyPackage.privateKeyOpenSSH = secrets.bootstrapSshPrivateKeyOpenSSH;
  snapshot.brainConfig.bootstrapSshHostKeyPackage.privateKeyOpenSSH = secrets.bootstrapSshHostPrivateKeyOpenSSH;
  snapshot.brainConfig.dnsCredential.material = secrets.dnsCredentialMaterial;
  if (secrets.localContainerBootstraps.empty() == false)
  {
    snapshot.masterAuthority.runtimeState.updateSelf.localContainerBootstraps = secrets.localContainerBootstraps;
  }
  if (secrets.machineRecoveryWitnesses.empty() == false)
  {
    snapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses = secrets.machineRecoveryWitnesses;
  }

  for (uint32_t left = 0; left < secrets.containerRuntimeStateSecrets.size(); ++left)
  {
    for (uint32_t right = 0; right < left; ++right)
    {
      if (secrets.containerRuntimeStateSecrets[left].machineUUID ==
              secrets.containerRuntimeStateSecrets[right].machineUUID &&
          secrets.containerRuntimeStateSecrets[left].containerUUID ==
              secrets.containerRuntimeStateSecrets[right].containerUUID)
      {
        if (failure)
        {
          failure->assign("persistent brain snapshot duplicate container runtime secret"_ctv);
        }
        return false;
      }
    }
  }

  for (const BrainReplicatedContainerRuntimeState& runtimeState : snapshot.masterAuthority.containerRuntimeStates)
  {
    uint32_t matches = 0;
    for (const auto& runtimeStateSecrets : secrets.containerRuntimeStateSecrets)
    {
      matches += runtimeState.machineUUID == runtimeStateSecrets.machineUUID &&
                 runtimeState.plan.uuid == runtimeStateSecrets.containerUUID;
    }
    if (matches != 1)
    {
      if (failure)
      {
        failure->assign("persistent brain snapshot runtime record has no unique private sidecar"_ctv);
      }
      return false;
    }
  }

  for (const auto& runtimeStateSecrets : secrets.containerRuntimeStateSecrets)
  {
    BrainReplicatedContainerRuntimeState *matched = nullptr;
    for (BrainReplicatedContainerRuntimeState& runtimeState : snapshot.masterAuthority.containerRuntimeStates)
    {
      if (runtimeState.machineUUID == runtimeStateSecrets.machineUUID &&
          runtimeState.plan.uuid == runtimeStateSecrets.containerUUID)
      {
        if (matched != nullptr)
        {
          if (failure)
          {
            failure->assign("persistent brain snapshot container runtime secret is ambiguous"_ctv);
          }
          return false;
        }
        matched = &runtimeState;
      }
    }

    if (matched == nullptr ||
        runtimeStateSecrets.runtimeState.machineUUID != runtimeStateSecrets.machineUUID ||
        runtimeStateSecrets.runtimeState.plan.uuid != runtimeStateSecrets.containerUUID)
    {
      if (failure)
      {
        failure->assign("persistent brain snapshot runtime record sidecar identity differs"_ctv);
      }
      return false;
    }
    *matched = runtimeStateSecrets.runtimeState;
  }

  // Serving plans are staged desired state, not observations.  Their public
  // descriptor binds the container and machine plus deployment/application and
  // shard identities before the private payload is restored.
  for (uint32_t left = 0; left < secrets.servingRuntimeStateSecrets.size(); ++left)
  {
    for (uint32_t right = 0; right < left; ++right)
    {
      if (secrets.servingRuntimeStateSecrets[left].machineUUID ==
              secrets.servingRuntimeStateSecrets[right].machineUUID &&
          secrets.servingRuntimeStateSecrets[left].containerUUID ==
              secrets.servingRuntimeStateSecrets[right].containerUUID)
      {
        if (failure) failure->assign("persistent brain snapshot duplicate serving runtime secret"_ctv);
        return false;
      }
    }
  }

  for (BrainReplicatedContainerRuntimeState& descriptor : snapshot.masterAuthority.servingRuntimeStates)
  {
    const ProdigyPersistentContainerRuntimeStateSecrets *matched = nullptr;
    for (const auto& runtimeStateSecrets : secrets.servingRuntimeStateSecrets)
    {
      if (descriptor.machineUUID == runtimeStateSecrets.machineUUID &&
          descriptor.plan.uuid == runtimeStateSecrets.containerUUID)
      {
        if (matched != nullptr)
        {
          if (failure) failure->assign("persistent brain snapshot serving runtime secret is ambiguous"_ctv);
          return false;
        }
        matched = &runtimeStateSecrets;
      }
    }

    if (matched == nullptr || descriptor.machineUUID == 0 || descriptor.plan.uuid == 0 ||
        descriptor.plan.config.applicationID == 0 || descriptor.plan.config.deploymentID() == 0 ||
        matched->runtimeState.machineUUID != descriptor.machineUUID ||
        matched->runtimeState.plan.uuid != descriptor.plan.uuid ||
        matched->runtimeState.plan.config.deploymentID() != descriptor.plan.config.deploymentID() ||
        matched->runtimeState.plan.config.applicationID != descriptor.plan.config.applicationID ||
        matched->runtimeState.plan.shardGroup != descriptor.plan.shardGroup)
    {
      if (failure) failure->assign("persistent brain snapshot serving runtime sidecar identity differs"_ctv);
      return false;
    }
    descriptor = matched->runtimeState;
  }

  for (const auto& runtimeStateSecrets : secrets.servingRuntimeStateSecrets)
  {
    uint32_t matches = 0;
    for (const BrainReplicatedContainerRuntimeState& descriptor : snapshot.masterAuthority.servingRuntimeStates)
    {
      matches += descriptor.machineUUID == runtimeStateSecrets.machineUUID &&
                 descriptor.plan.uuid == runtimeStateSecrets.containerUUID;
    }
    if (matches != 1)
    {
      if (failure) failure->assign("persistent brain snapshot serving runtime secret has no descriptor"_ctv);
      return false;
    }
  }

  for (const auto& [applicationID, factorySecrets] : secrets.tlsVaultFactorySecretsByApp)
  {
    auto it = snapshot.masterAuthority.tlsVaultFactoriesByApp.find(applicationID);
    if (it == snapshot.masterAuthority.tlsVaultFactoriesByApp.end())
    {
      if (failure)
      {
        failure->snprintf<"persistent brain snapshot tls factory secrets missing app {itoa}"_ctv>(applicationID);
      }
      return false;
    }

    it->second.rootKeyPem = factorySecrets.rootKeyPem;
    it->second.intermediateKeyPem = factorySecrets.intermediateKeyPem;
  }

  for (const auto& [applicationID, setSecrets] : secrets.apiCredentialSecretsByApp)
  {
    auto it = snapshot.masterAuthority.apiCredentialSetsByApp.find(applicationID);
    if (it == snapshot.masterAuthority.apiCredentialSetsByApp.end())
    {
      if (failure)
      {
        failure->snprintf<"persistent brain snapshot api credential secrets missing app {itoa}"_ctv>(applicationID);
      }
      return false;
    }

    for (const auto& credentialSecret : setSecrets.credentials)
    {
      bool matched = false;
      for (auto& credential : it->second.credentials)
      {
        if (credential.name.equals(credentialSecret.name) && credential.provider.equals(credentialSecret.provider) && credential.generation == credentialSecret.generation)
        {
          credential.material = credentialSecret.material;
          matched = true;
          break;
        }
      }

      if (matched == false)
      {
        if (failure)
        {
          failure->snprintf<"persistent brain snapshot api credential secret missing credential {}"_ctv>(
              credentialSecret.name);
        }
        return false;
      }
    }
  }

  for (const ProdigyPersistentTlsResumptionEpochSecret& epochSecret : secrets.tlsResumptionEpochSecrets)
  {
    auto snapshotIt = snapshot.masterAuthority.runtimeState.tlsResumptionSnapshotsByWormhole.find(epochSecret.registryKey);
    if (snapshotIt == snapshot.masterAuthority.runtimeState.tlsResumptionSnapshotsByWormhole.end())
    {
      if (failure)
      {
        failure->snprintf<"persistent brain snapshot resumption secret missing snapshot {}"_ctv>(epochSecret.registryKey);
      }
      return false;
    }

    bool matched = false;
    for (TlsResumptionKeyEpoch& epoch : snapshotIt->second.keyRing)
    {
      if (epoch.generation == epochSecret.generation && std::memcmp(epoch.keyID, epochSecret.keyID, sizeof(epoch.keyID)) == 0)
      {
        std::memcpy(epoch.masterSecret, epochSecret.masterSecret, sizeof(epoch.masterSecret));
        matched = true;
        break;
      }
    }

    if (matched == false)
    {
      if (failure)
      {
        failure->snprintf<"persistent brain snapshot resumption secret missing epoch {itoa}"_ctv>(
            epochSecret.generation);
      }
      return false;
    }
  }

  for (const ProdigyPersistentPublicTlsCertificateSecret& certificateSecret : secrets.publicTlsCertificateSecrets)
  {
    bool matched = false;
    for (PublicTlsCertificateState& certificate : snapshot.masterAuthority.runtimeState.publicTlsCertificates)
    {
      if (certificate.identity.name.equals(certificateSecret.identityName) && certificate.identity.generation == certificateSecret.generation)
      {
        certificate.identity.keyPem = certificateSecret.keyPem;
        matched = true;
        break;
      }
    }

    if (matched == false)
    {
      if (failure)
      {
        failure->snprintf<"persistent brain snapshot public tls secret missing certificate {}"_ctv>(
            certificateSecret.identityName);
      }
      return false;
    }
  }

  snapshot.masterAuthority.runtimeState.transportTLSAuthority.clusterRootKeyPem = secrets.transportTLSAuthorityClusterRootKeyPem;
  snapshot.masterAuthority.runtimeState.mothershipTunnelProviderDesiredState.gatewayAuth.serverKeyPem = secrets.mothershipTunnelGatewayServerKeyPem;

  for (const auto& operationSecrets : secrets.pendingAddMachinesOperationSecrets)
  {
    bool matched = false;
    for (auto& operation : snapshot.masterAuthority.runtimeState.pendingAddMachinesOperations)
    {
      if (operation.operationID == operationSecrets.operationID)
      {
        operation.request.bootstrapSshKeyPackage.privateKeyOpenSSH = operationSecrets.bootstrapSshPrivateKeyOpenSSH;
        operation.request.bootstrapSshHostKeyPackage.privateKeyOpenSSH = operationSecrets.bootstrapSshHostPrivateKeyOpenSSH;
        matched = true;
        break;
      }
    }

    if (matched == false)
    {
      if (failure)
      {
        failure->snprintf<"persistent brain snapshot add-machines secrets missing operation {itoa}"_ctv>(
            operationSecrets.operationID);
      }
      return false;
    }
  }

  bool foundRetirementCarrier = false;
  for (auto& [executionID, carrier] : snapshot.masterAuthority.runtimeState.taskExecutions)
  {
    (void)executionID;
    if (!prodigyContainerRetirementJournalCarrier(carrier))
    {
      continue;
    }
    foundRetirementCarrier = true;

    ProdigyContainerRetirementJournal journal = {};
    if (!prodigyParsePersistentContainerRetirementDescriptor(carrier, journal))
    {
      if (failure) failure->assign("persistent brain snapshot retirement descriptor is invalid"_ctv);
      return false;
    }

    for (ProdigyContainerRetirementIntent& intent : journal.intents)
    {
      uint32_t matches = 0;
      const String *bootstrap = nullptr;
      if (journal.version == ProdigyContainerRetirementJournal::legacyVersion)
      {
        for (const auto& retirementSecrets : secrets.containerRetirementBootstrapSecrets)
        {
          if (retirementSecrets.matches(intent))
          {
            ++matches;
            bootstrap = &retirementSecrets.bootstrap;
          }
        }
      }
      else
      {
        for (const auto& retirementSecrets : secrets.containerRetirementBootstrapSecretsV2)
        {
          if (retirementSecrets.matches(intent))
          {
            ++matches;
            bootstrap = &retirementSecrets.bootstrap;
          }
        }
      }
      if (intent.killAcked)
      {
        if (matches != 0)
        {
          if (failure) failure->assign("persistent brain snapshot terminal retirement has private bootstrap"_ctv);
          return false;
        }
        continue;
      }
      if (matches != 1 || bootstrap == nullptr || bootstrap->empty())
      {
        if (failure) failure->assign("persistent brain snapshot retirement bootstrap sidecar is missing or ambiguous"_ctv);
        return false;
      }
      intent.bootstrap = *bootstrap;
    }

    for (const auto& retirementSecrets : secrets.containerRetirementBootstrapSecrets)
    {
      const ProdigyContainerRetirementIntent *intent =
          prodigyFindContainerRetirementIntentInValidatedJournal(journal, retirementSecrets.containerUUID);
      if (journal.version != ProdigyContainerRetirementJournal::legacyVersion ||
          intent == nullptr || intent->killAcked || !retirementSecrets.matches(*intent))
      {
        if (failure) failure->assign("persistent brain snapshot retirement bootstrap sidecar identity differs"_ctv);
        return false;
      }
    }
    for (const auto& retirementSecrets : secrets.containerRetirementBootstrapSecretsV2)
    {
      const ProdigyContainerRetirementIntent *intent =
          prodigyFindContainerRetirementIntentInValidatedJournal(journal, retirementSecrets.containerUUID);
      if ((journal.version != ProdigyContainerRetirementJournal::pairedIntentVersion &&
           journal.version != ProdigyContainerRetirementJournal::currentVersion) ||
          intent == nullptr || intent->killAcked || !retirementSecrets.matches(*intent))
      {
        if (failure) failure->assign("persistent brain snapshot retirement bootstrap sidecar identity differs"_ctv);
        return false;
      }
    }

    if (!prodigyValidateContainerRetirementJournal(journal) ||
        !prodigyPersistentWriteContainerRetirementDescriptor(carrier, journal))
    {
      if (failure) failure->assign("persistent brain snapshot restored retirement journal is invalid"_ctv);
      return false;
    }
  }
  if (!foundRetirementCarrier &&
      (!secrets.containerRetirementBootstrapSecrets.empty() ||
       !secrets.containerRetirementBootstrapSecretsV2.empty()))
  {
    if (failure) failure->assign("persistent brain snapshot retirement bootstrap sidecar has no carrier"_ctv);
    return false;
  }

  if (!prodigyValidateStatefulServingAuthorities(snapshot.masterAuthority.runtimeState.statefulServingAuthorities,
        snapshot.masterAuthority.servingRuntimeStates, snapshot.masterAuthority.runtimeState.generation))
  {
    if (failure) failure->assign("persistent brain snapshot serving authority is incomplete or invalid"_ctv);
    return false;
  }
  return true;
}

static bool prodigyPersistentSnapshotRetirementDescriptorsNeedNoSecrets(
    const ProdigyPersistentBrainSnapshot& snapshot, String *failure = nullptr)
{
  for (const auto& [executionID, carrier] : snapshot.masterAuthority.runtimeState.taskExecutions)
  {
    (void)executionID;
    if (!prodigyContainerRetirementJournalCarrier(carrier))
    {
      continue;
    }
    ProdigyContainerRetirementJournal journal = {};
    if (!prodigyParsePersistentContainerRetirementDescriptor(carrier, journal))
    {
      if (failure) failure->assign("persistent brain snapshot retirement descriptor is invalid"_ctv);
      return false;
    }
    for (const auto& intent : journal.intents)
    {
      if (!intent.killAcked)
      {
        if (failure) failure->assign("persistent brain snapshot retirement bootstrap sidecar is missing or ambiguous"_ctv);
        return false;
      }
    }
  }
  return true;
}

static bool prodigyPersistentSnapshotServingRuntimeDescriptorsNeedNoSecrets(
    const ProdigyPersistentBrainSnapshot& snapshot, String *failure = nullptr)
{
  if (!snapshot.masterAuthority.servingRuntimeStates.empty() ||
      !snapshot.masterAuthority.runtimeState.statefulServingAuthorities.empty())
  {
    if (failure) failure->assign("persistent brain snapshot serving runtime private sidecar is missing"_ctv);
    return false;
  }
  return true;
}

static bool prodigyPersistentSnapshotClusterPairEnrollmentsNeedNoSecrets(
    const ProdigyPersistentBrainSnapshot& snapshot, String *failure = nullptr)
{
  if (prodigyValidatePersistentClusterPairEnrollmentDescriptors(
          snapshot.masterAuthority.runtimeState.clusterPairEnrollments,
          snapshot.brainConfig.clusterUUID,
          snapshot.masterAuthority.runtimeState.generation,
          false,
          true,
          failure)) return true;
  if (failure && failure->size() == 0)
    failure->assign("persistent brain snapshot cluster pair private root sidecar is missing"_ctv);
  return false;
}

static bool prodigyPersistentSnapshotTransportCredentialEnrollmentsNeedNoSecrets(
    const ProdigyPersistentBrainSnapshot& snapshot, String *failure = nullptr)
{
  if (snapshot.masterAuthority.runtimeState.transportCredentialEnrollments.empty()) return true;
  if (failure) failure->assign("persistent brain snapshot transport credential authority sidecar is missing"_ctv);
  return false;
}

static inline void prodigyExtractPersistentLocalBrainStateSecrets(
    const ProdigyPersistentLocalBrainState& state,
    ProdigyPersistentLocalBrainState& publicState,
    ProdigyPersistentLocalBrainStateSecrets& secrets)
{
  publicState = state;
  secrets.clear();

  secrets.clusterRootKeyPem = state.transportTLS.clusterRootKeyPem;
  secrets.localKeyPem = state.transportTLS.localKeyPem;
  prodigyClearPersistentSecretString(publicState.transportTLS.clusterRootKeyPem);
  prodigyClearPersistentSecretString(publicState.transportTLS.localKeyPem);
  if (state.transportCredentials.enabled)
  {
    secrets.transportNodeCredential = state.transportCredentials.self;
    secrets.transportAuthorityRoot = state.transportCredentialAuthorityRoot;
    OPENSSL_cleanse(publicState.transportCredentials.self.secret, sizeof(publicState.transportCredentials.self.secret));
    OPENSSL_cleanse(publicState.transportCredentialAuthorityRoot.root, sizeof(publicState.transportCredentialAuthorityRoot.root));
  }
}

static inline bool prodigyApplyPersistentLocalBrainStateSecrets(
    ProdigyPersistentLocalBrainState& state,
    const ProdigyPersistentLocalBrainStateSecrets& secrets)
{
  if (!prodigyLocalTransportCredentialStateValid(state, false)) return false;
  if (state.transportCredentials.enabled)
  {
    const auto& expected = state.transportCredentials.self;
    const auto& supplied = secrets.transportNodeCredential;
    if (!prodigyTransportCredentialBootstrapValid(state.transportCredentials, false) || !supplied.valid() ||
        expected.nodeUUID != state.uuid || expected.clusterUUID != state.ownerClusterUUID ||
        expected.nodeUUID != supplied.nodeUUID || expected.clusterUUID != supplied.clusterUUID ||
        expected.operationUUID != supplied.operationUUID || expected.role != supplied.role ||
        expected.authorityEpoch != supplied.authorityEpoch || expected.keyEpoch != supplied.keyEpoch ||
        expected.authorityGeneration != supplied.authorityGeneration ||
        expected.rootAuthorityGeneration != supplied.rootAuthorityGeneration) return false;
  }
  else if (secrets.transportNodeCredential.nodeUUID != 0) return false;
  const auto& expectedRoot = state.transportCredentialAuthorityRoot;
  const auto& suppliedRoot = secrets.transportAuthorityRoot;
  if (expectedRoot.authorityEpoch != suppliedRoot.authorityEpoch || expectedRoot.keyEpoch != suppliedRoot.keyEpoch ||
      expectedRoot.authorityGeneration != suppliedRoot.authorityGeneration) return false;
  ProdigyPersistentLocalBrainState candidate = state;
  if (candidate.transportCredentials.enabled) candidate.transportCredentials.self = secrets.transportNodeCredential;
  candidate.transportCredentialAuthorityRoot = suppliedRoot;
  if (!prodigyLocalTransportCredentialStateValid(candidate)) return false;
  state.transportTLS.clusterRootKeyPem = secrets.clusterRootKeyPem;
  state.transportTLS.localKeyPem = secrets.localKeyPem;
  if (state.transportCredentials.enabled) state.transportCredentials.self = secrets.transportNodeCredential;
  state.transportCredentialAuthorityRoot = suppliedRoot;
  return true;
}

template <typename T>
static bool prodigyPersistentSerializedEqual(const T& lhs, const T& rhs)
{
  T lhsCopy = lhs;
  T rhsCopy = rhs;

  String lhsSerialized = {};
  String rhsSerialized = {};
  BitseryEngine::serialize(lhsSerialized, lhsCopy);
  BitseryEngine::serialize(rhsSerialized, rhsCopy);

  bool equal = lhsSerialized.equals(rhsSerialized);
  Vault::secureClearString(lhsSerialized);
  Vault::secureClearString(rhsSerialized);
  return equal;
}

template <typename Value>
static bool prodigyPersistentMapValueEqual(const Value& lhs, const Value& rhs)
{
  if constexpr (std::is_arithmetic_v<Value> || std::is_enum_v<Value>)
  {
    return lhs == rhs;
  }
  else
  {
    return prodigyPersistentSerializedEqual(lhs, rhs);
  }
}

template <typename Key, typename Value>
static bool prodigyPersistentMapEqual(
    const bytell_hash_map<Key, Value>& lhs,
    const bytell_hash_map<Key, Value>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (const auto& [key, value] : lhs)
  {
    auto it = rhs.find(key);
    if (it == rhs.end() || prodigyPersistentMapValueEqual(value, it->second) == false)
    {
      return false;
    }
  }

  return true;
}

template <typename Key, typename Value>
static bool prodigyPersistentMapEqual(
    const bytell_hash_subvector<Key, Value>& lhs,
    const bytell_hash_subvector<Key, Value>& rhs)
{
  return prodigyPersistentMapEqual(lhs.map, rhs.map);
}

static bool prodigyPersistentApiCredentialsEqual(
    const Vector<ApiCredential>& lhs, const Vector<ApiCredential>& rhs)
{
  if (lhs.size() != rhs.size()) return false;
  for (uint32_t index = 0; index < lhs.size(); ++index)
  {
    if (!prodigyPersistentMapEqual(lhs[index].metadata, rhs[index].metadata)) return false;
    auto left = lhs[index], right = rhs[index];
    left.metadata.clear(); right.metadata.clear();
    if (!prodigyPersistentSerializedEqual(left, right)) return false;
  }
  return true;
}

template <>
inline bool prodigyPersistentMapValueEqual<ApplicationApiCredentialSet>(
    const ApplicationApiCredentialSet& lhs, const ApplicationApiCredentialSet& rhs)
{
  if (!prodigyPersistentApiCredentialsEqual(lhs.credentials, rhs.credentials)) return false;
  auto left = lhs, right = rhs;
  left.credentials.clear(); right.credentials.clear();
  return prodigyPersistentSerializedEqual(left, right);
}

static bool prodigyPersistentRetainedBootstrapEqual(
    const NeuronContainerBootstrap& lhs,
    const NeuronContainerBootstrap& rhs)
{
  if (!prodigyPersistentApiCredentialsEqual(lhs.plan.credentialBundle.apiCredentials, rhs.plan.credentialBundle.apiCredentials) ||
      prodigyPersistentMapEqual(lhs.plan.subscriptions, rhs.plan.subscriptions) == false ||
      prodigyPersistentMapEqual(lhs.plan.advertisements, rhs.plan.advertisements) == false ||
      prodigyPersistentMapEqual(lhs.plan.subscriptionPairings, rhs.plan.subscriptionPairings) == false ||
      prodigyPersistentMapEqual(lhs.plan.advertisementPairings, rhs.plan.advertisementPairings) == false)
  {
    return false;
  }

  NeuronContainerBootstrap lhsCopy = lhs;
  NeuronContainerBootstrap rhsCopy = rhs;
  lhsCopy.plan.credentialBundle.apiCredentials.clear();
  rhsCopy.plan.credentialBundle.apiCredentials.clear();
  lhsCopy.plan.subscriptions.clear();
  lhsCopy.plan.advertisements.clear();
  lhsCopy.plan.subscriptionPairings.clear();
  lhsCopy.plan.advertisementPairings.clear();
  rhsCopy.plan.subscriptions.clear();
  rhsCopy.plan.advertisements.clear();
  rhsCopy.plan.subscriptionPairings.clear();
  rhsCopy.plan.advertisementPairings.clear();
  return prodigyPersistentSerializedEqual(lhsCopy, rhsCopy);
}

static bool prodigyPersistentContainerRuntimeStateEqual(
    const BrainReplicatedContainerRuntimeState& lhs,
    const BrainReplicatedContainerRuntimeState& rhs)
{
  NeuronContainerBootstrap lhsBootstrap = {}, rhsBootstrap = {};
  lhsBootstrap.plan = lhs.plan;
  rhsBootstrap.plan = rhs.plan;
  if (prodigyPersistentRetainedBootstrapEqual(lhsBootstrap, rhsBootstrap) == false)
  {
    return false;
  }

  auto lhsCopy = lhs;
  auto rhsCopy = rhs;
  lhsCopy.plan = {};
  rhsCopy.plan = {};
  return prodigyPersistentSerializedEqual(lhsCopy, rhsCopy);
}

static bool prodigyPersistentBrainSnapshotsEqual(
    const ProdigyPersistentBrainSnapshot& lhs,
    const ProdigyPersistentBrainSnapshot& rhs)
{
  const auto& lhsAuthority = lhs.masterAuthority;
  const auto& rhsAuthority = rhs.masterAuthority;
  if (!prodigyPersistentMapEqual(lhs.brainConfig.configBySlug, rhs.brainConfig.configBySlug) ||
      !prodigyPersistentMapEqual(lhs.brainConfig.dnsCredential.metadata, rhs.brainConfig.dnsCredential.metadata) ||
      prodigyPersistentMapEqual(lhsAuthority.tlsVaultFactoriesByApp, rhsAuthority.tlsVaultFactoriesByApp) == false ||
      prodigyPersistentMapEqual(lhsAuthority.apiCredentialSetsByApp, rhsAuthority.apiCredentialSetsByApp) == false ||
      prodigyPersistentMapEqual(lhsAuthority.reservedApplicationIDsByName, rhsAuthority.reservedApplicationIDsByName) == false ||
      prodigyPersistentMapEqual(lhsAuthority.reservedApplicationNamesByID, rhsAuthority.reservedApplicationNamesByID) == false ||
      prodigyPersistentMapEqual(lhsAuthority.deploymentPlans, rhsAuthority.deploymentPlans) == false ||
      prodigyPersistentMapEqual(lhsAuthority.failedDeployments, rhsAuthority.failedDeployments) == false ||
      lhsAuthority.containerRuntimeStates.size() != rhsAuthority.containerRuntimeStates.size() ||
      lhsAuthority.servingRuntimeStates.size() != rhsAuthority.servingRuntimeStates.size() ||
      lhsAuthority.runtimeState != rhsAuthority.runtimeState)
  {
    return false;
  }

  for (uint32_t index = 0; index < lhsAuthority.servingRuntimeStates.size(); ++index)
  {
    if (prodigyPersistentContainerRuntimeStateEqual(
            lhsAuthority.servingRuntimeStates[index],
            rhsAuthority.servingRuntimeStates[index]) == false)
    {
      return false;
    }
  }

  for (uint32_t index = 0; index < lhsAuthority.containerRuntimeStates.size(); ++index)
  {
    if (prodigyPersistentContainerRuntimeStateEqual(
            lhsAuthority.containerRuntimeStates[index],
            rhsAuthority.containerRuntimeStates[index]) == false)
    {
      return false;
    }
  }

  ProdigyPersistentBrainSnapshot lhsCopy = lhs;
  ProdigyPersistentBrainSnapshot rhsCopy = rhs;
  lhsCopy.brainConfig.configBySlug.clear();
  rhsCopy.brainConfig.configBySlug.clear();
  lhsCopy.brainConfig.dnsCredential.metadata.clear();
  rhsCopy.brainConfig.dnsCredential.metadata.clear();
  lhsCopy.masterAuthority.tlsVaultFactoriesByApp.clear();
  lhsCopy.masterAuthority.apiCredentialSetsByApp.clear();
  lhsCopy.masterAuthority.reservedApplicationIDsByName.clear();
  lhsCopy.masterAuthority.reservedApplicationNamesByID.clear();
  lhsCopy.masterAuthority.deploymentPlans.clear();
  lhsCopy.masterAuthority.failedDeployments.clear();
  lhsCopy.masterAuthority.containerRuntimeStates.clear();
  lhsCopy.masterAuthority.servingRuntimeStates.clear();
  lhsCopy.masterAuthority.runtimeState = {};
  rhsCopy.masterAuthority.tlsVaultFactoriesByApp.clear();
  rhsCopy.masterAuthority.apiCredentialSetsByApp.clear();
  rhsCopy.masterAuthority.reservedApplicationIDsByName.clear();
  rhsCopy.masterAuthority.reservedApplicationNamesByID.clear();
  rhsCopy.masterAuthority.deploymentPlans.clear();
  rhsCopy.masterAuthority.failedDeployments.clear();
  rhsCopy.masterAuthority.containerRuntimeStates.clear();
  rhsCopy.masterAuthority.servingRuntimeStates.clear();
  rhsCopy.masterAuthority.runtimeState = {};
  return prodigyPersistentSerializedEqual(lhsCopy, rhsCopy);
}

static bool prodigyPersistentRawBytesEqual(const String& lhs, const String& rhs)
{
  return lhs.size() == rhs.size() && (lhs.size() == 0 || std::memcmp(lhs.data(), rhs.data(), lhs.size()) == 0);
}

static bool prodigyPersistentStoredRecordSecretVersion(const String& serialized, uint64_t& secretVersion)
{
  if (serialized.size() < sizeof(secretVersion))
  {
    secretVersion = 0;
    return false;
  }

  const uint8_t *bytes = reinterpret_cast<const uint8_t *>(serialized.data());
  secretVersion = 0;
  for (size_t i = 0; i < sizeof(secretVersion); ++i)
  {
    secretVersion |= uint64_t(bytes[i]) << (8 * i);
  }

  return true;
}

static bool prodigyPersistentStoredRecordPayloadEquals(const String& serialized, const String& payload)
{
  if (serialized.size() != sizeof(uint64_t) + payload.size())
  {
    return false;
  }

  const uint8_t *serializedBytes = reinterpret_cast<const uint8_t *>(serialized.data());
  return payload.size() == 0 || std::memcmp(serializedBytes + sizeof(uint64_t), payload.data(), payload.size()) == 0;
}

template <typename StoredRecord>
static bool prodigyLoadPersistentStoredRecord(const String& serialized, StoredRecord& record)
{
  record = {};
  return BitseryEngine::deserializeSafe(serialized, record);
}

class ProdigyPersistentStateStore {
private:

  constexpr static const char *bootColumnFamily = "boot";
  constexpr static const char *brainColumnFamily = "brain";
  constexpr static const char *bootKey = "local";
  constexpr static const char *brainSnapshotKey = "snapshot";
  constexpr static const char *localBrainStateKey = "local_brain_state";
  constexpr static const char *consumedBootstrapBundleSupersessionReceiptKey = "consumed_bootstrap_bundle_supersession_receipt";

  // Separated snapshot values contribute only references to TidesDB's memtable
  // limit. Bound committed value bytes as well so frequent overwrites cannot
  // keep obsolete value-log segments pinned indefinitely waiting for idle.
  constexpr static uint64_t snapshotFlushBytes = 64ULL * 1024 * 1024;
  TidesDB db{""_ctv, TidesDB::Durability::inherit, snapshotFlushBytes};
  TidesDB secretsDb{""_ctv, TidesDB::Durability::inherit, snapshotFlushBytes};

  bool loadStoredBootStateRecord(ProdigyPersistentStoredBootState& record, String *failure = nullptr)
  {
    String serialized = {};
    if (db.read(bootColumnFamily, bootKey, serialized, failure) == false)
    {
      return false;
    }

    if (prodigyLoadPersistentStoredRecord(serialized, record) == false)
    {
      if (failure)
      {
        failure->assign("invalid persistent boot state");
      }
      return false;
    }

    return true;
  }

  bool loadStoredBrainSnapshotRecord(ProdigyPersistentStoredBrainSnapshot& record, String *failure = nullptr)
  {
    String serialized = {};
    if (db.read(brainColumnFamily, brainSnapshotKey, serialized, failure) == false)
    {
      return false;
    }

    if (prodigyLoadPersistentStoredRecord(serialized, record) == false)
    {
      if (failure)
      {
        failure->assign("invalid persistent brain snapshot");
      }
      return false;
    }

    return true;
  }

  bool loadStoredLocalBrainStateRecord(ProdigyPersistentStoredLocalBrainState& record, String *failure = nullptr)
  {
    String serialized = {};
    if (db.read(brainColumnFamily, localBrainStateKey, serialized, failure) == false)
    {
      return false;
    }

    if (prodigyLoadPersistentStoredRecord(serialized, record) == false)
    {
      if (failure)
      {
        failure->assign("invalid persistent local brain state");
      }
      return false;
    }

    return true;
  }

  template <typename SecretsRecord>
  bool loadSecretRecord(
      const char *columnFamily,
      const char *baseKey,
      uint64_t version,
      SecretsRecord& record,
      const char *failureMessage,
      String *failure = nullptr)
  {
    String secretKey = {};
    prodigyBuildPersistentSecretRecordKey(baseKey, version, secretKey);

    String serialized = {};
    if (secretsDb.read(columnFamily, secretKey, serialized, failure) == false)
    {
      return false;
    }

    if (BitseryEngine::deserializeSafe(serialized, record) == false)
    {
      if (failure)
      {
        failure->assign(failureMessage);
      }
      return false;
    }

    return true;
  }

  template <typename SecretsRecord>
  bool saveSecretRecord(
      const char *columnFamily,
      const char *baseKey,
      uint64_t version,
      SecretsRecord& record,
      String *failure = nullptr)
  {
    String secretKey = {};
    prodigyBuildPersistentSecretRecordKey(baseKey, version, secretKey);

    String serialized = {};
    BitseryEngine::serialize(serialized, record);
    bool ok = secretsDb.write(columnFamily, secretKey, serialized, failure);
    Vault::secureClearString(serialized);
    return ok;
  }

  void removeSecretRecordBestEffort(const char *columnFamily, const char *baseKey, uint64_t version)
  {
    if (version == 0)
    {
      return;
    }

    String secretKey = {};
    prodigyBuildPersistentSecretRecordKey(baseKey, version, secretKey);
    String ignoredFailure = {};
    (void)secretsDb.remove(columnFamily, secretKey, &ignoredFailure);
  }

  uint64_t previousBootSecretVersion(void)
  {
    ProdigyPersistentStoredBootState record = {};
    String failure = {};
    if (loadStoredBootStateRecord(record, &failure))
    {
      return record.secretVersion;
    }

    return 0;
  }

  uint64_t previousBrainSnapshotSecretVersion(void)
  {
    ProdigyPersistentStoredBrainSnapshot record = {};
    String failure = {};
    if (loadStoredBrainSnapshotRecord(record, &failure))
    {
      return record.secretVersion;
    }

    return 0;
  }

  uint64_t previousLocalBrainStateSecretVersion(void)
  {
    ProdigyPersistentStoredLocalBrainState record = {};
    String failure = {};
    if (loadStoredLocalBrainStateRecord(record, &failure))
    {
      return record.secretVersion;
    }

    return 0;
  }

public:

  explicit ProdigyPersistentStateStore(const String& path = ""_ctv)
  {
    String resolvedPath = {};
    if (path.size() > 0)
    {
      resolvedPath = path;
    }
    else
    {
      resolveProdigyPersistentStateDBPath(resolvedPath);
    }

    db.setPath(resolvedPath);

    String resolvedSecretsPath = {};
    resolveProdigyPersistentSecretsDBPath(resolvedPath, resolvedSecretsPath);
    secretsDb.setPath(resolvedSecretsPath);
  }

  const String& path(void) const
  {
    return db.path();
  }

  const String& secretsPath(void) const
  {
    return secretsDb.path();
  }

  // Reads only the public stored snapshot record. This intentionally does not
  // open or decrypt the snapshot secret sidecar.
  bool readStoredClusterUUID(uint128_t& clusterUUID, String *failure = nullptr)
  {
    clusterUUID = 0;
    ProdigyPersistentStoredBrainSnapshot stored = {};
    if (loadStoredBrainSnapshotRecord(stored, failure) == false)
    {
      return false;
    }

    clusterUUID = stored.state.brainConfig.clusterUUID;
    if (clusterUUID == 0)
    {
      if (failure)
      {
        failure->assign("persistent brain snapshot has no cluster UUID"_ctv);
      }
      return false;
    }

    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  void close(void)
  {
    db.close();
    secretsDb.close();
  }

  bool loadBootState(ProdigyPersistentBootState& state, String *failure = nullptr)
  {
    ProdigyPersistentStoredBootState stored = {};
    if (loadStoredBootStateRecord(stored, failure) == false)
    {
      return false;
    }

    state = stored.state;
    if (stored.secretVersion != 0)
    {
      ProdigyPersistentBootStateSecrets secrets = {};
      bool ok = loadSecretRecord(
          bootColumnFamily,
          bootKey,
          stored.secretVersion,
          secrets,
          "invalid persistent boot state secrets",
          failure);
      if (ok == false)
      {
        return false;
      }

      prodigyApplyPersistentBootStateSecrets(state, secrets);
      secrets.clear();
    }

    prodigyStripManagedCloudBootstrapCredentials(state.runtimeEnvironment);
    return true;
  }

  bool saveBootState(const ProdigyPersistentBootState& state, String *failure = nullptr)
  {
    ProdigyPersistentBootState canonicalState = state;
    prodigyStripManagedCloudBootstrapCredentials(canonicalState.runtimeEnvironment);

    ProdigyPersistentBootState existingState = {};
    String loadFailure = {};
    if (loadBootState(existingState, &loadFailure))
    {
      if (prodigyPersistentSerializedEqual(existingState, canonicalState))
      {
        if (failure)
        {
          failure->clear();
        }
        return true;
      }
    }
    else if (loadFailure.size() > 0 && loadFailure != "record not found"_ctv)
    {
      if (failure)
      {
        failure->assign(loadFailure);
      }
      return false;
    }

    ProdigyPersistentBootState publicState = {};
    ProdigyPersistentBootStateSecrets secrets = {};
    prodigyExtractPersistentBootStateSecrets(canonicalState, publicState, secrets);

    uint64_t previousVersion = previousBootSecretVersion();
    uint64_t newVersion = 0;
    if (secrets.empty() == false)
    {
      newVersion = prodigyGeneratePersistentSecretVersion();
      if (saveSecretRecord(bootColumnFamily, bootKey, newVersion, secrets, failure) == false)
      {
        secrets.clear();
        return false;
      }
    }

    ProdigyPersistentStoredBootState stored = {};
    stored.secretVersion = newVersion;
    stored.state = std::move(publicState);

    String serialized = {};
    BitseryEngine::serialize(serialized, stored);
    bool ok = db.write(bootColumnFamily, bootKey, serialized, failure);
    if (ok && previousVersion != newVersion)
    {
      removeSecretRecordBestEffort(bootColumnFamily, bootKey, previousVersion);
    }

    Vault::secureClearString(serialized);
    secrets.clear();
    return ok;
  }

  bool loadBrainSnapshot(ProdigyPersistentBrainSnapshot& snapshot, String *failure = nullptr)
  {
    ProdigyPersistentStoredBrainSnapshot stored = {};
    if (loadStoredBrainSnapshotRecord(stored, failure) == false)
    {
      return false;
    }

    snapshot = stored.state;
    if (stored.secretVersion != 0)
    {
      ProdigyPersistentBrainSnapshotSecrets secrets = {};
      bool ok = loadSecretRecord(
          brainColumnFamily,
          brainSnapshotKey,
          stored.secretVersion,
          secrets,
          "invalid persistent brain snapshot secrets",
          failure);
      if (ok == false)
      {
        return false;
      }

      ok = prodigyApplyPersistentBrainSnapshotSecrets(snapshot, secrets, failure);
      secrets.clear();
      if (ok == false)
      {
        return false;
      }
    }
    else if (prodigyPersistentSnapshotRetirementDescriptorsNeedNoSecrets(snapshot, failure) == false ||
             prodigyPersistentSnapshotServingRuntimeDescriptorsNeedNoSecrets(snapshot, failure) == false ||
             prodigyPersistentSnapshotClusterPairEnrollmentsNeedNoSecrets(snapshot, failure) == false ||
             prodigyPersistentSnapshotTransportCredentialEnrollmentsNeedNoSecrets(snapshot, failure) == false)
    {
      return false;
    }

    prodigyStripManagedCloudBootstrapCredentials(snapshot.brainConfig.runtimeEnvironment);
    prodigyStripMachineHardwareCapturesFromClusterTopology(snapshot.topology);
    return true;
  }

  bool saveBrainSnapshot(const ProdigyPersistentBrainSnapshot& snapshot, String *failure = nullptr)
  {
    ProdigyPersistentBrainSnapshot canonicalSnapshot = snapshot;
    prodigyStripManagedCloudBootstrapCredentials(canonicalSnapshot.brainConfig.runtimeEnvironment);
    prodigyStripMachineHardwareCapturesFromClusterTopology(canonicalSnapshot.topology);

    ProdigyPersistentBrainSnapshot publicSnapshot = {};
    ProdigyPersistentBrainSnapshotSecrets secrets = {};
    if (prodigyExtractPersistentBrainSnapshotSecrets(
            std::move(canonicalSnapshot), publicSnapshot, secrets, failure) == false)
    {
      secrets.clear();
      return false;
    }

    String serializedPublicSnapshot = {};
    BitseryEngine::serialize(serializedPublicSnapshot, publicSnapshot);

    String serializedSecrets = {};
    if (secrets.empty() == false)
    {
      BitseryEngine::serialize(serializedSecrets, secrets);
    }

    uint64_t previousVersion = 0;
    String existingStoredRecord = {};
    String loadFailure = {};
    if (db.read(brainColumnFamily, brainSnapshotKey, existingStoredRecord, &loadFailure))
    {
      uint64_t existingVersion = 0;
      if (prodigyPersistentStoredRecordSecretVersion(existingStoredRecord, existingVersion))
      {
        if (existingVersion == 0)
        {
          previousVersion = 0;
          if (serializedSecrets.size() == 0 && prodigyPersistentStoredRecordPayloadEquals(existingStoredRecord, serializedPublicSnapshot))
          {
            Vault::secureClearString(serializedPublicSnapshot);
            secrets.clear();
            if (failure)
            {
              failure->clear();
            }
            return true;
          }
        }
        else
        {
          String existingSerializedSecrets = {};
          String secretFailure = {};
          String existingSecretKey = {};
          prodigyBuildPersistentSecretRecordKey(brainSnapshotKey, existingVersion, existingSecretKey);
          if (secretsDb.read(brainColumnFamily, existingSecretKey, existingSerializedSecrets, &secretFailure))
          {
            previousVersion = existingVersion;
            bool samePublicSnapshot = prodigyPersistentStoredRecordPayloadEquals(
                existingStoredRecord,
                serializedPublicSnapshot);
            bool sameSecrets = prodigyPersistentRawBytesEqual(existingSerializedSecrets, serializedSecrets);
            Vault::secureClearString(existingSerializedSecrets);
            if (samePublicSnapshot && sameSecrets)
            {
              Vault::secureClearString(serializedPublicSnapshot);
              Vault::secureClearString(serializedSecrets);
              secrets.clear();
              if (failure)
              {
                failure->clear();
              }
              return true;
            }
          }
          else if (secretFailure.size() > 0 && secretFailure != "record not found"_ctv)
          {
            Vault::secureClearString(serializedPublicSnapshot);
            Vault::secureClearString(serializedSecrets);
            secrets.clear();
            if (failure)
            {
              failure->assign(secretFailure);
            }
            return false;
          }
        }
      }
    }
    else if (loadFailure.size() > 0 && loadFailure != "record not found"_ctv)
    {
      Vault::secureClearString(serializedPublicSnapshot);
      Vault::secureClearString(serializedSecrets);
      secrets.clear();
      if (failure)
      {
        failure->assign(loadFailure);
      }
      return false;
    }

    uint64_t newVersion = 0;
    if (secrets.empty() == false)
    {
      newVersion = prodigyGeneratePersistentSecretVersion();
      if (saveSecretRecord(brainColumnFamily, brainSnapshotKey, newVersion, secrets, failure) == false)
      {
        Vault::secureClearString(serializedPublicSnapshot);
        Vault::secureClearString(serializedSecrets);
        secrets.clear();
        return false;
      }
    }

    ProdigyPersistentStoredBrainSnapshot stored = {};
    stored.secretVersion = newVersion;
    stored.state = std::move(publicSnapshot);

    String serialized = {};
    BitseryEngine::serialize(serialized, stored);
    bool ok = db.write(brainColumnFamily, brainSnapshotKey, serialized, failure);
    if (ok && previousVersion != newVersion)
    {
      removeSecretRecordBestEffort(brainColumnFamily, brainSnapshotKey, previousVersion);
    }

    Vault::secureClearString(serialized);
    Vault::secureClearString(serializedPublicSnapshot);
    Vault::secureClearString(serializedSecrets);
    secrets.clear();
    return ok;
  }

  bool loadLocalBrainState(ProdigyPersistentLocalBrainState& state, String *failure = nullptr)
  {
    ProdigyPersistentStoredLocalBrainState stored = {};
    if (loadStoredLocalBrainStateRecord(stored, failure) == false)
    {
      return false;
    }

    state = stored.state;
    if (stored.secretVersion != 0)
    {
      ProdigyPersistentLocalBrainStateSecrets secrets = {};
      bool ok = loadSecretRecord(
          brainColumnFamily,
          localBrainStateKey,
          stored.secretVersion,
          secrets,
          "invalid persistent local brain state secrets",
          failure);
      if (ok == false)
      {
        return false;
      }

      ok = prodigyApplyPersistentLocalBrainStateSecrets(state, secrets);
      secrets.clear();
      if (!ok)
      {
        state = {};
        if (failure) failure->assign("persistent local transport credential sidecar mismatch"_ctv);
        return false;
      }
    }
    if (!prodigyLocalTransportCredentialStateValid(state))
    {
      state = {};
      if (failure) failure->assign("persistent local transport credential is invalid or missing"_ctv);
      return false;
    }
    return true;
  }

  bool saveLocalBrainState(const ProdigyPersistentLocalBrainState& state, String *failure = nullptr)
  {
    if (!prodigyLocalTransportCredentialStateValid(state))
    {
      if (failure) failure->assign("invalid local transport credential state"_ctv);
      return false;
    }
    ProdigyPersistentLocalBrainState existingState = {};
    String loadFailure = {};
    if (loadLocalBrainState(existingState, &loadFailure))
    {
      if (prodigyPersistentSerializedEqual(existingState, state))
      {
        if (failure)
        {
          failure->clear();
        }
        return true;
      }
    }
    else if (loadFailure.size() > 0 && loadFailure != "record not found"_ctv)
    {
      if (failure)
      {
        failure->assign(loadFailure);
      }
      return false;
    }

    ProdigyPersistentLocalBrainState publicState = {};
    ProdigyPersistentLocalBrainStateSecrets secrets = {};
    prodigyExtractPersistentLocalBrainStateSecrets(state, publicState, secrets);

    uint64_t previousVersion = previousLocalBrainStateSecretVersion();
    uint64_t newVersion = 0;
    if (secrets.empty() == false)
    {
      newVersion = prodigyGeneratePersistentSecretVersion();
      if (saveSecretRecord(brainColumnFamily, localBrainStateKey, newVersion, secrets, failure) == false)
      {
        secrets.clear();
        return false;
      }
    }

    ProdigyPersistentStoredLocalBrainState stored = {};
    stored.secretVersion = newVersion;
    stored.state = std::move(publicState);

    String serialized = {};
    BitseryEngine::serialize(serialized, stored);
    bool ok = db.write(brainColumnFamily, localBrainStateKey, serialized, failure);
    if (ok && previousVersion != newVersion)
    {
      removeSecretRecordBestEffort(brainColumnFamily, localBrainStateKey, previousVersion);
    }

    Vault::secureClearString(serialized);
    secrets.clear();
    return ok;
  }

  bool loadConsumedBootstrapBundleSupersessionReceipt(
      ProdigyPersistentConsumedBootstrapBundleSupersessionReceipt& receipt,
      String *failure = nullptr)
  {
    String serialized = {};
    if (db.read(brainColumnFamily, consumedBootstrapBundleSupersessionReceiptKey, serialized, failure) == false)
    {
      return false;
    }

    if (BitseryEngine::deserializeSafe(serialized, receipt) == false)
    {
      receipt = {};
      if (failure) failure->assign("invalid consumed bootstrap bundle supersession receipt");
      return false;
    }

    return true;
  }

  bool saveConsumedBootstrapBundleSupersessionReceipt(
      const ProdigyPersistentConsumedBootstrapBundleSupersessionReceipt& receipt,
      String *failure = nullptr)
  {
    String serialized = {};
    BitseryEngine::serialize(serialized, receipt);
    const bool ok = db.write(brainColumnFamily, consumedBootstrapBundleSupersessionReceiptKey, serialized, failure);
    Vault::secureClearString(serialized);
    return ok;
  }

  bool loadOrCreateLocalBrainUUID(uint128_t& uuid, String *failure = nullptr)
  {
    uuid = 0;

    ProdigyPersistentLocalBrainState state = {};
    String loadFailure = {};
    if (loadLocalBrainState(state, &loadFailure))
    {
      uuid = state.uuid;
    }
    else if (loadFailure.size() > 0 && loadFailure != "record not found"_ctv)
    {
      if (failure)
      {
        failure->assign(loadFailure);
      }
      return false;
    }

    if (uuid == 0)
    {
      state.uuid = Random::generateNumberWithNBits<128, uint128_t>();
      if (saveLocalBrainState(state, failure) == false)
      {
        return false;
      }

      uuid = state.uuid;
    }

    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  bool removeBrainSnapshot(String *failure = nullptr)
  {
    return db.remove(brainColumnFamily, brainSnapshotKey, failure);
  }
};

enum class ProdigyBrainSnapshotCommitResult : uint8_t
{
  snapshotFailed,
  snapshotCommittedBootStateFailed,
  snapshotAndBootStateCommitted
};

static inline ProdigyBrainSnapshotCommitResult prodigyCommitBrainSnapshot(
    ProdigyPersistentStateStore& store,
    ProdigyPersistentBrainSnapshot snapshot,
    ProdigyPersistentBootState bootState,
    ProdigyPersistentBrainSnapshot& cachedSnapshot,
    ProdigyPersistentBootState& cachedBootState,
    bool& haveCachedSnapshot,
    String& failure)
{
  failure.clear();
  if (store.saveBrainSnapshot(snapshot, &failure) == false)
  {
    return ProdigyBrainSnapshotCommitResult::snapshotFailed;
  }

  prodigyReplaceCachedBrainSnapshot(cachedSnapshot, std::move(snapshot));
  haveCachedSnapshot = true;

  if (store.saveBootState(bootState, &failure) == false)
  {
    return ProdigyBrainSnapshotCommitResult::snapshotCommittedBootStateFailed;
  }

  cachedBootState = std::move(bootState);
  return ProdigyBrainSnapshotCommitResult::snapshotAndBootStateCommitted;
}
